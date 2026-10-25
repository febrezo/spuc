use anyhow::Result;

use crate::ast::{CompareOp, Expr};
use crate::emitters::{EmitResult, FailureCause, FidelityStatus};
use crate::ir::{IrExpr, IrOp, IrPredicate, IrValue};
use crate::parser;

const TARGET_PLATFORM: &str = "cytomic-orion-sql";
const REGEX_UNSUPPORTED_REASON: &str = "STIX MATCHES requires PCRE regex; Cytomic public documentation confirms SQL-like dialect but does not formally document a regex operator.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MatchKind {
    Like,
    Matches,
    Unknown,
}

#[derive(Debug)]
struct LowerCtx {
    match_kinds: Vec<MatchKind>,
    match_index: usize,
}

#[derive(Debug)]
struct Lowered {
    condition: String,
    event_type: &'static str,
}

#[derive(Debug)]
enum LowerFailure {
    Unsupported {
        reason: String,
        cause: FailureCause,
    },
    UnsupportedRegex {
        regex: String,
        suggested_fallback: Option<String>,
        fallback_event_type: Option<&'static str>,
    },
}

pub fn emit(ir: &IrExpr, source_pattern: &str, _description: Option<&str>) -> Result<EmitResult> {
    if matches!(ir, IrExpr::FollowedBy(_)) {
        return Ok(unsupported_field(
            "unsupported_field: Cytomic emitter does not support FOLLOWEDBY sequence semantics",
            FailureCause::BackendSemanticsMissing,
        ));
    }

    let match_kinds = collect_match_kinds(source_pattern);
    let mut ctx = LowerCtx {
        match_kinds,
        match_index: 0,
    };

    match lower_expr(ir, &mut ctx) {
        Ok(lowered) => Ok(EmitResult {
            status: FidelityStatus::Exact,
            notes: vec![
                format!("target_platform = \"{TARGET_PLATFORM}\""),
                "Cytomic emitted in default EDR-compatible Telemetry mode".to_string(),
            ],
            rule: Some(render_query(
                source_pattern,
                lowered.event_type,
                &lowered.condition,
            )),
            cause: None,
        }),
        Err(LowerFailure::Unsupported { reason, cause }) => Ok(unsupported_field(reason, cause)),
        Err(LowerFailure::UnsupportedRegex {
            regex,
            suggested_fallback,
            fallback_event_type,
        }) => Ok(EmitResult {
            status: FidelityStatus::Unsupported,
            notes: vec![
                "unsupported_regex: Cytomic regex support is not configured".to_string(),
                format!("original_regex: {regex}"),
                REGEX_UNSUPPORTED_REASON.to_string(),
            ],
            rule: Some(render_unsupported_regex(
                source_pattern,
                &regex,
                suggested_fallback.as_deref(),
                fallback_event_type.unwrap_or("PROCESS"),
            )),
            cause: Some(FailureCause::BackendSemanticsMissing),
        }),
    }
}

fn collect_match_kinds(source_pattern: &str) -> Vec<MatchKind> {
    let Ok(pattern) = parser::parse_rule(source_pattern) else {
        return Vec::new();
    };
    let mut kinds = Vec::new();
    collect_match_kinds_expr(&pattern.expr, &mut kinds);
    kinds
}

fn collect_match_kinds_expr(expr: &Expr, kinds: &mut Vec<MatchKind>) {
    match expr {
        Expr::Comparison(cmp) => match cmp.op {
            CompareOp::Like => kinds.push(MatchKind::Like),
            CompareOp::Matches => kinds.push(MatchKind::Matches),
            _ => {}
        },
        Expr::And(left, right) | Expr::Or(left, right) => {
            collect_match_kinds_expr(left, kinds);
            collect_match_kinds_expr(right, kinds);
        }
        Expr::FollowedBy(parts) => {
            for part in parts {
                collect_match_kinds_expr(part, kinds);
            }
        }
        Expr::Qualified(inner, _) => collect_match_kinds_expr(inner, kinds),
    }
}

fn lower_expr(expr: &IrExpr, ctx: &mut LowerCtx) -> std::result::Result<Lowered, LowerFailure> {
    match expr {
        IrExpr::Predicate(predicate) => lower_predicate(predicate, ctx),
        IrExpr::All(parts) => lower_joined(parts, ctx, "AND", "\nAND "),
        IrExpr::Any(parts) => lower_joined(parts, ctx, "OR", " OR "),
        IrExpr::FollowedBy(_) => Err(LowerFailure::Unsupported {
            reason: "unsupported_field: Cytomic emitter does not support FOLLOWEDBY sequence semantics".to_string(),
            cause: FailureCause::BackendSemanticsMissing,
        }),
        IrExpr::Qualified(_, _) => Err(LowerFailure::Unsupported {
            reason: "unsupported_field: Cytomic emitter does not support STIX observation qualifiers such as REPEATS, WITHIN, START or STOP".to_string(),
            cause: FailureCause::BackendSemanticsMissing,
        }),
    }
}

fn lower_joined(
    parts: &[IrExpr],
    ctx: &mut LowerCtx,
    op: &str,
    separator: &str,
) -> std::result::Result<Lowered, LowerFailure> {
    let mut lowered = Vec::new();
    for part in parts {
        lowered.push(lower_expr(part, ctx)?);
    }
    let Some(event_type) = common_event_type(&lowered) else {
        return Err(LowerFailure::Unsupported {
            reason: "unsupported_field: mixed Cytomic Telemetry EventType values in one STIX pattern cannot be represented conservatively".to_string(),
            cause: FailureCause::BackendSemanticsMissing,
        });
    };
    let conditions = lowered
        .into_iter()
        .map(|part| {
            if op == "OR" {
                format!("({})", part.condition)
            } else {
                part.condition
            }
        })
        .collect::<Vec<_>>();
    Ok(Lowered {
        condition: conditions.join(separator),
        event_type,
    })
}

fn common_event_type(lowered: &[Lowered]) -> Option<&'static str> {
    let first = lowered.first()?.event_type;
    lowered
        .iter()
        .all(|part| part.event_type == first)
        .then_some(first)
}

fn lower_predicate(
    predicate: &IrPredicate,
    ctx: &mut LowerCtx,
) -> std::result::Result<Lowered, LowerFailure> {
    let mapping = map_field(predicate)?;
    let condition = match mapping.fields.as_slice() {
        [field] => lower_single_field(predicate, field, ctx),
        fields => lower_multi_field(predicate, fields, ctx),
    }
    .map_err(|failure| match failure {
        LowerFailure::UnsupportedRegex {
            regex,
            suggested_fallback,
            ..
        } => LowerFailure::UnsupportedRegex {
            regex,
            suggested_fallback,
            fallback_event_type: Some(mapping.event_type),
        },
        other => other,
    })?;
    Ok(Lowered {
        condition,
        event_type: mapping.event_type,
    })
}

struct FieldMapping {
    event_type: &'static str,
    fields: Vec<&'static str>,
}

fn map_field(predicate: &IrPredicate) -> std::result::Result<FieldMapping, LowerFailure> {
    let mapping = match (predicate.target.as_str(), predicate.field.as_str()) {
        ("process", "name") => ("PROCESS", vec!["ProcessName"]),
        ("process", "command_line") => ("PROCESS", vec!["CommandLine"]),
        ("process", "pid") => ("PROCESS", vec!["ChildPid"]),
        ("process", "parent_ref.name") => ("PROCESS", vec!["ParentFilename"]),
        ("file", "name") => ("PROCESS", vec!["ChildFilename"]),
        ("file", "path") => ("PROCESS", vec!["ChildPath"]),
        ("file", "hashes.MD5") | ("file", "hashes.'MD5'") => ("PROCESS", vec!["ChildMd5"]),
        ("ipv4-addr", "value") => ("NETWORK", vec!["RemoteIp"]),
        ("network-traffic", "dst_ref.value") => ("NETWORK", vec!["RemoteIp"]),
        ("network-traffic", "dst_port") => ("NETWORK", vec!["RemotePort"]),
        ("network-traffic", "src_ref.value") => ("NETWORK", vec!["LocalIp"]),
        ("network-traffic", "src_port") => ("NETWORK", vec!["LocalPort"]),
        ("domain-name", "value") => ("NETWORK", vec!["DomainList", "InitialDomain", "Hostname"]),
        ("windows-registry-key", "key") => ("REGISTRY", vec!["Key"]),
        ("windows-registry-key", "values[*].name") => ("REGISTRY", vec!["Value"]),
        ("windows-registry-key", "values[*].data") => ("REGISTRY", vec!["ValueData"]),
        _ => {
            return Err(LowerFailure::Unsupported {
                reason: format!(
                    "unsupported_field: no conservative Cytomic mapping for {}:{}",
                    predicate.target, predicate.field
                ),
                cause: FailureCause::SchemaUncertain,
            });
        }
    };
    Ok(FieldMapping {
        event_type: mapping.0,
        fields: mapping.1,
    })
}

fn lower_single_field(
    predicate: &IrPredicate,
    field: &str,
    ctx: &mut LowerCtx,
) -> std::result::Result<String, LowerFailure> {
    match predicate.op {
        IrOp::Matches => lower_match_predicate(predicate, field, ctx),
        IrOp::Eq | IrOp::Ne | IrOp::Gt | IrOp::Ge | IrOp::Lt | IrOp::Le => {
            if is_ordering_op(&predicate.op) && !is_numeric_or_date_field(field) {
                return Err(LowerFailure::Unsupported {
                    reason: format!(
                        "unsupported_field: ordered comparison is not conservative for Cytomic field {field}"
                    ),
                    cause: FailureCause::BackendSemanticsMissing,
                });
            }
            Ok(format!(
                "{field} {} {}",
                sql_operator(&predicate.op)?,
                sql_value(&predicate.value)?
            ))
        }
        IrOp::IsSubset => Err(LowerFailure::Unsupported {
            reason:
                "unsupported_field: Cytomic emitter does not support STIX ISSUBSET/CIDR semantics"
                    .to_string(),
            cause: FailureCause::BackendSemanticsMissing,
        }),
    }
}

fn lower_multi_field(
    predicate: &IrPredicate,
    fields: &[&str],
    ctx: &mut LowerCtx,
) -> std::result::Result<String, LowerFailure> {
    if matches!(predicate.op, IrOp::Matches) {
        let regex = string_value(&predicate.value)?;
        let kind = ctx
            .match_kinds
            .get(ctx.match_index)
            .copied()
            .unwrap_or(MatchKind::Unknown);
        ctx.match_index += 1;
        let mut conditions = Vec::new();
        for field in fields {
            conditions.push(lower_match_field(&regex, field, kind)?);
        }
        return Ok(format!("({})", conditions.join(" OR ")));
    }

    let joiner = if matches!(predicate.op, IrOp::Ne) {
        " AND "
    } else {
        " OR "
    };
    let mut conditions = Vec::new();
    for field in fields {
        conditions.push(lower_single_field(predicate, field, ctx)?);
    }
    Ok(format!("({})", conditions.join(joiner)))
}

fn lower_match_predicate(
    predicate: &IrPredicate,
    field: &str,
    ctx: &mut LowerCtx,
) -> std::result::Result<String, LowerFailure> {
    let regex = string_value(&predicate.value)?;
    let kind = ctx
        .match_kinds
        .get(ctx.match_index)
        .copied()
        .unwrap_or(MatchKind::Unknown);
    ctx.match_index += 1;

    match kind {
        MatchKind::Like => lower_match_field(&regex, field, kind),
        MatchKind::Matches | MatchKind::Unknown => lower_match_field(&regex, field, kind),
    }
}

fn lower_match_field(
    regex: &str,
    field: &str,
    kind: MatchKind,
) -> std::result::Result<String, LowerFailure> {
    match kind {
        MatchKind::Like => {
            let like = regex_from_normalized_like(regex).ok_or_else(|| LowerFailure::Unsupported {
                reason: format!(
                    "unsupported_regex: normalized STIX LIKE pattern cannot be safely converted to SQL LIKE: {regex}"
                ),
                cause: FailureCause::BackendSemanticsMissing,
            })?;
            Ok(format!("{field} LIKE {}", quote_sql_string(&like)))
        }
        MatchKind::Matches | MatchKind::Unknown => {
            let suggested_fallback = simple_case_insensitive_contains(regex).map(|needle| {
                format!(
                    "LOWER({field}) LIKE {}",
                    quote_sql_string(&format!("%{}%", needle))
                )
            });
            Err(LowerFailure::UnsupportedRegex {
                regex: regex.to_string(),
                suggested_fallback,
                fallback_event_type: None,
            })
        }
    }
}

fn sql_operator(op: &IrOp) -> std::result::Result<&'static str, LowerFailure> {
    match op {
        IrOp::Eq => Ok("="),
        IrOp::Ne => Ok("<>"),
        IrOp::Gt => Ok(">"),
        IrOp::Ge => Ok(">="),
        IrOp::Lt => Ok("<"),
        IrOp::Le => Ok("<="),
        IrOp::Matches | IrOp::IsSubset => Err(LowerFailure::Unsupported {
            reason: "unsupported_field: unsupported Cytomic SQL operator".to_string(),
            cause: FailureCause::BackendSemanticsMissing,
        }),
    }
}

fn sql_value(value: &IrValue) -> std::result::Result<String, LowerFailure> {
    match value {
        IrValue::String(value) | IrValue::Timestamp(value) => Ok(quote_sql_string(value)),
        IrValue::Integer(value) => Ok(value.to_string()),
        IrValue::Boolean(value) => Ok(value.to_string()),
        IrValue::Hex(_) => Err(LowerFailure::Unsupported {
            reason: "unsupported_field: Cytomic emitter does not support hex literals".to_string(),
            cause: FailureCause::BackendSemanticsMissing,
        }),
    }
}

fn string_value(value: &IrValue) -> std::result::Result<String, LowerFailure> {
    match value {
        IrValue::String(value) => Ok(value.clone()),
        _ => Err(LowerFailure::Unsupported {
            reason: "unsupported_regex: STIX MATCHES/LIKE requires a string literal".to_string(),
            cause: FailureCause::BackendSemanticsMissing,
        }),
    }
}

fn is_ordering_op(op: &IrOp) -> bool {
    matches!(op, IrOp::Gt | IrOp::Ge | IrOp::Lt | IrOp::Le)
}

fn is_numeric_or_date_field(field: &str) -> bool {
    matches!(field, "ChildPid" | "ParentPid" | "RemotePort" | "LocalPort")
}

fn quote_sql_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn regex_from_normalized_like(regex: &str) -> Option<String> {
    let inner = regex.strip_prefix('^')?.strip_suffix('$')?;
    let mut out = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '.' if chars.peek() == Some(&'*') => {
                chars.next();
                out.push('%');
            }
            '.' => out.push('_'),
            '\\' => out.push(chars.next()?),
            '%' | '_' => {
                out.push('\\');
                out.push(ch);
            }
            '^' | '$' | '|' | '(' | ')' | '[' | ']' | '{' | '}' | '*' | '+' | '?' => {
                return None;
            }
            _ => out.push(ch),
        }
    }
    Some(out)
}

fn simple_case_insensitive_contains(regex: &str) -> Option<String> {
    let mut body = regex.strip_prefix("(?i)")?;
    body = body.strip_prefix('^').unwrap_or(body);
    body = body.strip_suffix('$').unwrap_or(body);
    body = body.strip_prefix(".*")?;
    body = body.strip_suffix(".*")?;
    if body.is_empty() || body.chars().any(is_regex_meta) {
        return None;
    }
    Some(body.to_ascii_lowercase())
}

fn is_regex_meta(ch: char) -> bool {
    matches!(
        ch,
        '\\' | '.' | '*' | '+' | '?' | '|' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$'
    )
}

fn render_query(source_pattern: &str, event_type: &str, condition: &str) -> String {
    format!(
        "-- target_platform: {TARGET_PLATFORM}\n-- source_stix_pattern: {}\nSELECT *\nFROM Telemetry\nWHERE EventType = '{}'\nAND {};",
        sanitize_comment(source_pattern),
        event_type,
        condition
    )
}

fn render_unsupported_regex(
    source_pattern: &str,
    regex: &str,
    suggested_fallback: Option<&str>,
    fallback_event_type: &str,
) -> String {
    let mut out = format!(
        "UNSUPPORTED:\ntarget_platform = \"{TARGET_PLATFORM}\"\nsource_stix_pattern = \"{}\"\nreason = \"{REGEX_UNSUPPORTED_REASON}\"\nregex = \"{}\"",
        escape_metadata(source_pattern),
        escape_metadata(regex)
    );
    if let Some(fallback) = suggested_fallback {
        out.push_str("\nsuggested_fallback =\n");
        out.push_str(&render_query(source_pattern, fallback_event_type, fallback));
    }
    out
}

fn sanitize_comment(value: &str) -> String {
    value.replace(['\n', '\r'], " ")
}

fn escape_metadata(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn unsupported_field(reason: impl Into<String>, cause: FailureCause) -> EmitResult {
    EmitResult {
        status: FidelityStatus::Unsupported,
        notes: vec![reason.into()],
        rule: None,
        cause: Some(cause),
    }
}

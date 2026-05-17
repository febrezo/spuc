use anyhow::{bail, Result};

use crate::emitters::{EmitResult, FidelityStatus};
use crate::ir::{IrExpr, IrOp, IrPredicate, IrQualifier, IrValue};

pub fn emit(ir: &IrExpr, _description: Option<&str>) -> Result<EmitResult> {
    let (base, qualifiers) = peel_qualifiers(ir);
    if let IrExpr::FollowedBy(parts) = base {
        return emit_followedby(parts, &qualifiers);
    }
    let disjuncts = expand_conjunctions(base)?;

    let mut parts = Vec::new();
    let mut dataset: Option<String> = None;
    let mut notes = Vec::new();

    for conj in disjuncts {
        if has_multi_user_account_conjunction(&conj) {
            return Ok(EmitResult::unsupported(
                "EQL cannot faithfully represent multi-entity user-account conjunctions as one event",
            ));
        }
        let lowered = lower_all(&conj)?;
        dataset = merge_dataset(dataset, lowered.dataset);
        parts.push(format!("({})", lowered.condition));
        notes.extend(lowered.notes);
    }

    let mut qualifier_filters = Vec::new();
    for q in qualifiers {
        match q {
            IrQualifier::StartStop { start, stop } => {
                qualifier_filters.push(format!(
                    "(@timestamp >= datetime(\"{start}\") and @timestamp < datetime(\"{stop}\"))"
                ));
            }
            IrQualifier::RepeatsTimes(times) => {
                notes.push(format!(
                    "REPEATS {times} TIMES kept as advisory only (cardinality/event identity is not enforceable in plain EQL where-clause)"
                ));
                notes.push("@status:partial".to_string());
            }
            IrQualifier::WithinSeconds(secs) => {
                notes.push(format!(
                    "WITHIN {secs} SECONDS kept as advisory only (time-window correlation is not enforceable in plain EQL where-clause)"
                ));
            }
        }
    }

    let final_dataset = dataset.unwrap_or_else(|| "any".to_string());
    let mut condition = parts.join(" or ");
    if !qualifier_filters.is_empty() {
        condition = format!("({condition}) and {}", qualifier_filters.join(" and "));
    }

    Ok(EmitResult {
        status: if notes.is_empty() {
            FidelityStatus::Exact
        } else {
            FidelityStatus::Partial
        },
        notes,
        rule: Some(format!("{final_dataset} where {condition}")),
        cause: None,
    })
}

fn emit_followedby(parts: &[IrExpr], qualifiers: &[IrQualifier]) -> Result<EmitResult> {
    if parts.len() < 2 {
        return Ok(EmitResult::unsupported(
            "FOLLOWEDBY requires at least two observation expressions",
        ));
    }

    let mut maxspan_secs: Option<f64> = None;
    for q in qualifiers {
        match q {
            IrQualifier::WithinSeconds(secs) => {
                maxspan_secs = Some(*secs);
            }
            IrQualifier::RepeatsTimes(_) => {
                return Ok(EmitResult::unsupported(
                    "EQL FOLLOWEDBY does NOT support outer REPEATS qualifiers in this baseline",
                ));
            }
            IrQualifier::StartStop { .. } => {
                return Ok(EmitResult::unsupported(
                    "EQL FOLLOWEDBY does NOT support outer START/STOP qualifiers in this baseline",
                ));
            }
        }
    }

    let mut steps = Vec::new();
    let mut notes = Vec::new();

    for part in parts {
        if matches!(part, IrExpr::Qualified(_, _)) {
            return Ok(EmitResult::unsupported(
                "EQL FOLLOWEDBY does NOT support per-step observation qualifiers in this baseline",
            ));
        }

        let disjuncts = expand_conjunctions(part)?;
        if disjuncts.len() != 1 {
            return Ok(EmitResult::unsupported(
                "EQL FOLLOWEDBY does not support OR branches inside sequence steps in this baseline",
            ));
        }
        let conj = &disjuncts[0];
        if has_multi_user_account_conjunction(conj) {
            return Ok(EmitResult::unsupported(
                "EQL cannot faithfully represent multi-entity user-account conjunctions as one event",
            ));
        }

        let lowered = lower_all(conj)?;
        let dataset = lowered.dataset.unwrap_or_else(|| "any".to_string());
        steps.push(format!("[{dataset} where {}]", lowered.condition));
        notes.extend(lowered.notes);
    }

    let mut sequence_head = "sequence".to_string();
    if let Some(secs) = maxspan_secs {
        sequence_head = format!("sequence with maxspan={}", eql_maxspan_literal(secs));
        notes.push(format!(
            "WITHIN {secs} SECONDS lowered to EQL sequence maxspan"
        ));
    }

    Ok(EmitResult {
        status: FidelityStatus::Exact,
        notes,
        rule: Some(format!("{sequence_head} {}", steps.join(" "))),
        cause: None,
    })
}

fn eql_maxspan_literal(secs: f64) -> String {
    let rounded = secs.round();
    if (secs - rounded).abs() < f64::EPSILON {
        format!("{}s", rounded as i64)
    } else {
        let millis = (secs * 1000.0).round().max(1.0) as i64;
        format!("{millis}ms")
    }
}

fn peel_qualifiers(mut ir: &IrExpr) -> (&IrExpr, Vec<IrQualifier>) {
    let mut qualifiers = Vec::new();
    while let IrExpr::Qualified(inner, qs) = ir {
        qualifiers.extend(qs.clone());
        ir = inner.as_ref();
    }
    (ir, qualifiers)
}

struct EqlExpr {
    dataset: Option<String>,
    condition: String,
    notes: Vec<String>,
}

fn lower_all(predicates: &[IrPredicate]) -> Result<EqlExpr> {
    let mut conditions = Vec::new();
    let mut dataset: Option<String> = None;
    let mut notes = Vec::new();
    for p in predicates {
        let (ds, cond, mut pred_notes) = lower_predicate(p)?;
        dataset = merge_dataset(dataset, ds);
        conditions.push(cond);
        notes.append(&mut pred_notes);
    }
    if has_standalone_network_observable(predicates) && !has_network_traffic(predicates) {
        notes.push(
            "standalone IP/domain/URL observables are backend-dependent mappings without full network-traffic context"
                .to_string(),
        );
    }
    if has_ambiguous_network_subset(predicates) {
        notes.push(
            "network-traffic:*_ref.value ISSUBSET without explicit *_ref.type is backend-dependent (value can be non-IP in STIX)"
                .to_string(),
        );
    }
    Ok(EqlExpr {
        dataset,
        condition: conditions.join(" and "),
        notes,
    })
}

fn lower_predicate(p: &IrPredicate) -> Result<(Option<String>, String, Vec<String>)> {
    validate_operator(p)?;

    if let Some(cond) = standalone_network_condition(p)? {
        let mut notes = vec![
            "standalone IP/MAC observables are mapped as source OR destination without full network-traffic context"
                .to_string(),
        ];
        if let IrValue::String(v) = &p.value {
            if v.contains('/') && matches!(p.target.as_str(), "ipv4-addr" | "ipv6-addr") {
                notes.push("CIDR/range semantics can be backend-dependent".to_string());
            }
        }
        return Ok((Some("network".to_string()), cond, notes));
    }

    if p.op == IrOp::IsSubset {
        return lower_subset_predicate(p);
    }

    let field = map_field(p)?;
    let op = match p.op {
        IrOp::Eq => "==",
        IrOp::Ne => "!=",
        IrOp::Gt => ">",
        IrOp::Ge => ">=",
        IrOp::Lt => "<",
        IrOp::Le => "<=",
        IrOp::Matches => "regex",
        IrOp::IsSubset => {
            bail!("internal error: ISSUBSET should be handled before generic lowering")
        }
    };

    let condition = if p.op == IrOp::Matches {
        match &p.value {
            IrValue::String(s) => format!("{field} regex \"{s}\""),
            _ => bail!("EQL MATCHES requires a string literal"),
        }
    } else {
        let value = match &p.value {
            IrValue::String(s) => format!("\"{}\"", s),
            IrValue::Integer(i) => i.to_string(),
            IrValue::Boolean(b) => b.to_string(),
            IrValue::Hex(h) => format!("\"{}\"", h),
            IrValue::Timestamp(ts) => format!("datetime(\"{ts}\")"),
        };
        format!("{field} {op} {value}")
    };

    let mut notes = Vec::new();
    if is_file_temporal_field(p) {
        notes.push("schema-dependent temporal field; verify ECS/profile mapping".to_string());
    }
    if matches!(
        (p.target.as_str(), p.field.as_str()),
        ("process", "created_time")
    ) {
        notes.push("schema-dependent temporal field; verify ECS/profile mapping".to_string());
    }
    if matches!(
        (p.target.as_str(), p.field.as_str()),
        ("windows-registry-key", "modified_time")
    ) {
        notes.push("schema-dependent timestamp field; verify backend mapping".to_string());
    }
    if matches!(
        (p.target.as_str(), p.field.as_str()),
        ("process", "is_hidden")
    ) {
        notes.push("process:is_hidden flattened to backend process visibility fields".to_string());
    }
    if (p.target.as_str(), p.field.as_str()) == ("process", "image_ref.name")
        || (p.target.as_str(), p.field.as_str()) == ("process", "parent_ref.command_line")
        || (p.target.as_str() == "process"
            && p.field.as_str().starts_with("image_ref.hashes.SHA-256"))
    {
        notes
            .push("process references flattened into executable/parent process fields".to_string());
    }
    if (p.target.as_str(), p.field.as_str()) == ("windows-registry-key", "values[*].name")
        || (p.target.as_str(), p.field.as_str()) == ("windows-registry-key", "values[*].data")
        || (p.target.as_str(), p.field.as_str()) == ("windows-registry-key", "values[*].data_type")
    {
        notes
            .push("registry value fields flattened into backend registry event fields".to_string());
    }
    if (p.target.as_str(), p.field.as_str()) == ("artifact", "mime_type")
        || ((p.target.as_str(), p.field.as_str()) == ("artifact", "payload_bin")
            && !matches!(p.op, IrOp::Matches))
    {
        notes.push("artifact schema fields are backend-dependent and may require pipeline-specific mapping".to_string());
    }
    if (p.target.as_str(), p.field.as_str()) == ("file", "mime_type") {
        notes.push(
            "file:mime_type mapping is schema-dependent; verify backend field profile".to_string(),
        );
    }
    if (p.target.as_str(), p.field.as_str()) == ("artifact", "payload_bin")
        && matches!(p.op, IrOp::Matches)
    {
        notes.push("artifact:payload_bin regex evaluation may depend on backend field encoding (bytes vs text/hex)".to_string());
        notes.push("@conf50".to_string());
    }
    if matches!(p.op, IrOp::Matches) {
        notes.push("regex behavior can be backend-dependent".to_string());
    }
    if p.target.as_str() == "user-account" {
        notes.push("user-account field mappings are schema-dependent".to_string());
    }
    if (p.target.as_str(), p.field.as_str()) == ("directory", "path") {
        notes.push("directory path mapping is schema-dependent".to_string());
    }
    if (p.target.as_str(), p.field.as_str()) == ("network-traffic", "protocols") {
        notes.push(
            "network-traffic:protocols is an ordered STIX stack; mapping may only reflect a single protocol token"
                .to_string(),
        );
    }
    if matches!(
        (p.target.as_str(), p.field.as_str()),
        ("network-traffic", "src_ref.value")
            | ("network-traffic", "dst_ref.value")
            | ("network-traffic", "src_port")
            | ("network-traffic", "dst_port")
            | ("network-traffic", "protocols")
    ) {
        notes.push(
            "schema-dependent network-traffic mapping; verify source/destination role and field population in backend profile"
                .to_string(),
        );
    }
    if p.target.as_str() == "autonomous-system" {
        notes.push(
            "schema-dependent autonomous-system mapping; verify backend field profile".to_string(),
        );
    }
    if let IrValue::String(v) = &p.value {
        if v.contains('/')
            && matches!(
                (p.target.as_str(), p.field.as_str()),
                ("network-traffic", "src_ref.value")
                    | ("network-traffic", "dst_ref.value")
                    | ("ipv4-addr", "value")
                    | ("ipv6-addr", "value")
            )
        {
            notes.push("CIDR/range semantics can be backend-dependent".to_string());
        }
    }
    Ok((dataset_hint(p), condition, notes))
}

fn has_multi_user_account_conjunction(predicates: &[IrPredicate]) -> bool {
    fn distinct_eq_values<'a>(
        predicates: &'a [IrPredicate],
        field: &str,
    ) -> std::collections::BTreeSet<&'a str> {
        predicates
            .iter()
            .filter_map(|p| {
                if p.target == "user-account" && p.field == field && p.op == IrOp::Eq {
                    if let IrValue::String(v) = &p.value {
                        return Some(v.as_str());
                    }
                }
                None
            })
            .collect()
    }

    let account_type = distinct_eq_values(predicates, "account_type");
    let user_id = distinct_eq_values(predicates, "user_id");
    let account_login = distinct_eq_values(predicates, "account_login");

    account_type.len() > 1 || user_id.len() > 1 || account_login.len() > 1
}

fn validate_operator(p: &IrPredicate) -> Result<()> {
    let allowed: &[IrOp] = match (p.target.as_str(), p.field.as_str()) {
        ("artifact", f) if f.starts_with("hashes.") => &[IrOp::Eq, IrOp::Ne],
        ("artifact", "mime_type") | ("artifact", "payload_bin") => {
            &[IrOp::Eq, IrOp::Ne, IrOp::Matches]
        }
        ("file", f) if f.starts_with("hashes.") => &[IrOp::Eq, IrOp::Ne],
        ("file", "mime_type") => &[IrOp::Eq, IrOp::Ne, IrOp::Matches],
        ("domain-name", "value") => &[IrOp::Eq, IrOp::Ne, IrOp::Matches],
        ("url", "value") => &[IrOp::Eq, IrOp::Ne, IrOp::Matches],
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.") => {
            &[IrOp::Eq, IrOp::Ne]
        }
        ("email-message", _) => &[IrOp::Eq, IrOp::Ne, IrOp::Matches],
        ("file", "name") => &[IrOp::Eq, IrOp::Ne, IrOp::Matches],
        ("directory", "path") => &[IrOp::Eq, IrOp::Ne, IrOp::Matches],
        ("directory", "ctime") | ("directory", "mtime") | ("directory", "atime") => {
            &[IrOp::Eq, IrOp::Ne, IrOp::Gt, IrOp::Ge, IrOp::Lt, IrOp::Le]
        }
        ("file", "size") => &[IrOp::Eq, IrOp::Ne, IrOp::Gt, IrOp::Ge, IrOp::Lt, IrOp::Le],
        ("file", "ctime") | ("file", "mtime") | ("file", "atime") => {
            &[IrOp::Eq, IrOp::Ne, IrOp::Gt, IrOp::Ge, IrOp::Lt, IrOp::Le]
        }
        ("ipv4-addr", "value") | ("ipv6-addr", "value") => {
            &[IrOp::Eq, IrOp::Ne, IrOp::Matches, IrOp::IsSubset]
        }
        ("mac-addr", "value") => &[IrOp::Eq, IrOp::Ne, IrOp::Matches],
        ("network-traffic", "src_ref.value") | ("network-traffic", "dst_ref.value") => {
            &[IrOp::Eq, IrOp::Ne, IrOp::Matches, IrOp::IsSubset]
        }
        ("network-traffic", "src_port") | ("network-traffic", "dst_port") => {
            &[IrOp::Eq, IrOp::Ne, IrOp::Gt, IrOp::Ge, IrOp::Lt, IrOp::Le]
        }
        ("network-traffic", "protocols") => &[IrOp::Eq, IrOp::Ne, IrOp::Matches],
        ("process", "command_line")
        | ("process", "name")
        | ("process", "image_ref.name")
        | ("process", "cwd")
        | ("process", "parent_ref.command_line") => &[IrOp::Eq, IrOp::Ne, IrOp::Matches],
        ("process", "pid") => &[IrOp::Eq, IrOp::Ne, IrOp::Gt, IrOp::Ge, IrOp::Lt, IrOp::Le],
        ("process", "is_hidden") => &[IrOp::Eq, IrOp::Ne],
        ("process", "created_time") => {
            &[IrOp::Eq, IrOp::Ne, IrOp::Gt, IrOp::Ge, IrOp::Lt, IrOp::Le]
        }
        ("process", f) if f.starts_with("image_ref.hashes.") => &[IrOp::Eq, IrOp::Ne],
        ("user-account", "account_type") | ("user-account", "account_login") => {
            &[IrOp::Eq, IrOp::Ne, IrOp::Matches]
        }
        ("user-account", "user_id") => {
            &[IrOp::Eq, IrOp::Ne, IrOp::Gt, IrOp::Ge, IrOp::Lt, IrOp::Le]
        }
        ("windows-registry-key", "modified_time") => {
            &[IrOp::Eq, IrOp::Ne, IrOp::Gt, IrOp::Ge, IrOp::Lt, IrOp::Le]
        }
        ("windows-registry-key", _) => &[IrOp::Eq, IrOp::Ne, IrOp::Matches],
        ("autonomous-system", "number") => {
            &[IrOp::Eq, IrOp::Ne, IrOp::Gt, IrOp::Ge, IrOp::Lt, IrOp::Le]
        }
        ("autonomous-system", "name") | ("autonomous-system", "rir") => {
            &[IrOp::Eq, IrOp::Ne, IrOp::Matches]
        }
        _ => &[
            IrOp::Eq,
            IrOp::Ne,
            IrOp::Gt,
            IrOp::Ge,
            IrOp::Lt,
            IrOp::Le,
            IrOp::Matches,
        ],
    };

    if allowed.contains(&p.op) {
        Ok(())
    } else {
        bail!(
            "EQL emitter does not support operator {:?} for {}:{}",
            p.op,
            p.target,
            p.field
        )
    }
}

fn dataset_hint(p: &IrPredicate) -> Option<String> {
    match p.target.as_str() {
        "process" => Some("process".to_string()),
        "network-traffic" => Some("network".to_string()),
        "file" | "directory" => Some("file".to_string()),
        "autonomous-system" => Some("network".to_string()),
        "email-message" => Some("email".to_string()),
        _ => None,
    }
}

fn map_field(p: &IrPredicate) -> Result<String> {
    match (p.target.as_str(), p.field.as_str()) {
        ("process", "command_line") => Ok("process.command_line".to_string()),
        ("process", "name") => Ok("process.name".to_string()),
        ("process", "image_ref.name") => Ok("process.name".to_string()),
        ("process", "pid") => Ok("process.pid".to_string()),
        ("process", "is_hidden") => Ok("process.is_hidden".to_string()),
        ("process", "cwd") => Ok("process.working_directory".to_string()),
        ("process", "created_time") => Ok("process.created".to_string()),
        ("process", "parent_ref.command_line") => Ok("process.parent.command_line".to_string()),
        ("process", f) if f.starts_with("image_ref.hashes.SHA-256") => {
            Ok("process.hash.sha256".to_string())
        }
        ("file", "name") => Ok("file.name".to_string()),
        ("file", "mime_type") => Ok("file.mime_type".to_string()),
        ("directory", "path") => Ok("directory.path".to_string()),
        ("directory", "ctime") => Ok("directory.ctime".to_string()),
        ("directory", "mtime") => Ok("directory.mtime".to_string()),
        ("directory", "atime") => Ok("directory.atime".to_string()),
        ("file", "size") => Ok("file.size".to_string()),
        ("file", "ctime") => Ok("file.ctime".to_string()),
        ("file", "mtime") => Ok("file.mtime".to_string()),
        ("file", "atime") => Ok("file.atime".to_string()),
        ("file", f) if f.starts_with("hashes.MD5") => Ok("file.hash.md5".to_string()),
        ("file", f) if f.starts_with("hashes.SHA-1") => Ok("file.hash.sha1".to_string()),
        ("file", f) if f.starts_with("hashes.SHA-256") => Ok("file.hash.sha256".to_string()),
        ("file", f) if f.starts_with("hashes.SHA-512") => Ok("file.hash.sha512".to_string()),
        ("file", f) if f.starts_with("hashes.SHA3-256") => Ok("file.hash.sha3_256".to_string()),
        ("file", f) if f.starts_with("hashes.SHA3-512") => Ok("file.hash.sha3_512".to_string()),
        ("file", f) if f.starts_with("hashes.SSDEEP") => Ok("file.hash.ssdeep".to_string()),
        ("file", f) if f.starts_with("hashes.TLSH") => Ok("file.hash.tlsh".to_string()),
        ("artifact", f) if f.starts_with("hashes.MD5") => Ok("file.hash.md5".to_string()),
        ("artifact", f) if f.starts_with("hashes.SHA-1") => Ok("file.hash.sha1".to_string()),
        ("artifact", f) if f.starts_with("hashes.SHA-256") => Ok("file.hash.sha256".to_string()),
        ("artifact", f) if f.starts_with("hashes.SHA-512") => Ok("file.hash.sha512".to_string()),
        ("artifact", f) if f.starts_with("hashes.SHA3-256") => Ok("file.hash.sha3_256".to_string()),
        ("artifact", f) if f.starts_with("hashes.SHA3-512") => Ok("file.hash.sha3_512".to_string()),
        ("artifact", f) if f.starts_with("hashes.SSDEEP") => Ok("file.hash.ssdeep".to_string()),
        ("artifact", f) if f.starts_with("hashes.TLSH") => Ok("file.hash.tlsh".to_string()),
        ("artifact", "mime_type") => Ok("artifact.mime_type".to_string()),
        ("artifact", "payload_bin") => Ok("artifact.payload_bin".to_string()),
        ("ipv4-addr", "value") => Ok("destination.ip".to_string()),
        ("ipv6-addr", "value") => Ok("destination.ip".to_string()),
        ("mac-addr", "value") => Ok("destination.mac".to_string()),
        ("domain-name", "value") => Ok("destination.domain".to_string()),
        ("url", "value") => Ok("url.full".to_string()),
        ("network-traffic", "protocols") => Ok("network.protocol".to_string()),
        ("windows-registry-key", "key") => Ok("registry.key".to_string()),
        ("windows-registry-key", "values[*].name") => Ok("registry.value".to_string()),
        ("windows-registry-key", "values[*].data") => Ok("registry.data".to_string()),
        ("windows-registry-key", "values[*].data_type") => Ok("registry.data.type".to_string()),
        ("windows-registry-key", "modified_time") => Ok("registry.modified_time".to_string()),
        ("network-traffic", "src_ref.value") => Ok("source.ip".to_string()),
        ("network-traffic", "dst_ref.value") => Ok("destination.ip".to_string()),
        ("network-traffic", "src_port") => Ok("source.port".to_string()),
        ("network-traffic", "dst_port") => Ok("destination.port".to_string()),
        ("user-account", "account_type") => Ok("user.type".to_string()),
        ("user-account", "user_id") => Ok("user.id".to_string()),
        ("user-account", "account_login") => Ok("user.name".to_string()),
        ("autonomous-system", "number") => Ok("as.number".to_string()),
        ("autonomous-system", "name") => Ok("as.organization.name".to_string()),
        ("autonomous-system", "rir") => Ok("as.rir".to_string()),
        ("email-message", "from_ref.value") => Ok("email.from.address".to_string()),
        ("email-message", "sender_ref.value") => Ok("email.from.address".to_string()),
        ("email-message", "subject") => Ok("email.subject".to_string()),
        ("email-message", "body") => Ok("email.body".to_string()),
        ("email-message", "to_refs[*].value") => Ok("email.to.address".to_string()),
        ("email-message", "body_multipart[*].body_raw_ref.name") => {
            Ok("email.attachments.file.name".to_string())
        }
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.'MD5'") => {
            Ok("email.attachments.file.hash.md5".to_string())
        }
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA-1'") => {
            Ok("email.attachments.file.hash.sha1".to_string())
        }
        ("email-message", f)
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA-256'") =>
        {
            Ok("email.attachments.file.hash.sha256".to_string())
        }
        ("email-message", f)
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA-512'") =>
        {
            Ok("email.attachments.file.hash.sha512".to_string())
        }
        ("email-message", f)
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA3-256'") =>
        {
            Ok("email.attachments.file.hash.sha3_256".to_string())
        }
        ("email-message", f)
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA3-512'") =>
        {
            Ok("email.attachments.file.hash.sha3_512".to_string())
        }
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.SSDEEP") => {
            Ok("email.attachments.file.hash.ssdeep".to_string())
        }
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.TLSH") => {
            Ok("email.attachments.file.hash.tlsh".to_string())
        }
        _ => bail!(
            "EQL emitter does not support predicate {}:{}",
            p.target,
            p.field
        ),
    }
}

fn is_file_temporal_field(p: &IrPredicate) -> bool {
    matches!(
        (p.target.as_str(), p.field.as_str()),
        ("file", "ctime")
            | ("file", "mtime")
            | ("file", "atime")
            | ("directory", "ctime")
            | ("directory", "mtime")
            | ("directory", "atime")
    )
}

fn has_network_traffic(predicates: &[IrPredicate]) -> bool {
    predicates
        .iter()
        .any(|p| p.target.as_str() == "network-traffic")
}

fn has_standalone_network_observable(predicates: &[IrPredicate]) -> bool {
    predicates.iter().any(|p| {
        matches!(
            (p.target.as_str(), p.field.as_str()),
            ("ipv4-addr", "value")
                | ("ipv6-addr", "value")
                | ("mac-addr", "value")
                | ("domain-name", "value")
                | ("url", "value")
        )
    })
}

fn standalone_network_condition(p: &IrPredicate) -> Result<Option<String>> {
    let (src, dst) = match (p.target.as_str(), p.field.as_str()) {
        ("ipv4-addr", "value") | ("ipv6-addr", "value") => ("source.ip", "destination.ip"),
        ("mac-addr", "value") => ("source.mac", "destination.mac"),
        _ => return Ok(None),
    };
    let op = match p.op {
        IrOp::Eq => "==",
        IrOp::Ne => "!=",
        IrOp::Matches => "regex",
        IrOp::IsSubset => "",
        _ => bail!("EQL standalone network observables only support =, != and MATCHES/LIKE"),
    };
    let value = match &p.value {
        IrValue::String(s) => s,
        _ => bail!("EQL standalone network observable requires string value"),
    };
    let cond = match p.op {
        IrOp::Matches => format!("({src} regex \"{value}\" or {dst} regex \"{value}\")"),
        IrOp::IsSubset => {
            format!("(cidrMatch({src}, \"{value}\") or cidrMatch({dst}, \"{value}\"))")
        }
        _ => format!("({src} {op} \"{value}\" or {dst} {op} \"{value}\")"),
    };
    Ok(Some(cond))
}

fn lower_subset_predicate(p: &IrPredicate) -> Result<(Option<String>, String, Vec<String>)> {
    let field = map_field(p)?;
    let cidr = match &p.value {
        IrValue::String(s) => s,
        _ => bail!("EQL ISSUBSET requires a CIDR string"),
    };
    if !matches!(
        (p.target.as_str(), p.field.as_str()),
        ("ipv4-addr", "value")
            | ("ipv6-addr", "value")
            | ("network-traffic", "src_ref.value")
            | ("network-traffic", "dst_ref.value")
    ) {
        bail!(
            "EQL emitter does not support ISSUBSET for {}:{}",
            p.target,
            p.field
        );
    }
    let mut notes = vec![
        "ISSUBSET semantics depend on backend CIDR function support and field typing".to_string(),
    ];
    if matches!(
        (p.target.as_str(), p.field.as_str()),
        ("network-traffic", "src_ref.value") | ("network-traffic", "dst_ref.value")
    ) {
        notes.push(
            "network-traffic:*_ref.value ISSUBSET assumes IP-typed refs; add *_ref.type for stronger semantics"
                .to_string(),
        );
    }
    Ok((
        dataset_hint(p),
        format!("cidrMatch({field}, \"{cidr}\")"),
        notes,
    ))
}

fn has_ambiguous_network_subset(predicates: &[IrPredicate]) -> bool {
    let has_src_subset = predicates.iter().any(|p| {
        p.op == IrOp::IsSubset
            && (p.target.as_str(), p.field.as_str()) == ("network-traffic", "src_ref.value")
    });
    let has_dst_subset = predicates.iter().any(|p| {
        p.op == IrOp::IsSubset
            && (p.target.as_str(), p.field.as_str()) == ("network-traffic", "dst_ref.value")
    });
    let has_src_type = predicates.iter().any(|p| {
        p.op == IrOp::Eq
            && (p.target.as_str(), p.field.as_str()) == ("network-traffic", "src_ref.type")
    });
    let has_dst_type = predicates.iter().any(|p| {
        p.op == IrOp::Eq
            && (p.target.as_str(), p.field.as_str()) == ("network-traffic", "dst_ref.type")
    });
    (has_src_subset && !has_src_type) || (has_dst_subset && !has_dst_type)
}

fn merge_dataset(lhs: Option<String>, rhs: Option<String>) -> Option<String> {
    match (lhs, rhs) {
        (Some(a), Some(b)) if a == b => Some(a),
        (Some(_), Some(_)) => None,
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn expand_conjunctions(ir: &IrExpr) -> Result<Vec<Vec<IrPredicate>>> {
    match ir {
        IrExpr::Predicate(p) => Ok(vec![vec![p.clone()]]),
        IrExpr::All(exprs) => {
            let mut acc: Vec<Vec<IrPredicate>> = vec![Vec::new()];
            for e in exprs {
                let part = expand_conjunctions(e)?;
                let mut next = Vec::new();
                for left in &acc {
                    for right in &part {
                        let mut combined = left.clone();
                        combined.extend(right.clone());
                        next.push(combined);
                    }
                }
                acc = next;
            }
            Ok(acc)
        }
        IrExpr::Any(exprs) => {
            let mut res = Vec::new();
            for e in exprs {
                res.extend(expand_conjunctions(e)?);
            }
            Ok(res)
        }
        IrExpr::FollowedBy(_) => bail!("FOLLOWEDBY sequence cannot be lowered as conjunction"),
        IrExpr::Qualified(inner, _) => expand_conjunctions(inner),
    }
}

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use pest::iterators::Pair;

use crate::ast::{CompareOp, Comparison, Expr, ObservationQualifier, Pattern, Value};

use super::parse::Rule;

pub fn to_ast(pair: Pair<'_, Rule>) -> Result<Pattern> {
    let mut inner = pair.into_inner();
    let expr_pair = inner.next().ok_or_else(|| anyhow!("missing expr"))?;
    Ok(Pattern {
        expr: build_expr(expr_pair)?,
    })
}

fn build_expr(pair: Pair<'_, Rule>) -> Result<Expr> {
    match pair.as_rule() {
        Rule::rule => {
            let inner = pair
                .into_inner()
                .next()
                .ok_or_else(|| anyhow!("missing pattern expression"))?;
            build_expr(inner)
        }
        Rule::observation_expressions => {
            let mut inner = pair.into_inner();
            let first = inner
                .next()
                .ok_or_else(|| anyhow!("missing observation expression"))?;
            let mut parts = vec![build_expr(first)?];
            for next in inner {
                parts.push(build_expr(next)?);
            }
            if parts.len() == 1 {
                Ok(parts.remove(0))
            } else {
                Ok(Expr::FollowedBy(parts))
            }
        }
        Rule::observation_expression => {
            let mut inner = pair.into_inner();
            let first = inner
                .next()
                .ok_or_else(|| anyhow!("missing observation expr inner"))?;
            let expr = build_expr(first)?;
            apply_observation_qualifiers(expr, inner)
        }
        Rule::observation_or => fold_or(pair.into_inner()),
        Rule::observation_and => fold_and(pair.into_inner()),
        Rule::observation_term => {
            let mut inner = pair.into_inner();
            let first = inner
                .next()
                .ok_or_else(|| anyhow!("missing observation term"))?;
            let expr = build_expr(first)?;
            let mut qualifiers = Vec::new();

            for q in inner {
                push_qualifier_checked(&mut qualifiers, parse_qualifier(q)?)?;
            }

            if qualifiers.is_empty() {
                Ok(expr)
            } else {
                Ok(Expr::Qualified(Box::new(expr), qualifiers))
            }
        }
        Rule::observation_primary => {
            let inner = pair
                .into_inner()
                .next()
                .ok_or_else(|| anyhow!("missing observation primary"))?;
            build_expr(inner)
        }
        Rule::bracket_expr => {
            let inner = pair
                .into_inner()
                .next()
                .ok_or_else(|| anyhow!("missing bracketed comparison"))?;
            build_expr(inner)
        }
        Rule::comparison_expr => fold_or(pair.into_inner()),
        Rule::comparison_and => fold_and(pair.into_inner()),
        Rule::comparison_term => {
            let inner = pair
                .into_inner()
                .next()
                .ok_or_else(|| anyhow!("missing comparison term"))?;
            build_expr(inner)
        }
        Rule::qualifier => Err(anyhow!(
            "qualifier node is not expected at top-level transform stage"
        )),
        Rule::prop_test => build_comparison(pair),
        _ => Err(anyhow!(
            "unsupported rule in AST transform: {:?}",
            pair.as_rule()
        )),
    }
}

fn apply_observation_qualifiers<'a>(
    expr: Expr,
    qualifiers_iter: impl Iterator<Item = Pair<'a, Rule>>,
) -> Result<Expr> {
    let mut qualifiers = Vec::new();
    for q in qualifiers_iter {
        push_qualifier_checked(&mut qualifiers, parse_qualifier(q)?)?;
    }
    if qualifiers.is_empty() {
        Ok(expr)
    } else {
        Ok(Expr::Qualified(Box::new(expr), qualifiers))
    }
}

fn push_qualifier_checked(
    qualifiers: &mut Vec<ObservationQualifier>,
    parsed: ParsedQualifier,
) -> Result<()> {
    match parsed {
        ParsedQualifier::Repeats(times) => {
            if qualifiers
                .iter()
                .any(|q| matches!(q, ObservationQualifier::RepeatsTimes(_)))
            {
                bail!("observation expression cannot contain more than one REPEATS qualifier");
            }
            qualifiers.push(ObservationQualifier::RepeatsTimes(times));
        }
        ParsedQualifier::Within(seconds) => {
            if qualifiers
                .iter()
                .any(|q| matches!(q, ObservationQualifier::WithinSeconds(_)))
            {
                bail!("observation expression cannot contain more than one WITHIN qualifier");
            }
            qualifiers.push(ObservationQualifier::WithinSeconds(seconds));
        }
        ParsedQualifier::StartStop { start, stop } => {
            if qualifiers
                .iter()
                .any(|q| matches!(q, ObservationQualifier::StartStop { .. }))
            {
                bail!("observation expression cannot contain more than one START/STOP qualifier");
            }
            qualifiers.push(ObservationQualifier::StartStop { start, stop });
        }
    }
    Ok(())
}

enum ParsedQualifier {
    Repeats(i64),
    Within(f64),
    StartStop { start: String, stop: String },
}

fn parse_qualifier(pair: Pair<'_, Rule>) -> Result<ParsedQualifier> {
    let inner = pair
        .into_inner()
        .next()
        .ok_or_else(|| anyhow!("missing qualifier body"))?;
    match inner.as_rule() {
        Rule::repeated_qualifier => {
            let mut it = inner.into_inner();
            let n = it
                .find(|p| matches!(p.as_rule(), Rule::int_pos_literal))
                .ok_or_else(|| anyhow!("missing REPEATS count"))?
                .as_str()
                .parse::<i64>()?;
            if n <= 0 {
                bail!("REPEATS requires a strictly positive integer");
            }
            Ok(ParsedQualifier::Repeats(n))
        }
        Rule::within_qualifier => {
            let mut seconds: Option<f64> = None;
            for p in inner.into_inner() {
                match p.as_rule() {
                    Rule::int_pos_literal | Rule::float_pos_literal => {
                        seconds = Some(p.as_str().parse::<f64>()?);
                    }
                    _ => {}
                }
            }
            let secs = seconds.ok_or_else(|| anyhow!("missing WITHIN seconds"))?;
            if secs <= 0.0 {
                bail!("WITHIN requires a strictly positive seconds value");
            }
            Ok(ParsedQualifier::Within(secs))
        }
        Rule::start_stop_qualifier => {
            let mut stamps = Vec::new();
            for p in inner.into_inner() {
                if p.as_rule() == Rule::timestamp_literal {
                    stamps.push(trim_timestamp(p.as_str()));
                }
            }
            if stamps.len() != 2 {
                bail!("START/STOP requires two timestamps");
            }
            Ok(ParsedQualifier::StartStop {
                start: stamps[0].clone(),
                stop: stamps[1].clone(),
            })
        }
        _ => bail!("unsupported qualifier"),
    }
}

fn fold_or<'a>(inner: impl Iterator<Item = Pair<'a, Rule>>) -> Result<Expr> {
    let mut iter = inner;
    let first = iter
        .next()
        .ok_or_else(|| anyhow!("missing left-hand expression"))?;
    let mut expr = build_expr(first)?;

    for rhs in iter {
        expr = Expr::Or(Box::new(expr), Box::new(build_expr(rhs)?));
    }

    Ok(expr)
}

fn fold_and<'a>(inner: impl Iterator<Item = Pair<'a, Rule>>) -> Result<Expr> {
    let mut iter = inner;
    let first = iter
        .next()
        .ok_or_else(|| anyhow!("missing left-hand expression"))?;
    let mut expr = build_expr(first)?;

    for rhs in iter {
        expr = Expr::And(Box::new(expr), Box::new(build_expr(rhs)?));
    }

    Ok(expr)
}

fn build_comparison(pair: Pair<'_, Rule>) -> Result<Expr> {
    let mut inner = pair.clone().into_inner();
    let first = inner
        .next()
        .ok_or_else(|| anyhow!("missing object path in comparison"))?;

    if matches!(first.as_rule(), Rule::NOT | Rule::EXISTS) {
        bail!("Only simple equality comparisons are supported for now (no NOT/EXISTS)");
    }

    let object_path = first;

    // Look ahead for optional NOT
    let next = inner.next();
    if matches!(next.as_ref().map(|p| p.as_rule()), Some(Rule::NOT)) {
        bail!("Negated comparisons (NOT) are not supported yet");
    }

    let op_pair = next.ok_or_else(|| anyhow!("missing operator in comparison"))?;
    let raw_literal = if op_pair.as_rule() == Rule::MATCHES {
        recover_regex_literal(pair.as_str())
    } else {
        None
    };
    let value = if let Some(lit) = raw_literal {
        Value::String(lit)
    } else {
        let value_pair = inner
            .next()
            .ok_or_else(|| anyhow!("missing value in comparison"))?;
        build_value(value_pair)?
    };

    let (object_type, field) = parse_object_path(object_path)?;

    let op = match op_pair.as_rule() {
        Rule::eq_op => CompareOp::Eq,
        Rule::neq_op => CompareOp::Ne,
        Rule::gt_op => CompareOp::Gt,
        Rule::lt_op => CompareOp::Lt,
        Rule::ge_op => CompareOp::Ge,
        Rule::le_op => CompareOp::Le,
        Rule::LIKE => CompareOp::Like,
        Rule::MATCHES => CompareOp::Matches,
        Rule::ISSUBSET => CompareOp::IsSubset,
        _ => bail!("unsupported operator"),
    };

    Ok(Expr::Comparison(Comparison {
        object_type,
        field,
        op,
        value,
    }))
}

fn recover_regex_literal(src: &str) -> Option<String> {
    let upper = src.to_uppercase();
    let idx = upper.find("MATCHES")?;
    let tail = src[idx + "MATCHES".len()..].trim();
    let start = tail.find('\'')?;
    let tail2 = &tail[start + 1..];
    let end = tail2.rfind('\'')?;
    Some(tail2[..end].to_string())
}

fn parse_object_path(pair: Pair<'_, Rule>) -> Result<(String, String)> {
    let mut inner = pair.into_inner();
    let object_type = inner
        .next()
        .ok_or_else(|| anyhow!("missing object type"))?
        .as_str()
        .to_string();

    let field_component = inner
        .next()
        .ok_or_else(|| anyhow!("missing field path component"))?;

    let mut parts = Vec::new();
    parts.push(parse_field_piece(field_component)?);

    for component in inner {
        let mut comp_inner = component.into_inner();
        let piece = comp_inner
            .next()
            .ok_or_else(|| anyhow!("missing nested field component"))?;
        let piece_str = parse_field_piece(piece)?;
        if piece_str.starts_with('[') {
            if let Some(last) = parts.last_mut() {
                last.push_str(&piece_str);
                continue;
            }
        }
        parts.push(piece_str);
    }

    Ok((object_type, parts.join(".")))
}

fn parse_field_piece(piece: Pair<'_, Rule>) -> Result<String> {
    Ok(match piece.as_rule() {
        Rule::first_path_component => {
            let mut inner = piece.into_inner();
            let inner_piece = inner
                .next()
                .ok_or_else(|| anyhow!("missing field identifier"))?;
            parse_field_piece(inner_piece)?
        }
        Rule::key_path_step => {
            let mut inner = piece.into_inner();
            let inner_piece = inner
                .next()
                .ok_or_else(|| anyhow!("missing key path component"))?;
            parse_field_piece(inner_piece)?
        }
        Rule::index_path_step => {
            let raw = piece.as_str().to_string();
            let mut inner = piece.into_inner();
            let inner_piece = match inner.next() {
                Some(v) => v,
                None => {
                    if raw == "[*]" {
                        return Ok("[*]".to_string());
                    }
                    bail!("missing index component");
                }
            };
            match inner_piece.as_rule() {
                Rule::int_pos_literal | Rule::int_neg_literal | Rule::string_literal => {
                    format!("[{}]", inner_piece.as_str())
                }
                _ if inner_piece.as_str() == "*" => "[*]".to_string(),
                _ => bail!("unsupported index component"),
            }
        }
        Rule::identifier_without_hyphen => piece.as_str().to_string(),
        Rule::string_literal => trim_quotes(piece.as_str()),
        _ => bail!("unsupported field path component"),
    })
}

fn build_value(pair: Pair<'_, Rule>) -> Result<Value> {
    match pair.as_rule() {
        Rule::primitive_literal => {
            let raw = pair.as_str().to_string();
            let mut inner = pair.into_inner();
            if let Some(concrete) = inner.next() {
                build_value(concrete)
            } else {
                match raw.as_str() {
                    "true" => Ok(Value::Boolean(true)),
                    "false" => Ok(Value::Boolean(false)),
                    _ => Err(anyhow!("missing literal value")),
                }
            }
        }
        Rule::orderable_literal => {
            let mut inner = pair.into_inner();
            let concrete = inner
                .next()
                .ok_or_else(|| anyhow!("missing literal value"))?;
            build_value(concrete)
        }
        Rule::string_literal => Ok(Value::String(trim_quotes(pair.as_str()))),
        Rule::int_pos_literal | Rule::int_neg_literal => Ok(Value::Integer(pair.as_str().parse()?)),
        Rule::binary_literal => Ok(Value::Hex(binary_to_hex(trim_binary(pair.as_str()))?)),
        Rule::hex_literal => Ok(Value::Hex(trim_hex(pair.as_str()))),
        Rule::timestamp_literal => Ok(Value::Timestamp(trim_timestamp(pair.as_str()))),
        Rule::bool_literal => {
            let val = match pair.as_str() {
                "true" => true,
                "false" => false,
                _ => bail!("invalid boolean literal"),
            };
            Ok(Value::Boolean(val))
        }
        Rule::TRUE => Ok(Value::Boolean(true)),
        Rule::FALSE => Ok(Value::Boolean(false)),
        _ => bail!("Unsupported literal type in this MVP"),
    }
}

fn trim_quotes(raw: &str) -> String {
    let inner = raw.trim_matches('\'');
    unescape_stix_string(inner)
}

fn unescape_stix_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.peek().copied() {
                Some('\\') => {
                    chars.next();
                    out.push('\\');
                }
                Some('\'') => {
                    chars.next();
                    out.push('\'');
                }
                Some(next) => {
                    // Keep unknown escapes verbatim to avoid changing semantics implicitly.
                    chars.next();
                    out.push('\\');
                    out.push(next);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn trim_hex(raw: &str) -> String {
    raw.trim_start_matches("h'")
        .trim_end_matches('\'')
        .to_string()
}

fn trim_binary(raw: &str) -> String {
    raw.trim_start_matches("b'")
        .trim_end_matches('\'')
        .to_string()
}

fn trim_timestamp(raw: &str) -> String {
    raw.trim_start_matches("t'")
        .trim_end_matches('\'')
        .to_string()
}

fn binary_to_hex(base64_text: String) -> Result<String> {
    let normalized: String = base64_text
        .chars()
        .filter(|c| *c != '\n' && *c != '\r')
        .collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(normalized.as_bytes())
        .map_err(|e| anyhow!("invalid binary literal (base64): {e}"))?;
    Ok(bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>())
}

use anyhow::{Result, bail};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::ast::{CompareOp, Expr, ObservationQualifier, Pattern, Value};
use crate::ir::{IrExpr, IrOp, IrPredicate, IrQualifier, IrValue};

pub fn stix_to_ir(pattern: &Pattern) -> Result<IrExpr> {
    lower_expr(&pattern.expr)
}

fn lower_expr(expr: &Expr) -> Result<IrExpr> {
    match expr {
        Expr::Comparison(cmp) => {
            let (object_type, field) = canonicalize_stix_path(&cmp.object_type, &cmp.field);
            validate_stix21_path(&object_type, &field)?;
            validate_value_type(&object_type, &field, &cmp.value)?;
            if matches!(cmp.op, CompareOp::IsSubset) {
                if !matches_subset_scope(&object_type, &field) {
                    bail!(
                        "ISSUBSET is not supported for {}:{} in STIX 2.1 network calibration scope",
                        object_type,
                        field
                    );
                }
                match &cmp.value {
                    Value::String(s) if is_valid_cidr_literal(s) => {}
                    _ => {
                        bail!(
                            "ISSUBSET for {}:{} requires a CIDR literal on the right-hand side",
                            object_type,
                            field
                        );
                    }
                }
            }

            let value = match &cmp.value {
                Value::String(v) => IrValue::String(v.clone()),
                Value::Integer(v) => IrValue::Integer(*v),
                Value::Boolean(v) => IrValue::Boolean(*v),
                Value::Hex(v) => IrValue::Hex(v.clone()),
                Value::Timestamp(v) => IrValue::Timestamp(v.clone()),
            };

            Ok(IrExpr::Predicate(IrPredicate {
                target: object_type.clone(),
                field: field.clone(),
                op: match cmp.op {
                    CompareOp::Eq => IrOp::Eq,
                    CompareOp::Ne => IrOp::Ne,
                    CompareOp::Gt => IrOp::Gt,
                    CompareOp::Ge => IrOp::Ge,
                    CompareOp::Lt => IrOp::Lt,
                    CompareOp::Le => IrOp::Le,
                    // LIKE is lowered to MATCHES so emitters only handle one regex-like op.
                    CompareOp::Like => IrOp::Matches,
                    CompareOp::Matches => IrOp::Matches,
                    CompareOp::IsSubset => IrOp::IsSubset,
                },
                value: match (object_type.as_str(), field.as_str(), &cmp.op, value) {
                    // artifact:payload_bin equality compares byte sequences.
                    // Plain string literals are byte strings, not base64/hex encodings.
                    (
                        "artifact",
                        "payload_bin",
                        CompareOp::Eq | CompareOp::Ne,
                        IrValue::String(s),
                    ) => IrValue::Hex(string_to_hex_bytes(&s)?),
                    // Allow binary literals on MATCHES by turning bytes into \xNN regex escapes.
                    ("artifact", "payload_bin", CompareOp::Matches, IrValue::Hex(h)) => {
                        IrValue::String(hex_to_regex_bytes(&h)?)
                    }
                    // STIX string literals keep escaped backslashes; normalize common byte-regex
                    // escapes so downstream engines receive real byte escapes (\xNN).
                    ("artifact", "payload_bin", CompareOp::Matches, IrValue::String(s)) => {
                        IrValue::String(normalize_payload_regex_escapes(&s))
                    }
                    (_, _, CompareOp::Like, IrValue::String(pattern)) => {
                        IrValue::String(like_to_regex(&pattern))
                    }
                    (_, _, _, v) => v,
                },
            }))
        }
        Expr::And(left, right) => Ok(IrExpr::All(vec![lower_expr(left)?, lower_expr(right)?])),
        Expr::Or(left, right) => Ok(IrExpr::Any(vec![lower_expr(left)?, lower_expr(right)?])),
        Expr::FollowedBy(parts) => {
            let mut lowered = Vec::with_capacity(parts.len());
            for part in parts {
                lowered.push(lower_expr(part)?);
            }
            Ok(IrExpr::FollowedBy(lowered))
        }
        Expr::Qualified(inner, quals) => {
            let lowered = lower_expr(inner)?;
            let mut out = Vec::new();
            for q in quals {
                match q {
                    ObservationQualifier::WithinSeconds(s) => {
                        out.push(IrQualifier::WithinSeconds(*s))
                    }
                    ObservationQualifier::RepeatsTimes(n) => {
                        out.push(IrQualifier::RepeatsTimes(*n))
                    }
                    ObservationQualifier::StartStop { start, stop } => {
                        out.push(IrQualifier::StartStop {
                            start: start.clone(),
                            stop: stop.clone(),
                        })
                    }
                }
            }
            Ok(IrExpr::Qualified(Box::new(lowered), out))
        }
    }
}

fn validate_stix21_path(object_type: &str, field: &str) -> Result<()> {
    // Custom extension object paths are allowed by design.
    if object_type.starts_with("x-") {
        return Ok(());
    }

    if (object_type, field) == ("domain-name", "resolves_to_refs[*].value") {
        bail!(
            "normalization_not_implemented: reference traversal is outside current normalization scope for STIX 2.1 path {}:{}",
            object_type,
            field
        );
    }

    let ok = match (object_type, field) {
        ("artifact", "mime_type") | ("artifact", "payload_bin") => true,
        ("artifact", f) if f.starts_with("hashes.") => true,

        ("domain-name", "value") => true,
        ("url", "value") => true,
        ("autonomous-system", "number")
        | ("autonomous-system", "name")
        | ("autonomous-system", "rir") => true,

        ("email-message", "body")
        | ("email-message", "subject")
        | ("email-message", "from_ref.value")
        | ("email-message", "sender_ref.value")
        | ("email-message", "to_refs[*].value")
        | ("email-message", "body_multipart[*].body_raw_ref.name") => true,
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.") => true,

        ("file", "name")
        | ("file", "mime_type")
        | ("file", "size")
        | ("file", "magic_number_hex")
        | ("file", "ctime")
        | ("file", "mtime")
        | ("file", "atime") => true,
        ("file", f) if f.starts_with("hashes.") => true,
        ("directory", "path")
        | ("directory", "ctime")
        | ("directory", "mtime")
        | ("directory", "atime") => true,

        ("ipv4-addr", "value") | ("ipv6-addr", "value") | ("mac-addr", "value") => true,

        ("network-traffic", "src_ref.value")
        | ("network-traffic", "dst_ref.value")
        | ("network-traffic", "src_ref.type")
        | ("network-traffic", "dst_ref.type")
        | ("network-traffic", "src_port")
        | ("network-traffic", "dst_port")
        | ("network-traffic", "protocols") => true,

        ("process", "name") | ("process", "command_line") | ("process", "image_ref.name") => true,
        ("process", "pid")
        | ("process", "is_hidden")
        | ("process", "cwd")
        | ("process", "created_time")
        | ("process", "parent_ref.command_line") => true,
        ("process", f) if f.starts_with("image_ref.hashes.") => true,

        ("user-account", "account_type")
        | ("user-account", "user_id")
        | ("user-account", "account_login") => true,

        ("windows-registry-key", "key")
        | ("windows-registry-key", "number_of_subkeys")
        | ("windows-registry-key", "values[*].name")
        | ("windows-registry-key", "values[*].data")
        | ("windows-registry-key", "values[*].data_type")
        | ("windows-registry-key", "modified_time") => true,

        ("x509-certificate", "issuer") | ("x509-certificate", "serial_number") => true,
        _ => false,
    };

    if ok {
        Ok(())
    } else {
        bail!(
            "stix21_invalid_or_unsupported_path: {}:{} is not valid in this STIX 2.1 normalization scope",
            object_type,
            field
        )
    }
}

fn canonicalize_stix_path(object_type: &str, field: &str) -> (String, String) {
    match (object_type, field) {
        ("win-registry-key", f) => ("windows-registry-key".to_string(), f.to_string()),
        ("file", "created") => ("file".to_string(), "ctime".to_string()),
        ("file", "modified") => ("file".to_string(), "mtime".to_string()),
        ("file", "accessed") => ("file".to_string(), "atime".to_string()),
        ("file", "parent_directory_ref.path") => {
            ("directory".to_string(), "path".to_string())
        }
        (o, f) => (o.to_string(), f.to_string()),
    }
}

fn validate_value_type(object_type: &str, field: &str, value: &Value) -> Result<()> {
    let needs_timestamp = match (object_type, field) {
        ("file", "ctime")
        | ("file", "mtime")
        | ("file", "atime")
        | ("directory", "ctime")
        | ("directory", "mtime")
        | ("directory", "atime")
        | ("windows-registry-key", "modified_time") => true,
        ("process", "created_time") => true,
        _ => false,
    };
    if needs_timestamp && !matches!(value, Value::Timestamp(_)) {
        bail!(
            "timestamp value required for temporal object path {}:{}",
            object_type,
            field
        );
    }
    if (object_type, field) == ("autonomous-system", "number")
        && !matches!(value, Value::Integer(_))
    {
        bail!("integer value required for autonomous-system:number");
    }
    Ok(())
}

fn matches_subset_scope(object_type: &str, field: &str) -> bool {
    matches!(
        (object_type, field),
        ("ipv4-addr", "value")
            | ("ipv6-addr", "value")
            | ("network-traffic", "src_ref.value")
            | ("network-traffic", "dst_ref.value")
    )
}

fn is_valid_cidr_literal(v: &str) -> bool {
    if let Some((ip, prefix)) = v.split_once('/') {
        if let Ok(ip4) = ip.parse::<Ipv4Addr>() {
            return prefix.parse::<u8>().map(|p| p <= 32).unwrap_or(false)
                && ip4.octets().len() == 4;
        }
        if let Ok(ip6) = ip.parse::<Ipv6Addr>() {
            return prefix.parse::<u8>().map(|p| p <= 128).unwrap_or(false)
                && ip6.segments().len() == 8;
        }
    }
    false
}

fn like_to_regex(pattern: &str) -> String {
    let mut out = String::from("^");
    for ch in pattern.chars() {
        match ch {
            '%' => out.push_str(".*"),
            '_' => out.push('.'),
            '.' | '^' | '$' | '|' | '(' | ')' | '[' | ']' | '{' | '}' | '*' | '+' | '?' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out.push('$');
    out
}

fn string_to_hex_bytes(s: &str) -> Result<String> {
    let mut out = String::new();
    for ch in s.chars() {
        let cp = ch as u32;
        if cp > 0xFF {
            bail!("artifact:payload_bin string literal contains code point > U+00FF");
        }
        out.push_str(&format!("{:02x}", cp as u8));
    }
    Ok(out)
}

fn hex_to_regex_bytes(hex: &str) -> Result<String> {
    let clean = hex.replace(|c: char| c.is_whitespace(), "");
    if clean.len() % 2 != 0 {
        bail!("binary literal must contain an even number of hex digits");
    }
    if !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("binary literal contains non-hex characters");
    }
    let mut out = String::new();
    let mut i = 0;
    while i < clean.len() {
        out.push_str("\\x");
        out.push_str(&clean[i..i + 2]);
        i += 2;
    }
    Ok(out)
}

fn normalize_payload_regex_escapes(s: &str) -> String {
    s.replace("\\\\x", "\\x")
}

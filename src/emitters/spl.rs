#![allow(dead_code)]

use anyhow::{Result, bail};

use crate::emitters::{EmitResult, FidelityStatus};
use crate::ir::{IrExpr, IrOp, IrPredicate, IrValue};

pub fn emit(ir: &IrExpr, _description: Option<&str>) -> Result<EmitResult> {
    if matches!(ir, IrExpr::FollowedBy(_)) {
        return Ok(EmitResult::unsupported(
            "SPL emitter does NOT support FOLLOWEDBY sequence semantics in this baseline",
        ));
    }
    let disjuncts = expand_conjunctions(ir)?;
    let mut parts = Vec::new();
    let mut notes = Vec::new();
    for conj in disjuncts {
        let (expr, expr_notes) = lower_all(&conj)?;
        notes.extend(expr_notes);
        parts.push(format!("({})", expr));
    }

    let status = if notes.is_empty() {
        FidelityStatus::Exact
    } else {
        FidelityStatus::Partial
    };

    Ok(EmitResult {
        status,
        notes,
        rule: Some(format!("search {}", parts.join(" OR "))),
        cause: None,
    })
}

fn lower_all(predicates: &[IrPredicate]) -> Result<(String, Vec<String>)> {
    let mut parts = Vec::new();
    let mut notes = Vec::new();
    for p in predicates {
        let (part, n) = lower_predicate(p)?;
        parts.push(part);
        notes.extend(n);
    }
    Ok((parts.join(" "), notes))
}

fn lower_predicate(p: &IrPredicate) -> Result<(String, Vec<String>)> {
    let (field, notes) = map_field(p)?;
    let value = match &p.value {
        IrValue::String(s) => format!("\"{}\"", s),
        IrValue::Integer(i) => i.to_string(),
        IrValue::Boolean(b) => b.to_string(),
        IrValue::Hex(_) => bail!("SPL emitter does not support hex literals"),
        IrValue::Timestamp(ts) => format!("\"{ts}\""),
    };

    let op = match p.op {
        IrOp::Eq => "=",
        IrOp::Ne => "!=",
        IrOp::Gt => ">",
        IrOp::Ge => ">=",
        IrOp::Lt => "<",
        IrOp::Le => "<=",
        IrOp::Matches => "MATCHES",
        IrOp::IsSubset => "ISSUBSET",
    };

    let rendered = if p.op == IrOp::Matches {
        format!("regex {field}={}", value)
    } else {
        format!("{field}{op}{value}")
    };

    Ok((rendered, notes))
}

fn map_field(p: &IrPredicate) -> Result<(String, Vec<String>)> {
    match (p.target.as_str(), p.field.as_str()) {
        ("network-traffic", "dst_ref.value") | ("ipv4-addr", "value") => {
            Ok(("dest_ip".to_string(), Vec::new()))
        }
        ("network-traffic", "src_ref.value") => Ok(("src_ip".to_string(), Vec::new())),
        ("network-traffic", "src_port") => Ok(("src_port".to_string(), Vec::new())),
        ("network-traffic", "dst_port") => Ok(("dest_port".to_string(), Vec::new())),
        ("process", "command_line") => Ok(("process".to_string(), Vec::new())),
        ("file", "name") => Ok(("file_name".to_string(), Vec::new())),
        ("file", "size") => Ok((
            "file_size".to_string(),
            vec!["Splunk CIM uses file_size in kilobytes; verify unit conversion".to_string()],
        )),
        ("file", f) if f.starts_with("hashes.MD5") => Ok(("file_hash_md5".to_string(), Vec::new())),
        ("file", f) if f.starts_with("hashes.SHA-1") => {
            Ok(("file_hash_sha1".to_string(), Vec::new()))
        }
        ("file", f) if f.starts_with("hashes.SHA-256") => {
            Ok(("file_hash_sha256".to_string(), Vec::new()))
        }
        ("file", f) if f.starts_with("hashes.SHA-512") => {
            Ok(("file_hash_sha512".to_string(), Vec::new()))
        }
        ("file", f) if f.starts_with("hashes.SHA3-256") => {
            Ok(("file_hash_sha3_256".to_string(), Vec::new()))
        }
        ("file", f) if f.starts_with("hashes.SHA3-512") => {
            Ok(("file_hash_sha3_512".to_string(), Vec::new()))
        }
        ("file", f) if f.starts_with("hashes.SSDEEP") => {
            Ok(("file_hash_ssdeep".to_string(), Vec::new()))
        }
        ("file", f) if f.starts_with("hashes.TLSH") => {
            Ok(("file_hash_tlsh".to_string(), Vec::new()))
        }
        ("artifact", f) if f.starts_with("hashes.MD5") => {
            Ok(("artifact_hash_md5".to_string(), Vec::new()))
        }
        ("artifact", f) if f.starts_with("hashes.SHA-1") => {
            Ok(("artifact_hash_sha1".to_string(), Vec::new()))
        }
        ("artifact", f) if f.starts_with("hashes.SHA-256") => {
            Ok(("artifact_hash_sha256".to_string(), Vec::new()))
        }
        ("artifact", f) if f.starts_with("hashes.SHA-512") => {
            Ok(("artifact_hash_sha512".to_string(), Vec::new()))
        }
        ("artifact", f) if f.starts_with("hashes.SHA3-256") => {
            Ok(("artifact_hash_sha3_256".to_string(), Vec::new()))
        }
        ("artifact", f) if f.starts_with("hashes.SHA3-512") => {
            Ok(("artifact_hash_sha3_512".to_string(), Vec::new()))
        }
        ("artifact", f) if f.starts_with("hashes.SSDEEP") => {
            Ok(("artifact_hash_ssdeep".to_string(), Vec::new()))
        }
        ("artifact", f) if f.starts_with("hashes.TLSH") => {
            Ok(("artifact_hash_tlsh".to_string(), Vec::new()))
        }
        ("ipv6-addr", "value") => Ok((
            "dest_ip".to_string(),
            vec!["also consider src_ip".to_string()],
        )),
        ("mac-addr", "value") => Ok((
            "dest_mac".to_string(),
            vec!["also consider src_mac".to_string()],
        )),
        ("network-traffic", "protocols") => Ok(("protocol".to_string(), Vec::new())),
        ("domain-name", "value") => Ok(("dest_domain".to_string(), Vec::new())),
        ("user-account", "account_type") => Ok(("user_account_type".to_string(), Vec::new())),
        ("user-account", "user_id") => Ok(("user_id".to_string(), Vec::new())),
        ("user-account", "account_login") => Ok(("user".to_string(), Vec::new())),
        ("windows-registry-key", "key") => Ok(("registry_key".to_string(), Vec::new())),
        ("windows-registry-key", "values[*].name") => {
            Ok(("registry_value_name".to_string(), Vec::new()))
        }
        ("windows-registry-key", "values[*].data") => {
            Ok(("registry_value_data".to_string(), Vec::new()))
        }
        ("windows-registry-key", "modified_time") => {
            Ok(("registry_modified_time".to_string(), Vec::new()))
        }
        ("file", "created") => Ok((
            "file_create_time".to_string(),
            vec!["Assuming CIM field file_create_time; requires CIM mapping".to_string()],
        )),
        ("email-message", "from_ref.value") => Ok(("email_from".to_string(), Vec::new())),
        ("email-message", "sender_ref.value") => Ok(("email_sender".to_string(), Vec::new())),
        ("email-message", "to_refs[*].value") => Ok(("email_to".to_string(), Vec::new())),
        ("email-message", "subject") => Ok(("email_subject".to_string(), Vec::new())),
        ("email-message", "body") => Ok(("email_body".to_string(), Vec::new())),
        ("email-message", "body_multipart[*].body_raw_ref.name") => {
            Ok(("attachment_name".to_string(), Vec::new()))
        }
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.'MD5'") => {
            Ok(("attachment_md5".to_string(), Vec::new()))
        }
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA-1'") => {
            Ok(("attachment_sha1".to_string(), Vec::new()))
        }
        ("email-message", f)
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA-256'") =>
        {
            Ok(("attachment_sha256".to_string(), Vec::new()))
        }
        ("email-message", f)
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA-512'") =>
        {
            Ok(("attachment_sha512".to_string(), Vec::new()))
        }
        ("email-message", f)
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA3-256'") =>
        {
            Ok(("attachment_sha3_256".to_string(), Vec::new()))
        }
        ("email-message", f)
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA3-512'") =>
        {
            Ok(("attachment_sha3_512".to_string(), Vec::new()))
        }
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.SSDEEP") => {
            Ok(("attachment_ssdeep".to_string(), Vec::new()))
        }
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.TLSH") => {
            Ok(("attachment_tlsh".to_string(), Vec::new()))
        }
        _ => bail!(
            "SPL emitter does not support predicate {}:{}",
            p.target,
            p.field
        ),
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
        IrExpr::FollowedBy(_) => {
            bail!("SPL does NOT support FOLLOWEDBY sequence semantics in this baseline")
        }
        IrExpr::Qualified(_, _) => bail!("SPL does NOT support observation qualifiers yet"),
    }
}

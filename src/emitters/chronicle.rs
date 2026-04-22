#![allow(dead_code)]

use anyhow::{bail, Result};

use crate::emitters::{EmitResult, FidelityStatus};
use crate::ir::{IrExpr, IrOp, IrPredicate, IrValue};

pub fn emit(ir: &IrExpr, description: Option<&str>) -> Result<EmitResult> {
    let predicates = match ir {
        IrExpr::Predicate(p) => vec![p.clone()],
        IrExpr::All(exprs) => collect_predicates(exprs)?,
        IrExpr::Any(_) => {
            return Ok(EmitResult::unsupported(
                "Chronicle emitter does not support OR yet",
            ));
        }
        IrExpr::FollowedBy(_) => {
            return Ok(EmitResult::unsupported(
                "Chronicle emitter does not support FOLLOWEDBY sequence semantics yet",
            ));
        }
        IrExpr::Qualified(_, _) => {
            return Ok(EmitResult::unsupported(
                "Chronicle emitter does NOT support observation qualifiers yet",
            ));
        }
    };

    let mut event_lines = Vec::new();
    for p in predicates {
        event_lines.push(lower_predicate(&p)?);
    }

    let events_block = event_lines
        .into_iter()
        .map(|e| format!("    $e.{e}"))
        .collect::<Vec<_>>()
        .join("\n");

    let header = description
        .map(|d| format!("rule \"[SPUC Generated Chronicle Rule] {d}\" {{"))
        .unwrap_or_else(|| "rule \"[SPUC Generated Chronicle Rule]\" {".to_string());
    let rule = format!("{header}\n  events:\n{events_block}\n\n  condition:\n    $e\n}}");
    Ok(EmitResult {
        status: FidelityStatus::Exact,
        notes: Vec::new(),
        rule: Some(rule),
        cause: None,
    })
}

fn lower_predicate(p: &IrPredicate) -> Result<String> {
    if p.op != IrOp::Eq {
        bail!("Chronicle emitter only supports equality comparisons");
    }

    match (p.target.as_str(), p.field.as_str(), &p.value) {
        ("process", "command_line", IrValue::String(v)) => {
            Ok(format!("process.command_line contains \"{v}\""))
        }
        ("process", "image_ref.name", IrValue::String(v)) => {
            Ok(format!("process.file.name = \"{v}\""))
        }
        ("network-traffic", "src_ref.value", IrValue::String(v)) => {
            Ok(format!("network.src.ip = \"{v}\""))
        }
        ("network-traffic", "src_port", IrValue::Integer(v)) => {
            Ok(format!("network.src.port = {v}"))
        }
        ("network-traffic", "dst_ref.value", IrValue::String(v)) => {
            Ok(format!("network.dest.ip = \"{v}\""))
        }
        ("network-traffic", "dst_port", IrValue::Integer(v)) => {
            Ok(format!("network.dest.port = {v}"))
        }
        ("network-traffic", "protocols", IrValue::String(v)) => {
            Ok(format!("network.protocol = \"{v}\""))
        }
        ("domain-name", "value", IrValue::String(v)) => {
            Ok(format!("network.dest.domain = \"{v}\""))
        }
        ("file", "created", IrValue::Timestamp(v)) => Ok(format!("file.create_time = \"{v}\"")),
        ("file", "name", IrValue::String(v)) => Ok(format!("file.name = \"{v}\"")),
        ("file", "size", IrValue::Integer(v)) => Ok(format!("file.size = {v}")),
        ("file", f, IrValue::String(v)) if f.starts_with("hashes.MD5") => {
            Ok(format!("file.hash.md5 = \"{v}\""))
        }
        ("file", f, IrValue::String(v)) if f.starts_with("hashes.SHA-1") => {
            Ok(format!("file.hash.sha1 = \"{v}\""))
        }
        ("file", f, IrValue::String(v)) if f.starts_with("hashes.SHA-256") => {
            Ok(format!("file.hash.sha256 = \"{v}\""))
        }
        ("file", f, IrValue::String(v)) if f.starts_with("hashes.SHA-512") => {
            Ok(format!("file.hash.sha512 = \"{v}\""))
        }
        ("file", f, IrValue::String(v)) if f.starts_with("hashes.SHA3-256") => {
            Ok(format!("file.hash.sha3_256 = \"{v}\""))
        }
        ("file", f, IrValue::String(v)) if f.starts_with("hashes.SHA3-512") => {
            Ok(format!("file.hash.sha3_512 = \"{v}\""))
        }
        ("file", f, IrValue::String(v)) if f.starts_with("hashes.SSDEEP") => {
            Ok(format!("file.hash.ssdeep = \"{v}\""))
        }
        ("file", f, IrValue::String(v)) if f.starts_with("hashes.TLSH") => {
            Ok(format!("file.hash.tlsh = \"{v}\""))
        }
        ("artifact", f, IrValue::String(v)) if f.starts_with("hashes.MD5") => {
            Ok(format!("file.hash.md5 = \"{v}\""))
        }
        ("artifact", f, IrValue::String(v)) if f.starts_with("hashes.SHA-1") => {
            Ok(format!("file.hash.sha1 = \"{v}\""))
        }
        ("artifact", f, IrValue::String(v)) if f.starts_with("hashes.SHA-256") => {
            Ok(format!("file.hash.sha256 = \"{v}\""))
        }
        ("artifact", f, IrValue::String(v)) if f.starts_with("hashes.SHA-512") => {
            Ok(format!("file.hash.sha512 = \"{v}\""))
        }
        ("artifact", f, IrValue::String(v)) if f.starts_with("hashes.SHA3-256") => {
            Ok(format!("file.hash.sha3_256 = \"{v}\""))
        }
        ("artifact", f, IrValue::String(v)) if f.starts_with("hashes.SHA3-512") => {
            Ok(format!("file.hash.sha3_512 = \"{v}\""))
        }
        ("artifact", f, IrValue::String(v)) if f.starts_with("hashes.SSDEEP") => {
            Ok(format!("file.hash.ssdeep = \"{v}\""))
        }
        ("artifact", f, IrValue::String(v)) if f.starts_with("hashes.TLSH") => {
            Ok(format!("file.hash.tlsh = \"{v}\""))
        }
        ("user-account", "account_type", IrValue::String(v)) => Ok(format!("user.type = \"{v}\"")),
        ("user-account", "user_id", IrValue::String(v)) => Ok(format!("user.id = \"{v}\"")),
        ("user-account", "account_login", IrValue::String(v)) => Ok(format!("user.name = \"{v}\"")),
        ("ipv4-addr", "value", IrValue::String(v)) => Ok(format!("network.dest.ip = \"{v}\"")),
        ("ipv6-addr", "value", IrValue::String(v)) => Ok(format!("network.dest.ip = \"{v}\"")),
        ("mac-addr", "value", IrValue::String(v)) => Ok(format!("network.dest.mac = \"{v}\"")),
        ("artifact", f, IrValue::String(v)) if f.starts_with("hashes.MD5") => {
            Ok(format!("file.hash.md5 = \"{v}\""))
        }
        ("artifact", f, IrValue::String(v)) if f.starts_with("hashes.SHA-1") => {
            Ok(format!("file.hash.sha1 = \"{v}\""))
        }
        ("artifact", f, IrValue::String(v)) if f.starts_with("hashes.SHA-256") => {
            Ok(format!("file.hash.sha256 = \"{v}\""))
        }
        ("artifact", f, IrValue::String(v)) if f.starts_with("hashes.SHA-512") => {
            Ok(format!("file.hash.sha512 = \"{v}\""))
        }
        ("artifact", f, IrValue::String(v)) if f.starts_with("hashes.SHA3-256") => {
            Ok(format!("file.hash.sha3_256 = \"{v}\""))
        }
        ("artifact", f, IrValue::String(v)) if f.starts_with("hashes.SHA3-512") => {
            Ok(format!("file.hash.sha3_512 = \"{v}\""))
        }
        ("artifact", f, IrValue::String(v)) if f.starts_with("hashes.SSDEEP") => {
            Ok(format!("file.hash.ssdeep = \"{v}\""))
        }
        ("artifact", f, IrValue::String(v)) if f.starts_with("hashes.TLSH") => {
            Ok(format!("file.hash.tlsh = \"{v}\""))
        }
        ("windows-registry-key", "key", IrValue::String(v)) => {
            Ok(format!("registry.key = \"{v}\""))
        }
        ("windows-registry-key", "values[*].name", IrValue::String(v)) => {
            Ok(format!("registry.value = \"{v}\""))
        }
        ("windows-registry-key", "values[*].data", IrValue::String(v)) => {
            Ok(format!("registry.data = \"{v}\""))
        }
        ("windows-registry-key", "modified_time", IrValue::Timestamp(v)) => {
            Ok(format!("registry.modified_time = \"{v}\""))
        }
        ("email-message", "from_ref.value", IrValue::String(v))
        | ("email-message", "sender_ref.value", IrValue::String(v)) => {
            Ok(format!("email.from.address = \"{v}\""))
        }
        ("email-message", "subject", IrValue::String(v)) => Ok(format!("email.subject = \"{v}\"")),
        ("email-message", "body", IrValue::String(v)) => Ok(format!("email.body = \"{v}\"")),
        ("email-message", "to_refs[*].value", IrValue::String(v)) => {
            Ok(format!("email.to.address = \"{v}\""))
        }
        ("email-message", "body_multipart[*].body_raw_ref.name", IrValue::String(v)) => {
            Ok(format!("email.attachment.name = \"{v}\""))
        }
        ("email-message", f, IrValue::String(v))
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.'MD5'") =>
        {
            Ok(format!("email.attachment.hash.md5 = \"{v}\""))
        }
        ("email-message", f, IrValue::String(v))
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA-1'") =>
        {
            Ok(format!("email.attachment.hash.sha1 = \"{v}\""))
        }
        ("email-message", f, IrValue::String(v))
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA-256'") =>
        {
            Ok(format!("email.attachment.hash.sha256 = \"{v}\""))
        }
        ("email-message", f, IrValue::String(v))
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA-512'") =>
        {
            Ok(format!("email.attachment.hash.sha512 = \"{v}\""))
        }
        ("email-message", f, IrValue::String(v))
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA3-256'") =>
        {
            Ok(format!("email.attachment.hash.sha3_256 = \"{v}\""))
        }
        ("email-message", f, IrValue::String(v))
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA3-512'") =>
        {
            Ok(format!("email.attachment.hash.sha3_512 = \"{v}\""))
        }
        ("email-message", f, IrValue::String(v))
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.SSDEEP") =>
        {
            Ok(format!("email.attachment.hash.ssdeep = \"{v}\""))
        }
        ("email-message", f, IrValue::String(v))
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.TLSH") =>
        {
            Ok(format!("email.attachment.hash.tlsh = \"{v}\""))
        }
        _ => bail!(
            "Chronicle emitter does not support predicate {}:{}",
            p.target,
            p.field
        ),
    }
}

fn collect_predicates(exprs: &[IrExpr]) -> Result<Vec<IrPredicate>> {
    let mut predicates = Vec::new();
    for expr in exprs {
        match expr {
            IrExpr::Predicate(p) => predicates.push(p.clone()),
            IrExpr::All(nested) => predicates.extend(collect_predicates(nested)?),
            IrExpr::Any(_) => bail!("Chronicle emitter does not support OR inside AND"),
            IrExpr::FollowedBy(_) => {
                bail!("Chronicle emitter does not support FOLLOWEDBY sequence semantics")
            }
            IrExpr::Qualified(_, _) => {
                bail!("Chronicle emitter does NOT support observation qualifiers")
            }
        }
    }
    Ok(predicates)
}

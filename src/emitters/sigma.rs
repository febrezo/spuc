use anyhow::{Result, anyhow, bail};
use serde::Serialize;
use std::collections::BTreeSet;

use crate::emitters::EmitResult;
use crate::ir::{IrExpr, IrOp, IrPredicate, IrQualifier, IrValue};
use serde_yaml::Value;

#[derive(Serialize)]
struct SigmaRule {
    title: String,
    logsource: SigmaLogSource,
    detection: SigmaDetection,
}

#[derive(Serialize)]
struct SigmaLogSource {
    category: String,
}

#[derive(Serialize)]
struct SigmaDetection {
    #[serde(flatten)]
    selections: serde_yaml::Mapping,
    condition: String,
}

pub fn emit(ir: &IrExpr, description: Option<&str>) -> Result<EmitResult> {
    let (base, qualifiers) = peel_qualifiers(ir);
    if matches!(base, IrExpr::FollowedBy(_)) {
        return Ok(EmitResult::unsupported(
            "Sigma does NOT support FOLLOWEDBY sequence semantics in this baseline",
        ));
    }
    match build_detections(base) {
        Ok(detections) => {
            let category = sigma_category(base);
            let mut out_rules = Vec::new();
            let mut notes = sigma_notes(base);
            for q in qualifiers {
                match q {
                    IrQualifier::RepeatsTimes(times) => {
                        notes.push(format!(
                            "REPEATS {times} TIMES kept as advisory only (Sigma cannot enforce cardinality/event identity)"
                        ));
                        notes.push("@status:partial".to_string());
                    }
                    IrQualifier::WithinSeconds(_) | IrQualifier::StartStop { .. } => {
                        return Ok(EmitResult::unsupported(
                            "Sigma does NOT support WITHIN/START STOP qualifiers in this baseline",
                        ));
                    }
                }
            }
            for (selections, condition) in detections {
                let rule = SigmaRule {
                    title: match description {
                        Some(desc) => format!("[SPUC Generated Sigma Rule] {desc}"),
                        None => "[SPUC Generated Sigma Rule] auto".to_string(),
                    },
                    logsource: SigmaLogSource {
                        category: category.clone(),
                    },
                    detection: SigmaDetection {
                        selections,
                        condition,
                    },
                };
                out_rules.push(serde_yaml::to_string(&rule)?);
            }

            notes.sort();
            notes.dedup();
            if notes.is_empty() {
                Ok(EmitResult::exact(out_rules.join("---\n")))
            } else {
                Ok(EmitResult {
                    status: crate::emitters::FidelityStatus::Partial,
                    notes,
                    rule: Some(out_rules.join("---\n")),
                    cause: None,
                })
            }
        }
        Err(e) => Ok(EmitResult::unsupported(e.to_string())),
    }
}

fn peel_qualifiers<'a>(mut ir: &'a IrExpr) -> (&'a IrExpr, Vec<IrQualifier>) {
    let mut qualifiers = Vec::new();
    while let IrExpr::Qualified(inner, qs) = ir {
        qualifiers.extend(qs.clone());
        ir = inner;
    }
    (ir, qualifiers)
}

fn sigma_notes(ir: &IrExpr) -> Vec<String> {
    let mut notes = Vec::new();
    let mut preds = Vec::new();
    collect_predicates(ir, &mut preds);
    if preds.iter().any(|p| matches!(p.op, IrOp::Matches)) {
        notes.push("regex behavior can be backend-dependent after sigma conversion".to_string());
    }
    if preds.iter().any(|p| matches!(p.op, IrOp::IsSubset)) {
        notes.push(
            "ISSUBSET lowered via Sigma cidr matching; backend support can be backend-dependent"
                .to_string(),
        );
    }
    if preds.iter().any(|p| is_timestamp_predicate(p)) {
        notes.push("schema-dependent timestamp fields; verify backend mapping".to_string());
    }
    if preds.iter().any(|p| {
        matches!(
            (p.target.as_str(), p.field.as_str()),
            ("process", "is_hidden")
        )
    }) {
        notes.push("process:is_hidden flattened to backend process visibility fields".to_string());
    }
    if preds.iter().any(|p| {
        (p.target.as_str(), p.field.as_str()) == ("process", "image_ref.name")
            || (p.target.as_str(), p.field.as_str()) == ("process", "parent_ref.command_line")
            || (p.target.as_str() == "process"
                && p.field.as_str().starts_with("image_ref.hashes.SHA-256"))
    }) {
        notes
            .push("process references flattened into executable/parent process fields".to_string());
    }
    let has_network = preds.iter().any(|p| p.target == "network-traffic");
    let has_standalone_network = preds.iter().any(|p| {
        matches!(
            (p.target.as_str(), p.field.as_str()),
            ("ipv4-addr", "value")
                | ("ipv6-addr", "value")
                | ("mac-addr", "value")
                | ("domain-name", "value")
                | ("url", "value")
        )
    });
    if has_standalone_network && !has_network {
        notes.push(
            "standalone IP/domain/URL observables are backend-dependent mappings without full network-traffic context"
                .to_string(),
        );
    }
    if preds
        .iter()
        .any(|p| (p.target.as_str(), p.field.as_str()) == ("network-traffic", "protocols"))
    {
        notes.push(
            "schema-dependent protocol mapping: network-traffic:protocols is an ordered STIX stack; backend may only expose a single protocol token"
                .to_string(),
        );
    }
    if preds.iter().any(|p| {
        matches!(
            (p.target.as_str(), p.field.as_str(), &p.value),
            ("network-traffic", "src_ref.value", IrValue::String(v))
                | ("network-traffic", "dst_ref.value", IrValue::String(v))
                | ("ipv4-addr", "value", IrValue::String(v))
                | ("ipv6-addr", "value", IrValue::String(v))
                if v.contains('/')
        )
    }) {
        notes.push("CIDR/range semantics can be backend-dependent".to_string());
    }
    if has_ambiguous_network_subset(&preds) {
        notes.push(
            "network-traffic:*_ref.value ISSUBSET without explicit *_ref.type is backend-dependent (value can be non-IP in STIX)"
                .to_string(),
        );
    }
    if preds.iter().any(|p| p.target == "autonomous-system") {
        notes.push("autonomous-system field mappings are schema-dependent".to_string());
    }
    if preds.iter().any(|p| p.target == "directory") {
        notes.push("directory field mappings are schema-dependent".to_string());
    }
    if preds.iter().any(|p| p.target == "user-account") {
        notes.push("user-account field mappings are schema-dependent".to_string());
    }
    notes
}

fn has_ambiguous_network_subset(preds: &[&IrPredicate]) -> bool {
    let has_src_subset = preds.iter().any(|p| {
        p.op == IrOp::IsSubset
            && (p.target.as_str(), p.field.as_str()) == ("network-traffic", "src_ref.value")
    });
    let has_dst_subset = preds.iter().any(|p| {
        p.op == IrOp::IsSubset
            && (p.target.as_str(), p.field.as_str()) == ("network-traffic", "dst_ref.value")
    });
    let has_src_type = preds.iter().any(|p| {
        p.op == IrOp::Eq
            && (p.target.as_str(), p.field.as_str()) == ("network-traffic", "src_ref.type")
    });
    let has_dst_type = preds.iter().any(|p| {
        p.op == IrOp::Eq
            && (p.target.as_str(), p.field.as_str()) == ("network-traffic", "dst_ref.type")
    });
    (has_src_subset && !has_src_type) || (has_dst_subset && !has_dst_type)
}

fn collect_predicates<'a>(ir: &'a IrExpr, out: &mut Vec<&'a IrPredicate>) {
    match ir {
        IrExpr::Predicate(p) => out.push(p),
        IrExpr::All(v) | IrExpr::Any(v) => {
            for e in v {
                collect_predicates(e, out);
            }
        }
        IrExpr::FollowedBy(v) => {
            for e in v {
                collect_predicates(e, out);
            }
        }
        IrExpr::Qualified(inner, _) => collect_predicates(inner, out),
    }
}

fn build_selection(name: &str, predicates: &[IrPredicate]) -> Result<serde_yaml::Mapping> {
    if has_multi_user_account_conjunction(predicates) {
        bail!(
            "Sigma cannot faithfully represent multi-entity user-account conjunctions as one event"
        );
    }
    let mut map = serde_yaml::Mapping::new();
    let mut values = serde_yaml::Mapping::new();
    let mut condition_parts = Vec::new();

    for (idx, predicate) in predicates.iter().enumerate() {
        validate_operator(predicate)?;

        let field = sigma_field_with_op(predicate)?;
        let value = ir_value_to_yaml(&predicate.value)?;

        if predicate.op == IrOp::Ne {
            let neg_name = format!("{name}_not{}", idx + 1);
            let mut neg_values = serde_yaml::Mapping::new();
            neg_values.insert(Value::String(field), value.clone());
            map.insert(Value::String(neg_name.clone()), Value::Mapping(neg_values));
            condition_parts.push(format!("not {neg_name}"));
            continue;
        }

        insert_or_append(&mut values, Value::String(field), value.clone());

        // If IP/MAC field, also mirror to destination/source
        if let Some(alt) = map_sigma_alt(predicate) {
            let key_alt = Value::String(alt);
            let val_alt = ir_value_to_yaml(&predicate.value)?;
            insert_or_append(&mut values, key_alt, val_alt);
        }
    }

    if !values.is_empty() {
        map.insert(
            serde_yaml::Value::String(name.to_string()),
            serde_yaml::Value::Mapping(values),
        );
        condition_parts.insert(0, name.to_string());
    }
    if condition_parts.is_empty() {
        bail!("sigma received empty predicate set");
    }
    map.insert(
        serde_yaml::Value::String("__condition".to_string()),
        serde_yaml::Value::String(condition_parts.join(" and ")),
    );
    Ok(map)
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

fn insert_or_append(values: &mut serde_yaml::Mapping, key: Value, value: Value) {
    match values.get_mut(&key) {
        Some(existing) => match existing {
            Value::Sequence(seq) => seq.push(value),
            _ => {
                let prev = existing.clone();
                *existing = Value::Sequence(vec![prev, value]);
            }
        },
        None => {
            values.insert(key, value);
        }
    }
}

fn is_hash_predicate(p: &IrPredicate) -> bool {
    match (p.target.as_str(), p.field.as_str()) {
        ("file", f) | ("artifact", f) => f.starts_with("hashes."),
        ("email-message", f) => f.starts_with("body_multipart[*].body_raw_ref.hashes."),
        _ => false,
    }
}

fn is_numeric_predicate(p: &IrPredicate) -> bool {
    matches!(
        (p.target.as_str(), p.field.as_str()),
        ("network-traffic", "src_port")
            | ("network-traffic", "dst_port")
            | ("autonomous-system", "number")
            | ("file", "size")
            | ("user-account", "user_id")
            | ("process", "pid")
    )
}

fn validate_operator(p: &IrPredicate) -> Result<()> {
    let ok = if is_hash_predicate(p) {
        matches!(p.op, IrOp::Eq | IrOp::Ne)
    } else if is_boolean_predicate(p) {
        matches!(p.op, IrOp::Eq | IrOp::Ne)
    } else if is_timestamp_predicate(p) {
        matches!(
            p.op,
            IrOp::Eq | IrOp::Ne | IrOp::Gt | IrOp::Ge | IrOp::Lt | IrOp::Le
        )
    } else if is_numeric_predicate(p) {
        matches!(
            p.op,
            IrOp::Eq | IrOp::Ne | IrOp::Gt | IrOp::Ge | IrOp::Lt | IrOp::Le
        )
    } else if is_subset_predicate(p) {
        matches!(p.op, IrOp::Eq | IrOp::Ne | IrOp::Matches | IrOp::IsSubset)
    } else {
        matches!(p.op, IrOp::Eq | IrOp::Ne | IrOp::Matches)
    };

    if !is_valid_timestamp_value(p) {
        bail!(
            "Sigma requires timestamp literal (t'...') for {}:{}",
            p.target,
            p.field
        );
    }

    if ok {
        Ok(())
    } else if is_hash_predicate(p) {
        bail!(
            "Sigma does NOT support operator {} for hash predicate {}:{} (only Eq/Ne)",
            op_label(&p.op),
            p.target,
            p.field
        )
    } else if is_timestamp_predicate(p) {
        bail!(
            "Sigma does NOT support operator {} for timestamp predicate {}:{} (only Eq/Ne/Gt/Ge/Lt/Le)",
            op_label(&p.op),
            p.target,
            p.field
        )
    } else if is_boolean_predicate(p) {
        bail!(
            "Sigma does NOT support operator {} for boolean predicate {}:{} (only Eq/Ne)",
            op_label(&p.op),
            p.target,
            p.field
        )
    } else if is_numeric_predicate(p) {
        bail!(
            "Sigma does NOT support operator {} for numeric predicate {}:{} (only Eq/Ne/Gt/Ge/Lt/Le)",
            op_label(&p.op),
            p.target,
            p.field
        )
    } else if is_subset_predicate(p) {
        bail!(
            "Sigma does NOT support operator {} for CIDR-capable predicate {}:{} (only Eq/Ne/Matches/IsSubset)",
            op_label(&p.op),
            p.target,
            p.field
        )
    } else {
        bail!("Sigma does NOT support operator {} yet", op_label(&p.op))
    }
}

fn is_subset_predicate(p: &IrPredicate) -> bool {
    matches!(
        (p.target.as_str(), p.field.as_str()),
        ("ipv4-addr", "value")
            | ("ipv6-addr", "value")
            | ("network-traffic", "src_ref.value")
            | ("network-traffic", "dst_ref.value")
    )
}

fn is_boolean_predicate(p: &IrPredicate) -> bool {
    matches!(
        (p.target.as_str(), p.field.as_str()),
        ("process", "is_hidden")
    )
}

fn sigma_field_with_op(p: &IrPredicate) -> Result<String> {
    let field = map_sigma_field(p)?;
    Ok(match p.op {
        IrOp::Matches => format!("{field}|re"),
        IrOp::IsSubset => format!("{field}|cidr"),
        IrOp::Gt => format!("{field}|gt"),
        IrOp::Ge => format!("{field}|gte"),
        IrOp::Lt => format!("{field}|lt"),
        IrOp::Le => format!("{field}|lte"),
        _ => field,
    })
}

fn is_timestamp_predicate(p: &IrPredicate) -> bool {
    matches!(
        (p.target.as_str(), p.field.as_str()),
        ("directory", "atime")
            | ("directory", "ctime")
            | ("directory", "mtime")
            | ("file", "atime")
            | ("file", "ctime")
            | ("file", "mtime")
            | ("process", "created_time")
            | ("windows-registry-key", "modified_time")
    )
}

fn is_valid_timestamp_value(p: &IrPredicate) -> bool {
    if !is_timestamp_predicate(p) {
        return true;
    }
    matches!(p.value, IrValue::Timestamp(_))
}

fn op_label(op: &IrOp) -> &'static str {
    match op {
        IrOp::Eq => "Eq EQUAL (=)",
        IrOp::Ne => "Ne NOT_EQUAL (!=)",
        IrOp::Gt => "Gt GREATER_THAN (>)",
        IrOp::Ge => "Ge GREATER_OR_EQUAL (>=)",
        IrOp::Lt => "Lt LESS_THAN (<)",
        IrOp::Le => "Le LESS_OR_EQUAL (<=)",
        IrOp::Matches => "Matches REGEX (MATCHES/LIKE)",
        IrOp::IsSubset => "IsSubset CIDR_SUBSET (ISSUBSET)",
    }
}

fn map_sigma_field(p: &IrPredicate) -> Result<String> {
    let out = match (p.target.as_str(), p.field.as_str()) {
        ("network-traffic", "src_ref.value") => "source.ip".to_string(),
        ("network-traffic", "dst_ref.value") => "destination.ip".to_string(),
        ("network-traffic", "src_port") => "source.port".to_string(),
        ("network-traffic", "dst_port") => "destination.port".to_string(),
        ("network-traffic", "protocols") => "network.protocol".to_string(),
        ("url", "value") => "url.full".to_string(),
        ("email-message", "from_ref.value") => "email.from".to_string(),
        ("email-message", "sender_ref.value") => "email.sender".to_string(),
        ("email-message", "subject") => "email.subject".to_string(),
        ("email-message", "body") => "email.body".to_string(),
        ("email-message", "to_refs[*].value") => "email.to".to_string(),
        ("email-message", "body_multipart[*].body_raw_ref.name") => "attachment.name".to_string(),
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.'MD5'") => {
            "attachment.hash.md5".to_string()
        }
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA-1'") => {
            "attachment.hash.sha1".to_string()
        }
        ("email-message", f)
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA-256'") =>
        {
            "attachment.hash.sha256".to_string()
        }
        ("email-message", f)
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA-512'") =>
        {
            "attachment.hash.sha512".to_string()
        }
        ("email-message", f)
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA3-256'") =>
        {
            "attachment.hash.sha3_256".to_string()
        }
        ("email-message", f)
            if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA3-512'") =>
        {
            "attachment.hash.sha3_512".to_string()
        }
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.SSDEEP") => {
            "attachment.hash.ssdeep".to_string()
        }
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.TLSH") => {
            "attachment.hash.tlsh".to_string()
        }
        ("file", "name") => "file.name".to_string(),
        ("directory", "path") => "file.directory".to_string(),
        ("directory", "atime") => "file.atime".to_string(),
        ("directory", "ctime") => "file.ctime".to_string(),
        ("directory", "mtime") => "file.mtime".to_string(),
        ("file", "size") => "file.size".to_string(),
        ("file", "atime") => "file.atime".to_string(),
        ("file", "ctime") => "file.ctime".to_string(),
        ("file", "mtime") => "file.mtime".to_string(),
        ("process", "command_line") => "process.command_line".to_string(),
        ("process", "name") => "process.name".to_string(),
        ("process", "pid") => "process.pid".to_string(),
        ("process", "is_hidden") => "process.is_hidden".to_string(),
        ("process", "cwd") => "process.working_directory".to_string(),
        ("process", "created_time") => "process.created".to_string(),
        ("process", "image_ref.name") => "process.name".to_string(),
        ("process", "parent_ref.command_line") => "process.parent.command_line".to_string(),
        ("process", f) if f.starts_with("image_ref.hashes.SHA-256") => {
            "process.hash.sha256".to_string()
        }
        ("file", f) if f.starts_with("hashes.MD5") => "file.hash.md5".to_string(),
        ("file", f) if f.starts_with("hashes.SHA-1") => "file.hash.sha1".to_string(),
        ("file", f) if f.starts_with("hashes.SHA-256") => "file.hash.sha256".to_string(),
        ("file", f) if f.starts_with("hashes.SHA-512") => "file.hash.sha512".to_string(),
        ("file", f) if f.starts_with("hashes.SHA3-256") => "file.hash.sha3_256".to_string(),
        ("file", f) if f.starts_with("hashes.SHA3-512") => "file.hash.sha3_512".to_string(),
        ("file", f) if f.starts_with("hashes.SSDEEP") => "file.hash.ssdeep".to_string(),
        ("file", f) if f.starts_with("hashes.TLSH") => "file.hash.tlsh".to_string(),
        ("user-account", "account_type") => "user.type".to_string(),
        ("user-account", "user_id") => "user.id".to_string(),
        ("user-account", "account_login") => "user.name".to_string(),
        ("autonomous-system", "number") => "as.number".to_string(),
        ("autonomous-system", "name") => "as.organization.name".to_string(),
        ("autonomous-system", "rir") => "as.rir".to_string(),
        ("domain-name", "value") => "destination.domain".to_string(),
        ("ipv4-addr", "value") | ("ipv6-addr", "value") | ("mac-addr", "value") => {
            bail!(
                "Sigma standalone {}:{} is unsupported in baseline to avoid implicit source/destination directionality bias",
                p.target,
                p.field
            )
        }
        ("windows-registry-key", "key") => "registry.key".to_string(),
        ("windows-registry-key", "values[*].name") => "registry.value".to_string(),
        ("windows-registry-key", "values[*].data") => "registry.data".to_string(),
        ("windows-registry-key", "modified_time") => "registry.modified_time".to_string(),
        _ => {
            bail!(
                "Sigma has no documented field mapping for {}:{} (raw STIX path passthrough disabled)",
                p.target,
                p.field
            )
        }
    };
    Ok(out)
}

fn map_sigma_alt(p: &IrPredicate) -> Option<String> {
    let _ = p;
    None
}

fn ir_value_to_yaml(value: &IrValue) -> Result<Value> {
    Ok(match value {
        IrValue::String(s) => Value::String(s.clone()),
        IrValue::Integer(i) => serde_yaml::to_value(*i)?,
        IrValue::Boolean(b) => Value::Bool(*b),
        IrValue::Hex(h) => Value::String(h.clone()),
        IrValue::Timestamp(ts) => Value::String(ts.clone()),
    })
}

fn sigma_category(ir: &IrExpr) -> String {
    fn walk(expr: &IrExpr, targets: &mut BTreeSet<String>) {
        match expr {
            IrExpr::Predicate(p) => {
                targets.insert(p.target.clone());
            }
            IrExpr::All(v) | IrExpr::Any(v) => {
                for e in v {
                    walk(e, targets);
                }
            }
            IrExpr::FollowedBy(v) => {
                for e in v {
                    walk(e, targets);
                }
            }
            IrExpr::Qualified(inner, _) => walk(inner, targets),
        }
    }

    fn is_network_target(t: &str) -> bool {
        matches!(
            t,
            "network-traffic"
                | "ipv4-addr"
                | "ipv6-addr"
                | "mac-addr"
                | "domain-name"
                | "url"
                | "autonomous-system"
        )
    }

    let mut targets = BTreeSet::new();
    walk(ir, &mut targets);

    if targets.len() == 1 {
        return match targets
            .iter()
            .next()
            .map(|s| s.as_str())
            .unwrap_or("unknown")
        {
            "email-message" => "email".to_string(),
            "file" | "directory" => "file_event".to_string(),
            "process" => "process_creation".to_string(),
            "windows-registry-key" => "registry_set".to_string(),
            t if is_network_target(t) => "network_connection".to_string(),
            _ => "generic".to_string(),
        };
    }

    if !targets.is_empty() && targets.iter().all(|t| is_network_target(t)) {
        "network_connection".to_string()
    } else {
        "generic".to_string()
    }
}

fn collect_ip_any(exprs: &[IrExpr]) -> Result<Option<Vec<String>>> {
    let mut ips = Vec::new();
    for expr in exprs {
        match expr {
            IrExpr::Predicate(p) => {
                if p.op == IrOp::Eq && is_ip_predicate(p) {
                    if let IrValue::String(ip) = &p.value {
                        ips.push(ip.clone());
                        continue;
                    }
                }
                return Ok(None);
            }
            IrExpr::Qualified(inner, _) => {
                if let IrExpr::Predicate(p) = &**inner {
                    if p.op == IrOp::Eq && is_ip_predicate(p) {
                        if let IrValue::String(ip) = &p.value {
                            ips.push(ip.clone());
                            continue;
                        }
                    }
                }
                return Ok(None);
            }
            IrExpr::FollowedBy(_) => return Ok(None),
            _ => return Ok(None),
        }
    }

    Ok(Some(ips))
}

fn is_ip_predicate(p: &IrPredicate) -> bool {
    matches!(
        (p.target.as_str(), p.field.as_str()),
        ("network-traffic", "src_ref.value") | ("network-traffic", "dst_ref.value")
    )
}

fn build_dual_ip_selections(ips: &[String]) -> Result<serde_yaml::Mapping> {
    let mut map = serde_yaml::Mapping::new();

    let seq: Vec<Value> = ips.iter().cloned().map(Value::String).collect();
    let mut src = serde_yaml::Mapping::new();
    src.insert(
        Value::String("source.ip".to_string()),
        Value::Sequence(seq.clone()),
    );

    let mut dst = serde_yaml::Mapping::new();
    dst.insert(
        Value::String("destination.ip".to_string()),
        Value::Sequence(seq),
    );

    map.insert(
        Value::String("selection_src".to_string()),
        Value::Mapping(src),
    );
    map.insert(
        Value::String("selection_dst".to_string()),
        Value::Mapping(dst),
    );

    Ok(map)
}

fn build_detections(ir: &IrExpr) -> Result<Vec<(serde_yaml::Mapping, String)>> {
    // Special-case IP OR handled via aggregation when no AND is present.
    if let IrExpr::Any(exprs) = ir {
        if let Some(ips) = collect_ip_any(exprs)? {
            let selections = build_dual_ip_selections(&ips)?;
            return Ok(vec![(
                selections,
                "selection_src or selection_dst".to_string(),
            )]);
        }
    }

    let conjunctions = expand_conjunctions(ir)?;
    let mut results = Vec::new();
    for (idx, conj) in conjunctions.iter().enumerate() {
        let name = if conjunctions.len() > 1 {
            format!("selection{}", idx + 1)
        } else {
            "selection".to_string()
        };
        let mut selection = build_selection(&name, conj)?;
        let condition = selection
            .remove(Value::String("__condition".to_string()))
            .and_then(|v| match v {
                Value::String(s) => Some(s),
                _ => None,
            })
            .ok_or_else(|| anyhow!("missing sigma condition"))?;
        results.push((selection, condition));
    }
    Ok(results)
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
            bail!("Sigma does NOT support FOLLOWEDBY sequence semantics in this baseline")
        }
        IrExpr::Qualified(_, _) => {
            bail!("Sigma does NOT support observation qualifiers in this lowering path")
        }
    }
}

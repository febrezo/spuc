use anyhow::{Result, bail};

use crate::emitters::{EmitResult, FidelityStatus};
use crate::ir::{IrExpr, IrOp, IrPredicate, IrQualifier, IrValue};

pub fn emit(ir: &IrExpr, _description: Option<&str>) -> Result<EmitResult> {
    let (base, qualifiers) = peel_qualifiers(ir);
    if matches!(base, IrExpr::FollowedBy(_)) {
        return Ok(EmitResult::unsupported(
            "KQL emitter does NOT support FOLLOWEDBY sequence semantics in this baseline",
        ));
    }
    let disjuncts = expand_conjunctions(base)?;
    let mut parts = Vec::new();
    let mut table: Option<String> = None;
    let mut notes = Vec::new();

    for conj in disjuncts {
        if has_multi_user_account_conjunction(&conj) {
            return Ok(EmitResult::unsupported(
                "KQL cannot faithfully represent multi-entity user-account conjunctions as one row",
            ));
        }
        let lowered = lower_all(&conj)?;
        table = merge_table(table, lowered.table);
        parts.push(format!("({})", lowered.condition));
        notes.extend(lowered.notes);
    }

    let tbl = table.unwrap_or_else(|| "DeviceEvents".to_string());
    let mut qualifier_filters = Vec::new();
    for q in qualifiers {
        match q {
            IrQualifier::StartStop { start, stop } => {
                qualifier_filters.push(format!(
                    "(Timestamp >= datetime(\"{start}\") and Timestamp < datetime(\"{stop}\"))"
                ));
            }
            IrQualifier::RepeatsTimes(times) => {
                notes.push(format!(
                    "REPEATS {times} TIMES kept as advisory only (cardinality/event identity is not enforceable in plain KQL where-clause)"
                ));
                notes.push("@status:partial".to_string());
            }
            IrQualifier::WithinSeconds(secs) => {
                notes.push(format!(
                    "WITHIN {secs} SECONDS kept as advisory only (time-window correlation is not enforceable in plain KQL where-clause)"
                ));
            }
        }
    }

    let mut condition = parts.join(" or ");
    if !qualifier_filters.is_empty() {
        condition = format!("({condition}) and {}", qualifier_filters.join(" and "));
    }

    let status = if notes.is_empty() {
        FidelityStatus::Exact
    } else {
        FidelityStatus::Partial
    };

    Ok(EmitResult {
        status,
        notes,
        rule: Some(format!("{tbl}\n| where {condition}")),
        cause: None,
    })
}

fn peel_qualifiers<'a>(mut ir: &'a IrExpr) -> (&'a IrExpr, Vec<IrQualifier>) {
    let mut qualifiers = Vec::new();
    while let IrExpr::Qualified(inner, qs) = ir {
        qualifiers.extend(qs.clone());
        ir = inner;
    }
    (ir, qualifiers)
}

struct KqlExpr {
    table: Option<String>,
    condition: String,
    notes: Vec<String>,
}

fn lower_all(predicates: &[IrPredicate]) -> Result<KqlExpr> {
    let mut parts = Vec::new();
    let mut table: Option<String> = None;
    let mut notes = Vec::new();
    for p in predicates {
        let lowered = lower_predicate(p)?;
        table = merge_table(table, lowered.table);
        parts.push(lowered.condition);
        notes.extend(lowered.notes);
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
    Ok(KqlExpr {
        table,
        condition: parts.join(" and "),
        notes,
    })
}

struct KqlPred {
    table: Option<String>,
    condition: String,
    notes: Vec<String>,
}

fn lower_predicate(p: &IrPredicate) -> Result<KqlPred> {
    validate_operator(p)?;
    if let Some(condition) = standalone_network_condition(p)? {
        let mut notes = vec![
            "standalone IP/MAC observables are mapped as local OR remote without full network-traffic context"
                .to_string(),
        ];
        if let IrValue::String(v) = &p.value {
            if v.contains('/') && matches!(p.target.as_str(), "ipv4-addr" | "ipv6-addr") {
                notes.push("CIDR/range semantics can be backend-dependent".to_string());
            }
        }
        if matches!(p.op, IrOp::Matches) {
            notes.push("regex behavior can be backend-dependent".to_string());
        }
        return Ok(KqlPred {
            table: Some("DeviceNetworkEvents".to_string()),
            condition,
            notes,
        });
    }
    if p.op == IrOp::IsSubset {
        return lower_subset_predicate(p);
    }
    let mapping = map_field(p)?;
    let value = match (p.target.as_str(), p.field.as_str(), &p.value) {
        ("artifact", "payload_bin", IrValue::Hex(h)) => format!("\"{h}\""),
        (_, _, IrValue::String(s)) => format!("\"{}\"", s),
        (_, _, IrValue::Integer(i)) => i.to_string(),
        (_, _, IrValue::Boolean(b)) => b.to_string(),
        (_, _, IrValue::Hex(_)) => bail!("KQL emitter does not support hex literals yet"),
        (_, _, IrValue::Timestamp(ts)) => format!("datetime(\"{ts}\")"),
    };

    let op = match p.op {
        IrOp::Eq => "==",
        IrOp::Ne => "!=",
        IrOp::Gt => ">",
        IrOp::Ge => ">=",
        IrOp::Lt => "<",
        IrOp::Le => "<=",
        IrOp::Matches => "matches regex",
        IrOp::IsSubset => {
            bail!("internal error: ISSUBSET should be handled before generic lowering")
        }
    };

    let condition = if p.op == IrOp::Matches {
        format!("{} {} \"{}\"", mapping.field, op, value.trim_matches('"'))
    } else {
        format!("{} {} {}", mapping.field, op, value)
    };

    let mut notes = mapping.notes;
    if (p.target.as_str(), p.field.as_str()) == ("artifact", "payload_bin")
        && matches!(p.op, IrOp::Matches)
    {
        notes.retain(|n| !n.contains("artifact schema fields are backend-dependent"));
    }
    if matches!(p.op, IrOp::Matches) {
        notes.push("regex behavior can be backend-dependent".to_string());
    }
    if (p.target.as_str(), p.field.as_str()) == ("artifact", "payload_bin")
        && matches!(p.op, IrOp::Matches)
    {
        notes.push("artifact:payload_bin regex evaluation may depend on backend field encoding (bytes vs text/hex)".to_string());
        notes.push("@conf50".to_string());
    }
    if (p.target.as_str(), p.field.as_str()) == ("network-traffic", "protocols") {
        notes.push(
            "network-traffic:protocols is an ordered STIX stack; mapping may only reflect a single protocol token"
                .to_string(),
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
    Ok(KqlPred {
        table: mapping.table,
        condition,
        notes,
    })
}

fn validate_operator(p: &IrPredicate) -> Result<()> {
    let allowed: &[IrOp] = match (p.target.as_str(), p.field.as_str()) {
        ("artifact", f) if f.starts_with("hashes.") => &[IrOp::Eq, IrOp::Ne],
        ("artifact", "mime_type") | ("artifact", "payload_bin") => {
            &[IrOp::Eq, IrOp::Ne, IrOp::Matches]
        }
        ("file", f) if f.starts_with("hashes.") => &[IrOp::Eq, IrOp::Ne],
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
            "KQL emitter does not support operator {:?} for {}:{}",
            p.op,
            p.target,
            p.field
        )
    }
}

struct KqlField {
    table: Option<String>,
    field: String,
    notes: Vec<String>,
}

fn map_field(p: &IrPredicate) -> Result<KqlField> {
    match (p.target.as_str(), p.field.as_str()) {
        ("process", "image_ref.name") => Ok(KqlField {
            table: Some("DeviceProcessEvents".to_string()),
            field: "FileName".to_string(),
            notes: vec!["process references flattened into executable/parent process fields".to_string()],
        }),
        ("process", "command_line") => Ok(KqlField {
            table: Some("DeviceProcessEvents".to_string()),
            field: "ProcessCommandLine".to_string(),
            notes: Vec::new(),
        }),
        ("process", "name") => Ok(KqlField {
            table: Some("DeviceProcessEvents".to_string()),
            field: "FileName".to_string(),
            notes: Vec::new(),
        }),
        ("process", "pid") => Ok(KqlField {
            table: Some("DeviceProcessEvents".to_string()),
            field: "ProcessId".to_string(),
            notes: Vec::new(),
        }),
        ("process", "is_hidden") => bail!(
            "KQL emitter semantic mapping is missing for process:is_hidden in the selected baseline"
        ),
        ("process", "cwd") => Ok(KqlField {
            table: Some("DeviceProcessEvents".to_string()),
            field: "FolderPath".to_string(),
            notes: vec!["cwd mapped to FolderPath; verify semantics".to_string()],
        }),
        ("process", "created_time") => Ok(KqlField {
            table: Some("DeviceProcessEvents".to_string()),
            field: "ProcessCreationTime".to_string(),
            notes: vec!["schema-dependent temporal field; verify ProcessCreationTime mapping".to_string()],
        }),
        ("process", "parent_ref.command_line") => Ok(KqlField {
            table: Some("DeviceProcessEvents".to_string()),
            field: "InitiatingProcessCommandLine".to_string(),
            notes: vec!["process references flattened into executable/parent process fields".to_string()],
        }),
        ("process", f) if f.starts_with("image_ref.hashes.SHA-256") => Ok(KqlField {
            table: Some("DeviceProcessEvents".to_string()),
            field: "SHA256".to_string(),
            notes: vec!["process references flattened into executable/parent process fields".to_string()],
        }),
        ("network-traffic", "src_ref.value") => Ok(KqlField {
            table: Some("DeviceNetworkEvents".to_string()),
            field: "LocalIP".to_string(),
            notes: vec![
                "schema-dependent network-traffic mapping; LocalIP/RemoteIP role assumptions depend on backend schema".to_string(),
            ],
        }),
        ("network-traffic", "src_port") => Ok(KqlField {
            table: Some("DeviceNetworkEvents".to_string()),
            field: "LocalPort".to_string(),
            notes: vec![
                "schema-dependent network-traffic mapping; LocalPort/RemotePort role assumptions depend on backend schema".to_string(),
            ],
        }),
        ("network-traffic", "dst_ref.value") => Ok(KqlField {
            table: Some("DeviceNetworkEvents".to_string()),
            field: "RemoteIP".to_string(),
            notes: vec![
                "schema-dependent network-traffic mapping; LocalIP/RemoteIP role assumptions depend on backend schema".to_string(),
            ],
        }),
        ("network-traffic", "dst_port") => Ok(KqlField {
            table: Some("DeviceNetworkEvents".to_string()),
            field: "RemotePort".to_string(),
            notes: vec![
                "schema-dependent network-traffic mapping; LocalPort/RemotePort role assumptions depend on backend schema".to_string(),
            ],
        }),
        ("user-account", "account_type") => Ok(KqlField {
            table: Some("IdentityInfo".to_string()),
            field: "AccountType".to_string(),
            notes: vec!["user-account field mappings are schema-dependent".to_string()],
        }),
        ("user-account", "user_id") => Ok(KqlField {
            table: Some("IdentityInfo".to_string()),
            field: "AccountObjectId".to_string(),
            notes: vec!["user-account field mappings are schema-dependent".to_string()],
        }),
        ("user-account", "account_login") => Ok(KqlField {
            table: Some("IdentityInfo".to_string()),
            field: "AccountName".to_string(),
            notes: vec!["user-account field mappings are schema-dependent".to_string()],
        }),
        ("email-message", "from_ref.value") => Ok(KqlField {
            table: Some("EmailEvents".to_string()),
            field: "SenderFromAddress".to_string(),
            notes: Vec::new(),
        }),
        ("email-message", "sender_ref.value") => Ok(KqlField {
            table: Some("EmailEvents".to_string()),
            field: "SenderFromAddress".to_string(),
            notes: Vec::new(),
        }),
        ("email-message", "subject") => Ok(KqlField {
            table: Some("EmailEvents".to_string()),
            field: "Subject".to_string(),
            notes: Vec::new(),
        }),
        ("email-message", "body") => Ok(KqlField {
            table: Some("EmailEvents".to_string()),
            field: "Body".to_string(),
            notes: Vec::new(),
        }),
        ("email-message", "to_refs[*].value") => Ok(KqlField {
            table: Some("EmailEvents".to_string()),
            field: "RecipientEmailAddress".to_string(),
            notes: Vec::new(),
        }),
        ("email-message", "body_multipart[*].body_raw_ref.name") => Ok(KqlField {
            table: Some("EmailEvents".to_string()),
            field: "AttachmentName".to_string(),
            notes: Vec::new(),
        }),
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.'MD5'") => {
            Ok(KqlField {
                table: Some("EmailEvents".to_string()),
                field: "AttachmentMD5".to_string(),
                notes: Vec::new(),
            })
        }
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA-1'") => {
            Ok(KqlField {
                table: Some("EmailEvents".to_string()),
                field: "AttachmentSHA1".to_string(),
                notes: Vec::new(),
            })
        }
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA-256'") => {
            Ok(KqlField {
                table: Some("EmailEvents".to_string()),
                field: "AttachmentSHA256".to_string(),
                notes: Vec::new(),
            })
        }
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA-512'") => {
            Ok(KqlField {
                table: Some("EmailEvents".to_string()),
                field: "AttachmentSHA512".to_string(),
                notes: Vec::new(),
            })
        }
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA3-256'") => {
            Ok(KqlField {
                table: Some("EmailEvents".to_string()),
                field: "AttachmentSHA3_256".to_string(),
                notes: vec!["non-standard column; ensure mapping exists".to_string()],
            })
        }
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.'SHA3-512'") => {
            Ok(KqlField {
                table: Some("EmailEvents".to_string()),
                field: "AttachmentSHA3_512".to_string(),
                notes: vec!["non-standard column; ensure mapping exists".to_string()],
            })
        }
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.SSDEEP") => {
            Ok(KqlField {
                table: Some("EmailEvents".to_string()),
                field: "AttachmentSSDEEP".to_string(),
                notes: vec!["non-standard column; ensure mapping exists".to_string()],
            })
        }
        ("email-message", f) if f.starts_with("body_multipart[*].body_raw_ref.hashes.TLSH") => {
            Ok(KqlField {
                table: Some("EmailEvents".to_string()),
                field: "AttachmentTLSH".to_string(),
                notes: vec!["non-standard column; ensure mapping exists".to_string()],
            })
        }
        ("file", "name") => Ok(KqlField {
            table: Some("DeviceFileEvents".to_string()),
            field: "FileName".to_string(),
            notes: Vec::new(),
        }),
        ("directory", "path") => Ok(KqlField {
            table: Some("DeviceFileEvents".to_string()),
            field: "FolderPath".to_string(),
            notes: vec!["directory path mapping is schema-dependent".to_string()],
        }),
        ("directory", "ctime") | ("directory", "mtime") | ("directory", "atime") => Ok(KqlField {
            table: Some("DeviceFileEvents".to_string()),
            field: "Timestamp".to_string(),
            notes: vec![
                "directory timestamps downgraded to event Timestamp (not exact directory metadata time)".to_string(),
            ],
        }),
        ("file", "size") => Ok(KqlField {
            table: Some("DeviceFileEvents".to_string()),
            field: "FileSize".to_string(),
            notes: Vec::new(),
        }),
        ("file", f) if f.starts_with("hashes.MD5") => Ok(KqlField {
            table: Some("DeviceFileEvents".to_string()),
            field: "MD5".to_string(),
            notes: Vec::new(),
        }),
        ("file", f) if f.starts_with("hashes.SHA-1") => Ok(KqlField {
            table: Some("DeviceFileEvents".to_string()),
            field: "SHA1".to_string(),
            notes: Vec::new(),
        }),
        ("file", f) if f.starts_with("hashes.SHA-256") => Ok(KqlField {
            table: Some("DeviceFileEvents".to_string()),
            field: "SHA256".to_string(),
            notes: Vec::new(),
        }),
        ("file", f) if f.starts_with("hashes.SHA-512") => Ok(KqlField {
            table: Some("DeviceFileEvents".to_string()),
            field: "SHA512".to_string(),
            notes: Vec::new(),
        }),
        ("file", f) if f.starts_with("hashes.SHA3-256") => Ok(KqlField {
            table: Some("DeviceFileEvents".to_string()),
            field: "SHA3_256".to_string(),
            notes: vec!["non-standard column; ensure mapping exists".to_string()],
        }),
        ("file", f) if f.starts_with("hashes.SHA3-512") => Ok(KqlField {
            table: Some("DeviceFileEvents".to_string()),
            field: "SHA3_512".to_string(),
            notes: vec!["non-standard column; ensure mapping exists".to_string()],
        }),
        ("file", f) if f.starts_with("hashes.SSDEEP") => Ok(KqlField {
            table: Some("DeviceFileEvents".to_string()),
            field: "SSDEEP".to_string(),
            notes: vec!["non-standard column; ensure mapping exists".to_string()],
        }),
        ("file", f) if f.starts_with("hashes.TLSH") => Ok(KqlField {
            table: Some("DeviceFileEvents".to_string()),
            field: "TLSH".to_string(),
            notes: vec!["non-standard column; ensure mapping exists".to_string()],
        }),
        ("artifact", f) if f.starts_with("hashes.MD5") => Ok(KqlField {
            table: Some("EmailAttachmentInfo" .to_string()),
            field: "MD5".to_string(),
            notes: vec!["artifact hashes mapped as attachment hashes; adjust table if needed".to_string()],
        }),
        ("artifact", f) if f.starts_with("hashes.SHA-1") => Ok(KqlField {
            table: Some("EmailAttachmentInfo" .to_string()),
            field: "SHA1".to_string(),
            notes: vec!["artifact hashes mapped as attachment hashes; adjust table if needed".to_string()],
        }),
        ("artifact", f) if f.starts_with("hashes.SHA-256") => Ok(KqlField {
            table: Some("EmailAttachmentInfo" .to_string()),
            field: "SHA256".to_string(),
            notes: vec!["artifact hashes mapped as attachment hashes; adjust table if needed".to_string()],
        }),
        ("artifact", f) if f.starts_with("hashes.SHA-512") => Ok(KqlField {
            table: Some("EmailAttachmentInfo" .to_string()),
            field: "SHA512".to_string(),
            notes: vec!["artifact hashes mapped as attachment hashes; adjust table if needed".to_string()],
        }),
        ("artifact", f) if f.starts_with("hashes.SHA3-256") => Ok(KqlField {
            table: Some("EmailAttachmentInfo" .to_string()),
            field: "SHA3_256".to_string(),
            notes: vec!["non-standard; ensure mapping exists".to_string()],
        }),
        ("artifact", f) if f.starts_with("hashes.SHA3-512") => Ok(KqlField {
            table: Some("EmailAttachmentInfo" .to_string()),
            field: "SHA3_512".to_string(),
            notes: vec!["non-standard; ensure mapping exists".to_string()],
        }),
        ("artifact", f) if f.starts_with("hashes.SSDEEP") => Ok(KqlField {
            table: Some("EmailAttachmentInfo" .to_string()),
            field: "SSDEEP".to_string(),
            notes: vec!["non-standard; ensure mapping exists".to_string()],
        }),
        ("artifact", f) if f.starts_with("hashes.TLSH") => Ok(KqlField {
            table: Some("EmailAttachmentInfo" .to_string()),
            field: "TLSH".to_string(),
            notes: vec!["non-standard; ensure mapping exists".to_string()],
        }),
        ("artifact", "mime_type") => Ok(KqlField {
            table: Some("DeviceEvents".to_string()),
            field: "ArtifactMimeType".to_string(),
            notes: vec![
                "artifact schema fields are backend-dependent and may require pipeline-specific mapping".to_string(),
            ],
        }),
        ("artifact", "payload_bin") => Ok(KqlField {
            table: Some("DeviceEvents".to_string()),
            field: "ArtifactPayload".to_string(),
            notes: vec![
                "artifact schema fields are backend-dependent and may require pipeline-specific mapping".to_string(),
            ],
        }),
        ("ipv4-addr", "value") => Ok(KqlField {
            table: Some("DeviceNetworkEvents".to_string()),
            field: "RemoteIP".to_string(),
            notes: vec!["mapped as destination; source also implied".to_string()],
        }),
        ("ipv6-addr", "value") => Ok(KqlField {
            table: Some("DeviceNetworkEvents".to_string()),
            field: "RemoteIP".to_string(),
            notes: vec!["mapped as destination; source also implied".to_string()],
        }),
        ("mac-addr", "value") => Ok(KqlField {
            table: Some("DeviceNetworkEvents".to_string()),
            field: "RemoteMAC".to_string(),
            notes: vec!["mapped as destination; source also implied".to_string()],
        }),
        ("domain-name", "value") => Ok(KqlField {
            table: Some("DeviceNetworkEvents".to_string()),
            field: "RemoteUrl".to_string(),
            notes: vec!["mapped as domain/URL; adjust mapping if needed".to_string()],
        }),
        ("url", "value") => Ok(KqlField {
            table: Some("DeviceNetworkEvents".to_string()),
            field: "RemoteUrl".to_string(),
            notes: vec!["mapped as domain/URL; adjust mapping if needed".to_string()],
        }),
        ("network-traffic", "protocols") => Ok(KqlField {
            table: Some("DeviceNetworkEvents".to_string()),
            field: "Protocol".to_string(),
            notes: vec![
                "schema-dependent network-traffic protocol mapping; backend may expose only one protocol token from STIX protocol stack".to_string(),
            ],
        }),
        ("windows-registry-key", "key") => Ok(KqlField {
            table: Some("RegistryEvents".to_string()),
            field: "RegistryKey".to_string(),
            notes: Vec::new(),
        }),
        ("windows-registry-key", "values[*].name") => Ok(KqlField {
            table: Some("RegistryEvents".to_string()),
            field: "RegistryValueName".to_string(),
            notes: vec!["registry value fields flattened into backend registry event fields".to_string()],
        }),
        ("windows-registry-key", "values[*].data") => Ok(KqlField {
            table: Some("RegistryEvents".to_string()),
            field: "RegistryValueData".to_string(),
            notes: vec!["registry value fields flattened into backend registry event fields".to_string()],
        }),
        ("windows-registry-key", "values[*].data_type") => Ok(KqlField {
            table: Some("RegistryEvents".to_string()),
            field: "RegistryValueType".to_string(),
            notes: vec!["registry value fields flattened into backend registry event fields".to_string()],
        }),
        ("windows-registry-key", "modified_time") => Ok(KqlField {
            table: Some("RegistryEvents".to_string()),
            field: "Timestamp".to_string(),
            notes: vec!["modified_time downgraded to event Timestamp (not exact key write time)".to_string()],
        }),
        ("autonomous-system", "number") => Ok(KqlField {
            table: Some("DeviceNetworkEvents".to_string()),
            field: "RemoteASN".to_string(),
            notes: vec!["ASN mapping is schema-dependent".to_string()],
        }),
        ("autonomous-system", "name") => Ok(KqlField {
            table: Some("DeviceNetworkEvents".to_string()),
            field: "RemoteASName".to_string(),
            notes: vec!["ASN name mapping is schema-dependent".to_string()],
        }),
        ("autonomous-system", "rir") => Ok(KqlField {
            table: Some("DeviceNetworkEvents".to_string()),
            field: "RemoteASRIR".to_string(),
            notes: vec!["ASN RIR mapping is schema-dependent/non-standard; verify backend field".to_string()],
        }),
        _ => bail!(
            "KQL emitter does not support predicate {}:{}",
            p.target,
            p.field
        ),
    }
}

fn merge_table(lhs: Option<String>, rhs: Option<String>) -> Option<String> {
    match (lhs, rhs) {
        (Some(a), Some(b)) if a == b => Some(a),
        (Some(_), Some(_)) => None,
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
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
    let (local, remote) = match (p.target.as_str(), p.field.as_str()) {
        ("ipv4-addr", "value") | ("ipv6-addr", "value") => ("LocalIP", "RemoteIP"),
        ("mac-addr", "value") => ("LocalMAC", "RemoteMAC"),
        _ => return Ok(None),
    };
    let op = match p.op {
        IrOp::Eq => "==",
        IrOp::Ne => "!=",
        IrOp::Matches => "matches regex",
        IrOp::IsSubset => "",
        _ => bail!("KQL standalone network observables only support =, != and MATCHES/LIKE"),
    };
    let value = match &p.value {
        IrValue::String(s) => s,
        _ => bail!("KQL standalone network observable requires string value"),
    };
    let cond = match p.op {
        IrOp::IsSubset => {
            let fn_name = if p.target == "ipv6-addr" {
                "ipv6_is_in_range"
            } else {
                "ipv4_is_in_range"
            };
            format!("({fn_name}({local}, \"{value}\") or {fn_name}({remote}, \"{value}\"))")
        }
        _ => format!("({local} {op} \"{value}\" or {remote} {op} \"{value}\")"),
    };
    Ok(Some(cond))
}

fn lower_subset_predicate(p: &IrPredicate) -> Result<KqlPred> {
    let mapping = map_field(p)?;
    let cidr = match &p.value {
        IrValue::String(s) => s,
        _ => bail!("KQL ISSUBSET requires a CIDR string"),
    };
    if !matches!(
        (p.target.as_str(), p.field.as_str()),
        ("ipv4-addr", "value")
            | ("ipv6-addr", "value")
            | ("network-traffic", "src_ref.value")
            | ("network-traffic", "dst_ref.value")
    ) {
        bail!(
            "KQL emitter does not support ISSUBSET for {}:{}",
            p.target,
            p.field
        );
    }
    let fn_name = if cidr.contains(':') {
        "ipv6_is_in_range"
    } else {
        "ipv4_is_in_range"
    };
    let mut notes = mapping.notes;
    notes.push(
        "ISSUBSET semantics depend on backend CIDR helper behavior and field typing".to_string(),
    );
    if matches!(
        (p.target.as_str(), p.field.as_str()),
        ("network-traffic", "src_ref.value") | ("network-traffic", "dst_ref.value")
    ) {
        notes.push(
            "network-traffic:*_ref.value ISSUBSET assumes IP-typed refs; add *_ref.type for stronger semantics"
                .to_string(),
        );
    }
    Ok(KqlPred {
        table: mapping.table,
        condition: format!("{fn_name}({}, \"{cidr}\")", mapping.field),
        notes,
    })
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

use anyhow::{Result, bail};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::emitters::EmitResult;
use crate::ir::{IrExpr, IrOp, IrPredicate, IrValue};

pub fn emit(ir: &IrExpr, description: Option<&str>) -> Result<EmitResult> {
    let predicates = match ir {
        IrExpr::Predicate(p) => vec![p.clone()],
        IrExpr::All(exprs) => collect_predicates(exprs)?,
        IrExpr::Any(_) => {
            return Ok(EmitResult::unsupported(
                "YARA emitter does not support observation operators (OR/FOLLOWEDBY) for now",
            ));
        }
        IrExpr::FollowedBy(_) => {
            return Ok(EmitResult::unsupported(
                "YARA emitter does NOT support FOLLOWEDBY sequence semantics",
            ));
        }
        IrExpr::Qualified(_, _) => {
            return Ok(EmitResult::unsupported(
                "YARA emitter does NOT support observation qualifiers (REPEATS/WITHIN/START STOP) in this baseline",
            ));
        }
    };

    let mut conditions = Vec::new();
    let mut strings = Vec::new();
    let mut notes = Vec::new();

    let mut auto_counter = 0usize;

    for (idx, p) in predicates.iter().enumerate() {
        match (p.target.as_str(), p.field.as_str(), &p.value) {
            ("process", _, _) => bail!("YARA does not support process metadata semantics directly"),
            ("windows-registry-key", _, _) => {
                bail!("YARA does not support windows-registry-key metadata semantics directly")
            }
            ("autonomous-system", _, _) => {
                bail!("YARA does not support autonomous-system telemetry semantics directly")
            }
            ("directory", _, _) => {
                bail!("YARA does not support directory metadata semantics directly")
            }
            ("network-traffic", _, _) => {
                bail!("YARA does not support network-traffic event semantics directly")
            }
            ("ipv4-addr", "value", _)
            | ("ipv6-addr", "value", _)
            | ("mac-addr", "value", _)
            | ("domain-name", "value", _)
            | ("url", "value", _) => {
                bail!(
                    "YARA does not support standalone network observable semantics as telemetry predicates"
                )
            }
            ("email-message", _, _) => {
                bail!("YARA does not support email-message event metadata semantics directly")
            }
            ("file", field, IrValue::String(val)) if field.starts_with("hashes.") => {
                let hash_fn = yara_hash_function(field).ok_or_else(|| {
                    anyhow::anyhow!(
                        "YARA only supports MD5/SHA-1/SHA-256 for file hashes; unsupported {}",
                        field
                    )
                })?;
                match p.op {
                    IrOp::Eq => conditions.push(format!("{hash_fn}(0, filesize) == \"{val}\"")),
                    IrOp::Ne => conditions.push(format!("{hash_fn}(0, filesize) != \"{val}\"")),
                    _ => bail!("YARA hash predicates only support = and !="),
                }
            }
            ("artifact", field, IrValue::String(_)) if field.starts_with("hashes.") => {
                bail!("YARA does not support artifact hash metadata semantics directly");
            }
            ("artifact", "mime_type", _) => {
                bail!("YARA does not support artifact:mime_type metadata semantics directly");
            }
            ("artifact", "payload_bin", IrValue::Hex(bytes)) => {
                if !matches!(p.op, IrOp::Eq | IrOp::Ne) {
                    bail!("YARA artifact:payload_bin binary predicates only support = and !=");
                }
                auto_counter += 1;
                let name = format!("$payload{}", auto_counter);
                let byte_seq = hex_to_spaced(bytes)?;
                let byte_len = hex_byte_len(bytes)?;
                strings.push(format!("{name} = {{ {byte_seq} }}"));
                conditions.push(full_payload_condition(&name, byte_len, p.op.clone())?);
            }
            ("artifact", "payload_bin", IrValue::String(v)) => {
                if !matches!(p.op, IrOp::Matches) {
                    bail!("YARA artifact:payload_bin string predicates only support MATCHES/LIKE");
                }
                auto_counter += 1;
                let name = format!("$payload_re{}", auto_counter);
                let regex = escape_regex_delimiter(v);
                strings.push(format!("{name} = /{regex}/"));
                conditions.push(name.to_string());
                notes.push(
                    "artifact:payload_bin MATCHES translated to YARA regex over scanned bytes; backend regex behavior can vary"
                        .to_string(),
                );
            }
            ("file", "magic_number_hex", IrValue::Hex(bytes)) => {
                let name = format!("$magic{}", idx);
                let byte_seq = hex_to_spaced(bytes)?;
                strings.push(format!("{name} = {{ {byte_seq} }}"));
                push_string_condition(&mut conditions, &name, p.op.clone(), true)?;
            }
            ("file", "magic_number_hex", IrValue::String(bytes)) => {
                let name = format!("$magic{}", idx);
                let byte_seq = hex_to_spaced(bytes)?;
                strings.push(format!("{name} = {{ {byte_seq} }}"));
                push_string_condition(&mut conditions, &name, p.op.clone(), true)?;
            }
            ("file", "atime", IrValue::Timestamp(_))
            | ("file", "ctime", IrValue::Timestamp(_))
            | ("file", "mtime", IrValue::Timestamp(_)) => {
                bail!("YARA emitter does not support timestamp predicates for file timestamps");
            }
            ("file", "size", IrValue::Integer(size)) => {
                conditions.push(yara_numeric_compare("filesize", p.op.clone(), *size)?);
            }
            ("file", "name", IrValue::String(v)) => {
                let _ = v;
                bail!("YARA does not support file:name metadata semantics directly");
            }
            (_, _, IrValue::String(_)) => {
                bail!(
                    "YARA has no honest mapping for {}:{} without collapsing metadata to raw content matching",
                    p.target,
                    p.field
                );
            }
            (_, _, IrValue::Hex(bytes)) => {
                if !matches!(p.op, IrOp::Eq | IrOp::Ne) {
                    bail!("YARA hex predicates only support = and !=");
                }
                auto_counter += 1;
                let name = format!("$auto{}", auto_counter);
                let byte_seq = hex_to_spaced(bytes)?;
                strings.push(format!("{name} = {{ {byte_seq} }}"));
                push_string_condition(&mut conditions, &name, p.op.clone(), false)?;
            }
            (_, _, IrValue::Integer(i)) => {
                bail!(
                    "YARA has no honest mapping for integer metadata predicate {}:{} ({i})",
                    p.target,
                    p.field
                );
            }
            (_, _, IrValue::Timestamp(_)) => {
                bail!(
                    "YARA has no honest mapping for timestamp metadata predicate {}:{}",
                    p.target,
                    p.field
                );
            }
            (_, _, IrValue::Boolean(_)) => {
                bail!("YARA boolean predicates are not supported")
            }
        }
    }

    let strings_section = if strings.is_empty() {
        String::new()
    } else {
        format!("  strings:\n    {}\n", strings.join("\n    "))
    };

    let condition = if conditions.is_empty() {
        bail!("YARA emitter received no usable predicates");
    } else {
        conditions.join(" and ")
    };

    let meta = description
        .map(|d| {
            format!(
                "  meta:\n    description = \"[SPUC Generated YARA Rule] {}\"\n",
                d
            )
        })
        .unwrap_or_else(|| {
            "  meta:\n    description = \"[SPUC Generated YARA Rule]\"\n".to_string()
        });
    let rule_name = build_rule_name(&condition, &strings);
    let rule =
        format!("rule {rule_name} {{\n{meta}{strings_section}  condition:\n    {condition}\n}}");

    notes.sort();
    notes.dedup();
    Ok(if notes.is_empty() {
        EmitResult::exact(rule)
    } else {
        EmitResult {
            status: crate::emitters::FidelityStatus::Partial,
            notes,
            rule: Some(rule),
            cause: None,
        }
    })
}

fn collect_predicates(exprs: &[IrExpr]) -> Result<Vec<IrPredicate>> {
    let mut predicates = Vec::new();
    for expr in exprs {
        match expr {
            IrExpr::Predicate(p) => predicates.push(p.clone()),
            IrExpr::All(nested) => predicates.extend(collect_predicates(nested)?),
            IrExpr::Any(_) => bail!("YARA emitter does not support OR inside AND"),
            IrExpr::FollowedBy(_) => {
                bail!("YARA emitter does NOT support FOLLOWEDBY sequence semantics")
            }
            IrExpr::Qualified(_, _) => {
                bail!(
                    "YARA emitter does NOT support observation qualifiers (REPEATS/WITHIN/START STOP) in this baseline"
                )
            }
        }
    }
    Ok(predicates)
}

fn push_string_condition(
    conditions: &mut Vec<String>,
    name: &str,
    op: IrOp,
    at_zero: bool,
) -> Result<()> {
    let base = if at_zero {
        format!("{name} at 0")
    } else {
        name.to_string()
    };
    match op {
        IrOp::Eq => conditions.push(base),
        IrOp::Ne => conditions.push(format!("not ({base})")),
        _ => bail!("YARA byte-pattern predicates only support = and !="),
    }
    Ok(())
}

fn yara_numeric_compare(field: &str, op: IrOp, value: i64) -> Result<String> {
    let out = match op {
        IrOp::Eq => format!("{field} == {value}"),
        IrOp::Ne => format!("{field} != {value}"),
        IrOp::Gt => format!("{field} > {value}"),
        IrOp::Ge => format!("{field} >= {value}"),
        IrOp::Lt => format!("{field} < {value}"),
        IrOp::Le => format!("{field} <= {value}"),
        _ => bail!("YARA numeric predicates only support =, !=, >, >=, < and <="),
    };
    Ok(out)
}

fn escape_regex_delimiter(input: &str) -> String {
    input.replace('/', "\\/")
}

fn build_rule_name(condition: &str, strings: &[String]) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut hasher = DefaultHasher::new();
    condition.hash(&mut hasher);
    strings.hash(&mut hasher);
    let h = hasher.finish();
    format!("spuc_rule_{ts}_{:08x}", (h & 0xffff_ffff) as u32)
}

fn yara_hash_function(field: &str) -> Option<&'static str> {
    if field.starts_with("hashes.MD5") {
        Some("hash.md5")
    } else if field.starts_with("hashes.SHA-1") {
        Some("hash.sha1")
    } else if field.starts_with("hashes.SHA-256") {
        Some("hash.sha256")
    } else {
        None
    }
}

fn hex_to_spaced(s: &str) -> Result<String> {
    let clean = s.replace(|c: char| c.is_whitespace(), "");
    if clean.len() % 2 != 0 {
        bail!("magic_number_hex must have even number of hex digits");
    }
    let mut bytes = Vec::new();
    let chars: Vec<char> = clean.chars().collect();
    for chunk in chars.chunks(2) {
        bytes.push(format!("{}{}", chunk[0], chunk[1]).to_uppercase());
    }
    Ok(bytes.join(" "))
}

fn hex_byte_len(s: &str) -> Result<usize> {
    let clean = s.replace(|c: char| c.is_whitespace(), "");
    if clean.len() % 2 != 0 {
        bail!("hex payload must have even number of digits");
    }
    Ok(clean.len() / 2)
}

fn full_payload_condition(name: &str, byte_len: usize, op: IrOp) -> Result<String> {
    let eq = format!("({name} at 0 and filesize == {byte_len})");
    match op {
        IrOp::Eq => Ok(eq),
        IrOp::Ne => Ok(format!("not {eq}")),
        _ => bail!("YARA artifact:payload_bin equality only supports = and !="),
    }
}

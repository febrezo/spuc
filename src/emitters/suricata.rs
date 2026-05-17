use anyhow::{bail, Result};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::emitters::{EmitResult, FidelityStatus};
use crate::ir::{IrExpr, IrOp, IrPredicate, IrValue};

pub fn emit(ir: &IrExpr, description: Option<&str>) -> Result<EmitResult> {
    let has_network = contains_network_traffic(ir);
    let has_standalone = contains_standalone_network_observable(ir);
    if let Some(ips) = collect_ipv4_any(ir)? {
        let joined = format!("[{}]", ips.join(","));
        let sid_dst = sid_for("suricata_any_dst", &joined);
        let sid_src = sid_for("suricata_any_src", &joined);
        let out = [
            format!(
                "alert ip any any -> {joined} any (msg:\"{}\"; sid:{sid_dst}; rev:1;)",
                suricata_msg("SPUC generated Suricata rule - dst match", description)
            ),
            format!(
                "alert ip {joined} any -> any any (msg:\"{}\"; sid:{sid_src}; rev:1;)",
                suricata_msg("SPUC generated Suricata rule - src match", description)
            ),
        ]
        .join("\n");
        if has_standalone && !has_network {
            return Ok(EmitResult {
                status: FidelityStatus::BackendDependent,
                notes: vec![
                    "standalone IP observables are backend-dependent mappings without full network-traffic context".to_string(),
                    "standalone IP lowering emits source and destination variants; directionality remains ambiguous".to_string(),
                ],
                rule: Some(out),
                cause: None,
            });
        }
        return Ok(EmitResult::exact(out));
    }

    let artifact_payload = contains_artifact_payload(ir);
    let payload_equality = contains_payload_equality(ir);
    let payload_regex = contains_payload_regex(ir);
    let has_subset = contains_issubset(ir);
    match lower_expr(ir, description) {
        Ok(rules) => {
            if artifact_payload {
                let mut notes = vec![
                    "artifact:payload_bin mapped to Suricata content/pcre over payload bytes; semantics are backend-dependent".to_string(),
                ];
                let status = if payload_equality {
                    notes.push("artifact:payload_bin equality is lowered to containment in Suricata content matching".to_string());
                    notes.push("@status:partial".to_string());
                    FidelityStatus::Partial
                } else {
                    FidelityStatus::BackendDependent
                };
                if payload_regex {
                    notes.push("regex behavior can be backend-dependent".to_string());
                }
                Ok(EmitResult {
                    status,
                    notes,
                    rule: Some(rules.join("\n")),
                    cause: None,
                })
            } else {
                if has_standalone && !has_network {
                    Ok(EmitResult {
                        status: FidelityStatus::BackendDependent,
                        notes: vec![
                            "standalone IP observables are backend-dependent mappings without full network-traffic context".to_string(),
                            "standalone IP lowering emits source and destination variants; directionality remains ambiguous".to_string(),
                        ],
                        rule: Some(rules.join("\n")),
                        cause: None,
                    })
                } else if has_subset {
                    Ok(EmitResult {
                        status: FidelityStatus::BackendDependent,
                        notes: vec![
                            "ISSUBSET lowered to Suricata CIDR address matching; semantics are backend-dependent for subset intent".to_string(),
                        ],
                        rule: Some(rules.join("\n")),
                        cause: None,
                    })
                } else {
                    Ok(EmitResult::exact(rules.join("\n")))
                }
            }
        }
        Err(e) => Ok(EmitResult::unsupported(e.to_string())),
    }
}

fn lower_expr(expr: &IrExpr, description: Option<&str>) -> Result<Vec<String>> {
    match expr {
        IrExpr::Predicate(p) => Ok(vec![emit_rule(std::slice::from_ref(p), description)?]),
        IrExpr::All(exprs) => {
            let predicates = collect_predicates(exprs)?;
            Ok(vec![emit_rule(&predicates, description)?])
        }
        IrExpr::Any(exprs) => {
            let mut rules = Vec::new();
            for branch in exprs {
                rules.extend(lower_expr(branch, description)?);
            }
            Ok(rules)
        }
        IrExpr::FollowedBy(_) => {
            bail!("Suricata does NOT support FOLLOWEDBY sequence semantics yet")
        }
        IrExpr::Qualified(_, _) => bail!(
            "Suricata does NOT support observation qualifiers (REPEATS/WITHIN/START STOP) in this baseline"
        ),
    }
}

fn collect_predicates(exprs: &[IrExpr]) -> Result<Vec<IrPredicate>> {
    let mut predicates = Vec::new();

    for expr in exprs {
        match expr {
            IrExpr::Predicate(p) => predicates.push(p.clone()),
            IrExpr::All(nested) => predicates.extend(collect_predicates(nested)?),
            IrExpr::Any(_) => bail!("OR inside an AND is not supported for suricata yet"),
            IrExpr::FollowedBy(_) => {
                bail!("Suricata does NOT support FOLLOWEDBY sequence semantics yet")
            }
            IrExpr::Qualified(_, _) => {
                bail!(
                    "Suricata does NOT support observation qualifiers (REPEATS/WITHIN/START STOP) in this baseline"
                )
            }
        }
    }

    Ok(predicates)
}

fn emit_rule(predicates: &[IrPredicate], description: Option<&str>) -> Result<String> {
    let mut proto: Option<String> = None;
    let mut src_ip: Option<String> = None;
    let mut dst_ip: Option<String> = None;
    let mut src_port: Option<i64> = None;
    let mut dst_port: Option<i64> = None;
    let mut payload_opts: Vec<String> = Vec::new();

    for predicate in predicates {
        if !matches!(
            (predicate.target.as_str(), predicate.field.as_str()),
            ("artifact", "payload_bin")
        ) && (predicate.op != IrOp::Eq
            && (predicate.op != IrOp::IsSubset || !is_ip_predicate(predicate)))
        {
            bail!(
                "Suricata does NOT support operator {} yet",
                op_label(&predicate.op)
            );
        }

        match (
            predicate.target.as_str(),
            predicate.field.as_str(),
            &predicate.value,
        ) {
            ("network-traffic", "src_ref.value", IrValue::String(ip))
                if matches!(predicate.op, IrOp::Eq | IrOp::IsSubset) =>
            {
                src_ip = Some(ip.clone())
            }
            ("ipv4-addr", "value", IrValue::String(ip))
                if matches!(predicate.op, IrOp::Eq | IrOp::IsSubset) =>
            {
                dst_ip = Some(ip.clone())
            }
            ("network-traffic", "protocols", IrValue::String(p)) => {
                proto = Some(normalize_proto(p)?);
            }
            ("network-traffic", "src_port", IrValue::Integer(port)) => src_port = Some(*port),
            ("network-traffic", "dst_port", IrValue::Integer(port)) => dst_port = Some(*port),
            ("network-traffic", "dst_ref.value", IrValue::String(ip))
                if matches!(predicate.op, IrOp::Eq | IrOp::IsSubset) =>
            {
                dst_ip = Some(ip.clone())
            }
            ("artifact", "payload_bin", IrValue::Hex(bytes)) => {
                let content = bytes_to_suricata_content(bytes)?;
                match predicate.op {
                    IrOp::Eq => payload_opts.push(format!("content:\"{content}\";")),
                    IrOp::Ne => payload_opts.push(format!("content:!\"{content}\";")),
                    _ => {
                        bail!("Suricata artifact:payload_bin only supports =, != and MATCHES/LIKE")
                    }
                }
            }
            ("artifact", "payload_bin", IrValue::String(re)) => {
                if predicate.op != IrOp::Matches {
                    bail!("Suricata artifact:payload_bin regex predicates require MATCHES/LIKE");
                }
                payload_opts.push(format!("pcre:\"/{}/s\";", escape_suricata_pcre(re)));
            }
            ("artifact", "mime_type", _) => {
                bail!("Suricata does NOT support predicate artifact:mime_type for now");
            }
            ("file", "created", IrValue::Timestamp(ts)) => {
                bail!("Suricata does NOT support timestamp predicate file:created ({ts})");
            }
            _ => bail!(
                "Suricata does NOT support predicate {}:{} for now",
                predicate.target,
                predicate.field
            ),
        }
    }

    let mut proto = proto.unwrap_or_else(|| {
        if src_port.is_some() || dst_port.is_some() {
            "tcp".to_string()
        } else {
            "ip".to_string()
        }
    });
    if !payload_opts.is_empty() && proto == "ip" {
        proto = "tcp".to_string();
    }
    let payload = if payload_opts.is_empty() {
        String::new()
    } else {
        format!("{} ", payload_opts.join(" "))
    };

    let sid_seed = format!(
        "{}|{:?}|{:?}|{:?}|{:?}|{}",
        proto, src_ip, src_port, dst_ip, dst_port, payload
    );
    let sid = sid_for("suricata_rule", &sid_seed);

    match (src_ip.as_deref(), src_port, dst_ip.as_deref(), dst_port) {
        (Some(src), Some(sport), Some(dst), Some(dport)) => Ok(format!(
            "alert {} {src} {sport} -> {dst} {dport} (msg:\"{}\"; {payload}sid:{sid}; rev:1;)",
            proto,
            suricata_msg("SPUC generated Suricata rule", description)
        )),
        (Some(src), None, Some(dst), Some(dport)) => Ok(format!(
            "alert {} {src} any -> {dst} {dport} (msg:\"{}\"; {payload}sid:{sid}; rev:1;)",
            proto,
            suricata_msg("SPUC generated Suricata rule", description)
        )),
        (Some(src), Some(sport), Some(dst), None) => Ok(format!(
            "alert {} {src} {sport} -> {dst} any (msg:\"{}\"; {payload}sid:{sid}; rev:1;)",
            proto,
            suricata_msg("SPUC generated Suricata rule", description)
        )),
        (Some(src), None, Some(dst), None) => Ok(format!(
            "alert {} {src} any -> {dst} any (msg:\"{}\"; {payload}sid:{sid}; rev:1;)",
            proto,
            suricata_msg("SPUC generated Suricata rule", description)
        )),
        (Some(src), Some(sport), None, Some(dport)) => Ok(format!(
            "alert {} {src} {sport} -> any {dport} (msg:\"{}\"; {payload}sid:{sid}; rev:1;)",
            proto,
            suricata_msg("SPUC generated Suricata rule", description)
        )),
        (None, None, Some(dst), Some(dport)) => Ok(format!(
            "alert {} any any -> {dst} {dport} (msg:\"{}\"; {payload}sid:{sid}; rev:1;)",
            proto,
            suricata_msg("SPUC generated Suricata rule", description)
        )),
        (None, None, Some(dst), None) => Ok(format!(
            "alert {} any any -> {dst} any (msg:\"{}\"; {payload}sid:{sid}; rev:1;)",
            proto,
            suricata_msg("SPUC generated Suricata rule", description)
        )),
        (Some(src), Some(sport), None, None) => Ok(format!(
            "alert {} {src} {sport} -> any any (msg:\"{}\"; {payload}sid:{sid}; rev:1;)",
            proto,
            suricata_msg("SPUC generated Suricata rule", description)
        )),
        (Some(src), None, None, None) => Ok(format!(
            "alert {} {src} any -> any any (msg:\"{}\"; {payload}sid:{sid}; rev:1;)",
            proto,
            suricata_msg("SPUC generated Suricata rule", description)
        )),
        (None, None, None, Some(dport)) => Ok(format!(
            "alert {} any any -> any {dport} (msg:\"{}\"; {payload}sid:{sid}; rev:1;)",
            proto,
            suricata_msg("SPUC generated Suricata rule", description)
        )),
        (None, Some(sport), None, _) => Ok(format!(
            "alert {} any {sport} -> any any (msg:\"{}\"; {payload}sid:{sid}; rev:1;)",
            proto,
            suricata_msg("SPUC generated Suricata rule", description)
        )),
        (None, None, None, None) if !payload_opts.is_empty() => Ok(format!(
            "alert tcp any any -> any any (msg:\"{}\"; {payload}sid:{sid}; rev:1;)",
            suricata_msg("SPUC generated Suricata rule", description)
        )),
        (None, None, None, None) => bail!("suricata received an empty predicate list"),
        _ => bail!("suricata could not build a rule from the given predicate combination"),
    }
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

fn normalize_proto(raw: &str) -> Result<String> {
    match raw.to_ascii_lowercase().as_str() {
        "tcp" | "udp" | "icmp" | "ip" => Ok(raw.to_ascii_lowercase()),
        other => bail!("unsupported suricata protocol '{other}' (expected tcp/udp/icmp/ip)"),
    }
}

fn sid_for(kind: &str, seed: &str) -> u32 {
    let mut hasher = DefaultHasher::new();
    kind.hash(&mut hasher);
    seed.hash(&mut hasher);
    2_000_000 + (hasher.finish() % 1_000_000) as u32
}

fn suricata_msg(base: &str, description: Option<&str>) -> String {
    match description {
        Some(desc) => format!("[SPUC Generated Suricata Rule] {desc}"),
        None => format!("[SPUC Generated Suricata Rule] {base}"),
    }
}

fn collect_ipv4_any(ir: &IrExpr) -> Result<Option<Vec<String>>> {
    match ir {
        IrExpr::Predicate(p) => {
            if matches!(p.op, IrOp::Eq | IrOp::IsSubset) && is_standalone_ip_observable(p) {
                if let IrValue::String(ip) = &p.value {
                    return Ok(Some(vec![ip.clone()]));
                }
            }
            Ok(None)
        }
        IrExpr::Any(branches) if !branches.is_empty() => {
            let mut ips = Vec::new();
            for branch in branches {
                if let IrExpr::Predicate(p) = branch {
                    if matches!(p.op, IrOp::Eq | IrOp::IsSubset) && is_standalone_ip_observable(p) {
                        if let IrValue::String(ip) = &p.value {
                            ips.push(ip.clone());
                            continue;
                        }
                    }
                }
                return Ok(None);
            }
            Ok(Some(ips))
        }
        IrExpr::FollowedBy(_) => Ok(None),
        _ => Ok(None),
    }
}

fn is_ip_predicate(p: &IrPredicate) -> bool {
    matches!(
        (p.target.as_str(), p.field.as_str()),
        ("ipv4-addr", "value")
            | ("ipv6-addr", "value")
            | ("network-traffic", "src_ref.value")
            | ("network-traffic", "dst_ref.value")
    )
}

fn is_standalone_ip_observable(p: &IrPredicate) -> bool {
    matches!(
        (p.target.as_str(), p.field.as_str()),
        ("ipv4-addr", "value") | ("ipv6-addr", "value")
    )
}

fn contains_network_traffic(ir: &IrExpr) -> bool {
    match ir {
        IrExpr::Predicate(p) => p.target == "network-traffic",
        IrExpr::All(v) | IrExpr::Any(v) | IrExpr::FollowedBy(v) => {
            v.iter().any(contains_network_traffic)
        }
        IrExpr::Qualified(inner, _) => contains_network_traffic(inner),
    }
}

fn contains_standalone_network_observable(ir: &IrExpr) -> bool {
    match ir {
        IrExpr::Predicate(p) => matches!(p.target.as_str(), "ipv4-addr" | "ipv6-addr"),
        IrExpr::All(v) | IrExpr::Any(v) | IrExpr::FollowedBy(v) => {
            v.iter().any(contains_standalone_network_observable)
        }
        IrExpr::Qualified(inner, _) => contains_standalone_network_observable(inner),
    }
}

fn contains_artifact_payload(ir: &IrExpr) -> bool {
    match ir {
        IrExpr::Predicate(p) => {
            p.target == "artifact" && (p.field == "payload_bin" || p.field == "mime_type")
        }
        IrExpr::All(v) | IrExpr::Any(v) | IrExpr::FollowedBy(v) => {
            v.iter().any(contains_artifact_payload)
        }
        IrExpr::Qualified(inner, _) => contains_artifact_payload(inner),
    }
}

fn contains_payload_regex(ir: &IrExpr) -> bool {
    match ir {
        IrExpr::Predicate(p) => {
            p.target == "artifact" && p.field == "payload_bin" && p.op == IrOp::Matches
        }
        IrExpr::All(v) | IrExpr::Any(v) | IrExpr::FollowedBy(v) => {
            v.iter().any(contains_payload_regex)
        }
        IrExpr::Qualified(inner, _) => contains_payload_regex(inner),
    }
}

fn contains_payload_equality(ir: &IrExpr) -> bool {
    match ir {
        IrExpr::Predicate(p) => {
            p.target == "artifact"
                && p.field == "payload_bin"
                && matches!(p.op, IrOp::Eq | IrOp::Ne)
        }
        IrExpr::All(v) | IrExpr::Any(v) | IrExpr::FollowedBy(v) => {
            v.iter().any(contains_payload_equality)
        }
        IrExpr::Qualified(inner, _) => contains_payload_equality(inner),
    }
}

fn contains_issubset(ir: &IrExpr) -> bool {
    match ir {
        IrExpr::Predicate(p) => p.op == IrOp::IsSubset,
        IrExpr::All(v) | IrExpr::Any(v) | IrExpr::FollowedBy(v) => v.iter().any(contains_issubset),
        IrExpr::Qualified(inner, _) => contains_issubset(inner),
    }
}

fn bytes_to_suricata_content(hex: &str) -> Result<String> {
    let clean = hex.replace(|c: char| c.is_whitespace(), "");
    if clean.len() % 2 != 0 || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("invalid hex payload literal");
    }
    let mut out = String::from("|");
    let mut i = 0;
    while i < clean.len() {
        out.push_str(&clean[i..i + 2].to_ascii_uppercase());
        if i + 2 < clean.len() {
            out.push(' ');
        }
        i += 2;
    }
    out.push('|');
    Ok(out)
}

fn escape_suricata_pcre(input: &str) -> String {
    input.replace('/', "\\/")
}

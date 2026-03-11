use anyhow::{Result, anyhow};
use serde::Serialize;

use crate::emulation::ability::Ability;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MaterializedDirectory {
    pub path: String,
    pub source_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MaterializedFile {
    pub path: String,
    pub size_bytes: Option<u64>,
    pub content_literal: Option<String>,
    pub content_regex: Option<String>,
    pub source_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MaterializedProcess {
    pub command_line: String,
    pub process_name: Option<String>,
    pub working_directory: Option<String>,
    pub source_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MaterializedRegistry {
    pub key_path: String,
    pub value_name: Option<String>,
    pub value_data: Option<String>,
    pub value_type: Option<String>,
    pub subkey_count: Option<u32>,
    pub source_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MaterializedNetwork {
    pub mode: String,
    pub destination: String,
    pub port: Option<u16>,
    pub protocol: String,
    pub source_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MaterializationPlan {
    pub root_hint: String,
    pub directories: Vec<MaterializedDirectory>,
    pub files: Vec<MaterializedFile>,
    pub processes: Vec<MaterializedProcess>,
    pub registry: Vec<MaterializedRegistry>,
    pub network: Vec<MaterializedNetwork>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
struct StringConstraint {
    action_id: String,
    operator: String,
    value: String,
}

#[derive(Debug, Clone)]
struct IntConstraint {
    action_id: String,
    operator: String,
    value: i64,
}

pub fn build_materialization_plan(ability: &Ability) -> Result<MaterializationPlan> {
    let mut file_name = Vec::<StringConstraint>::new();
    let mut file_size = Vec::<IntConstraint>::new();
    let mut file_content = Vec::<StringConstraint>::new();
    let mut dir_path = Vec::<StringConstraint>::new();
    let mut process_command_line = Vec::<StringConstraint>::new();
    let mut process_name = Vec::<StringConstraint>::new();
    let mut process_cwd = Vec::<StringConstraint>::new();
    let mut registry_key = Vec::<StringConstraint>::new();
    let mut registry_value_name = Vec::<StringConstraint>::new();
    let mut registry_value_data = Vec::<StringConstraint>::new();
    let mut registry_value_type = Vec::<StringConstraint>::new();
    let mut registry_subkey_count = Vec::<IntConstraint>::new();
    let mut network_dst_host = Vec::<StringConstraint>::new();
    let mut network_protocol = Vec::<StringConstraint>::new();
    let mut network_dst_type = Vec::<StringConstraint>::new();
    let mut network_dst_port = Vec::<IntConstraint>::new();
    let mut dns_domain = Vec::<StringConstraint>::new();
    let mut notes = Vec::new();

    for action in &ability.actions {
        let obs = action.observable.to_ascii_lowercase();
        let op = action.operator.to_ascii_uppercase();
        let action_type = action.action_type.to_ascii_lowercase();
        if obs == "file:name"
            || action_type == "materialize_file_name"
            || action_type == "emit_file_name"
        {
            file_name.push(StringConstraint {
                action_id: action.id.clone(),
                operator: op,
                value: action.value.clone(),
            });
            continue;
        }
        if obs == "file:size"
            || action_type == "materialize_file_size"
            || action_type == "emit_file_size"
        {
            let parsed = action.value.trim().parse::<i64>().map_err(|_| {
                anyhow!(
                    "action '{}' has non-numeric file:size value '{}'",
                    action.id,
                    action.value
                )
            })?;
            file_size.push(IntConstraint {
                action_id: action.id.clone(),
                operator: op,
                value: parsed,
            });
            continue;
        }
        if obs == "artifact:payload_bin" || action_type == "materialize_file_content" {
            file_content.push(StringConstraint {
                action_id: action.id.clone(),
                operator: op,
                value: action.value.clone(),
            });
            continue;
        }
        if obs == "directory:path"
            || action_type == "materialize_directory_path"
            || action_type == "emit_directory_path"
        {
            dir_path.push(StringConstraint {
                action_id: action.id.clone(),
                operator: op,
                value: action.value.clone(),
            });
            continue;
        }
        if obs == "process:command_line" || action_type == "emit_process_command_line" {
            process_command_line.push(StringConstraint {
                action_id: action.id.clone(),
                operator: op,
                value: action.value.clone(),
            });
            continue;
        }
        if obs == "process:name" || action_type == "emit_process_name" {
            process_name.push(StringConstraint {
                action_id: action.id.clone(),
                operator: op,
                value: action.value.clone(),
            });
            continue;
        }
        if obs == "process:cwd" || action_type == "emit_process_cwd" {
            process_cwd.push(StringConstraint {
                action_id: action.id.clone(),
                operator: op,
                value: action.value.clone(),
            });
            continue;
        }
        if obs == "windows-registry-key:key" || action_type == "materialize_registry_key_path" {
            registry_key.push(StringConstraint {
                action_id: action.id.clone(),
                operator: op,
                value: action.value.clone(),
            });
            continue;
        }
        if obs == "windows-registry-key:values[*].name"
            || action_type == "materialize_registry_value_name"
        {
            registry_value_name.push(StringConstraint {
                action_id: action.id.clone(),
                operator: op,
                value: action.value.clone(),
            });
            continue;
        }
        if obs == "windows-registry-key:values[*].data"
            || action_type == "materialize_registry_value_data"
        {
            registry_value_data.push(StringConstraint {
                action_id: action.id.clone(),
                operator: op,
                value: action.value.clone(),
            });
            continue;
        }
        if obs == "windows-registry-key:values[*].data_type"
            || action_type == "materialize_registry_value_type"
        {
            registry_value_type.push(StringConstraint {
                action_id: action.id.clone(),
                operator: op,
                value: action.value.clone(),
            });
            continue;
        }
        if obs == "windows-registry-key:number_of_subkeys"
            || action_type == "materialize_registry_subkey_count"
        {
            let parsed = action.value.trim().parse::<i64>().map_err(|_| {
                anyhow!(
                    "action '{}' has non-numeric windows-registry-key:number_of_subkeys value '{}'",
                    action.id,
                    action.value
                )
            })?;
            registry_subkey_count.push(IntConstraint {
                action_id: action.id.clone(),
                operator: op,
                value: parsed,
            });
            continue;
        }
        if obs == "network-traffic:dst_ref.value" || action_type == "emit_network_dst_host" {
            network_dst_host.push(StringConstraint {
                action_id: action.id.clone(),
                operator: op,
                value: action.value.clone(),
            });
            continue;
        }
        if obs == "network-traffic:dst_ref.type" || action_type == "emit_network_dst_type" {
            network_dst_type.push(StringConstraint {
                action_id: action.id.clone(),
                operator: op,
                value: action.value.clone(),
            });
            continue;
        }
        if obs == "network-traffic:protocols" || action_type == "emit_network_protocol" {
            network_protocol.push(StringConstraint {
                action_id: action.id.clone(),
                operator: op,
                value: action.value.clone(),
            });
            continue;
        }
        if obs == "network-traffic:dst_port" || action_type == "emit_network_dst_port" {
            let parsed = action.value.trim().parse::<i64>().map_err(|_| {
                anyhow!(
                    "action '{}' has non-numeric network-traffic:dst_port value '{}'",
                    action.id,
                    action.value
                )
            })?;
            network_dst_port.push(IntConstraint {
                action_id: action.id.clone(),
                operator: op,
                value: parsed,
            });
            continue;
        }
        if obs == "domain-name:value" || action_type == "emit_dns_query_domain" {
            dns_domain.push(StringConstraint {
                action_id: action.id.clone(),
                operator: op,
                value: action.value.clone(),
            });
            continue;
        }
        notes.push(format!(
            "action '{}' ({}) has no concrete materialization yet",
            action.id, action.observable
        ));
    }

    let mut directories = Vec::new();
    if !dir_path.is_empty() {
        let path = synthesize_string_constraints(&dir_path, "spuc-generated-directory", true)?;
        let source_actions = dir_path
            .iter()
            .map(|c| c.action_id.clone())
            .collect::<Vec<_>>();
        directories.push(MaterializedDirectory {
            path,
            source_actions,
        });
    }

    let mut files = Vec::new();
    if !file_name.is_empty() || !file_size.is_empty() || !file_content.is_empty() {
        let raw_name = if file_name.is_empty() {
            "spuc-generated-file.bin".to_string()
        } else {
            synthesize_string_constraints(&file_name, "spuc-generated-file.bin", false)?
        };
        let name = sanitize_path_component(&raw_name);
        let size_bytes = if file_size.is_empty() {
            None
        } else {
            Some(solve_size_constraints(&file_size)?)
        };
        let (content_literal, content_regex) = if file_content.is_empty() {
            (None, None)
        } else {
            let content = synthesize_string_constraints(&file_content, "spuc-content", false)?;
            let has_matches = file_content
                .iter()
                .any(|c| c.operator.eq_ignore_ascii_case("MATCHES"));
            if has_matches {
                (Some(content), Some(file_content[0].value.clone()))
            } else {
                (Some(content), None)
            }
        };
        let mut source_actions = file_name
            .iter()
            .map(|c| c.action_id.clone())
            .collect::<Vec<_>>();
        source_actions.extend(file_size.iter().map(|c| c.action_id.clone()));
        source_actions.extend(file_content.iter().map(|c| c.action_id.clone()));
        files.push(MaterializedFile {
            path: name,
            size_bytes,
            content_literal,
            content_regex,
            source_actions,
        });
    }

    let mut processes = Vec::new();
    if !process_command_line.is_empty() || !process_name.is_empty() || !process_cwd.is_empty() {
        let process_name_value = if process_name.is_empty() {
            None
        } else {
            Some(synthesize_string_constraints(
                &process_name,
                "spuc-process",
                false,
            )?)
        };
        let mut command_line = if process_command_line.is_empty() {
            process_name_value
                .as_ref()
                .map(|name| format!("{name} --spuc-benign"))
                .unwrap_or_else(|| "echo \"spuc process telemetry\"".to_string())
        } else {
            synthesize_string_constraints(
                &process_command_line,
                "echo \"spuc process telemetry\"",
                false,
            )?
        };
        if let Some(name) = &process_name_value {
            if !command_line
                .to_ascii_lowercase()
                .contains(&name.to_ascii_lowercase())
            {
                command_line = format!("{name} --spuc-benign");
            }
        }
        let working_directory = if process_cwd.is_empty() {
            None
        } else {
            Some(synthesize_string_constraints(
                &process_cwd,
                "spuc-generated-working-directory",
                true,
            )?)
        };
        let mut source_actions = process_command_line
            .iter()
            .map(|c| c.action_id.clone())
            .collect::<Vec<_>>();
        source_actions.extend(process_name.iter().map(|c| c.action_id.clone()));
        source_actions.extend(process_cwd.iter().map(|c| c.action_id.clone()));
        processes.push(MaterializedProcess {
            command_line,
            process_name: process_name_value,
            working_directory,
            source_actions,
        });
    }

    let mut registry = Vec::new();
    if !registry_key.is_empty()
        || !registry_value_name.is_empty()
        || !registry_value_data.is_empty()
        || !registry_value_type.is_empty()
        || !registry_subkey_count.is_empty()
    {
        let key_path = if registry_key.is_empty() {
            "HKEY_CURRENT_USER\\Software\\SPUC\\Generated".to_string()
        } else {
            synthesize_string_constraints(
                &registry_key,
                "HKEY_CURRENT_USER\\Software\\SPUC\\Generated",
                true,
            )?
        };
        let value_name = if registry_value_name.is_empty() {
            None
        } else {
            Some(synthesize_string_constraints(
                &registry_value_name,
                "SpucValue",
                false,
            )?)
        };
        let value_data = if registry_value_data.is_empty() {
            None
        } else {
            Some(synthesize_string_constraints(
                &registry_value_data,
                "spuc-registry-data",
                false,
            )?)
        };
        let value_type = if registry_value_type.is_empty() {
            None
        } else {
            let candidate = synthesize_string_constraints(&registry_value_type, "REG_SZ", false)?
                .to_uppercase();
            if candidate != "REG_SZ" && candidate != "REG_DWORD" {
                return Err(anyhow!(
                    "unsupported registry value type '{}', expected REG_SZ or REG_DWORD",
                    candidate
                ));
            }
            Some(candidate)
        };
        let subkey_count = if registry_subkey_count.is_empty() {
            None
        } else {
            let count = solve_bounded_int_constraints(&registry_subkey_count, 0, 64, 1)?;
            Some(u32::try_from(count).map_err(|_| anyhow!("registry subkey count overflow"))?)
        };
        let mut source_actions = registry_key
            .iter()
            .map(|c| c.action_id.clone())
            .collect::<Vec<_>>();
        source_actions.extend(registry_value_name.iter().map(|c| c.action_id.clone()));
        source_actions.extend(registry_value_data.iter().map(|c| c.action_id.clone()));
        source_actions.extend(registry_value_type.iter().map(|c| c.action_id.clone()));
        source_actions.extend(registry_subkey_count.iter().map(|c| c.action_id.clone()));
        registry.push(MaterializedRegistry {
            key_path,
            value_name,
            value_data,
            value_type,
            subkey_count,
            source_actions,
        });
    }

    let mut network = Vec::new();
    if !network_dst_host.is_empty() || !network_protocol.is_empty() || !network_dst_port.is_empty()
    {
        let destination = synthesize_string_constraints(&network_dst_host, "127.0.0.1", false)?;
        let protocol_raw = if network_protocol.is_empty() {
            "tcp".to_string()
        } else {
            synthesize_string_constraints(&network_protocol, "tcp", false)?
        };
        let protocol = normalize_network_protocol(&protocol_raw);
        let default_port = if protocol == "dns" { 53 } else { 443 };
        let port = if network_dst_port.is_empty() {
            default_port
        } else {
            u16::try_from(solve_bounded_int_constraints(
                &network_dst_port,
                1,
                65535,
                1,
            )?)
            .map_err(|_| anyhow!("network destination port out of range"))?
        };
        let mut source_actions = network_dst_host
            .iter()
            .map(|c| c.action_id.clone())
            .collect::<Vec<_>>();
        source_actions.extend(network_protocol.iter().map(|c| c.action_id.clone()));
        source_actions.extend(network_dst_port.iter().map(|c| c.action_id.clone()));
        source_actions.extend(network_dst_type.iter().map(|c| c.action_id.clone()));
        network.push(MaterializedNetwork {
            mode: "connect".to_string(),
            destination,
            port: Some(port),
            protocol,
            source_actions,
        });
    }

    if !dns_domain.is_empty() {
        let destination = synthesize_string_constraints(&dns_domain, "example.com", false)?;
        let port = if network_dst_port.is_empty() {
            53
        } else {
            u16::try_from(solve_bounded_int_constraints(
                &network_dst_port,
                1,
                65535,
                1,
            )?)
            .map_err(|_| anyhow!("dns destination port out of range"))?
        };
        let mut source_actions = dns_domain
            .iter()
            .map(|c| c.action_id.clone())
            .collect::<Vec<_>>();
        source_actions.extend(network_dst_port.iter().map(|c| c.action_id.clone()));
        network.push(MaterializedNetwork {
            mode: "dns_query".to_string(),
            destination,
            port: Some(port),
            protocol: "dns".to_string(),
            source_actions,
        });
    }

    Ok(MaterializationPlan {
        root_hint: "$HOME/.spuc-emulation".to_string(),
        directories,
        files,
        processes,
        registry,
        network,
        notes,
    })
}

fn synthesize_string_constraints(
    constraints: &[StringConstraint],
    fallback: &str,
    path_like: bool,
) -> Result<String> {
    let mut eq_values = constraints
        .iter()
        .filter(|c| c.operator.eq_ignore_ascii_case("EQ"))
        .map(|c| c.value.trim().to_string())
        .collect::<Vec<_>>();
    eq_values.dedup();
    if eq_values.len() > 1 {
        return Err(anyhow!(
            "conflicting equality constraints: {}",
            eq_values.join(", ")
        ));
    }

    let ne_values = constraints
        .iter()
        .filter(|c| c.operator.eq_ignore_ascii_case("NE"))
        .map(|c| c.value.trim().to_string())
        .collect::<Vec<_>>();

    let matches_values = constraints
        .iter()
        .filter(|c| c.operator.eq_ignore_ascii_case("MATCHES"))
        .map(|c| c.value.trim().to_string())
        .collect::<Vec<_>>();

    let mut candidate = if let Some(eq) = eq_values.first() {
        eq.clone()
    } else if let Some(regex) = matches_values.first() {
        synthesize_regex_sample(regex, fallback)?
    } else {
        fallback.to_string()
    };

    if candidate.trim().is_empty() {
        candidate = fallback.to_string();
    }
    while ne_values.iter().any(|ne| ne == &candidate) {
        candidate.push_str("_spuc");
    }

    if path_like && candidate.trim().is_empty() {
        return Err(anyhow!("unable to synthesize non-empty path"));
    }
    Ok(candidate)
}

fn solve_size_constraints(constraints: &[IntConstraint]) -> Result<u64> {
    let value = solve_bounded_int_constraints(constraints, 0, i64::MAX, 100)?;
    u64::try_from(value).map_err(|_| anyhow!("file:size must be >= 0"))
}

fn solve_bounded_int_constraints(
    constraints: &[IntConstraint],
    lower_bound: i64,
    upper_bound: i64,
    gt_margin: i64,
) -> Result<i64> {
    let mut eq: Option<i64> = None;
    let mut min_inclusive: i64 = lower_bound;
    let mut max_inclusive: i64 = upper_bound;
    let mut forbidden = Vec::<i64>::new();
    let mut max_gt: Option<i64> = None;
    let mut only_gt_constraints = true;

    for c in constraints {
        match c.operator.as_str() {
            "EQ" => {
                eq = Some(c.value);
                only_gt_constraints = false;
            }
            "NE" => {
                forbidden.push(c.value);
                only_gt_constraints = false;
            }
            "GT" => {
                min_inclusive = min_inclusive.max(c.value.saturating_add(1));
                max_gt = Some(max_gt.map_or(c.value, |current| current.max(c.value)));
            }
            "GE" => {
                min_inclusive = min_inclusive.max(c.value);
                only_gt_constraints = false;
            }
            "LT" => {
                max_inclusive = max_inclusive.min(c.value.saturating_sub(1));
                only_gt_constraints = false;
            }
            "LE" => {
                max_inclusive = max_inclusive.min(c.value);
                only_gt_constraints = false;
            }
            other => {
                return Err(anyhow!("unsupported numeric operator '{}'", other));
            }
        }
    }

    if let Some(eq_value) = eq {
        if eq_value < min_inclusive || eq_value > max_inclusive || forbidden.contains(&eq_value) {
            return Err(anyhow!("unsatisfiable numeric constraints"));
        }
        return Ok(eq_value);
    }

    if min_inclusive > max_inclusive {
        return Err(anyhow!("unsatisfiable numeric constraints"));
    }

    let mut candidate = min_inclusive;
    if only_gt_constraints && max_inclusive == i64::MAX {
        if let Some(gt) = max_gt {
            candidate = gt.saturating_add(gt_margin).max(min_inclusive);
        }
    }
    candidate = candidate.max(lower_bound).min(upper_bound);
    if candidate > max_inclusive {
        candidate = min_inclusive;
    }
    while forbidden.contains(&candidate) {
        candidate = candidate.saturating_add(1);
        if candidate > max_inclusive {
            return Err(anyhow!("unsatisfiable numeric constraints"));
        }
    }
    Ok(candidate)
}

fn normalize_network_protocol(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("dns") {
        "dns".to_string()
    } else if lower.contains("udp") {
        "udp".to_string()
    } else {
        "tcp".to_string()
    }
}

fn parse_repetition(chars: &[char], start: usize) -> Result<(usize, usize)> {
    if start >= chars.len() {
        return Ok((1, start));
    }
    match chars[start] {
        '*' => Ok((1, start + 1)),
        '+' => Ok((1, start + 1)),
        '?' => Ok((1, start + 1)),
        '{' => {
            let mut i = start + 1;
            let mut min_raw = String::new();
            while i < chars.len() && chars[i].is_ascii_digit() {
                min_raw.push(chars[i]);
                i += 1;
            }
            if min_raw.is_empty() {
                return Err(anyhow!("invalid quantifier: expected minimum repetition"));
            }
            if i < chars.len() && chars[i] == ',' {
                i += 1;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
            }
            if i >= chars.len() || chars[i] != '}' {
                return Err(anyhow!("invalid quantifier: unclosed quantifier"));
            }
            i += 1;
            let min_count = min_raw
                .parse::<usize>()
                .map_err(|_| anyhow!("invalid quantifier minimum"))?;
            Ok((min_count, i))
        }
        _ => Ok((1, start)),
    }
}

fn sample_char_from_class(class_raw: &str) -> char {
    let mut class = class_raw.chars().collect::<Vec<_>>();
    if class.is_empty() {
        return 'x';
    }
    let is_negated = class.first() == Some(&'^');
    if is_negated {
        class.remove(0);
    }
    if class.is_empty() {
        return if is_negated { 'x' } else { 'a' };
    }

    let mut i = 0usize;
    let mut positive_samples = Vec::new();
    while i < class.len() {
        let ch = class[i];
        if i + 2 < class.len() && class[i + 1] == '-' {
            positive_samples.push(ch);
            i += 3;
            continue;
        }
        positive_samples.push(ch);
        i += 1;
    }
    if !is_negated {
        return positive_samples.first().copied().unwrap_or('x');
    }

    let candidates = ['x', 'a', 'Z', '7', '_', '.'];
    for candidate in candidates {
        if !positive_samples.contains(&candidate) {
            return candidate;
        }
    }
    'x'
}

pub fn synthesize_regex_sample(pattern: &str, fallback: &str) -> Result<String> {
    let mut p = pattern.trim().to_string();
    while p.starts_with("(?i)") {
        p = p["(?i)".len()..].to_string();
    }
    if let Some(stripped) = p.strip_prefix('^') {
        p = stripped.to_string();
    }
    if let Some(stripped) = p.strip_suffix('$') {
        p = stripped.to_string();
    }
    if p.is_empty() {
        return Ok(fallback.to_string());
    }

    let chars = p.chars().collect::<Vec<_>>();
    let mut i = 0usize;
    let mut out = String::new();
    while i < chars.len() {
        let ch = chars[i];
        let token = match ch {
            '\\' => {
                i += 1;
                if i >= chars.len() {
                    return Err(anyhow!("invalid regex '{}': dangling escape", pattern));
                }
                let mapped = match chars[i] {
                    'd' => '7',
                    'w' => 'w',
                    's' => '_',
                    '.' => '.',
                    '\\' => '\\',
                    '/' => '/',
                    '-' => '-',
                    '_' => '_',
                    other => other,
                };
                i += 1;
                mapped
            }
            '.' => {
                i += 1;
                'x'
            }
            '[' => {
                i += 1;
                let class_start = i;
                let mut closed = false;
                while i < chars.len() {
                    if chars[i] == ']' {
                        closed = true;
                        break;
                    }
                    i += 1;
                }
                if !closed {
                    return Err(anyhow!(
                        "invalid regex '{}': unclosed character class",
                        pattern
                    ));
                }
                let class_raw = chars[class_start..i].iter().collect::<String>();
                i += 1;
                sample_char_from_class(&class_raw)
            }
            '*' | '+' | '?' => {
                return Err(anyhow!(
                    "invalid regex '{}': quantifier without preceding token",
                    pattern
                ));
            }
            '{' => {
                return Err(anyhow!(
                    "invalid regex '{}': quantifier without preceding token",
                    pattern
                ));
            }
            '(' | ')' | '|' => {
                return Err(anyhow!(
                    "regex '{}' uses unsupported construct '{}'",
                    pattern,
                    ch
                ));
            }
            other => {
                i += 1;
                other
            }
        };
        let (min_repetitions, next_i) = parse_repetition(&chars, i)
            .map_err(|err| anyhow!("invalid regex '{}': {}", pattern, err))?;
        i = next_i;
        let repeats = min_repetitions.max(1);
        for _ in 0..repeats {
            out.push(token);
        }
    }

    let normalized = out.trim().to_string();
    if normalized.is_empty() {
        Ok(fallback.to_string())
    } else {
        Ok(normalized)
    }
}

pub fn sanitize_path_component(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        if ch == '\\' || ch == '/' || ch.is_ascii_control() {
            continue;
        }
        out.push(ch);
    }
    let trimmed = out.trim().to_string();
    if trimmed.is_empty() {
        "spuc-generated-file.bin".to_string()
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regex_sample_handles_simple_suffix_pattern() {
        let sample = synthesize_regex_sample("^.*\\.log$", "fallback").expect("sample");
        assert!(sample.ends_with(".log"));
    }

    #[test]
    fn regex_sample_honors_character_class_and_quantifier() {
        let pattern = "^MZ[0-9]{2}$";
        let sample = synthesize_regex_sample(pattern, "fallback").expect("sample");
        assert_eq!(sample, "MZ00", "sample should satisfy minimum quantifier");
    }

    #[test]
    fn size_constraints_gt_prefers_margin() {
        let constraints = vec![IntConstraint {
            action_id: "act-1".to_string(),
            operator: "GT".to_string(),
            value: 2400,
        }];
        let value = solve_size_constraints(&constraints).expect("size");
        assert_eq!(value, 2500);
    }

    #[test]
    fn size_constraints_detect_unsat() {
        let constraints = vec![
            IntConstraint {
                action_id: "act-1".to_string(),
                operator: "LT".to_string(),
                value: 5,
            },
            IntConstraint {
                action_id: "act-2".to_string(),
                operator: "GE".to_string(),
                value: 5,
            },
        ];
        assert!(solve_size_constraints(&constraints).is_err());
    }

    #[test]
    fn bounded_constraints_resolve_valid_port() {
        let constraints = vec![
            IntConstraint {
                action_id: "act-1".to_string(),
                operator: "GE".to_string(),
                value: 1024,
            },
            IntConstraint {
                action_id: "act-2".to_string(),
                operator: "LE".to_string(),
                value: 1024,
            },
        ];
        let value =
            solve_bounded_int_constraints(&constraints, 1, 65535, 1).expect("port constraints");
        assert_eq!(value, 1024);
    }
}

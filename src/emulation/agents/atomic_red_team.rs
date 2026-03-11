use anyhow::Result;

use crate::emulation::ability::Ability;
use crate::emulation::agents::{AbilityExporter, BashExporter, PowershellExporter};

pub struct AtomicRedTeamExporter;

fn normalize_platforms(platforms: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for item in platforms {
        let value = item.trim().to_ascii_lowercase();
        if value == "any" {
            for candidate in ["windows", "linux", "macos"] {
                if !out.iter().any(|v| v == candidate) {
                    out.push(candidate.to_string());
                }
            }
            continue;
        }
        if !value.is_empty() && !out.iter().any(|v| v == &value) {
            out.push(value);
        }
    }
    if out.is_empty() {
        out.push("linux".to_string());
    }
    out
}

fn fallback_command(ability: &Ability) -> String {
    let mut out = String::new();
    out.push_str("echo \"[spuc] atomic fallback command\"\n");
    for action in &ability.actions {
        out.push_str(&format!(
            "echo \"[spuc] {} {} {} '{}'\"\n",
            action.id,
            action.observable,
            action.operator,
            action.value.replace('"', "\\\"")
        ));
    }
    out
}

fn platform_command(ability: &Ability, platform: &str) -> String {
    if platform == "windows" {
        let base = PowershellExporter
            .export(ability)
            .unwrap_or_else(|_| fallback_command(ability));
        return append_action_trace(base, ability, true);
    }
    let base = BashExporter
        .export(ability)
        .unwrap_or_else(|_| fallback_command(ability));
    append_action_trace(base, ability, false)
}

fn indent_block(value: &str, pad: &str) -> String {
    value
        .lines()
        .map(|line| format!("{pad}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn append_action_trace(mut script: String, ability: &Ability, windows: bool) -> String {
    if !script.ends_with('\n') {
        script.push('\n');
    }
    if windows {
        script.push_str("Write-Host \"[spuc] atomic action trace\"\n");
        for action in &ability.actions {
            script.push_str(&format!(
                "Write-Host \"[spuc] {} {} {} '{}'\"\n",
                action.id,
                action.observable,
                action.operator,
                action.value.replace('"', "`\"")
            ));
        }
    } else {
        script.push_str("echo \"[spuc] atomic action trace\"\n");
        for action in &ability.actions {
            script.push_str(&format!(
                "echo \"[spuc] {} {} {} '{}'\"\n",
                action.id,
                action.observable,
                action.operator,
                action.value.replace('"', "\\\"")
            ));
        }
    }
    script
}

fn yaml_quote(value: &str) -> String {
    value.replace('\'', "''")
}

impl AbilityExporter for AtomicRedTeamExporter {
    fn export(&self, ability: &Ability) -> Result<String> {
        let platforms = normalize_platforms(&ability.supported_platforms);
        let mut out = String::new();
        out.push_str("attack_technique: T0000\n");
        out.push_str(&format!("display_name: '{}'\n", yaml_quote(&ability.name)));
        out.push_str("atomic_tests:\n");

        for (idx, platform) in platforms.iter().enumerate() {
            let command = platform_command(ability, platform);
            let executor = if platform == "windows" {
                "powershell"
            } else {
                "sh"
            };
            out.push_str(&format!(
                "  - name: '{} ({})'\n",
                yaml_quote(&ability.name),
                platform
            ));
            out.push_str(&format!(
                "    auto_generated_guid: '{}-{:03}'\n",
                ability.id.replace('\'', ""),
                idx + 1
            ));
            out.push_str(&format!(
                "    description: '{}'\n",
                yaml_quote(&format!(
                    "{} | source_pattern: {}",
                    ability.description, ability.source_pattern
                ))
            ));
            out.push_str("    supported_platforms:\n");
            out.push_str(&format!("      - {}\n", platform));
            out.push_str("    executor:\n");
            out.push_str(&format!("      name: {}\n", executor));
            out.push_str("      command: |\n");
            out.push_str(&indent_block(&command, "        "));
            out.push('\n');
        }
        Ok(out)
    }
}

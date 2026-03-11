use anyhow::Result;
use serde_json::json;

use crate::emulation::ability::Ability;
use crate::emulation::agents::{AbilityExporter, BashExporter, PowershellExporter};

pub struct MitreCalderaExporter;

fn normalize_platforms(platforms: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for item in platforms {
        let value = item.trim().to_ascii_lowercase();
        if value == "any" {
            for candidate in ["windows", "linux", "darwin"] {
                if !out.iter().any(|v| v == candidate) {
                    out.push(candidate.to_string());
                }
            }
            continue;
        }
        let mapped = if value == "macos" {
            "darwin".to_string()
        } else {
            value
        };
        if !mapped.is_empty() && !out.iter().any(|v| v == &mapped) {
            out.push(mapped);
        }
    }
    if out.is_empty() {
        out.push("linux".to_string());
    }
    out
}

fn fallback_command(ability: &Ability) -> String {
    let mut out = String::new();
    out.push_str("echo \"[spuc] caldera fallback command\"\n");
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

fn platform_command(ability: &Ability, platform: &str) -> (String, String) {
    if platform == "windows" {
        let command = PowershellExporter
            .export(ability)
            .unwrap_or_else(|_| fallback_command(ability));
        return (
            "psh".to_string(),
            append_action_trace(command, ability, true),
        );
    }
    let command = BashExporter
        .export(ability)
        .unwrap_or_else(|_| fallback_command(ability));
    (
        "sh".to_string(),
        append_action_trace(command, ability, false),
    )
}

fn append_action_trace(mut script: String, ability: &Ability, windows: bool) -> String {
    if !script.ends_with('\n') {
        script.push('\n');
    }
    if windows {
        script.push_str("Write-Host \"[spuc] caldera action trace\"\n");
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
        script.push_str("echo \"[spuc] caldera action trace\"\n");
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

impl AbilityExporter for MitreCalderaExporter {
    fn export(&self, ability: &Ability) -> Result<String> {
        let mut platforms = serde_json::Map::new();
        for platform in normalize_platforms(&ability.supported_platforms) {
            let (executor, command) = platform_command(ability, &platform);
            let mut executor_map = serde_json::Map::new();
            executor_map.insert(
                executor,
                json!({
                    "command": command,
                    "payloads": [],
                    "uploads": [],
                    "cleanup": "",
                }),
            );
            platforms.insert(platform, serde_json::Value::Object(executor_map));
        }

        let value = json!({
            "id": ability.id,
            "name": ability.name,
            "description": ability.description,
            "tactic": "collection",
            "technique": {
                "attack_id": "T0000",
                "name": "SPUC generated technique mapping",
            },
            "repeatable": false,
            "delete_payload": false,
            "privilege": "User",
            "platforms": serde_json::Value::Object(platforms),
            "metadata": {
                "source_pattern": ability.source_pattern,
                "confidence": ability.confidence,
                "schema_version": ability.schema_version,
                "actions": ability
                    .actions
                    .iter()
                    .map(|action| format!(
                        "{} {} {} '{}'",
                        action.observable, action.operator, action.value, action.id
                    ))
                    .collect::<Vec<_>>(),
            }
        });

        Ok(serde_json::to_string_pretty(&value)?)
    }
}

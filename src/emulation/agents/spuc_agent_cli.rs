use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

use spuc::emulation::ability::{ABILITY_SCHEMA_VERSION, Ability};
use spuc::emulation::validate::{local_agent_profile, validate_ability};

#[derive(Debug, Parser)]
#[command(name = "spuc-agent")]
#[command(
    about = "SPUC Agent validates defensive emulation abilities generated from STIX patterns.",
    arg_required_else_help = true
)]
struct AgentCli {
    #[command(subcommand)]
    command: AgentCommands,
}

#[derive(Debug, Subcommand)]
enum AgentCommands {
    /// Validate an ability JSON file and report local compatibility
    Validate {
        #[arg(short = 'i', long = "input")]
        input: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = AgentCli::parse();
    match cli.command {
        AgentCommands::Validate { input } => {
            let raw = fs::read_to_string(&input)?;
            let value: Value = serde_json::from_str(&raw)?;
            let schema_version = value
                .get("schema_version")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Ability JSON is missing 'schema_version'"))?;
            if schema_version != ABILITY_SCHEMA_VERSION {
                return Err(anyhow!(
                    "Unsupported ability schema_version '{}'. Supported version: {}",
                    schema_version,
                    ABILITY_SCHEMA_VERSION
                ));
            }

            let ability: Ability = serde_json::from_value(value)?;
            let profile = local_agent_profile();
            let report = validate_ability(&ability, &profile);
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use spuc::emulation::ability::{
        ABILITY_SCHEMA_VERSION, AbilityAction, AbilityClassification, AbilityRequirement,
        EmulationLevel,
    };
    use spuc::emulation::validate::{CompatibilityStatus, default_capabilities_for_platform};

    fn sample_ability() -> Ability {
        Ability {
            schema_version: ABILITY_SCHEMA_VERSION.to_string(),
            id: "abl-agent-test".to_string(),
            name: "Agent test".to_string(),
            description: "Agent test ability".to_string(),
            supported_platforms: vec![std::env::consts::OS.to_string()],
            requires: vec![AbilityRequirement {
                id: "cap.process.spawn".to_string(),
                description: "Spawn process".to_string(),
            }],
            optional: vec![],
            agent_capabilities: vec!["cap.telemetry.process".to_string()],
            actions: vec![AbilityAction {
                id: "act-1".to_string(),
                title: "Emit process observable".to_string(),
                action_type: "emit_process_command_line".to_string(),
                observable: "process:command_line".to_string(),
                operator: "MATCHES".to_string(),
                value: "^.*echo.*$".to_string(),
                safe_instructions: "Run a benign command.".to_string(),
            }],
            source_pattern: "[process:command_line MATCHES '^.*echo.*$']".to_string(),
            classification: AbilityClassification::CommandLineTrace,
            emulation_level: EmulationLevel::TraceSimulation,
            confidence: 70,
        }
    }

    #[test]
    fn parses_ability_json() {
        let ability = sample_ability();
        let raw = serde_json::to_string(&ability).expect("serialize");
        let parsed: Ability = serde_json::from_str(&raw).expect("parse");
        assert_eq!(parsed.id, "abl-agent-test");
    }

    #[test]
    fn validation_reports_not_executable_for_invalid_structure() {
        let mut ability = sample_ability();
        ability.actions.clear();
        let profile = spuc::emulation::validate::AgentProfile {
            platform: std::env::consts::OS.to_string(),
            capabilities: default_capabilities_for_platform(std::env::consts::OS),
        };
        let report = validate_ability(&ability, &profile);
        assert_eq!(report.compatibility, CompatibilityStatus::NotExecutable);
    }

    #[test]
    fn validation_reports_not_executable_for_missing_required_capability() {
        let mut ability = sample_ability();
        ability.requires.push(AbilityRequirement {
            id: "cap.unknown".to_string(),
            description: "Unknown capability".to_string(),
        });
        let profile = spuc::emulation::validate::AgentProfile {
            platform: std::env::consts::OS.to_string(),
            capabilities: default_capabilities_for_platform(std::env::consts::OS),
        };
        let report = validate_ability(&ability, &profile);
        assert_eq!(report.compatibility, CompatibilityStatus::NotExecutable);
    }

    #[test]
    fn validation_reports_partial_for_missing_optional_capability() {
        let mut ability = sample_ability();
        ability.optional.push(AbilityRequirement {
            id: "cap.unknown.optional".to_string(),
            description: "Optional unknown capability".to_string(),
        });
        let profile = spuc::emulation::validate::AgentProfile {
            platform: std::env::consts::OS.to_string(),
            capabilities: default_capabilities_for_platform(std::env::consts::OS),
        };
        let report = validate_ability(&ability, &profile);
        assert_eq!(
            report.compatibility,
            CompatibilityStatus::PartiallyExecutable
        );
    }
}

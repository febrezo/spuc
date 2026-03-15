mod app;
mod cli;
mod commands;
mod core;
#[cfg(feature = "desktop-tauri")]
mod desktop;
mod domain;
mod paths;
mod tui;
mod ui;
mod web;

use anyhow::Result;
use clap::{Parser, error::ErrorKind};

use crate::cli::Cli;
pub(crate) use crate::core::{ast, emitters, ir, normalize, parser};
pub(crate) use crate::domain::catalog;

fn main() -> Result<()> {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let kind = err.kind();
            err.print()?;
            if matches!(
                kind,
                ErrorKind::DisplayHelp | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            ) {
                print_dynamic_sigma_help();
                return Ok(());
            }
            if matches!(kind, ErrorKind::DisplayVersion) {
                return Ok(());
            }
            return Err(err.into());
        }
    };
    app::run::run(cli)
}

fn print_dynamic_sigma_help() {
    let targets = crate::commands::sigma_targets::dynamic_sigma_targets();
    if targets.is_empty() {
        return;
    }
    println!();
    println!("Supported dynamic sigma targets (discovered via sigma):");
    for target in targets {
        println!("  {target}");
    }
}

#[cfg(test)]
mod tests {
    use crate::app::run::{parse_candidate_selection_ids, resolve_output_blocks};
    use crate::cli::BuildOutput;
    use spuc::emulation::ability as emu_ability;
    use spuc::emulation::output::OutputBlock;

    fn sample_ability(id: &str) -> emu_ability::Ability {
        emu_ability::Ability {
            schema_version: emu_ability::ABILITY_SCHEMA_VERSION.to_string(),
            id: id.to_string(),
            name: format!("ability-{id}"),
            description: "sample".to_string(),
            ttp: None,
            supported_platforms: vec!["linux".to_string()],
            requires: vec![emu_ability::AbilityRequirement {
                id: "cap.process.spawn".to_string(),
                description: "spawn".to_string(),
            }],
            optional: vec![],
            agent_capabilities: vec!["cap.telemetry.process".to_string()],
            actions: vec![emu_ability::AbilityAction {
                id: "act-001".to_string(),
                title: "act".to_string(),
                action_type: "emit_process_command_line".to_string(),
                observable: "process:command_line".to_string(),
                operator: "MATCHES".to_string(),
                value: "^.*$".to_string(),
                safe_instructions: "safe".to_string(),
            }],
            source_pattern: "[process:command_line MATCHES '^.*$']".to_string(),
            classification: emu_ability::AbilityClassification::CommandLineTrace,
            emulation_level: emu_ability::EmulationLevel::TraceSimulation,
            confidence: 70,
        }
    }

    #[test]
    fn candidate_selection_parser_accepts_indexes_and_ids() {
        let candidates = vec![sample_ability("abl-1"), sample_ability("abl-2")];
        let by_idx = parse_candidate_selection_ids(&candidates, "2,1").expect("idx parse");
        assert_eq!(by_idx, vec!["abl-2", "abl-1"]);
        let by_id = parse_candidate_selection_ids(&candidates, "abl-1").expect("id parse");
        assert_eq!(by_id, vec!["abl-1"]);
    }

    #[test]
    fn candidate_selection_parser_rejects_unknown_values() {
        let candidates = vec![sample_ability("abl-1")];
        let err = parse_candidate_selection_ids(&candidates, "99").expect_err("invalid index");
        assert!(err.to_string().contains("Invalid ability index"));
        let err = parse_candidate_selection_ids(&candidates, "abl-9").expect_err("invalid id");
        assert!(err.to_string().contains("Unknown ability"));
    }

    #[test]
    fn resolve_output_blocks_expands_all() {
        let blocks = resolve_output_blocks(&[BuildOutput::All], &[]);
        assert_eq!(
            blocks,
            vec![
                OutputBlock::Summary,
                OutputBlock::Canonical,
                OutputBlock::Artifact,
                OutputBlock::Manifest
            ]
        );
    }
}

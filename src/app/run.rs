#![allow(dead_code)]

use anyhow::Result;
use spuc::emulation::ability as emu_ability;
use spuc::emulation::output::OutputBlock;

use crate::cli::{BuildOutput, Cli, Commands, SigmaCommands};
use crate::commands;
use crate::ui::ansi::{BOLD, RESET};
use crate::ui::banner::BANNER;

const STANDALONE_WEB_PORT: u16 = 8090;

pub(crate) fn run(cli: Cli) -> Result<()> {
    if cli.version {
        return commands::version::run();
    }

    // Probe sigma once per process so dynamic sigma-to-* targets are ready for CLI and web flows.
    commands::sigma_runtime::warmup_sigma_runtime();

    let command = match cli.command.as_ref() {
        Some(command) => command,
        None => {
            println!("{BOLD}{BANNER}{RESET}");
            run_standalone_web_mode()?;
            println!();
            return Ok(());
        }
    };

    if !matches!(command, Commands::Version {}) {
        println!("{BOLD}{BANNER}{RESET}");
    }

    match command {
        Commands::Translate {
            to,
            sigma_targets,
            rule,
            file,
            output,
            description,
            ttp,
            rule_confidence,
            mode,
            export,
            refresh,
        } => commands::translate::run(commands::translate::options(
            to,
            rule,
            file.as_deref(),
            output.as_deref(),
            description.as_deref(),
            ttp.as_deref(),
            *rule_confidence,
            sigma_targets,
            *mode,
            export,
            *refresh,
        ))?,
        Commands::Verify { rule, file } => commands::verify::run(rule, file)?,
        Commands::Emulate {
            to,
            rule,
            file,
            output,
            description,
            ttp,
            rule_confidence,
            mode,
            export,
            refresh,
        } => commands::emulate::run(commands::emulate::options(
            to,
            rule,
            file.as_deref(),
            output.as_deref(),
            description.as_deref(),
            ttp.as_deref(),
            *rule_confidence,
            *mode,
            export,
            *refresh,
        ))?,
        Commands::Jsonrpc { port, token } => commands::jsonrpc::run(*port, token.clone())?,
        Commands::Web {
            port,
            admin_user,
            admin_password,
            no_login,
        } => commands::web::run(*port, admin_user, admin_password.as_deref(), *no_login)?,
        Commands::Version {} => commands::version::run()?,
        Commands::Sigma { command } => match command {
            SigmaCommands::Status => commands::sigma::status()?,
            SigmaCommands::ListTargets => commands::sigma::list_targets()?,
            SigmaCommands::UpdateConfig => commands::sigma::update_config()?,
        },
    }

    if !matches!(command, Commands::Version {}) {
        println!();
    }

    Ok(())
}

fn run_standalone_web_mode() -> Result<()> {
    #[cfg(feature = "desktop-tauri")]
    {
        return crate::desktop::run(STANDALONE_WEB_PORT);
    }

    #[cfg(not(feature = "desktop-tauri"))]
    {
        eprintln!(
            "Desktop GUI not compiled. Rebuild with --features desktop-tauri for standalone window mode."
        );
    }
    commands::web::run(STANDALONE_WEB_PORT, "admin", None, true)
}

pub(crate) fn resolve_output_blocks(
    show: &[BuildOutput],
    default: &[OutputBlock],
) -> Vec<OutputBlock> {
    crate::commands::common::resolve_output_blocks(show, default)
}

pub(crate) fn parse_candidate_selection_ids(
    candidates: &[emu_ability::Ability],
    selection: &str,
) -> Result<Vec<String>> {
    crate::commands::plan::parse_candidate_selection_ids(candidates, selection)
}

extern crate self as spuc;

mod app;
mod cli;
mod commands;
mod core;
mod domain;
pub mod paths;
mod ui;
mod web;

use anyhow::Result;
use clap::{error::ErrorKind, Parser};

pub(crate) use crate::core::{ast, emitters, ir, normalize, parser};
pub(crate) use crate::domain::catalog;

pub fn run_main() -> Result<()> {
    let cli = match cli::Cli::try_parse() {
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

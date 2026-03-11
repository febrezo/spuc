use anyhow::Result;

use crate::catalog;
use crate::cli::AdversaryCommands;

pub(crate) fn run(action: &AdversaryCommands) -> Result<()> {
    catalog::run_adversary_command(action)
}

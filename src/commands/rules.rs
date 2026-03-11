use anyhow::Result;

use crate::catalog;
use crate::cli::RuleCommands;

pub(crate) fn run(action: &RuleCommands) -> Result<()> {
    catalog::run_rule_command(action)
}

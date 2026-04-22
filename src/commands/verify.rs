use anyhow::{anyhow, Result};
use std::path::PathBuf;

use crate::ui::ansi::{GREEN, RED, RESET};
use crate::ui::print::render_rule_header;

pub(crate) use crate::commands::common::verify_rule;

pub(crate) fn run(rule: &[String], file: &Option<PathBuf>) -> Result<()> {
    let rules = crate::commands::common::load_rules(rule, file.as_deref())?;
    if rules.is_empty() {
        return Err(anyhow!("No rules provided. Use --rule or --file."));
    }

    for (idx, rule_str) in rules.iter().enumerate() {
        render_rule_header(idx, rules.len(), rule_str);
        match verify_rule(rule_str) {
            Ok(_) => println!("{GREEN}✅ OK{RESET}\n"),
            Err(e) => println!("{RED}✖️  Error:{RESET} {e}\n"),
        }
    }
    Ok(())
}

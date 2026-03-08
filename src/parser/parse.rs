use anyhow::{Context, Result, anyhow};
use pest::Parser;
use pest_derive::Parser;

use crate::ast::Pattern;

#[derive(Parser)]
#[grammar = "parser/grammar.pest"]
pub struct StixParser;

pub fn parse_rule(input: &str) -> Result<Pattern> {
    let mut pairs = StixParser::parse(Rule::rule, input)
        .map_err(|e| {
            let rendered = e.to_string();
            let hint = "Check brackets [], operators (AND/OR), and quoted strings following STIX syntax.";
            anyhow!(
                "\u{001b}[31mParse error\u{001b}[0m: {rendered}\n  \u{001b}[33mHint\u{001b}[0m: {hint}"
            )
        })
        .with_context(|| "STIX pattern parsing failed")?;

    let pair = pairs.next().ok_or_else(|| anyhow!("empty parse result"))?;
    super::transform::to_ast(pair)
}

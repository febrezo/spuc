use anyhow::{anyhow, Context, Result};
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

#[cfg(test)]
mod tests {
    use super::parse_rule;

    #[test]
    fn rejects_unquoted_string_in_followedby_sequence() {
        let invalid =
            "[process:name = 'cmd.exe'] FOLLOWEDBY [process:name = a.exe] WITHIN 300 SECONDS";
        let err = parse_rule(invalid).expect_err("parser must reject unquoted string literal");
        let msg = err.to_string();
        assert!(
            msg.contains("Parse error") || msg.contains("STIX pattern parsing failed"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn accepts_followedby_with_within_when_literals_are_quoted() {
        let valid =
            "[process:name = 'cmd.exe'] FOLLOWEDBY [process:name = 'a.exe'] WITHIN 300 SECONDS";
        let parsed = parse_rule(valid);
        assert!(
            parsed.is_ok(),
            "valid FOLLOWEDBY/WITHIN pattern should parse"
        );
    }
}

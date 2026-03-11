use anyhow::Result;
use std::path::Path;

use crate::cli::{AbilityTarget, ConversionMode, ExportFormat};
use crate::commands::common::{EmulateOptions, RuleInput};

pub(crate) fn run(options: EmulateOptions<'_>) -> Result<()> {
    crate::commands::common::emulate_rules(options)
}

pub(crate) fn options<'a>(
    targets: &'a [AbilityTarget],
    rules: &'a [String],
    rule_file: Option<&'a Path>,
    output_dir: Option<&'a Path>,
    description: Option<&'a str>,
    confidence: Option<u8>,
    mode: ConversionMode,
    export_formats: &'a [ExportFormat],
    refresh_cache: bool,
) -> EmulateOptions<'a> {
    EmulateOptions {
        targets,
        input: RuleInput {
            inline_rules: rules,
            rule_file,
        },
        output_dir,
        description,
        confidence,
        mode,
        export_formats,
        refresh_cache,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_groups_emulate_parameters() {
        let targets = [AbilityTarget::SpucAgent];
        let rules = ["[process:command_line LIKE '%echo%']".to_string()];
        let export_formats = [ExportFormat::Csv];
        let rule_file = Path::new("rules.txt");
        let output_dir = Path::new("artifacts");

        let options = super::options(
            &targets,
            &rules,
            Some(rule_file),
            Some(output_dir),
            Some("demo"),
            Some(70),
            ConversionMode::Strict,
            &export_formats,
            false,
        );

        assert_eq!(options.targets, &targets);
        assert_eq!(options.input.inline_rules, &rules);
        assert_eq!(options.input.rule_file, Some(rule_file));
        assert_eq!(options.output_dir, Some(output_dir));
        assert_eq!(options.description, Some("demo"));
        assert_eq!(options.confidence, Some(70));
        assert_eq!(options.mode, ConversionMode::Strict);
        assert_eq!(options.export_formats, &export_formats);
        assert!(!options.refresh_cache);
    }
}

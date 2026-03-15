use anyhow::Result;
use std::path::Path;

use crate::cli::{ConversionMode, ExportFormat};
use crate::commands::common::{RuleInput, TranslateOptions};

pub(crate) fn run(options: TranslateOptions<'_>) -> Result<()> {
    crate::commands::common::translate_rules(options)
}

pub(crate) fn options<'a>(
    targets: &'a [String],
    rules: &'a [String],
    rule_file: Option<&'a Path>,
    output_dir: Option<&'a Path>,
    description: Option<&'a str>,
    ttp: Option<&'a str>,
    confidence: Option<u8>,
    sigma_targets: &'a [String],
    mode: ConversionMode,
    export_formats: &'a [ExportFormat],
    refresh_cache: bool,
) -> TranslateOptions<'a> {
    TranslateOptions {
        targets,
        input: RuleInput {
            inline_rules: rules,
            rule_file,
        },
        output_dir,
        description,
        ttp,
        confidence,
        sigma_targets,
        mode,
        export_formats,
        refresh_cache,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_groups_translate_parameters() {
        let targets = ["sigma".to_string(), "sigma-to-splunk".to_string()];
        let rules = ["[process:name = 'cmd.exe']".to_string()];
        let sigma_targets = ["splunk".to_string()];
        let export_formats = [ExportFormat::Csv];
        let rule_file = Path::new("rules.txt");
        let output_dir = Path::new("artifacts");

        let options = super::options(
            &targets,
            &rules,
            Some(rule_file),
            Some(output_dir),
            Some("demo"),
            Some("T1059"),
            Some(80),
            &sigma_targets,
            ConversionMode::Partial,
            &export_formats,
            true,
        );

        assert_eq!(options.targets, &targets);
        assert_eq!(options.input.inline_rules, &rules);
        assert_eq!(options.input.rule_file, Some(rule_file));
        assert_eq!(options.output_dir, Some(output_dir));
        assert_eq!(options.description, Some("demo"));
        assert_eq!(options.ttp, Some("T1059"));
        assert_eq!(options.confidence, Some(80));
        assert_eq!(options.sigma_targets, &sigma_targets);
        assert_eq!(options.mode, ConversionMode::Partial);
        assert_eq!(options.export_formats, &export_formats);
        assert!(options.refresh_cache);
    }
}

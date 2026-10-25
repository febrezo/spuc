use anyhow::{anyhow, Result};

use crate::cli::ConversionMode;
use crate::commands::common::{
    apply_indicator_confidence_resolved, build_result_view, emit_target_with_mode_resolved,
    finalize_result, parse_and_normalize, resolve_translation_targets,
};
use crate::emitters::{EmitResult, FailureCause};

#[derive(Debug, Clone)]
pub(crate) struct TranslationEvaluation {
    pub(crate) target: String,
    pub(crate) runtime_status: String,
    pub(crate) conversion_confidence: u8,
    pub(crate) rule_confidence: Option<u8>,
    pub(crate) cause: Option<String>,
    pub(crate) summary: String,
    pub(crate) notes: Vec<String>,
    pub(crate) output: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TranslationRequest<'a> {
    pub(crate) rule: &'a str,
    pub(crate) targets: &'a [String],
    pub(crate) description: Option<&'a str>,
    pub(crate) sigma_targets: &'a [String],
    pub(crate) mode: ConversionMode,
    pub(crate) rule_confidence: Option<u8>,
}

pub(crate) fn resolve_targets_from_labels(labels: &[String]) -> Vec<String> {
    if labels.is_empty() {
        crate::commands::common::available_detection_target_labels()
    } else {
        labels.to_vec()
    }
}

pub(crate) fn evaluate_rule_from_labels(
    rule: &str,
    labels: &[String],
    description: Option<&str>,
    sigma_targets: &[String],
    mode: ConversionMode,
    rule_confidence: Option<u8>,
) -> Result<Vec<TranslationEvaluation>> {
    let targets = resolve_targets_from_labels(labels);
    evaluate_rule(TranslationRequest {
        rule,
        targets: &targets,
        description,
        sigma_targets,
        mode,
        rule_confidence,
    })
}

pub(crate) fn evaluate_rule(request: TranslationRequest<'_>) -> Result<Vec<TranslationEvaluation>> {
    let targets = resolve_translation_targets(request.targets, request.sigma_targets);
    if targets.is_empty() {
        return Err(anyhow!("no valid target selected"));
    }

    let parsed = parse_and_normalize(request.rule);
    let mut rows = Vec::with_capacity(targets.len());

    for target in &targets {
        let label = target.label();
        let emit = match &parsed {
            Ok(ir_expr) => emit_target_with_mode_resolved(
                target,
                ir_expr,
                request.rule,
                request.description,
                request.sigma_targets,
                request.mode,
            )
            .unwrap_or_else(|error| {
                EmitResult::unsupported_with_cause(
                    error.to_string(),
                    FailureCause::EmitterNotImplemented,
                )
            }),
            Err(error) => error.clone(),
        };

        let emit = finalize_result(&label, emit);
        let emit = apply_indicator_confidence_resolved(target, emit, request.rule_confidence);
        let view = build_result_view(&label, &emit, request.rule_confidence);

        rows.push(TranslationEvaluation {
            target: label,
            runtime_status: view.runtime_status,
            conversion_confidence: view.conversion_confidence,
            rule_confidence: view.rule_confidence,
            cause: view.cause,
            summary: view.summary,
            notes: view.notes,
            output: emit.rule,
        });
    }

    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_targets_defaults_to_all_targets() {
        let targets = resolve_targets_from_labels(&[]);
        assert!(targets.contains(&"sigma".to_string()));
    }

    #[test]
    fn resolve_targets_ignores_unknown_values() {
        let labels = vec!["unknown".to_string(), "kql".to_string()];
        let targets = resolve_targets_from_labels(&labels);
        assert_eq!(targets, labels);
    }

    #[test]
    fn evaluate_rule_builds_rows() {
        let targets = ["kql".to_string()];
        let rows = evaluate_rule(TranslationRequest {
            rule: "[process:name = 'cmd.exe']",
            targets: &targets,
            description: None,
            sigma_targets: &[],
            mode: ConversionMode::Strict,
            rule_confidence: Some(80),
        })
        .expect("evaluation should succeed");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].target, "kql");
        assert!(!rows[0].runtime_status.is_empty());
        assert_eq!(rows[0].rule_confidence, Some(80));
    }

    #[test]
    fn evaluate_rule_rejects_empty_targets() {
        let invalid = ["unknown-only".to_string()];
        let err = evaluate_rule(TranslationRequest {
            rule: "[process:name = 'cmd.exe']",
            targets: &invalid,
            description: None,
            sigma_targets: &[],
            mode: ConversionMode::Strict,
            rule_confidence: None,
        })
        .expect_err("must fail");
        assert!(err.to_string().contains("no valid target selected"));
    }
}

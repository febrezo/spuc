#![allow(dead_code)]

use anyhow::{anyhow, Result};
use chrono::Utc;
use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{BufRead as IoBufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::catalog::activities::{ActivityLog, TranslationActivity};
use crate::cli::{AbilityTarget, BuildOutput, ConversionMode, ExportFormat, OutputTarget};
use crate::commands::sigma_runtime::sigma_runtime_info;
use crate::commands::sigma_targets::{
    dynamic_sigma_targets, dynamic_target_label, target_to_backend,
};
use crate::emitters::{self, EmitResult, FailureCause, FidelityStatus};
use crate::ui::ansi::{BOLD, GREEN, GREEN_SOFT, ORANGE, PURPLE, RED, RESET, UNBOLD, YELLOW};
use crate::ui::output::{self as emu_output, OutputBlock};
use crate::ui::print::{render_coverage_header, render_rule_header};
use crate::{ir, normalize, parser};

type CoverageInfo = (
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Vec<String>,
);

pub(crate) fn known_detection_target_labels() -> Vec<String> {
    available_detection_target_labels()
}

pub(crate) fn available_detection_target_labels() -> Vec<String> {
    let mut labels = all_targets()
        .into_iter()
        .map(output_target_key)
        .map(str::to_string)
        .collect::<Vec<_>>();
    for dynamic in dynamic_sigma_targets() {
        if !labels.contains(&dynamic) {
            labels.push(dynamic);
        }
    }
    labels
}

fn output_target_key(target: OutputTarget) -> &'static str {
    match target {
        OutputTarget::Sigma => "sigma",
        OutputTarget::Eql => "eql",
        OutputTarget::Kql => "kql",
        OutputTarget::CytomicOrionSql => "cytomic-orion-sql",
        OutputTarget::Snort => "snort",
        OutputTarget::Suricata => "suricata",
        OutputTarget::Yara => "yara",
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ResolvedOutputTarget {
    Native(OutputTarget),
    SigmaDynamic { label: String, backend: String },
}

impl ResolvedOutputTarget {
    pub(crate) fn label(&self) -> String {
        match self {
            ResolvedOutputTarget::Native(target) => output_target_key(*target).to_string(),
            ResolvedOutputTarget::SigmaDynamic { label, .. } => label.clone(),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RuleInput<'a> {
    pub(crate) inline_rules: &'a [String],
    pub(crate) rule_file: Option<&'a Path>,
}

impl<'a> RuleInput<'a> {
    pub(crate) fn load(self) -> Result<Vec<String>> {
        load_rules(self.inline_rules, self.rule_file)
    }
}

pub(crate) struct TranslateOptions<'a> {
    pub(crate) targets: &'a [String],
    pub(crate) input: RuleInput<'a>,
    pub(crate) output_dir: Option<&'a Path>,
    pub(crate) description: Option<&'a str>,
    pub(crate) ttp: Option<&'a str>,
    pub(crate) confidence: Option<u8>,
    pub(crate) sigma_targets: &'a [String],
    pub(crate) mode: ConversionMode,
    pub(crate) export_formats: &'a [ExportFormat],
}

pub(crate) fn load_rules(rules: &[String], file: Option<&Path>) -> Result<Vec<String>> {
    let mut out = Vec::new();
    out.extend(rules.iter().cloned());

    if let Some(path) = file {
        let f = File::open(path)?;
        let reader = BufReader::new(f);
        for line in reader.lines() {
            let l = line?;
            let trimmed = l.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_string());
            }
        }
    }

    Ok(out)
}

pub(crate) fn verify_rule(rule: &str) -> Result<()> {
    let ast = parser::parse_rule(rule)?;
    normalize::stix_to_ir(&ast)?;
    Ok(())
}

pub(crate) fn translate_rules(options: TranslateOptions<'_>) -> Result<()> {
    let rules = options.input.load()?;
    if rules.is_empty() {
        return Err(anyhow!("No rules provided. Use --rule or --file."));
    }

    let targets = resolve_translation_targets(options.targets, options.sigma_targets);
    if targets.is_empty() {
        return Err(anyhow!("No valid detection target selected."));
    }

    let should_export_csv = resolve_csv_export(options.output_dir, options.export_formats, true)?;
    let activities = ActivityLog::from_default_root().ok();
    let mut csv_rows: Vec<CsvRow> = Vec::new();
    for (idx, rule_str) in rules.iter().enumerate() {
        render_rule_header(idx, rules.len(), rule_str);
        let parsed = parse_and_normalize(rule_str);

        for target in &targets {
            let label = target.label();
            let result = match &parsed {
                Ok(ir_expr) => emit_target_with_mode_resolved(
                    target,
                    ir_expr,
                    rule_str,
                    options.description,
                    options.sigma_targets,
                    options.mode,
                )
                .unwrap_or_else(|e| {
                    EmitResult::unsupported_with_cause(
                        e.to_string(),
                        FailureCause::EmitterNotImplemented,
                    )
                }),
                Err(res) => res.clone(),
            };
            let result = finalize_result(&label, result);
            let result = apply_indicator_confidence_resolved(target, result, options.confidence);
            let view = build_result_view(&label, &result, options.confidence);
            render_result(&label, &result, &view);

            record_activity(
                activities.as_ref(),
                TranslationActivity::new(
                    "translate",
                    rule_str,
                    &label,
                    &view.runtime_status,
                    view.conversion_confidence,
                    None,
                ),
            );

            if should_export_csv {
                csv_rows.push(CsvRow {
                    input_rule: rule_str.clone(),
                    target: label.to_uppercase(),
                    runtime_status: view.runtime_status.clone(),
                    conversion_confidence: view.conversion_confidence,
                    rule_confidence: view.rule_confidence,
                    cause: view.cause.clone().unwrap_or_default(),
                    summary: view.summary.clone(),
                    notes: view.notes.join(" | "),
                    output: view.output.clone().unwrap_or_default(),
                });
            }
        }
        println!();
    }
    if let Some(dir) = options.output_dir.filter(|_| should_export_csv) {
        write_csv_named(dir, "spuc_output.csv", &csv_rows)?;
    }
    Ok(())
}

pub(crate) fn parse_target(raw: &str) -> Option<OutputTarget> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "sigma" => Some(OutputTarget::Sigma),
        "eql" => Some(OutputTarget::Eql),
        "kql" => Some(OutputTarget::Kql),
        "cytomic-orion-sql" | "cytomic" | "orion-sql" => Some(OutputTarget::CytomicOrionSql),
        "snort" => Some(OutputTarget::Snort),
        "suricata" => Some(OutputTarget::Suricata),
        "yara" => Some(OutputTarget::Yara),
        _ => None,
    }
}

pub(crate) fn parse_ability_target(raw: &str) -> Option<AbilityTarget> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "spuc-agent" => Some(AbilityTarget::SpucAgent),
        "bash" => Some(AbilityTarget::Bash),
        "powershell" => Some(AbilityTarget::Powershell),
        "atomic-red-team" | "atomic" => Some(AbilityTarget::AtomicRedTeam),
        "mitre-caldera" | "caldera" => Some(AbilityTarget::MitreCaldera),
        _ => None,
    }
}

pub(crate) fn resolve_translation_targets(
    targets: &[String],
    sigma_targets: &[String],
) -> Vec<ResolvedOutputTarget> {
    let requested = if targets.is_empty() {
        available_detection_target_labels()
    } else {
        targets
            .iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
    };

    let explicit_sigma_backend_labels = sigma_targets
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .filter_map(|value| {
            target_to_backend(&value).or_else(|| {
                if value.starts_with("sigma-to-") {
                    None
                } else {
                    Some(value)
                }
            })
        })
        .map(|backend| dynamic_target_label(&backend))
        .collect::<Vec<_>>();

    let mut expanded = requested.clone();
    let has_native_sigma = requested.iter().any(|label| label == "sigma");
    let has_dynamic_sigma = requested
        .iter()
        .any(|label| target_to_backend(label).is_some());

    if has_native_sigma && explicit_sigma_backend_labels.is_empty() {
        expanded.extend(dynamic_sigma_targets());
    }
    if has_native_sigma || has_dynamic_sigma || !explicit_sigma_backend_labels.is_empty() {
        expanded.push("sigma".to_string());
    }
    expanded.extend(explicit_sigma_backend_labels);

    let mut resolved = Vec::new();
    let mut seen = Vec::new();
    for label in expanded {
        if seen.contains(&label) {
            continue;
        }
        seen.push(label.clone());
        if let Some(native) = parse_target(&label) {
            resolved.push(ResolvedOutputTarget::Native(native));
            continue;
        }
        if let Some(backend) = target_to_backend(&label) {
            resolved.push(ResolvedOutputTarget::SigmaDynamic { label, backend });
        }
    }
    resolved
}

fn resolve_csv_export(
    output: Option<&Path>,
    export: &[ExportFormat],
    default_with_output: bool,
) -> Result<bool> {
    if !export.is_empty() && output.is_none() {
        return Err(anyhow!("--export requires --output <directory>."));
    }
    let wants_csv = if export.is_empty() {
        default_with_output
    } else {
        export.contains(&ExportFormat::Csv)
    };
    Ok(output.is_some() && wants_csv)
}

fn record_activity(activities: Option<&ActivityLog>, activity: TranslationActivity) {
    if let Some(activities) = activities {
        if let Err(err) = activities.record_translation_activity(&activity) {
            println!("{YELLOW}Warning: unable to record catalog activity: {err}{RESET}");
        }
    }
}

/// Records a visible (non-hidden) catalog activity row. Used by the web rules
/// save flow so statuses in the grid derive from honest translate activity.
pub(crate) fn record_visible_translation_activity(
    command: &str,
    rule: &str,
    target: &str,
    status: &str,
    impact: u8,
) {
    let Ok(activities) = ActivityLog::from_default_root() else {
        return;
    };
    record_activity(
        Some(&activities),
        TranslationActivity::new(command, rule, target, status, impact, None),
    );
}

pub(crate) fn resolve_output_blocks(
    show: &[BuildOutput],
    default: &[OutputBlock],
) -> Vec<OutputBlock> {
    if show.is_empty() {
        return emu_output::normalize_blocks(default.to_vec());
    }
    if show.contains(&BuildOutput::All) {
        return emu_output::normalize_blocks(vec![
            OutputBlock::Summary,
            OutputBlock::Canonical,
            OutputBlock::Artifact,
            OutputBlock::Manifest,
        ]);
    }
    let mapped = show
        .iter()
        .map(|value| match value {
            BuildOutput::Summary => OutputBlock::Summary,
            BuildOutput::Canonical => OutputBlock::Canonical,
            BuildOutput::Artifact => OutputBlock::Artifact,
            BuildOutput::Manifest => OutputBlock::Manifest,
            BuildOutput::All => OutputBlock::Summary,
        })
        .collect();
    emu_output::normalize_blocks(mapped)
}

pub(crate) fn parse_build_outputs(raw: &str) -> Result<Vec<BuildOutput>> {
    let mut values = Vec::new();
    for token in raw.split(',').map(str::trim).filter(|v| !v.is_empty()) {
        let value = match token.to_ascii_lowercase().as_str() {
            "summary" => BuildOutput::Summary,
            "canonical" => BuildOutput::Canonical,
            "artifact" => BuildOutput::Artifact,
            "manifest" => BuildOutput::Manifest,
            "all" => BuildOutput::All,
            _ => {
                return Err(anyhow!(
                    "unsupported SHOW value '{}'. Allowed: summary, canonical, artifact, manifest, all",
                    token
                ));
            }
        };
        values.push(value);
    }
    if values.is_empty() {
        return Err(anyhow!(
            "SHOW cannot be empty. Allowed: summary, canonical, artifact, manifest, all"
        ));
    }
    Ok(values)
}

fn output_block_name(block: OutputBlock) -> &'static str {
    match block {
        OutputBlock::Summary => "summary",
        OutputBlock::Canonical => "canonical",
        OutputBlock::Artifact => "artifact",
        OutputBlock::Manifest => "manifest",
    }
}

pub(crate) fn show_output_value(show: &[BuildOutput], default: &[OutputBlock]) -> String {
    resolve_output_blocks(show, default)
        .iter()
        .map(|b| output_block_name(*b))
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn default_campaign_show() -> Vec<BuildOutput> {
    vec![BuildOutput::Summary, BuildOutput::Manifest]
}

fn styled_var(name: &str) -> String {
    format!("{BOLD}{PURPLE}{name}{RESET}")
}

fn styled_var_help(name: &str) -> String {
    format!("{BOLD}{YELLOW}{name}{RESET}")
}

fn print_variable_docs(title: &str, docs: &[(&str, &str)]) {
    println!("{YELLOW}{title}{RESET}");
    for (name, desc) in docs {
        println!(
            "{YELLOW}  {}{YELLOW}: {}{RESET}",
            styled_var_help(name),
            desc
        );
    }
}

fn print_variable_value(name: &str, value: impl AsRef<str>) {
    println!("  {}={}", styled_var(name), value.as_ref());
}

fn with_period(message: &str) -> String {
    let trimmed = message.trim();
    if trimmed.ends_with('.') || trimmed.ends_with('!') || trimmed.ends_with('?') {
        trimmed.to_string()
    } else {
        format!("{trimmed}.")
    }
}

fn ui_error(message: &str) {
    println!("{RED}❌ {}{RESET}", with_period(message));
}

fn ui_warn(message: &str) {
    println!("{YELLOW}{}{}", with_period(message), RESET);
}

fn bold_cmd(command: &str) -> String {
    format!("{BOLD}{command}{UNBOLD}")
}

fn quoted_bold(text: &str) -> String {
    format!("{BOLD}\"{text}\"{UNBOLD}")
}

fn emit_target(
    target: &OutputTarget,
    ir: &ir::IrExpr,
    description: Option<&str>,
    sigma_targets: &[String],
) -> Result<EmitResult> {
    let sanitized_ir = drop_redundant_network_ref_type(ir);
    match target {
        OutputTarget::Sigma => emit_sigma(&sanitized_ir, description, sigma_targets),
        OutputTarget::Eql => emitters::eql::emit(&sanitized_ir, description),
        OutputTarget::Kql => emitters::kql::emit(&sanitized_ir, description),
        OutputTarget::CytomicOrionSql => emitters::cytomic_orion_sql::emit(
            &sanitized_ir,
            "<source pattern unavailable>",
            description,
        ),
        OutputTarget::Suricata => emitters::suricata::emit(&sanitized_ir, description),
        OutputTarget::Snort => emitters::snort::emit(&sanitized_ir, description),
        OutputTarget::Yara => emitters::yara::emit(&sanitized_ir, description),
    }
}

pub(crate) fn emit_target_with_mode(
    target: &OutputTarget,
    ir: &ir::IrExpr,
    description: Option<&str>,
    sigma_targets: &[String],
    mode: ConversionMode,
) -> Result<EmitResult> {
    emit_with_mode(ir, mode, |expr| {
        emit_target(target, expr, description, sigma_targets)
    })
}

fn emit_dynamic_sigma_target(
    ir: &ir::IrExpr,
    description: Option<&str>,
    backend: &str,
) -> Result<EmitResult> {
    let sanitized_ir = drop_redundant_network_ref_type(ir);
    let mut sigma_result = emitters::sigma::emit(&sanitized_ir, description)?;
    let Some(yaml) = sigma_result.rule.clone() else {
        return Ok(sigma_result);
    };
    let converted = run_sigma_convert(&yaml, backend)?;
    sigma_result.rule = Some(converted);
    Ok(sigma_result)
}

pub(crate) fn emit_target_with_mode_resolved(
    target: &ResolvedOutputTarget,
    ir: &ir::IrExpr,
    source_rule: &str,
    description: Option<&str>,
    sigma_targets: &[String],
    mode: ConversionMode,
) -> Result<EmitResult> {
    match target {
        ResolvedOutputTarget::Native(OutputTarget::CytomicOrionSql) => {
            emit_with_mode(ir, mode, |expr| {
                let sanitized_ir = drop_redundant_network_ref_type(expr);
                emitters::cytomic_orion_sql::emit(&sanitized_ir, source_rule, description)
            })
        }
        ResolvedOutputTarget::Native(native) => {
            emit_target_with_mode(native, ir, description, sigma_targets, mode)
        }
        ResolvedOutputTarget::SigmaDynamic { backend, .. } => emit_with_mode(ir, mode, |expr| {
            emit_dynamic_sigma_target(expr, description, backend)
        }),
    }
}

fn emit_with_mode<F>(ir: &ir::IrExpr, mode: ConversionMode, mut emit: F) -> Result<EmitResult>
where
    F: FnMut(&ir::IrExpr) -> Result<EmitResult>,
{
    let base = match emit(ir) {
        Ok(res) => res,
        Err(e) => EmitResult::unsupported(e.to_string()),
    };
    if !matches!(mode, ConversionMode::Partial)
        || !matches!(base.status, FidelityStatus::Unsupported)
    {
        return Ok(base);
    }

    if let Some(partial) = try_partial_emit(ir, &mut emit)? {
        return Ok(partial);
    }
    Ok(base)
}

fn try_partial_emit<F>(ir: &ir::IrExpr, emit: &mut F) -> Result<Option<EmitResult>>
where
    F: FnMut(&ir::IrExpr) -> Result<EmitResult>,
{
    let predicates = match collect_predicates_for_partial(ir) {
        Some(p) => p,
        None => return Ok(None),
    };
    if predicates.len() < 2 {
        return Ok(None);
    }

    let mut rules = Vec::new();
    let mut notes = Vec::new();
    let mut omitted = Vec::new();
    for p in predicates {
        let expr = ir::IrExpr::Predicate(p.clone());
        let res = match emit(&expr) {
            Ok(r) => r,
            Err(e) => EmitResult::unsupported(e.to_string()),
        };
        if matches!(res.status, FidelityStatus::Unsupported) {
            omitted.push(format_predicate(&p));
            continue;
        }
        if let Some(rule) = res.rule {
            rules.push(rule);
        }
        notes.extend(res.notes);
    }

    if rules.is_empty() || omitted.is_empty() {
        return Ok(None);
    }
    notes.push("@status:partial".to_string());
    notes.push("Supported subset emitted; unsupported predicates omitted".to_string());
    for o in omitted {
        notes.push(format!("omitted predicate: {o}"));
    }

    Ok(Some(EmitResult {
        status: FidelityStatus::Partial,
        notes,
        rule: Some(rules.join("\n\n--- partial clause ---\n\n")),
        cause: None,
    }))
}

fn drop_redundant_network_ref_type(ir: &ir::IrExpr) -> ir::IrExpr {
    fn is_ref_type_eq(predicate: &ir::IrPredicate, field: &str) -> bool {
        predicate.target == "network-traffic"
            && predicate.field == field
            && predicate.op == ir::IrOp::Eq
            && matches!(predicate.value, ir::IrValue::String(_))
    }

    fn has_ref_value(exprs: &[ir::IrExpr], field: &str) -> bool {
        exprs.iter().any(|expr| {
            if let ir::IrExpr::Predicate(predicate) = expr {
                return predicate.target == "network-traffic" && predicate.field == field;
            }
            false
        })
    }

    match ir {
        ir::IrExpr::Predicate(_) => ir.clone(),
        ir::IrExpr::All(exprs) => {
            let sanitized = exprs
                .iter()
                .map(drop_redundant_network_ref_type)
                .collect::<Vec<_>>();
            let has_src_value = has_ref_value(&sanitized, "src_ref.value");
            let has_dst_value = has_ref_value(&sanitized, "dst_ref.value");
            let mut filtered = sanitized
                .into_iter()
                .filter(|expr| {
                    if let ir::IrExpr::Predicate(predicate) = expr {
                        if has_src_value && is_ref_type_eq(predicate, "src_ref.type") {
                            return false;
                        }
                        if has_dst_value && is_ref_type_eq(predicate, "dst_ref.type") {
                            return false;
                        }
                    }
                    true
                })
                .collect::<Vec<_>>();
            if filtered.len() == 1 {
                return filtered.remove(0);
            }
            ir::IrExpr::All(filtered)
        }
        ir::IrExpr::Any(exprs) => {
            ir::IrExpr::Any(exprs.iter().map(drop_redundant_network_ref_type).collect())
        }
        ir::IrExpr::FollowedBy(exprs) => {
            ir::IrExpr::FollowedBy(exprs.iter().map(drop_redundant_network_ref_type).collect())
        }
        ir::IrExpr::Qualified(inner, qualifiers) => ir::IrExpr::Qualified(
            Box::new(drop_redundant_network_ref_type(inner)),
            qualifiers.clone(),
        ),
    }
}

fn collect_predicates_for_partial(ir: &ir::IrExpr) -> Option<Vec<ir::IrPredicate>> {
    fn walk(expr: &ir::IrExpr, out: &mut Vec<ir::IrPredicate>) -> bool {
        match expr {
            ir::IrExpr::Predicate(p) => {
                out.push(p.clone());
                true
            }
            ir::IrExpr::All(v) => v.iter().all(|e| walk(e, out)),
            ir::IrExpr::Qualified(inner, _) => walk(inner, out),
            ir::IrExpr::FollowedBy(_) => false,
            ir::IrExpr::Any(_) => false,
        }
    }
    let mut out = Vec::new();
    if walk(ir, &mut out) {
        Some(out)
    } else {
        None
    }
}

fn format_predicate(p: &ir::IrPredicate) -> String {
    let op = match p.op {
        ir::IrOp::Eq => "=",
        ir::IrOp::Ne => "!=",
        ir::IrOp::Gt => ">",
        ir::IrOp::Ge => ">=",
        ir::IrOp::Lt => "<",
        ir::IrOp::Le => "<=",
        ir::IrOp::Matches => "MATCHES",
        ir::IrOp::IsSubset => "ISSUBSET",
    };
    let value = match &p.value {
        ir::IrValue::String(s) => format!("'{s}'"),
        ir::IrValue::Integer(i) => i.to_string(),
        ir::IrValue::Boolean(b) => b.to_string(),
        ir::IrValue::Hex(h) => format!("h'{h}'"),
        ir::IrValue::Timestamp(ts) => format!("t'{ts}'"),
    };
    format!("{}:{} {} {}", p.target, p.field, op, value)
}

pub(crate) fn all_targets() -> Vec<OutputTarget> {
    vec![
        OutputTarget::Sigma,
        OutputTarget::Eql,
        OutputTarget::Kql,
        OutputTarget::CytomicOrionSql,
        OutputTarget::Yara,
        OutputTarget::Snort,
        OutputTarget::Suricata,
    ]
}

#[derive(Debug, Clone)]
pub(crate) struct ResultView {
    pub(crate) runtime_status: String,
    pub(crate) conversion_confidence: u8,
    pub(crate) rule_confidence: Option<u8>,
    pub(crate) cause: Option<String>,
    pub(crate) summary: String,
    pub(crate) notes: Vec<String>,
    pub(crate) output: Option<String>,
}

#[derive(Debug, Clone)]
struct CsvRow {
    input_rule: String,
    target: String,
    runtime_status: String,
    conversion_confidence: u8,
    rule_confidence: Option<u8>,
    cause: String,
    summary: String,
    notes: String,
    output: String,
}

fn write_csv_named(dir: &Path, file_name: &str, rows: &[CsvRow]) -> Result<()> {
    fs::create_dir_all(dir)?;
    let path = dir.join(file_name);
    let mut file = File::create(&path)?;

    writeln!(
        file,
        "input_rule,target,runtime_status,conversion_confidence,rule_confidence,cause,summary,notes,output"
    )?;
    for row in rows {
        writeln!(
            file,
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
            csv_escape(&row.input_rule),
            csv_escape(&row.target),
            csv_escape(&row.runtime_status),
            row.conversion_confidence,
            row.rule_confidence
                .map(|v| v.to_string())
                .unwrap_or_default(),
            csv_escape(&row.cause),
            csv_escape(&row.summary),
            csv_escape(&row.notes),
            csv_escape(&row.output)
        )?;
    }

    eprintln!("Wrote CSV results to {}", path.display());
    Ok(())
}

fn csv_escape(value: &str) -> String {
    value.replace('\"', "\"\"")
}

pub(crate) fn build_result_view(
    label: &str,
    res: &EmitResult,
    rule_confidence: Option<u8>,
) -> ResultView {
    let notes = visible_notes(&res.notes)
        .into_iter()
        .map(|n| capitalize_first(&n))
        .collect::<Vec<_>>();
    ResultView {
        runtime_status: status_label(&res.status).to_string(),
        conversion_confidence: computed_confidence(label, &res.status, &res.notes),
        rule_confidence,
        cause: res
            .cause
            .as_ref()
            .map(|c| failure_cause_human(c).to_string()),
        summary: capitalize_first(&result_summary(res, &notes)),
        notes,
        output: res.rule.clone(),
    }
}

fn result_summary(res: &EmitResult, notes: &[String]) -> String {
    match res.status {
        FidelityStatus::Exact => "semantic mapping preserved".to_string(),
        FidelityStatus::SchemaDependent => "mapping depends on backend schema/profile".to_string(),
        FidelityStatus::BackendDependent => {
            "mapping depends on backend runtime behavior".to_string()
        }
        FidelityStatus::Partial => "supported subset emitted".to_string(),
        FidelityStatus::Lossy => "mapping degraded but related".to_string(),
        FidelityStatus::Unsupported => notes
            .first()
            .cloned()
            .unwrap_or_else(|| "no honest mapping available".to_string()),
    }
}

fn render_result(label: &str, res: &EmitResult, view: &ResultView) {
    let pretty = if label.starts_with("sigma-to-") {
        label.to_ascii_uppercase()
    } else {
        pretty_label(label).to_string()
    };
    let style = status_style(&res.status, view.conversion_confidence);
    println!();
    println!(
        "{}{}{} {} (status={}, conversion_confidence={}/100){RESET}",
        style.color,
        if style.bold { BOLD } else { "" },
        style.icon,
        pretty,
        view.runtime_status,
        view.conversion_confidence
    );
    if let Some(rule_confidence) = view.rule_confidence {
        println!("RuleConfidence={rule_confidence}/100");
    }
    if let Some(cause) = &view.cause {
        println!("Cause={cause}");
    }
    println!("Summary={}", view.summary);
    if !view.notes.is_empty() {
        println!("Notes={}", view.notes.join(" | "));
    }
    if let Some(rule) = &res.rule {
        println!(
            "{}──────────────── output ────────────────{RESET}",
            style.color
        );
        println!("{rule}");
    }
}

fn capitalize_first(input: &str) -> String {
    if input.starts_with("unsupported_") {
        return input.to_string();
    }
    let mut chars = input.chars();
    match chars.next() {
        Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

struct StatusStyle {
    color: &'static str,
    icon: &'static str,
    bold: bool,
}

fn status_style(status: &FidelityStatus, confidence: u8) -> StatusStyle {
    if matches!(status, FidelityStatus::Unsupported) {
        return StatusStyle {
            color: RED,
            icon: "🔴",
            bold: true,
        };
    }
    if confidence < 50 {
        return StatusStyle {
            color: ORANGE,
            icon: "🟠",
            bold: false,
        };
    }
    if confidence < 70 {
        return StatusStyle {
            color: YELLOW,
            icon: "🟡",
            bold: false,
        };
    }

    match status {
        FidelityStatus::Exact => StatusStyle {
            color: GREEN,
            icon: "🟢",
            bold: true,
        },
        FidelityStatus::SchemaDependent
        | FidelityStatus::BackendDependent
        | FidelityStatus::Partial => StatusStyle {
            color: GREEN_SOFT,
            icon: "🟢",
            bold: false,
        },
        FidelityStatus::Lossy => StatusStyle {
            color: YELLOW,
            icon: "🟡",
            bold: false,
        },
        FidelityStatus::Unsupported => unreachable!(),
    }
}

fn visible_notes(notes: &[String]) -> Vec<String> {
    dedup_notes(notes)
        .into_iter()
        .filter(|n| !n.starts_with('@'))
        .collect()
}

fn computed_confidence(label: &str, status: &FidelityStatus, notes: &[String]) -> u8 {
    if matches!(status, FidelityStatus::Unsupported) {
        return 0;
    }
    let (min, max) = status_confidence_range(status);
    let mut confidence: u8 = match status {
        FidelityStatus::Exact => 95,
        FidelityStatus::SchemaDependent => 78,
        FidelityStatus::BackendDependent => 68,
        FidelityStatus::Partial => 58,
        FidelityStatus::Lossy => 45,
        FidelityStatus::Unsupported => 0,
    };
    for note in dedup_notes(notes) {
        let n = note.to_ascii_lowercase();
        if n == "@conf50" {
            confidence = confidence.min(50);
        }
        if n.contains("schema") || n.contains("ensure mapping exists") || n.contains("verify ") {
            confidence = confidence.saturating_sub(10);
        }
        if n.contains("timestamp") || n.contains("downgraded") {
            confidence = confidence.saturating_sub(12);
        }
        if n.contains("omitted predicate") {
            confidence = confidence.saturating_sub(15);
        }
        if n.contains("regex") || n.contains("matches") {
            confidence = confidence.saturating_sub(4);
        }
        if n.contains("lossy") || n.contains("semantic mismatch") {
            confidence = confidence.saturating_sub(12);
        }
    }
    if label == "eql" && has_timestamp_field_note(notes) && confidence > 80 {
        confidence = 80;
    }
    confidence.clamp(min, max)
}

pub(crate) fn pretty_label(label: &str) -> &'static str {
    if label.starts_with("sigma-to-") {
        return "Sigma";
    }
    match label {
        "snort" => "Snort",
        "suricata" => "Suricata",
        "sigma" => "Sigma",
        "eql" => "EQL",
        "kql" => "KQL",
        "cytomic-orion-sql" => "Cytomic",
        "yara" => "YARA",
        _ => "Target",
    }
}

fn status_confidence_range(status: &FidelityStatus) -> (u8, u8) {
    match status {
        FidelityStatus::Exact => (90, 100),
        FidelityStatus::SchemaDependent => (65, 85),
        FidelityStatus::BackendDependent => (55, 75),
        FidelityStatus::Partial => (40, 70),
        FidelityStatus::Lossy => (25, 60),
        FidelityStatus::Unsupported => (0, 0),
    }
}

fn status_label(status: &FidelityStatus) -> &'static str {
    match status {
        FidelityStatus::Exact => "exact",
        FidelityStatus::SchemaDependent => "schema-dependent",
        FidelityStatus::BackendDependent => "backend-dependent",
        FidelityStatus::Partial => "partial",
        FidelityStatus::Lossy => "lossy",
        FidelityStatus::Unsupported => "unsupported",
    }
}

fn failure_cause_human(cause: &FailureCause) -> &'static str {
    match cause {
        FailureCause::ParseError => "Parse error",
        FailureCause::NormalizationError => "Normalization error",
        FailureCause::EmitterNotImplemented => "Emitter not implemented",
        FailureCause::BackendSemanticsMissing => "Backend semantics missing",
        FailureCause::SchemaUncertain => "Schema uncertain",
    }
}

fn has_timestamp_field_note(notes: &[String]) -> bool {
    notes.iter().any(|n| {
        let low = n.to_ascii_lowercase();
        low.contains("file.created")
            || low.contains("file.ctime")
            || low.contains("file.atime")
            || low.contains("file.mtime")
            || low.contains("modified_time")
    })
}

fn dedup_notes(notes: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for n in notes {
        if !out.contains(n) {
            out.push(n.clone());
        }
    }
    out
}

pub(crate) fn apply_indicator_confidence(
    target: &OutputTarget,
    mut res: EmitResult,
    indicator_confidence: Option<u8>,
) -> EmitResult {
    let Some(conf) = indicator_confidence else {
        return res;
    };
    if let Some(rule) = &res.rule {
        let updated = match target {
            OutputTarget::Sigma => inject_sigma_indicator_confidence(rule, conf),
            OutputTarget::Yara => inject_yara_indicator_confidence(rule, conf),
            OutputTarget::Snort | OutputTarget::Suricata => {
                format!("# spuc_indicator_confidence: {conf}\n{rule}")
            }
            OutputTarget::Eql | OutputTarget::Kql => {
                format!("// spuc_indicator_confidence: {conf}\n{rule}")
            }
            OutputTarget::CytomicOrionSql => {
                format!("-- spuc_indicator_confidence: {conf}\n{rule}")
            }
        };
        res.rule = Some(updated);
    }
    res
}

pub(crate) fn apply_indicator_confidence_resolved(
    target: &ResolvedOutputTarget,
    res: EmitResult,
    indicator_confidence: Option<u8>,
) -> EmitResult {
    match target {
        ResolvedOutputTarget::Native(native) => {
            apply_indicator_confidence(native, res, indicator_confidence)
        }
        ResolvedOutputTarget::SigmaDynamic { .. } => res,
    }
}

fn inject_sigma_indicator_confidence(rule: &str, conf: u8) -> String {
    rule.split("---\n")
        .map(|doc| {
            if doc.contains("x_spuc_indicator_confidence:") {
                doc.to_string()
            } else {
                format!("x_spuc_indicator_confidence: {conf}\n{doc}")
            }
        })
        .collect::<Vec<_>>()
        .join("---\n")
}

fn inject_yara_indicator_confidence(rule: &str, conf: u8) -> String {
    if rule.contains("spuc_indicator_confidence") {
        return rule.to_string();
    }
    if rule.contains("meta:\n") {
        return rule.replacen(
            "meta:\n",
            &format!("meta:\n    spuc_indicator_confidence = \"{conf}\"\n"),
            1,
        );
    }
    format!("/* spuc_indicator_confidence: {conf} */\n{rule}")
}

pub(crate) fn finalize_result(label: &str, mut res: EmitResult) -> EmitResult {
    res.notes = dedup_notes(&res.notes);
    if matches!(res.status, FidelityStatus::Unsupported) {
        if res.cause.is_none() {
            res.cause = Some(classify_unsupported_cause(&res.notes.join(" | ")));
        }
        return res;
    }
    let raw = res.notes.join(" | ").to_ascii_lowercase();
    if raw.contains("@status:partial") || raw.contains("omitted predicate:") {
        res.status = FidelityStatus::Partial;
    } else if raw.contains("lossy") || raw.contains("downgraded") {
        res.status = FidelityStatus::Lossy;
    } else if raw.contains("ensure mapping exists")
        || raw.contains("verify ")
        || raw.contains("schema")
        || raw.contains("non-standard")
        || raw.contains("flattened")
    {
        res.status = FidelityStatus::SchemaDependent;
    } else if raw.contains("backend") || (raw.contains("regex") && label == "sigma") {
        res.status = FidelityStatus::BackendDependent;
    } else {
        res.status = FidelityStatus::Exact;
    }
    res.cause = None;
    res
}

pub(crate) fn parse_and_normalize(rule: &str) -> Result<ir::IrExpr, EmitResult> {
    let ast = parser::parse_rule(rule)
        .map_err(|e| EmitResult::unsupported_with_cause(e.to_string(), FailureCause::ParseError))?;
    normalize::stix_to_ir(&ast).map_err(|e| {
        EmitResult::unsupported_with_cause(e.to_string(), FailureCause::NormalizationError)
    })
}

fn classify_unsupported_cause(msg: &str) -> FailureCause {
    let m = msg.to_ascii_lowercase();
    if m.contains("parse") {
        FailureCause::ParseError
    } else if m.contains("normalize")
        || m.contains("normalization")
        || m.contains("reference traversal not implemented")
        || m.contains("outside current normalization scope")
    {
        FailureCause::NormalizationError
    } else if m.contains("mapping exists")
        || m.contains("schema")
        || m.contains("field")
        || m.contains("verify ")
    {
        FailureCause::SchemaUncertain
    } else if m.contains("does not support")
        || m.contains("not support")
        || m.contains("semantic")
        || m.contains("unsupported")
    {
        FailureCause::BackendSemanticsMissing
    } else {
        FailureCause::EmitterNotImplemented
    }
}

#[allow(dead_code)]
fn print_coverage(target: Option<OutputTarget>) {
    match target {
        Some(t) => print_coverage_for(t),
        None => {
            println!("{YELLOW}Select a target to view coverage:{RESET}");
            let all = all_targets();
            for (idx, t) in all.iter().enumerate() {
                println!("  {}. {:?}", idx + 1, t);
            }
            print!("Enter number: ");
            let _ = std::io::stdout().flush();
            let mut buf = String::new();
            if std::io::stdin().read_line(&mut buf).is_ok() {
                if let Ok(choice) = buf.trim().parse::<usize>() {
                    if choice > 0 && choice <= all.len() {
                        print_coverage_for(all[choice - 1]);
                    }
                }
            }
        }
    }
}

#[allow(dead_code)]
fn print_coverage_for(target: OutputTarget) {
    let info = coverage_info();
    if let Some((desc, object_paths, operators, qualifiers, notes)) = info.get(&target) {
        println!();
        render_coverage_header(&target);
        println!();

        println!("{BOLD}Description{RESET}");
        for line in desc {
            println!("  - {}", line);
        }

        println!();
        println!("{BOLD}Object paths (type:property){RESET}");
        for obs in object_paths {
            println!("  - {}", obs);
        }

        println!();
        println!("{BOLD}Operators{RESET}");
        for op in operators {
            println!("  - {}", op);
        }

        if !qualifiers.is_empty() {
            println!();
            println!("{BOLD}Observation Qualifiers{RESET}");
            for q in qualifiers {
                println!("  - {}", q);
            }
        }

        if !notes.is_empty() {
            println!();
            println!("{BOLD}Notes{RESET}");
            for note in notes {
                println!("  - {}", note);
            }
        }

        println!();
        println!(
            "{BOLD}Fidelity model{RESET}\n  - coverage = path/operator availability\n  - runtime_status + conversion_confidence = semantic fidelity at conversion time"
        );
    } else {
        println!("{RED}No coverage info for {:?}{RESET}", target);
    }
}

#[allow(dead_code)]
fn coverage_info() -> HashMap<OutputTarget, CoverageInfo> {
    let mut map = HashMap::new();
    map.insert(
        OutputTarget::Sigma,
        (
            vec![
                "Sigma rule generator for detections".to_string(),
                "Emits selections with AND/OR; can be converted by sigma plugins".to_string(),
                "Docs: https://sigmahq.io".to_string(),
            ],
            vec![
                "domain-name:value (ops: =, LIKE, MATCHES)".to_string(),
                "url:value (ops: =, LIKE, MATCHES)".to_string(),
                "email-message:from_ref.value | sender_ref.value | to_refs[*].value | body_multipart[*].body_raw_ref.name (ops: =)".to_string(),
                "email-message:subject | body (ops: =, LIKE, MATCHES)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'MD5' | 'SHA-1' | 'SHA-256' | 'SHA-512' | 'SHA3-256' | 'SHA3-512' | SSDEEP | TLSH (ops: =, !=)".to_string(),
                "file:atime (ops: =, !=, >, >=, <, <=; timestamp only)".to_string(),
                "file:ctime (ops: =, !=, >, >=, <, <=; timestamp only)".to_string(),
                "file:hashes.MD5 (ops: =, !=)".to_string(),
                "file:hashes.SHA-1 (ops: =, !=)".to_string(),
                "file:hashes.SHA-256 (ops: =, !=)".to_string(),
                "file:hashes.SHA-512 (ops: =, !=)".to_string(),
                "file:hashes.SHA3-256 (ops: =, !=)".to_string(),
                "file:hashes.SHA3-512 (ops: =, !=)".to_string(),
                "file:hashes.SSDEEP (ops: =, !=)".to_string(),
                "file:hashes.TLSH (ops: =, !=)".to_string(),
                "file:mtime (ops: =, !=, >, >=, <, <=; timestamp only)".to_string(),
                "file:name (ops: =, !=, LIKE, MATCHES)".to_string(),
                "file:size (ops: =, !=, >, >=, <, <=)".to_string(),
                "directory:path (ops: =, !=, LIKE, MATCHES)".to_string(),
                "directory:ctime | mtime | atime (ops: =, !=, >, >=, <, <=; timestamp only)".to_string(),
                "network-traffic:src_ref.value | dst_ref.value (ops: =, LIKE, MATCHES, ISSUBSET)".to_string(),
                "network-traffic:src_port | dst_port (ops: =)".to_string(),
                "network-traffic:protocols (ops: =)".to_string(),
                "autonomous-system:number (ops: =, !=, >, >=, <, <=)".to_string(),
                "autonomous-system:name | rir (ops: =, !=, LIKE, MATCHES)".to_string(),
                "user-account:account_type | account_login (ops: =, !=, LIKE, MATCHES)".to_string(),
                "user-account:user_id (ops: =, !=, >, >=, <, <=)".to_string(),
                "windows-registry-key:key | values[*].name | values[*].data | values[*].data_type (ops: =, !=, MATCHES)".to_string(),
                "windows-registry-key:modified_time (ops: =, !=, >, >=, <, <=; timestamp only)".to_string(),
            ],
            vec!["=", "!=", ">", ">=", "<", "<=", "LIKE", "MATCHES (regex)", "ISSUBSET (CIDR)"]
                .into_iter()
                .map(String::from)
                .collect(),
            vec![
                "REPEATS: advisory-only (cardinality/event identity not enforceable; status downgraded to partial)".to_string(),
                "START/STOP: not supported".to_string(),
                "WITHIN: not supported".to_string(),
            ],
            vec![
                "Standalone ipv4/ipv6/mac observables are unsupported in Sigma baseline to avoid implicit directionality bias".to_string(),
                "Regex/LIKE supported on domain, network refs, registry keys, email subject/body".to_string(),
                "Raw STIX path passthrough is disabled; unmapped fields return unsupported".to_string(),
                "FOLLOWEDBY is unsupported in Sigma baseline (no honest sequence semantics)".to_string(),
                "Multi-entity user-account conjunctions are unsupported in strict mode (single-event semantics cannot be preserved)".to_string(),
                "network-traffic:* is the canonical network family; standalone IP/domain/URL can be weaker without connection context".to_string(),
            ],
        ),
    );
    map.insert(
        OutputTarget::Eql,
        (
            vec![
                "Elastic EQL-style endpoint hunting queries".to_string(),
                "Best effort mapping for process/file/network/email/registry telemetry".to_string(),
                "Docs: https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html".to_string(),
            ],
            vec![
                "artifact:hashes.MD5 (ops: =, !=)".to_string(),
                "artifact:hashes.SHA-1 (ops: =, !=)".to_string(),
                "artifact:hashes.SHA-256 (ops: =, !=)".to_string(),
                "artifact:hashes.SHA-512 (ops: =, !=)".to_string(),
                "artifact:hashes.SHA3-256 (ops: =, !=)".to_string(),
                "artifact:hashes.SHA3-512 (ops: =, !=)".to_string(),
                "artifact:hashes.SSDEEP (ops: =, !=)".to_string(),
                "artifact:hashes.TLSH (ops: =, !=)".to_string(),
                "artifact:mime_type (ops: =, !=, LIKE, MATCHES)".to_string(),
                "artifact:payload_bin (ops: =, !=, LIKE, MATCHES)".to_string(),
                "domain-name:value (ops: =, !=, LIKE, MATCHES)".to_string(),
                "url:value (ops: =, !=, LIKE, MATCHES)".to_string(),
                "file:hashes.MD5 (ops: =, !=)".to_string(),
                "file:hashes.SHA-1 (ops: =, !=)".to_string(),
                "file:hashes.SHA-256 (ops: =, !=)".to_string(),
                "file:hashes.SHA-512 (ops: =, !=)".to_string(),
                "file:hashes.SHA3-256 (ops: =, !=)".to_string(),
                "file:hashes.SHA3-512 (ops: =, !=)".to_string(),
                "file:hashes.SSDEEP (ops: =, !=)".to_string(),
                "file:hashes.TLSH (ops: =, !=)".to_string(),
                "file:name (ops: =, !=, LIKE, MATCHES)".to_string(),
                "file:size (ops: =, !=, >, >=, <, <=)".to_string(),
                "directory:path (ops: =, !=, LIKE, MATCHES)".to_string(),
                "directory:ctime | mtime | atime (ops: =, !=, >, >=, <, <=)".to_string(),
                "email-message:body | body_multipart[*].body_raw_ref.name | from_ref.value | sender_ref.value | subject | to_refs[*].value (ops: =, !=, LIKE, MATCHES)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'MD5' (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA-1' (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA-256' (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA-512' (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA3-256' (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA3-512' (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.SSDEEP (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.TLSH (ops: =, !=)".to_string(),
                "ipv4-addr:value | ipv6-addr:value (ops: =, !=, LIKE, MATCHES, ISSUBSET)".to_string(),
                "mac-addr:value (ops: =, !=, LIKE, MATCHES)".to_string(),
                "network-traffic:protocols (ops: =, !=, LIKE, MATCHES)".to_string(),
                "network-traffic:src_ref.value | dst_ref.value (ops: =, !=, LIKE, MATCHES, ISSUBSET)".to_string(),
                "network-traffic:src_port | dst_port (ops: =, !=, >, >=, <, <=)".to_string(),
                "autonomous-system:number (ops: =, !=, >, >=, <, <=)".to_string(),
                "autonomous-system:name | rir (ops: =, !=, LIKE, MATCHES)".to_string(),
                "process:image_ref.name | process:command_line (ops: =, !=, LIKE, MATCHES)".to_string(),
                "user-account:account_login | account_type (ops: =, !=, LIKE, MATCHES)".to_string(),
                "user-account:user_id (ops: =, !=, >, >=, <, <=)".to_string(),
                "windows-registry-key:key | values[*].name | values[*].data | values[*].data_type (ops: =, !=, LIKE, MATCHES)".to_string(),
                "windows-registry-key:modified_time (ops: =, !=, >, >=, <, <=)".to_string(),
            ],
            vec!["=", "!=", ">", ">=", "<", "<=", "LIKE", "MATCHES (regex)", "ISSUBSET (CIDR)"]
                .into_iter()
                .map(String::from)
                .collect(),
            vec![
                "REPEATS: advisory-only (cardinality/event identity not enforceable in plain where-clause)".to_string(),
                "START/STOP: supported as @timestamp filter".to_string(),
                "WITHIN: supported for FOLLOWEDBY via `sequence with maxspan`; advisory-only in plain where-clause".to_string(),
            ],
            vec![
                "Mixed datasets in one expression fallback to `any where ...`".to_string(),
                "artifact:payload_bin uses STIX byte normalization; regex behavior depends on backend field encoding".to_string(),
                "FOLLOWEDBY is supported via EQL `sequence`; outer WITHIN lowers to `maxspan`, while per-step qualifiers remain unsupported".to_string(),
                "network-traffic:* mappings are preferred; standalone IP/domain/URL mappings are backend-dependent shortcuts".to_string(),
                "network-traffic:*_ref.type is not mapped in EQL baseline (kept unsupported to avoid pseudo-fields)".to_string(),
                "Multi-entity user-account conjunctions are unsupported in strict mode (single-event semantics cannot be preserved)".to_string(),
            ],
        ),
    );
    map.insert(
        OutputTarget::CytomicOrionSql,
        (
            vec![
                "Cytomic Advanced SQL Query emitter".to_string(),
                "Default output uses EDR-compatible Telemetry with EventType filters".to_string(),
                "Regex MATCHES is rejected unless support is explicitly configured in a future profile".to_string(),
            ],
            vec![
                "process:name -> ProcessName (ops: =, !=, LIKE)".to_string(),
                "process:command_line -> CommandLine (ops: =, !=, LIKE)".to_string(),
                "process:pid -> ChildPid (ops: =, !=, >, >=, <, <=)".to_string(),
                "process:parent_ref.name -> ParentFilename (ops: =, !=, LIKE)".to_string(),
                "file:name | path | hashes.MD5 -> ChildFilename | ChildPath | ChildMd5 (ops: =, !=, LIKE)".to_string(),
                "ipv4-addr:value | network-traffic refs/ports -> RemoteIp/LocalIp/RemotePort/LocalPort".to_string(),
                "domain-name:value -> DomainList OR InitialDomain OR Hostname".to_string(),
                "windows-registry-key:key | values[*].name | values[*].data -> Key | Value | ValueData".to_string(),
            ],
            vec!["=", "!=", ">", ">=", "<", "<=", "LIKE"]
                .into_iter()
                .map(String::from)
                .collect(),
            vec![
                "MATCHES: unsupported_regex by default; simple (?i).*value.* receives a suggested LIKE fallback".to_string(),
                "REPEATS/WITHIN/START/STOP: not supported".to_string(),
            ],
            vec![
                "Full Orion table preference is not enabled without a schema/profile selector; default mode stays on Telemetry".to_string(),
                "Unmapped STIX object paths fail explicitly with unsupported_field".to_string(),
                "Mixed Telemetry EventType patterns are rejected conservatively".to_string(),
            ],
        ),
    );
    map.insert(
        OutputTarget::Kql,
        (
            vec![
                "KQL queries aligned to Microsoft Defender/Sentinel-style tables".to_string(),
                "Maps STIX observables to DeviceProcessEvents/DeviceNetworkEvents/etc.".to_string(),
                "Docs: https://learn.microsoft.com/azure/data-explorer/kusto/query/".to_string(),
            ],
            vec![
                "artifact:hashes.MD5 -> EmailAttachmentInfo (ops: =, !=)".to_string(),
                "artifact:hashes.SHA-1 -> EmailAttachmentInfo (ops: =, !=)".to_string(),
                "artifact:hashes.SHA-256 -> EmailAttachmentInfo (ops: =, !=)".to_string(),
                "artifact:hashes.SHA-512 -> EmailAttachmentInfo (ops: =, !=)".to_string(),
                "artifact:hashes.SHA3-256 -> EmailAttachmentInfo (ops: =, !=)".to_string(),
                "artifact:hashes.SHA3-512 -> EmailAttachmentInfo (ops: =, !=)".to_string(),
                "artifact:hashes.SSDEEP -> EmailAttachmentInfo (ops: =, !=)".to_string(),
                "artifact:hashes.TLSH -> EmailAttachmentInfo (ops: =, !=)".to_string(),
                "artifact:mime_type -> DeviceEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "artifact:payload_bin -> DeviceEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "domain-name:value -> DeviceNetworkEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "url:value -> DeviceNetworkEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "email-message:body | body_multipart[*].body_raw_ref.name | from_ref.value | sender_ref.value | subject | to_refs[*].value -> EmailEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'MD5' -> EmailEvents (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA-1' -> EmailEvents (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA-256' -> EmailEvents (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA-512' -> EmailEvents (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA3-256' -> EmailEvents (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA3-512' -> EmailEvents (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.SSDEEP -> EmailEvents (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.TLSH -> EmailEvents (ops: =, !=)".to_string(),
                "file:hashes.MD5 -> DeviceFileEvents (ops: =, !=)".to_string(),
                "file:hashes.SHA-1 -> DeviceFileEvents (ops: =, !=)".to_string(),
                "file:hashes.SHA-256 -> DeviceFileEvents (ops: =, !=)".to_string(),
                "file:hashes.SHA-512 -> DeviceFileEvents (ops: =, !=)".to_string(),
                "file:hashes.SHA3-256 -> DeviceFileEvents (ops: =, !=)".to_string(),
                "file:hashes.SHA3-512 -> DeviceFileEvents (ops: =, !=)".to_string(),
                "file:hashes.SSDEEP -> DeviceFileEvents (ops: =, !=)".to_string(),
                "file:hashes.TLSH -> DeviceFileEvents (ops: =, !=)".to_string(),
                "file:name -> DeviceFileEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "file:size -> DeviceFileEvents (ops: =, !=, >, >=, <, <=)".to_string(),
                "directory:path -> DeviceFileEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "directory:ctime | mtime | atime -> DeviceFileEvents (ops: =, !=, >, >=, <, <=)".to_string(),
                "ipv4-addr:value | ipv6-addr:value -> DeviceNetworkEvents (ops: =, !=, LIKE, MATCHES, ISSUBSET)".to_string(),
                "mac-addr:value -> DeviceNetworkEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "network-traffic:protocols -> DeviceNetworkEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "network-traffic:src_ref.value | dst_ref.value -> DeviceNetworkEvents (ops: =, !=, LIKE, MATCHES, ISSUBSET)".to_string(),
                "network-traffic:src_port | dst_port -> DeviceNetworkEvents (ops: =, !=, >, >=, <, <=)".to_string(),
                "autonomous-system:number -> DeviceNetworkEvents (ops: =, !=, >, >=, <, <=)".to_string(),
                "autonomous-system:name | rir -> DeviceNetworkEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "process:image_ref.name | process:command_line -> DeviceProcessEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "user-account:account_login | account_type -> IdentityInfo (ops: =, !=, LIKE, MATCHES)".to_string(),
                "user-account:user_id -> IdentityInfo (ops: =, !=, >, >=, <, <=)".to_string(),
                "windows-registry-key:key | values[*].name | values[*].data | values[*].data_type -> RegistryEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "windows-registry-key:modified_time -> RegistryEvents (ops: =, !=, >, >=, <, <=)".to_string(),
            ],
            vec!["=", "!=", ">", ">=", "<", "<=", "LIKE", "MATCHES (regex)", "ISSUBSET (CIDR)"]
                .into_iter()
                .map(String::from)
                .collect(),
            vec![
                "REPEATS: advisory-only (cardinality/event identity not enforceable in plain where-clause)".to_string(),
                "START/STOP: supported as Timestamp filter".to_string(),
                "WITHIN: accepted as advisory note (no strict event-window enforcement)".to_string(),
            ],
            vec![
                "Some fields use non-standard columns and are emitted with advisory notes".to_string(),
                "If one rule mixes tables, output falls back to DeviceEvents".to_string(),
                "artifact:payload_bin uses STIX byte normalization; regex behavior depends on backend field encoding".to_string(),
                "FOLLOWEDBY is unsupported in KQL baseline (no honest sequence lowering implemented)".to_string(),
                "network-traffic:* mappings are preferred; standalone IP/domain/URL mappings are backend-dependent shortcuts".to_string(),
                "network-traffic:*_ref.type is not mapped in KQL baseline (kept unsupported to avoid pseudo-fields)".to_string(),
                "Multi-entity user-account conjunctions are unsupported in strict mode (single-row semantics cannot be preserved)".to_string(),
            ],
        ),
    );
    map.insert(
        OutputTarget::Suricata,
        (
            vec![
                "Suricata inline/IDS alerts".to_string(),
                "Builds IP/port-based alerts for network traffic".to_string(),
                "Docs: https://suricata.io/".to_string(),
            ],
            vec![
                "ipv4-addr:value (ops: =, ISSUBSET)".to_string(),
                "network-traffic:src_ref.value (ops: =, ISSUBSET)".to_string(),
                "network-traffic:dst_ref.value (ops: =, ISSUBSET)".to_string(),
                "network-traffic:src_port (ops: =)".to_string(),
                "network-traffic:dst_port (ops: =)".to_string(),
                "network-traffic:protocols (ops: =)".to_string(),
                "artifact:payload_bin (ops: =, !=, LIKE, MATCHES)".to_string(),
            ],
            vec!["=", "!=", "LIKE", "MATCHES (regex)", "ISSUBSET (CIDR)"]
                .into_iter()
                .map(String::from)
                .collect(),
            vec![
                "REPEATS: not supported (cardinality semantics cannot be preserved in current lowering)".to_string(),
                "START/STOP: not supported".to_string(),
                "WITHIN: not supported".to_string(),
            ],
            vec![
                "Network predicates remain equality-based except CIDR ISSUBSET on IP-capable fields".to_string(),
                "FOLLOWEDBY is unsupported in Suricata baseline".to_string(),
                "artifact:payload_bin equality is lowered to content containment (partial fidelity)".to_string(),
                "artifact:payload_bin regex uses pcre/content and is backend-dependent".to_string(),
                "network-traffic:* equality is the canonical Suricata mapping; standalone IP shortcuts can be weaker".to_string(),
            ],
        ),
    );
    map.insert(
        OutputTarget::Snort,
        (
            vec![
                "Snort alert signatures".to_string(),
                "Builds IP/port-based alerts for network traffic".to_string(),
                "Docs: https://snort.org/".to_string(),
            ],
            vec![
                "ipv4-addr:value (ops: =, ISSUBSET)".to_string(),
                "network-traffic:src_ref.value (ops: =, ISSUBSET)".to_string(),
                "network-traffic:dst_ref.value (ops: =, ISSUBSET)".to_string(),
                "network-traffic:src_port (ops: =)".to_string(),
                "network-traffic:dst_port (ops: =)".to_string(),
                "network-traffic:protocols (ops: =)".to_string(),
                "artifact:payload_bin (ops: =, !=, LIKE, MATCHES)".to_string(),
            ],
            vec!["=", "!=", "LIKE", "MATCHES (regex)", "ISSUBSET (CIDR)"]
                .into_iter()
                .map(String::from)
                .collect(),
            vec![
                "REPEATS: not supported (cardinality semantics cannot be preserved in current lowering)".to_string(),
                "START/STOP: not supported".to_string(),
                "WITHIN: not supported".to_string(),
            ],
            vec![
                "Network predicates remain equality-based except CIDR ISSUBSET on IP-capable fields".to_string(),
                "FOLLOWEDBY is unsupported in Snort baseline".to_string(),
                "artifact:payload_bin equality is lowered to content containment (partial fidelity)".to_string(),
                "artifact:payload_bin regex uses pcre/content and is backend-dependent".to_string(),
                "network-traffic:* equality is the canonical Snort mapping; standalone IP shortcuts can be weaker".to_string(),
            ],
        ),
    );
    map.insert(
        OutputTarget::Yara,
        (
            vec![
                "YARA rules for literal matching".to_string(),
                "Only native file/content predicates are emitted; telemetry metadata is rejected".to_string(),
                "Docs: https://yara.readthedocs.io/".to_string(),
            ],
            vec![
                "artifact:payload_bin (ops: =, !=, LIKE, MATCHES)".to_string(),
                "file:hashes.MD5 (ops: =, !=)".to_string(),
                "file:hashes.SHA-1 (ops: =, !=)".to_string(),
                "file:hashes.SHA-256 (ops: =, !=)".to_string(),
                "file:magic_number_hex (ops: =, !=)".to_string(),
                "file:size (ops: =, !=, >, >=, <, <=)".to_string(),
            ],
            vec!["=", "!=", ">", ">=", "<", "<=", "LIKE", "MATCHES (regex)"]
                .into_iter()
                .map(String::from)
                .collect(),
            vec![
                "REPEATS: not supported (cardinality semantics cannot be preserved in current lowering)".to_string(),
                "START/STOP: not supported".to_string(),
                "WITHIN: not supported".to_string(),
            ],
            vec![
                "OR and FOLLOWEDBY unsupported; timestamps unsupported".to_string(),
                "Observation operator FOLLOWEDBY is rejected explicitly".to_string(),
                "Telemetry/metadata observables (network/process/registry/user/email/directory/autonomous-system) are unsupported".to_string(),
                "Standalone IP/domain/URL/mac mappings are rejected to avoid misleading content-only downgrades".to_string(),
                "file:name and timestamp metadata are unsupported due semantic mismatch".to_string(),
                "artifact:payload_bin equality is exact full-payload matching; regex matching remains backend-dependent".to_string(),
                "Only file hash MD5/SHA-1/SHA-256 are mapped natively".to_string(),
            ],
        ),
    );
    map
}

fn emit_sigma(
    ir: &ir::IrExpr,
    description: Option<&str>,
    _sigma_targets: &[String],
) -> Result<EmitResult> {
    emitters::sigma::emit(ir, description)
}

fn write_sigma_temp_rule(yaml: &str) -> Result<PathBuf> {
    let mut path = env::temp_dir();
    let nonce = Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_default()
        .unsigned_abs();
    path.push(format!("spuc_sigma_{}_{}.yml", std::process::id(), nonce));
    let mut file = File::create(&path)?;
    file.write_all(yaml.as_bytes())?;
    Ok(path)
}

fn run_sigma_convert(yaml: &str, backend: &str) -> Result<String> {
    let prepared_yaml = ensure_sigma_title(yaml);
    let path = write_sigma_temp_rule(&prepared_yaml)?;
    let sigma_bin = sigma_runtime_info().binary.clone();
    let out = Command::new(&sigma_bin)
        .args(["convert", "-t", backend, path.to_string_lossy().as_ref()])
        .output()
        .map_err(|e| anyhow!("failed to run sigma: {e}"))?;
    let _ = fs::remove_file(&path);
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(anyhow!(
            "sigma failed ({backend}): {}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

fn ensure_sigma_title(yaml: &str) -> String {
    yaml.split("---\n")
        .map(ensure_sigma_title_doc)
        .collect::<Vec<_>>()
        .join("---\n")
}

fn ensure_sigma_title_doc(doc: &str) -> String {
    if sigma_doc_has_non_empty_title(doc) {
        return doc.to_string();
    }
    format!("title: '[SPUC Generated Sigma Rule] auto'\n{doc}")
}

fn sigma_doc_has_non_empty_title(doc: &str) -> bool {
    doc.lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("title:"))
        .map(|value| {
            let title = value.trim().trim_matches('"').trim_matches('\'');
            !title.is_empty()
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_accepts_native_detection_targets() {
        assert_eq!(parse_target("sigma"), Some(OutputTarget::Sigma));
        assert_eq!(parse_target("eql"), Some(OutputTarget::Eql));
        assert_eq!(parse_target("kql"), Some(OutputTarget::Kql));
        assert_eq!(
            parse_target("cytomic-orion-sql"),
            Some(OutputTarget::CytomicOrionSql)
        );
        assert_eq!(parse_target("snort"), Some(OutputTarget::Snort));
        assert_eq!(parse_target("suricata"), Some(OutputTarget::Suricata));
        assert_eq!(parse_target("yara"), Some(OutputTarget::Yara));
    }

    #[test]
    fn known_detection_targets_include_native_targets() {
        let targets = known_detection_target_labels();
        assert!(targets.contains(&"sigma".to_string()));
        assert!(targets.contains(&"eql".to_string()));
        assert!(targets.contains(&"kql".to_string()));
    }

    #[test]
    fn drop_redundant_network_type_when_value_exists() {
        let rule = parser::parse_rule(
            "[network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'example.com']",
        )
        .expect("parse");
        let lowered = normalize::stix_to_ir(&rule).expect("normalize");
        let cleaned = drop_redundant_network_ref_type(&lowered);
        let rendered = format!("{cleaned:?}");
        assert!(rendered.contains("dst_ref.value"));
        assert!(!rendered.contains("dst_ref.type"));
    }

    #[test]
    fn ensure_sigma_title_adds_missing_title() {
        let yaml = "logsource:\n  category: generic\ndetection:\n  condition: selection1\n";
        let prepared = ensure_sigma_title(yaml);
        assert!(prepared.starts_with("title: '[SPUC Generated Sigma Rule] auto'\n"));
    }

    #[test]
    fn ensure_sigma_title_keeps_existing_title() {
        let yaml = "title: Existing\nlogsource:\n  category: generic\ndetection:\n  condition: selection1\n";
        let prepared = ensure_sigma_title(yaml);
        assert!(prepared.starts_with("title: Existing\n"));
    }

    #[test]
    fn sigma_backend_fallback_notes_keep_native_output_contract() {
        let mut result = EmitResult::exact("title: native\n".to_string());
        result.notes.push(
            "sigma backend conversion unavailable; returning native Sigma output".to_string(),
        );
        result.notes.push(
            "requested sigma backends skipped because sigma command/plugin runtime is unavailable"
                .to_string(),
        );
        assert_eq!(result.rule.as_deref(), Some("title: native\n"));
        assert_eq!(result.status, FidelityStatus::Exact);
        assert_eq!(result.notes.len(), 2);
    }

    #[test]
    fn sigma_backend_requests_also_include_native_sigma_target() {
        let resolved = resolve_translation_targets(&["kql".to_string()], &["splunk".to_string()]);
        let labels = resolved
            .into_iter()
            .map(|target| target.label())
            .collect::<Vec<_>>();
        assert_eq!(
            labels,
            vec![
                "kql".to_string(),
                "sigma".to_string(),
                "sigma-to-splunk".to_string()
            ]
        );
    }

    #[test]
    fn explicit_sigma_dynamic_target_keeps_native_sigma_target() {
        let resolved = resolve_translation_targets(&["sigma-to-splunk".to_string()], &[]);
        let labels = resolved
            .into_iter()
            .map(|target| target.label())
            .collect::<Vec<_>>();
        assert_eq!(
            labels,
            vec!["sigma-to-splunk".to_string(), "sigma".to_string()]
        );
    }
}

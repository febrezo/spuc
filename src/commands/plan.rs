#![allow(dead_code)]

use anyhow::{Result, anyhow};
use chrono::Utc;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::{AbilityTarget, AdversaryCommands, BuildOutput, RuleCommands};
use crate::commands::common::{
    ability_classification_label, ability_target_extension, ability_target_label,
    ability_target_to_export, all_ability_targets, build_ability_from_rule, parse_ability_target,
    render_ability_card,
};
use crate::paths;
use crate::tui::{
    SpucEditor, campaign_completion_words, load_editor_history, new_spuc_editor, read_line_compact,
    read_line_with_spacing, save_editor_history, set_editor_words,
};
use crate::ui::ansi::{BLUE, BOLD, GREEN, PURPLE, RED, RESET, UNBOLD, YELLOW};
use spuc::emulation::ability as emu_ability;
use spuc::emulation::campaign as emu_campaign;
use spuc::emulation::catalog::{AbilityCatalog, TranslationActivity};
use spuc::emulation::export::{self as emu_export};
use spuc::emulation::output::{self as emu_output, OutputBlock, OutputSection};
use spuc::emulation::validate as emu_validate;

pub(crate) const INTRUSION_SET_DEFAULT_DESCRIPTION: &str = "intrusion set generated with SPUC";
pub(crate) const ALLOWED_PLATFORMS: [&str; 4] = ["linux", "windows", "macos", "any"];

pub(crate) struct CampaignOptions<'a> {
    pub(crate) name: Option<&'a str>,
    pub(crate) description: Option<&'a str>,
    pub(crate) platforms: &'a [String],
    pub(crate) search: Option<&'a str>,
    pub(crate) ability_ids: &'a [String],
    pub(crate) dummy_sleep: &'a [u64],
    pub(crate) dummy_label: &'a [String],
    pub(crate) order: &'a [String],
    pub(crate) executor: Option<AbilityTarget>,
    pub(crate) output: Option<&'a Path>,
    pub(crate) guided: bool,
    pub(crate) show: &'a [BuildOutput],
}

fn resolve_output_blocks(show: &[BuildOutput], default: &[OutputBlock]) -> Vec<OutputBlock> {
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

fn parse_build_outputs(raw: &str) -> Result<Vec<BuildOutput>> {
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

fn show_output_value(show: &[BuildOutput], default: &[OutputBlock]) -> String {
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

pub(crate) fn run(options: CampaignOptions<'_>) -> Result<()> {
    build_campaign(options)
}

pub(crate) fn build_campaign(options: CampaignOptions<'_>) -> Result<()> {
    let platforms = normalize_platforms(options.platforms)?;
    let catalog = AbilityCatalog::from_default_root()?;
    let mut selected_ids = options.ability_ids.to_vec();
    append_dummy_abilities(
        &catalog,
        &mut selected_ids,
        primary_platform_hint(&platforms),
        options.dummy_sleep,
        options.dummy_label,
    )?;
    if options.guided {
        let mut state = CampaignConsoleState::new(
            options.name.unwrap_or(""),
            options.description,
            &platforms,
            options.search,
            options.output,
            &selected_ids,
            options.order,
            options.executor,
            options.show,
        );
        run_campaign_console(&catalog, &mut state)?;
        return Ok(());
    }

    if selected_ids.is_empty() {
        return Err(anyhow!(
            "No abilities selected. Use --ability / --dummy-sleep / --dummy-label or --guided."
        ));
    }

    if !options.order.is_empty() {
        selected_ids = reorder_ids(&selected_ids, options.order)?;
    }

    let state = CampaignConsoleState::new(
        options.name.unwrap_or(""),
        options.description,
        &platforms,
        options.search,
        options.output,
        &selected_ids,
        &selected_ids,
        options.executor,
        options.show,
    );
    build_and_render_campaign(
        &catalog,
        &state,
        options.executor.unwrap_or(AbilityTarget::SpucAgent),
    )
}

pub(crate) fn export_saved_adversary(
    path: &Path,
    executor: AbilityTarget,
    output: Option<&Path>,
    show: &[BuildOutput],
) -> Result<()> {
    let campaign = emu_campaign::load_campaign_yaml(path)?;
    let catalog = AbilityCatalog::from_default_root()?;
    let selected = catalog.select_by_ids(
        &campaign
            .steps
            .iter()
            .map(|step| step.ability_ref.clone())
            .collect::<Vec<_>>(),
    )?;
    let platforms = if campaign.steps.is_empty() {
        vec!["any".to_string()]
    } else {
        campaign
            .steps
            .iter()
            .map(|step| step.platform.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    };
    let state = CampaignConsoleState {
        intrusion_set_id: campaign.intrusion_set_id,
        name: campaign.name,
        description: Some(campaign.description),
        output: output.map(Path::to_path_buf),
        platforms,
        search: None,
        confidence: campaign.confidence,
        show: if show.is_empty() {
            default_campaign_show()
        } else {
            show.to_vec()
        },
        executor: Some(executor),
        selected_ids: selected.iter().map(|ability| ability.id.clone()).collect(),
        output_is_user_defined: output.is_some(),
        mode: CampaignConsoleMode::Normal,
        current_results: Vec::new(),
    };
    build_and_render_campaign(&catalog, &state, executor)
}

fn append_dummy_abilities(
    catalog: &AbilityCatalog,
    selected_ids: &mut Vec<String>,
    platform: Option<&str>,
    dummy_sleep: &[u64],
    dummy_label: &[String],
) -> Result<()> {
    for seconds in dummy_sleep {
        let ability = build_dummy_sleep_ability(*seconds, platform);
        let ability_id = upsert_dummy_ability(catalog, &ability)?;
        if !selected_ids.iter().any(|id| id == &ability_id) {
            selected_ids.push(ability_id.clone());
        }
        println!(
            "{YELLOW}Dummy ability added: {} (sleep {}s){RESET}",
            ability_id, seconds
        );
    }
    for label in dummy_label {
        if label.trim().is_empty() {
            continue;
        }
        let ability = build_dummy_label_ability(label, platform);
        let ability_id = upsert_dummy_ability(catalog, &ability)?;
        if !selected_ids.iter().any(|id| id == &ability_id) {
            selected_ids.push(ability_id.clone());
        }
        println!(
            "{YELLOW}Dummy ability added: {} (label \"{}\"){}",
            ability_id,
            label.trim(),
            RESET
        );
    }
    Ok(())
}

fn upsert_dummy_ability(
    catalog: &AbilityCatalog,
    ability: &emu_ability::Ability,
) -> Result<String> {
    let (path, _created) = catalog.upsert_by_source_pattern(ability)?;
    let id = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(&ability.id)
        .to_string();
    Ok(id)
}

fn build_dummy_sleep_ability(seconds: u64, platform: Option<&str>) -> emu_ability::Ability {
    let platform = platform.unwrap_or("any").to_ascii_lowercase();
    emu_ability::Ability {
        schema_version: emu_ability::ABILITY_SCHEMA_VERSION.to_string(),
        id: format!("abl-dummy-sleep-{platform}-{seconds}s"),
        name: format!("SPUC dummy sleep {}s", seconds),
        description: format!(
            "Dummy ability to delay execution flow by {} second(s) in a defensive simulation.",
            seconds
        ),
        ttp: None,
        supported_platforms: vec![platform.clone()],
        requires: vec![],
        optional: vec![],
        agent_capabilities: vec![],
        actions: vec![emu_ability::AbilityAction {
            id: "act-dummy-sleep-001".to_string(),
            title: "Delay execution".to_string(),
            action_type: "sleep_seconds".to_string(),
            observable: "x-spuc-dummy:sleep_seconds".to_string(),
            operator: "EQUALS".to_string(),
            value: seconds.to_string(),
            safe_instructions: format!(
                "Wait {} second(s) before the next ability to simulate paced execution.",
                seconds
            ),
        }],
        source_pattern: format!(
            "[x-spuc-dummy:type = 'sleep' AND x-spuc-dummy:seconds = '{}' AND x-spuc-dummy:platform = '{}']",
            seconds, platform
        ),
        classification: emu_ability::AbilityClassification::CommandLineTrace,
        emulation_level: emu_ability::EmulationLevel::TraceSimulation,
        confidence: 100,
    }
}

fn build_dummy_label_ability(label: &str, platform: Option<&str>) -> emu_ability::Ability {
    let platform = platform.unwrap_or("any").to_ascii_lowercase();
    let label_trimmed = label.trim();
    let label_tag = slugify_token(label_trimmed);
    let label_literal = label_trimmed.replace('\'', "\\'");
    emu_ability::Ability {
        schema_version: emu_ability::ABILITY_SCHEMA_VERSION.to_string(),
        id: format!("abl-dummy-label-{platform}-{label_tag}"),
        name: format!("SPUC dummy label {}", label_trimmed),
        description: format!(
            "Dummy ability to inject a controlled execution label: {}.",
            label_trimmed
        ),
        ttp: None,
        supported_platforms: vec![platform.clone()],
        requires: vec![],
        optional: vec![],
        agent_capabilities: vec![],
        actions: vec![emu_ability::AbilityAction {
            id: "act-dummy-label-001".to_string(),
            title: "Emit execution label".to_string(),
            action_type: "execution_label".to_string(),
            observable: "x-spuc-dummy:label".to_string(),
            operator: "EQUALS".to_string(),
            value: label_trimmed.to_string(),
            safe_instructions: format!(
                "Emit label '{}' in logs/telemetry to delimit execution phases.",
                label_trimmed
            ),
        }],
        source_pattern: format!(
            "[x-spuc-dummy:type = 'label' AND x-spuc-dummy:label = '{}' AND x-spuc-dummy:platform = '{}']",
            label_literal, platform
        ),
        classification: emu_ability::AbilityClassification::CommandLineTrace,
        emulation_level: emu_ability::EmulationLevel::TraceSimulation,
        confidence: 100,
    }
}

fn add_sleep_ability(
    catalog: &AbilityCatalog,
    state: &mut CampaignConsoleState,
    seconds: u64,
) -> Result<()> {
    let ability = build_dummy_sleep_ability(seconds, primary_platform_hint(&state.platforms));
    ensure_ability_compatible_with_platforms(&ability, &state.platforms)?;
    let ability_id = upsert_dummy_ability(catalog, &ability)?;
    if !state.selected_ids.iter().any(|id| id == &ability_id) {
        state.selected_ids.push(ability_id.clone());
    }
    println!(
        "{YELLOW}Dummy ability selected: {} (sleep {}s){RESET}",
        ability_id, seconds
    );
    Ok(())
}

fn add_label_ability(
    catalog: &AbilityCatalog,
    state: &mut CampaignConsoleState,
    label: &str,
) -> Result<()> {
    let ability = build_dummy_label_ability(label, primary_platform_hint(&state.platforms));
    ensure_ability_compatible_with_platforms(&ability, &state.platforms)?;
    let ability_id = upsert_dummy_ability(catalog, &ability)?;
    if !state.selected_ids.iter().any(|id| id == &ability_id) {
        state.selected_ids.push(ability_id.clone());
    }
    println!(
        "{YELLOW}Dummy ability selected: {} (label \"{}\"){}",
        ability_id,
        label.trim(),
        RESET
    );
    Ok(())
}

fn command_suffix<'a>(input: &'a str, lower: &str, prefixes: &[&str]) -> Option<&'a str> {
    for prefix in prefixes {
        if lower.starts_with(prefix) {
            return Some(input[prefix.len()..].trim());
        }
    }
    None
}

fn entry_label(count: usize) -> String {
    if count == 1 {
        "1 entry".to_string()
    } else {
        format!("{count} entries")
    }
}

#[derive(Debug, Clone)]
struct CatalogRuleEntry {
    rule_id: String,
    ability_id: Option<String>,
    name: String,
    description: Option<String>,
    ttp: Option<String>,
    confidence: u8,
    emulable: bool,
    rule: String,
    last_seen_utc: String,
    commands: Vec<String>,
    targets: Vec<String>,
    statuses: Vec<String>,
    activity_count: usize,
}

#[derive(Debug, Clone)]
struct CatalogAdversaryEntry {
    adversary_id: String,
    source_intrusion_set_id: String,
    path: PathBuf,
    name: String,
    confidence: u8,
    steps: usize,
    platforms: Vec<String>,
    description: String,
    ability_refs: Vec<String>,
}

fn load_catalog_data() -> Result<(
    AbilityCatalog,
    Vec<emu_ability::Ability>,
    Vec<CatalogRuleEntry>,
    Vec<CatalogAdversaryEntry>,
)> {
    let catalog = AbilityCatalog::from_default_root()?;
    let abilities = catalog.list()?;
    let rules = build_catalog_rule_entries(&catalog, &abilities)?;
    let adversaries = build_catalog_adversary_entries()?;
    Ok((catalog, abilities, rules, adversaries))
}

fn run_rule_command(action: &RuleCommands) -> Result<()> {
    let (catalog, _abilities, rules, _adversaries) = load_catalog_data()?;
    match action {
        RuleCommands::List { limit } => {
            let filtered = filter_rule_entries(&rules, None, Some(*limit));
            print_rule_search_results(&filtered, rules.len(), "Rules");
        }
        RuleCommands::Search { query, limit } => {
            let filtered = filter_rule_entries(&rules, query.as_deref(), Some(*limit));
            print_rule_search_results(&filtered, rules.len(), "Rules");
        }
        RuleCommands::Show { id } => {
            let entry = resolve_rule_selector(id, &rules, None)?;
            show_rule_entry(&entry);
        }
        RuleCommands::Export { id, to, output } => {
            let entry = resolve_rule_selector(id, &rules, None)?;
            export_rule_entry(&catalog, &entry, to, output.as_deref())?;
        }
        RuleCommands::Edit {
            id,
            name,
            description,
            confidence,
        } => {
            let entry = resolve_rule_selector(id, &rules, None)?;
            edit_rule_entry(
                &catalog,
                &entry,
                name.as_deref(),
                description.as_deref(),
                *confidence,
            )?;
        }
        RuleCommands::Delete { id } => {
            let entry = resolve_rule_selector(id, &rules, None)?;
            delete_rule_entry(&catalog, &entry, None)?;
        }
    }
    Ok(())
}

fn run_adversary_command(action: &AdversaryCommands) -> Result<()> {
    let (_catalog, _abilities, _rules, adversaries) = load_catalog_data()?;
    match action {
        AdversaryCommands::List { limit } => {
            let filtered = filter_adversary_entries(&adversaries, None, Some(*limit));
            print_adversary_search_results(&filtered, adversaries.len(), "Adversaries");
        }
        AdversaryCommands::Search { query, limit } => {
            let filtered = filter_adversary_entries(&adversaries, query.as_deref(), Some(*limit));
            print_adversary_search_results(&filtered, adversaries.len(), "Adversaries");
        }
        AdversaryCommands::Show { id } => {
            let entry = resolve_adversary_selector(id, &adversaries, None)?;
            show_adversary_entry(&entry);
        }
        AdversaryCommands::Export {
            id,
            to,
            output,
            show,
        } => {
            let entry = resolve_adversary_selector(id, &adversaries, None)?;
            export_adversary_entry(&entry, *to, output.as_deref(), show)?;
        }
        AdversaryCommands::Edit {
            id,
            name,
            description,
            confidence,
        } => {
            let entry = resolve_adversary_selector(id, &adversaries, None)?;
            edit_adversary_entry(&entry, name.as_deref(), description.as_deref(), *confidence)?;
        }
        AdversaryCommands::Delete { id } => {
            let entry = resolve_adversary_selector(id, &adversaries, None)?;
            delete_adversary_entry(&entry, None)?;
        }
    }
    Ok(())
}

fn build_catalog_rule_entries(
    catalog: &AbilityCatalog,
    abilities: &[emu_ability::Ability],
) -> Result<Vec<CatalogRuleEntry>> {
    let activities = catalog.list_translation_activities(None, None)?;
    let mut ability_by_rule: HashMap<String, &emu_ability::Ability> = HashMap::new();
    for ability in abilities {
        ability_by_rule
            .entry(ability.source_pattern.clone())
            .or_insert(ability);
    }

    let mut grouped: BTreeMap<String, Vec<TranslationActivity>> = BTreeMap::new();
    for activity in activities {
        grouped
            .entry(activity.rule.clone())
            .or_default()
            .push(activity);
    }

    let mut entries = grouped
        .into_iter()
        .map(|(rule, items)| {
            let ability = ability_by_rule.get(&rule).copied();
            let confidence = ability
                .map(|item| item.confidence)
                .unwrap_or_else(|| items.iter().map(|item| item.impact).max().unwrap_or(0));
            let stable_token = items
                .iter()
                .find_map(|item| {
                    (!item.rule_hash.trim().is_empty()).then(|| item.rule_hash.clone())
                })
                .unwrap_or_else(|| stable_catalog_token(&rule));
            let mut commands = BTreeSet::new();
            let mut targets = BTreeSet::new();
            let mut statuses = BTreeSet::new();
            let mut last_seen_utc = String::new();
            for item in &items {
                commands.insert(item.command.clone());
                targets.insert(item.target.clone());
                statuses.insert(item.status.clone());
                if item.timestamp_utc > last_seen_utc {
                    last_seen_utc = item.timestamp_utc.clone();
                }
            }
            CatalogRuleEntry {
                rule_id: format!("rule-{}", short_catalog_token(&stable_token)),
                ability_id: ability.map(|item| item.id.clone()),
                name: ability
                    .map(|item| item.name.clone())
                    .unwrap_or_else(|| format!("Rule {}", short_catalog_token(&stable_token))),
                description: ability.map(|item| item.description.clone()),
                ttp: ability.and_then(|item| item.ttp.clone()),
                confidence,
                emulable: ability.map(ability_is_emulable).unwrap_or(false),
                rule,
                last_seen_utc,
                commands: commands.into_iter().collect(),
                targets: targets.into_iter().collect(),
                statuses: statuses.into_iter().collect(),
                activity_count: items.len(),
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    Ok(entries)
}

fn filter_rule_entries(
    entries: &[CatalogRuleEntry],
    search: Option<&str>,
    limit: Option<usize>,
) -> Vec<CatalogRuleEntry> {
    let mut filtered = entries
        .iter()
        .filter(|entry| row_matches_query(&catalog_rule_row(entry), search))
        .cloned()
        .collect::<Vec<_>>();
    if let Some(max) = limit {
        filtered.truncate(max);
    }
    filtered
}

fn catalog_rule_row(entry: &CatalogRuleEntry) -> Vec<String> {
    vec![
        entry.rule_id.clone(),
        entry.name.clone(),
        entry.confidence.to_string(),
        yes_no(entry.emulable),
        entry.rule.clone(),
    ]
}

fn print_rule_search_results(entries: &[CatalogRuleEntry], total_entries: usize, title: &str) {
    let rows = entries
        .iter()
        .enumerate()
        .map(|(idx, entry)| {
            let mut row = vec![(idx + 1).to_string()];
            row.extend(catalog_rule_row(entry));
            row
        })
        .collect::<Vec<_>>();
    println!(
        "{BOLD}{title} ({}/{}){RESET}\n",
        rows.len(),
        entry_label(total_entries)
    );
    if rows.is_empty() {
        println!("{YELLOW}No rules found.{RESET}");
        return;
    }
    print_table(
        &["#", "RULE_ID", "NAME", "CONFIDENCE", "EMULABLE", "RULE"],
        &rows,
    );
}

fn build_catalog_adversary_entries() -> Result<Vec<CatalogAdversaryEntry>> {
    let Some(dir) = paths::campaigns_dir() else {
        return Ok(Vec::new());
    };
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut campaigns = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let path = entry?.path();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if ext != "yaml" && ext != "yml" && ext != "json" {
            continue;
        }
        if let Ok(campaign) = emu_campaign::load_campaign_yaml(&path) {
            campaigns.push((path, campaign));
        }
    }
    let mut entries = campaigns
        .into_iter()
        .map(|(path, campaign)| {
            let mut platforms = BTreeSet::new();
            let mut ability_refs = Vec::new();
            for step in &campaign.steps {
                platforms.insert(step.platform.clone());
                ability_refs.push(step.ability_ref.clone());
            }
            CatalogAdversaryEntry {
                adversary_id: catalog_adversary_id(&campaign.intrusion_set_id),
                source_intrusion_set_id: campaign.intrusion_set_id,
                path,
                name: campaign.name,
                confidence: campaign.confidence,
                steps: campaign.steps.len(),
                platforms: platforms.into_iter().collect(),
                description: campaign.description,
                ability_refs,
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| a.adversary_id.cmp(&b.adversary_id));
    Ok(entries)
}

fn filter_adversary_entries(
    entries: &[CatalogAdversaryEntry],
    search: Option<&str>,
    limit: Option<usize>,
) -> Vec<CatalogAdversaryEntry> {
    let mut filtered = entries
        .iter()
        .filter(|entry| row_matches_query(&catalog_adversary_row(entry), search))
        .cloned()
        .collect::<Vec<_>>();
    if let Some(max) = limit {
        filtered.truncate(max);
    }
    filtered
}

fn catalog_adversary_row(entry: &CatalogAdversaryEntry) -> Vec<String> {
    vec![
        entry.adversary_id.clone(),
        entry.name.clone(),
        entry.confidence.to_string(),
        entry.steps.to_string(),
        entry.platforms.join(", "),
        entry.description.clone(),
    ]
}

fn print_adversary_search_results(
    entries: &[CatalogAdversaryEntry],
    total_entries: usize,
    title: &str,
) {
    let rows = entries
        .iter()
        .enumerate()
        .map(|(idx, entry)| {
            let mut row = vec![(idx + 1).to_string()];
            row.extend(catalog_adversary_row(entry));
            row
        })
        .collect::<Vec<_>>();
    println!(
        "{BOLD}{title} ({}/{}){RESET}\n",
        rows.len(),
        entry_label(total_entries)
    );
    if rows.is_empty() {
        println!("{YELLOW}No adversaries found.{RESET}");
        return;
    }
    print_table(
        &[
            "#",
            "ADVERSARY_ID",
            "NAME",
            "CONFIDENCE",
            "STEPS",
            "PLATFORMS",
            "DESCRIPTION",
        ],
        &rows,
    );
}

fn resolve_rule_selector(
    selector: &str,
    all_entries: &[CatalogRuleEntry],
    current_entries: Option<&[CatalogRuleEntry]>,
) -> Result<CatalogRuleEntry> {
    if let Ok(index) = selector.parse::<usize>() {
        if index == 0 {
            return Err(anyhow!("index starts at 1"));
        }
        let source = current_entries.unwrap_or(all_entries);
        return source
            .get(index - 1)
            .cloned()
            .ok_or_else(|| anyhow!("rule index '{}' is out of range", index));
    }
    all_entries
        .iter()
        .find(|entry| {
            entry.rule_id == selector
                || entry.rule == selector
                || entry.ability_id.as_deref() == Some(selector)
        })
        .cloned()
        .ok_or_else(|| anyhow!("rule '{}' not found", selector))
}

fn resolve_adversary_selector(
    selector: &str,
    all_entries: &[CatalogAdversaryEntry],
    current_entries: Option<&[CatalogAdversaryEntry]>,
) -> Result<CatalogAdversaryEntry> {
    if let Ok(index) = selector.parse::<usize>() {
        if index == 0 {
            return Err(anyhow!("index starts at 1"));
        }
        let source = current_entries.unwrap_or(all_entries);
        return source
            .get(index - 1)
            .cloned()
            .ok_or_else(|| anyhow!("adversary index '{}' is out of range", index));
    }
    all_entries
        .iter()
        .find(|entry| {
            entry.adversary_id == selector
                || entry.source_intrusion_set_id == selector
                || entry.name == selector
        })
        .cloned()
        .ok_or_else(|| anyhow!("adversary '{}' not found", selector))
}

fn show_rule_entry(rule: &CatalogRuleEntry) {
    println!("{YELLOW}{BOLD}Rule Detail{RESET}");
    println!("{YELLOW}- rule_id: {}{RESET}", rule.rule_id);
    if let Some(ability_id) = &rule.ability_id {
        println!("{YELLOW}- ability_id: {}{RESET}", ability_id);
    }
    println!("{YELLOW}- name: {}{RESET}", rule.name);
    println!(
        "{YELLOW}- description: {}{RESET}",
        rule.description.as_deref().unwrap_or("-")
    );
    println!("{YELLOW}- confidence: {}{RESET}", rule.confidence);
    println!("{YELLOW}- emulable: {}{RESET}", yes_no(rule.emulable));
    println!("{YELLOW}- last_seen_utc: {}{RESET}", rule.last_seen_utc);
    println!("{YELLOW}- activity_count: {}{RESET}", rule.activity_count);
    println!(
        "{YELLOW}- commands: {}{RESET}",
        join_or_dash(&rule.commands)
    );
    println!("{YELLOW}- targets: {}{RESET}", join_or_dash(&rule.targets));
    println!(
        "{YELLOW}- statuses: {}{RESET}",
        join_or_dash(&rule.statuses)
    );
    println!("{YELLOW}- rule: {}{RESET}", rule.rule);
}

fn show_adversary_entry(adversary: &CatalogAdversaryEntry) {
    println!("{YELLOW}{BOLD}Adversary Detail{RESET}");
    println!("{YELLOW}- adversary_id: {}{RESET}", adversary.adversary_id);
    println!(
        "{YELLOW}- source_intrusion_set_id: {}{RESET}",
        adversary.source_intrusion_set_id
    );
    println!("{YELLOW}- name: {}{RESET}", adversary.name);
    println!("{YELLOW}- confidence: {}{RESET}", adversary.confidence);
    println!("{YELLOW}- steps: {}{RESET}", adversary.steps);
    println!(
        "{YELLOW}- platforms: {}{RESET}",
        adversary.platforms.join(", ")
    );
    println!("{YELLOW}- description: {}{RESET}", adversary.description);
    println!(
        "{YELLOW}- ability_refs: {}{RESET}",
        join_or_dash(&adversary.ability_refs)
    );
    println!("{YELLOW}- path: {}{RESET}", adversary.path.display());
}

fn export_rule_entry(
    catalog: &AbilityCatalog,
    rule: &CatalogRuleEntry,
    targets: &[AbilityTarget],
    output: Option<&Path>,
) -> Result<()> {
    let ability = load_or_rebuild_rule_ability(catalog, rule)?;
    export_single_ability(&ability, targets, output)
}

fn export_single_ability(
    ability: &emu_ability::Ability,
    targets: &[AbilityTarget],
    output: Option<&Path>,
) -> Result<()> {
    let selected_targets = if targets.is_empty() {
        all_ability_targets()
    } else {
        targets.to_vec()
    };
    let summary = render_ability_card(ability);
    for target in selected_targets {
        let target_label = ability_target_label(target);
        let artifact = emu_export::export_ability(ability_target_to_export(target), ability)?;
        if let Some(dir) = output {
            fs::create_dir_all(dir)?;
            let artifact_path = dir.join(format!(
                "{}-{}.{}",
                ability.id,
                target_label.replace('-', "_"),
                ability_target_extension(target)
            ));
            fs::write(&artifact_path, &artifact)?;
            println!(
                "{YELLOW}Artifact ({target_label}) saved to {}{RESET}",
                artifact_path.display()
            );
        }
        let sections = vec![
            OutputSection {
                block: OutputBlock::Summary,
                title: format!("Rule Export Summary ({target_label})"),
                body: summary.clone(),
            },
            OutputSection {
                block: OutputBlock::Artifact,
                title: format!("Rule Export Artifact ({target_label})"),
                body: artifact,
            },
        ];
        println!("{}", emu_output::render_sections(&sections));
    }
    Ok(())
}

fn load_or_rebuild_rule_ability(
    catalog: &AbilityCatalog,
    rule: &CatalogRuleEntry,
) -> Result<emu_ability::Ability> {
    if let Some(ability_id) = &rule.ability_id {
        if let Some(ability) = catalog.get_by_id(ability_id)? {
            return Ok(ability);
        }
    }
    build_ability_from_rule(
        &rule.rule,
        None,
        Some(&rule.name),
        rule.description.as_deref(),
        rule.ttp.as_deref(),
        rule.confidence,
    )
}

fn edit_rule_entry(
    catalog: &AbilityCatalog,
    rule: &CatalogRuleEntry,
    name: Option<&str>,
    description: Option<&str>,
    confidence: Option<u8>,
) -> Result<()> {
    let ability_id = rule.ability_id.as_deref().ok_or_else(|| {
        anyhow!(
            "rule '{}' is activity-only and cannot be edited",
            rule.rule_id
        )
    })?;
    let mut ability = catalog
        .get_by_id(ability_id)?
        .ok_or_else(|| anyhow!("ability '{}' not found", ability_id))?;
    let mut changed = false;
    if let Some(name) = name {
        ability.name = name.to_string();
        changed = true;
    }
    if let Some(description) = description {
        ability.description = description.to_string();
        changed = true;
    }
    if let Some(confidence) = confidence {
        ability.confidence = confidence;
        changed = true;
    }
    if !changed {
        return Err(anyhow!(
            "no editable fields provided. Allowed: --name, --description, --confidence"
        ));
    }
    catalog.save(&ability)?;
    println!("{YELLOW}Rule updated: {}{RESET}", rule.rule_id);
    Ok(())
}

fn edit_adversary_entry(
    adversary: &CatalogAdversaryEntry,
    name: Option<&str>,
    description: Option<&str>,
    confidence: Option<u8>,
) -> Result<()> {
    let mut campaign = emu_campaign::load_campaign_yaml(&adversary.path)?;
    let mut changed = false;
    if let Some(name) = name {
        campaign.name = name.to_string();
        changed = true;
    }
    if let Some(description) = description {
        campaign.description = description.to_string();
        changed = true;
    }
    if let Some(confidence) = confidence {
        campaign.confidence = confidence;
        changed = true;
    }
    if !changed {
        return Err(anyhow!(
            "no editable fields provided. Allowed: --name, --description, --confidence"
        ));
    }
    emu_campaign::save_campaign_yaml(&campaign, Some(&adversary.path))?;
    println!(
        "{YELLOW}Adversary updated: {}{RESET}",
        adversary.adversary_id
    );
    Ok(())
}

fn export_adversary_entry(
    adversary: &CatalogAdversaryEntry,
    executor: AbilityTarget,
    output: Option<&Path>,
    show: &[BuildOutput],
) -> Result<()> {
    let campaign = emu_campaign::load_campaign_yaml(&adversary.path)?;
    let catalog = AbilityCatalog::from_default_root()?;
    let selected = catalog.select_by_ids(&adversary.ability_refs)?;
    let platforms = if adversary.platforms.is_empty() {
        vec!["any".to_string()]
    } else {
        adversary.platforms.clone()
    };
    let state = CampaignConsoleState {
        intrusion_set_id: campaign.intrusion_set_id,
        name: campaign.name,
        description: Some(campaign.description),
        output: output.map(Path::to_path_buf),
        platforms,
        search: None,
        confidence: campaign.confidence,
        show: if show.is_empty() {
            default_campaign_show()
        } else {
            show.to_vec()
        },
        executor: Some(executor),
        selected_ids: selected.iter().map(|ability| ability.id.clone()).collect(),
        output_is_user_defined: output.is_some(),
        mode: CampaignConsoleMode::Normal,
        current_results: Vec::new(),
    };
    build_and_render_campaign(&catalog, &state, executor)
}

fn delete_rule_entry(
    catalog: &AbilityCatalog,
    rule: &CatalogRuleEntry,
    confirmation: Option<&str>,
) -> Result<()> {
    confirm_manual_delete(
        &format!("rule {}", rule.rule_id),
        &format!("DELETE {}", rule.rule_id),
        confirmation,
    )?;
    let mut removed = 0usize;
    if let Some(ability_id) = &rule.ability_id {
        if catalog.delete_by_id(ability_id)? {
            removed += 1;
        }
    }
    let activity_rows = catalog.delete_activities_by_rule(&rule.rule)?;
    println!(
        "{YELLOW}Rule deleted: {} (abilities removed: {}, activity rows removed: {}){RESET}",
        rule.rule_id, removed, activity_rows
    );
    Ok(())
}

fn delete_adversary_entry(
    adversary: &CatalogAdversaryEntry,
    confirmation: Option<&str>,
) -> Result<()> {
    confirm_manual_delete(
        &format!("adversary {}", adversary.adversary_id),
        &format!("DELETE {}", adversary.adversary_id),
        confirmation,
    )?;
    fs::remove_file(&adversary.path)?;
    println!(
        "{YELLOW}Adversary deleted: {}{RESET}",
        adversary.adversary_id
    );
    Ok(())
}

fn row_matches_query(row: &[String], query: Option<&str>) -> bool {
    let Some(query) = query else {
        return true;
    };
    let needle = query.to_ascii_lowercase();
    row.iter()
        .any(|value| value.to_ascii_lowercase().contains(&needle))
}

fn ability_is_emulable(ability: &emu_ability::Ability) -> bool {
    ability.validate_structure().is_ok()
        && all_ability_targets().into_iter().any(|target| {
            emu_export::export_ability(ability_target_to_export(target), ability).is_ok()
        })
}

fn yes_no(value: bool) -> String {
    if value {
        "yes".to_string()
    } else {
        "no".to_string()
    }
}

fn stable_catalog_token(input: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn short_catalog_token(input: &str) -> String {
    input.chars().take(12).collect()
}

fn catalog_adversary_id(intrusion_set_id: &str) -> String {
    if intrusion_set_id.starts_with("adversary-") {
        intrusion_set_id.to_string()
    } else if let Some(suffix) = intrusion_set_id.strip_prefix("intrusion-set-") {
        format!("adversary-{suffix}")
    } else {
        format!("adversary-{intrusion_set_id}")
    }
}

fn join_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(", ")
    }
}

fn confirm_manual_delete(label: &str, expected: &str, provided: Option<&str>) -> Result<()> {
    if let Some(provided) = provided {
        if provided.trim() == expected {
            return Ok(());
        }
        return Err(anyhow!(
            "delete confirmation mismatch. Expected '{}'",
            expected
        ));
    }
    println!("{YELLOW}Manual confirmation required to delete {label}.{RESET}");
    println!("{YELLOW}Type exactly: {BOLD}{expected}{RESET}");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    if line.trim() != expected {
        return Err(anyhow!("delete cancelled"));
    }
    Ok(())
}

fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    if headers.is_empty() {
        return;
    }
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (idx, cell) in row.iter().enumerate() {
            if idx < widths.len() {
                widths[idx] = widths[idx].max(cell.chars().count());
            }
        }
    }

    let header = headers
        .iter()
        .enumerate()
        .map(|(idx, title)| format!("{title:<width$}", width = widths[idx]))
        .collect::<Vec<_>>()
        .join(" | ");
    let separator = widths
        .iter()
        .map(|width| "-".repeat(*width))
        .collect::<Vec<_>>()
        .join("-+-");

    println!("{YELLOW}{BOLD}{header}{RESET}");
    println!("{YELLOW}{separator}{RESET}");
    for row in rows {
        let line = widths
            .iter()
            .enumerate()
            .map(|(idx, width)| {
                let value = row.get(idx).map(String::as_str).unwrap_or("");
                format!("{value:<w$}", w = *width)
            })
            .collect::<Vec<_>>()
            .join(" | ");
        println!("{YELLOW}{line}{RESET}");
    }
}

fn render_campaign_card(campaign: &emu_campaign::Campaign) -> String {
    let step_lines = campaign
        .steps
        .iter()
        .map(|s| {
            format!(
                "{} => ability={} platform={} after={}",
                s.id,
                s.ability_ref,
                s.platform,
                s.after.as_deref().unwrap_or("-")
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "- schema_version: {}\n- intrusion_set_id: {}\n- name: {}\n- description: {}\n- confidence: {}\n- steps:\n{}",
        campaign.schema_version,
        campaign.intrusion_set_id,
        campaign.name,
        campaign.description,
        campaign.confidence,
        step_lines
    )
}

pub(crate) fn parse_candidate_selection_ids(
    candidates: &[emu_ability::Ability],
    selection: &str,
) -> Result<Vec<String>> {
    if selection.trim().is_empty() {
        return Ok(candidates.iter().map(|a| a.id.clone()).collect());
    }
    let mut selected = Vec::new();
    for token in selection
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Ok(idx) = token.parse::<usize>() {
            if idx > 0 {
                if let Some(item) = candidates.get(idx - 1) {
                    selected.push(item.id.clone());
                    continue;
                }
            }
            return Err(anyhow!("Invalid ability index '{}'", token));
        }
        if let Some(item) = candidates.iter().find(|a| a.id == token) {
            selected.push(item.id.clone());
        } else {
            return Err(anyhow!("Unknown ability '{}'", token));
        }
    }
    Ok(selected)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CampaignConsoleMode {
    Normal,
    CatalogView,
}

pub(crate) struct CampaignConsoleState {
    pub(crate) intrusion_set_id: String,
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) output: Option<PathBuf>,
    pub(crate) platforms: Vec<String>,
    pub(crate) search: Option<String>,
    pub(crate) confidence: u8,
    pub(crate) show: Vec<BuildOutput>,
    pub(crate) executor: Option<AbilityTarget>,
    pub(crate) selected_ids: Vec<String>,
    pub(crate) output_is_user_defined: bool,
    pub(crate) mode: CampaignConsoleMode,
    pub(crate) current_results: Vec<emu_ability::Ability>,
}

impl CampaignConsoleState {
    #[allow(clippy::too_many_arguments)]
    fn new(
        name: &str,
        description: Option<&str>,
        platforms: &[String],
        search: Option<&str>,
        output: Option<&Path>,
        selected_abilities: &[String],
        order: &[String],
        executor: Option<AbilityTarget>,
        show: &[BuildOutput],
    ) -> Self {
        let mut selected_ids = selected_abilities.to_vec();
        if !order.is_empty() {
            if let Ok(reordered) = reorder_ids(&selected_ids, order) {
                selected_ids = reordered;
            }
        }
        let intrusion_set_id = format!("intrusion-set-{}", Utc::now().timestamp_millis());
        let normalized_name = if name.trim().is_empty() {
            String::new()
        } else {
            name.to_string()
        };
        let normalized_platforms = platforms.to_vec();
        let output_is_user_defined = output.is_some();
        Self {
            intrusion_set_id: intrusion_set_id.clone(),
            name: normalized_name.clone(),
            description: description
                .map(|v| v.to_string())
                .filter(|v| !v.trim().is_empty())
                .or_else(|| Some(INTRUSION_SET_DEFAULT_DESCRIPTION.to_string())),
            output: output.map(Path::to_path_buf).or_else(|| {
                default_campaign_output_path(
                    &normalized_name,
                    output_platform_hint(&normalized_platforms),
                )
            }),
            platforms: normalized_platforms,
            search: search
                .map(|v| v.to_string())
                .filter(|v| !v.trim().is_empty()),
            confidence: 70,
            executor,
            show: if show.is_empty() {
                default_campaign_show()
            } else {
                show.to_vec()
            },
            selected_ids,
            output_is_user_defined,
            mode: CampaignConsoleMode::Normal,
            current_results: Vec::new(),
        }
    }
}

fn campaign_prompt(mode: CampaignConsoleMode) -> String {
    if mode == CampaignConsoleMode::CatalogView {
        format!("{BOLD}spuc (plan @ catalog)>{RESET} ")
    } else {
        format!("{BOLD}spuc (plan)>{RESET} ")
    }
}

fn bootstrap_campaign_required_fields(
    rl: &mut SpucEditor,
    catalog: &AbilityCatalog,
    state: &mut CampaignConsoleState,
) -> Result<()> {
    if state.name.trim().is_empty() {
        loop {
            let Some(line) = read_line_compact(rl, "Intrusion set name> ")? else {
                return Err(anyhow!("Planner cancelled."));
            };
            let value = line.trim();
            if value.is_empty() {
                ui_error("NAME is required");
                continue;
            }
            state.name = value.to_string();
            refresh_campaign_output_path(state);
            break;
        }
    }
    if state.platforms.is_empty() {
        loop {
            let Some(line) =
                read_line_compact(rl, "Platforms (comma-separated: linux,windows,macos,any)> ")?
            else {
                return Err(anyhow!("Planner cancelled."));
            };
            let value = line.trim();
            if value.is_empty() {
                ui_error("PLATFORM is required");
                continue;
            }
            match parse_platforms_value(value) {
                Ok(platforms) if !platforms.is_empty() => {
                    let incompatible =
                        incompatible_selected_abilities_for_platforms(catalog, state, &platforms)?;
                    if !incompatible.is_empty() {
                        ui_error(&format!(
                            "Incompatible PLATFORM for selected abilities: {}",
                            incompatible.join(", ")
                        ));
                        continue;
                    }
                    state.platforms = platforms;
                    refresh_campaign_output_path(state);
                    break;
                }
                Ok(_) => ui_error("PLATFORM is required"),
                Err(err) => ui_error(&err.to_string()),
            }
        }
    }
    Ok(())
}

fn run_campaign_console(catalog: &AbilityCatalog, state: &mut CampaignConsoleState) -> Result<()> {
    println!("{YELLOW}Intrusion set planner initialized.{RESET}");
    println!();
    let mut rl = new_spuc_editor()?;
    load_editor_history(&mut rl);
    if let Err(err) = bootstrap_campaign_required_fields(&mut rl, catalog, state) {
        ui_warn(&err.to_string());
        save_editor_history(&mut rl);
        return Ok(());
    }
    show_campaign_variables(state);

    loop {
        let prompt = campaign_prompt(state.mode);
        set_editor_words(&mut rl, campaign_completion_words(state));
        let Some(line) = read_line_with_spacing(&mut rl, &prompt)? else {
            println!("{YELLOW}Planner cancelled.{RESET}");
            save_editor_history(&mut rl);
            return Ok(());
        };
        let input = line.trim();
        if input.is_empty() {
            continue;
        }
        let lower = input.to_ascii_lowercase();

        if lower == "help" || lower == "?" {
            print_campaign_help(state.mode);
            continue;
        }
        if lower.starts_with("help ") {
            let topic = input["help ".len()..].trim();
            let normalized_topic = normalize_campaign_topic(topic);
            if !print_campaign_topic_help(&normalized_topic, state.mode) {
                ui_error(&format!(
                    "Command {} is not supported. Use {}",
                    bold_cmd(topic),
                    bold_cmd("help")
                ));
            }
            continue;
        }
        if lower == "show" {
            show_campaign_variables(state);
            continue;
        }
        if lower == "show_selected" || lower == "show selected" {
            show_selected_abilities(state);
            continue;
        }
        if let Some(id) = command_suffix(input, &lower, &["show_ability ", "show ability "]) {
            if let Err(err) = show_ability_detail(catalog, state, id) {
                ui_error(&err.to_string());
            }
            continue;
        }
        if lower == "list" {
            if let Err(err) = list_all_catalog_abilities(catalog, state) {
                ui_error(&err.to_string());
            }
            continue;
        }
        if lower.starts_with("set ") {
            if let Err(err) = handle_campaign_set(catalog, state, input["set ".len()..].trim()) {
                ui_error(&err.to_string());
            }
            continue;
        }
        if lower.starts_with("unset ") {
            if let Err(err) = handle_campaign_unset(state, input["unset ".len()..].trim()) {
                ui_error(&err.to_string());
            }
            continue;
        }
        if lower == "search" || lower.starts_with("search ") {
            let value = if lower == "search" {
                String::new()
            } else {
                input["search ".len()..].trim().to_string()
            };
            if value.trim().is_empty() {
                ui_error(&format!(
                    "Command {} requires text. Example: {} powershell",
                    bold_cmd("search"),
                    bold_cmd("search")
                ));
                continue;
            }
            state.search = Some(value);
            if let Err(err) = enter_catalog_mode(catalog, state) {
                ui_error(&err.to_string());
            }
            continue;
        }
        if lower.starts_with("filter_by ") {
            if let Err(err) = handle_filter_by(catalog, state, input["filter_by ".len()..].trim()) {
                ui_error(&err.to_string());
                continue;
            }
            if let Err(err) = enter_catalog_mode(catalog, state) {
                ui_error(&err.to_string());
            }
            continue;
        }
        if lower.starts_with("select ") {
            let selector = input["select ".len()..].trim();
            if let Err(err) = select_ability(catalog, state, selector) {
                ui_error(&err.to_string());
            }
            continue;
        }
        if lower.starts_with("unselect ") {
            let selector = input["unselect ".len()..].trim();
            if let Err(err) = unselect_ability(state, selector) {
                ui_error(&err.to_string());
            }
            continue;
        }
        if lower.starts_with("reorder ") {
            let selectors = parse_csv_ids(input["reorder ".len()..].trim());
            match reorder_ids(&state.selected_ids, &selectors) {
                Ok(reordered) => {
                    state.selected_ids = reordered;
                    ui_warn("Selected abilities reordered");
                }
                Err(err) => ui_error(&err.to_string()),
            }
            continue;
        }
        if let Some(seconds_raw) =
            command_suffix(input, &lower, &["add_sleep ", "add dummy sleep "])
        {
            let seconds = match seconds_raw.parse::<u64>() {
                Ok(value) => value,
                Err(_) => {
                    ui_error("sleep seconds must be a positive integer");
                    continue;
                }
            };
            if seconds == 0 {
                ui_error("sleep seconds must be greater than zero");
                continue;
            }
            if let Err(err) = add_sleep_ability(catalog, state, seconds) {
                ui_error(&err.to_string());
            }
            continue;
        }
        if let Some(label) = command_suffix(input, &lower, &["add_label ", "add dummy label "]) {
            if label.is_empty() {
                ui_error("label text cannot be empty");
                continue;
            }
            if let Err(err) = add_label_ability(catalog, state, label) {
                ui_error(&err.to_string());
            }
            continue;
        }
        if lower == "back" || lower == "backp" {
            if state.mode == CampaignConsoleMode::CatalogView {
                state.mode = CampaignConsoleMode::Normal;
                state.current_results.clear();
                println!("{YELLOW}Back to intrusion set configuration.{RESET}");
            } else {
                println!("{YELLOW}Planner cancelled.{RESET}");
                save_editor_history(&mut rl);
                return Ok(());
            }
            continue;
        }
        if lower == "build"
            || lower.starts_with("build ")
            || lower == "export"
            || lower.starts_with("export ")
            || lower == "run"
            || lower == "save"
        {
            let executor = match parse_build_executor_input(input, state.executor) {
                Ok(value) => value,
                Err(err) => {
                    ui_error(&err.to_string());
                    continue;
                }
            };
            match build_and_render_campaign(catalog, state, executor) {
                Ok(()) => {
                    save_editor_history(&mut rl);
                    return Ok(());
                }
                Err(err) => ui_error(&err.to_string()),
            }
            continue;
        }
        if lower == "exit" || lower == "quit" {
            println!("{YELLOW}Planner cancelled.{RESET}");
            save_editor_history(&mut rl);
            return Ok(());
        }

        ui_error(&format!(
            "Command {} is not supported in {} mode. Use {}",
            bold_cmd(input),
            bold_cmd("plan"),
            bold_cmd("help")
        ));
    }
}

fn print_campaign_help(mode: CampaignConsoleMode) {
    println!("{YELLOW}Commands available:{RESET}");
    println!(
        "{YELLOW}  {BOLD}show{RESET}{YELLOW} -> show current variables and selected abilities. Example: {BOLD}show{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}show_selected{RESET}{YELLOW} -> list selected ability ids. Example: {BOLD}show_selected{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}show_ability <id|index>{RESET}{YELLOW} -> show one ability detail. Example: {BOLD}show_ability 3{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}set VARIABLE=value{RESET}{YELLOW} -> update planner variable. Example: {BOLD}set PLATFORM=linux,windows{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}unset VARIABLE{RESET}{YELLOW} -> reset planner variable. Example: {BOLD}unset PLATFORM{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}search <text>{RESET}{YELLOW} -> enter catalog mode with text search. Example: {BOLD}search powershell{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}filter_by <field>=<value>{RESET}{YELLOW} -> set quick filters. Example: {BOLD}filter_by confidence=80{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}list{RESET}{YELLOW} -> list all catalog abilities. Example: {BOLD}list{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}select <id|index>{RESET}{YELLOW} -> select an ability. Example: {BOLD}select 2{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}unselect <id>{RESET}{YELLOW} -> remove one selected ability. Example: {BOLD}unselect abl-123{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}reorder <id-or-index,...>{RESET}{YELLOW} -> reorder selected abilities. Example: {BOLD}reorder 3,2,1{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}add_sleep <seconds>{RESET}{YELLOW} -> add pacing dummy ability. Example: {BOLD}add_sleep 5{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}add_label <text>{RESET}{YELLOW} -> add marker dummy ability. Example: {BOLD}add_label phase_a{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}build <spuc-agent|bash|powershell|atomic-red-team|mitre-caldera>{RESET}{YELLOW} -> compile outputs for one executor. Example: {BOLD}build spuc-agent{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}export <spuc-agent|bash|powershell|atomic-red-team|mitre-caldera>{RESET}{YELLOW} -> alias of build for writing artifacts. Example: {BOLD}export bash{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}help <command>{RESET}{YELLOW} -> detailed help for one command. Example: {BOLD}help build{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}back{RESET}{YELLOW} -> leave catalog mode or cancel planner. Example: {BOLD}back{RESET}"
    );
    println!("{YELLOW}  {BOLD}exit{RESET}{YELLOW} -> cancel planner. Example: {BOLD}exit{RESET}");
    if mode == CampaignConsoleMode::CatalogView {
        println!();
        println!(
            "{YELLOW}Catalog mode active: use {BOLD}show_ability{RESET}{YELLOW}, {BOLD}select{RESET}{YELLOW}, {BOLD}back{RESET}{YELLOW}.{RESET}"
        );
    }
}

fn normalize_campaign_topic(topic: &str) -> String {
    topic
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("_")
}

fn print_campaign_topic_help(topic: &str, mode: CampaignConsoleMode) -> bool {
    match topic.trim().to_ascii_lowercase().as_str() {
        "show" => {
            println!(
                "{YELLOW}{BOLD}show{RESET}{YELLOW}: prints variable descriptions + current configuration + selected abilities.{RESET}"
            );
            println!("{YELLOW}Example: {BOLD}show{RESET}");
            true
        }
        "set" => {
            println!(
                "{YELLOW}{BOLD}set VARIABLE=value{RESET}{YELLOW}: updates a planner variable.{RESET}"
            );
            println!(
                "{YELLOW}Examples: {BOLD}set NAME=Validation Set{RESET}{YELLOW}, {BOLD}set PLATFORM=linux,windows{RESET}"
            );
            true
        }
        "unset" => {
            println!(
                "{YELLOW}{BOLD}unset VARIABLE{RESET}{YELLOW}: resets one planner variable to default.{RESET}"
            );
            println!("{YELLOW}Example: {BOLD}unset PLATFORM{RESET}");
            true
        }
        "search" => {
            println!(
                "{YELLOW}{BOLD}search <text>{RESET}{YELLOW}: enters catalog mode and filters by free text.{RESET}"
            );
            println!("{YELLOW}Example: {BOLD}search powershell{RESET}");
            true
        }
        "filter_by" => {
            println!(
                "{YELLOW}{BOLD}filter_by <field>=<value>{RESET}{YELLOW}: applies catalog filters (platform, confidence).{RESET}"
            );
            println!(
                "{YELLOW}Examples: {BOLD}filter_by platform=linux{RESET}{YELLOW}, {BOLD}filter_by confidence=80{RESET}"
            );
            true
        }
        "list" => {
            println!(
                "{YELLOW}{BOLD}list{RESET}{YELLOW}: prints all abilities from local catalog with index.{RESET}"
            );
            println!("{YELLOW}Example: {BOLD}list{RESET}");
            true
        }
        "show_selected" => {
            println!(
                "{YELLOW}{BOLD}show_selected{RESET}{YELLOW}: prints selected ability ids in execution order.{RESET}"
            );
            println!("{YELLOW}Example: {BOLD}show_selected{RESET}");
            true
        }
        "show_ability" | "ability" => {
            println!(
                "{YELLOW}{BOLD}show_ability <id|index>{RESET}{YELLOW}: prints the full ability payload summary.{RESET}"
            );
            println!("{YELLOW}Example: {BOLD}show_ability 1{RESET}");
            true
        }
        "select" => {
            println!(
                "{YELLOW}{BOLD}select <id|index>{RESET}{YELLOW}: appends an ability to selected list.{RESET}"
            );
            println!("{YELLOW}Example: {BOLD}select abl-123{RESET}");
            true
        }
        "unselect" => {
            println!(
                "{YELLOW}{BOLD}unselect <id>{RESET}{YELLOW}: removes one ability from selected list.{RESET}"
            );
            println!("{YELLOW}Example: {BOLD}unselect abl-123{RESET}");
            true
        }
        "reorder" => {
            println!(
                "{YELLOW}{BOLD}reorder <id-or-index,...>{RESET}{YELLOW}: reorder selected abilities by id/index mix.{RESET}"
            );
            println!("{YELLOW}Example: {BOLD}reorder 3,2,1{RESET}");
            true
        }
        "add_sleep" | "add_dummy_sleep" => {
            println!(
                "{YELLOW}{BOLD}add_sleep <seconds>{RESET}{YELLOW}: adds a dummy delay ability to pace execution flow.{RESET}"
            );
            println!("{YELLOW}Example: {BOLD}add_sleep 5{RESET}");
            true
        }
        "add_label" | "add_dummy_label" => {
            println!(
                "{YELLOW}{BOLD}add_label <text>{RESET}{YELLOW}: adds a dummy marker ability to annotate execution phases.{RESET}"
            );
            println!("{YELLOW}Example: {BOLD}add_label phase_a{RESET}");
            true
        }
        "build" | "export" | "run" | "save" => {
            println!(
                "{YELLOW}{BOLD}build/export <executor>{RESET}{YELLOW}: compiles one output set per selected platform for that executor.{RESET}"
            );
            println!(
                "{YELLOW}Executors: {BOLD}spuc-agent{RESET}{YELLOW}, {BOLD}bash{RESET}{YELLOW}, {BOLD}powershell{RESET}{YELLOW}, {BOLD}atomic-red-team{RESET}{YELLOW}, {BOLD}mitre-caldera{RESET}"
            );
            println!("{YELLOW}Example: {BOLD}build spuc-agent{RESET}");
            true
        }
        "back" => {
            if mode == CampaignConsoleMode::CatalogView {
                println!(
                    "{YELLOW}{BOLD}back{RESET}{YELLOW}: leaves catalog mode and returns to planner mode.{RESET}"
                );
            } else {
                println!(
                    "{YELLOW}{BOLD}back{RESET}{YELLOW}: cancels planner and returns to previous console.{RESET}"
                );
            }
            true
        }
        "exit" | "quit" => {
            println!(
                "{YELLOW}{BOLD}exit{RESET}{YELLOW}/{BOLD}quit{RESET}{YELLOW}: cancels planner immediately.{RESET}"
            );
            true
        }
        _ => false,
    }
}

fn parse_build_executor_input(
    raw: &str,
    default_executor: Option<AbilityTarget>,
) -> Result<AbilityTarget> {
    let normalized = raw.trim();
    let token_opt = if normalized.eq_ignore_ascii_case("build")
        || normalized.eq_ignore_ascii_case("export")
        || normalized.eq_ignore_ascii_case("run")
        || normalized.eq_ignore_ascii_case("save")
    {
        None
    } else if normalized.to_ascii_lowercase().starts_with("build ") {
        Some(normalized["build ".len()..].trim())
    } else if normalized.to_ascii_lowercase().starts_with("export ") {
        Some(normalized["export ".len()..].trim())
    } else {
        None
    };

    if let Some(token) = token_opt {
        return parse_ability_target(token).ok_or_else(|| {
            anyhow!(
                "executor '{}' is not supported. Allowed: spuc-agent, bash, powershell, atomic-red-team, mitre-caldera.",
                token
            )
        });
    };

    default_executor.ok_or_else(|| {
        anyhow!(
            "build/export requires executor. Example: {} {}",
            bold_cmd("build"),
            bold_cmd("spuc-agent")
        )
    })
}

fn show_campaign_variables(state: &CampaignConsoleState) {
    print_variable_docs(
        "Variables description:",
        &[
            (
                "INTRUSION_SET_ID",
                "Unique intrusion set id used in manifest filename.",
            ),
            ("NAME", "Intrusion set name (required before build)."),
            ("DESCRIPTION", "Intrusion set description."),
            (
                "OUTPUT",
                "Manifest output path (default: spuc-intrusion_set-<platform>-<snake_case_name>.yaml under config intrusion_sets folder).",
            ),
            ("FORMAT", "Fixed yaml for manifests in this iteration."),
            (
                "SHOW",
                "Visible output blocks: summary, canonical, artifact, manifest, all.",
            ),
            (
                "PLATFORM",
                "Candidate platform filter list (linux/windows/macos/any).",
            ),
            (
                "CONFIDENCE",
                "Minimum ability confidence filter (default 70).",
            ),
        ],
    );
    println!();
    println!("{YELLOW}⚙️ Current configuration:{RESET}");
    print_variable_value("INTRUSION_SET_ID", &state.intrusion_set_id);
    print_variable_value("NAME", &state.name);
    print_variable_value("DESCRIPTION", state.description.as_deref().unwrap_or(""));
    print_variable_value(
        "OUTPUT",
        state
            .output
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
    );
    print_variable_value("FORMAT", "yaml");
    print_variable_value(
        "SHOW",
        show_output_value(&state.show, &[OutputBlock::Summary, OutputBlock::Manifest]),
    );
    print_variable_value(
        "PLATFORM",
        if state.platforms.is_empty() {
            String::new()
        } else {
            state.platforms.join(",")
        },
    );
    print_variable_value("CONFIDENCE", state.confidence.to_string());
    println!();
    show_selected_abilities(state);
}

fn show_selected_abilities(state: &CampaignConsoleState) {
    println!(
        "{BOLD}{GREEN}🧩 Selected abilities ({}){RESET}",
        state.selected_ids.len()
    );
    if state.selected_ids.is_empty() {
        println!("  (none)");
        return;
    }
    for (idx, id) in state.selected_ids.iter().enumerate() {
        println!("  {}. {}", idx + 1, id);
    }
}

fn show_ability_detail(
    catalog: &AbilityCatalog,
    state: &CampaignConsoleState,
    selector: &str,
) -> Result<()> {
    if selector.is_empty() {
        return Err(anyhow!("show_ability requires an id"));
    }
    let from_results = if let Ok(idx) = selector.parse::<usize>() {
        if idx == 0 {
            return Err(anyhow!("index starts at 1"));
        }
        state.current_results.get(idx - 1).cloned()
    } else {
        state
            .current_results
            .iter()
            .find(|a| a.id == selector)
            .cloned()
    };
    let ability = if let Some(found) = from_results {
        found
    } else {
        catalog
            .get_by_id(selector)?
            .ok_or_else(|| anyhow!("ability '{selector}' not found"))?
    };
    println!(
        "{BOLD}{PURPLE}🧪 Ability detail: {} ({}){RESET}",
        ability.id, ability.name
    );
    println!("  description: {}", ability.description);
    println!(
        "  supported_platforms: {}",
        ability.supported_platforms.join(", ")
    );
    println!(
        "  classification: {}",
        ability_classification_label(&ability.classification)
    );
    println!("  confidence: {}", ability.confidence);
    println!("  source_pattern: {}", ability.source_pattern);
    println!("  actions:");
    for action in &ability.actions {
        println!(
            "    - {} | {} {} '{}' | {}",
            action.id, action.observable, action.operator, action.value, action.safe_instructions
        );
    }
    Ok(())
}

fn enter_catalog_mode(catalog: &AbilityCatalog, state: &mut CampaignConsoleState) -> Result<()> {
    let all = catalog.list()?;
    state.current_results = apply_campaign_filters(&all, state);
    state.mode = CampaignConsoleMode::CatalogView;
    println!(
        "{BOLD}{BLUE}🔎 Catalog results: {} ability(ies){RESET}",
        state.current_results.len()
    );
    list_catalog_results(state);
    println!("{YELLOW}Use: show_ability <id> | select <id|index> | back{RESET}");
    Ok(())
}

fn list_all_catalog_abilities(
    catalog: &AbilityCatalog,
    state: &mut CampaignConsoleState,
) -> Result<()> {
    state.current_results = catalog.list()?;
    list_catalog_results(state);
    Ok(())
}

fn list_catalog_results(state: &CampaignConsoleState) {
    if state.current_results.is_empty() {
        println!("{YELLOW}No abilities match current filters.{RESET}");
        return;
    }
    let rows = state
        .current_results
        .iter()
        .enumerate()
        .map(|(idx, ability)| {
            vec![
                (idx + 1).to_string(),
                ability.id.clone(),
                ability.name.clone(),
                ability.supported_platforms.join(", "),
                ability.confidence.to_string(),
            ]
        })
        .collect::<Vec<_>>();
    print_table(&["#", "ID", "NAME", "PLATFORMS", "CONFIDENCE"], &rows);
}

fn handle_filter_by(
    catalog: &AbilityCatalog,
    state: &mut CampaignConsoleState,
    raw: &str,
) -> Result<()> {
    let (field, value) = parse_key_value(raw)?;
    if value.trim().is_empty() {
        return Err(anyhow!("filter_by value cannot be empty"));
    }
    match field.to_ascii_lowercase().as_str() {
        "platform" => {
            let platforms = parse_platforms_value(value)?;
            let incompatible =
                incompatible_selected_abilities_for_platforms(catalog, state, &platforms)?;
            if !incompatible.is_empty() {
                return Err(anyhow!(
                    "Incompatible PLATFORM for selected abilities: {}",
                    incompatible.join(", ")
                ));
            }
            state.platforms = platforms;
        }
        "confidence" => {
            let parsed = value
                .parse::<u8>()
                .map_err(|_| anyhow!("confidence must be numeric (0..100)"))?;
            if parsed > 100 {
                return Err(anyhow!("confidence must be between 0 and 100"));
            }
            state.confidence = parsed;
        }
        other => {
            return Err(anyhow!(
                "unsupported filter field '{}'. Supported: platform, confidence",
                other
            ));
        }
    }
    Ok(())
}

fn handle_campaign_set(
    catalog: &AbilityCatalog,
    state: &mut CampaignConsoleState,
    raw: &str,
) -> Result<()> {
    let (key, value) = parse_key_value(raw)?;
    match key.to_ascii_uppercase().as_str() {
        "INTRUSION_SET_ID" => {
            state.intrusion_set_id = value.to_string();
            refresh_campaign_output_path(state);
        }
        "NAME" => {
            state.name = value.to_string();
            refresh_campaign_output_path(state);
        }
        "DESCRIPTION" => {
            state.description = if value.trim().is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        }
        "OUTPUT" => {
            state.output = if value.trim().is_empty() {
                state.output_is_user_defined = false;
                default_campaign_output_path(&state.name, output_platform_hint(&state.platforms))
            } else {
                state.output_is_user_defined = true;
                Some(PathBuf::from(value))
            }
        }
        "FORMAT" => {
            return Err(anyhow!("FORMAT is fixed to yaml in this iteration."));
        }
        "PLATFORM" => {
            let platforms = parse_platforms_value(value)?;
            let incompatible =
                incompatible_selected_abilities_for_platforms(catalog, state, &platforms)?;
            if !incompatible.is_empty() {
                return Err(anyhow!(
                    "Incompatible PLATFORM for selected abilities: {}",
                    incompatible.join(", ")
                ));
            }
            state.platforms = platforms;
            refresh_campaign_output_path(state);
        }
        "SHOW" => {
            state.show = parse_build_outputs(value)?;
        }
        "CONFIDENCE" => {
            let parsed = value
                .parse::<u8>()
                .map_err(|_| anyhow!("CONFIDENCE must be numeric (0..100)"))?;
            if parsed > 100 {
                return Err(anyhow!("CONFIDENCE must be between 0 and 100"));
            }
            state.confidence = parsed;
        }
        other => {
            return Err(anyhow!(
                "unknown variable '{}'. Use help for supported variables.",
                other
            ));
        }
    }
    println!("{YELLOW}Variable updated.{RESET}");
    Ok(())
}

fn handle_campaign_unset(state: &mut CampaignConsoleState, key: &str) -> Result<()> {
    match key.trim().to_ascii_uppercase().as_str() {
        "DESCRIPTION" => state.description = Some(INTRUSION_SET_DEFAULT_DESCRIPTION.to_string()),
        "OUTPUT" => {
            state.output_is_user_defined = false;
            refresh_campaign_output_path(state);
        }
        "PLATFORM" => {
            state.platforms.clear();
            refresh_campaign_output_path(state);
        }
        "SHOW" => state.show = default_campaign_show(),
        "CONFIDENCE" => state.confidence = 70,
        "NAME" => {
            state.name = String::new();
            refresh_campaign_output_path(state);
        }
        "INTRUSION_SET_ID" => {
            state.intrusion_set_id = format!("intrusion-set-{}", Utc::now().timestamp_millis());
            refresh_campaign_output_path(state);
        }
        "FORMAT" => {
            println!("{YELLOW}FORMAT is fixed to yaml in this iteration.{RESET}");
        }
        other => return Err(anyhow!("cannot unset '{}'", other)),
    }
    println!("{YELLOW}Variable unset/reset.{RESET}");
    Ok(())
}

fn select_ability(
    catalog: &AbilityCatalog,
    state: &mut CampaignConsoleState,
    selector: &str,
) -> Result<()> {
    if selector.trim().is_empty() {
        return Err(anyhow!("select requires an ability id or index"));
    }
    let chosen_ability = if let Ok(idx) = selector.parse::<usize>() {
        if idx == 0 {
            return Err(anyhow!("index starts at 1"));
        }
        let item = state
            .current_results
            .get(idx - 1)
            .ok_or_else(|| anyhow!("invalid index '{}'", idx))?;
        item.clone()
    } else if let Some(item) = state.current_results.iter().find(|a| a.id == selector) {
        item.clone()
    } else {
        catalog
            .get_by_id(selector)?
            .ok_or_else(|| anyhow!("ability '{}' not found", selector))?
    };
    ensure_ability_compatible_with_platforms(&chosen_ability, &state.platforms)?;
    let chosen_id = chosen_ability.id.clone();
    if !state.selected_ids.iter().any(|id| id == &chosen_id) {
        state.selected_ids.push(chosen_id.clone());
        println!("{YELLOW}Added ability '{chosen_id}' to intrusion set.{RESET}");
    } else {
        println!("{YELLOW}Ability '{chosen_id}' is already selected.{RESET}");
    }
    Ok(())
}

fn incompatible_platforms_for_ability(
    ability: &emu_ability::Ability,
    platforms: &[String],
) -> Vec<String> {
    platforms
        .iter()
        .filter(|platform| !ability_supports_platform(ability, platform))
        .cloned()
        .collect()
}

fn ensure_ability_compatible_with_platforms(
    ability: &emu_ability::Ability,
    platforms: &[String],
) -> Result<()> {
    if platforms.is_empty() {
        return Ok(());
    }
    let incompatible = incompatible_platforms_for_ability(ability, platforms);
    if incompatible.is_empty() {
        return Ok(());
    }
    Err(anyhow!(
        "Incompatible PLATFORM for selected ability '{}': {}",
        ability.id,
        incompatible.join(", ")
    ))
}

fn unselect_ability(state: &mut CampaignConsoleState, selector: &str) -> Result<()> {
    if selector.trim().is_empty() {
        return Err(anyhow!("unselect requires an ability id"));
    }
    let before = state.selected_ids.len();
    state.selected_ids.retain(|id| id != selector);
    if state.selected_ids.len() == before {
        println!("{YELLOW}Ability '{}' was not selected.{RESET}", selector);
    } else {
        println!("{YELLOW}Removed ability '{}'.{RESET}", selector);
    }
    Ok(())
}

fn apply_campaign_filters(
    abilities: &[emu_ability::Ability],
    state: &CampaignConsoleState,
) -> Vec<emu_ability::Ability> {
    let mut items = abilities.to_vec();
    if let Some(search) = &state.search {
        let needle = search.to_ascii_lowercase();
        items.retain(|a| {
            format!("{} {} {} {}", a.id, a.name, a.description, a.source_pattern)
                .to_ascii_lowercase()
                .contains(&needle)
        });
    }
    if !state.platforms.is_empty() {
        items.retain(|a| {
            state.platforms.iter().any(|target_platform| {
                a.supported_platforms.iter().any(|supported| {
                    supported.eq_ignore_ascii_case("any")
                        || target_platform.eq_ignore_ascii_case("any")
                        || supported.eq_ignore_ascii_case(target_platform)
                })
            })
        });
    }
    items.retain(|a| a.confidence >= state.confidence);
    items
}

fn parse_key_value(raw: &str) -> Result<(&str, &str)> {
    let (left, right) = raw
        .split_once('=')
        .ok_or_else(|| anyhow!("expected KEY=value syntax"))?;
    let key = left.trim();
    if key.is_empty() {
        return Err(anyhow!("key cannot be empty"));
    }
    Ok((key, right.trim()))
}

fn normalize_platform(platform: Option<&str>) -> Result<Option<String>> {
    let Some(raw) = platform else {
        return Ok(None);
    };
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(None);
    }
    if ALLOWED_PLATFORMS
        .iter()
        .any(|allowed| *allowed == normalized)
    {
        Ok(Some(normalized))
    } else {
        Err(anyhow!(
            "unsupported platform '{}'. Allowed values: {}",
            raw,
            ALLOWED_PLATFORMS.join(", ")
        ))
    }
}

fn normalize_platforms(platforms: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for raw in platforms {
        let normalized = normalize_platform(Some(raw))?
            .ok_or_else(|| anyhow!("platform value cannot be empty"))?;
        if !out.iter().any(|item| item == &normalized) {
            out.push(normalized);
        }
    }
    if out.iter().any(|value| value == "any") {
        return Ok(vec!["any".to_string()]);
    }
    Ok(out)
}

fn parse_platforms_value(value: &str) -> Result<Vec<String>> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    let raw = value
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    normalize_platforms(&raw)
}

fn output_platform_hint(platforms: &[String]) -> Option<&str> {
    if platforms.is_empty() {
        None
    } else if platforms.len() == 1 {
        Some(platforms[0].as_str())
    } else {
        Some("multi")
    }
}

fn primary_platform_hint(platforms: &[String]) -> Option<&str> {
    platforms.first().map(String::as_str)
}

fn default_campaign_output_path(name: &str, platform: Option<&str>) -> Option<PathBuf> {
    paths::campaigns_dir().map(|root| {
        root.join(emu_campaign::default_campaign_filename(
            name, platform, "yaml",
        ))
    })
}

fn slugify_token(raw: &str) -> String {
    let mut out = String::new();
    let mut prev_sep = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_sep = false;
        } else if !prev_sep {
            out.push('_');
            prev_sep = true;
        }
    }
    let trimmed = out.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "unnamed".to_string()
    } else {
        trimmed
    }
}

fn refresh_campaign_output_path(state: &mut CampaignConsoleState) {
    if state.output_is_user_defined {
        return;
    }
    state.output =
        default_campaign_output_path(&state.name, output_platform_hint(&state.platforms));
}

fn parse_csv_ids(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn reorder_ids(current: &[String], order: &[String]) -> Result<Vec<String>> {
    let mut reordered = Vec::new();
    for selector in order {
        let wanted = if let Some(found) = current.iter().find(|id| *id == selector) {
            found.clone()
        } else if let Ok(index) = selector.parse::<usize>() {
            if index == 0 {
                return Err(anyhow!("reorder index starts at 1"));
            }
            current.get(index - 1).cloned().ok_or_else(|| {
                anyhow!(
                    "reorder index '{}' is out of range (selected abilities: {})",
                    index,
                    current.len()
                )
            })?
        } else {
            return Err(anyhow!(
                "ability '{}' from order is not selected in current intrusion set",
                selector
            ));
        };

        if !reordered.iter().any(|id| id == &wanted) {
            reordered.push(wanted);
        }
    }
    for id in current {
        if !reordered.iter().any(|item| item == id) {
            reordered.push(id.clone());
        }
    }
    Ok(reordered)
}

fn ability_supports_platform(ability: &emu_ability::Ability, platform: &str) -> bool {
    if platform.eq_ignore_ascii_case("any") {
        return true;
    }
    ability.supported_platforms.iter().any(|supported| {
        supported.eq_ignore_ascii_case("any") || supported.eq_ignore_ascii_case(platform)
    })
}

fn incompatible_selected_abilities_for_platforms(
    catalog: &AbilityCatalog,
    state: &CampaignConsoleState,
    platforms: &[String],
) -> Result<Vec<String>> {
    if state.selected_ids.is_empty() {
        return Ok(Vec::new());
    }
    let selected = catalog.select_by_ids(&state.selected_ids)?;
    let mut out = Vec::new();
    for platform in platforms {
        for ability in &selected {
            if !ability_supports_platform(ability, platform) {
                out.push(format!("{}@{}", ability.id, platform));
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn resolve_plan_build_root(state: &CampaignConsoleState) -> Result<PathBuf> {
    let root = if let Some(output) = &state.output {
        if output.extension().is_some() {
            output
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."))
        } else {
            output.clone()
        }
    } else {
        paths::campaigns_dir().ok_or_else(|| anyhow!("cannot resolve config root"))?
    };
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn ordered_ids_for_subset(
    selected_ids: &[String],
    abilities: &[emu_ability::Ability],
) -> Vec<String> {
    selected_ids
        .iter()
        .filter(|id| abilities.iter().any(|ability| &ability.id == *id))
        .cloned()
        .collect()
}

fn validate_ability_for_build(
    ability: &emu_ability::Ability,
    executor: AbilityTarget,
    platform: &str,
) -> Result<()> {
    if let Err(issues) = ability.validate_structure() {
        return Err(anyhow!(
            "ability '{}' failed structural validation: {}",
            ability.id,
            issues.join(" | ")
        ));
    }
    if executor == AbilityTarget::SpucAgent {
        let profile = if platform.eq_ignore_ascii_case("any") {
            emu_validate::local_agent_profile()
        } else {
            emu_validate::AgentProfile {
                platform: platform.to_string(),
                capabilities: emu_validate::default_capabilities_for_platform(platform),
            }
        };
        let report = emu_validate::validate_ability(ability, &profile);
        if report.compatibility == emu_validate::CompatibilityStatus::NotExecutable {
            return Err(anyhow!(
                "spuc-agent validation failed for ability '{}' on platform '{}': {}",
                ability.id,
                platform,
                report.reasons.join(" | ")
            ));
        }
    }
    let _ = emu_export::export_ability(ability_target_to_export(executor), ability)?;
    Ok(())
}

fn build_and_render_campaign(
    catalog: &AbilityCatalog,
    state: &CampaignConsoleState,
    executor: AbilityTarget,
) -> Result<()> {
    if state.name.trim().is_empty() {
        return Err(anyhow!("NAME is required. Set it with: set NAME=<value>"));
    }
    if state.selected_ids.is_empty() {
        return Err(anyhow!(
            "No abilities selected. Use search/filter_by and select commands first."
        ));
    }
    if state.platforms.is_empty() {
        return Err(anyhow!(
            "PLATFORM is required. Set it with: set PLATFORM=linux or pass --platform."
        ));
    }
    let selected = catalog.select_by_ids(&state.selected_ids)?;
    let platforms = state.platforms.clone();
    let root = resolve_plan_build_root(state)?;
    let executor_label = ability_target_label(executor);
    let executor_ext = ability_target_extension(executor);
    let name_tag = slugify_token(&state.name);

    let mut sections = Vec::new();
    let mut saved_manifest_paths = Vec::new();
    let mut saved_artifact_paths = Vec::new();

    for platform in platforms {
        let incompatible = selected
            .iter()
            .filter(|ability| !ability_supports_platform(ability, &platform))
            .map(|ability| ability.id.clone())
            .collect::<Vec<_>>();
        if !incompatible.is_empty() {
            return Err(anyhow!(
                "Inconsistent build for platform '{}': abilities not compatible: {}",
                platform,
                incompatible.join(", ")
            ));
        }
        let selected_for_platform = selected
            .iter()
            .filter(|ability| ability_supports_platform(ability, &platform))
            .cloned()
            .collect::<Vec<_>>();
        if selected_for_platform.is_empty() {
            return Err(anyhow!(
                "No selected abilities are compatible with platform '{}'.",
                platform
            ));
        }

        for ability in &selected_for_platform {
            validate_ability_for_build(ability, executor, &platform)?;
        }

        let ordered_ids = ordered_ids_for_subset(&state.selected_ids, &selected_for_platform);
        let mut campaign = emu_campaign::build_campaign_ordered_with_confidence(
            state.intrusion_set_id.clone(),
            state.name.clone(),
            state
                .description
                .clone()
                .unwrap_or_else(|| INTRUSION_SET_DEFAULT_DESCRIPTION.to_string()),
            &selected_for_platform,
            &ordered_ids,
            state.confidence,
        );
        for step in &mut campaign.steps {
            if step.platform.eq_ignore_ascii_case("any") {
                step.platform = platform.clone();
            }
        }
        campaign.validate_structure().map_err(|issues| {
            anyhow!(
                "Generated intrusion set failed validation on platform '{}': {}",
                platform,
                issues.join(" | ")
            )
        })?;

        let base_name = format!(
            "spuc-intrusion_set-{}-{}-{}",
            slugify_token(&platform),
            name_tag,
            executor_label
        );
        let manifest_path = root.join(format!("{base_name}.yaml"));
        let saved_path = emu_campaign::save_campaign_yaml(&campaign, Some(&manifest_path))?;
        let manifest = fs::read_to_string(&saved_path)?;
        let canonical = serde_json::to_string_pretty(&campaign)?;
        saved_manifest_paths.push(saved_path.clone());

        for ability in &selected_for_platform {
            let artifact = emu_export::export_ability(ability_target_to_export(executor), ability)?;
            let artifact_path = root.join(format!(
                "{base_name}-{}.{}",
                slugify_token(&ability.id),
                executor_ext
            ));
            fs::write(&artifact_path, artifact)?;
            saved_artifact_paths.push(artifact_path);
        }

        for block in
            resolve_output_blocks(&state.show, &[OutputBlock::Summary, OutputBlock::Manifest])
        {
            match block {
                OutputBlock::Summary => sections.push(OutputSection {
                    block,
                    title: format!("Intrusion Set Summary ({platform}, {executor_label})"),
                    body: render_campaign_card(&campaign),
                }),
                OutputBlock::Canonical => sections.push(OutputSection {
                    block,
                    title: format!("Intrusion Set Canonical JSON ({platform}, {executor_label})"),
                    body: canonical.clone(),
                }),
                OutputBlock::Manifest => sections.push(OutputSection {
                    block,
                    title: format!("Intrusion Set Manifest ({})", saved_path.display()),
                    body: manifest.clone(),
                }),
                OutputBlock::Artifact => sections.push(OutputSection {
                    block,
                    title: format!("Intrusion Set Artifacts ({platform}, {executor_label})"),
                    body: saved_artifact_paths
                        .iter()
                        .filter(|path| {
                            path.file_name()
                                .and_then(|name| name.to_str())
                                .is_some_and(|name| {
                                    name.contains(&format!(
                                        "spuc-intrusion_set-{}-{}-{}",
                                        slugify_token(&platform),
                                        name_tag,
                                        executor_label
                                    ))
                                })
                        })
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join("\n"),
                }),
            }
        }
    }

    println!("{}", emu_output::render_sections(&sections));
    for path in &saved_manifest_paths {
        println!("{YELLOW}Intrusion set saved to {}{RESET}", path.display());
    }
    for path in &saved_artifact_paths {
        println!(
            "{YELLOW}Artifact ({}) saved to {}{RESET}",
            executor_label,
            path.display()
        );
    }
    Ok(())
}

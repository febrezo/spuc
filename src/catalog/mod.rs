#![allow(dead_code)]

use anyhow::{anyhow, Result};
use std::collections::{hash_map::DefaultHasher, BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use crate::cli::{AbilityTarget, AdversaryCommands, BuildOutput, RuleCommands};
use crate::commands::common::{
    ability_target_extension, ability_target_label, ability_target_to_export, all_ability_targets,
    build_ability_from_rule, known_detection_target_labels, render_ability_card,
};
use crate::commands::plan::export_saved_adversary;
use crate::paths;
use crate::ui::ansi::{BOLD, RESET, YELLOW};
use crate::ui::print::entry_label;
use spuc::emulation::ability as emu_ability;
use spuc::emulation::campaign as emu_campaign;
use spuc::emulation::catalog::{AbilityCatalog, TranslationActivity};
use spuc::emulation::export::{self as emu_export};
use spuc::emulation::output::{self as emu_output, OutputBlock, OutputSection};

type LoadedCatalogData = (
    AbilityCatalog,
    Vec<emu_ability::Ability>,
    Vec<CatalogRuleEntry>,
    Vec<CatalogAdversaryEntry>,
);

#[derive(Debug, Clone)]
pub(crate) struct CatalogRuleEntry {
    pub(crate) rule_id: String,
    pub(crate) ability_id: Option<String>,
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) ttp: Option<String>,
    pub(crate) confidence: u8,
    pub(crate) emulable: bool,
    pub(crate) rule: String,
    pub(crate) last_seen_utc: String,
    pub(crate) commands: Vec<String>,
    pub(crate) targets: Vec<String>,
    pub(crate) statuses: Vec<String>,
    pub(crate) target_statuses: BTreeMap<String, String>,
    pub(crate) emulation_statuses: BTreeMap<String, String>,
    pub(crate) activity_count: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct CatalogAdversaryEntry {
    pub(crate) adversary_id: String,
    pub(crate) source_intrusion_set_id: String,
    pub(crate) path: PathBuf,
    pub(crate) name: String,
    pub(crate) confidence: u8,
    pub(crate) steps: usize,
    pub(crate) platforms: Vec<String>,
    pub(crate) description: String,
    pub(crate) ability_refs: Vec<String>,
}

pub(crate) fn load_catalog_data() -> Result<LoadedCatalogData> {
    let catalog = AbilityCatalog::from_default_root()?;
    let abilities = catalog.list()?;
    let rules = build_catalog_rule_entries(&catalog, &abilities)?;
    let adversaries = build_catalog_adversary_entries()?;
    Ok((catalog, abilities, rules, adversaries))
}

pub(crate) fn run_rule_command(action: &RuleCommands) -> Result<()> {
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

pub(crate) fn run_adversary_command(action: &AdversaryCommands) -> Result<()> {
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
            let mut activities_by_target: HashMap<String, Vec<&TranslationActivity>> =
                HashMap::new();
            let mut last_seen_utc = String::new();
            for item in &items {
                commands.insert(item.command.clone());
                targets.insert(item.target.clone());
                statuses.insert(item.status.clone());
                activities_by_target
                    .entry(item.target.to_ascii_lowercase())
                    .or_default()
                    .push(item);
                if item.timestamp_utc > last_seen_utc {
                    last_seen_utc = item.timestamp_utc.clone();
                }
            }

            let target_statuses = known_detection_target_labels()
                .into_iter()
                .map(|target| {
                    let status = activities_by_target
                        .get(&target)
                        .map(|items| collapse_target_status(items))
                        .unwrap_or_else(|| "unsupported".to_string());
                    (target, status)
                })
                .collect::<BTreeMap<_, _>>();

            let emulation_statuses = [
                "spuc-agent",
                "bash",
                "powershell",
                "atomic-red-team",
                "mitre-caldera",
            ]
            .iter()
            .map(|target| {
                let status = activities_by_target
                    .get(*target)
                    .map(|items| collapse_target_status(items))
                    .unwrap_or_else(|| "unsupported".to_string());
                ((*target).to_string(), status)
            })
            .collect::<BTreeMap<_, _>>();

            CatalogRuleEntry {
                rule_id: catalog_indicator_id(&stable_token),
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
                target_statuses,
                emulation_statuses,
                activity_count: items.len(),
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    Ok(entries)
}

fn collapse_target_status(activities: &[&TranslationActivity]) -> String {
    if activities
        .iter()
        .any(|item| item.status.eq_ignore_ascii_case("exact"))
    {
        return "exact".to_string();
    }

    if activities.iter().any(|item| {
        let status = item.status.to_ascii_lowercase();
        status.contains("lossy")
            || status.contains("partial")
            || status.contains("dependent")
            || status.contains("schema")
            || status.contains("backend")
    }) {
        return "lossy".to_string();
    }

    if activities
        .iter()
        .any(|item| item.status.eq_ignore_ascii_case("unsupported"))
    {
        return "unsupported".to_string();
    }

    activities
        .iter()
        .max_by(|a, b| a.timestamp_utc.cmp(&b.timestamp_utc))
        .map(|item| item.status.to_ascii_lowercase())
        .unwrap_or_else(|| "unsupported".to_string())
}

pub(crate) fn filter_rule_entries(
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

pub(crate) fn print_rule_search_results(
    entries: &[CatalogRuleEntry],
    total_entries: usize,
    title: &str,
) {
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

pub(crate) fn filter_adversary_entries(
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

pub(crate) fn print_adversary_search_results(
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

pub(crate) fn resolve_rule_selector(
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

pub(crate) fn resolve_adversary_selector(
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

pub(crate) fn show_rule_entry(rule: &CatalogRuleEntry) {
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

pub(crate) fn show_adversary_entry(adversary: &CatalogAdversaryEntry) {
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

pub(crate) fn export_rule_entry(
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

pub(crate) fn edit_rule_entry(
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

pub(crate) fn edit_adversary_entry(
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

pub(crate) fn export_adversary_entry(
    adversary: &CatalogAdversaryEntry,
    executor: AbilityTarget,
    output: Option<&Path>,
    show: &[BuildOutput],
) -> Result<()> {
    export_saved_adversary(&adversary.path, executor, output, show)
}

pub(crate) fn delete_rule_entry(
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

pub(crate) fn delete_adversary_entry(
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

fn catalog_indicator_id(stable_token: &str) -> String {
    let mut left = DefaultHasher::new();
    "indicator".hash(&mut left);
    stable_token.hash(&mut left);
    let left = left.finish();

    let mut right = DefaultHasher::new();
    stable_token.hash(&mut right);
    "spuc-catalog-rule".hash(&mut right);
    let right = right.finish();

    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&left.to_be_bytes());
    bytes[8..].copy_from_slice(&right.to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "indicator--{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

fn catalog_adversary_id(intrusion_set_id: &str) -> String {
    emu_campaign::catalog_adversary_id(intrusion_set_id)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn activity(status: &str, ts: &str) -> TranslationActivity {
        TranslationActivity {
            activity_id: "act-1".to_string(),
            timestamp_utc: ts.to_string(),
            command: "translate".to_string(),
            rule: "[process:name = 'cmd.exe']".to_string(),
            rule_hash: "hash".to_string(),
            engine_version: "test".to_string(),
            target: "kql".to_string(),
            status: status.to_string(),
            impact: 70,
            hidden: false,
            output_path: None,
        }
    }

    #[test]
    fn collapse_target_status_prioritizes_exact() {
        let rows = [
            activity("unsupported", "2026-01-01T00:00:00Z"),
            activity("exact", "2026-01-01T00:00:01Z"),
        ];
        let refs = rows.iter().collect::<Vec<_>>();
        assert_eq!(collapse_target_status(&refs), "exact");
    }

    #[test]
    fn collapse_target_status_marks_lossy_bucket() {
        let rows = [
            activity("schema-dependent", "2026-01-01T00:00:00Z"),
            activity("backend-dependent", "2026-01-01T00:00:01Z"),
        ];
        let refs = rows.iter().collect::<Vec<_>>();
        assert_eq!(collapse_target_status(&refs), "lossy");
    }

    #[test]
    fn catalog_rule_ids_are_stix_indicator_ids() {
        let id = catalog_indicator_id("stable-rule-token");
        assert!(id.starts_with("indicator--"));
        assert_eq!(
            id.len(),
            "indicator--00000000-0000-4000-8000-000000000000".len()
        );
        let uuid = id.strip_prefix("indicator--").expect("indicator id prefix");
        let parts = uuid.split('-').collect::<Vec<_>>();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
        assert_eq!(parts[2].as_bytes()[0], b'4');
        assert!(matches!(parts[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b'));
    }
}

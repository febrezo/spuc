#![allow(dead_code)]

pub mod activities;
pub mod rules;

use anyhow::{anyhow, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::catalog::activities::{ActivityLog, TranslationActivity};
use crate::commands::common::known_detection_target_labels;
use crate::paths;
use crate::ui::ansi::{BOLD, RESET, YELLOW};
use crate::ui::print::entry_label;

type LoadedCatalogData = Vec<CatalogRuleEntry>;

#[derive(Debug, Clone)]
pub(crate) struct CatalogRuleEntry {
    pub(crate) rule_id: String,
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) ttp: Option<String>,
    pub(crate) confidence: u8,
    pub(crate) rule: String,
    pub(crate) last_seen_utc: String,
    pub(crate) commands: Vec<String>,
    pub(crate) targets: Vec<String>,
    pub(crate) statuses: Vec<String>,
    pub(crate) target_statuses: BTreeMap<String, String>,
    pub(crate) activity_count: usize,
}

pub(crate) fn load_catalog_data() -> Result<LoadedCatalogData> {
    let config_root =
        paths::spuc_config_root().ok_or_else(|| anyhow!("cannot resolve config root"))?;
    rules::ensure_rules_seeded(&config_root)?;
    build_catalog_rule_entries()
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
    print_table(&["#", "RULE_ID", "NAME", "CONFIDENCE", "RULE"], &rows);
}

fn row_matches_query(row: &[String], query: Option<&str>) -> bool {
    let Some(query) = query else {
        return true;
    };
    let needle = query.to_ascii_lowercase();
    row.iter()
        .any(|value| value.to_ascii_lowercase().contains(&needle))
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
    const BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut left = BASIS;
    for byte in b"indicator".iter().chain(stable_token.as_bytes().iter()) {
        left ^= u64::from(*byte);
        left = left.wrapping_mul(PRIME);
    }
    let mut right = BASIS;
    for byte in stable_token
        .as_bytes()
        .iter()
        .chain(b"spuc-catalog-rule".iter())
    {
        right ^= u64::from(*byte);
        right = right.wrapping_mul(PRIME);
    }

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

pub(crate) fn build_catalog_rule_entries() -> Result<Vec<CatalogRuleEntry>> {
    let config_root =
        paths::spuc_config_root().ok_or_else(|| anyhow!("cannot resolve config root"))?;
    rules::ensure_rules_seeded(&config_root)?;
    let persisted = rules::load_persisted_rules(&config_root)?;
    let activity_log = ActivityLog::from_default_root()?;
    let activities_all = activity_log.list_translation_activities(None, None)?;

    // Statuses derive from visible translate rows only: hidden legacy cache
    // rows (old dual-flow emulate/translate rows) are intentionally excluded.
    let mut grouped: BTreeMap<String, Vec<&TranslationActivity>> = BTreeMap::new();
    for activity in activities_all
        .iter()
        .filter(|item| item.command == "translate" && !item.hidden)
    {
        grouped
            .entry(activity.rule.clone())
            .or_default()
            .push(activity);
    }

    let mut entries = Vec::new();
    let mut persisted_patterns = std::collections::BTreeSet::new();
    for rule in &persisted {
        persisted_patterns.insert(rule.source_pattern.trim().to_string());
        // Re-encode the persisted metadata so every downstream view keeps
        // decoding tlp/pap/ttp/observables/indicates from the description.
        let description = rules::encode_rule_metadata_description(
            rule.description.as_deref(),
            Some(&rule.tlp),
            Some(&rule.pap),
            rule.ttp.as_deref(),
            rule.target_platform.as_deref(),
            Some(&rule.observables),
            Some(&rule.indicates_list),
        );
        let items = grouped
            .get(rule.source_pattern.trim())
            .cloned()
            .unwrap_or_default();

        let mut commands = BTreeSet::new();
        let mut targets = BTreeSet::new();
        let mut statuses = BTreeSet::new();
        let mut activities_by_target: HashMap<String, Vec<&TranslationActivity>> = HashMap::new();
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

        entries.push(CatalogRuleEntry {
            rule_id: rule.indicator_id.clone(),
            name: rule.name.clone(),
            description,
            ttp: rule.ttp.clone(),
            confidence: rule.rule_confidence.unwrap_or(70),
            rule: rule.source_pattern.clone(),
            last_seen_utc,
            commands: commands.into_iter().collect(),
            targets: targets.into_iter().collect(),
            statuses: statuses.into_iter().collect(),
            target_statuses,
            activity_count: items.len(),
        });
    }

    for (rule, items) in grouped {
        if persisted_patterns.contains(rule.trim()) {
            continue;
        }
        let stable_token = items
            .iter()
            .find_map(|item| (!item.rule_hash.trim().is_empty()).then(|| item.rule_hash.clone()))
            .unwrap_or_else(|| stable_catalog_token(&rule));
        let mut commands = BTreeSet::new();
        let mut targets = BTreeSet::new();
        let mut statuses = BTreeSet::new();
        let mut activities_by_target: HashMap<String, Vec<&TranslationActivity>> = HashMap::new();
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

        entries.push(CatalogRuleEntry {
            rule_id: catalog_indicator_id(&stable_token),
            name: format!("Rule {}", short_catalog_token(&stable_token)),
            description: None,
            ttp: None,
            confidence: items.iter().map(|item| item.impact).max().unwrap_or(0),
            rule,
            last_seen_utc,
            commands: commands.into_iter().collect(),
            targets: targets.into_iter().collect(),
            statuses: statuses.into_iter().collect(),
            target_statuses,
            activity_count: items.len(),
        });
    }

    entries.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    Ok(entries)
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
        .find(|entry| entry.rule_id == selector || entry.rule == selector)
        .cloned()
        .ok_or_else(|| anyhow!("rule '{}' not found", selector))
}

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

    #[test]
    fn rule_rows_merge_persisted_and_activity_derived_patterns() {
        crate::web::test_support::with_test_config_dir("catalog_rows_merge", || {
            let root = crate::paths::spuc_config_root().expect("config root");
            let pattern_a = "[process:name = 'cmd.exe']";
            let pattern_b = "[file:name = 'evil.exe']";

            let persisted = rules::PersistedRule {
                indicator_id: rules::mint_rule_indicator_id(pattern_a),
                source_pattern: pattern_a.to_string(),
                name: "Persisted rule".to_string(),
                description: Some("Persisted description".to_string()),
                tlp: "TLP:AMBER".to_string(),
                pap: "PAP:GREEN".to_string(),
                ttp: Some("T1111".to_string()),
                target_platform: Some("windows".to_string()),
                observables: vec!["process".to_string()],
                indicates: None,
                indicates_list: Vec::new(),
                rule_confidence: Some(80),
            };
            rules::save_persisted_rules(&root, &[persisted]).expect("persist");

            // Activities: hidden legacy rows for A (must be ignored), visible
            // translate rows for B (must drive a derived row).
            let catalog_dir = root.join("catalog");
            std::fs::create_dir_all(&catalog_dir).expect("catalog dir");
            let mut lines = Vec::new();
            let hidden_legacy = serde_json::json!({
                "activity_id": "act-h1",
                "timestamp_utc": "2024-01-01T00:00:00+00:00",
                "command": "emulate",
                "rule": pattern_a,
                "rule_hash": "hash-a",
                "engine_version": "legacy",
                "target": "bash",
                "status": "exact",
                "impact": 70,
                "hidden": true,
                "output_path": null
            });
            lines.push(hidden_legacy.to_string());
            let visible_b = serde_json::json!({
                "activity_id": "act-v1",
                "timestamp_utc": "2024-02-01T00:00:00+00:00",
                "command": "translate",
                "rule": pattern_b,
                "rule_hash": "hash-b",
                "engine_version": "legacy",
                "target": "sigma",
                "status": "exact",
                "impact": 95,
                "hidden": false,
                "output_path": null
            });
            lines.push(visible_b.to_string());
            std::fs::write(
                catalog_dir.join("translation_activities.jsonl"),
                lines.join("\n") + "\n",
            )
            .expect("write activities");

            let entries = build_catalog_rule_entries().expect("rows");
            assert_eq!(entries.len(), 2);

            let row_a = entries
                .iter()
                .find(|entry| entry.rule.trim() == pattern_a)
                .expect("persisted row");
            assert_eq!(row_a.rule_id, rules::mint_rule_indicator_id(pattern_a));
            assert_eq!(row_a.name, "Persisted rule");
            let description = row_a.description.clone().expect("row description");
            let decoded = rules::decode_rule_metadata_description(Some(description));
            assert_eq!(
                decoded.description.as_deref(),
                Some("Persisted description")
            );
            assert_eq!(decoded.tlp, "TLP:AMBER");
            assert_eq!(decoded.observables, vec!["process".to_string()]);
            // Hidden legacy rows must not drive visible statuses.
            assert!(row_a.commands.is_empty());
            assert!(row_a.statuses.is_empty());
            assert_eq!(row_a.activity_count, 0);
            assert!(row_a.target_statuses.values().all(|v| v == "unsupported"));

            let row_b = entries
                .iter()
                .find(|entry| entry.rule.trim() == pattern_b)
                .expect("activity-derived row");
            assert!(row_b.rule_id.starts_with("indicator--"));
            assert!(row_b.name.starts_with("Rule "));
            assert!(row_b.description.is_none());
            assert!(row_b.statuses.contains(&"exact".to_string()));
            assert!(row_b.targets.contains(&"sigma".to_string()));
            assert_eq!(row_b.activity_count, 1);
        });
    }
}

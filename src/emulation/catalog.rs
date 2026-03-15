use anyhow::{Result, anyhow};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::emulation::ability::Ability;
use crate::paths;

#[derive(Debug, Clone)]
pub struct AbilityCatalog {
    root: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TranslationActivity {
    pub activity_id: String,
    pub timestamp_utc: String,
    pub command: String,
    pub rule: String,
    #[serde(default)]
    pub rule_hash: String,
    #[serde(default)]
    pub engine_version: String,
    pub target: String,
    pub status: String,
    pub impact: u8,
    #[serde(default)]
    pub hidden: bool,
    pub output_path: Option<String>,
}

impl TranslationActivity {
    pub fn new(
        command: &str,
        rule: &str,
        target: &str,
        status: &str,
        impact: u8,
        output_path: Option<String>,
    ) -> Self {
        Self {
            activity_id: format!("act-{}", Utc::now().timestamp_micros()),
            timestamp_utc: Utc::now().to_rfc3339(),
            command: command.to_string(),
            rule: rule.to_string(),
            rule_hash: String::new(),
            engine_version: String::new(),
            target: target.to_string(),
            status: status.to_string(),
            impact,
            hidden: false,
            output_path,
        }
    }

    pub fn with_cache_meta(mut self, rule_hash: &str, engine_version: &str, hidden: bool) -> Self {
        self.rule_hash = rule_hash.to_string();
        self.engine_version = engine_version.to_string();
        self.hidden = hidden;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleActivitySummary {
    pub rule: String,
    pub hits: usize,
    pub last_seen_utc: String,
    pub last_command: String,
    pub last_status: String,
    pub last_impact: u8,
}

impl AbilityCatalog {
    pub fn from_default_root() -> Result<Self> {
        let root = paths::abilities_dir().ok_or_else(|| anyhow!("cannot resolve config root"))?;
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn from_root(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn save(&self, ability: &Ability) -> Result<PathBuf> {
        let path = self.root.join(format!("{}.json", ability.id));
        let raw = serde_json::to_string_pretty(ability)?;
        fs::write(&path, raw)?;
        Ok(path)
    }

    pub fn find_by_source_pattern(&self, source_pattern: &str) -> Result<Option<Ability>> {
        let normalized = source_pattern.trim();
        let found = self.list()?.into_iter().find(|item| {
            item.source_pattern == source_pattern || item.source_pattern.trim() == normalized
        });
        Ok(found)
    }

    pub fn upsert_by_source_pattern(&self, ability: &Ability) -> Result<(PathBuf, bool)> {
        if let Some(existing) = self.find_by_source_pattern(&ability.source_pattern)? {
            let mut updated = ability.clone();
            updated.id = existing.id;
            let path = self.save(&updated)?;
            return Ok((path, false));
        }
        let path = self.save(ability)?;
        Ok((path, true))
    }

    pub fn delete_by_id(&self, ability_id: &str) -> Result<bool> {
        let path = self.root.join(format!("{ability_id}.json"));
        if !path.exists() {
            return Ok(false);
        }
        fs::remove_file(path)?;
        Ok(true)
    }

    pub fn list(&self) -> Result<Vec<Ability>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let raw = fs::read_to_string(&path)?;
            let ability: Ability = serde_json::from_str(&raw)?;
            out.push(ability);
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    pub fn get_by_id(&self, ability_id: &str) -> Result<Option<Ability>> {
        let path = self.root.join(format!("{ability_id}.json"));
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(path)?;
        let ability: Ability = serde_json::from_str(&raw)?;
        Ok(Some(ability))
    }

    pub fn search_and_filter(
        &self,
        query: Option<&str>,
        platform: Option<&str>,
    ) -> Result<Vec<Ability>> {
        let mut items = self.list()?;
        if let Some(q) = query {
            let ql = q.to_ascii_lowercase();
            items.retain(|a| {
                let hay = format!("{} {} {} {}", a.id, a.name, a.description, a.source_pattern)
                    .to_ascii_lowercase();
                hay.contains(&ql)
            });
        }
        if let Some(p) = platform {
            let pl = p.to_ascii_lowercase();
            items.retain(|a| {
                a.supported_platforms
                    .iter()
                    .any(|sp| sp.eq_ignore_ascii_case("any") || sp.to_ascii_lowercase() == pl)
            });
        }
        Ok(items)
    }

    pub fn select_by_ids(&self, ids: &[String]) -> Result<Vec<Ability>> {
        let mut selected = Vec::new();
        for id in ids {
            if let Some(ability) = self.get_by_id(id)? {
                selected.push(ability);
            } else {
                return Err(anyhow!("ability '{id}' not found in catalog"));
            }
        }
        Ok(selected)
    }

    pub fn record_translation_activity(&self, activity: &TranslationActivity) -> Result<()> {
        let path = self.activities_path()?;
        let mut file = OpenOptions::new().append(true).create(true).open(path)?;
        let mut row = serde_json::to_vec(activity)?;
        row.push(b'\n');
        file.write_all(&row)?;
        Ok(())
    }

    pub fn list_translation_activities(
        &self,
        search: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<TranslationActivity>> {
        let path = self.activities_path()?;
        if !path.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let needle = search.map(|v| v.to_ascii_lowercase());
        for line in fs::read_to_string(path)?.lines().map(str::trim) {
            if line.is_empty() {
                continue;
            }
            let Ok(parsed) = serde_json::from_str::<TranslationActivity>(line) else {
                continue;
            };
            if let Some(query) = &needle {
                let hay = format!(
                    "{} {} {} {} {}",
                    parsed.rule, parsed.target, parsed.status, parsed.command, parsed.timestamp_utc
                )
                .to_ascii_lowercase();
                if !hay.contains(query) {
                    continue;
                }
            }
            out.push(parsed);
        }
        out.sort_by(|a, b| {
            b.timestamp_utc
                .cmp(&a.timestamp_utc)
                .then_with(|| b.activity_id.cmp(&a.activity_id))
        });
        if let Some(max) = limit {
            out.truncate(max);
        }
        Ok(out)
    }

    pub fn has_cached_activity(
        &self,
        command: &str,
        rule_hash: &str,
        engine_version: &str,
        target: &str,
        hidden: bool,
    ) -> Result<bool> {
        let path = self.activities_path()?;
        if !path.exists() {
            return Ok(false);
        }
        for line in fs::read_to_string(path)?.lines().map(str::trim) {
            if line.is_empty() {
                continue;
            }
            let Ok(parsed) = serde_json::from_str::<TranslationActivity>(line) else {
                continue;
            };
            if parsed.command == command
                && parsed.rule_hash == rule_hash
                && parsed.engine_version == engine_version
                && parsed.target == target
                && parsed.hidden == hidden
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn delete_activities_by_rule(&self, rule: &str) -> Result<usize> {
        let path = self.activities_path()?;
        if !path.exists() {
            return Ok(0);
        }
        let mut kept = Vec::new();
        let mut removed = 0usize;
        for line in fs::read_to_string(&path)?.lines().map(str::trim) {
            if line.is_empty() {
                continue;
            }
            let Ok(parsed) = serde_json::from_str::<TranslationActivity>(line) else {
                continue;
            };
            if parsed.rule == rule {
                removed += 1;
            } else {
                kept.push(line.to_string());
            }
        }
        let mut rewritten = kept.join("\n");
        if !rewritten.is_empty() {
            rewritten.push('\n');
        }
        fs::write(path, rewritten)?;
        Ok(removed)
    }

    pub fn list_rule_activity_summary(
        &self,
        search: Option<&str>,
    ) -> Result<Vec<RuleActivitySummary>> {
        let activities = self.list_translation_activities(search, None)?;
        let mut by_rule: std::collections::BTreeMap<String, RuleActivitySummary> =
            std::collections::BTreeMap::new();
        for item in activities {
            if let Some(summary) = by_rule.get_mut(&item.rule) {
                summary.hits += 1;
            } else {
                by_rule.insert(
                    item.rule.clone(),
                    RuleActivitySummary {
                        rule: item.rule.clone(),
                        hits: 1,
                        last_seen_utc: item.timestamp_utc.clone(),
                        last_command: item.command.clone(),
                        last_status: item.status.clone(),
                        last_impact: item.impact,
                    },
                );
            }
        }
        let mut out: Vec<_> = by_rule.into_values().collect();
        out.sort_by(|a, b| {
            b.last_seen_utc
                .cmp(&a.last_seen_utc)
                .then_with(|| a.rule.cmp(&b.rule))
        });
        Ok(out)
    }

    fn activities_path(&self) -> Result<PathBuf> {
        let config_root = if self.root.file_name().and_then(|s| s.to_str()) == Some("abilities") {
            self.root
                .parent()
                .ok_or_else(|| anyhow!("invalid catalog root path"))?
                .to_path_buf()
        } else {
            self.root.clone()
        };
        let catalog_dir = config_root.join("catalog");
        fs::create_dir_all(&catalog_dir)?;
        Ok(catalog_dir.join("translation_activities.jsonl"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulation::ability::{
        ABILITY_SCHEMA_VERSION, Ability, AbilityAction, AbilityClassification, AbilityRequirement,
        EmulationLevel,
    };

    fn sample_ability(id: &str, platform: &str, name: &str) -> Ability {
        Ability {
            schema_version: ABILITY_SCHEMA_VERSION.to_string(),
            id: id.to_string(),
            name: name.to_string(),
            description: "sample".to_string(),
            ttp: None,
            supported_platforms: vec![platform.to_string()],
            requires: vec![AbilityRequirement {
                id: "cap.process.spawn".to_string(),
                description: "spawn".to_string(),
            }],
            optional: vec![],
            agent_capabilities: vec!["cap.telemetry.process".to_string()],
            actions: vec![AbilityAction {
                id: "act-001".to_string(),
                title: "title".to_string(),
                action_type: "emit_process_command_line".to_string(),
                observable: "process:command_line".to_string(),
                operator: "MATCHES".to_string(),
                value: "^.*$".to_string(),
                safe_instructions: "safe".to_string(),
            }],
            source_pattern: "[process:command_line MATCHES '^.*$']".to_string(),
            classification: AbilityClassification::CommandLineTrace,
            emulation_level: EmulationLevel::TraceSimulation,
            confidence: 70,
        }
    }

    #[test]
    fn save_and_list_catalog() {
        let root = std::env::temp_dir().join(format!(
            "spuc_catalog_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let catalog = AbilityCatalog::from_root(root).expect("catalog");
        catalog
            .save(&sample_ability("abl-1", "linux", "echo test"))
            .expect("save");
        let items = catalog.list().expect("list");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "abl-1");
    }

    #[test]
    fn search_and_filter_catalog() {
        let root = std::env::temp_dir().join(format!(
            "spuc_catalog_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let catalog = AbilityCatalog::from_root(root).expect("catalog");
        catalog
            .save(&sample_ability("abl-1", "linux", "echo test"))
            .expect("save");
        catalog
            .save(&sample_ability("abl-2", "windows", "powershell test"))
            .expect("save");
        let q = catalog
            .search_and_filter(Some("powershell"), None)
            .expect("search");
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].id, "abl-2");
        let f = catalog
            .search_and_filter(None, Some("linux"))
            .expect("filter");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "abl-1");
    }

    #[test]
    fn get_by_id_and_select_by_ids() {
        let root = std::env::temp_dir().join(format!(
            "spuc_catalog_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let catalog = AbilityCatalog::from_root(root).expect("catalog");
        catalog
            .save(&sample_ability("abl-1", "linux", "echo test"))
            .expect("save");
        catalog
            .save(&sample_ability("abl-2", "windows", "powershell test"))
            .expect("save");

        let one = catalog.get_by_id("abl-2").expect("get").expect("exists");
        assert_eq!(one.name, "powershell test");

        let selected = catalog
            .select_by_ids(&["abl-2".to_string(), "abl-1".to_string()])
            .expect("select");
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].id, "abl-2");
        assert_eq!(selected[1].id, "abl-1");
    }

    #[test]
    fn delete_by_id_removes_entry() {
        let root = std::env::temp_dir().join(format!(
            "spuc_catalog_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let catalog = AbilityCatalog::from_root(root).expect("catalog");
        catalog
            .save(&sample_ability("abl-1", "linux", "echo test"))
            .expect("save");

        let removed = catalog.delete_by_id("abl-1").expect("delete");
        assert!(removed);
        assert!(catalog.get_by_id("abl-1").expect("get").is_none());
    }

    #[test]
    fn activity_log_records_and_lists_in_desc_order() {
        let root = std::env::temp_dir().join(format!(
            "spuc_catalog_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let catalog = AbilityCatalog::from_root(root).expect("catalog");
        catalog
            .record_translation_activity(&TranslationActivity::new(
                "translate",
                "[process:name = 'cmd.exe']",
                "sigma",
                "exact",
                95,
                None,
            ))
            .expect("record");
        catalog
            .record_translation_activity(&TranslationActivity::new(
                "emulate",
                "[process:command_line MATCHES '^.*echo.*$']",
                "bash",
                "exact",
                70,
                None,
            ))
            .expect("record");

        let all = catalog
            .list_translation_activities(None, Some(10))
            .expect("list");
        assert_eq!(all.len(), 2);
        assert!(all[0].timestamp_utc >= all[1].timestamp_utc);
    }

    #[test]
    fn activity_rule_summary_groups_by_rule() {
        let root = std::env::temp_dir().join(format!(
            "spuc_catalog_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let catalog = AbilityCatalog::from_root(root).expect("catalog");
        let rule = "[process:command_line MATCHES '^.*echo.*$']";
        catalog
            .record_translation_activity(&TranslationActivity::new(
                "emulate",
                rule,
                "spuc-agent",
                "exact",
                70,
                None,
            ))
            .expect("record");
        catalog
            .record_translation_activity(&TranslationActivity::new(
                "emulate", rule, "bash", "exact", 70, None,
            ))
            .expect("record");

        let rules = catalog.list_rule_activity_summary(None).expect("rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule, rule);
        assert_eq!(rules[0].hits, 2);
    }

    #[test]
    fn upsert_by_source_pattern_reuses_existing_id() {
        let root = std::env::temp_dir().join(format!(
            "spuc_catalog_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let catalog = AbilityCatalog::from_root(root).expect("catalog");

        let mut first = sample_ability("abl-1", "linux", "first");
        first.source_pattern = "[process:command_line MATCHES '^.*echo.*$']".to_string();
        let (_path, created) = catalog
            .upsert_by_source_pattern(&first)
            .expect("first upsert");
        assert!(created);

        let mut second = sample_ability("abl-2", "windows", "second");
        second.source_pattern = first.source_pattern.clone();
        let (_path, created) = catalog
            .upsert_by_source_pattern(&second)
            .expect("second upsert");
        assert!(!created);

        let items = catalog.list().expect("list");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "abl-1");
        assert_eq!(items[0].name, "second");
    }

    #[test]
    fn activity_log_survives_concurrent_appends() {
        use std::sync::Arc;
        use std::thread;

        let root = std::env::temp_dir().join(format!(
            "spuc_catalog_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let catalog = Arc::new(AbilityCatalog::from_root(root).expect("catalog"));

        let mut handles = Vec::new();
        for worker in 0..8usize {
            let catalog = Arc::clone(&catalog);
            handles.push(thread::spawn(move || {
                for item in 0..25usize {
                    let rule = format!(
                        "[process:command_line MATCHES ^worker-{worker}-item-{item}-echo.*]"
                    );
                    let activity =
                        TranslationActivity::new("translate", &rule, "sigma", "exact", 95, None);
                    catalog
                        .record_translation_activity(&activity)
                        .expect("record");
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread join");
        }

        let activities = catalog
            .list_translation_activities(None, None)
            .expect("list activities");
        assert_eq!(activities.len(), 8 * 25);
    }
    #[test]
    fn has_cached_activity_matches_cache_meta() {
        let root = std::env::temp_dir().join(format!(
            "spuc_catalog_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let catalog = AbilityCatalog::from_root(root).expect("catalog");
        catalog
            .record_translation_activity(
                &TranslationActivity::new(
                    "translate",
                    "[process:name = 'cmd.exe']",
                    "sigma",
                    "exact",
                    95,
                    None,
                )
                .with_cache_meta("abc123", "spuc-test", true),
            )
            .expect("record");

        assert!(
            catalog
                .has_cached_activity("translate", "abc123", "spuc-test", "sigma", true)
                .expect("cache")
        );
        assert!(
            !catalog
                .has_cached_activity("translate", "abc123", "spuc-test", "sigma", false)
                .expect("cache")
        );
    }
}

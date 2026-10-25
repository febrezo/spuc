//! Translation activity log (moved out of the emulation namespace).
//!
//! Owns `<config_root>/catalog/translation_activities.jsonl`. Row format and
//! serde semantics are byte-compatible with the log this module replaces:
//! unknown/missing optional fields are tolerated when reading.

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use crate::paths;

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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub rule: String,
    pub hits: usize,
    pub last_seen_utc: String,
    pub last_command: String,
    pub last_status: String,
    pub last_impact: u8,
}

#[derive(Debug, Clone)]
pub struct ActivityLog {
    config_root: PathBuf,
}

impl ActivityLog {
    pub fn from_default_root() -> Result<Self> {
        let config_root =
            paths::spuc_config_root().ok_or_else(|| anyhow!("cannot resolve config root"))?;
        Self::from_root(config_root)
    }

    pub fn from_root(config_root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&config_root)?;
        Ok(Self { config_root })
    }

    pub fn path(&self) -> Result<PathBuf> {
        let catalog_dir = self.config_root.join("catalog");
        fs::create_dir_all(&catalog_dir)?;
        Ok(catalog_dir.join("translation_activities.jsonl"))
    }

    pub fn record_translation_activity(&self, activity: &TranslationActivity) -> Result<()> {
        let path = self.path()?;
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
        let path = self.path()?;
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

    pub fn delete_activities_by_rule(&self, rule: &str) -> Result<usize> {
        let path = self.path()?;
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

    /// Deletes ONLY visible translate rows for a rule. Hidden legacy rows
    /// (old emulate/translate cache rows) stay on disk untouched.
    pub fn delete_translate_activities_by_rule(&self, rule: &str) -> Result<usize> {
        let path = self.path()?;
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
            if parsed.rule == rule && parsed.command == "translate" && !parsed.hidden {
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

    pub fn has_cached_activity(
        &self,
        command: &str,
        rule_hash: &str,
        engine_version: &str,
        target: &str,
        hidden: bool,
    ) -> Result<bool> {
        let path = self.path()?;
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "spuc_activities_test_{}_{}_{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    #[test]
    fn activity_log_path_is_config_root_catalog_file() {
        let root = test_root("path");
        let log = ActivityLog::from_root(root.clone()).expect("log");
        assert_eq!(
            log.path().expect("path"),
            root.join("catalog/translation_activities.jsonl")
        );
    }

    #[test]
    fn activity_log_records_and_lists_in_desc_order() {
        let log = ActivityLog::from_root(test_root("order")).expect("log");
        log.record_translation_activity(&TranslationActivity::new(
            "translate",
            "[process:name = 'cmd.exe']",
            "sigma",
            "exact",
            95,
            None,
        ))
        .expect("record");
        log.record_translation_activity(&TranslationActivity::new(
            "emulate",
            "[process:command_line MATCHES '^.*echo.*$']",
            "bash",
            "exact",
            70,
            None,
        ))
        .expect("record");

        let all = log
            .list_translation_activities(None, Some(10))
            .expect("list");
        assert_eq!(all.len(), 2);
        assert!(all[0].timestamp_utc >= all[1].timestamp_utc);
    }

    #[test]
    fn activity_rule_summary_groups_by_rule() {
        let log = ActivityLog::from_root(test_root("summary")).expect("log");
        let rule = "[process:command_line MATCHES '^.*echo.*$']";
        log.record_translation_activity(&TranslationActivity::new(
            "emulate",
            rule,
            "spuc-agent",
            "exact",
            70,
            None,
        ))
        .expect("record");
        log.record_translation_activity(&TranslationActivity::new(
            "emulate", rule, "bash", "exact", 70, None,
        ))
        .expect("record");

        let rules = log.list_rule_activity_summary(None).expect("rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule, rule);
        assert_eq!(rules[0].hits, 2);
    }

    #[test]
    fn has_cached_activity_matches_cache_meta() {
        let log = ActivityLog::from_root(test_root("cache")).expect("log");
        log.record_translation_activity(
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

        assert!(log
            .has_cached_activity("translate", "abc123", "spuc-test", "sigma", true)
            .expect("cache"));
        assert!(!log
            .has_cached_activity("translate", "abc123", "spuc-test", "sigma", false)
            .expect("cache"));
    }

    #[test]
    fn activity_log_survives_concurrent_appends() {
        use std::sync::Arc;
        use std::thread;

        let log = Arc::new(ActivityLog::from_root(test_root("concurrent")).expect("log"));

        let mut handles = Vec::new();
        for worker in 0..8usize {
            let log = Arc::clone(&log);
            handles.push(thread::spawn(move || {
                for item in 0..25usize {
                    let rule = format!(
                        "[process:command_line MATCHES ^worker-{worker}-item-{item}-echo.*]"
                    );
                    let activity =
                        TranslationActivity::new("translate", &rule, "sigma", "exact", 95, None);
                    log.record_translation_activity(&activity).expect("record");
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread join");
        }

        let activities = log.list_translation_activities(None, None).expect("list");
        assert_eq!(activities.len(), 8 * 25);
    }

    #[test]
    fn delete_visible_translate_rows_purges_only_visible_translate() {
        let log = ActivityLog::from_root(test_root("purge")).expect("log");
        let rule = "[process:name = 'cmd.exe']";
        for (command, hidden) in [
            ("translate", false),
            ("translate", true),
            ("emulate", false),
            ("emulate", true),
        ] {
            let activity = TranslationActivity::new(command, rule, "sigma", "exact", 95, None)
                .with_cache_meta("h", "v", hidden);
            log.record_translation_activity(&activity).expect("record");
        }

        let removed = log
            .delete_translate_activities_by_rule(rule)
            .expect("delete visible");
        assert_eq!(removed, 1);

        let survivors = log
            .list_translation_activities(Some(rule), None)
            .expect("list");
        assert_eq!(survivors.len(), 3);
        // Visible translate rows are gone; legacy hidden rows and visible
        // emulate rows stay on disk untouched.
        assert!(!survivors
            .iter()
            .any(|item| item.command == "translate" && !item.hidden));
        assert!(survivors
            .iter()
            .any(|item| item.command == "translate" && item.hidden));
        assert!(survivors
            .iter()
            .any(|item| item.command == "emulate" && !item.hidden));
        assert!(survivors
            .iter()
            .any(|item| item.command == "emulate" && item.hidden));
    }
}

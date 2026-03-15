use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::emulation::ability::Ability;
use crate::paths;

pub const CAMPAIGN_SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CampaignStep {
    pub id: String,
    pub ability_ref: String,
    pub platform: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Campaign {
    pub schema_version: String,
    #[serde(alias = "campaign_id")]
    pub intrusion_set_id: String,
    pub name: String,
    pub description: String,
    pub confidence: u8,
    pub steps: Vec<CampaignStep>,
}

impl Campaign {
    pub fn validate_structure(&self) -> std::result::Result<(), Vec<String>> {
        let mut issues = Vec::new();
        if self.schema_version != CAMPAIGN_SCHEMA_VERSION {
            issues.push(format!(
                "schema_version '{}' is not supported (expected {})",
                self.schema_version, CAMPAIGN_SCHEMA_VERSION
            ));
        }
        if self.intrusion_set_id.trim().is_empty() {
            issues.push("intrusion_set_id must not be empty".to_string());
        }
        if self.name.trim().is_empty() {
            issues.push("name must not be empty".to_string());
        }
        if self.steps.is_empty() {
            issues.push("steps must contain at least one step".to_string());
        }
        if self.confidence > 100 {
            issues.push("confidence must be <= 100".to_string());
        }
        for step in &self.steps {
            if step.id.trim().is_empty() {
                issues.push("step id must not be empty".to_string());
            }
            if step.ability_ref.trim().is_empty() {
                issues.push("step ability_ref must not be empty".to_string());
            }
            if step.platform.trim().is_empty() {
                issues.push("step platform must not be empty".to_string());
            }
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }
}

pub fn build_campaign(
    intrusion_set_id: String,
    name: String,
    description: String,
    abilities: &[Ability],
) -> Campaign {
    build_campaign_ordered(intrusion_set_id, name, description, abilities, &[])
}

pub fn build_campaign_ordered(
    intrusion_set_id: String,
    name: String,
    description: String,
    abilities: &[Ability],
    ordered_ids: &[String],
) -> Campaign {
    build_campaign_ordered_with_confidence(
        intrusion_set_id,
        name,
        description,
        abilities,
        ordered_ids,
        70,
    )
}

pub fn build_campaign_ordered_with_confidence(
    intrusion_set_id: String,
    name: String,
    description: String,
    abilities: &[Ability],
    ordered_ids: &[String],
    confidence: u8,
) -> Campaign {
    let ordered = order_abilities(abilities, ordered_ids);
    let mut steps = Vec::new();
    for (idx, ability) in ordered.iter().enumerate() {
        let step_id = format!("step-{:03}", idx + 1);
        let after = if idx == 0 {
            None
        } else {
            Some(format!("step-{:03}", idx))
        };
        let platform = ability
            .supported_platforms
            .first()
            .cloned()
            .unwrap_or_else(|| "any".to_string());
        steps.push(CampaignStep {
            id: step_id,
            ability_ref: ability.id.clone(),
            platform,
            after,
            delay_seconds: None,
            timeout_seconds: None,
        });
    }
    Campaign {
        schema_version: CAMPAIGN_SCHEMA_VERSION.to_string(),
        intrusion_set_id,
        name,
        description,
        confidence,
        steps,
    }
}

pub fn save_campaign_yaml(campaign: &Campaign, out: Option<&PathBuf>) -> Result<PathBuf> {
    let path = resolve_campaign_path(campaign, out)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("yaml")
        .to_ascii_lowercase();
    if ext == "json" {
        fs::write(&path, serde_json::to_string_pretty(campaign)?)?;
    } else {
        fs::write(&path, serde_yaml::to_string(campaign)?)?;
    }
    Ok(path)
}

pub fn load_campaign_yaml(path: &Path) -> Result<Campaign> {
    let raw = fs::read_to_string(path)?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("yaml")
        .to_ascii_lowercase();
    let campaign: Campaign = if ext == "json" {
        serde_json::from_str(&raw)?
    } else {
        serde_yaml::from_str(&raw)?
    };
    Ok(campaign)
}

fn resolve_campaign_path(campaign: &Campaign, out: Option<&PathBuf>) -> Result<PathBuf> {
    if let Some(path) = out {
        return Ok(path.clone());
    }
    let dir = paths::campaigns_dir().ok_or_else(|| anyhow!("cannot resolve config root"))?;
    fs::create_dir_all(&dir)?;
    let platform = inferred_campaign_platform(campaign);
    Ok(dir.join(default_campaign_filename(
        &campaign.name,
        Some(platform.as_str()),
        "yaml",
    )))
}

pub fn default_campaign_filename(name: &str, platform: Option<&str>, extension: &str) -> String {
    let ext = if extension.trim().is_empty() {
        "yaml"
    } else {
        extension.trim().trim_start_matches('.')
    };
    let platform_tag = normalize_tag(platform.unwrap_or("any"));
    let name_tag = normalize_tag(name);
    format!("spuc-intrusion_set-{platform_tag}-{name_tag}.{ext}")
}

fn inferred_campaign_platform(campaign: &Campaign) -> String {
    let mut unique = BTreeSet::new();
    for step in &campaign.steps {
        if !step.platform.trim().is_empty() {
            unique.insert(step.platform.trim().to_ascii_lowercase());
        }
    }
    if unique.is_empty() {
        "any".to_string()
    } else if unique.len() == 1 {
        unique
            .into_iter()
            .next()
            .unwrap_or_else(|| "any".to_string())
    } else {
        "multi".to_string()
    }
}

fn normalize_tag(raw: &str) -> String {
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

fn order_abilities<'a>(abilities: &'a [Ability], order: &[String]) -> Vec<&'a Ability> {
    if order.is_empty() {
        return abilities.iter().collect();
    }
    let mut ordered = Vec::new();
    for wanted in order {
        if let Some(found) = abilities.iter().find(|a| a.id == *wanted) {
            ordered.push(found);
        }
    }
    for ability in abilities {
        if !ordered.iter().any(|a| a.id == ability.id) {
            ordered.push(ability);
        }
    }
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulation::ability::{
        ABILITY_SCHEMA_VERSION, AbilityAction, AbilityClassification, AbilityRequirement,
        EmulationLevel,
    };

    fn sample_ability(id: &str) -> Ability {
        Ability {
            schema_version: ABILITY_SCHEMA_VERSION.to_string(),
            id: id.to_string(),
            name: format!("ability {id}"),
            description: "sample".to_string(),
            ttp: None,
            supported_platforms: vec!["linux".to_string()],
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
    fn builds_campaign_with_ordered_steps() {
        let abilities = vec![sample_ability("abl-1"), sample_ability("abl-2")];
        let campaign = build_campaign(
            "intrusion-set-001".to_string(),
            "Intrusion Set".to_string(),
            "desc".to_string(),
            &abilities,
        );
        assert_eq!(campaign.steps.len(), 2);
        assert_eq!(campaign.confidence, 70);
        assert_eq!(campaign.steps[0].ability_ref, "abl-1");
        assert_eq!(campaign.steps[1].after.as_deref(), Some("step-001"));
    }

    #[test]
    fn persists_campaign_yaml() {
        let abilities = vec![sample_ability("abl-1")];
        let campaign = build_campaign(
            "intrusion-set-001".to_string(),
            "Intrusion Set".to_string(),
            "desc".to_string(),
            &abilities,
        );
        let out = std::env::temp_dir().join(format!(
            "spuc_intrusion_set_{}.yaml",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = save_campaign_yaml(&campaign, Some(&out)).expect("save");
        let loaded = load_campaign_yaml(&path).expect("load");
        assert_eq!(loaded.intrusion_set_id, "intrusion-set-001");
    }

    #[test]
    fn persists_campaign_json() {
        let abilities = vec![sample_ability("abl-1")];
        let campaign = build_campaign(
            "intrusion-set-001".to_string(),
            "Intrusion Set".to_string(),
            "desc".to_string(),
            &abilities,
        );
        let out = std::env::temp_dir().join(format!(
            "spuc_intrusion_set_{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = save_campaign_yaml(&campaign, Some(&out)).expect("save");
        let loaded = load_campaign_yaml(&path).expect("load");
        assert_eq!(loaded.intrusion_set_id, "intrusion-set-001");
    }

    #[test]
    fn ordered_campaign_respects_requested_order() {
        let abilities = vec![sample_ability("abl-1"), sample_ability("abl-2")];
        let campaign = build_campaign_ordered(
            "intrusion-set-001".to_string(),
            "Intrusion Set".to_string(),
            "desc".to_string(),
            &abilities,
            &["abl-2".to_string()],
        );
        assert_eq!(campaign.confidence, 70);
        assert_eq!(campaign.steps[0].ability_ref, "abl-2");
        assert_eq!(campaign.steps[1].ability_ref, "abl-1");
    }

    #[test]
    fn default_campaign_filename_uses_platform_and_snake_case_name() {
        let file = default_campaign_filename("Blue Team Validation", Some("linux"), "yaml");
        assert_eq!(
            file,
            "spuc-intrusion_set-linux-blue_team_validation.yaml".to_string()
        );
    }
}

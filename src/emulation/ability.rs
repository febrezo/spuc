use serde::{Deserialize, Serialize};

pub const ABILITY_SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AbilityClassification {
    CommandLineTrace,
    ProcessExecutionTrace,
    FileDrop,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EmulationLevel {
    TraceSimulation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbilityRequirement {
    pub id: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbilityAction {
    pub id: String,
    pub title: String,
    pub action_type: String,
    pub observable: String,
    pub operator: String,
    pub value: String,
    pub safe_instructions: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ability {
    pub schema_version: String,
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttp: Option<String>,
    pub supported_platforms: Vec<String>,
    pub requires: Vec<AbilityRequirement>,
    pub optional: Vec<AbilityRequirement>,
    pub agent_capabilities: Vec<String>,
    pub actions: Vec<AbilityAction>,
    pub source_pattern: String,
    pub classification: AbilityClassification,
    pub emulation_level: EmulationLevel,
    pub confidence: u8,
}

pub fn is_supported_schema_version(version: &str) -> bool {
    version == ABILITY_SCHEMA_VERSION
}

impl Ability {
    pub fn validate_structure(&self) -> std::result::Result<(), Vec<String>> {
        let mut issues = Vec::new();
        if !is_supported_schema_version(&self.schema_version) {
            issues.push(format!(
                "schema_version '{}' is not supported (expected {})",
                self.schema_version, ABILITY_SCHEMA_VERSION
            ));
        }
        if self.id.trim().is_empty() {
            issues.push("id must not be empty".to_string());
        }
        if self.name.trim().is_empty() {
            issues.push("name must not be empty".to_string());
        }
        if self
            .ttp
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            issues.push("ttp must not be blank when provided".to_string());
        }
        if self.source_pattern.trim().is_empty() {
            issues.push("source_pattern must not be empty".to_string());
        }
        if self.supported_platforms.is_empty() {
            issues.push("supported_platforms must contain at least one entry".to_string());
        }
        if self.actions.is_empty() {
            issues.push("actions must contain at least one action".to_string());
        }
        if self.confidence > 100 {
            issues.push("confidence must be <= 100".to_string());
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ability() -> Ability {
        Ability {
            schema_version: ABILITY_SCHEMA_VERSION.to_string(),
            id: "abl-test-001".to_string(),
            name: "Sample".to_string(),
            description: "Sample description".to_string(),
            ttp: Some("T1059".to_string()),
            supported_platforms: vec!["linux".to_string()],
            requires: vec![AbilityRequirement {
                id: "cap.process.spawn".to_string(),
                description: "Can spawn benign process".to_string(),
            }],
            optional: vec![],
            agent_capabilities: vec!["cap.telemetry.process".to_string()],
            actions: vec![AbilityAction {
                id: "act-1".to_string(),
                title: "Emit process command line".to_string(),
                action_type: "emit_process_command_line".to_string(),
                observable: "process:command_line".to_string(),
                operator: "MATCHES".to_string(),
                value: "^.*echo.*$".to_string(),
                safe_instructions: "Run a benign command to match telemetry.".to_string(),
            }],
            source_pattern: "[process:command_line MATCHES '^.*echo.*$']".to_string(),
            classification: AbilityClassification::CommandLineTrace,
            emulation_level: EmulationLevel::TraceSimulation,
            confidence: 70,
        }
    }

    #[test]
    fn ability_structure_validation_detects_missing_fields() {
        let mut ability = sample_ability();
        ability.actions.clear();
        let issues = ability.validate_structure().expect_err("expected invalid");
        assert!(
            issues.iter().any(|i| i.contains("actions")),
            "missing action validation"
        );
    }

    #[test]
    fn schema_version_validation_rejects_unknown() {
        let mut ability = sample_ability();
        ability.schema_version = "2.0".to_string();
        let issues = ability.validate_structure().expect_err("expected invalid");
        assert!(
            issues.iter().any(|i| i.contains("schema_version")),
            "missing schema validation"
        );
    }
}

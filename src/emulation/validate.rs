use serde::Serialize;

use crate::emulation::ability::{Ability, ABILITY_SCHEMA_VERSION};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub check: String,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    Executable,
    PartiallyExecutable,
    NotExecutable,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidationReport {
    pub ability_id: String,
    pub schema_version: String,
    pub host_platform: String,
    pub compatibility: CompatibilityStatus,
    pub missing_required_capabilities: Vec<String>,
    pub missing_optional_capabilities: Vec<String>,
    pub unsupported_platform: bool,
    pub reasons: Vec<String>,
    pub checks: Vec<CheckResult>,
    pub summary: String,
}

#[derive(Debug, Clone)]
pub struct AgentProfile {
    pub platform: String,
    pub capabilities: Vec<String>,
}

pub fn host_platform() -> &'static str {
    match std::env::consts::OS {
        "windows" => "windows",
        "macos" => "macos",
        "linux" => "linux",
        other => other,
    }
}

pub fn local_agent_profile() -> AgentProfile {
    let platform = host_platform().to_string();
    AgentProfile {
        capabilities: default_capabilities_for_platform(&platform),
        platform,
    }
}

pub fn default_capabilities_for_platform(platform: &str) -> Vec<String> {
    let mut caps = vec![
        "cap.process.spawn".to_string(),
        "cap.file.create".to_string(),
        "cap.directory.create".to_string(),
        "cap.network.connect".to_string(),
        "cap.dns.resolve".to_string(),
        "cap.telemetry.process".to_string(),
        "cap.telemetry.file".to_string(),
        "cap.telemetry.network".to_string(),
    ];
    match platform {
        "windows" => {
            caps.push("cap.shell.powershell".to_string());
            caps.push("cap.registry.write".to_string());
            caps.push("cap.telemetry.registry".to_string());
        }
        "linux" | "macos" => caps.push("cap.shell.bash".to_string()),
        _ => {}
    }
    caps
}

pub fn validate_ability(ability: &Ability, profile: &AgentProfile) -> ValidationReport {
    let mut checks = Vec::new();
    let mut reasons = Vec::new();

    let schema_ok = ability.schema_version == ABILITY_SCHEMA_VERSION;
    checks.push(CheckResult {
        check: "schema_version".to_string(),
        status: if schema_ok {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        detail: if schema_ok {
            format!("schema_version '{}' is supported.", ability.schema_version)
        } else {
            format!(
                "schema_version '{}' is not supported (expected {}).",
                ability.schema_version, ABILITY_SCHEMA_VERSION
            )
        },
    });
    if !schema_ok {
        reasons.push("unsupported schema version".to_string());
    }

    match ability.validate_structure() {
        Ok(()) => checks.push(CheckResult {
            check: "ability_structure".to_string(),
            status: CheckStatus::Pass,
            detail: "Ability JSON structure is valid.".to_string(),
        }),
        Err(issues) => {
            checks.push(CheckResult {
                check: "ability_structure".to_string(),
                status: CheckStatus::Fail,
                detail: issues.join(" | "),
            });
            reasons.push("invalid ability structure".to_string());
        }
    }

    let platform_ok = ability
        .supported_platforms
        .iter()
        .any(|p| p.eq_ignore_ascii_case("any") || p.eq_ignore_ascii_case(&profile.platform));
    checks.push(CheckResult {
        check: "platform_compatibility".to_string(),
        status: if platform_ok {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        detail: if platform_ok {
            format!(
                "Host platform '{}' is included in ability supported_platforms.",
                profile.platform
            )
        } else {
            format!(
                "Host platform '{}' is not included in ability supported_platforms {:?}.",
                profile.platform, ability.supported_platforms
            )
        },
    });
    if !platform_ok {
        reasons.push("unsupported platform".to_string());
    }

    let missing_required: Vec<String> = ability
        .requires
        .iter()
        .filter(|req| !profile.capabilities.iter().any(|cap| cap == &req.id))
        .map(|req| req.id.clone())
        .collect();

    let missing_agent_caps: Vec<String> = ability
        .agent_capabilities
        .iter()
        .filter(|req| !profile.capabilities.iter().any(|cap| cap == *req))
        .cloned()
        .collect();

    let mut missing_required_all = missing_required.clone();
    for cap in missing_agent_caps {
        if !missing_required_all.contains(&cap) {
            missing_required_all.push(cap);
        }
    }

    checks.push(CheckResult {
        check: "required_capabilities".to_string(),
        status: if missing_required_all.is_empty() {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        detail: if missing_required_all.is_empty() {
            "All required capabilities are available.".to_string()
        } else {
            format!(
                "Missing required capabilities: {}",
                missing_required_all.join(", ")
            )
        },
    });
    if !missing_required_all.is_empty() {
        reasons.push(format!(
            "missing required capability: {}",
            missing_required_all.join(", ")
        ));
    }

    let missing_optional: Vec<String> = ability
        .optional
        .iter()
        .filter(|req| !profile.capabilities.iter().any(|cap| cap == &req.id))
        .map(|req| req.id.clone())
        .collect();
    checks.push(CheckResult {
        check: "optional_capabilities".to_string(),
        status: if missing_optional.is_empty() {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        detail: if missing_optional.is_empty() {
            "All optional capabilities are available.".to_string()
        } else {
            format!(
                "Missing optional capabilities: {}",
                missing_optional.join(", ")
            )
        },
    });
    if !missing_optional.is_empty() {
        reasons.push(format!(
            "optional capability unavailable: {}",
            missing_optional.join(", ")
        ));
    }

    let has_fail = checks.iter().any(|c| c.status == CheckStatus::Fail);
    let has_warn = checks.iter().any(|c| c.status == CheckStatus::Warn);
    let compatibility = if has_fail {
        CompatibilityStatus::NotExecutable
    } else if has_warn {
        CompatibilityStatus::PartiallyExecutable
    } else {
        CompatibilityStatus::Executable
    };
    let summary = match compatibility {
        CompatibilityStatus::Executable => {
            "Ability is executable on this host in controlled mode.".to_string()
        }
        CompatibilityStatus::PartiallyExecutable => {
            "Ability is partially executable; optional capabilities are missing.".to_string()
        }
        CompatibilityStatus::NotExecutable => {
            "Ability is not executable on this host due to failed checks.".to_string()
        }
    };

    ValidationReport {
        ability_id: ability.id.clone(),
        schema_version: ability.schema_version.clone(),
        host_platform: profile.platform.clone(),
        compatibility,
        missing_required_capabilities: missing_required_all,
        missing_optional_capabilities: missing_optional,
        unsupported_platform: !platform_ok,
        reasons,
        checks,
        summary,
    }
}

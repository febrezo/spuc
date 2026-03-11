use anyhow::Result;

use crate::emulation::ability::Ability;
use crate::emulation::agents::{
    AbilityExporter, AtomicRedTeamExporter, BashExporter, MitreCalderaExporter, PowershellExporter,
    SpucAgentExporter,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbilityExportTarget {
    SpucAgent,
    Bash,
    Powershell,
    AtomicRedTeam,
    MitreCaldera,
}

pub fn export_ability(target: AbilityExportTarget, ability: &Ability) -> Result<String> {
    match target {
        AbilityExportTarget::SpucAgent => SpucAgentExporter.export(ability),
        AbilityExportTarget::Bash => BashExporter.export(ability),
        AbilityExportTarget::Powershell => PowershellExporter.export(ability),
        AbilityExportTarget::AtomicRedTeam => AtomicRedTeamExporter.export(ability),
        AbilityExportTarget::MitreCaldera => MitreCalderaExporter.export(ability),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulation::ability::{
        ABILITY_SCHEMA_VERSION, Ability, AbilityAction, AbilityClassification, AbilityRequirement,
        EmulationLevel,
    };

    fn sample_ability() -> Ability {
        Ability {
            schema_version: ABILITY_SCHEMA_VERSION.to_string(),
            id: "abl-test-001".to_string(),
            name: "Sample".to_string(),
            description: "Sample description".to_string(),
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
    fn spuc_agent_exporter_outputs_json() {
        let ability = sample_ability();
        let out = export_ability(AbilityExportTarget::SpucAgent, &ability).expect("export failed");
        assert!(out.contains("\"id\": \"abl-test-001\""));
        assert!(out.contains("\"schema_version\": \"1.0\""));
        assert!(out.contains("\"execution_plan\""));
    }

    #[test]
    fn bash_exporter_outputs_script() {
        let ability = sample_ability();
        let out = export_ability(AbilityExportTarget::Bash, &ability).expect("export failed");
        assert!(out.starts_with("#!/usr/bin/env bash"));
        assert!(out.contains("executed process probe"));
    }

    #[test]
    fn powershell_exporter_outputs_script() {
        let ability = sample_ability();
        let out = export_ability(AbilityExportTarget::Powershell, &ability).expect("export failed");
        assert!(out.contains("Write-Host"));
        assert!(out.contains("executed process probe"));
    }

    #[test]
    fn atomic_red_team_exporter_outputs_yaml() {
        let ability = sample_ability();
        let out =
            export_ability(AbilityExportTarget::AtomicRedTeam, &ability).expect("export failed");
        assert!(out.contains("attack_technique: T0000"));
        assert!(out.contains("atomic_tests:"));
    }

    #[test]
    fn mitre_caldera_exporter_outputs_json() {
        let ability = sample_ability();
        let out =
            export_ability(AbilityExportTarget::MitreCaldera, &ability).expect("export failed");
        assert!(out.contains("\"platforms\""));
        assert!(out.contains("\"technique\""));
    }
}

use anyhow::Result;

use crate::emulation::ability::Ability;
use crate::emulation::agents::AbilityExporter;
use crate::emulation::materialize;

pub struct SpucAgentExporter;

impl AbilityExporter for SpucAgentExporter {
    fn export(&self, ability: &Ability) -> Result<String> {
        let plan = materialize::build_materialization_plan(ability)?;
        let mut value = serde_json::to_value(ability)?;
        if let serde_json::Value::Object(map) = &mut value {
            map.insert("execution_plan".to_string(), serde_json::to_value(plan)?);
        }
        Ok(serde_json::to_string_pretty(&value)?)
    }
}

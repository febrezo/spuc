use anyhow::Result;

use crate::emulation::ability::Ability;

pub mod atomic_red_team;
pub mod bash;
pub mod mitre_caldera;
pub mod powershell;
pub mod spuc_agent;

pub use atomic_red_team::AtomicRedTeamExporter;
pub use bash::BashExporter;
pub use mitre_caldera::MitreCalderaExporter;
pub use powershell::PowershellExporter;
pub use spuc_agent::SpucAgentExporter;

pub trait AbilityExporter {
    fn export(&self, ability: &Ability) -> Result<String>;
}

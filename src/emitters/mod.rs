use serde::Serialize;

pub mod chronicle;
pub mod eql;
pub mod kql;
pub mod openioc;
pub mod sigma;
pub mod snort;
pub mod spl;
pub mod suricata;
pub mod yara;

#[derive(Debug, Clone, Serialize)]
pub enum FidelityStatus {
    Exact,
    SchemaDependent,
    BackendDependent,
    Partial,
    Lossy,
    Unsupported,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCause {
    ParseError,
    NormalizationError,
    EmitterNotImplemented,
    BackendSemanticsMissing,
    SchemaUncertain,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmitResult {
    pub status: FidelityStatus,
    pub notes: Vec<String>,
    pub rule: Option<String>,
    pub cause: Option<FailureCause>,
}

impl EmitResult {
    pub fn exact(rule: String) -> Self {
        Self {
            status: FidelityStatus::Exact,
            notes: Vec::new(),
            rule: Some(rule),
            cause: None,
        }
    }

    pub fn unsupported(reason: impl Into<String>) -> Self {
        Self {
            status: FidelityStatus::Unsupported,
            notes: vec![reason.into()],
            rule: None,
            cause: None,
        }
    }

    pub fn unsupported_with_cause(reason: impl Into<String>, cause: FailureCause) -> Self {
        Self {
            status: FidelityStatus::Unsupported,
            notes: vec![reason.into()],
            rule: None,
            cause: Some(cause),
        }
    }
}

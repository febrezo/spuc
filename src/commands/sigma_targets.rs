use crate::commands::sigma_runtime::sigma_runtime_info;

pub(crate) const SIGMA_TARGET_PREFIX: &str = "sigma-to-";

pub(crate) fn dynamic_sigma_targets() -> Vec<String> {
    let runtime = sigma_runtime_info();
    dynamic_targets_from_backends(&runtime.compatible_backends)
}

pub(crate) fn dynamic_target_label(backend: &str) -> String {
    format!("{SIGMA_TARGET_PREFIX}{backend}")
}

pub(crate) fn target_to_backend(label: &str) -> Option<String> {
    let normalized = label.trim().to_ascii_lowercase();
    if !normalized.starts_with(SIGMA_TARGET_PREFIX) {
        return None;
    }
    let backend = normalized
        .trim_start_matches(SIGMA_TARGET_PREFIX)
        .trim()
        .to_string();
    if backend.is_empty() {
        return None;
    }
    Some(backend)
}

pub(crate) fn is_dynamic_target_available(label: &str) -> bool {
    let Some(backend) = target_to_backend(label) else {
        return false;
    };
    let runtime = sigma_runtime_info();
    runtime.compatible_backends.contains(&backend)
}

fn dynamic_targets_from_backends(backends: &[String]) -> Vec<String> {
    backends
        .iter()
        .map(|backend| dynamic_target_label(backend))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{dynamic_target_label, dynamic_targets_from_backends, target_to_backend};

    #[test]
    fn sigma_target_label_roundtrip() {
        let label = dynamic_target_label("splunk");
        assert_eq!(label, "sigma-to-splunk");
        assert_eq!(target_to_backend(&label), Some("splunk".to_string()));
    }

    #[test]
    fn generate_dynamic_targets_from_backends() {
        let backends = vec!["splunk".to_string(), "elasticsearch".to_string()];
        let targets = dynamic_targets_from_backends(&backends);
        assert_eq!(
            targets,
            vec![
                "sigma-to-splunk".to_string(),
                "sigma-to-elasticsearch".to_string()
            ]
        );
    }
}

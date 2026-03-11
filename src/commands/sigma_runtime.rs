use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::commands::sigma_discovery::{SigmaPluginEntry, parse_plugin_list};

const SIGMA_DISCOVERY_TIMEOUT_SECS: u64 = 8;

#[derive(Debug, Clone, Default)]
pub(crate) struct SigmaRuntimeInfo {
    pub(crate) binary: String,
    pub(crate) installed: bool,
    pub(crate) operational: bool,
    pub(crate) compatible_backends: Vec<String>,
    pub(crate) warning: Option<String>,
}

#[derive(Debug)]
struct CommandRun {
    status: ExitStatus,
    stdout: String,
    stderr: String,
    timed_out: bool,
}

static SIGMA_RUNTIME_INFO: OnceLock<SigmaRuntimeInfo> = OnceLock::new();

pub(crate) fn warmup_sigma_runtime() {
    let _ = sigma_runtime_info();
}

pub(crate) fn sigma_runtime_info() -> &'static SigmaRuntimeInfo {
    SIGMA_RUNTIME_INFO.get_or_init(detect_sigma_runtime)
}

fn detect_sigma_runtime() -> SigmaRuntimeInfo {
    detect_sigma_runtime_for_binary(sigma_binary())
}

fn detect_sigma_runtime_for_binary(binary: String) -> SigmaRuntimeInfo {
    let timeout = Duration::from_secs(SIGMA_DISCOVERY_TIMEOUT_SECS);
    let run = run_command_with_timeout(&binary, &["plugin", "list"], timeout);

    let mut info = SigmaRuntimeInfo {
        binary: binary.clone(),
        ..SigmaRuntimeInfo::default()
    };

    let run = match run {
        Ok(result) => {
            info.installed = true;
            result
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            eprintln!("sigma not available; skipping dynamic sigma targets");
            return info;
        }
        Err(error) => {
            info.warning = Some(format!("failed to execute sigma: {error}"));
            eprintln!("sigma not available; skipping dynamic sigma targets");
            return info;
        }
    };

    if run.timed_out {
        info.warning = Some(format!(
            "sigma plugin list timed out after {} seconds",
            SIGMA_DISCOVERY_TIMEOUT_SECS
        ));
        eprintln!("sigma detected but plugin discovery timed out");
        return info;
    }

    if !run.status.success() {
        info.warning = Some(format!(
            "sigma plugin list failed: {}",
            compact_text(&run.stderr)
        ));
        eprintln!("sigma detected but plugin discovery failed");
        return info;
    }

    info.operational = true;
    let discovered = match parse_plugin_list(&run.stdout) {
        Ok(entries) => entries,
        Err(error) => {
            info.warning = Some(error.clone());
            eprintln!("sigma detected; plugin list parse failed: {error}");
            return info;
        }
    };
    info.compatible_backends = compatible_backends_from_entries(&discovered);

    eprintln!(
        "sigma detected; discovered {} compatible sigma backends",
        info.compatible_backends.len()
    );

    info
}

pub(crate) fn sigma_binary() -> String {
    env::var("SPUC_SIGMA_BIN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "sigma".to_string())
}

fn compatible_backends_from_entries(entries: &[SigmaPluginEntry]) -> Vec<String> {
    let mut out = Vec::new();
    for entry in entries {
        if entry.plugin_type != "backend" {
            continue;
        }
        if entry.compatible == Some(false) {
            continue;
        }
        if !out.contains(&entry.identifier) {
            out.push(entry.identifier.clone());
        }
    }
    out
}

fn run_command_with_timeout(
    binary: &str,
    args: &[&str],
    timeout: Duration,
) -> io::Result<CommandRun> {
    let nonce = format!(
        "{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let stdout_path = env::temp_dir().join(format!("spuc_sigma_stdout_{nonce}.log"));
    let stderr_path = env::temp_dir().join(format!("spuc_sigma_stderr_{nonce}.log"));
    let stdout_file = File::create(&stdout_path)?;
    let stderr_file = File::create(&stderr_path)?;

    let mut child = Command::new(binary)
        .args(args)
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .spawn()?;

    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            let _ = child.kill();
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(25));
    };

    let stdout = fs::read_to_string(&stdout_path).unwrap_or_default();
    let stderr = fs::read_to_string(&stderr_path).unwrap_or_default();
    let _ = fs::remove_file(stdout_path);
    let _ = fs::remove_file(stderr_path);

    Ok(CommandRun {
        status,
        stdout,
        stderr,
        timed_out,
    })
}

fn compact_text(value: &str) -> String {
    let compact = value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if compact.is_empty() {
        "unknown error".to_string()
    } else {
        compact
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{compatible_backends_from_entries, detect_sigma_runtime_for_binary};
    use crate::commands::sigma_discovery::SigmaPluginEntry;

    #[test]
    fn compatible_backend_filter_keeps_backend_yes_only() {
        let entries = vec![
            SigmaPluginEntry {
                plugin_type: "backend".to_string(),
                identifier: "splunk".to_string(),
                compatible: Some(true),
            },
            SigmaPluginEntry {
                plugin_type: "backend".to_string(),
                identifier: "secops".to_string(),
                compatible: Some(false),
            },
            SigmaPluginEntry {
                plugin_type: "pipeline".to_string(),
                identifier: "ecs".to_string(),
                compatible: Some(true),
            },
        ];
        let backends = compatible_backends_from_entries(&entries);
        assert_eq!(backends, vec!["splunk".to_string()]);
    }

    #[test]
    fn detection_handles_missing_sigma_binary() {
        let info = detect_sigma_runtime_for_binary("/definitely/missing/sigma".to_string());
        assert!(!info.installed);
        assert!(!info.operational);
        assert!(info.compatible_backends.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn detection_handles_sigma_plugin_list_error() {
        let script = write_script(
            r#"#!/bin/sh
if [ "$1" = "plugin" ] && [ "$2" = "list" ]; then
  echo "plugin list error" 1>&2
  exit 2
fi
exit 0
"#,
        );
        let info = detect_sigma_runtime_for_binary(script.to_string_lossy().to_string());
        assert!(info.installed);
        assert!(!info.operational);
        assert!(info.compatible_backends.is_empty());
    }

    #[cfg(unix)]
    fn write_script(contents: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("spuc_sigma_runtime_test_{ts}.sh"));
        fs::write(&path, contents).expect("write script");
        let mut perms = fs::metadata(&path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).expect("chmod");
        path
    }
}

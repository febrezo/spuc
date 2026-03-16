use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::commands::sigma_discovery::{SigmaPluginEntry, parse_plugin_list};
use crate::paths::spuc_config_root;

const SIGMA_DISCOVERY_TIMEOUT_SECS: u64 = 8;
const SIGMA_RUNTIME_CACHE_VERSION: u8 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct SigmaRuntimeInfo {
    pub(crate) binary: String,
    pub(crate) installed: bool,
    pub(crate) operational: bool,
    pub(crate) compatible_backends: Vec<String>,
    pub(crate) warning: Option<String>,
    #[serde(default)]
    pub(crate) cache_used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SigmaRuntimeCache {
    format_version: u8,
    cached_at_unix: u64,
    runtime: SigmaRuntimeInfo,
}

#[derive(Debug)]
struct CommandRun {
    status: ExitStatus,
    stdout: String,
    stderr: String,
    timed_out: bool,
}

static SIGMA_RUNTIME_INFO: OnceLock<Mutex<Option<SigmaRuntimeInfo>>> = OnceLock::new();

pub(crate) fn warmup_sigma_runtime() {
    let _ = sigma_runtime_info();
}

pub(crate) fn sigma_runtime_info() -> SigmaRuntimeInfo {
    let state = SIGMA_RUNTIME_INFO.get_or_init(|| Mutex::new(None));
    let mut guard = state.lock().expect("sigma runtime state lock poisoned");
    if let Some(info) = &*guard {
        return info.clone();
    }

    let info = load_cached_runtime().unwrap_or_else(detect_and_cache_sigma_runtime);
    *guard = Some(info.clone());
    info
}

pub(crate) fn refresh_sigma_runtime_cache() -> SigmaRuntimeInfo {
    let refreshed = detect_and_cache_sigma_runtime();
    let state = SIGMA_RUNTIME_INFO.get_or_init(|| Mutex::new(None));
    let mut guard = state.lock().expect("sigma runtime state lock poisoned");
    *guard = Some(refreshed.clone());
    refreshed
}

fn detect_sigma_runtime() -> SigmaRuntimeInfo {
    // If SIGMA_RPC_URL is configured, try remote backend discovery first.
    if crate::commands::sigma_rpc::is_configured() {
        if let Some(entries) = crate::commands::sigma_rpc::discover_backends_from_remote() {
            let backends = compatible_backends_from_entries(&entries);
            if !backends.is_empty() {
                return SigmaRuntimeInfo {
                    binary: "sigma-jsonrpc".to_string(),
                    installed: true,
                    operational: true,
                    compatible_backends: backends,
                    warning: None,
                    cache_used: false,
                };
            }
            eprintln!("[sigma-jsonrpc] remote discovery returned no backends, falling back to local sigma");
        } else {
            eprintln!("[sigma-jsonrpc] remote discovery failed, falling back to local sigma");
        }
    }
    detect_sigma_runtime_for_binary(sigma_binary())
}

fn detect_and_cache_sigma_runtime() -> SigmaRuntimeInfo {
    let info = detect_sigma_runtime();
    let _ = persist_runtime_cache(&info);
    info
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
            return info;
        }
        Err(error) => {
            info.warning = Some(format!("failed to execute sigma: {error}"));
            return info;
        }
    };

    if run.timed_out {
        info.warning = Some(format!(
            "sigma plugin list timed out after {} seconds",
            SIGMA_DISCOVERY_TIMEOUT_SECS
        ));
        return info;
    }

    if !run.status.success() {
        info.warning = Some(format!(
            "sigma plugin list failed: {}",
            compact_text(&run.stderr)
        ));
        return info;
    }

    info.operational = true;
    let discovered = match parse_plugin_list(&run.stdout) {
        Ok(entries) => entries,
        Err(error) => {
            info.warning = Some(error.clone());
            return info;
        }
    };
    info.compatible_backends = compatible_backends_from_entries(&discovered);

    info
}

fn sigma_runtime_cache_path() -> Option<std::path::PathBuf> {
    spuc_config_root().map(|root| root.join("sigma").join("runtime.json"))
}

fn load_cached_runtime() -> Option<SigmaRuntimeInfo> {
    let path = sigma_runtime_cache_path()?;
    load_cached_runtime_from_path(&path, &sigma_binary())
}

fn load_cached_runtime_from_path(path: &Path, expected_binary: &str) -> Option<SigmaRuntimeInfo> {
    let raw = fs::read_to_string(path).ok()?;
    let cache: SigmaRuntimeCache = serde_json::from_str(&raw).ok()?;
    if cache.format_version != SIGMA_RUNTIME_CACHE_VERSION {
        return None;
    }
    if cache.runtime.binary.trim() != expected_binary.trim() {
        return None;
    }
    let mut runtime = cache.runtime;
    runtime.cache_used = true;
    Some(runtime)
}

fn persist_runtime_cache(info: &SigmaRuntimeInfo) -> io::Result<()> {
    let Some(path) = sigma_runtime_cache_path() else {
        return Ok(());
    };
    persist_runtime_cache_to_path(&path, info)
}

fn persist_runtime_cache_to_path(path: &Path, info: &SigmaRuntimeInfo) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut runtime = info.clone();
    runtime.cache_used = false;
    let cache = SigmaRuntimeCache {
        format_version: SIGMA_RUNTIME_CACHE_VERSION,
        cached_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        runtime,
    };
    let json = serde_json::to_string_pretty(&cache)
        .map_err(|error| io::Error::other(format!("serialize sigma cache: {error}")))?;
    fs::write(path, json)
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

    use super::{
        SigmaRuntimeInfo, compatible_backends_from_entries, detect_sigma_runtime_for_binary,
        load_cached_runtime_from_path, persist_runtime_cache_to_path,
    };
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

    #[test]
    fn cache_roundtrip_loads_runtime() {
        let path = write_cache_path("roundtrip");
        let info = SigmaRuntimeInfo {
            binary: "sigma".to_string(),
            installed: true,
            operational: true,
            compatible_backends: vec!["splunk".to_string()],
            warning: None,
            cache_used: false,
        };
        persist_runtime_cache_to_path(&path, &info).expect("persist cache");

        let loaded = load_cached_runtime_from_path(&path, "sigma").expect("load cache");
        assert!(loaded.cache_used);
        assert!(loaded.operational);
        assert_eq!(loaded.compatible_backends, vec!["splunk".to_string()]);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn cache_is_ignored_when_binary_changes() {
        let path = write_cache_path("binary_mismatch");
        let info = SigmaRuntimeInfo {
            binary: "sigma-custom".to_string(),
            installed: true,
            operational: true,
            compatible_backends: vec!["splunk".to_string()],
            warning: None,
            cache_used: false,
        };
        persist_runtime_cache_to_path(&path, &info).expect("persist cache");

        let loaded = load_cached_runtime_from_path(&path, "sigma");
        assert!(loaded.is_none());

        let _ = fs::remove_file(path);
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

    fn write_cache_path(tag: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("spuc_sigma_runtime_cache_{tag}_{ts}.json"))
    }
}

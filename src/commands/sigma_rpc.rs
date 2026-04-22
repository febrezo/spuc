/// HTTP client for the sigma-jsonrpc external service.
///
/// When `SIGMA_RPC_URL` is set SPUC will try to discover Sigma backends
/// through the remote service instead of (or in addition to) the local
/// sigma CLI.  Actual conversion is delegated to the service too.
///
/// The protocol is JSON-RPC 2.0 over plain HTTP POST.
use std::env;

use serde::Deserialize;
use serde_json::json;

use crate::commands::sigma_discovery::SigmaPluginEntry;

const ENV_RPC_URL: &str = "SIGMA_RPC_URL";
const ENV_RPC_TOKEN: &str = "SPUC_SIGMA_RPC_TOKEN";
const DEFAULT_RPC_URL: &str = "http://localhost:8080/jsonrpc";
const DEFAULT_TIMEOUT_SECS: u64 = 15;
const DEFAULT_LOCAL_DISCOVERY_TIMEOUT_SECS: u64 = 2;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Returns the configured RPC URL, or `None` if the env var is not set.
pub(crate) fn rpc_url() -> Option<String> {
    if let Some(explicit) = rpc_url_from_env() {
        return Some(explicit);
    }
    Some(DEFAULT_RPC_URL.to_string())
}

/// Returns `true` if a remote sigma-jsonrpc service is configured.
pub(crate) fn is_configured() -> bool {
    rpc_url().is_some()
}

fn rpc_url_from_env() -> Option<String> {
    let raw = env::var(ENV_RPC_URL).ok()?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn rpc_bearer_token() -> Option<String> {
    let raw = env::var(ENV_RPC_TOKEN).ok()?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

// ---------------------------------------------------------------------------
// Wire types (minimal – only what SPUC needs)
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct RpcResponse<T: Default> {
    #[serde(default)]
    pub result: Option<T>,
    #[serde(default)]
    pub error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    pub message: String,
}

#[derive(Debug, Deserialize)]
struct PluginEntry {
    pub identifier: String,
    pub plugin_type: String,
    pub compatible: Option<bool>,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Default, Deserialize)]
struct BackendsResult {
    #[serde(default)]
    pub backends: Vec<PluginEntry>,
    #[serde(default)]
    pub pipelines: Vec<PluginEntry>,
}

#[derive(Debug, Default, Deserialize)]
struct ConvertResult {
    pub success: bool,
    pub converted_output: Option<String>,
    pub stderr: Option<String>,
    pub error_detail: Option<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Discover sigma backends from the remote service.
///
/// Returns `None` on any network / parse error so the caller can fall back to
/// local sigma CLI discovery.
pub(crate) fn discover_backends_from_remote() -> Option<Vec<SigmaPluginEntry>> {
    let url = rpc_url()?;
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sigma.backends",
        "params": {}
    });

    let response: RpcResponse<BackendsResult> = make_rpc_call(&url, payload).ok()?;

    if let Some(err) = response.error {
        eprintln!("[sigma-jsonrpc] sigma.backends error: {}", err.message);
        return None;
    }

    let result = response.result?;
    let mut entries = Vec::new();
    for p in result.backends.iter().chain(result.pipelines.iter()) {
        entries.push(SigmaPluginEntry {
            plugin_type: p.plugin_type.clone(),
            identifier: p.identifier.clone(),
            compatible: p.compatible,
        });
    }
    Some(entries)
}

/// Convert a Sigma rule via the remote service.
///
/// Returns `Ok(output)` on success, or an error string describing the failure.
pub(crate) fn remote_convert(
    rule_yaml: &str,
    target: &str,
    pipeline: Option<&str>,
) -> Result<String, String> {
    let url = rpc_url().ok_or_else(|| "SIGMA_RPC_URL not configured".to_string())?;

    let mut params = json!({
        "rule_content": rule_yaml,
        "target": target,
    });
    if let Some(p) = pipeline {
        params["pipeline"] = json!(p);
    }

    let payload = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "sigma.convert",
        "params": params
    });

    let response: RpcResponse<ConvertResult> =
        make_rpc_call(&url, payload).map_err(|e| e.to_string())?;

    if let Some(err) = response.error {
        return Err(format!("RPC error: {}", err.message));
    }

    let result = response
        .result
        .ok_or_else(|| "empty result from sigma-jsonrpc".to_string())?;

    if !result.success {
        return Err(result
            .error_detail
            .or(result.stderr)
            .unwrap_or_else(|| "sigma convert failed".to_string()));
    }

    result
        .converted_output
        .ok_or_else(|| "sigma convert returned empty output".to_string())
}

// ---------------------------------------------------------------------------
// HTTP helper
// ---------------------------------------------------------------------------

fn make_rpc_call<T: for<'de> serde::Deserialize<'de> + Default>(
    url: &str,
    payload: serde_json::Value,
) -> anyhow::Result<RpcResponse<T>> {
    let timeout_secs = if rpc_url_from_env().is_some() {
        DEFAULT_TIMEOUT_SECS
    } else {
        // Keep fallback localhost probing fast when no explicit SIGMA_RPC_URL is configured.
        DEFAULT_LOCAL_DISCOVERY_TIMEOUT_SECS
    };
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build();

    let mut request = agent.post(url).set("Content-Type", "application/json");
    if let Some(token) = rpc_bearer_token() {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }

    let response = request.send_json(payload)?;

    let parsed: RpcResponse<T> = response.into_json()?;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, OnceLock};

    use super::{is_configured, rpc_bearer_token, rpc_url};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn rpc_url_returns_localhost_default_when_unset() {
        let _guard = env_lock().lock().expect("env lock poisoned");
        unsafe {
            std::env::remove_var("SIGMA_RPC_URL");
        }
        assert_eq!(rpc_url().as_deref(), Some("http://localhost:8080/jsonrpc"));
        assert!(is_configured());
    }

    #[test]
    fn rpc_url_trims_value_when_set() {
        let _guard = env_lock().lock().expect("env lock poisoned");
        unsafe {
            std::env::set_var("SIGMA_RPC_URL", "  http://localhost:8000/rpc  ");
        }
        assert_eq!(rpc_url().as_deref(), Some("http://localhost:8000/rpc"));
        assert!(is_configured());
        unsafe {
            std::env::remove_var("SIGMA_RPC_URL");
        }
    }

    #[test]
    fn rpc_token_trims_value_when_set() {
        let _guard = env_lock().lock().expect("env lock poisoned");
        unsafe {
            std::env::set_var("SPUC_SIGMA_RPC_TOKEN", "  test-token  ");
        }
        assert_eq!(rpc_bearer_token().as_deref(), Some("test-token"));
        unsafe {
            std::env::remove_var("SPUC_SIGMA_RPC_TOKEN");
        }
    }
}

use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn spuc_agent_bin() -> String {
    if let Ok(bin) = std::env::var("CARGO_BIN_EXE_spuc-agent") {
        return bin;
    }
    if let Ok(bin) = std::env::var("CARGO_BIN_EXE_spuc_agent") {
        return bin;
    }
    let bin = "target/debug/spuc-agent".to_string();
    let status = Command::new("cargo")
        .args(["build", "-q", "-p", "spuc-cli", "--bin", "spuc-agent"])
        .status()
        .expect("failed to build spuc-agent binary for tests");
    assert!(
        status.success(),
        "failed to build spuc-agent binary for tests"
    );
    assert!(
        Path::new(&bin).exists(),
        "spuc-agent binary missing after build"
    );
    bin
}

fn write_temp_ability(payload: &Value) -> std::path::PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock error")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("spuc_agent_ability_{ts}.json"));
    fs::write(
        &path,
        serde_json::to_string_pretty(payload).expect("serialize"),
    )
    .expect("write ability json");
    path
}

fn base_ability(platforms: Vec<&str>) -> Value {
    json!({
      "schema_version": "1.0",
      "id": "abl-agent-cli-001",
      "name": "Agent CLI test",
      "description": "Agent CLI test ability",
      "supported_platforms": platforms,
      "requires": [
        { "id": "cap.process.spawn", "description": "Can spawn process" }
      ],
      "optional": [],
      "agent_capabilities": ["cap.telemetry.process"],
      "actions": [
        {
          "id": "act-001",
          "title": "Emit process observable",
          "action_type": "emit_process_command_line",
          "observable": "process:command_line",
          "operator": "MATCHES",
          "value": "^.*echo.*$",
          "safe_instructions": "Run benign echo command."
        }
      ],
      "source_pattern": "[process:command_line MATCHES '^.*echo.*$']",
      "classification": "command_line_trace",
      "emulation_level": "trace_simulation",
      "confidence": 70
    })
}

#[test]
fn spuc_agent_validate_reports_executable_for_compatible_ability() {
    let host = std::env::consts::OS;
    let input = write_temp_ability(&base_ability(vec![host]));

    let out = Command::new(spuc_agent_bin())
        .args(["validate", "--input"])
        .arg(&input)
        .output()
        .expect("failed to run spuc-agent");
    assert!(
        out.status.success(),
        "spuc-agent failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: Value = serde_json::from_slice(&out.stdout).expect("invalid report json");
    assert_eq!(json["compatibility"], "executable");
}

#[test]
fn spuc_agent_validate_reports_not_executable_for_platform_mismatch() {
    let input = write_temp_ability(&base_ability(vec!["platform-never-supported"]));

    let out = Command::new(spuc_agent_bin())
        .args(["validate", "--input"])
        .arg(&input)
        .output()
        .expect("failed to run spuc-agent");
    assert!(
        out.status.success(),
        "spuc-agent failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: Value = serde_json::from_slice(&out.stdout).expect("invalid report json");
    assert_eq!(json["compatibility"], "not_executable");
}

#[test]
fn spuc_agent_validate_reports_partial_when_optional_capability_missing() {
    let mut ability = base_ability(vec![std::env::consts::OS]);
    ability["optional"] = json!([
      { "id": "cap.optional.unknown", "description": "Optional unknown capability" }
    ]);
    let input = write_temp_ability(&ability);

    let out = Command::new(spuc_agent_bin())
        .args(["validate", "--input"])
        .arg(&input)
        .output()
        .expect("failed to run spuc-agent");
    assert!(
        out.status.success(),
        "spuc-agent failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: Value = serde_json::from_slice(&out.stdout).expect("invalid report json");
    assert_eq!(json["compatibility"], "partially_executable");
}

#[test]
fn spuc_agent_validate_fails_for_unsupported_schema_version() {
    let mut ability = base_ability(vec![std::env::consts::OS]);
    ability["schema_version"] = json!("999.0");
    let input = write_temp_ability(&ability);

    let out = Command::new(spuc_agent_bin())
        .args(["validate", "--input"])
        .arg(&input)
        .output()
        .expect("failed to run spuc-agent");
    assert!(
        !out.status.success(),
        "expected schema-version failure, stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Unsupported ability schema_version"),
        "unexpected stderr: {stderr}"
    );
}

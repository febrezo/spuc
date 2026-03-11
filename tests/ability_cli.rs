use serde_json::Value;
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn spuc_bin() -> &'static str {
    env!("CARGO_BIN_EXE_spuc")
}

fn temp_config_root() -> std::path::PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock error")
        .as_nanos();
    std::env::temp_dir().join(format!("spuc_cfg_test_{ts}"))
}

fn extract_json_value(stdout: &[u8]) -> Value {
    let raw = String::from_utf8_lossy(stdout);
    let start = raw
        .find('{')
        .unwrap_or_else(|| panic!("expected json payload in stdout, got: {raw}"));
    let end = raw
        .rfind('}')
        .unwrap_or_else(|| panic!("expected json payload end in stdout, got: {raw}"));
    serde_json::from_str(&raw[start..=end]).expect("invalid json payload")
}

#[test]
fn emulate_generates_spuc_agent_json_stdout() {
    let root = temp_config_root();
    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "emulate",
            "--rule",
            "[process:command_line MATCHES '^.*echo.*$']",
            "--to",
            "spuc-agent",
        ])
        .output()
        .expect("failed to run emulate command");
    assert!(
        out.status.success(),
        "emulate command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json = extract_json_value(&out.stdout);
    assert_eq!(json["schema_version"], "1.0");
    assert_eq!(json["classification"], "command_line_trace");
    assert_eq!(json["emulation_level"], "trace_simulation");
    assert!(json["supported_platforms"].as_array().is_some());
    assert_eq!(
        json["source_pattern"],
        "[process:command_line MATCHES '^.*echo.*$']"
    );
    assert!(json["actions"].as_array().is_some_and(|a| !a.is_empty()));
}

#[test]
fn emulate_writes_output_directory_and_powershell_artifact() {
    let root = temp_config_root();
    let out_dir = root.join("exports");
    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "emulate",
            "--rule",
            "[file:name MATCHES '^.*\\\\.log$']",
            "--to",
            "spuc-agent",
            "--to",
            "powershell",
            "--output",
        ])
        .arg(&out_dir)
        .output()
        .expect("failed to run emulate command");
    assert!(
        out.status.success(),
        "emulate command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut exported: Vec<_> = fs::read_dir(&out_dir)
        .expect("exports dir missing")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();
    exported.sort();
    assert_eq!(exported.len(), 2);
    assert!(
        exported
            .iter()
            .any(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
    );
    assert!(
        exported
            .iter()
            .any(|p| p.extension().and_then(|e| e.to_str()) == Some("ps1"))
    );

    let ps_path = exported
        .iter()
        .find(|p| p.extension().and_then(|e| e.to_str()) == Some("ps1"))
        .expect("powershell export missing");
    let ps = fs::read_to_string(ps_path).expect("missing powershell file");
    assert!(ps.contains("Write-Host"));
}

#[test]
fn emulate_always_saves_ability_into_catalog() {
    let root = temp_config_root();
    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "emulate",
            "--rule",
            "[directory:path MATCHES '^/tmp/spuc/.*$']",
            "--to",
            "bash",
        ])
        .output()
        .expect("failed to run emulate command");
    assert!(
        out.status.success(),
        "emulate command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let ability_files: Vec<_> = fs::read_dir(root.join("abilities"))
        .expect("abilities directory missing")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    assert_eq!(ability_files.len(), 1);
}

#[test]
fn emulate_strict_rejects_unsupported_observable_scope() {
    let root = temp_config_root();
    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "emulate",
            "--rule",
            "[ipv4-addr:value = '1.1.1.1']",
            "--to",
            "spuc-agent",
        ])
        .output()
        .expect("failed to run emulate command");
    assert!(
        !out.status.success(),
        "expected failure, got success with stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("process:command_line/name/cwd"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn emulate_partial_mode_skips_unsupported_rules_when_possible() {
    let root = temp_config_root();
    let rules_file = root.join("rules.stix");
    fs::create_dir_all(&root).expect("config root");
    fs::write(
        &rules_file,
        "[ipv4-addr:value = '1.1.1.1']\n[process:command_line MATCHES '^.*echo.*$']\n",
    )
    .expect("write rules");

    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["emulate", "--file"])
        .arg(&rules_file)
        .args(["--to", "bash", "--mode", "partial"])
        .output()
        .expect("failed to run emulate command");
    assert!(
        out.status.success(),
        "expected partial success, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Skipping rule (partial mode)"));
    assert!(stdout.contains("Emulation Artifact (bash)"));
}

#[test]
fn emulate_file_size_generates_materialized_plan_and_powershell_size() {
    let root = temp_config_root();
    let out_dir = root.join("exports");
    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "emulate",
            "--rule",
            "[file:size > 2400]",
            "--to",
            "spuc-agent",
            "--to",
            "powershell",
            "--to",
            "bash",
            "--output",
        ])
        .arg(&out_dir)
        .output()
        .expect("failed to run emulate command");
    assert!(
        out.status.success(),
        "emulate command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json_path = fs::read_dir(&out_dir)
        .expect("exports dir missing")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .find(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
        .expect("spuc-agent json export missing");
    let raw_json = fs::read_to_string(json_path).expect("read json export");
    let parsed: Value = serde_json::from_str(&raw_json).expect("valid json export");
    assert_eq!(parsed["execution_plan"]["files"][0]["size_bytes"], 2500);

    let ps_path = fs::read_dir(&out_dir)
        .expect("exports dir missing")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .find(|path| path.extension().and_then(|e| e.to_str()) == Some("ps1"))
        .expect("powershell export missing");
    let ps = fs::read_to_string(ps_path).expect("missing powershell file");
    assert!(ps.contains("$SizeBytes = 2500"));
    assert!(ps.contains("WriteAllBytes"));

    let bash_path = fs::read_dir(&out_dir)
        .expect("exports dir missing")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .find(|path| path.extension().and_then(|e| e.to_str()) == Some("sh"))
        .expect("bash export missing");
    let bash = fs::read_to_string(bash_path).expect("missing bash file");
    assert!(bash.contains("TARGET_SIZE=2500"));
    assert!(bash.contains("truncate -s"));
}

#[test]
fn emulate_file_hash_rule_fails_and_does_not_create_ability() {
    let root = temp_config_root();
    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "emulate",
            "--rule",
            "[file:hashes.MD5 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']",
            "--to",
            "spuc-agent",
        ])
        .output()
        .expect("failed to run emulate command");
    assert!(
        !out.status.success(),
        "expected strict emulate failure for hash file predicate"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Hash-constrained file predicates are not materializable"));

    let abilities_dir = root.join("abilities");
    if abilities_dir.exists() {
        let count = fs::read_dir(abilities_dir)
            .expect("read abilities dir")
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
            .count();
        assert_eq!(count, 0, "no ability should be created for hash-only rules");
    }
}

#[test]
fn emulate_artifact_payload_regex_generates_materialized_content() {
    let root = temp_config_root();
    let out_dir = root.join("exports");
    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "emulate",
            "--rule",
            "[artifact:payload_bin MATCHES '^MZ[0-9]{2}$']",
            "--to",
            "spuc-agent",
            "--to",
            "powershell",
            "--output",
        ])
        .arg(&out_dir)
        .output()
        .expect("failed to run emulate command");
    assert!(
        out.status.success(),
        "emulate command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json_path = fs::read_dir(&out_dir)
        .expect("exports dir missing")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .find(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
        .expect("spuc-agent json export missing");
    let raw_json = fs::read_to_string(json_path).expect("read json export");
    let parsed: Value = serde_json::from_str(&raw_json).expect("valid json export");
    assert_eq!(
        parsed["execution_plan"]["files"][0]["content_literal"],
        "MZ00"
    );

    let ps_path = fs::read_dir(&out_dir)
        .expect("exports dir missing")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .find(|path| path.extension().and_then(|e| e.to_str()) == Some("ps1"))
        .expect("powershell export missing");
    let ps = fs::read_to_string(ps_path).expect("missing powershell file");
    assert!(ps.contains("WriteAllText"));
    assert!(ps.contains("MZ00"));
}

#[test]
fn emulate_artifact_payload_hex_rule_fails_and_does_not_create_ability() {
    let root = temp_config_root();
    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "emulate",
            "--rule",
            "[artifact:payload_bin = h'4d5a']",
            "--to",
            "spuc-agent",
        ])
        .output()
        .expect("failed to run emulate command");
    assert!(
        !out.status.success(),
        "expected strict emulate failure for hex payload predicate"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("does not materialize hex artifact:payload_bin values yet"));

    let abilities_dir = root.join("abilities");
    if abilities_dir.exists() {
        let count = fs::read_dir(abilities_dir)
            .expect("read abilities dir")
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
            .count();
        assert_eq!(
            count, 0,
            "no ability should be created for unsupported hex payload rules"
        );
    }
}

#[test]
fn emulate_registry_rule_generates_registry_artifacts() {
    let root = temp_config_root();
    let out_dir = root.join("exports");
    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "emulate",
            "--rule",
            "[windows-registry-key:key = 'HKEY_CURRENT_USER\\\\Software\\\\SPUC\\\\Stage' AND windows-registry-key:values[*].name = 'Stage' AND windows-registry-key:values[*].data = 'Ready']",
            "--to",
            "spuc-agent",
            "--to",
            "powershell",
            "--output",
        ])
        .arg(&out_dir)
        .output()
        .expect("failed to run emulate command");
    assert!(
        out.status.success(),
        "emulate command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json_path = fs::read_dir(&out_dir)
        .expect("exports dir missing")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .find(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
        .expect("spuc-agent json export missing");
    let raw_json = fs::read_to_string(json_path).expect("read json export");
    let parsed: Value = serde_json::from_str(&raw_json).expect("valid json export");
    assert_eq!(
        parsed["execution_plan"]["registry"][0]["value_name"],
        "Stage"
    );
    assert_eq!(
        parsed["execution_plan"]["registry"][0]["value_data"],
        "Ready"
    );

    let ps_path = fs::read_dir(&out_dir)
        .expect("exports dir missing")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .find(|path| path.extension().and_then(|e| e.to_str()) == Some("ps1"))
        .expect("powershell export missing");
    let ps = fs::read_to_string(ps_path).expect("missing powershell file");
    assert!(ps.contains("New-ItemProperty"));
    assert!(ps.contains("materialized registry key"));
}

#[test]
fn emulate_network_source_ip_rule_fails_and_does_not_create_ability() {
    let root = temp_config_root();
    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "emulate",
            "--rule",
            "[network-traffic:src_ref.value = '10.0.0.5']",
            "--to",
            "bash",
        ])
        .output()
        .expect("failed to run emulate command");
    assert!(
        !out.status.success(),
        "expected strict emulate failure for source-side network predicate"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("source-side fields are not materializable"));

    let abilities_dir = root.join("abilities");
    if abilities_dir.exists() {
        let count = fs::read_dir(abilities_dir)
            .expect("read abilities dir")
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
            .count();
        assert_eq!(
            count, 0,
            "no ability should be created for unsupported source-side network rules"
        );
    }
}

#[test]
fn emulate_network_destination_generates_bash_and_spuc_agent_artifacts() {
    let root = temp_config_root();
    let out_dir = root.join("exports");
    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "emulate",
            "--rule",
            "[network-traffic:dst_ref.value = 'example.com' AND network-traffic:dst_port = 53 AND network-traffic:protocols = 'udp']",
            "--to",
            "spuc-agent",
            "--to",
            "bash",
            "--output",
        ])
        .arg(&out_dir)
        .output()
        .expect("failed to run emulate command");
    assert!(
        out.status.success(),
        "emulate command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json_path = fs::read_dir(&out_dir)
        .expect("exports dir missing")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .find(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
        .expect("spuc-agent json export missing");
    let raw_json = fs::read_to_string(json_path).expect("read json export");
    let parsed: Value = serde_json::from_str(&raw_json).expect("valid json export");
    assert_eq!(
        parsed["execution_plan"]["network"][0]["destination"],
        "example.com"
    );
    assert_eq!(parsed["execution_plan"]["network"][0]["port"], 53);
    assert_eq!(parsed["execution_plan"]["network"][0]["protocol"], "udp");

    let bash_path = fs::read_dir(&out_dir)
        .expect("exports dir missing")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .find(|path| path.extension().and_then(|e| e.to_str()) == Some("sh"))
        .expect("bash export missing");
    let bash = fs::read_to_string(bash_path).expect("missing bash file");
    assert!(bash.contains("NET_DEST='example.com'"));
    assert!(bash.contains("NET_PROTO='udp'"));
}

#[test]
fn emulate_exports_atomic_and_caldera_for_registry_parseables() {
    let root = temp_config_root();
    let out_dir = root.join("exports");
    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "emulate",
            "--rule",
            "[windows-registry-key:key = 'HKEY_CURRENT_USER\\\\Software\\\\SPUC\\\\Atomic' AND windows-registry-key:values[*].name = 'Mode' AND windows-registry-key:values[*].data = 'Safe']",
            "--to",
            "atomic-red-team",
            "--to",
            "mitre-caldera",
            "--output",
        ])
        .arg(&out_dir)
        .output()
        .expect("failed to run emulate command");
    assert!(
        out.status.success(),
        "emulate command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let yaml_path = fs::read_dir(&out_dir)
        .expect("exports dir missing")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .find(|path| path.extension().and_then(|e| e.to_str()) == Some("yaml"))
        .expect("atomic red team yaml export missing");
    let yaml = fs::read_to_string(yaml_path).expect("read yaml export");
    assert!(yaml.contains("attack_technique: T0000"));
    assert!(yaml.contains("atomic_tests:"));
    assert!(yaml.contains("[spuc] atomic action trace"));
    assert!(yaml.contains("windows-registry-key:key"));

    let json_path = fs::read_dir(&out_dir)
        .expect("exports dir missing")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .find(|path| {
            path.extension().and_then(|e| e.to_str()) == Some("json")
                && path.to_string_lossy().contains("mitre_caldera")
        })
        .expect("mitre-caldera json export missing");
    let raw_json = fs::read_to_string(json_path).expect("read caldera json export");
    let parsed: Value = serde_json::from_str(&raw_json).expect("valid caldera json export");
    assert!(parsed["platforms"].is_object());
    assert!(parsed["metadata"]["actions"].is_array());
    assert!(raw_json.contains("[spuc] caldera action trace"));
}

#![cfg(feature = "legacy-cli-tests")]

use serde_yaml::Value;
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn spuc_bin() -> String {
    let bin =
        std::env::var("CARGO_BIN_EXE_spuc").unwrap_or_else(|_| "target/debug/spuc".to_string());
    if !Path::new(&bin).exists() {
        let status = Command::new("cargo")
            .args(["build", "-q", "-p", "spuc-cli", "--bin", "spuc"])
            .status()
            .expect("failed to build spuc binary for tests");
        assert!(status.success(), "failed to build spuc binary for tests");
    }
    bin
}

fn temp_config_root() -> std::path::PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock error")
        .as_nanos();
    std::env::temp_dir().join(format!("spuc_cfg_test_{ts}"))
}

fn ability_ids(config_root: &std::path::Path) -> BTreeSet<String> {
    let dir = config_root.join("abilities");
    if !dir.exists() {
        return BTreeSet::new();
    }
    fs::read_dir(dir)
        .expect("list abilities")
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            (path.extension().and_then(|e| e.to_str()) == Some("json")).then(|| {
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default()
                    .to_string()
            })
        })
        .collect()
}

fn run_save_ability(config_root: &std::path::Path, rule: &str) -> String {
    let before = ability_ids(config_root);
    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", config_root)
        .args(["emulate", "--rule", rule, "--to", "spuc-agent"])
        .output()
        .expect("failed to run emulate");
    assert!(
        out.status.success(),
        "emulate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let after = ability_ids(config_root);
    let diff: Vec<_> = after.difference(&before).cloned().collect();
    assert_eq!(diff.len(), 1, "expected exactly one new ability id");
    diff[0].clone()
}

fn read_activity_log(config_root: &std::path::Path) -> Vec<serde_json::Value> {
    let path = config_root
        .join("catalog")
        .join("translation_activities.jsonl");
    if !path.exists() {
        return Vec::new();
    }
    fs::read_to_string(path)
        .expect("read activity log")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid jsonl activity row"))
        .collect()
}

fn strip_ansi_escape_codes(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_escape = false;
    while let Some(ch) = chars.next() {
        if in_escape {
            if ('@'..='~').contains(&ch) {
                in_escape = false;
            }
            continue;
        }
        if ch == '\u{1b}' && matches!(chars.peek(), Some('[')) {
            in_escape = true;
            let _ = chars.next();
            continue;
        }
        out.push(ch);
    }
    out
}

fn first_token_with_prefix(input: &str, prefix: &str) -> Option<String> {
    strip_ansi_escape_codes(input)
        .split_whitespace()
        .find(|token| token.starts_with(prefix))
        .map(|token| token.trim().to_string())
}

#[test]
fn catalog_rules_and_search_work() {
    let root = temp_config_root();
    let rule = "[process:command_line MATCHES '^.*echo.*$']";
    let _ability_id = run_save_ability(&root, rule);

    let listed = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["rules", "list"])
        .output()
        .expect("failed to run rules list");
    assert!(
        listed.status.success(),
        "rules list failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed_stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(listed_stdout.contains("Rules (1/1 entry)"));
    assert!(listed_stdout.contains(rule));

    let rules = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["rules", "search"])
        .output()
        .expect("failed to run rules search");
    assert!(
        rules.status.success(),
        "rules search failed: {}",
        String::from_utf8_lossy(&rules.stderr)
    );
    let stdout = String::from_utf8_lossy(&rules.stdout);
    assert!(stdout.contains("RULE_ID"));
    assert!(stdout.contains("EMULABLE"));
    assert!(stdout.contains(rule));

    let search = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["rules", "search", "echo"])
        .output()
        .expect("failed to run rules search");
    assert!(
        search.status.success(),
        "rules search failed: {}",
        String::from_utf8_lossy(&search.stderr)
    );
    let stdout = String::from_utf8_lossy(&search.stdout);
    assert!(stdout.contains("Rules ("));
    assert!(stdout.contains("1/1 entry"));
    assert!(stdout.contains(rule));
}

#[test]
fn catalog_rules_include_translation_history_and_show_details() {
    let root = temp_config_root();
    let _ability_id = run_save_ability(&root, "[process:command_line MATCHES '^.*echo.*$']");
    let translated_rule = "[process:name = 'cmd.exe']";

    let translate = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["translate", "--rule", translated_rule, "--to", "sigma"])
        .output()
        .expect("failed to run translate");
    assert!(
        translate.status.success(),
        "translate failed: {}",
        String::from_utf8_lossy(&translate.stderr)
    );

    let rules = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["rules", "search", "cmd.exe"])
        .output()
        .expect("failed to run rules search");
    assert!(
        rules.status.success(),
        "rules search failed: {}",
        String::from_utf8_lossy(&rules.stderr)
    );
    let rules_out = String::from_utf8_lossy(&rules.stdout);
    assert!(rules_out.contains("Rules ("));
    assert!(rules_out.contains("1/2 entries"));
    assert!(rules_out.contains(translated_rule));
    let rule_id = first_token_with_prefix(&rules_out, "rule-").expect("missing rule id");

    let show = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["rules", "show", &rule_id])
        .output()
        .expect("failed to run rules show");
    assert!(
        show.status.success(),
        "rules show failed: {}",
        String::from_utf8_lossy(&show.stderr)
    );
    let show_out = String::from_utf8_lossy(&show.stdout);
    assert!(show_out.contains("\u{1b}[33m"));
    assert!(show_out.contains("Rule Detail"));
    assert!(show_out.contains("commands: emulate, translate"));
    assert!(show_out.contains(translated_rule));
}

#[test]
fn plan_intrusion_set_from_catalog_and_persist_manifest() {
    let root = temp_config_root();
    let ability_1 = run_save_ability(&root, "[process:command_line MATCHES '^.*echo.*$']");
    let ability_2 = run_save_ability(&root, "[file:name MATCHES '^.*log$']");

    let out_dir = root.join("intrusion_sets");
    let out_path =
        out_dir.join("spuc-intrusion-set-linux-validation_intrusion_set-spuc-agent.yaml");
    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "plan",
            "--name",
            "Validation intrusion set",
            "--platform",
            "linux",
            "--executor",
            "spuc-agent",
            "--ability",
            &ability_2,
            "--ability",
            &ability_1,
            "--order",
            &format!("{ability_1},{ability_2}"),
            "--output",
        ])
        .arg(&out_dir)
        .args(["--show", "manifest"])
        .output()
        .expect("failed to run plan");
    assert!(
        out.status.success(),
        "plan failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let raw = fs::read_to_string(&out_path).expect("intrusion-set manifest file missing");
    let manifest: Value = serde_yaml::from_str(&raw).expect("invalid intrusion-set yaml");
    assert_eq!(manifest["schema_version"], Value::String("1.0".to_string()));
    assert_eq!(
        manifest["name"],
        Value::String("Validation intrusion set".to_string())
    );
    assert_eq!(manifest["confidence"], Value::Number(70.into()));

    let steps = manifest["steps"]
        .as_sequence()
        .expect("steps should be sequence");
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0]["ability_ref"], Value::String(ability_1));
    assert_eq!(steps[1]["ability_ref"], Value::String(ability_2));
}

#[test]
fn plan_order_accepts_mixed_id_and_index_tokens() {
    let root = temp_config_root();
    let ability_1 = run_save_ability(&root, "[process:command_line MATCHES '^.*echo.*$']");
    let ability_2 = run_save_ability(&root, "[file:name MATCHES '^.*log$']");
    let ability_3 = run_save_ability(&root, "[directory:path MATCHES '^/tmp/.*$']");

    let out_dir = root.join("intrusion_sets");
    let out_path = out_dir.join("spuc-intrusion-set-linux-mixed_order-spuc-agent.yaml");
    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "plan",
            "--name",
            "Mixed order",
            "--platform",
            "linux",
            "--executor",
            "spuc-agent",
            "--ability",
            &ability_1,
            "--ability",
            &ability_2,
            "--ability",
            &ability_3,
            "--order",
            &format!("{ability_3},2,1"),
            "--output",
        ])
        .arg(&out_dir)
        .args(["--show", "manifest"])
        .output()
        .expect("failed to run plan mixed order");
    assert!(
        out.status.success(),
        "plan mixed order failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Intrusion set saved to"));
    assert!(stdout.contains(&out_path.display().to_string()));

    let raw =
        fs::read_to_string(&out_path).expect("mixed order intrusion-set manifest file missing");
    let manifest: Value = serde_yaml::from_str(&raw).expect("invalid intrusion-set yaml");
    let steps = manifest["steps"]
        .as_sequence()
        .expect("steps should be sequence");
    assert_eq!(steps.len(), 3);
    assert_eq!(steps[0]["ability_ref"], Value::String(ability_3));
    assert_eq!(steps[1]["ability_ref"], Value::String(ability_2));
    assert_eq!(steps[2]["ability_ref"], Value::String(ability_1));
}

#[test]
fn guided_plan_console_supports_set_search_select_and_build() {
    let root = temp_config_root();
    let echo_ability = run_save_ability(&root, "[process:command_line MATCHES '^.*echo.*$']");
    let _tmp_ability = run_save_ability(&root, "[file:name MATCHES '^.*\\\\.tmp$']");

    let out_dir = root.join("intrusion_sets");
    let out_path = out_dir.join("spuc-intrusion-set-linux-guided_intrusion_set-spuc-agent.yaml");
    let mut cmd = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "plan",
            "--name",
            "Initial name",
            "--platform",
            "linux",
            "--guided",
            "--show",
            "manifest",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn guided plan command");

    let script = format!(
        "set NAME=Guided intrusion set\nset OUTPUT={}\nsearch echo\nshow_ability 1\nselect 1\nback\nbuild spuc-agent\n",
        out_dir.display()
    );
    cmd.stdin
        .as_mut()
        .expect("stdin missing")
        .write_all(script.as_bytes())
        .expect("failed to write script");

    let out = cmd.wait_with_output().expect("wait output");
    assert!(
        out.status.success(),
        "guided plan failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Intrusion set planner initialized"));
    assert!(stdout.contains("spuc (plan)>"));
    assert!(stdout.contains("spuc (plan @ catalog)>"));
    assert!(stdout.contains("Ability detail"));
    assert!(stdout.contains("Intrusion set saved to"));
    assert!(stdout.contains(&out_path.display().to_string()));
    let plain_stdout = strip_ansi_escape_codes(&stdout);
    assert!(
        plain_stdout.contains("Intrusion set planner initialized.\n\nVariables description:"),
        "expected a blank line after planner initialization message"
    );
    assert!(
        plain_stdout.contains("Variables description:\n  INTRUSION_SET_ID:"),
        "expected no blank line after variables description title"
    );
    let docs_idx = plain_stdout
        .find("Variables description:")
        .expect("variable meaning block not found");
    let current_cfg_idx = plain_stdout
        .find("⚙️ Current configuration:")
        .expect("current configuration header not found");
    let values_idx = plain_stdout
        .find("INTRUSION_SET_ID=")
        .expect("variable value block not found");
    let selected_idx = plain_stdout
        .find("Selected abilities (0)")
        .expect("selected abilities block not found");
    assert!(
        docs_idx < current_cfg_idx && current_cfg_idx < values_idx && values_idx < selected_idx,
        "expected docs -> current configuration -> current values -> selected abilities ordering"
    );
    assert!(
        !plain_stdout.contains("🧩 Intrusion set planner initialized."),
        "planner opening message must not contain an icon"
    );
    assert!(
        plain_stdout.contains("CONFIDENCE: Minimum ability confidence filter (default 70).\n\n⚙️ Current configuration:"),
        "expected a blank line before current configuration header"
    );
    assert!(
        plain_stdout.contains("CONFIDENCE=70\n\n🧩 Selected abilities (0)"),
        "expected a blank line between variable values and selected abilities"
    );

    let raw = fs::read_to_string(&out_path).expect("guided manifest missing");
    let manifest_yaml: serde_yaml::Value = serde_yaml::from_str(&raw).expect("invalid yaml");
    assert_eq!(manifest_yaml["name"], "Guided intrusion set");
    assert_eq!(manifest_yaml["steps"][0]["ability_ref"], echo_ability);
}

#[test]
fn plan_supports_multiple_output_blocks() {
    let root = temp_config_root();
    let ability_id = run_save_ability(&root, "[process:command_line MATCHES '^.*echo.*$']");

    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "plan",
            "--name",
            "Show intrusion set",
            "--platform",
            "linux",
            "--executor",
            "spuc-agent",
            "--ability",
            &ability_id,
            "--show",
            "summary,canonical,manifest",
        ])
        .output()
        .expect("failed to run plan with show blocks");
    assert!(
        out.status.success(),
        "plan with show failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Intrusion Set Summary"));
    assert!(stdout.contains("Intrusion Set Canonical JSON"));
    assert!(stdout.contains("Intrusion Set Manifest"));
}

#[test]
fn plan_default_output_filename_is_representative() {
    let root = temp_config_root();
    let ability_id = run_save_ability(&root, "[process:command_line MATCHES '^.*echo.*$']");
    let expected_path = root
        .join("intrusion_sets")
        .join("spuc-intrusion-set-any-blue_team_validation-spuc-agent.yaml");

    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "plan",
            "--name",
            "Blue Team Validation",
            "--platform",
            "any",
            "--executor",
            "spuc-agent",
            "--ability",
            &ability_id,
            "--show",
            "manifest",
        ])
        .output()
        .expect("failed to run plan with default output");
    assert!(
        out.status.success(),
        "plan with default output failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Intrusion set saved to"));
    assert!(stdout.contains(&expected_path.display().to_string()));
    assert!(
        expected_path.exists(),
        "expected representative intrusion-set filename"
    );
}

#[test]
fn plan_supports_dummy_abilities_and_build_artifacts() {
    let root = temp_config_root();
    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "plan",
            "--name",
            "Dummy Flow",
            "--platform",
            "any",
            "--executor",
            "spuc-agent",
            "--dummy-sleep",
            "3",
            "--dummy-label",
            "phase-a",
            "--show",
            "manifest",
        ])
        .output()
        .expect("failed to run plan dummy abilities");
    assert!(
        out.status.success(),
        "plan dummy abilities failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Artifact (spuc-agent) saved to"));
    assert!(stdout.contains("abl-dummy-sleep"));
    assert!(stdout.contains("abl-dummy-label"));

    let out_path = root
        .join("intrusion_sets")
        .join("spuc-intrusion-set-any-dummy_flow-spuc-agent.yaml");
    let raw = fs::read_to_string(&out_path).expect("dummy flow manifest missing");
    let manifest: Value = serde_yaml::from_str(&raw).expect("invalid dummy flow yaml");
    let steps = manifest["steps"]
        .as_sequence()
        .expect("steps should be sequence");
    assert_eq!(steps.len(), 2);
    let step_refs: Vec<String> = steps
        .iter()
        .filter_map(|step| step["ability_ref"].as_str().map(ToOwned::to_owned))
        .collect();
    assert!(
        step_refs.iter().any(|id| id.contains("abl-dummy-sleep")),
        "expected sleep dummy ability in steps"
    );
    assert!(
        step_refs.iter().any(|id| id.contains("abl-dummy-label")),
        "expected label dummy ability in steps"
    );
}

#[test]
fn plan_builds_materialized_file_artifacts_for_powershell_spuc_agent_and_bash() {
    let root = temp_config_root();
    let ability_id = run_save_ability(&root, "[file:size > 2400]");
    let out_dir = root.join("intrusion_sets");

    let ps = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "plan",
            "--name",
            "File Size Materialization",
            "--platform",
            "linux",
            "--executor",
            "powershell",
            "--ability",
            &ability_id,
            "--output",
        ])
        .arg(&out_dir)
        .args(["--show", "manifest"])
        .output()
        .expect("failed to run plan build powershell");
    assert!(
        ps.status.success(),
        "plan powershell failed: {}",
        String::from_utf8_lossy(&ps.stderr)
    );
    let ps_artifact = fs::read_dir(&out_dir)
        .expect("list out dir")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .find(|path| {
            path.extension().and_then(|e| e.to_str()) == Some("ps1")
                && path
                    .to_string_lossy()
                    .contains("file_size_materialization-powershell")
        })
        .expect("powershell artifact not found");
    let ps_raw = fs::read_to_string(ps_artifact).expect("read powershell artifact");
    assert!(ps_raw.contains("$SizeBytes = 2500"));

    let agent = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "plan",
            "--name",
            "File Size Materialization",
            "--platform",
            "linux",
            "--executor",
            "spuc-agent",
            "--ability",
            &ability_id,
            "--output",
        ])
        .arg(&out_dir)
        .args(["--show", "manifest"])
        .output()
        .expect("failed to run plan build spuc-agent");
    assert!(
        agent.status.success(),
        "plan spuc-agent failed: {}",
        String::from_utf8_lossy(&agent.stderr)
    );
    let agent_artifact = fs::read_dir(&out_dir)
        .expect("list out dir")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .find(|path| {
            path.extension().and_then(|e| e.to_str()) == Some("json")
                && path
                    .to_string_lossy()
                    .contains("file_size_materialization-spuc-agent")
        })
        .expect("spuc-agent artifact not found");
    let raw = fs::read_to_string(agent_artifact).expect("read spuc-agent artifact");
    let parsed: serde_json::Value = serde_json::from_str(&raw).expect("valid spuc-agent json");
    assert_eq!(parsed["execution_plan"]["files"][0]["size_bytes"], 2500);

    let bash = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "plan",
            "--name",
            "File Size Materialization",
            "--platform",
            "linux",
            "--executor",
            "bash",
            "--ability",
            &ability_id,
            "--output",
        ])
        .arg(&out_dir)
        .args(["--show", "manifest"])
        .output()
        .expect("failed to run plan build bash");
    assert!(
        bash.status.success(),
        "plan bash failed: {}",
        String::from_utf8_lossy(&bash.stderr)
    );
    let bash_artifact = fs::read_dir(&out_dir)
        .expect("list out dir")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .find(|path| {
            path.extension().and_then(|e| e.to_str()) == Some("sh")
                && path
                    .to_string_lossy()
                    .contains("file_size_materialization-bash")
        })
        .expect("bash artifact not found");
    let bash_raw = fs::read_to_string(bash_artifact).expect("read bash artifact");
    assert!(bash_raw.contains("TARGET_SIZE=2500"));
}

#[test]
fn guided_plan_can_add_dummy_abilities_and_build() {
    let root = temp_config_root();
    let out_dir = root.join("intrusion_sets");
    let out_path = out_dir.join("spuc-intrusion-set-any-guided_dummy-spuc-agent.yaml");

    let mut cmd = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "plan",
            "--name",
            "Guided dummy",
            "--platform",
            "any",
            "--guided",
            "--show",
            "manifest",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn guided plan for dummy abilities");

    let script = format!(
        "set OUTPUT={}\nadd_sleep 2\nadd_label prep-phase\nbuild spuc-agent\n",
        out_dir.display()
    );
    cmd.stdin
        .as_mut()
        .expect("stdin missing")
        .write_all(script.as_bytes())
        .expect("failed to write guided dummy script");

    let out = cmd.wait_with_output().expect("wait output");
    assert!(
        out.status.success(),
        "guided plan with dummy abilities failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Dummy ability selected"));
    assert!(stdout.contains("Intrusion set saved to"));
    assert!(stdout.contains(&out_path.display().to_string()));

    let raw = fs::read_to_string(&out_path).expect("guided dummy manifest missing");
    let manifest_yaml: serde_yaml::Value = serde_yaml::from_str(&raw).expect("invalid yaml");
    let steps = manifest_yaml["steps"]
        .as_sequence()
        .expect("steps should be sequence");
    assert_eq!(steps.len(), 2);
    assert!(steps[0]["ability_ref"]
        .as_str()
        .is_some_and(|id| id.contains("abl-dummy")));
    assert!(steps[1]["ability_ref"]
        .as_str()
        .is_some_and(|id| id.contains("abl-dummy")));
}

#[test]
fn guided_plan_help_supports_topic_help_and_hides_variable_docs() {
    let root = temp_config_root();
    let mut cmd = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "plan",
            "--name",
            "Help check",
            "--platform",
            "linux",
            "--guided",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn guided plan help command");

    let script = "help\nhelp build\nexit\n";
    cmd.stdin
        .as_mut()
        .expect("stdin missing")
        .write_all(script.as_bytes())
        .expect("failed to write guided help script");

    let out = cmd.wait_with_output().expect("wait output");
    assert!(
        out.status.success(),
        "guided plan help flow failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let plain_stdout = strip_ansi_escape_codes(&String::from_utf8_lossy(&out.stdout));
    assert!(plain_stdout.contains("Commands available:"));
    assert!(
        plain_stdout.contains("build <spuc-agent|bash|powershell|atomic-red-team|mitre-caldera>")
    );
    assert!(plain_stdout.contains("Example: build spuc-agent"));
    assert_eq!(
        plain_stdout.matches("Variables description:").count(),
        1,
        "variable descriptions must appear only in show output, not in help output"
    );
}

#[test]
fn guided_plan_list_enumerates_all_abilities() {
    let root = temp_config_root();
    let windows_ability =
        run_save_ability(&root, "[process:command_line MATCHES '^.*cmd\\\\.exe.*$']");
    let linux_ability = run_save_ability(&root, "[process:command_line MATCHES '^.*/bin/echo.*$']");

    let mut cmd = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "plan",
            "--name",
            "List all",
            "--platform",
            "linux",
            "--guided",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn guided plan list command");

    let script = "list\nexit\n";
    cmd.stdin
        .as_mut()
        .expect("stdin missing")
        .write_all(script.as_bytes())
        .expect("failed to write guided list script");

    let out = cmd.wait_with_output().expect("wait output");
    assert!(
        out.status.success(),
        "guided plan list flow failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&windows_ability));
    assert!(stdout.contains(&linux_ability));
}

#[test]
fn explore_plan_prompts_for_missing_name_and_platform() {
    let root = temp_config_root();
    let mut cmd = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["explore"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn explore for plan prompt");

    let script = "plan\nPrompted set\nlinux\nexit\nexit\n";
    cmd.stdin
        .as_mut()
        .expect("stdin missing")
        .write_all(script.as_bytes())
        .expect("failed to write explore plan prompt script");

    let out = cmd.wait_with_output().expect("wait output");
    assert!(
        out.status.success(),
        "explore plan prompt flow failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let plain_stdout = strip_ansi_escape_codes(&String::from_utf8_lossy(&out.stdout));
    assert!(plain_stdout.contains("Intrusion set name>"));
    assert!(plain_stdout.contains("Platforms (comma-separated: linux,windows,macos,any)>"));
    assert!(plain_stdout.contains("NAME=Prompted set"));
    assert!(plain_stdout.contains("PLATFORM=linux"));
}

#[test]
fn guided_plan_reprompts_for_incompatible_platform_selection() {
    let root = temp_config_root();
    let windows_ability =
        run_save_ability(&root, "[process:command_line MATCHES '^.*cmd\\\\.exe.*$']");

    let mut cmd = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "plan",
            "--guided",
            "--name",
            "Platform prompt",
            "--ability",
            &windows_ability,
            "--show",
            "manifest",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn guided plan for platform reprompt");

    let script = "linux\nwindows\nbuild spuc-agent\n";
    cmd.stdin
        .as_mut()
        .expect("stdin missing")
        .write_all(script.as_bytes())
        .expect("failed to write guided reprompt script");

    let out = cmd.wait_with_output().expect("wait output");
    assert!(
        out.status.success(),
        "guided plan reprompt flow failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let plain_stdout = strip_ansi_escape_codes(&String::from_utf8_lossy(&out.stdout));
    assert!(plain_stdout.contains("Incompatible PLATFORM for selected abilities"));
    assert!(
        plain_stdout
            .matches("Platforms (comma-separated: linux,windows,macos,any)>")
            .count()
            >= 2,
        "platform prompt should appear again after incompatible input"
    );
    assert!(plain_stdout.contains("PLATFORM=windows"));
}

#[test]
fn explore_emulate_uses_translate_style_syntax() {
    let root = temp_config_root();
    let exports = root.join("exports");

    let mut cmd = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["explore"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn spuc explore");

    let script = format!(
        "emulate [process:command_line MATCHES '^.*echo.*$'] to spuc-agent,bash out={} conf=80\nrules search\nexit\n",
        exports.display()
    );
    cmd.stdin
        .as_mut()
        .expect("stdin missing")
        .write_all(script.as_bytes())
        .expect("failed to write explore script");

    let out = cmd.wait_with_output().expect("wait output");
    assert!(
        out.status.success(),
        "spuc explore flow failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("spuc>"));
    assert!(stdout.contains("Ability"));
    assert!(stdout.contains("in catalog"));
    assert!(stdout.contains("Rules ("));
    assert!(stdout.contains("1/1 entry"));
    assert!(exports.exists(), "expected export directory");
    let exported: Vec<_> = fs::read_dir(&exports)
        .expect("exports missing")
        .filter_map(|entry| entry.ok())
        .collect();
    assert_eq!(exported.len(), 2);
}

#[test]
fn emulate_reuses_same_ability_id_for_same_rule() {
    let root = temp_config_root();
    let rule = "[process:command_line MATCHES '^.*echo.*$']";

    let first = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["emulate", "--rule", rule, "--to", "spuc-agent"])
        .output()
        .expect("first emulate");
    assert!(first.status.success());

    let second = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["emulate", "--rule", rule, "--to", "spuc-agent"])
        .output()
        .expect("second emulate");
    assert!(second.status.success());
    let second_out = String::from_utf8_lossy(&second.stdout);
    assert!(second_out.contains("updated in catalog"));

    let ability_files: Vec<_> = fs::read_dir(root.join("abilities"))
        .expect("abilities dir")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect();
    assert_eq!(ability_files.len(), 1);
}

#[test]
fn translate_populates_hidden_emulation_and_catalog_rule() {
    let root = temp_config_root();
    let rule = "[process:command_line MATCHES '^.*echo.*$']";

    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["translate", "--rule", rule, "--to", "sigma"])
        .output()
        .expect("translate");
    assert!(out.status.success());

    let list = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["rules", "search"])
        .output()
        .expect("rules search");
    assert!(list.status.success());
    let list_out = String::from_utf8_lossy(&list.stdout);
    assert!(list_out.contains(rule));

    let activities = read_activity_log(&root);
    assert!(activities.iter().any(|item| {
        item["command"] == "emulate"
            && item["hidden"].as_bool() == Some(true)
            && item["rule"] == rule
    }));
}

#[test]
fn hidden_dual_flow_respects_cache_and_refresh() {
    let root = temp_config_root();
    let rule = "[process:command_line MATCHES '^.*echo.*$']";

    let first = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["emulate", "--rule", rule, "--to", "spuc-agent"])
        .output()
        .expect("first emulate");
    assert!(first.status.success());

    let count_hidden_translate = |entries: &[serde_json::Value]| {
        entries
            .iter()
            .filter(|item| item["command"] == "translate" && item["hidden"].as_bool() == Some(true))
            .count()
    };

    let count_first = count_hidden_translate(&read_activity_log(&root));
    assert!(count_first > 0);

    let second = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["emulate", "--rule", rule, "--to", "spuc-agent"])
        .output()
        .expect("second emulate");
    assert!(second.status.success());
    let count_second = count_hidden_translate(&read_activity_log(&root));
    assert_eq!(count_second, count_first);

    let third = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["emulate", "--rule", rule, "--to", "spuc-agent", "--refresh"])
        .output()
        .expect("refresh emulate");
    assert!(third.status.success());
    let count_third = count_hidden_translate(&read_activity_log(&root));
    assert!(count_third > count_second);
}

#[test]
fn catalog_list_shows_full_rule_without_truncation() {
    let root = temp_config_root();
    let long_rule = "[process:command_line MATCHES '^.*very-long-command-segment-1234567890-abcdefghij-klmnopqrst-uvwxyz.*$']";

    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["emulate", "--rule", long_rule, "--to", "spuc-agent"])
        .output()
        .expect("emulate long rule");
    assert!(out.status.success());

    let list = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["rules", "search"])
        .output()
        .expect("rules search");
    assert!(list.status.success());
    let list_out = String::from_utf8_lossy(&list.stdout);
    assert!(list_out.contains(long_rule));
}

#[test]
fn catalog_rules_include_name_confidence_emulable_and_rule_columns() {
    let root = temp_config_root();
    let rule = "[process:command_line MATCHES '^.*echo.*$']";
    let _ability_id = run_save_ability(&root, rule);

    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["rules", "search"])
        .output()
        .expect("rules search");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("RULE_ID"));
    assert!(stdout.contains("NAME"));
    assert!(stdout.contains("CONFIDENCE"));
    assert!(stdout.contains("EMULABLE"));
    assert!(stdout.contains("yes"));
    assert!(stdout.contains(rule));
}

#[test]
fn catalog_search_returns_only_matching_rows() {
    let root = temp_config_root();
    let matching_rule = "[process:name = 'cmd.exe']";
    let other_rule = "[process:command_line MATCHES '^.*echo.*$']";

    let translate = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "translate",
            "--rule",
            matching_rule,
            "--to",
            "sigma",
            "--to",
            "eql",
        ])
        .output()
        .expect("translate");
    assert!(translate.status.success());

    let emulate = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["emulate", "--rule", other_rule, "--to", "spuc-agent"])
        .output()
        .expect("emulate");
    assert!(emulate.status.success());

    let cat = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["rules", "search", "cmd.exe"])
        .output()
        .expect("rules search");
    assert!(cat.status.success());
    let stdout = String::from_utf8_lossy(&cat.stdout);
    let plain_stdout = strip_ansi_escape_codes(&stdout);
    assert!(stdout.contains("Rules ("));
    assert!(stdout.contains(matching_rule));
    assert!(!stdout.contains(other_rule));
    assert!(plain_stdout.contains("Rules (1/2 entries)\n\n"));
}

#[test]
fn rules_and_adversaries_can_export_objects() {
    let root = temp_config_root();
    let rule = "[process:name = 'cmd.exe']";
    let exports = root.join("exports");
    fs::create_dir_all(&exports).expect("create exports dir");
    let ability_id = run_save_ability(&root, "[process:command_line MATCHES '^.*echo.*$']");
    let out_dir = root.join("intrusion_sets");

    let out = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["translate", "--rule", rule, "--to", "sigma"])
        .output()
        .expect("translate");
    assert!(out.status.success());

    let plan = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "plan",
            "--name",
            "Adversary export test",
            "--platform",
            "linux",
            "--executor",
            "spuc-agent",
            "--ability",
            &ability_id,
            "--output",
        ])
        .arg(&out_dir)
        .args(["--show", "manifest"])
        .output()
        .expect("plan");
    assert!(plan.status.success());

    let adversary_out = exports.join("adversary_out");
    let adversaries = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "adversaries",
            "export",
            "1",
            "--to",
            "bash",
            "--output",
            adversary_out.to_str().expect("adversary out"),
        ])
        .output()
        .expect("adversaries export");
    assert!(adversaries.status.success());
    let exported_adv: Vec<_> = fs::read_dir(&adversary_out)
        .expect("read adversary export dir")
        .filter_map(|entry| entry.ok())
        .collect();
    assert!(!exported_adv.is_empty());

    let rules_out = exports.join("rules_out");
    let rules = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "rules",
            "export",
            "1",
            "--to",
            "spuc-agent",
            "--output",
            rules_out.to_str().expect("rules out"),
        ])
        .output()
        .expect("rules export");
    assert!(rules.status.success());
    let exported_rules: Vec<_> = fs::read_dir(&rules_out)
        .expect("read rules export dir")
        .filter_map(|entry| entry.ok())
        .collect();
    assert!(!exported_rules.is_empty());
}

#[test]
fn rules_can_edit_mutable_fields() {
    let root = temp_config_root();
    let rule = "[process:command_line MATCHES '^.*echo.*$']";
    let _ability_id = run_save_ability(&root, rule);

    let edit = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "rules",
            "edit",
            "1",
            "--name",
            "Edited rule",
            "--description",
            "Edited description",
            "--confidence",
            "81",
        ])
        .output()
        .expect("rules edit");
    assert!(edit.status.success());

    let show = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["rules", "show", "1"])
        .output()
        .expect("rules show");
    assert!(show.status.success());
    let stdout = String::from_utf8_lossy(&show.stdout);
    assert!(stdout.contains("Edited rule"));
    assert!(stdout.contains("Edited description"));
    assert!(stdout.contains("81"));
}

#[test]
fn rules_delete_requires_manual_confirmation() {
    let root = temp_config_root();
    let rule = "[process:command_line MATCHES '^.*echo.*$']";
    let _ability_id = run_save_ability(&root, rule);

    let listing = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["rules", "search"])
        .output()
        .expect("rules search");
    assert!(listing.status.success());
    let listing_out = String::from_utf8_lossy(&listing.stdout);
    let rule_id = first_token_with_prefix(&listing_out, "rule-").expect("missing rule id");

    let mut cmd = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["rules", "delete", &rule_id])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rules delete");
    let confirmation = format!("DELETE {}\n", rule_id);
    cmd.stdin
        .as_mut()
        .expect("stdin missing")
        .write_all(confirmation.as_bytes())
        .expect("write confirmation");
    let out = cmd.wait_with_output().expect("wait delete");
    assert!(out.status.success());

    let after = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["rules", "search"])
        .output()
        .expect("rules search after delete");
    assert!(after.status.success());
    let after_out = String::from_utf8_lossy(&after.stdout);
    assert!(!after_out.contains(&rule_id));
}

#[test]
fn catalog_adversaries_list_and_show_details() {
    let root = temp_config_root();
    let ability_id = run_save_ability(&root, "[process:command_line MATCHES '^.*echo.*$']");
    let out_dir = root.join("intrusion_sets");

    let plan = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "plan",
            "--name",
            "Set catalog test",
            "--platform",
            "linux",
            "--executor",
            "spuc-agent",
            "--ability",
            &ability_id,
            "--output",
        ])
        .arg(&out_dir)
        .args(["--show", "manifest"])
        .output()
        .expect("plan for set");
    assert!(plan.status.success());

    let adversaries = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["adversaries", "search"])
        .output()
        .expect("adversaries search");
    assert!(adversaries.status.success());
    let stdout = String::from_utf8_lossy(&adversaries.stdout);
    let plain_stdout = strip_ansi_escape_codes(&stdout);
    assert!(stdout.contains("ADVERSARY_ID"));
    assert!(stdout.contains("PLATFORMS"));
    assert!(stdout.contains("Set catalog test"));
    assert!(plain_stdout.contains("Adversaries (1/1 entry)\n\n"));
    let adversary_id =
        first_token_with_prefix(&stdout, "adversary-").expect("missing adversary id");

    let show = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["adversaries", "show", &adversary_id])
        .output()
        .expect("adversaries show");
    assert!(show.status.success());
    let show_out = String::from_utf8_lossy(&show.stdout);
    assert!(show_out.contains("\u{1b}[33m"));
    assert!(show_out.contains("Adversary Detail"));
    assert!(show_out.contains(&ability_id));
}

#[test]
fn plan_console_supports_export_alias() {
    let root = temp_config_root();
    let ability_id = run_save_ability(&root, "[process:command_line MATCHES '^.*echo.*$']");
    let out_dir = root.join("guided-export-out");

    let mut cmd = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "plan",
            "--guided",
            "--name",
            "Export alias",
            "--platform",
            "linux",
            "--ability",
            &ability_id,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn guided export alias");

    let script = format!("set OUTPUT={}\nexport bash\n", out_dir.display());
    cmd.stdin
        .as_mut()
        .expect("stdin missing")
        .write_all(script.as_bytes())
        .expect("write guided export script");

    let out = cmd.wait_with_output().expect("wait guided export");
    assert!(out.status.success());
    let exported: Vec<_> = fs::read_dir(&out_dir)
        .expect("read guided export dir")
        .filter_map(|entry| entry.ok())
        .collect();
    assert!(!exported.is_empty());
}

#[test]
fn explore_help_catalog_lists_grouped_commands() {
    let root = temp_config_root();
    let mut cmd = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["explore"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn explore for help catalog");

    let script = "help catalog\nhelp rules\nhelp adversaries\nexit\n";
    cmd.stdin
        .as_mut()
        .expect("stdin missing")
        .write_all(script.as_bytes())
        .expect("failed to write explore help catalog script");

    let out = cmd.wait_with_output().expect("wait output");
    assert!(out.status.success());
    let plain_stdout = strip_ansi_escape_codes(&String::from_utf8_lossy(&out.stdout));
    assert!(plain_stdout.contains("open rules catalog console"));
    assert!(plain_stdout.contains("open adversaries catalog console"));
    assert!(plain_stdout.contains("list [limit=<n>]"));
    assert!(plain_stdout.contains("spuc (rules @ rule-...)>"));
    assert!(plain_stdout.contains("spuc (adversaries @ adversary-...)>"));
}

#[test]
fn console_rules_mode_supports_contextual_export_and_back() {
    let root = temp_config_root();
    let rule = "[process:command_line MATCHES '^.*echo.*$']";
    let out_dir = root.join("rules-console-export");
    let _ability_id = run_save_ability(&root, rule);

    let mut cmd = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["console"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn console for rules mode");

    let script = format!(
        "rules\nlist\nshow 1\nexport bash out={}\nback\nback\nexit\n",
        out_dir.display()
    );
    cmd.stdin
        .as_mut()
        .expect("stdin missing")
        .write_all(script.as_bytes())
        .expect("failed to write rules console script");

    let out = cmd.wait_with_output().expect("wait rules console output");
    assert!(out.status.success());
    let plain_stdout = strip_ansi_escape_codes(&String::from_utf8_lossy(&out.stdout));
    assert!(plain_stdout.contains("spuc (rules)>"));
    assert!(plain_stdout.contains("spuc (rules @ rule-"));
    assert!(plain_stdout.contains("Back to rules catalog."));
    assert!(plain_stdout.contains("spuc>"));
    let exported: Vec<_> = fs::read_dir(&out_dir)
        .expect("missing rules export dir")
        .filter_map(|entry| entry.ok())
        .collect();
    assert!(!exported.is_empty());
}

#[test]
fn console_adversaries_mode_supports_contextual_export_and_back() {
    let root = temp_config_root();
    let ability_id = run_save_ability(&root, "[process:command_line MATCHES '^.*echo.*$']");
    let out_dir = root.join("adversaries-console-export");

    let plan = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "plan",
            "--name",
            "Console adversary",
            "--platform",
            "linux",
            "--executor",
            "bash",
            "--ability",
            &ability_id,
            "--output",
        ])
        .arg(root.join("intrusion_sets"))
        .args(["--show", "manifest"])
        .output()
        .expect("plan adversary for console");
    assert!(plan.status.success());

    let mut cmd = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args(["console"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn console for adversaries mode");

    let script = format!(
        "adversaries\nlist\nshow 1\nexport bash out={} show=manifest,artifact\nback\nback\nexit\n",
        out_dir.display()
    );
    cmd.stdin
        .as_mut()
        .expect("stdin missing")
        .write_all(script.as_bytes())
        .expect("failed to write adversaries console script");

    let out = cmd
        .wait_with_output()
        .expect("wait adversaries console output");
    assert!(out.status.success());
    let plain_stdout = strip_ansi_escape_codes(&String::from_utf8_lossy(&out.stdout));
    assert!(plain_stdout.contains("spuc (adversaries)>"));
    assert!(plain_stdout.contains("spuc (adversaries @ adversary-"));
    assert!(plain_stdout.contains("Back to adversaries catalog."));
    assert!(plain_stdout.contains("spuc>"));
    let exported: Vec<_> = fs::read_dir(&out_dir)
        .expect("missing adversaries export dir")
        .filter_map(|entry| entry.ok())
        .collect();
    assert!(!exported.is_empty());
}

#[test]
fn guided_plan_rejects_incompatible_ability_on_select() {
    let root = temp_config_root();
    let windows_ability =
        run_save_ability(&root, "[process:command_line MATCHES '^.*cmd\\\\.exe.*$']");

    let mut cmd = Command::new(spuc_bin())
        .env("SPUC_CONFIG_DIR", &root)
        .args([
            "plan",
            "--guided",
            "--name",
            "Select mismatch",
            "--platform",
            "linux",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn guided plan for incompatible select");

    let script = format!("list\nselect {}\nexit\n", windows_ability);
    cmd.stdin
        .as_mut()
        .expect("stdin missing")
        .write_all(script.as_bytes())
        .expect("failed to write guided incompatible select script");

    let out = cmd.wait_with_output().expect("wait output");
    assert!(
        out.status.success(),
        "guided plan incompatible select failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let plain_stdout = strip_ansi_escape_codes(&String::from_utf8_lossy(&out.stdout));
    assert!(plain_stdout.contains("Incompatible PLATFORM for selected ability"));
    assert!(!plain_stdout.contains("Added ability"));
}

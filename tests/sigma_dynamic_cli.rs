#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn spuc_bin() -> String {
    std::env::var("CARGO_BIN_EXE_spuc").unwrap_or_else(|_| "target/debug/spuc".to_string())
}

fn fake_sigma_script() -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("spuc_fake_sigma_{ts}.sh"));
    let script = r#"#!/bin/sh
if [ "$1" = "plugin" ] && [ "$2" = "list" ]; then
cat <<'EOF'
| Type     | Identifier     | Compatible? |
|----------|----------------|-------------|
| backend  | splunk         | yes         |
| backend  | elasticsearch  | yes         |
| backend  | secops         | no          |
| pipeline | ecs_windows    | yes         |
EOF
exit 0
fi
if [ "$1" = "convert" ]; then
  echo "converted $*"
  exit 0
fi
echo "sigma 0.0-test"
exit 0
"#;
    fs::write(&path, script).expect("write script");
    let mut perms = fs::metadata(&path).expect("metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).expect("chmod");
    path
}

#[test]
fn help_includes_dynamic_sigma_targets_when_sigma_available() {
    let sigma = fake_sigma_script();
    let out = Command::new(spuc_bin())
        .env("SPUC_SIGMA_BIN", &sigma)
        .arg("--help")
        .output()
        .expect("run help");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Supported dynamic sigma targets"));
    assert!(text.contains("sigma-to-splunk"));
    assert!(text.contains("sigma-to-elasticsearch"));
    assert!(!text.contains("sigma-to-secops"));
}

#[test]
fn sigma_commands_report_and_list_dynamic_targets() {
    let sigma = fake_sigma_script();
    let status = Command::new(spuc_bin())
        .env("SPUC_SIGMA_BIN", &sigma)
        .args(["sigma", "status"])
        .output()
        .expect("run sigma status");
    assert!(status.status.success());
    let status_text = String::from_utf8_lossy(&status.stdout);
    assert!(status_text.contains("installed=true"));
    assert!(status_text.contains("operational=true"));
    assert!(status_text.contains("splunk"));

    let list = Command::new(spuc_bin())
        .env("SPUC_SIGMA_BIN", &sigma)
        .args(["sigma", "list-targets"])
        .output()
        .expect("run sigma list-targets");
    assert!(list.status.success());
    let list_text = String::from_utf8_lossy(&list.stdout);
    assert!(list_text.contains("sigma-to-splunk"));
    assert!(list_text.contains("sigma-to-elasticsearch"));
    assert!(!list_text.contains("sigma-to-secops"));
}

#[test]
fn help_omits_dynamic_section_when_sigma_missing() {
    let out = Command::new(spuc_bin())
        .env("SPUC_SIGMA_BIN", "/definitely/missing/sigma")
        .arg("--help")
        .output()
        .expect("run help");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(!text.contains("Supported dynamic sigma targets"));
}

#[test]
fn translate_supports_sigma_to_dynamic_backend() {
    let sigma = fake_sigma_script();
    let out = Command::new(spuc_bin())
        .env("SPUC_SIGMA_BIN", &sigma)
        .args([
            "translate",
            "--to",
            "sigma-to-splunk",
            "--rule",
            "[process:name = 'cmd.exe']",
        ])
        .output()
        .expect("run translate dynamic");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("converted"));
    assert!(!text.to_ascii_lowercase().contains("status=unsupported"));
}

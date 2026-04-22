use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn spuc_bin() -> String {
    let bin =
        std::env::var("CARGO_BIN_EXE_spuc").unwrap_or_else(|_| "target/debug/spuc".to_string());
    if !Path::new(&bin).exists() {
        let status = Command::new("cargo")
            .args(["build", "-q", "-p", "spuc-server", "--bin", "spuc"])
            .status()
            .expect("failed to build spuc binary for tests");
        assert!(status.success(), "failed to build spuc binary for tests");
    }
    bin
}

#[test]
fn version_flag_prints_current_version_only() {
    let out = Command::new(spuc_bin())
        .arg("--version")
        .output()
        .expect("failed to run spuc --version");
    assert!(
        out.status.success(),
        "spuc --version failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
}

#[test]
fn help_groups_root_commands() {
    let out = Command::new(spuc_bin())
        .arg("help")
        .output()
        .expect("failed to run spuc help");
    assert!(
        out.status.success(),
        "spuc help failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Usage: spuc"));
    assert!(stdout.contains("Commands:"));

    let order = [
        "emulate",
        "jsonrpc",
        "translate",
        "verify",
        "version",
        "web",
    ];
    let mut previous = 0usize;
    for name in order {
        let marker = format!("\n  {name}");
        let pos = stdout
            .find(&marker)
            .unwrap_or_else(|| panic!("missing command in help output: {name}"));
        assert!(
            pos >= previous,
            "commands are not ordered alphabetically around: {name}"
        );
        previous = pos;
    }

    assert!(!stdout.contains("\n  serve"));
    assert!(!stdout.contains("\n  explore"));
}

#[test]
fn version_command_prints_current_version_only() {
    let out = Command::new(spuc_bin())
        .arg("version")
        .output()
        .expect("failed to run spuc version");
    assert!(
        out.status.success(),
        "spuc version failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
}

#[test]
fn removed_cli_commands_are_rejected() {
    for command in [
        "adversaries",
        "console",
        "plan",
        "rules",
        "learn",
        "explore",
    ] {
        let out = Command::new(spuc_bin())
            .arg(command)
            .output()
            .unwrap_or_else(|error| panic!("failed to run `spuc {command}`: {error}"));
        assert!(
            !out.status.success(),
            "`spuc {command}` should be rejected after CLI cleanup"
        );
        let stderr = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase();
        assert!(
            stderr.contains("unrecognized") || stderr.contains("unknown"),
            "expected unknown command error for `{command}`, got: {stderr}"
        );
    }
}

#[test]
fn convert_smoke_single_example() {
    let status = Command::new(spuc_bin())
        .args([
            "translate",
            "--file",
            "examples/network-traffic.stix",
            "--to",
            "sigma",
        ])
        .status()
        .expect("failed to run spuc binary");
    assert!(
        status.success(),
        "spuc translate failed for single smoke example"
    );
}

#[test]
fn convert_all_examples_without_crashing() {
    let dir = Path::new("examples");
    let mut files: Vec<_> = fs::read_dir(dir)
        .expect("examples directory should exist")
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            (path.extension().and_then(|e| e.to_str()) == Some("stix")).then_some(path)
        })
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no .stix files found in examples/");

    for file in files {
        let status = Command::new(spuc_bin())
            .args(["translate", "--file"])
            .arg(&file)
            .args(["--to", "sigma"])
            .status()
            .unwrap_or_else(|e| panic!("failed to run spuc for {}: {e}", file.display()));
        assert!(
            status.success(),
            "spuc translate failed for {}",
            file.display()
        );
    }
}

fn run_convert(rule: &str, target: &str) -> String {
    let out = Command::new(spuc_bin())
        .args(["translate", "--to", target, "--rule", rule])
        .output()
        .expect("failed to run spuc translate");
    assert!(
        out.status.success(),
        "spuc translate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn run_convert_with_conf(rule: &str, target: &str, conf: &str) -> (bool, String, String) {
    let out = Command::new(spuc_bin())
        .args([
            "translate",
            "--to",
            target,
            "--rule",
            rule,
            "--rule-confidence",
            conf,
        ])
        .output()
        .expect("failed to run spuc translate with confidence");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn csv_output_uses_structured_result_columns() {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock error")
        .as_nanos();
    let out_dir = std::env::temp_dir().join(format!("spuc_csv_test_{ts}"));
    fs::create_dir_all(&out_dir).expect("failed to create temp output dir");

    let out = Command::new(spuc_bin())
        .args([
            "translate",
            "--to",
            "sigma",
            "--rule",
            "[process:pid = 1234]",
            "--output",
        ])
        .arg(&out_dir)
        .args(["--rule-confidence", "80"])
        .output()
        .expect("failed to run spuc translate for csv");
    assert!(
        out.status.success(),
        "spuc translate failed for csv: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let csv = fs::read_to_string(out_dir.join("spuc_output.csv")).expect("missing csv file");
    assert!(csv.contains(
        "input_rule,target,runtime_status,conversion_confidence,rule_confidence,cause,summary,notes,output"
    ));
}

#[test]
fn normalization_scope_errors_are_specific() {
    let out = run_convert(
        "[domain-name:resolves_to_refs[*].value = '198.51.100.42']",
        "sigma",
    );
    let low = out.to_ascii_lowercase();
    assert!(low.contains("normalization_not_implemented"));
    assert!(low.contains("reference traversal"));
}

#[test]
fn file_mime_type_is_accepted_in_normalization_scope() {
    let out = run_convert(
        "[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f' AND file:mime_type = 'application/x-pdf']",
        "sigma",
    );
    let low = out.to_ascii_lowercase();
    assert!(!low.contains("stix21_invalid_or_unsupported_path"));
}

#[test]
fn artifact_payload_semantic_regressions() {
    let plain_qujd = run_convert("[artifact:payload_bin = 'QUJD']", "yara");
    let b64_qujd = run_convert("[artifact:payload_bin = b'QUJD']", "yara");
    assert!(plain_qujd.contains("{ 51 55 4A 44 }"));
    assert!(b64_qujd.contains("{ 41 42 43 }"));

    let plain_text = run_convert("[artifact:payload_bin = 'this is a test']", "yara");
    let b64_text = run_convert("[artifact:payload_bin = b'dGhpcyBpcyBhIHRlc3Q=']", "yara");
    let hex_text = run_convert(
        "[artifact:payload_bin = h'7468697320697320612074657374']",
        "yara",
    );
    assert!(plain_text.contains("{ 74 68 69 73 20 69 73 20 61 20 74 65 73 74 }"));
    assert!(b64_text.contains("{ 74 68 69 73 20 69 73 20 61 20 74 65 73 74 }"));
    assert!(hex_text.contains("{ 74 68 69 73 20 69 73 20 61 20 74 65 73 74 }"));

    let regex_hex = run_convert("[artifact:payload_bin MATCHES '\\\\x4d\\\\x5a']", "yara");
    let regex_mz = run_convert("[artifact:payload_bin MATCHES '^MZ']", "yara");
    let like_mz = run_convert("[artifact:payload_bin LIKE 'MZ%']", "yara");
    assert!(regex_hex.contains("/\\x4d\\x5a/"));
    assert!(regex_mz.contains("/^MZ/"));
    assert!(like_mz.contains("/^MZ.*$/"));

    let mixed = run_convert(
        "[artifact:mime_type = 'application/pdf' AND artifact:payload_bin = h'25504446']",
        "sigma",
    );
    assert!(mixed.contains("unsupported"));
    assert!(mixed.contains("raw STIX path passthrough disabled"));
}

#[test]
fn issubset_network_regressions() {
    let v4 = run_convert("[ipv4-addr:value ISSUBSET '198.51.100.0/24']", "kql");
    assert!(v4.contains("ipv4_is_in_range"));

    let v6 = run_convert("[ipv6-addr:value ISSUBSET '2001:db8::/32']", "kql");
    assert!(v6.contains("ipv6_is_in_range"));

    let nt = run_convert(
        "[network-traffic:src_ref.value ISSUBSET '10.0.0.0/8' AND network-traffic:protocols = 'tcp']",
        "sigma",
    );
    assert!(nt.contains("source.ip|cidr"));

    let unsupported = run_convert("[domain-name:value ISSUBSET 'evil.example']", "eql");
    assert!(unsupported.contains("unsupported"));
}

#[test]
fn network_ref_type_is_ignored_when_ref_value_exists_in_outputs() {
    let sigma = run_convert(
        "[network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'example.com']",
        "sigma",
    );
    assert!(!sigma
        .to_ascii_lowercase()
        .contains("no documented field mapping"));
    assert!(sigma.contains("destination.ip"));
}

#[test]
fn rule_confidence_validation_and_embedding() {
    let (ok0, out0, _) = run_convert_with_conf("[process:pid = 1234]", "sigma", "0");
    assert!(ok0);
    assert!(out0.contains("x_spuc_indicator_confidence: 0"));

    let (ok100, out100, _) =
        run_convert_with_conf("[artifact:payload_bin = h'4d5a']", "yara", "100");
    assert!(ok100);
    assert!(out100.contains("spuc_indicator_confidence = \"100\""));

    let (neg_ok, _, _neg_err) = run_convert_with_conf("[process:pid = 1234]", "sigma", "-1");
    assert!(!neg_ok);

    let (high_ok, _, _high_err) = run_convert_with_conf("[process:pid = 1234]", "sigma", "101");
    assert!(!high_ok);
}

#[test]
fn directory_and_autonomous_system_baseline() {
    let dir_path = run_convert("[directory:path = 'C:\\\\Windows\\\\System32']", "sigma");
    assert!(dir_path.contains("file.directory"));
    assert!(dir_path.contains("schema-dependent"));

    let dir_time = run_convert("[directory:mtime >= t'2025-01-01T00:00:00Z']", "eql");
    assert!(dir_time.contains("directory.mtime"));
    assert!(dir_time.contains("schema-dependent"));

    let asn_num = run_convert("[autonomous-system:number = 15169]", "kql");
    assert!(asn_num.contains("RemoteASN == 15169"));
    assert!(asn_num.contains("status=schema-dependent"));

    let asn_cmp = run_convert("[autonomous-system:number >= 64512]", "eql");
    assert!(asn_cmp.contains("as.number >= 64512"));
    assert!(asn_cmp.contains("status=schema-dependent"));

    let asn_name_eq = run_convert("[autonomous-system:name = 'Google LLC']", "sigma");
    assert!(asn_name_eq.contains("as.organization.name: Google LLC"));
    assert!(asn_name_eq.contains("status=schema-dependent"));

    let asn_name_like = run_convert("[autonomous-system:name LIKE 'Google%']", "sigma");
    assert!(asn_name_like.contains("as.organization.name|re"));

    let asn_name_re = run_convert(
        "[autonomous-system:name MATCHES '^(?i)(google|cloudflare).*$']",
        "kql",
    );
    assert!(asn_name_re.contains("RemoteASName matches regex @\""));

    let asn_rir_eq = run_convert("[autonomous-system:rir = 'ARIN']", "eql");
    assert!(asn_rir_eq.contains("as.rir == \"ARIN\""));
    assert!(asn_rir_eq.contains("status=schema-dependent"));

    let asn_rir_like = run_convert("[autonomous-system:rir LIKE 'RI%']", "kql");
    assert!(asn_rir_like.contains("RemoteASRIR matches regex @\""));

    let asn_compound = run_convert(
        "[autonomous-system:number = 13335 AND autonomous-system:name = 'Cloudflare, Inc.' AND autonomous-system:rir = 'ARIN']",
        "sigma",
    );
    assert!(asn_compound.contains("as.number: 13335"));
    assert!(asn_compound.contains("as.organization.name: Cloudflare, Inc."));
    assert!(asn_compound.contains("as.rir: ARIN"));

    let asn_snort = run_convert("[autonomous-system:number = 15169]", "snort");
    assert!(asn_snort.contains("status=unsupported"));

    let asn_yara = run_convert("[autonomous-system:name = 'Google LLC']", "yara");
    assert!(asn_yara.contains("status=unsupported"));
}

#[test]
fn yara_rejects_semantically_misleading_telemetry_mappings() {
    let url_ne = run_convert("[url:value != 'https://evil.example']", "yara");
    assert!(url_ne.contains("unsupported"));
    assert!(url_ne.contains("standalone network observable semantics"));

    let asn = run_convert("[autonomous-system:number = 13335]", "yara");
    assert!(asn.contains("unsupported"));
    assert!(asn.contains("autonomous-system telemetry semantics"));

    let dir = run_convert("[directory:path = 'C:\\\\Windows']", "yara");
    assert!(dir.contains("unsupported"));
    assert!(dir.contains("directory metadata semantics"));
}

#[test]
fn standalone_ip_semantics_are_not_forced_into_sigma_source_side() {
    let sigma_ip = run_convert("[ipv4-addr:value = '198.51.100.42']", "sigma");
    assert!(sigma_ip.contains("unsupported"));
    assert!(sigma_ip.contains("directionality bias"));
}

#[test]
fn sigma_or_registry_branches_are_emitted_in_single_rule() {
    let sigma = run_convert(
        "[windows-registry-key:key = 'HKEY_CURRENT_USER\\\\Software\\\\CryptoLocker\\\\Files' OR windows-registry-key:key = 'HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\CurrentVersion\\\\Run\\\\CryptoLocker_0388']",
        "sigma",
    );
    assert!(sigma.contains("selection1:"));
    assert!(sigma.contains("selection2:"));
    assert!(sigma.contains("condition: selection1 or selection2"));
    assert!(!sigma.contains("\n---\n"));
    assert_eq!(
        sigma
            .matches("title: '[SPUC Generated Sigma Rule] auto'")
            .count(),
        1
    );
}

#[test]
fn eql_kql_autonomous_system_are_schema_dependent_not_exact() {
    let eql = run_convert("[autonomous-system:rir = 'ARIN']", "eql");
    assert!(eql.contains("schema-dependent"));

    let kql = run_convert("[autonomous-system:number > 64511]", "kql");
    assert!(kql.contains("schema-dependent"));
}

#[test]
fn repeats_semantics_are_advisory_and_not_overclaimed() {
    let eql = run_convert("[ipv4-addr:value = '8.8.8.8'] REPEATS 3 TIMES", "eql");
    assert!(eql.contains("status=partial"));
    assert!(eql.contains("REPEATS 3 TIMES kept as advisory only"));

    let sigma = run_convert(
        "[network-traffic:dst_port = 53 AND network-traffic:protocols = 'udp'] REPEATS 10 TIMES",
        "sigma",
    );
    assert!(sigma.contains("status=partial"));
    assert!(sigma.contains("REPEATS 10 TIMES kept as advisory only"));

    let kql = run_convert(
        "[url:value = 'http://example.com/login'] REPEATS 2 TIMES",
        "kql",
    );
    assert!(kql.contains("status=partial"));
    assert!(kql.contains("REPEATS 2 TIMES kept as advisory only"));

    let eql_within = run_convert(
        "[domain-name:value = 'evil.example'] REPEATS 4 TIMES WITHIN 600 SECONDS",
        "eql",
    );
    assert!(eql_within.contains("status=partial"));
    assert!(eql_within.contains("WITHIN 600 SECONDS kept as advisory only"));

    let snort = run_convert(
        "[process:command_line LIKE '%powershell%'] REPEATS 5 TIMES",
        "snort",
    );
    assert!(snort.contains("status=unsupported"));
    assert!(snort.contains("observation qualifiers"));

    let suricata = run_convert(
        "[process:command_line LIKE '%powershell%'] REPEATS 5 TIMES",
        "suricata",
    );
    assert!(suricata.contains("status=unsupported"));

    let yara = run_convert(
        "[process:command_line LIKE '%powershell%'] REPEATS 5 TIMES",
        "yara",
    );
    assert!(yara.contains("status=unsupported"));
}

#[test]
fn followedby_initial_support_is_strict_and_conservative() {
    let eql = run_convert(
        "[process:name = 'cmd.exe'] FOLLOWEDBY [process:name = 'powershell.exe']",
        "eql",
    );
    assert!(eql.contains("sequence"));
    assert!(eql.contains("[process where"));
    assert!(eql.contains("process.name == \"cmd.exe\""));
    assert!(eql.contains("process.name == \"powershell.exe\""));

    let eql_net = run_convert(
        "[network-traffic:dst_port = 53] FOLLOWEDBY [network-traffic:dst_port = 443]",
        "eql",
    );
    assert!(eql_net.contains("sequence"));
    assert!(eql_net.contains("destination.port == 53"));
    assert!(eql_net.contains("destination.port == 443"));

    let eql_within = run_convert(
        "([process:name = 'cmd.exe'] FOLLOWEDBY [process:name = 'powershell.exe']) WITHIN 300 SECONDS",
        "eql",
    );
    assert!(eql_within.contains("sequence with maxspan=300s"));
    assert!(eql_within.contains("WITHIN 300 SECONDS lowered to EQL sequence maxspan"));

    let kql = run_convert(
        "[file:name = 'a.exe'] FOLLOWEDBY [file:name = 'b.exe']",
        "kql",
    );
    assert!(kql.contains("status=unsupported"));
    assert!(kql.contains("FOLLOWEDBY"));

    let sigma = run_convert(
        "[url:value = 'http://example.com/a'] FOLLOWEDBY [url:value = 'http://example.com/b']",
        "sigma",
    );
    assert!(sigma.contains("status=unsupported"));
    assert!(sigma.contains("FOLLOWEDBY"));

    let snort = run_convert(
        "[network-traffic:dst_port = 53] FOLLOWEDBY [network-traffic:dst_port = 443]",
        "snort",
    );
    assert!(snort.contains("status=unsupported"));

    let suricata = run_convert(
        "[network-traffic:dst_port = 53] FOLLOWEDBY [network-traffic:dst_port = 443]",
        "suricata",
    );
    assert!(suricata.contains("status=unsupported"));

    let yara = run_convert(
        "[url:value = 'http://example.com/a'] FOLLOWEDBY [url:value = 'http://example.com/b']",
        "yara",
    );
    assert!(yara.contains("status=unsupported"));
}

#[test]
fn user_account_rules_are_supported_in_baseline_emitters() {
    let single = run_convert(
        "[user-account:account_type = 'unix' AND user-account:user_id = '1007' AND user-account:account_login = 'Peter']",
        "sigma",
    );
    assert!(single.contains("user.type"));
    assert!(single.contains("user.id"));
    assert!(single.contains("user.name"));
    assert!(single.contains("schema-dependent"));

    let multi = run_convert(
        "[user-account:account_type = 'unix' AND user-account:user_id = '1007' AND user-account:account_login = 'Peter'] AND [user-account:account_type = 'unix' AND user-account:user_id = '1008' AND user-account:account_login = 'Paul'] AND [user-account:account_type = 'unix' AND user-account:user_id = '1009' AND user-account:account_login = 'Mary']",
        "eql",
    );
    assert!(multi.contains("unsupported"));
    assert!(multi.contains("multi-entity user-account conjunctions"));
}

#[test]
fn sigma_multi_user_account_conjunction_is_not_exact_and_not_array_collapsed() {
    let multi = run_convert(
        "[user-account:account_type = 'unix' AND user-account:user_id = '1007' AND user-account:account_login = 'Peter'] AND [user-account:account_type = 'unix' AND user-account:user_id = '1008' AND user-account:account_login = 'Paul'] AND [user-account:account_type = 'unix' AND user-account:user_id = '1009' AND user-account:account_login = 'Mary']",
        "sigma",
    );
    assert!(multi.contains("unsupported"));
    assert!(!multi.contains("user.id:\n    - '1007'"));
}

#[test]
fn human_facing_fields_are_capitalized() {
    let out = run_convert(
        "[domain-name:resolves_to_refs[*].value = '198.51.100.42']",
        "sigma",
    );
    assert!(out.contains("Cause="));
    assert!(out.contains("Summary="));
    assert!(out.contains("Notes="));
}

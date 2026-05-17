#![allow(dead_code)]

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use crate::cli::{ConversionMode, OutputTarget};
use crate::commands::common::{
    build_result_view, emit_target_with_mode, finalize_result, parse_and_normalize, verify_rule,
};
use crate::emitters::{EmitResult, FailureCause};
use crate::paths;
use crate::ui::ansi::{BLUE, BOLD, GREEN, RESET, UNBOLD, WHITE, YELLOW};
use crate::ui::print::{bold_cmd, ui_error, ui_warn};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct LearnChallengeView {
    pub(crate) id: &'static str,
    pub(crate) path_id: &'static str,
    pub(crate) title: &'static str,
    pub(crate) goal: &'static str,
    pub(crate) hint: &'static str,
    pub(crate) example: &'static str,
}

pub(crate) struct LearnChallenge {
    pub(crate) id: &'static str,
    path_id: &'static str,
    title: &'static str,
    goal: &'static str,
    hint: &'static str,
    example: &'static str,
}

#[derive(Clone, Copy)]
struct LearnPath {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    challenge_ids: &'static [&'static str],
}

pub(crate) const LEARN_CHALLENGES: [LearnChallenge; 15] = [
    LearnChallenge {
        id: "core001",
        path_id: "core",
        title: "Observable Basics",
        goal: "Write a pattern that filters by process command line and uses LIKE or MATCHES.",
        hint: "Use process:command_line and a text condition such as LIKE '%powershell%'.",
        example: "[process:command_line LIKE '%powershell%']",
    },
    LearnChallenge {
        id: "core002",
        path_id: "core",
        title: "Operator Composition",
        goal: "Write a pattern with two process conditions combined by AND.",
        hint: "Combine process:name and process:command_line with AND.",
        example: "[process:name = 'powershell.exe' AND process:command_line LIKE '%-enc%']",
    },
    LearnChallenge {
        id: "core003",
        path_id: "core",
        title: "Exact Match Basics",
        goal: "Detect powershell.exe by exact process name.",
        hint: "Use process:name with '=' and the value 'powershell.exe'.",
        example: "[process:name = 'powershell.exe']",
    },
    LearnChallenge {
        id: "core004",
        path_id: "core",
        title: "Simple Negation",
        goal: "Exclude cmd.exe using != on process:name.",
        hint: "Use process:name != 'cmd.exe'.",
        example: "[process:name != 'cmd.exe']",
    },
    LearnChallenge {
        id: "core005",
        path_id: "core",
        title: "OR Composition",
        goal: "Combine mshta.exe and rundll32.exe with OR.",
        hint: "Use OR between two process:name conditions.",
        example: "[process:name = 'mshta.exe' OR process:name = 'rundll32.exe']",
    },
    LearnChallenge {
        id: "ops001",
        path_id: "ops",
        title: "Triple AND",
        goal: "Write one observation with three conditions joined by AND.",
        hint: "Use process:name, process:command_line and process:pid together.",
        example: "[process:name = 'powershell.exe' AND process:command_line LIKE '%-enc%' AND process:pid > 1000]",
    },
    LearnChallenge {
        id: "ops002",
        path_id: "ops",
        title: "LIKE + MATCHES",
        goal: "Use both LIKE and MATCHES against process:command_line.",
        hint: "One condition with LIKE and another with MATCHES.",
        example: "[process:command_line LIKE '%powershell%' AND process:command_line MATCHES '(?i).*\\s-enc\\s.*']",
    },
    LearnChallenge {
        id: "ops003",
        path_id: "ops",
        title: "Boolean Precedence",
        goal: "Mix AND/OR with parentheses to avoid ambiguity.",
        hint: "Group OR branch inside parentheses, then AND another condition.",
        example: "[(process:name = 'cmd.exe' OR process:name = 'powershell.exe') AND process:command_line LIKE '%http%']",
    },
    LearnChallenge {
        id: "time001",
        path_id: "time",
        title: "Qualifier Drill",
        goal: "Write a pattern using REPEATS ... TIMES WITHIN ... SECONDS.",
        hint: "Start from one observable and append REPEATS and WITHIN qualifiers.",
        example: "[process:command_line LIKE '%powershell%'] REPEATS 3 TIMES WITHIN 300 SECONDS",
    },
    LearnChallenge {
        id: "time002",
        path_id: "time",
        title: "FOLLOWEDBY Window",
        goal: "Use FOLLOWEDBY with WITHIN for a short sequence.",
        hint: "Create two process observations and connect them with FOLLOWEDBY.",
        example: "([process:name = 'cmd.exe'] FOLLOWEDBY [process:name = 'powershell.exe']) WITHIN 120 SECONDS",
    },
    LearnChallenge {
        id: "time003",
        path_id: "time",
        title: "Network Repetition",
        goal: "Use REPEATS ... TIMES WITHIN with a network destination port.",
        hint: "Start with network-traffic:dst_port, then append repetition qualifiers.",
        example: "[network-traffic:dst_port = 22] REPEATS 10 TIMES WITHIN 60 SECONDS",
    },
    LearnChallenge {
        id: "time004",
        path_id: "time",
        title: "START / STOP Window",
        goal: "Constrain a process pattern with START and STOP timestamps.",
        hint: "Append START t'...' STOP t'...' after the observation.",
        example: "[process:name = 'wscript.exe'] START t'2025-01-01T00:00:00Z' STOP t'2025-01-01T01:00:00Z'",
    },
    LearnChallenge {
        id: "net001",
        path_id: "net",
        title: "Full Network Tuple",
        goal: "Use src IP, dst IP, dst port and protocol in one pattern.",
        hint: "Combine src_ref.value, dst_ref.value, dst_port and protocols with AND.",
        example: "[network-traffic:src_ref.value = '10.0.0.5' AND network-traffic:dst_ref.value = '203.0.113.10' AND network-traffic:dst_port = 443 AND network-traffic:protocols = 'tcp']",
    },
    LearnChallenge {
        id: "net002",
        path_id: "net",
        title: "CIDR ISSUBSET",
        goal: "Write ISSUBSET for source IPv4 range with explicit src_ref.type.",
        hint: "Use src_ref.type = 'ipv4-addr' and src_ref.value ISSUBSET '<cidr>'.",
        example: "[network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value ISSUBSET '10.0.0.0/8']",
    },
    LearnChallenge {
        id: "file001",
        path_id: "file",
        title: "File Triad",
        goal: "Combine SHA-256 hash, size threshold and executable filename.",
        hint: "Use file:hashes.SHA-256, file:size and file:name LIKE '%.exe'.",
        example: "[file:hashes.SHA-256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' AND file:size > 500000 AND file:name LIKE '%.exe']",
    },
];

const LEARN_PATHS: [LearnPath; 5] = [
    LearnPath {
        id: "core",
        title: "Path 1: Core Patterns",
        description: "Observables, exact match, negation and OR composition.",
        challenge_ids: &["core001", "core002", "core003", "core004", "core005"],
    },
    LearnPath {
        id: "ops",
        title: "Path 2: Operator Craft",
        description: "AND/OR composition, precedence and mixed text operators.",
        challenge_ids: &["ops001", "ops002", "ops003"],
    },
    LearnPath {
        id: "time",
        title: "Path 3: Temporal Logic",
        description: "Qualifiers, sequence and explicit time windows.",
        challenge_ids: &["time001", "time002", "time003", "time004"],
    },
    LearnPath {
        id: "net",
        title: "Path 4: Network Signals",
        description: "Network tuple composition and CIDR constraints.",
        challenge_ids: &["net001", "net002"],
    },
    LearnPath {
        id: "file",
        title: "Path 5: File Indicators",
        description: "File hash/size/name triage patterns.",
        challenge_ids: &["file001"],
    },
];

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
struct LearnProgress {
    attempted: BTreeSet<String>,
    completed: BTreeSet<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
struct SpucConfig {
    #[serde(default)]
    learn_progress: LearnProgress,
    #[serde(default)]
    learn_last_challenge: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LearnState {
    Pending,
    Attempted,
    Completed,
}

pub(crate) struct LearnSession {
    active_id: Option<String>,
    attempts: HashMap<String, usize>,
    config: SpucConfig,
    persist_enabled: bool,
}

impl LearnSession {
    pub(crate) fn new() -> Self {
        Self {
            active_id: None,
            attempts: HashMap::new(),
            config: load_spuc_config(),
            persist_enabled: true,
        }
    }

    fn challenge_state(&self, challenge_id: &str) -> LearnState {
        if self.config.learn_progress.completed.contains(challenge_id) {
            LearnState::Completed
        } else if self.config.learn_progress.attempted.contains(challenge_id) {
            LearnState::Attempted
        } else {
            LearnState::Pending
        }
    }

    fn persist_config(&mut self) {
        if !self.persist_enabled {
            return;
        }
        if let Err(e) = save_spuc_config(&self.config) {
            println!("{YELLOW}Warning: cannot persist SPUC config: {e}{RESET}");
            self.persist_enabled = false;
        }
    }
}

fn spuc_config_dir() -> Option<PathBuf> {
    paths::spuc_config_root()
}

fn spuc_config_path() -> Option<PathBuf> {
    spuc_config_dir().map(|dir| dir.join("config.json"))
}

fn load_spuc_config() -> SpucConfig {
    let Some(path) = spuc_config_path() else {
        return SpucConfig::default();
    };
    let Ok(raw) = fs::read_to_string(path) else {
        return SpucConfig::default();
    };
    serde_json::from_str::<SpucConfig>(&raw).unwrap_or_default()
}

fn save_spuc_config(config: &SpucConfig) -> Result<()> {
    let Some(path) = spuc_config_path() else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let raw = serde_json::to_string_pretty(config)?;
    fs::write(path, raw)?;
    Ok(())
}

pub(crate) fn learn_prompt(session: &LearnSession) -> String {
    if let Some(id) = &session.active_id {
        format!("{BOLD}spuc (learn @ {id})>{RESET} ")
    } else {
        format!("{BOLD}spuc (learn)>{RESET} ")
    }
}

fn learn_title(text: &str) -> String {
    format!("{BLUE}{BOLD}{text}{RESET}")
}

fn styled_challenge_id(session: &LearnSession, id: &str) -> String {
    let color = match session.challenge_state(id) {
        LearnState::Completed => GREEN,
        LearnState::Attempted => YELLOW,
        LearnState::Pending => WHITE,
    };
    format!("{color}{BOLD}{id}{RESET}")
}

pub(crate) fn run(list_only: bool, requested: Option<&str>) -> Result<()> {
    let mut session = LearnSession::new();
    if list_only {
        print_learn_catalog(&session);
        return Ok(());
    }

    print_learn_intro(&session);
    print_learn_catalog(&session);
    if let Some(id) = requested {
        select_learn_challenge(&mut session, id)?;
    }

    loop {
        let input = read_learn_line(&learn_prompt(&session))?;
        if handle_learn_input(&mut session, &input)? {
            break;
        }
    }
    Ok(())
}

pub(crate) fn print_learn_intro(session: &LearnSession) {
    println!("{}", learn_title("Learn Mode"));
    println!();
    println!(
        "{YELLOW}Guided STIX learning paths to practice observables, operators and qualifiers.{RESET}"
    );
    println!(
        "{YELLOW}Type {BOLD}list{UNBOLD} to browse paths, or write a challenge id to start.{RESET}"
    );
    println!(
        "{YELLOW}Commands available: {BOLD}list{RESET}{YELLOW} (example: {BOLD}list{RESET}{YELLOW}), {BOLD}<challenge-id>{RESET}{YELLOW} (example: {BOLD}core001{RESET}{YELLOW}), {BOLD}hint{RESET}{YELLOW}, {BOLD}solution{RESET}{YELLOW}, {BOLD}forget{RESET}{YELLOW}, {BOLD}back{RESET}{YELLOW}, {BOLD}exit{RESET}{YELLOW}.{RESET}"
    );
    if let Some(last) = session.config.learn_last_challenge.as_deref() {
        println!("{YELLOW}Last challenge: {BOLD}{last}{RESET}{YELLOW}.{RESET}");
    }
}

pub(crate) fn print_learn_catalog(session: &LearnSession) {
    println!();
    println!("{}", learn_title("Learning Paths"));
    println!();
    for path in LEARN_PATHS {
        println!("- {BLUE}{BOLD}{}{RESET} ({})", path.title, path.id);
        println!("{YELLOW}  {}{RESET}", path.description);
        for challenge_id in path.challenge_ids {
            if let Some(challenge) = find_learn_challenge(challenge_id) {
                println!(
                    "{YELLOW}  - {}: {}{RESET}",
                    styled_challenge_id(session, challenge.id),
                    challenge.goal
                );
            }
        }
    }
    println!();
    println!(
        "{YELLOW}Legend: {}completed{} | {}attempted{} | {}not started{}{RESET}",
        GREEN, RESET, YELLOW, RESET, WHITE, RESET
    );
}

pub(crate) fn challenge_catalog() -> Vec<LearnChallengeView> {
    LEARN_CHALLENGES
        .iter()
        .map(|challenge| LearnChallengeView {
            id: challenge.id,
            path_id: challenge.path_id,
            title: challenge.title,
            goal: challenge.goal,
            hint: challenge.hint,
            example: challenge.example,
        })
        .collect()
}

fn find_learn_challenge(id: &str) -> Option<&'static LearnChallenge> {
    LEARN_CHALLENGES
        .iter()
        .find(|challenge| challenge.id.eq_ignore_ascii_case(id))
}

pub(crate) fn challenge_hint(challenge_id: &str) -> Option<&'static str> {
    find_learn_challenge(challenge_id).map(|challenge| challenge.hint)
}

pub(crate) fn evaluate_challenge_submission(
    challenge_id: &str,
    candidate: &str,
) -> std::result::Result<(), String> {
    let challenge = find_learn_challenge(challenge_id)
        .ok_or_else(|| format!("Unknown challenge id: {challenge_id}"))?;
    evaluate_learn_submission(challenge, candidate)
}

pub(crate) fn select_learn_challenge(session: &mut LearnSession, challenge_id: &str) -> Result<()> {
    let Some(challenge) = find_learn_challenge(challenge_id) else {
        return Err(anyhow!("Unknown challenge id: {challenge_id}"));
    };
    session.active_id = Some(challenge.id.to_string());
    session.config.learn_last_challenge = Some(challenge.id.to_string());
    session.persist_config();
    println!(
        "{}",
        learn_title(&format!("Challenge {} — {}", challenge.id, challenge.title))
    );
    println!("Goal: {}", challenge.goal);
    println!("Path: {}", challenge.path_id);
    println!("Write your STIX pattern or use hint/solution.");
    Ok(())
}

pub(crate) fn handle_learn_input(session: &mut LearnSession, input: &str) -> Result<bool> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }

    let lower = trimmed.to_ascii_lowercase();
    if matches!(lower.as_str(), "exit" | "quit") {
        ui_warn("Leaving learn mode");
        return Ok(true);
    }
    if lower == "back" || lower == "backp" {
        session.active_id = None;
        println!("{YELLOW}Back to learn overview.{RESET}");
        return Ok(false);
    }
    if lower == "help" || lower == "?" {
        println!("{YELLOW}Commands available:{RESET}");
        println!(
            "{YELLOW}  {BOLD}list{RESET}{YELLOW}: show learning paths. Example: {BOLD}list{RESET}"
        );
        println!(
            "{YELLOW}  {BOLD}<challenge-id>{RESET}{YELLOW}: open one challenge. Example: {BOLD}core001{RESET}"
        );
        println!(
            "{YELLOW}  {BOLD}hint{RESET}{YELLOW}: show challenge hint. Example: {BOLD}hint{RESET}"
        );
        println!(
            "{YELLOW}  {BOLD}solution{RESET}{YELLOW}: show reference solution. Example: {BOLD}solution{RESET}"
        );
        println!(
            "{YELLOW}  {BOLD}forget{RESET}{YELLOW}: reset learn progress. Example: {BOLD}forget{RESET}"
        );
        println!(
            "{YELLOW}  {BOLD}back{RESET}{YELLOW}/{BOLD}exit{RESET}{YELLOW}: leave challenge/learn mode.{RESET}"
        );
        return Ok(false);
    }
    if lower == "list" {
        session.active_id = None;
        print_learn_catalog(session);
        return Ok(false);
    }
    if lower == "forget" {
        session.config.learn_progress = LearnProgress::default();
        session.config.learn_last_challenge = None;
        session.active_id = None;
        session.attempts.clear();
        session.persist_config();
        println!("{YELLOW}Progress cleared.{RESET}");
        return Ok(false);
    }
    if let Some(challenge) = find_learn_challenge(&lower) {
        select_learn_challenge(session, challenge.id)?;
        return Ok(false);
    }

    let Some(active_id) = session.active_id.clone() else {
        ui_error(&format!(
            "Command {} is not supported in {} mode. Use {} or choose {}",
            bold_cmd(trimmed),
            bold_cmd("learn"),
            bold_cmd("help"),
            bold_cmd("list")
        ));
        return Ok(false);
    };
    let challenge = find_learn_challenge(&active_id)
        .ok_or_else(|| anyhow!("internal error: active challenge not found"))?;

    if lower == "hint" {
        println!("{YELLOW}Hint:{RESET} {}", challenge.hint);
        return Ok(false);
    }
    if lower == "solution" {
        println!("{YELLOW}Example solution:{RESET} {}", challenge.example);
        return Ok(false);
    }

    session
        .config
        .learn_progress
        .attempted
        .insert(challenge.id.to_string());
    *session
        .attempts
        .entry(challenge.id.to_string())
        .or_insert(0) += 1;
    session.persist_config();

    match evaluate_learn_submission(challenge, trimmed) {
        Ok(()) => {
            session
                .config
                .learn_progress
                .completed
                .insert(challenge.id.to_string());
            session.persist_config();
            let attempt_count = session.attempts.get(challenge.id).copied().unwrap_or(1);
            println!(
                "{GREEN}Great! Challenge solved in {} attempt(s).{RESET}",
                attempt_count
            );
            print_learn_conversion_preview(trimmed);
            if let Some(next) = next_pending_challenge(session, challenge.path_id) {
                println!(
                    "{}",
                    learn_title(&format!("Next suggested challenge: {}", next.id))
                );
            }
        }
        Err(message) => {
            println!("{YELLOW}Not yet:{RESET} {message}.");
            println!("{YELLOW}Type {BOLD}hint{RESET}{YELLOW} for guidance.{RESET}");
        }
    }

    Ok(false)
}

fn next_pending_challenge(
    session: &LearnSession,
    path_id: &str,
) -> Option<&'static LearnChallenge> {
    let path = LEARN_PATHS.iter().find(|path| path.id == path_id)?;
    path.challenge_ids.iter().find_map(|id| {
        let challenge = find_learn_challenge(id)?;
        (session.challenge_state(challenge.id) != LearnState::Completed).then_some(challenge)
    })
}

fn evaluate_learn_submission(
    challenge: &LearnChallenge,
    candidate: &str,
) -> std::result::Result<(), String> {
    verify_rule(candidate).map_err(|e| format!("Pattern does not parse/normalize: {e}"))?;
    let lower = candidate.to_ascii_lowercase();
    let mut missing: Vec<&str> = Vec::new();

    match challenge.id {
        "core001" => {
            if !lower.contains("process:command_line") {
                missing.push("process:command_line");
            }
            if !lower.contains("like") && !lower.contains("matches") {
                missing.push("LIKE or MATCHES");
            }
        }
        "core002" => {
            if !lower.contains(" and ") {
                missing.push("AND");
            }
            if !lower.contains("process:name") {
                missing.push("process:name");
            }
            if !lower.contains("process:command_line") {
                missing.push("process:command_line");
            }
        }
        "core003" => {
            if !lower.contains("process:name") {
                missing.push("process:name");
            }
            if !lower.contains("=") {
                missing.push("=");
            }
            if !lower.contains("powershell.exe") {
                missing.push("powershell.exe");
            }
        }
        "core004" => {
            if !lower.contains("process:name") {
                missing.push("process:name");
            }
            if !lower.contains("!=") {
                missing.push("!=");
            }
            if !lower.contains("cmd.exe") {
                missing.push("cmd.exe");
            }
        }
        "core005" => {
            if !lower.contains(" or ") {
                missing.push("OR");
            }
            if !lower.contains("process:name") {
                missing.push("process:name");
            }
            if !lower.contains("mshta.exe") {
                missing.push("mshta.exe");
            }
            if !lower.contains("rundll32.exe") {
                missing.push("rundll32.exe");
            }
        }
        "ops001" => {
            if lower.matches(" and ").count() < 2 {
                missing.push("three conditions joined by AND");
            }
            if !lower.contains("process:name") {
                missing.push("process:name");
            }
            if !lower.contains("process:command_line") {
                missing.push("process:command_line");
            }
            if !lower.contains("process:pid") {
                missing.push("process:pid");
            }
        }
        "ops002" => {
            if !lower.contains("process:command_line") {
                missing.push("process:command_line");
            }
            if !lower.contains("like") {
                missing.push("LIKE");
            }
            if !lower.contains("matches") {
                missing.push("MATCHES");
            }
        }
        "ops003" => {
            if !lower.contains(" and ") {
                missing.push("AND");
            }
            if !lower.contains(" or ") {
                missing.push("OR");
            }
            if !lower.contains('(') || !lower.contains(')') {
                missing.push("parentheses");
            }
            if !lower.contains("process:name") {
                missing.push("process:name");
            }
            if !lower.contains("process:command_line") {
                missing.push("process:command_line");
            }
        }
        "time001" => {
            if !lower.contains("repeats") {
                missing.push("REPEATS");
            }
            if !lower.contains("times") {
                missing.push("TIMES");
            }
            if !lower.contains("within") {
                missing.push("WITHIN");
            }
        }
        "time002" => {
            if !lower.contains("followedby") {
                missing.push("FOLLOWEDBY");
            }
            if !lower.contains("within") {
                missing.push("WITHIN");
            }
        }
        "time003" => {
            if !lower.contains("network-traffic:dst_port") {
                missing.push("network-traffic:dst_port");
            }
            if !lower.contains("repeats") {
                missing.push("REPEATS");
            }
            if !lower.contains("times") {
                missing.push("TIMES");
            }
            if !lower.contains("within") {
                missing.push("WITHIN");
            }
        }
        "time004" => {
            if !lower.contains("process:name") {
                missing.push("process:name");
            }
            if !lower.contains("start") {
                missing.push("START");
            }
            if !lower.contains("stop") {
                missing.push("STOP");
            }
        }
        "net001" => {
            if !lower.contains("network-traffic:src_ref.value") {
                missing.push("network-traffic:src_ref.value");
            }
            if !lower.contains("network-traffic:dst_ref.value") {
                missing.push("network-traffic:dst_ref.value");
            }
            if !lower.contains("network-traffic:dst_port") {
                missing.push("network-traffic:dst_port");
            }
            if !lower.contains("network-traffic:protocols") {
                missing.push("network-traffic:protocols");
            }
        }
        "net002" => {
            if !lower.contains("network-traffic:src_ref.type") {
                missing.push("network-traffic:src_ref.type");
            }
            if !lower.contains("network-traffic:src_ref.value") {
                missing.push("network-traffic:src_ref.value");
            }
            if !lower.contains("issubset") {
                missing.push("ISSUBSET");
            }
        }
        "file001" => {
            if !lower.contains("file:hashes.sha-256") {
                missing.push("file:hashes.SHA-256");
            }
            if !lower.contains("file:size") {
                missing.push("file:size");
            }
            if !lower.contains("file:name") {
                missing.push("file:name");
            }
            if !lower.contains("like") {
                missing.push("LIKE");
            }
        }
        _ => {}
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("Missing required elements: {}", missing.join(", ")))
    }
}

fn print_learn_conversion_preview(rule: &str) {
    let parsed = match parse_and_normalize(rule) {
        Ok(ir) => ir,
        Err(_) => return,
    };
    let sigma_targets: Vec<String> = Vec::new();
    let preview_targets = [OutputTarget::Sigma, OutputTarget::Eql, OutputTarget::Kql];

    println!("{}", learn_title("Preview"));
    for target in preview_targets {
        let label = format!("{:?}", target).to_lowercase();
        let emit = emit_target_with_mode(
            &target,
            &parsed,
            None,
            &sigma_targets,
            ConversionMode::Strict,
        )
        .unwrap_or_else(|e| {
            EmitResult::unsupported_with_cause(e.to_string(), FailureCause::EmitterNotImplemented)
        });
        let emit = finalize_result(&label, emit);
        let view = build_result_view(&label, &emit, None);
        println!(
            "- {} -> status={}, confidence={}/100",
            label, view.runtime_status, view.conversion_confidence
        );
    }
}

fn read_learn_line(prompt: &str) -> Result<String> {
    println!();
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    println!();
    Ok(input.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_challenge_submission_accepts_valid_solution() {
        let result = evaluate_challenge_submission("core003", "[process:name = 'powershell.exe']");
        assert!(result.is_ok());
    }

    #[test]
    fn evaluate_challenge_submission_rejects_missing_elements() {
        let result = evaluate_challenge_submission("core003", "[process:name = 'cmd.exe']");
        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap_or_default()
            .contains("Missing required elements"));
    }
}

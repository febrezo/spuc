mod ast;
mod cli;
mod emitters;
mod ir;
mod normalize;
mod parser;

use anyhow::{Result, anyhow};
use chrono::Utc;
use clap::Parser;
use cli::{Cli, Commands, ConversionMode, OutputTarget};
use rustyline::DefaultEditor;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs::{self, File};
use std::io::{BufRead as IoBufRead, BufReader as IoBufReader};
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use emitters::{EmitResult, FailureCause, FidelityStatus};

const GREEN: &str = "\x1b[32m";
const GREEN_SOFT: &str = "\x1b[92m";
const BLUE: &str = "\x1b[34m";
const PURPLE: &str = "\x1b[35m";
const YELLOW: &str = "\x1b[33m";
const ORANGE: &str = "\x1b[38;5;208m";
const RED: &str = "\x1b[31m";
const WHITE: &str = "\x1b[37m";
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const BANNER: &str = r#"
         ____  ____  _   _  ____ 
        / ___||  _ \| | | |/ ___|
        \___ \| |_) | | | | |    
         ___) |  __/| |_| | |___ 
        |____/|_|    \___/ \____|
                         
     STIX Pattern Universal Conversor
         Coded with ❤️  by febrezo

"#;

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.version {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    println!("{BOLD}{BANNER}{RESET}");
    let command = cli
        .command
        .as_ref()
        .ok_or_else(|| anyhow!("No command provided. Use --help for usage."))?;

    match command {
        Commands::Convert {
            to,
            rule,
            file,
            output,
            description,
            rule_confidence,
            sigma_targets,
            mode,
        } => {
            let rules = load_rules(rule, file)?;
            if rules.is_empty() {
                return Err(anyhow!("No rules provided. Use --rule or --file."));
            }

            let mut targets = to.clone();
            if targets.is_empty() {
                targets = all_targets();
            }

            let mut csv_rows: Vec<CsvRow> = Vec::new();

            for (idx, rule_str) in rules.iter().enumerate() {
                render_rule_header(idx, rules.len(), rule_str);

                let parsed = parse_and_normalize(rule_str);

                for target in &targets {
                    let label = format!("{:?}", target).to_lowercase();
                    let result = match &parsed {
                        Ok(ir_expr) => emit_target_with_mode(
                            target,
                            ir_expr,
                            description.as_deref(),
                            sigma_targets,
                            mode.clone(),
                        )
                        .unwrap_or_else(|e| {
                            EmitResult::unsupported_with_cause(
                                e.to_string(),
                                FailureCause::EmitterNotImplemented,
                            )
                        }),
                        Err(res) => res.clone(),
                    };
                    let result = finalize_result(&label, result);
                    let result = apply_indicator_confidence(target, result, *rule_confidence);
                    let view = build_result_view(&label, &result, *rule_confidence);
                    render_result(&label, &result, &view);

                    if output.is_some() {
                        csv_rows.push(CsvRow {
                            input_rule: rule_str.clone(),
                            target: label.to_uppercase(),
                            runtime_status: view.runtime_status.clone(),
                            conversion_confidence: view.conversion_confidence,
                            rule_confidence: view.rule_confidence,
                            cause: view.cause.clone().unwrap_or_default(),
                            summary: view.summary.clone(),
                            notes: view.notes.join(" | "),
                            output: view.output.clone().unwrap_or_default(),
                        });
                    }
                }

                println!();
            }

            if let Some(dir) = output {
                write_csv(dir, &csv_rows)?;
            }
        }
        Commands::Verify { rule, file } => {
            let rules = load_rules(rule, file)?;
            if rules.is_empty() {
                return Err(anyhow!("No rules provided. Use --rule or --file."));
            }

            for (idx, rule_str) in rules.iter().enumerate() {
                render_rule_header(idx, rules.len(), rule_str);
                match verify_rule(rule_str) {
                    Ok(_) => println!("{GREEN}✅ OK{RESET}\n"),
                    Err(e) => println!("{RED}✖️  Error:{RESET} {e}\n"),
                }
            }
        }
        Commands::Doc { target } => {
            print_coverage(target.clone());
        }
        Commands::Learn { list, challenge } => {
            run_learn_mode(*list, challenge.as_deref())?;
        }
        Commands::Serve { port, token } => {
            run_service(*port, token.clone())?;
        }
        Commands::Interact {} => {
            run_tui()?;
        }
    }

    Ok(())
}

fn load_rules(rules: &[String], file: &Option<PathBuf>) -> Result<Vec<String>> {
    let mut out = Vec::new();
    out.extend(rules.iter().cloned());

    if let Some(path) = file {
        let f = File::open(path)?;
        let reader = BufReader::new(f);
        for line in reader.lines() {
            let l = line?;
            let trimmed = l.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_string());
            }
        }
    }

    Ok(out)
}

fn verify_rule(rule: &str) -> Result<()> {
    let ast = parser::parse_rule(rule)?;
    normalize::stix_to_ir(&ast)?;
    Ok(())
}

#[derive(Clone, Copy)]
struct LearnChallenge {
    id: &'static str,
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

const LEARN_CHALLENGES: [LearnChallenge; 3] = [
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
        id: "time001",
        path_id: "time",
        title: "Qualifier Drill",
        goal: "Write a pattern using REPEATS ... TIMES WITHIN ... SECONDS.",
        hint: "Start from one observable and append REPEATS and WITHIN qualifiers.",
        example: "[process:command_line LIKE '%powershell%'] REPEATS 3 TIMES WITHIN 300 SECONDS",
    },
];

const LEARN_PATHS: [LearnPath; 2] = [
    LearnPath {
        id: "core",
        title: "Path 1: Core Patterns",
        description: "Observables and boolean operator composition.",
        challenge_ids: &["core001", "core002"],
    },
    LearnPath {
        id: "time",
        title: "Path 2: Temporal Logic",
        description: "Qualifiers, repetition and time windows.",
        challenge_ids: &["time001"],
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

struct LearnSession {
    active_id: Option<String>,
    attempts: HashMap<String, usize>,
    config: SpucConfig,
    persist_enabled: bool,
}

impl LearnSession {
    fn new() -> Self {
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
    if let Ok(custom) = env::var("SPUC_CONFIG_DIR") {
        if !custom.trim().is_empty() {
            return Some(PathBuf::from(custom));
        }
    }

    #[cfg(target_os = "windows")]
    {
        return env::var("APPDATA")
            .ok()
            .map(|base| PathBuf::from(base).join("spuc"));
    }

    #[cfg(target_os = "macos")]
    {
        return env::var("HOME")
            .ok()
            .map(|home| PathBuf::from(home).join("Library/Application Support/spuc"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
            if !xdg.trim().is_empty() {
                return Some(PathBuf::from(xdg).join("spuc"));
            }
        }
        return env::var("HOME")
            .ok()
            .map(|home| PathBuf::from(home).join(".config/spuc"));
    }
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

fn learn_prompt(session: &LearnSession) -> String {
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

fn run_learn_mode(list_only: bool, requested: Option<&str>) -> Result<()> {
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

fn print_learn_intro(session: &LearnSession) {
    println!();
    println!("{}", learn_title("Learn Mode"));
    println!("Guided STIX learning paths.");
    println!("Commands: list, <challenge-id>, hint, solution, forget, back, exit");
    if let Some(last) = session.config.learn_last_challenge.as_deref() {
        println!("Last challenge: {BOLD}{last}{RESET}");
    }
}

fn print_learn_catalog(session: &LearnSession) {
    println!();
    println!("{}", learn_title("Learning Paths"));
    for path in LEARN_PATHS {
        println!("- {BLUE}{BOLD}{}{RESET} ({})", path.title, path.id);
        println!("  {}", path.description);
        for challenge_id in path.challenge_ids {
            if let Some(challenge) = find_learn_challenge(challenge_id) {
                println!(
                    "  - {}: {}",
                    styled_challenge_id(session, challenge.id),
                    challenge.goal
                );
            }
        }
    }
    println!(
        "Legend: {}completed{} | {}attempted{} | {}not started{}",
        GREEN, RESET, YELLOW, RESET, WHITE, RESET
    );
}

fn find_learn_challenge(id: &str) -> Option<&'static LearnChallenge> {
    LEARN_CHALLENGES
        .iter()
        .find(|challenge| challenge.id.eq_ignore_ascii_case(id))
}

fn select_learn_challenge(session: &mut LearnSession, challenge_id: &str) -> Result<()> {
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

fn handle_learn_input(session: &mut LearnSession, input: &str) -> Result<bool> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }

    let lower = trimmed.to_ascii_lowercase();
    if matches!(lower.as_str(), "exit" | "quit") {
        println!("{}", learn_title("Leaving learn mode"));
        return Ok(true);
    }
    if lower == "back" {
        session.active_id = None;
        println!("{YELLOW}Back to learn overview.{RESET}");
        return Ok(false);
    }
    if lower == "help" || lower == "?" {
        println!("{}", learn_title("Learn Commands"));
        println!("- list");
        println!("- <challenge-id> (core001, core002, time001)");
        println!("- hint");
        println!("- solution");
        println!("- forget");
        println!("- back / exit");
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
        println!("{YELLOW}Select a challenge first. Use 'list'.{RESET}");
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
            println!("{YELLOW}Not yet:{RESET} {message}");
            println!("Type 'hint' for guidance.");
        }
    }

    Ok(false)
}

fn next_pending_challenge<'a>(
    session: &LearnSession,
    path_id: &'a str,
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

fn render_rule_header(idx: usize, total: usize, rule: &str) {
    let plain = if total > 1 {
        format!("Rule {}/{}: {}", idx + 1, total, rule)
    } else {
        format!("Rule {}: {}", idx + 1, rule)
    };
    let styled = if total > 1 {
        format!(
            "{PURPLE}Rule {}/{}: {BOLD}{}{RESET}{PURPLE}{RESET}",
            idx + 1,
            total,
            rule
        )
    } else {
        format!(
            "{PURPLE}Rule {}: {BOLD}{}{RESET}{PURPLE}{RESET}",
            idx + 1,
            rule
        )
    };
    print_boxed_line(&plain, &styled);
}

fn render_coverage_header(target: &OutputTarget) {
    let plain = format!("Coverage for {:?}", target);
    let styled = format!("{PURPLE}{BOLD}{}{RESET}", plain);
    print_boxed_line(&plain, &styled);
}

fn print_boxed_line(plain: &str, styled: &str) {
    let width = plain.chars().count() + 2;
    let top = format!("┌{}┐", "─".repeat(width));
    let bot = format!("└{}┘", "─".repeat(width));
    println!("{BLUE}{top}{RESET}");
    println!("{BLUE}│{RESET} {styled} {BLUE}│{RESET}");
    println!("{BLUE}{bot}{RESET}");
}

fn parse_target(raw: &str) -> Option<OutputTarget> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "sigma" => Some(OutputTarget::Sigma),
        "eql" => Some(OutputTarget::Eql),
        "kql" => Some(OutputTarget::Kql),
        "snort" => Some(OutputTarget::Snort),
        "suricata" => Some(OutputTarget::Suricata),
        "yara" => Some(OutputTarget::Yara),
        _ => None,
    }
}

fn emit_target(
    target: &OutputTarget,
    ir: &ir::IrExpr,
    description: Option<&str>,
    sigma_targets: &Vec<String>,
) -> Result<EmitResult> {
    match target {
        OutputTarget::Sigma => emit_sigma(ir, description, sigma_targets),
        OutputTarget::Eql => emitters::eql::emit(ir, description),
        OutputTarget::Kql => emitters::kql::emit(ir, description),
        OutputTarget::Suricata => emitters::suricata::emit(ir, description),
        OutputTarget::Snort => emitters::snort::emit(ir, description),
        OutputTarget::Yara => emitters::yara::emit(ir, description),
    }
}

fn emit_target_with_mode(
    target: &OutputTarget,
    ir: &ir::IrExpr,
    description: Option<&str>,
    sigma_targets: &Vec<String>,
    mode: ConversionMode,
) -> Result<EmitResult> {
    let base = match emit_target(target, ir, description, sigma_targets) {
        Ok(res) => res,
        Err(e) => EmitResult::unsupported(e.to_string()),
    };
    if !matches!(mode, ConversionMode::Partial)
        || !matches!(base.status, FidelityStatus::Unsupported)
    {
        return Ok(base);
    }

    if let Some(partial) = try_partial_emit(target, ir, description, sigma_targets)? {
        return Ok(partial);
    }
    Ok(base)
}

fn try_partial_emit(
    target: &OutputTarget,
    ir: &ir::IrExpr,
    description: Option<&str>,
    sigma_targets: &Vec<String>,
) -> Result<Option<EmitResult>> {
    let predicates = match collect_predicates_for_partial(ir) {
        Some(p) => p,
        None => return Ok(None),
    };
    if predicates.len() < 2 {
        return Ok(None);
    }

    let mut rules = Vec::new();
    let mut notes = Vec::new();
    let mut omitted = Vec::new();
    for p in predicates {
        let expr = ir::IrExpr::Predicate(p.clone());
        let res = match emit_target(target, &expr, description, sigma_targets) {
            Ok(r) => r,
            Err(e) => EmitResult::unsupported(e.to_string()),
        };
        if matches!(res.status, FidelityStatus::Unsupported) {
            omitted.push(format_predicate(&p));
            continue;
        }
        if let Some(rule) = res.rule {
            rules.push(rule);
        }
        notes.extend(res.notes);
    }

    if rules.is_empty() || omitted.is_empty() {
        return Ok(None);
    }
    notes.push("@status:partial".to_string());
    notes.push("Supported subset emitted; unsupported predicates omitted".to_string());
    for o in omitted {
        notes.push(format!("omitted predicate: {o}"));
    }

    Ok(Some(EmitResult {
        status: FidelityStatus::Partial,
        notes,
        rule: Some(rules.join("\n\n--- partial clause ---\n\n")),
        cause: None,
    }))
}

fn collect_predicates_for_partial(ir: &ir::IrExpr) -> Option<Vec<ir::IrPredicate>> {
    fn walk(expr: &ir::IrExpr, out: &mut Vec<ir::IrPredicate>) -> bool {
        match expr {
            ir::IrExpr::Predicate(p) => {
                out.push(p.clone());
                true
            }
            ir::IrExpr::All(v) => v.iter().all(|e| walk(e, out)),
            ir::IrExpr::Qualified(inner, _) => walk(inner, out),
            ir::IrExpr::FollowedBy(_) => false,
            ir::IrExpr::Any(_) => false,
        }
    }
    let mut out = Vec::new();
    if walk(ir, &mut out) { Some(out) } else { None }
}

fn format_predicate(p: &ir::IrPredicate) -> String {
    let op = match p.op {
        ir::IrOp::Eq => "=",
        ir::IrOp::Ne => "!=",
        ir::IrOp::Gt => ">",
        ir::IrOp::Ge => ">=",
        ir::IrOp::Lt => "<",
        ir::IrOp::Le => "<=",
        ir::IrOp::Matches => "MATCHES",
        ir::IrOp::IsSubset => "ISSUBSET",
    };
    let value = match &p.value {
        ir::IrValue::String(s) => format!("'{s}'"),
        ir::IrValue::Integer(i) => i.to_string(),
        ir::IrValue::Boolean(b) => b.to_string(),
        ir::IrValue::Hex(h) => format!("h'{h}'"),
        ir::IrValue::Timestamp(ts) => format!("t'{ts}'"),
    };
    format!("{}:{} {} {}", p.target, p.field, op, value)
}

fn all_targets() -> Vec<OutputTarget> {
    vec![
        OutputTarget::Sigma,
        OutputTarget::Eql,
        OutputTarget::Kql,
        OutputTarget::Yara,
        OutputTarget::Snort,
        OutputTarget::Suricata,
    ]
}

#[derive(Debug, Clone)]
struct ResultView {
    runtime_status: String,
    conversion_confidence: u8,
    rule_confidence: Option<u8>,
    cause: Option<String>,
    summary: String,
    notes: Vec<String>,
    output: Option<String>,
}

#[derive(Debug, Clone)]
struct CsvRow {
    input_rule: String,
    target: String,
    runtime_status: String,
    conversion_confidence: u8,
    rule_confidence: Option<u8>,
    cause: String,
    summary: String,
    notes: String,
    output: String,
}

fn write_csv(dir: &PathBuf, rows: &[CsvRow]) -> Result<()> {
    fs::create_dir_all(dir)?;
    let path = dir.join("spuc_output.csv");
    let mut file = File::create(&path)?;

    writeln!(
        file,
        "input_rule,target,runtime_status,conversion_confidence,rule_confidence,cause,summary,notes,output"
    )?;
    for row in rows {
        writeln!(
            file,
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
            csv_escape(&row.input_rule),
            csv_escape(&row.target),
            csv_escape(&row.runtime_status),
            row.conversion_confidence,
            row.rule_confidence
                .map(|v| v.to_string())
                .unwrap_or_default(),
            csv_escape(&row.cause),
            csv_escape(&row.summary),
            csv_escape(&row.notes),
            csv_escape(&row.output)
        )?;
    }

    eprintln!("Wrote CSV results to {}", path.display());
    Ok(())
}

fn csv_escape(value: &str) -> String {
    value.replace('\"', "\"\"")
}

fn build_result_view(label: &str, res: &EmitResult, rule_confidence: Option<u8>) -> ResultView {
    let notes = visible_notes(&res.notes)
        .into_iter()
        .map(|n| capitalize_first(&n))
        .collect::<Vec<_>>();
    ResultView {
        runtime_status: status_label(&res.status).to_string(),
        conversion_confidence: computed_confidence(label, &res.status, &res.notes),
        rule_confidence,
        cause: res
            .cause
            .as_ref()
            .map(|c| failure_cause_human(c).to_string()),
        summary: capitalize_first(&result_summary(res, &notes)),
        notes,
        output: res.rule.clone(),
    }
}

fn result_summary(res: &EmitResult, notes: &[String]) -> String {
    match res.status {
        FidelityStatus::Exact => "semantic mapping preserved".to_string(),
        FidelityStatus::SchemaDependent => "mapping depends on backend schema/profile".to_string(),
        FidelityStatus::BackendDependent => {
            "mapping depends on backend runtime behavior".to_string()
        }
        FidelityStatus::Partial => "supported subset emitted".to_string(),
        FidelityStatus::Lossy => "mapping degraded but related".to_string(),
        FidelityStatus::Unsupported => notes
            .first()
            .cloned()
            .unwrap_or_else(|| "no honest mapping available".to_string()),
    }
}

fn render_result(label: &str, res: &EmitResult, view: &ResultView) {
    let pretty = pretty_label(label);
    let style = status_style(&res.status, view.conversion_confidence);
    println!();
    println!(
        "{}{}{} {} (status={}, conversion_confidence={}/100){RESET}",
        style.color,
        if style.bold { BOLD } else { "" },
        style.icon,
        pretty,
        view.runtime_status,
        view.conversion_confidence
    );
    if let Some(rule_confidence) = view.rule_confidence {
        println!("RuleConfidence={rule_confidence}/100");
    }
    if let Some(cause) = &view.cause {
        println!("Cause={cause}");
    }
    println!("Summary={}", view.summary);
    if !view.notes.is_empty() {
        println!("Notes={}", view.notes.join(" | "));
    }
    if let Some(rule) = &res.rule {
        if !matches!(res.status, FidelityStatus::Unsupported) {
            println!(
                "{}──────────────── output ────────────────{RESET}",
                style.color
            );
            println!("{rule}");
        }
    }
}

fn capitalize_first(input: &str) -> String {
    let mut chars = input.chars();
    match chars.next() {
        Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

struct StatusStyle {
    color: &'static str,
    icon: &'static str,
    bold: bool,
}

fn status_style(status: &FidelityStatus, confidence: u8) -> StatusStyle {
    if matches!(status, FidelityStatus::Unsupported) {
        return StatusStyle {
            color: RED,
            icon: "🔴",
            bold: true,
        };
    }
    if confidence < 50 {
        return StatusStyle {
            color: ORANGE,
            icon: "🟠",
            bold: false,
        };
    }
    if confidence < 70 {
        return StatusStyle {
            color: YELLOW,
            icon: "🟡",
            bold: false,
        };
    }

    match status {
        FidelityStatus::Exact => StatusStyle {
            color: GREEN,
            icon: "🟢",
            bold: true,
        },
        FidelityStatus::SchemaDependent
        | FidelityStatus::BackendDependent
        | FidelityStatus::Partial => StatusStyle {
            color: GREEN_SOFT,
            icon: "🟢",
            bold: false,
        },
        FidelityStatus::Lossy => StatusStyle {
            color: YELLOW,
            icon: "🟡",
            bold: false,
        },
        FidelityStatus::Unsupported => unreachable!(),
    }
}

fn visible_notes(notes: &[String]) -> Vec<String> {
    dedup_notes(notes)
        .into_iter()
        .filter(|n| !n.starts_with('@'))
        .collect()
}

fn computed_confidence(label: &str, status: &FidelityStatus, notes: &[String]) -> u8 {
    if matches!(status, FidelityStatus::Unsupported) {
        return 0;
    }
    let (min, max) = status_confidence_range(status);
    let mut confidence: u8 = match status {
        FidelityStatus::Exact => 95,
        FidelityStatus::SchemaDependent => 78,
        FidelityStatus::BackendDependent => 68,
        FidelityStatus::Partial => 58,
        FidelityStatus::Lossy => 45,
        FidelityStatus::Unsupported => 0,
    };
    for note in dedup_notes(notes) {
        let n = note.to_ascii_lowercase();
        if n == "@conf50" {
            confidence = confidence.min(50);
        }
        if n.contains("schema") || n.contains("ensure mapping exists") || n.contains("verify ") {
            confidence = confidence.saturating_sub(10);
        }
        if n.contains("timestamp") || n.contains("downgraded") {
            confidence = confidence.saturating_sub(12);
        }
        if n.contains("omitted predicate") {
            confidence = confidence.saturating_sub(15);
        }
        if n.contains("regex") || n.contains("matches") {
            confidence = confidence.saturating_sub(4);
        }
        if n.contains("lossy") || n.contains("semantic mismatch") {
            confidence = confidence.saturating_sub(12);
        }
    }
    if label == "eql" && has_timestamp_field_note(notes) && confidence > 80 {
        confidence = 80;
    }
    confidence.clamp(min, max)
}

fn pretty_label(label: &str) -> &'static str {
    match label {
        "snort" => "Snort",
        "suricata" => "Suricata",
        "sigma" => "Sigma",
        "eql" => "EQL",
        "kql" => "KQL",
        "yara" => "YARA",
        _ => "Target",
    }
}

fn status_confidence_range(status: &FidelityStatus) -> (u8, u8) {
    match status {
        FidelityStatus::Exact => (90, 100),
        FidelityStatus::SchemaDependent => (65, 85),
        FidelityStatus::BackendDependent => (55, 75),
        FidelityStatus::Partial => (40, 70),
        FidelityStatus::Lossy => (25, 60),
        FidelityStatus::Unsupported => (0, 0),
    }
}

fn status_label(status: &FidelityStatus) -> &'static str {
    match status {
        FidelityStatus::Exact => "exact",
        FidelityStatus::SchemaDependent => "schema-dependent",
        FidelityStatus::BackendDependent => "backend-dependent",
        FidelityStatus::Partial => "partial",
        FidelityStatus::Lossy => "lossy",
        FidelityStatus::Unsupported => "unsupported",
    }
}

fn failure_cause_human(cause: &FailureCause) -> &'static str {
    match cause {
        FailureCause::ParseError => "Parse error",
        FailureCause::NormalizationError => "Normalization error",
        FailureCause::EmitterNotImplemented => "Emitter not implemented",
        FailureCause::BackendSemanticsMissing => "Backend semantics missing",
        FailureCause::SchemaUncertain => "Schema uncertain",
    }
}

fn has_timestamp_field_note(notes: &[String]) -> bool {
    notes.iter().any(|n| {
        let low = n.to_ascii_lowercase();
        low.contains("file.created")
            || low.contains("file.ctime")
            || low.contains("file.atime")
            || low.contains("file.mtime")
            || low.contains("modified_time")
    })
}

fn dedup_notes(notes: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for n in notes {
        if !out.contains(n) {
            out.push(n.clone());
        }
    }
    out
}

fn apply_indicator_confidence(
    target: &OutputTarget,
    mut res: EmitResult,
    indicator_confidence: Option<u8>,
) -> EmitResult {
    let Some(conf) = indicator_confidence else {
        return res;
    };
    if let Some(rule) = &res.rule {
        let updated = match target {
            OutputTarget::Sigma => inject_sigma_indicator_confidence(rule, conf),
            OutputTarget::Yara => inject_yara_indicator_confidence(rule, conf),
            OutputTarget::Snort | OutputTarget::Suricata => {
                format!("# spuc_indicator_confidence: {conf}\n{rule}")
            }
            OutputTarget::Eql | OutputTarget::Kql => {
                format!("// spuc_indicator_confidence: {conf}\n{rule}")
            }
        };
        res.rule = Some(updated);
    }
    res
}

fn inject_sigma_indicator_confidence(rule: &str, conf: u8) -> String {
    rule.split("---\n")
        .map(|doc| {
            if doc.contains("x_spuc_indicator_confidence:") {
                doc.to_string()
            } else {
                format!("x_spuc_indicator_confidence: {conf}\n{doc}")
            }
        })
        .collect::<Vec<_>>()
        .join("---\n")
}

fn inject_yara_indicator_confidence(rule: &str, conf: u8) -> String {
    if rule.contains("spuc_indicator_confidence") {
        return rule.to_string();
    }
    if rule.contains("meta:\n") {
        return rule.replacen(
            "meta:\n",
            &format!("meta:\n    spuc_indicator_confidence = \"{conf}\"\n"),
            1,
        );
    }
    format!("/* spuc_indicator_confidence: {conf} */\n{rule}")
}

fn finalize_result(label: &str, mut res: EmitResult) -> EmitResult {
    res.notes = dedup_notes(&res.notes);
    if matches!(res.status, FidelityStatus::Unsupported) {
        if res.cause.is_none() {
            res.cause = Some(classify_unsupported_cause(&res.notes.join(" | ")));
        }
        return res;
    }
    let raw = res.notes.join(" | ").to_ascii_lowercase();
    if raw.contains("@status:partial") || raw.contains("omitted predicate:") {
        res.status = FidelityStatus::Partial;
    } else if raw.contains("lossy") || raw.contains("downgraded") {
        res.status = FidelityStatus::Lossy;
    } else if raw.contains("ensure mapping exists")
        || raw.contains("verify ")
        || raw.contains("schema")
        || raw.contains("non-standard")
        || raw.contains("flattened")
    {
        res.status = FidelityStatus::SchemaDependent;
    } else if raw.contains("backend") || (raw.contains("regex") && label == "sigma") {
        res.status = FidelityStatus::BackendDependent;
    } else {
        res.status = FidelityStatus::Exact;
    }
    res.cause = None;
    res
}

fn parse_and_normalize(rule: &str) -> Result<ir::IrExpr, EmitResult> {
    let ast = parser::parse_rule(rule)
        .map_err(|e| EmitResult::unsupported_with_cause(e.to_string(), FailureCause::ParseError))?;
    normalize::stix_to_ir(&ast).map_err(|e| {
        EmitResult::unsupported_with_cause(e.to_string(), FailureCause::NormalizationError)
    })
}

fn classify_unsupported_cause(msg: &str) -> FailureCause {
    let m = msg.to_ascii_lowercase();
    if m.contains("parse") {
        FailureCause::ParseError
    } else if m.contains("normalize")
        || m.contains("normalization")
        || m.contains("reference traversal not implemented")
        || m.contains("outside current normalization scope")
    {
        FailureCause::NormalizationError
    } else if m.contains("mapping exists")
        || m.contains("schema")
        || m.contains("field")
        || m.contains("verify ")
    {
        FailureCause::SchemaUncertain
    } else if m.contains("does not support")
        || m.contains("not support")
        || m.contains("semantic")
        || m.contains("unsupported")
    {
        FailureCause::BackendSemanticsMissing
    } else {
        FailureCause::EmitterNotImplemented
    }
}

fn print_coverage(target: Option<OutputTarget>) {
    match target {
        Some(t) => print_coverage_for(t),
        None => {
            println!("{YELLOW}Select a target to view coverage:{RESET}");
            let all = all_targets();
            for (idx, t) in all.iter().enumerate() {
                println!("  {}. {:?}", idx + 1, t);
            }
            print!("Enter number: ");
            let _ = std::io::stdout().flush();
            let mut buf = String::new();
            if let Ok(_) = std::io::stdin().read_line(&mut buf) {
                if let Ok(choice) = buf.trim().parse::<usize>() {
                    if choice > 0 && choice <= all.len() {
                        print_coverage_for(all[choice - 1].clone());
                    }
                }
            }
        }
    }
}

fn print_coverage_for(target: OutputTarget) {
    let info = coverage_info();
    if let Some((desc, object_paths, operators, qualifiers, notes)) = info.get(&target) {
        println!();
        render_coverage_header(&target);
        println!();

        println!("{BOLD}Description{RESET}");
        for line in desc {
            println!("  - {}", line);
        }

        println!();
        println!("{BOLD}Object paths (type:property){RESET}");
        for obs in object_paths {
            println!("  - {}", obs);
        }

        println!();
        println!("{BOLD}Operators{RESET}");
        for op in operators {
            println!("  - {}", op);
        }

        if !qualifiers.is_empty() {
            println!();
            println!("{BOLD}Observation Qualifiers{RESET}");
            for q in qualifiers {
                println!("  - {}", q);
            }
        }

        if !notes.is_empty() {
            println!();
            println!("{BOLD}Notes{RESET}");
            for note in notes {
                println!("  - {}", note);
            }
        }

        println!();
        println!(
            "{BOLD}Fidelity model{RESET}\n  - coverage = path/operator availability\n  - runtime_status + conversion_confidence = semantic fidelity at conversion time"
        );
    } else {
        println!("{RED}No coverage info for {:?}{RESET}", target);
    }
}

fn coverage_info() -> HashMap<
    OutputTarget,
    (
        Vec<String>,
        Vec<String>,
        Vec<String>,
        Vec<String>,
        Vec<String>,
    ),
> {
    let mut map = HashMap::new();
    map.insert(
        OutputTarget::Sigma,
        (
            vec![
                "Sigma rule generator for detections".to_string(),
                "Emits selections with AND/OR; can be converted by sigma-cli plugins".to_string(),
                "Docs: https://sigmahq.io".to_string(),
            ],
            vec![
                "domain-name:value (ops: =, LIKE, MATCHES)".to_string(),
                "url:value (ops: =, LIKE, MATCHES)".to_string(),
                "email-message:from_ref.value | sender_ref.value | to_refs[*].value | body_multipart[*].body_raw_ref.name (ops: =)".to_string(),
                "email-message:subject | body (ops: =, LIKE, MATCHES)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'MD5' | 'SHA-1' | 'SHA-256' | 'SHA-512' | 'SHA3-256' | 'SHA3-512' | SSDEEP | TLSH (ops: =, !=)".to_string(),
                "file:atime (ops: =, !=, >, >=, <, <=; timestamp only)".to_string(),
                "file:ctime (ops: =, !=, >, >=, <, <=; timestamp only)".to_string(),
                "file:hashes.MD5 (ops: =, !=)".to_string(),
                "file:hashes.SHA-1 (ops: =, !=)".to_string(),
                "file:hashes.SHA-256 (ops: =, !=)".to_string(),
                "file:hashes.SHA-512 (ops: =, !=)".to_string(),
                "file:hashes.SHA3-256 (ops: =, !=)".to_string(),
                "file:hashes.SHA3-512 (ops: =, !=)".to_string(),
                "file:hashes.SSDEEP (ops: =, !=)".to_string(),
                "file:hashes.TLSH (ops: =, !=)".to_string(),
                "file:mtime (ops: =, !=, >, >=, <, <=; timestamp only)".to_string(),
                "file:name (ops: =, !=, LIKE, MATCHES)".to_string(),
                "file:size (ops: =, !=, >, >=, <, <=)".to_string(),
                "directory:path (ops: =, !=, LIKE, MATCHES)".to_string(),
                "directory:ctime | mtime | atime (ops: =, !=, >, >=, <, <=; timestamp only)".to_string(),
                "network-traffic:src_ref.value | dst_ref.value (ops: =, LIKE, MATCHES, ISSUBSET)".to_string(),
                "network-traffic:src_port | dst_port (ops: =)".to_string(),
                "network-traffic:protocols (ops: =)".to_string(),
                "autonomous-system:number (ops: =, !=, >, >=, <, <=)".to_string(),
                "autonomous-system:name | rir (ops: =, !=, LIKE, MATCHES)".to_string(),
                "user-account:account_type | account_login (ops: =, !=, LIKE, MATCHES)".to_string(),
                "user-account:user_id (ops: =, !=, >, >=, <, <=)".to_string(),
                "windows-registry-key:key | values[*].name | values[*].data | values[*].data_type (ops: =, !=, MATCHES)".to_string(),
                "windows-registry-key:modified_time (ops: =, !=, >, >=, <, <=; timestamp only)".to_string(),
            ],
            vec!["=", "!=", ">", ">=", "<", "<=", "LIKE", "MATCHES (regex)", "ISSUBSET (CIDR)"]
                .into_iter()
                .map(String::from)
                .collect(),
            vec![
                "REPEATS: advisory-only (cardinality/event identity not enforceable; status downgraded to partial)".to_string(),
                "START/STOP: not supported".to_string(),
                "WITHIN: not supported".to_string(),
            ],
            vec![
                "Standalone ipv4/ipv6/mac observables are unsupported in Sigma baseline to avoid implicit directionality bias".to_string(),
                "Regex/LIKE supported on domain, network refs, registry keys, email subject/body".to_string(),
                "Raw STIX path passthrough is disabled; unmapped fields return unsupported".to_string(),
                "FOLLOWEDBY is unsupported in Sigma baseline (no honest sequence semantics)".to_string(),
                "Multi-entity user-account conjunctions are unsupported in strict mode (single-event semantics cannot be preserved)".to_string(),
                "network-traffic:* is the canonical network family; standalone IP/domain/URL can be weaker without connection context".to_string(),
            ],
        ),
    );
    map.insert(
        OutputTarget::Eql,
        (
            vec![
                "Elastic EQL-style endpoint hunting queries".to_string(),
                "Best effort mapping for process/file/network/email/registry telemetry".to_string(),
                "Docs: https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html".to_string(),
            ],
            vec![
                "artifact:hashes.MD5 (ops: =, !=)".to_string(),
                "artifact:hashes.SHA-1 (ops: =, !=)".to_string(),
                "artifact:hashes.SHA-256 (ops: =, !=)".to_string(),
                "artifact:hashes.SHA-512 (ops: =, !=)".to_string(),
                "artifact:hashes.SHA3-256 (ops: =, !=)".to_string(),
                "artifact:hashes.SHA3-512 (ops: =, !=)".to_string(),
                "artifact:hashes.SSDEEP (ops: =, !=)".to_string(),
                "artifact:hashes.TLSH (ops: =, !=)".to_string(),
                "artifact:mime_type (ops: =, !=, LIKE, MATCHES)".to_string(),
                "artifact:payload_bin (ops: =, !=, LIKE, MATCHES)".to_string(),
                "domain-name:value (ops: =, !=, LIKE, MATCHES)".to_string(),
                "url:value (ops: =, !=, LIKE, MATCHES)".to_string(),
                "file:hashes.MD5 (ops: =, !=)".to_string(),
                "file:hashes.SHA-1 (ops: =, !=)".to_string(),
                "file:hashes.SHA-256 (ops: =, !=)".to_string(),
                "file:hashes.SHA-512 (ops: =, !=)".to_string(),
                "file:hashes.SHA3-256 (ops: =, !=)".to_string(),
                "file:hashes.SHA3-512 (ops: =, !=)".to_string(),
                "file:hashes.SSDEEP (ops: =, !=)".to_string(),
                "file:hashes.TLSH (ops: =, !=)".to_string(),
                "file:name (ops: =, !=, LIKE, MATCHES)".to_string(),
                "file:size (ops: =, !=, >, >=, <, <=)".to_string(),
                "directory:path (ops: =, !=, LIKE, MATCHES)".to_string(),
                "directory:ctime | mtime | atime (ops: =, !=, >, >=, <, <=)".to_string(),
                "email-message:body | body_multipart[*].body_raw_ref.name | from_ref.value | sender_ref.value | subject | to_refs[*].value (ops: =, !=, LIKE, MATCHES)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'MD5' (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA-1' (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA-256' (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA-512' (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA3-256' (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA3-512' (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.SSDEEP (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.TLSH (ops: =, !=)".to_string(),
                "ipv4-addr:value | ipv6-addr:value (ops: =, !=, LIKE, MATCHES, ISSUBSET)".to_string(),
                "mac-addr:value (ops: =, !=, LIKE, MATCHES)".to_string(),
                "network-traffic:protocols (ops: =, !=, LIKE, MATCHES)".to_string(),
                "network-traffic:src_ref.value | dst_ref.value (ops: =, !=, LIKE, MATCHES, ISSUBSET)".to_string(),
                "network-traffic:src_port | dst_port (ops: =, !=, >, >=, <, <=)".to_string(),
                "autonomous-system:number (ops: =, !=, >, >=, <, <=)".to_string(),
                "autonomous-system:name | rir (ops: =, !=, LIKE, MATCHES)".to_string(),
                "process:image_ref.name | process:command_line (ops: =, !=, LIKE, MATCHES)".to_string(),
                "user-account:account_login | account_type (ops: =, !=, LIKE, MATCHES)".to_string(),
                "user-account:user_id (ops: =, !=, >, >=, <, <=)".to_string(),
                "windows-registry-key:key | values[*].name | values[*].data | values[*].data_type (ops: =, !=, LIKE, MATCHES)".to_string(),
                "windows-registry-key:modified_time (ops: =, !=, >, >=, <, <=)".to_string(),
            ],
            vec!["=", "!=", ">", ">=", "<", "<=", "LIKE", "MATCHES (regex)", "ISSUBSET (CIDR)"]
                .into_iter()
                .map(String::from)
                .collect(),
            vec![
                "REPEATS: advisory-only (cardinality/event identity not enforceable in plain where-clause)".to_string(),
                "START/STOP: supported as @timestamp filter".to_string(),
                "WITHIN: supported for FOLLOWEDBY via `sequence with maxspan`; advisory-only in plain where-clause".to_string(),
            ],
            vec![
                "Mixed datasets in one expression fallback to `any where ...`".to_string(),
                "artifact:payload_bin uses STIX byte normalization; regex behavior depends on backend field encoding".to_string(),
                "FOLLOWEDBY is supported via EQL `sequence`; outer WITHIN lowers to `maxspan`, while per-step qualifiers remain unsupported".to_string(),
                "network-traffic:* mappings are preferred; standalone IP/domain/URL mappings are backend-dependent shortcuts".to_string(),
                "network-traffic:*_ref.type is not mapped in EQL baseline (kept unsupported to avoid pseudo-fields)".to_string(),
                "Multi-entity user-account conjunctions are unsupported in strict mode (single-event semantics cannot be preserved)".to_string(),
            ],
        ),
    );
    map.insert(
        OutputTarget::Kql,
        (
            vec![
                "KQL queries aligned to Microsoft Defender/Sentinel-style tables".to_string(),
                "Maps STIX observables to DeviceProcessEvents/DeviceNetworkEvents/etc.".to_string(),
                "Docs: https://learn.microsoft.com/azure/data-explorer/kusto/query/".to_string(),
            ],
            vec![
                "artifact:hashes.MD5 -> EmailAttachmentInfo (ops: =, !=)".to_string(),
                "artifact:hashes.SHA-1 -> EmailAttachmentInfo (ops: =, !=)".to_string(),
                "artifact:hashes.SHA-256 -> EmailAttachmentInfo (ops: =, !=)".to_string(),
                "artifact:hashes.SHA-512 -> EmailAttachmentInfo (ops: =, !=)".to_string(),
                "artifact:hashes.SHA3-256 -> EmailAttachmentInfo (ops: =, !=)".to_string(),
                "artifact:hashes.SHA3-512 -> EmailAttachmentInfo (ops: =, !=)".to_string(),
                "artifact:hashes.SSDEEP -> EmailAttachmentInfo (ops: =, !=)".to_string(),
                "artifact:hashes.TLSH -> EmailAttachmentInfo (ops: =, !=)".to_string(),
                "artifact:mime_type -> DeviceEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "artifact:payload_bin -> DeviceEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "domain-name:value -> DeviceNetworkEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "url:value -> DeviceNetworkEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "email-message:body | body_multipart[*].body_raw_ref.name | from_ref.value | sender_ref.value | subject | to_refs[*].value -> EmailEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'MD5' -> EmailEvents (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA-1' -> EmailEvents (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA-256' -> EmailEvents (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA-512' -> EmailEvents (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA3-256' -> EmailEvents (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.'SHA3-512' -> EmailEvents (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.SSDEEP -> EmailEvents (ops: =, !=)".to_string(),
                "email-message:body_multipart[*].body_raw_ref.hashes.TLSH -> EmailEvents (ops: =, !=)".to_string(),
                "file:hashes.MD5 -> DeviceFileEvents (ops: =, !=)".to_string(),
                "file:hashes.SHA-1 -> DeviceFileEvents (ops: =, !=)".to_string(),
                "file:hashes.SHA-256 -> DeviceFileEvents (ops: =, !=)".to_string(),
                "file:hashes.SHA-512 -> DeviceFileEvents (ops: =, !=)".to_string(),
                "file:hashes.SHA3-256 -> DeviceFileEvents (ops: =, !=)".to_string(),
                "file:hashes.SHA3-512 -> DeviceFileEvents (ops: =, !=)".to_string(),
                "file:hashes.SSDEEP -> DeviceFileEvents (ops: =, !=)".to_string(),
                "file:hashes.TLSH -> DeviceFileEvents (ops: =, !=)".to_string(),
                "file:name -> DeviceFileEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "file:size -> DeviceFileEvents (ops: =, !=, >, >=, <, <=)".to_string(),
                "directory:path -> DeviceFileEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "directory:ctime | mtime | atime -> DeviceFileEvents (ops: =, !=, >, >=, <, <=)".to_string(),
                "ipv4-addr:value | ipv6-addr:value -> DeviceNetworkEvents (ops: =, !=, LIKE, MATCHES, ISSUBSET)".to_string(),
                "mac-addr:value -> DeviceNetworkEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "network-traffic:protocols -> DeviceNetworkEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "network-traffic:src_ref.value | dst_ref.value -> DeviceNetworkEvents (ops: =, !=, LIKE, MATCHES, ISSUBSET)".to_string(),
                "network-traffic:src_port | dst_port -> DeviceNetworkEvents (ops: =, !=, >, >=, <, <=)".to_string(),
                "autonomous-system:number -> DeviceNetworkEvents (ops: =, !=, >, >=, <, <=)".to_string(),
                "autonomous-system:name | rir -> DeviceNetworkEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "process:image_ref.name | process:command_line -> DeviceProcessEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "user-account:account_login | account_type -> IdentityInfo (ops: =, !=, LIKE, MATCHES)".to_string(),
                "user-account:user_id -> IdentityInfo (ops: =, !=, >, >=, <, <=)".to_string(),
                "windows-registry-key:key | values[*].name | values[*].data | values[*].data_type -> RegistryEvents (ops: =, !=, LIKE, MATCHES)".to_string(),
                "windows-registry-key:modified_time -> RegistryEvents (ops: =, !=, >, >=, <, <=)".to_string(),
            ],
            vec!["=", "!=", ">", ">=", "<", "<=", "LIKE", "MATCHES (regex)", "ISSUBSET (CIDR)"]
                .into_iter()
                .map(String::from)
                .collect(),
            vec![
                "REPEATS: advisory-only (cardinality/event identity not enforceable in plain where-clause)".to_string(),
                "START/STOP: supported as Timestamp filter".to_string(),
                "WITHIN: accepted as advisory note (no strict event-window enforcement)".to_string(),
            ],
            vec![
                "Some fields use non-standard columns and are emitted with advisory notes".to_string(),
                "If one rule mixes tables, output falls back to DeviceEvents".to_string(),
                "artifact:payload_bin uses STIX byte normalization; regex behavior depends on backend field encoding".to_string(),
                "FOLLOWEDBY is unsupported in KQL baseline (no honest sequence lowering implemented)".to_string(),
                "network-traffic:* mappings are preferred; standalone IP/domain/URL mappings are backend-dependent shortcuts".to_string(),
                "network-traffic:*_ref.type is not mapped in KQL baseline (kept unsupported to avoid pseudo-fields)".to_string(),
                "Multi-entity user-account conjunctions are unsupported in strict mode (single-row semantics cannot be preserved)".to_string(),
            ],
        ),
    );
    map.insert(
        OutputTarget::Suricata,
        (
            vec![
                "Suricata inline/IDS alerts".to_string(),
                "Builds IP/port-based alerts for network traffic".to_string(),
                "Docs: https://suricata.io/".to_string(),
            ],
            vec![
                "ipv4-addr:value (ops: =, ISSUBSET)".to_string(),
                "network-traffic:src_ref.value (ops: =, ISSUBSET)".to_string(),
                "network-traffic:dst_ref.value (ops: =, ISSUBSET)".to_string(),
                "network-traffic:src_port (ops: =)".to_string(),
                "network-traffic:dst_port (ops: =)".to_string(),
                "network-traffic:protocols (ops: =)".to_string(),
                "artifact:payload_bin (ops: =, !=, LIKE, MATCHES)".to_string(),
            ],
            vec!["=", "!=", "LIKE", "MATCHES (regex)", "ISSUBSET (CIDR)"]
                .into_iter()
                .map(String::from)
                .collect(),
            vec![
                "REPEATS: not supported (cardinality semantics cannot be preserved in current lowering)".to_string(),
                "START/STOP: not supported".to_string(),
                "WITHIN: not supported".to_string(),
            ],
            vec![
                "Network predicates remain equality-based except CIDR ISSUBSET on IP-capable fields".to_string(),
                "FOLLOWEDBY is unsupported in Suricata baseline".to_string(),
                "artifact:payload_bin equality is lowered to content containment (partial fidelity)".to_string(),
                "artifact:payload_bin regex uses pcre/content and is backend-dependent".to_string(),
                "network-traffic:* equality is the canonical Suricata mapping; standalone IP shortcuts can be weaker".to_string(),
            ],
        ),
    );
    map.insert(
        OutputTarget::Snort,
        (
            vec![
                "Snort alert signatures".to_string(),
                "Builds IP/port-based alerts for network traffic".to_string(),
                "Docs: https://snort.org/".to_string(),
            ],
            vec![
                "ipv4-addr:value (ops: =, ISSUBSET)".to_string(),
                "network-traffic:src_ref.value (ops: =, ISSUBSET)".to_string(),
                "network-traffic:dst_ref.value (ops: =, ISSUBSET)".to_string(),
                "network-traffic:src_port (ops: =)".to_string(),
                "network-traffic:dst_port (ops: =)".to_string(),
                "network-traffic:protocols (ops: =)".to_string(),
                "artifact:payload_bin (ops: =, !=, LIKE, MATCHES)".to_string(),
            ],
            vec!["=", "!=", "LIKE", "MATCHES (regex)", "ISSUBSET (CIDR)"]
                .into_iter()
                .map(String::from)
                .collect(),
            vec![
                "REPEATS: not supported (cardinality semantics cannot be preserved in current lowering)".to_string(),
                "START/STOP: not supported".to_string(),
                "WITHIN: not supported".to_string(),
            ],
            vec![
                "Network predicates remain equality-based except CIDR ISSUBSET on IP-capable fields".to_string(),
                "FOLLOWEDBY is unsupported in Snort baseline".to_string(),
                "artifact:payload_bin equality is lowered to content containment (partial fidelity)".to_string(),
                "artifact:payload_bin regex uses pcre/content and is backend-dependent".to_string(),
                "network-traffic:* equality is the canonical Snort mapping; standalone IP shortcuts can be weaker".to_string(),
            ],
        ),
    );
    map.insert(
        OutputTarget::Yara,
        (
            vec![
                "YARA rules for literal matching".to_string(),
                "Only native file/content predicates are emitted; telemetry metadata is rejected".to_string(),
                "Docs: https://yara.readthedocs.io/".to_string(),
            ],
            vec![
                "artifact:payload_bin (ops: =, !=, LIKE, MATCHES)".to_string(),
                "file:hashes.MD5 (ops: =, !=)".to_string(),
                "file:hashes.SHA-1 (ops: =, !=)".to_string(),
                "file:hashes.SHA-256 (ops: =, !=)".to_string(),
                "file:magic_number_hex (ops: =, !=)".to_string(),
                "file:size (ops: =, !=, >, >=, <, <=)".to_string(),
            ],
            vec!["=", "!=", ">", ">=", "<", "<=", "LIKE", "MATCHES (regex)"]
                .into_iter()
                .map(String::from)
                .collect(),
            vec![
                "REPEATS: not supported (cardinality semantics cannot be preserved in current lowering)".to_string(),
                "START/STOP: not supported".to_string(),
                "WITHIN: not supported".to_string(),
            ],
            vec![
                "OR and FOLLOWEDBY unsupported; timestamps unsupported".to_string(),
                "Observation operator FOLLOWEDBY is rejected explicitly".to_string(),
                "Telemetry/metadata observables (network/process/registry/user/email/directory/autonomous-system) are unsupported".to_string(),
                "Standalone IP/domain/URL/mac mappings are rejected to avoid misleading content-only downgrades".to_string(),
                "file:name and timestamp metadata are unsupported due semantic mismatch".to_string(),
                "artifact:payload_bin equality is exact full-payload matching; regex matching remains backend-dependent".to_string(),
                "Only file hash MD5/SHA-1/SHA-256 are mapped natively".to_string(),
            ],
        ),
    );
    map
}

#[derive(Debug, Deserialize)]
struct RpcRequest {
    rule: String,
    #[serde(default)]
    to: Vec<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    sigma_targets: Vec<String>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    rule_confidence: Option<u8>,
}

#[derive(Debug, Serialize)]
struct RpcResult {
    target: String,
    runtime_status: String,
    conversion_confidence: u8,
    rule_confidence: Option<u8>,
    cause: Option<String>,
    summary: String,
    notes: Vec<String>,
    output: Option<String>,
}

#[derive(Debug, Serialize)]
struct RpcResponse {
    ok: bool,
    results: Vec<RpcResult>,
    error: Option<String>,
}

fn run_service(port: u16, token: Option<String>) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let token = Arc::new(token.unwrap_or_else(generate_token));
    service_log_info(&format!("Service listening on http://127.0.0.1:{port}/rpc"));
    service_log_info(&format!("Bearer token: {}", token));
    service_log_info(&format!(
        "Example curl: curl -X POST 'http://127.0.0.1:{port}/rpc' -H 'Authorization: Bearer {token}' -H 'Content-Type: application/json' -d '{{\"rule\":\"[ipv4-addr:value = \\'1.1.1.1\\']\",\"to\":[\"sigma\"]}}'"
    ));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let token = Arc::clone(&token);
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream, &token) {
                        service_log_error(&format!("service error: {e}"));
                    }
                });
            }
            Err(e) => service_log_error(&format!("accept error: {e}")),
        }
    }
    Ok(())
}

fn service_log_info(msg: &str) {
    let ts = Utc::now().to_rfc3339();
    println!("{BLUE}[{ts} UTC+0]{RESET} {msg}");
}

fn service_log_error(msg: &str) {
    let ts = Utc::now().to_rfc3339();
    eprintln!("{RED}[{ts} UTC+0] {msg}{RESET}");
}

fn generate_token() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("spuc-{now:x}-{:x}", std::process::id())
}

fn handle_client(mut stream: TcpStream, token: &str) -> Result<()> {
    let mut reader = IoBufReader::new(&mut stream);
    let mut req_line = String::new();
    if reader.read_line(&mut req_line)? == 0 {
        return Ok(());
    }

    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() < 2 {
        return write_http_json(
            &mut stream,
            400,
            RpcResponse {
                ok: false,
                results: vec![],
                error: Some("bad request".to_string()),
            },
        );
    }
    let method = parts[0];
    let path = parts[1];

    let mut auth_header = String::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 || line == "\r\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let value = v.trim().to_string();
            if key == "authorization" {
                auth_header = value;
            } else if key == "content-length" {
                content_length = value.parse::<usize>().unwrap_or(0);
            }
        }
    }

    if method != "POST" || path != "/rpc" {
        return write_http_json(
            &mut stream,
            404,
            RpcResponse {
                ok: false,
                results: vec![],
                error: Some("not found".to_string()),
            },
        );
    }

    let expected = format!("Bearer {token}");
    if auth_header != expected {
        return write_http_json(
            &mut stream,
            401,
            RpcResponse {
                ok: false,
                results: vec![],
                error: Some("unauthorized".to_string()),
            },
        );
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    let request: RpcRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(e) => {
            return write_http_json(
                &mut stream,
                400,
                RpcResponse {
                    ok: false,
                    results: vec![],
                    error: Some(format!("invalid JSON: {e}")),
                },
            );
        }
    };

    let response = handle_rpc(request);
    write_http_json(&mut stream, 200, response)
}

fn handle_rpc(request: RpcRequest) -> RpcResponse {
    if let Some(conf) = request.rule_confidence {
        if conf > 100 {
            return RpcResponse {
                ok: false,
                results: vec![],
                error: Some("rule_confidence must be in range 0..100".to_string()),
            };
        }
    }
    let parsed = parse_and_normalize(&request.rule);
    let mode = match request
        .mode
        .as_deref()
        .unwrap_or("strict")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "partial" => ConversionMode::Partial,
        _ => ConversionMode::Strict,
    };
    let targets = if request.to.is_empty() {
        all_targets()
    } else {
        request.to.iter().filter_map(|t| parse_target(t)).collect()
    };

    if targets.is_empty() {
        return RpcResponse {
            ok: false,
            results: vec![],
            error: Some("no valid target selected".to_string()),
        };
    }

    let mut results = Vec::new();
    for target in targets {
        let label = format!("{:?}", target).to_lowercase();
        let emit = match &parsed {
            Ok(ir_expr) => emit_target_with_mode(
                &target,
                ir_expr,
                request.description.as_deref(),
                &request.sigma_targets,
                mode.clone(),
            )
            .unwrap_or_else(|e| {
                EmitResult::unsupported_with_cause(
                    e.to_string(),
                    FailureCause::EmitterNotImplemented,
                )
            }),
            Err(e) => e.clone(),
        };
        let emit = finalize_result(&label, emit);
        let emit = apply_indicator_confidence(&target, emit, request.rule_confidence);
        let view = build_result_view(&label, &emit, request.rule_confidence);
        results.push(RpcResult {
            target: label,
            runtime_status: view.runtime_status,
            conversion_confidence: view.conversion_confidence,
            rule_confidence: view.rule_confidence,
            cause: view.cause,
            summary: view.summary,
            notes: view.notes,
            output: emit.rule,
        });
    }

    RpcResponse {
        ok: true,
        results,
        error: None,
    }
}

fn write_http_json(stream: &mut TcpStream, code: u16, payload: RpcResponse) -> Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Error",
    };
    let body = serde_json::to_string(&payload)?;
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        code,
        reason,
        body.len(),
        body
    )?;
    stream.flush()?;
    Ok(())
}

fn run_tui() -> Result<()> {
    println!("{GREEN}Interactive TUI (type 'help' for commands, 'exit' to quit){RESET}");
    let commands = vec!["convert", "doc", "learn", "verify", "help", "exit"];
    enum TuiMode {
        Normal,
        Learn(LearnSession),
    }
    let mut mode = TuiMode::Normal;
    let mut rl = DefaultEditor::new().map_err(|e| anyhow!("init line editor: {e}"))?;
    let hist_path = history_path();
    if let Some(path) = &hist_path {
        let _ = rl.load_history(path);
    }
    loop {
        let learn_mode_prompt = matches!(mode, TuiMode::Learn(_));
        let prompt = match &mode {
            TuiMode::Normal => format!("{BOLD}spuc>{RESET} "),
            TuiMode::Learn(session) => learn_prompt(session),
        };
        if learn_mode_prompt {
            println!();
        }
        let input = match rl.readline(&prompt) {
            Ok(line) => {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    let _ = rl.add_history_entry(trimmed);
                }
                if learn_mode_prompt {
                    println!();
                }
                trimmed.to_string()
            }
            Err(_) => break,
        };
        if input.is_empty() {
            continue;
        }
        if let TuiMode::Learn(session) = &mut mode {
            let leave_learn = handle_learn_input(session, &input)?;
            if leave_learn {
                mode = TuiMode::Normal;
            }
            continue;
        }

        if input == "exit" || input == "quit" {
            break;
        }
        if input == "help" || input == "?" {
            println!("Available commands:");
            println!("  convert <rule> [to target1,target2] [desc=<text>]");
            println!("  verify <rule>");
            println!("  doc [target]");
            println!("  learn [list|challenge-id]");
            println!("  exit");
            println!();
            continue;
        }
        if input.starts_with("doc") || input.starts_with("cover") || input.starts_with("coverage") {
            let normalized = if input.starts_with("coverage") {
                input.replacen("coverage", "doc", 1)
            } else if input.starts_with("cover") {
                input.replacen("cover", "doc", 1)
            } else {
                input.clone()
            };
            let parts: Vec<&str> = normalized.split_whitespace().collect();
            if parts.len() > 1 {
                if let Some(t) = parse_target(parts[1]) {
                    print_coverage(Some(t));
                } else {
                    println!("{RED}Unknown target {}{RESET}", parts[1]);
                }
            } else {
                print_coverage(None);
            }
            println!();
            continue;
        }
        if input.starts_with("learn") {
            let parts: Vec<&str> = input.split_whitespace().collect();
            let mut list_only = false;
            let mut challenge: Option<&str> = None;
            for arg in parts.iter().skip(1) {
                if arg.eq_ignore_ascii_case("list")
                    || arg.eq_ignore_ascii_case("--list")
                    || arg.eq_ignore_ascii_case("-l")
                {
                    list_only = true;
                } else {
                    challenge = Some(arg);
                }
            }
            let mut session = LearnSession::new();
            print_learn_intro(&session);
            print_learn_catalog(&session);
            if let Some(challenge_id) = challenge {
                if let Err(e) = select_learn_challenge(&mut session, challenge_id) {
                    println!("{RED}{}{RESET}", e);
                    println!();
                    continue;
                }
            } else if list_only {
                println!("Use a challenge id to start, e.g. core001");
            }
            mode = TuiMode::Learn(session);
            continue;
        }
        if input.starts_with("convert") {
            let rest = input.strip_prefix("convert").unwrap().trim();
            let mut rule = rest.to_string();
            let mut to = Vec::new();
            let mut description: Option<String> = None;
            let sigma_targets: Vec<String> = Vec::new();
            let mut mode = ConversionMode::Strict;
            if let Some(idx) = rest.rfind(" to ") {
                rule = rest[..idx].trim().to_string();
                let target_str = rest[idx + 4..].trim();
                for t in target_str.split(',') {
                    if let Some(tt) = parse_target(t.trim()) {
                        to.push(tt);
                    }
                }
            }
            if let Some(idx) = rule.rfind(" desc=") {
                description = Some(rule[idx + 6..].trim().to_string());
                rule = rule[..idx].trim().to_string();
            }
            if let Some(idx) = rule.rfind(" mode=") {
                let m = rule[idx + 6..].trim().to_ascii_lowercase();
                if m == "partial" {
                    mode = ConversionMode::Partial;
                }
                rule = rule[..idx].trim().to_string();
            }
            if rule.is_empty() {
                println!("{RED}No rule provided{RESET}");
                println!();
                continue;
            }
            let parsed = parse_and_normalize(&rule);
            let targets = if to.is_empty() { all_targets() } else { to };
            match parsed {
                Ok(ir_expr) => {
                    for target in targets {
                        let label = format!("{:?}", target).to_lowercase();
                        let result = emit_target_with_mode(
                            &target,
                            &ir_expr,
                            description.as_deref(),
                            &sigma_targets,
                            mode.clone(),
                        )
                        .unwrap_or_else(|e| {
                            EmitResult::unsupported_with_cause(
                                e.to_string(),
                                FailureCause::EmitterNotImplemented,
                            )
                        });
                        let result = finalize_result(&label, result);
                        let view = build_result_view(&label, &result, None);
                        render_result(&label, &result, &view);
                    }
                }
                Err(e) => {
                    let err = finalize_result("tui", e);
                    let view = build_result_view("tui", &err, None);
                    render_result("tui", &err, &view);
                }
            }
            println!();
            continue;
        }

        if input.starts_with("verify") {
            let rest = input.strip_prefix("verify").unwrap_or("").trim();
            if rest.is_empty() {
                println!("{RED}No rule provided{RESET}");
                println!();
                continue;
            }
            match verify_rule(rest) {
                Ok(_) => println!("{GREEN}✅ OK{RESET}"),
                Err(e) => println!("{RED}✖️  Error:{RESET} {e}"),
            }
            println!();
            continue;
        }

        let mut matches: Vec<_> = commands
            .iter()
            .filter(|c| c.starts_with(&input))
            .cloned()
            .collect();
        matches.sort();
        matches.dedup();
        if matches.len() == 1 {
            println!("{YELLOW}Did you mean '{}'?{RESET}", matches[0]);
        } else if !matches.is_empty() {
            println!("{YELLOW}Suggestions:{RESET} {}", matches.join(", "));
        } else {
            println!("{RED}Unknown command{RESET}");
        }
        println!();
    }
    if let Some(path) = &hist_path {
        let _ = rl.save_history(path);
    }
    Ok(())
}

fn history_path() -> Option<PathBuf> {
    if let Ok(home) = env::var("HOME") {
        let mut p = PathBuf::from(home);
        p.push(".spuc_history");
        Some(p)
    } else {
        None
    }
}
fn emit_sigma(
    ir: &ir::IrExpr,
    description: Option<&str>,
    sigma_targets: &Vec<String>,
) -> Result<EmitResult> {
    if sigma_targets.is_empty() {
        return emitters::sigma::emit(ir, description);
    }

    if !sigma_available() {
        return Ok(EmitResult::unsupported(
            "sigma-cli not found. Install with: pipx install sigma-cli && sigma plugin install <backend>",
        ));
    }

    let yaml = match emitters::sigma::emit(ir, description) {
        Ok(res) if res.rule.is_some() => res.rule.unwrap(),
        Ok(res) => return Ok(res),
        Err(e) => return Err(e),
    };

    let mut outputs = Vec::new();
    for target in sigma_targets {
        let res = run_sigma_convert(&yaml, target)?;
        outputs.push(format!("== {target} ==\n{res}"));
    }

    Ok(EmitResult::exact(outputs.join("\n\n")))
}

fn sigma_available() -> bool {
    Command::new("sigma")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_sigma_convert(yaml: &str, backend: &str) -> Result<String> {
    use std::io::Write;
    let mut path = std::env::temp_dir();
    path.push(format!("spuc_sigma_{}.yml", std::process::id()));
    {
        let mut f = File::create(&path)?;
        f.write_all(yaml.as_bytes())?;
    }
    let out = Command::new("sigma")
        .args(["convert", "-t", backend, path.to_string_lossy().as_ref()])
        .output()
        .map_err(|e| anyhow!("failed to run sigma-cli: {e}"))?;
    let _ = std::fs::remove_file(&path);
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(anyhow!(
            "sigma-cli failed ({backend}): {}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

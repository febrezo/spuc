#![allow(dead_code)]

use anyhow::{anyhow, Result};
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::{Hinter, HistoryHinter};
use rustyline::history::DefaultHistory;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, Helper};
use std::path::PathBuf;

use crate::catalog::{
    delete_adversary_entry, delete_rule_entry, edit_adversary_entry, edit_rule_entry,
    export_adversary_entry, export_rule_entry, filter_adversary_entries, filter_rule_entries,
    load_catalog_data, print_adversary_search_results, print_rule_search_results,
    resolve_adversary_selector, resolve_rule_selector, show_adversary_entry, show_rule_entry,
    CatalogAdversaryEntry, CatalogRuleEntry,
};
use crate::cli::{AbilityTarget, BuildOutput, ConversionMode, ExportFormat};
use crate::commands::common::{parse_ability_target, parse_build_outputs};
use crate::commands::emulate::{options as emulate_options, run as run_emulate_command};
use crate::commands::learn::{
    handle_learn_input, learn_prompt, print_learn_catalog, print_learn_intro,
    select_learn_challenge, LearnSession, LEARN_CHALLENGES,
};
use crate::commands::plan::{
    default_campaign_show, run as run_campaign_command, CampaignConsoleState, CampaignOptions,
    ALLOWED_PLATFORMS,
};
use crate::commands::translate::{options as translate_options, run as run_translate_command};
use crate::commands::verify::verify_rule;
use crate::paths;
use crate::ui::ansi::{BOLD, GREEN, RESET, YELLOW};
use crate::ui::print::{bold_cmd, quoted_bold, ui_error, ui_warn};

pub(crate) type SpucEditor = Editor<SpucRlHelper, DefaultHistory>;
pub(crate) struct SpucRlHelper {
    words: Vec<String>,
    hinter: HistoryHinter,
}

impl SpucRlHelper {
    fn with_words(words: Vec<String>) -> Self {
        Self {
            words,
            hinter: HistoryHinter {},
        }
    }
}

impl Helper for SpucRlHelper {}
impl Highlighter for SpucRlHelper {}
impl Validator for SpucRlHelper {}

impl Hinter for SpucRlHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, ctx: &Context<'_>) -> Option<String> {
        self.hinter.hint(line, pos, ctx)
    }
}

impl Completer for SpucRlHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let safe_pos = pos.min(line.len());
        let head = &line[..safe_pos];
        let start = head
            .rfind(char::is_whitespace)
            .map(|idx| idx + 1)
            .unwrap_or(0);
        let token = &head[start..];
        let mut out = Vec::new();
        for word in &self.words {
            if word.starts_with(token) {
                out.push(Pair {
                    display: word.clone(),
                    replacement: word.clone(),
                });
            }
        }
        Ok((start, out))
    }
}

fn command_suffix<'a>(input: &'a str, lower: &str, prefixes: &[&str]) -> Option<&'a str> {
    for prefix in prefixes {
        if lower.starts_with(prefix) {
            return Some(input[prefix.len()..].trim());
        }
    }
    None
}

#[derive(Default)]
struct TuiCatalogBrowserState {
    rule_results: Vec<CatalogRuleEntry>,
    adversary_results: Vec<CatalogAdversaryEntry>,
}

#[derive(Default)]
struct RuleCatalogConsoleState {
    results: Vec<CatalogRuleEntry>,
    current: Option<CatalogRuleEntry>,
}

#[derive(Default)]
struct AdversaryCatalogConsoleState {
    results: Vec<CatalogAdversaryEntry>,
    current: Option<CatalogAdversaryEntry>,
}

fn rule_catalog_prompt(state: &RuleCatalogConsoleState) -> String {
    if let Some(rule) = &state.current {
        format!("{BOLD}spuc (rules @ {})>{RESET} ", rule.rule_id)
    } else {
        format!("{BOLD}spuc (rules)>{RESET} ")
    }
}

fn adversary_catalog_prompt(state: &AdversaryCatalogConsoleState) -> String {
    if let Some(adversary) = &state.current {
        format!(
            "{BOLD}spuc (adversaries @ {})>{RESET} ",
            adversary.adversary_id
        )
    } else {
        format!("{BOLD}spuc (adversaries)>{RESET} ")
    }
}

fn rule_catalog_completion_words(state: &RuleCatalogConsoleState) -> Vec<String> {
    let mut out = vec![
        "help".to_string(),
        "list".to_string(),
        "search".to_string(),
        "show".to_string(),
        "export".to_string(),
        "edit".to_string(),
        "delete".to_string(),
        "back".to_string(),
        "exit".to_string(),
        "to".to_string(),
        "out=".to_string(),
        "name=".to_string(),
        "description=".to_string(),
        "confidence=".to_string(),
        "limit=".to_string(),
        "spuc-agent".to_string(),
        "bash".to_string(),
        "powershell".to_string(),
        "atomic-red-team".to_string(),
        "mitre-caldera".to_string(),
    ];
    if let Some(rule) = &state.current {
        out.push(format!("show {}", rule.rule_id));
        out.push("export spuc-agent".to_string());
        out.push("export bash".to_string());
        out.push("export powershell".to_string());
        out.push("export atomic-red-team".to_string());
        out.push("export mitre-caldera".to_string());
    }
    out
}

fn adversary_catalog_completion_words(state: &AdversaryCatalogConsoleState) -> Vec<String> {
    let mut out = vec![
        "help".to_string(),
        "list".to_string(),
        "search".to_string(),
        "show".to_string(),
        "export".to_string(),
        "edit".to_string(),
        "delete".to_string(),
        "back".to_string(),
        "exit".to_string(),
        "to".to_string(),
        "out=".to_string(),
        "show=".to_string(),
        "summary".to_string(),
        "canonical".to_string(),
        "artifact".to_string(),
        "manifest".to_string(),
        "all".to_string(),
        "name=".to_string(),
        "description=".to_string(),
        "confidence=".to_string(),
        "limit=".to_string(),
        "spuc-agent".to_string(),
        "bash".to_string(),
        "powershell".to_string(),
        "atomic-red-team".to_string(),
        "mitre-caldera".to_string(),
    ];
    if let Some(adversary) = &state.current {
        out.push(format!("show {}", adversary.adversary_id));
        out.push("export spuc-agent".to_string());
        out.push("export bash".to_string());
        out.push("export powershell".to_string());
        out.push("export atomic-red-team".to_string());
        out.push("export mitre-caldera".to_string());
    }
    out
}

fn run_tui_rules_console() -> Result<()> {
    println!("{YELLOW}Rules catalog initialized.{RESET}");
    let mut state = RuleCatalogConsoleState::default();
    let mut rl = new_spuc_editor()?;
    load_editor_history(&mut rl);
    loop {
        let prompt = rule_catalog_prompt(&state);
        set_editor_words(&mut rl, rule_catalog_completion_words(&state));
        let Some(line) = read_line_with_spacing(&mut rl, &prompt)? else {
            save_editor_history(&mut rl);
            return Ok(());
        };
        let input = line.trim();
        if input.is_empty() {
            continue;
        }
        let lower = input.to_ascii_lowercase();
        if lower == "help" || lower == "?" || lower == "help rules" {
            print_tui_topic_help("rules");
            continue;
        }
        if lower.starts_with("help ") {
            print_tui_topic_help("rules");
            continue;
        }
        if lower == "back" || lower == "backp" {
            if state.current.is_some() {
                state.current = None;
                println!("{YELLOW}Back to rules catalog.{RESET}");
            } else {
                save_editor_history(&mut rl);
                return Ok(());
            }
            continue;
        }
        if lower == "exit" || lower == "quit" {
            save_editor_history(&mut rl);
            return Ok(());
        }

        let (catalog, _abilities, all_rules, _adversaries) = load_catalog_data()?;
        if lower == "list" || lower.starts_with("list ") {
            let limit = match parse_tui_list_limit_command(input) {
                Ok(limit) => limit,
                Err(err) => {
                    ui_error(&err.to_string());
                    continue;
                }
            };
            let results = filter_rule_entries(&all_rules, None, limit);
            state.results = results.clone();
            print_rule_search_results(&results, all_rules.len(), "Rules");
            continue;
        }
        if lower == "search" || lower.starts_with("search ") {
            let (query, limit) = match parse_tui_search_command(input) {
                Ok(values) => values,
                Err(err) => {
                    ui_error(&err.to_string());
                    continue;
                }
            };
            let results = filter_rule_entries(&all_rules, query.as_deref(), Some(limit));
            state.results = results.clone();
            print_rule_search_results(&results, all_rules.len(), "Rules");
            continue;
        }
        if lower == "show" {
            let entry = match resolve_rule_selector_or_current(
                "",
                &all_rules,
                Some(&state.results),
                state.current.as_ref(),
            ) {
                Ok(entry) => entry,
                Err(err) => {
                    ui_error(&err.to_string());
                    continue;
                }
            };
            show_rule_entry(&entry);
            state.current = Some(entry);
            continue;
        }
        if let Some(selector) = command_suffix(input, &lower, &["show "]) {
            let entry = match resolve_rule_selector(selector, &all_rules, Some(&state.results)) {
                Ok(entry) => entry,
                Err(err) => {
                    ui_error(&err.to_string());
                    continue;
                }
            };
            show_rule_entry(&entry);
            state.current = Some(entry);
            continue;
        }
        if lower == "export" || lower.starts_with("export ") {
            let payload = input.strip_prefix("export").unwrap_or("").trim();
            let (selector, targets, output) =
                match parse_tui_rule_export_command_with_context(payload, state.current.as_ref()) {
                    Ok(values) => values,
                    Err(err) => {
                        ui_error(&err.to_string());
                        continue;
                    }
                };
            let entry = match resolve_rule_selector(&selector, &all_rules, Some(&state.results)) {
                Ok(entry) => entry,
                Err(err) => {
                    ui_error(&err.to_string());
                    continue;
                }
            };
            if let Err(err) = export_rule_entry(&catalog, &entry, &targets, output.as_deref()) {
                ui_error(&err.to_string());
                continue;
            }
            state.current = Some(entry);
            continue;
        }
        if lower == "edit" || lower.starts_with("edit ") {
            let payload = input.strip_prefix("edit").unwrap_or("").trim();
            let edit = match parse_tui_edit_command_with_context(
                payload,
                state.current.as_ref().map(|entry| entry.rule_id.as_str()),
            ) {
                Ok(edit) => edit,
                Err(err) => {
                    ui_error(&err.to_string());
                    continue;
                }
            };
            let entry =
                match resolve_rule_selector(&edit.selector, &all_rules, Some(&state.results)) {
                    Ok(entry) => entry,
                    Err(err) => {
                        ui_error(&err.to_string());
                        continue;
                    }
                };
            if let Err(err) = edit_rule_entry(
                &catalog,
                &entry,
                edit.name.as_deref(),
                edit.description.as_deref(),
                edit.confidence,
            ) {
                ui_error(&err.to_string());
                continue;
            }
            let (_catalog, _abilities, refreshed_rules, _adversaries) = load_catalog_data()?;
            let refreshed = match resolve_rule_selector(
                &entry.rule_id,
                &refreshed_rules,
                Some(&refreshed_rules),
            ) {
                Ok(refreshed) => refreshed,
                Err(err) => {
                    ui_error(&err.to_string());
                    continue;
                }
            };
            state.current = Some(refreshed);
            state.results = refreshed_rules;
            continue;
        }
        if lower == "delete" || lower.starts_with("delete ") {
            let selector = input.strip_prefix("delete").unwrap_or("").trim();
            let entry = match resolve_rule_selector_or_current(
                selector,
                &all_rules,
                Some(&state.results),
                state.current.as_ref(),
            ) {
                Ok(entry) => entry,
                Err(err) => {
                    ui_error(&err.to_string());
                    continue;
                }
            };
            let confirmation = match prompt_delete_confirmation(&mut rl, &entry.rule_id) {
                Ok(confirmation) => confirmation,
                Err(err) => {
                    ui_error(&err.to_string());
                    continue;
                }
            };
            if let Err(err) = delete_rule_entry(&catalog, &entry, Some(&confirmation)) {
                ui_error(&err.to_string());
                continue;
            }
            state.results.retain(|item| item.rule_id != entry.rule_id);
            if state
                .current
                .as_ref()
                .is_some_and(|item| item.rule_id == entry.rule_id)
            {
                state.current = None;
            }
            continue;
        }

        ui_error(&format!(
            "Command {} is not supported in {} mode. Use {}",
            bold_cmd(input),
            bold_cmd("rules"),
            bold_cmd("help")
        ));
    }
}

fn run_tui_adversaries_console() -> Result<()> {
    println!("{YELLOW}Adversaries catalog initialized.{RESET}");
    let mut state = AdversaryCatalogConsoleState::default();
    let mut rl = new_spuc_editor()?;
    load_editor_history(&mut rl);
    loop {
        let prompt = adversary_catalog_prompt(&state);
        set_editor_words(&mut rl, adversary_catalog_completion_words(&state));
        let Some(line) = read_line_with_spacing(&mut rl, &prompt)? else {
            save_editor_history(&mut rl);
            return Ok(());
        };
        let input = line.trim();
        if input.is_empty() {
            continue;
        }
        let lower = input.to_ascii_lowercase();
        if lower == "help" || lower == "?" || lower == "help adversaries" {
            print_tui_topic_help("adversaries");
            continue;
        }
        if lower.starts_with("help ") {
            print_tui_topic_help("adversaries");
            continue;
        }
        if lower == "back" || lower == "backp" {
            if state.current.is_some() {
                state.current = None;
                println!("{YELLOW}Back to adversaries catalog.{RESET}");
            } else {
                save_editor_history(&mut rl);
                return Ok(());
            }
            continue;
        }
        if lower == "exit" || lower == "quit" {
            save_editor_history(&mut rl);
            return Ok(());
        }

        let (_catalog, _abilities, _rules, all_adversaries) = load_catalog_data()?;
        if lower == "list" || lower.starts_with("list ") {
            let limit = match parse_tui_list_limit_command(input) {
                Ok(limit) => limit,
                Err(err) => {
                    ui_error(&err.to_string());
                    continue;
                }
            };
            let results = filter_adversary_entries(&all_adversaries, None, limit);
            state.results = results.clone();
            print_adversary_search_results(&results, all_adversaries.len(), "Adversaries");
            continue;
        }
        if lower == "search" || lower.starts_with("search ") {
            let (query, limit) = match parse_tui_search_command(input) {
                Ok(values) => values,
                Err(err) => {
                    ui_error(&err.to_string());
                    continue;
                }
            };
            let results = filter_adversary_entries(&all_adversaries, query.as_deref(), Some(limit));
            state.results = results.clone();
            print_adversary_search_results(&results, all_adversaries.len(), "Adversaries");
            continue;
        }
        if lower == "show" {
            let entry = match resolve_adversary_selector_or_current(
                "",
                &all_adversaries,
                Some(&state.results),
                state.current.as_ref(),
            ) {
                Ok(entry) => entry,
                Err(err) => {
                    ui_error(&err.to_string());
                    continue;
                }
            };
            show_adversary_entry(&entry);
            state.current = Some(entry);
            continue;
        }
        if let Some(selector) = command_suffix(input, &lower, &["show "]) {
            let entry = match resolve_adversary_selector(
                selector,
                &all_adversaries,
                Some(&state.results),
            ) {
                Ok(entry) => entry,
                Err(err) => {
                    ui_error(&err.to_string());
                    continue;
                }
            };
            show_adversary_entry(&entry);
            state.current = Some(entry);
            continue;
        }
        if lower == "export" || lower.starts_with("export ") {
            let payload = input.strip_prefix("export").unwrap_or("").trim();
            let (selector, executor, output, show) =
                match parse_tui_adversary_export_command_with_context(
                    payload,
                    state.current.as_ref(),
                ) {
                    Ok(values) => values,
                    Err(err) => {
                        ui_error(&err.to_string());
                        continue;
                    }
                };
            let entry =
                match resolve_adversary_selector(&selector, &all_adversaries, Some(&state.results))
                {
                    Ok(entry) => entry,
                    Err(err) => {
                        ui_error(&err.to_string());
                        continue;
                    }
                };
            if let Err(err) = export_adversary_entry(&entry, executor, output.as_deref(), &show) {
                ui_error(&err.to_string());
                continue;
            }
            state.current = Some(entry);
            continue;
        }
        if lower == "edit" || lower.starts_with("edit ") {
            let payload = input.strip_prefix("edit").unwrap_or("").trim();
            let edit = match parse_tui_edit_command_with_context(
                payload,
                state
                    .current
                    .as_ref()
                    .map(|entry| entry.adversary_id.as_str()),
            ) {
                Ok(edit) => edit,
                Err(err) => {
                    ui_error(&err.to_string());
                    continue;
                }
            };
            let entry = match resolve_adversary_selector(
                &edit.selector,
                &all_adversaries,
                Some(&state.results),
            ) {
                Ok(entry) => entry,
                Err(err) => {
                    ui_error(&err.to_string());
                    continue;
                }
            };
            if let Err(err) = edit_adversary_entry(
                &entry,
                edit.name.as_deref(),
                edit.description.as_deref(),
                edit.confidence,
            ) {
                ui_error(&err.to_string());
                continue;
            }
            let (_catalog, _abilities, _rules, refreshed_adversaries) = load_catalog_data()?;
            let refreshed = match resolve_adversary_selector(
                &entry.adversary_id,
                &refreshed_adversaries,
                Some(&refreshed_adversaries),
            ) {
                Ok(refreshed) => refreshed,
                Err(err) => {
                    ui_error(&err.to_string());
                    continue;
                }
            };
            state.current = Some(refreshed);
            state.results = refreshed_adversaries;
            continue;
        }
        if lower == "delete" || lower.starts_with("delete ") {
            let selector = input.strip_prefix("delete").unwrap_or("").trim();
            let entry = match resolve_adversary_selector_or_current(
                selector,
                &all_adversaries,
                Some(&state.results),
                state.current.as_ref(),
            ) {
                Ok(entry) => entry,
                Err(err) => {
                    ui_error(&err.to_string());
                    continue;
                }
            };
            let confirmation = match prompt_delete_confirmation(&mut rl, &entry.adversary_id) {
                Ok(confirmation) => confirmation,
                Err(err) => {
                    ui_error(&err.to_string());
                    continue;
                }
            };
            if let Err(err) = delete_adversary_entry(&entry, Some(&confirmation)) {
                ui_error(&err.to_string());
                continue;
            }
            state
                .results
                .retain(|item| item.adversary_id != entry.adversary_id);
            if state
                .current
                .as_ref()
                .is_some_and(|item| item.adversary_id == entry.adversary_id)
            {
                state.current = None;
            }
            continue;
        }

        ui_error(&format!(
            "Command {} is not supported in {} mode. Use {}",
            bold_cmd(input),
            bold_cmd("adversaries"),
            bold_cmd("help")
        ));
    }
}

pub(crate) fn run_tui() -> Result<()> {
    println!("{GREEN}Interactive console (type 'help' for commands, 'exit' to quit){RESET}");
    let commands = vec![
        "translate",
        "emulate",
        "plan",
        "rules",
        "adversaries",
        "learn",
        "verify",
        "help",
        "exit",
        "quit",
    ];
    enum TuiMode {
        Normal,
        Learn(LearnSession),
    }
    let mut mode = TuiMode::Normal;
    let mut catalog_state = TuiCatalogBrowserState::default();
    let mut rl = new_spuc_editor()?;
    load_editor_history(&mut rl);
    loop {
        let prompt = match &mode {
            TuiMode::Normal => format!("{BOLD}spuc>{RESET} "),
            TuiMode::Learn(session) => learn_prompt(session),
        };
        let words = match &mode {
            TuiMode::Normal => root_completion_words(),
            TuiMode::Learn(_) => learn_completion_words(),
        };
        set_editor_words(&mut rl, words);
        let Some(input) = read_line_with_spacing(&mut rl, &prompt)? else {
            break;
        };
        let input = input.trim().to_string();
        if input.is_empty() {
            continue;
        }
        if let TuiMode::Learn(session) = &mut mode {
            match handle_learn_input(session, &input) {
                Ok(leave_learn) => {
                    if leave_learn {
                        mode = TuiMode::Normal;
                    }
                }
                Err(err) => ui_error(&err.to_string()),
            }
            continue;
        }

        if input == "exit" || input == "quit" {
            break;
        }
        if input == "help" || input == "?" || input == "help all" {
            print_root_help();
            continue;
        }
        if let Some(topic) = input.strip_prefix("help ").map(str::trim) {
            if print_tui_topic_help(topic) {
                continue;
            }
            ui_error(&format!("Command {} is not supported", bold_cmd(topic)));
            continue;
        }
        if input.ends_with(" help") {
            let topic = input.trim_end_matches(" help").trim();
            if print_tui_topic_help(topic) {
                continue;
            }
            ui_error(&format!("Command {} is not supported", bold_cmd(topic)));
            continue;
        }
        if input == "translate" || input.starts_with("translate ") {
            if let Err(err) = run_tui_translate_like_command(&input, false) {
                ui_error(&err.to_string());
            }
            continue;
        }
        if input == "emulate" || input.starts_with("emulate ") {
            if let Err(err) = run_tui_translate_like_command(&input, true) {
                ui_error(&err.to_string());
            }
            continue;
        }
        if input == "plan" {
            if let Err(err) = run_tui_plan() {
                ui_error(&err.to_string());
            }
            continue;
        }
        if input == "rules" {
            if let Err(err) = run_tui_rules_console() {
                ui_error(&err.to_string());
            }
            continue;
        }
        if input.starts_with("rules ") {
            if let Err(err) = run_tui_rules_command(&input, &mut rl, &mut catalog_state) {
                ui_error(&err.to_string());
            }
            continue;
        }
        if input == "adversaries" {
            if let Err(err) = run_tui_adversaries_console() {
                ui_error(&err.to_string());
            }
            continue;
        }
        if input.starts_with("adversaries ") {
            if let Err(err) = run_tui_adversaries_command(&input, &mut rl, &mut catalog_state) {
                ui_error(&err.to_string());
            }
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
                    ui_error(&e.to_string());
                    continue;
                }
            } else if list_only {
                ui_warn(&format!(
                    "Use command {} to start, for example {}",
                    bold_cmd("<challenge-id>"),
                    quoted_bold("core001")
                ));
            }
            mode = TuiMode::Learn(session);
            continue;
        }
        if input.starts_with("verify") {
            let rest = input.strip_prefix("verify").unwrap_or("").trim();
            if rest.is_empty() {
                ui_error(&format!(
                    "Command {} requires a STIX rule",
                    bold_cmd("verify")
                ));
                continue;
            }
            if matches!(rest, "help" | "--help" | "-h") {
                print_tui_topic_help("verify");
                continue;
            }
            match verify_rule(rest) {
                Ok(_) => println!("{GREEN}✅ OK{RESET}"),
                Err(e) => ui_error(&format!("Command {} failed: {}", bold_cmd("verify"), e)),
            }
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
            ui_warn(&format!("Did you mean command {}", bold_cmd(matches[0])));
        } else if !matches.is_empty() {
            ui_warn(&format!("Suggestions: {}", matches.join(", ")));
        } else {
            ui_error(&format!("Command {} is not supported", bold_cmd(&input)));
        }
    }
    save_editor_history(&mut rl);
    Ok(())
}

fn run_tui_plan() -> Result<()> {
    let empty_strings: &[String] = &[];
    let empty_dummy_sleep: &[u64] = &[];
    let show = [BuildOutput::Summary, BuildOutput::Manifest];
    run_campaign_command(CampaignOptions {
        name: None,
        description: None,
        platforms: empty_strings,
        search: None,
        ability_ids: empty_strings,
        dummy_sleep: empty_dummy_sleep,
        dummy_label: empty_strings,
        order: empty_strings,
        executor: None,
        output: None,
        guided: true,
        show: &show,
    })
}

fn print_root_help() {
    println!("{YELLOW}Workflow:{RESET}");
    println!(
        "{YELLOW}  {BOLD}translate{RESET}{YELLOW}: translate STIX rule to detections. Example: {BOLD}translate [process:name = 'cmd.exe'] to sigma{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}emulate{RESET}{YELLOW}: generate defensive artifacts. Example: {BOLD}emulate [process:command_line LIKE '%echo%'] to spuc-agent,bash{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}verify{RESET}{YELLOW}: parse/normalize check. Example: {BOLD}verify [process:name = 'powershell.exe']{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}learn{RESET}{YELLOW}: guided training mode. Example: {BOLD}learn core001{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}plan{RESET}{YELLOW}: intrusion-set planner. Example: {BOLD}plan --ability abl-001 --executor spuc-agent --platform linux{RESET}"
    );
    println!();
    println!("{YELLOW}Catalog:{RESET}");
    println!(
        "{YELLOW}  {BOLD}rules{RESET}{YELLOW}: open the rules catalog console. Example: {BOLD}rules{RESET}"
    );
    println!(
        "{YELLOW}  {BOLD}adversaries{RESET}{YELLOW}: open the adversaries catalog console. Example: {BOLD}adversaries{RESET}"
    );
    println!();
    println!("{YELLOW}General:{RESET}");
    println!(
        "{YELLOW}  {BOLD}help <command>{RESET}{YELLOW}: extended help per command. Example: {BOLD}help rules{RESET}"
    );
    println!("{YELLOW}  {BOLD}exit{RESET}{YELLOW}: leave interactive mode.{RESET}");
}

fn print_tui_topic_help(topic: &str) -> bool {
    match topic.trim().to_ascii_lowercase().as_str() {
        "translate" => {
            println!("{YELLOW}Commands available:{RESET}");
            println!(
                "{YELLOW}  {BOLD}translate{RESET}{YELLOW} <rule> [to sigma,eql,...] [desc=<text>] [mode=strict|partial] [out=<dir>] [conf=<0..100>]{RESET}"
            );
            println!(
                "{YELLOW}  Example: {BOLD}translate [process:name = 'cmd.exe'] to sigma,kql mode=partial{RESET}"
            );
            true
        }
        "emulate" => {
            println!("{YELLOW}Commands available:{RESET}");
            println!(
                "{YELLOW}  {BOLD}emulate{RESET}{YELLOW} <rule> [to spuc-agent,bash,powershell,atomic-red-team,mitre-caldera] [desc=<text>] [mode=strict|partial] [out=<dir>] [conf=<0..100>]{RESET}"
            );
            println!(
                "{YELLOW}  Example: {BOLD}emulate [process:command_line LIKE '%echo%'] to spuc-agent,bash out=./artifacts{RESET}"
            );
            true
        }
        "verify" => {
            println!("{YELLOW}Commands available:{RESET}");
            println!("{YELLOW}  {BOLD}verify{RESET}{YELLOW} <rule>{RESET}");
            println!("{YELLOW}  Example: {BOLD}verify [process:name = 'powershell.exe']{RESET}");
            true
        }
        "catalog" => {
            println!("{YELLOW}Commands available:{RESET}");
            println!(
                "{YELLOW}  {BOLD}rules{RESET}{YELLOW} -> open rules catalog console ({BOLD}spuc (rules)>{RESET}{YELLOW}){RESET}"
            );
            println!(
                "{YELLOW}  {BOLD}adversaries{RESET}{YELLOW} -> open adversaries catalog console ({BOLD}spuc (adversaries)>{RESET}{YELLOW}){RESET}"
            );
            println!("{YELLOW}  Examples: {BOLD}rules{RESET}{YELLOW}, {BOLD}adversaries{RESET}");
            true
        }
        "rules" => {
            println!("{YELLOW}Commands available:{RESET}");
            println!(
                "{YELLOW}  {BOLD}rules{RESET}{YELLOW} -> enter rules catalog console ({BOLD}spuc (rules)>{RESET}{YELLOW}){RESET}"
            );
            println!("{YELLOW}  {BOLD}list{RESET}{YELLOW} [limit=<n>]{RESET}");
            println!("{YELLOW}  {BOLD}search{RESET}{YELLOW} [text] [limit=<n>]{RESET}");
            println!("{YELLOW}  {BOLD}show{RESET}{YELLOW} [index|rule-id]{RESET}");
            println!(
                "{YELLOW}  {BOLD}export{RESET}{YELLOW} <index|rule-id> to <spuc-agent[,bash,powershell,atomic-red-team,mitre-caldera]> [out=<dir>]{RESET}"
            );
            println!(
                "{YELLOW}  {BOLD}export{RESET}{YELLOW} <spuc-agent[,bash,powershell,atomic-red-team,mitre-caldera]> [out=<dir>] (uses current selection){RESET}"
            );
            println!(
                "{YELLOW}  {BOLD}edit{RESET}{YELLOW} <index|rule-id> [name=<text>] [description=<text>] [confidence=<0..100>]{RESET}"
            );
            println!("{YELLOW}  {BOLD}delete{RESET}{YELLOW} <index|rule-id>{RESET}");
            println!(
                "{YELLOW}  {BOLD}back{RESET}{YELLOW}: leave selection or return to main console.{RESET}"
            );
            println!(
                "{YELLOW}  Example: {BOLD}show 1{RESET}{YELLOW} -> prompt changes to {BOLD}spuc (rules @ rule-...)>{RESET}"
            );
            true
        }
        "adversaries" => {
            println!("{YELLOW}Commands available:{RESET}");
            println!(
                "{YELLOW}  {BOLD}adversaries{RESET}{YELLOW} -> enter adversaries catalog console ({BOLD}spuc (adversaries)>{RESET}{YELLOW}){RESET}"
            );
            println!("{YELLOW}  {BOLD}list{RESET}{YELLOW} [limit=<n>]{RESET}");
            println!("{YELLOW}  {BOLD}search{RESET}{YELLOW} [text] [limit=<n>]{RESET}");
            println!("{YELLOW}  {BOLD}show{RESET}{YELLOW} [index|adversary-id]{RESET}");
            println!(
                "{YELLOW}  {BOLD}export{RESET}{YELLOW} <index|adversary-id> to <spuc-agent|bash|powershell|atomic-red-team|mitre-caldera> [out=<dir>] [show=summary,artifact,manifest]{RESET}"
            );
            println!(
                "{YELLOW}  {BOLD}export{RESET}{YELLOW} <spuc-agent|bash|powershell|atomic-red-team|mitre-caldera> [out=<dir>] [show=summary,artifact,manifest] (uses current selection){RESET}"
            );
            println!(
                "{YELLOW}  {BOLD}edit{RESET}{YELLOW} <index|adversary-id> [name=<text>] [description=<text>] [confidence=<0..100>]{RESET}"
            );
            println!("{YELLOW}  {BOLD}delete{RESET}{YELLOW} <index|adversary-id>{RESET}");
            println!(
                "{YELLOW}  {BOLD}back{RESET}{YELLOW}: leave selection or return to main console.{RESET}"
            );
            println!(
                "{YELLOW}  Example: {BOLD}show 1{RESET}{YELLOW} -> prompt changes to {BOLD}spuc (adversaries @ adversary-...)>{RESET}"
            );
            true
        }
        "learn" => {
            println!("{YELLOW}Commands available:{RESET}");
            println!("{YELLOW}  {BOLD}learn{RESET}{YELLOW} [list|challenge-id]{RESET}");
            println!("{YELLOW}  Example: {BOLD}learn time001{RESET}");
            true
        }
        "plan" => {
            println!("{YELLOW}Commands available:{RESET}");
            println!(
                "{YELLOW}  {BOLD}plan{RESET}{YELLOW} [--name <text>] [--platform linux,windows] [--ability <id>] [--dummy-sleep <seconds>] [--dummy-label <text>] [--executor spuc-agent|bash|powershell|atomic-red-team|mitre-caldera] [--guided]{RESET}"
            );
            println!(
                "{YELLOW}  Example: {BOLD}plan --name \"Validation\" --ability abl-001 --platform linux,windows --executor spuc-agent{RESET}"
            );
            true
        }
        "exit" | "quit" => {
            println!("{YELLOW}Commands available:{RESET}");
            println!("{YELLOW}  {BOLD}exit{RESET}{YELLOW} / {BOLD}quit{RESET}");
            println!("{YELLOW}  Example: {BOLD}exit{RESET}");
            true
        }
        _ => false,
    }
}

fn run_tui_translate_like_command(input: &str, emulate: bool) -> Result<()> {
    let command = if emulate { "emulate" } else { "translate" };
    let rest = input.strip_prefix(command).unwrap_or("").trim();
    if rest.is_empty() {
        let example_rule = quoted_bold("[process:name = 'cmd.exe']");
        return Err(anyhow!(
            "Command {} requires a STIX rule. Example: {} {} to {}",
            bold_cmd(command),
            bold_cmd(command),
            example_rule,
            bold_cmd(if emulate { "spuc-agent" } else { "sigma" })
        ));
    }
    let mut source = rest.to_string();
    let mut description: Option<String> = None;
    let mut output: Option<PathBuf> = None;
    let mut rule_confidence: Option<u8> = None;
    let mut mode = ConversionMode::Strict;

    loop {
        let markers = [" desc=", " out=", " conf=", " mode="];
        let mut rightmost: Option<(usize, &str)> = None;
        for marker in markers {
            if let Some(idx) = source.rfind(marker) {
                if matches!(rightmost, Some((prev, _)) if prev > idx) {
                    continue;
                }
                rightmost = Some((idx, marker));
            }
        }
        let Some((idx, marker)) = rightmost else {
            break;
        };
        let value = source[idx + marker.len()..].trim();
        match marker {
            " desc=" => description = Some(value.to_string()),
            " out=" if !value.is_empty() => output = Some(PathBuf::from(value)),
            " conf=" if !value.is_empty() => {
                let parsed = value
                    .parse::<u8>()
                    .map_err(|_| anyhow!("Option {} must be numeric (0..100)", bold_cmd("conf")))?;
                if parsed > 100 {
                    return Err(anyhow!(
                        "Option {} must be in range 0..100",
                        bold_cmd("conf")
                    ));
                }
                rule_confidence = Some(parsed);
            }
            " mode=" => {
                mode = match value.to_ascii_lowercase().as_str() {
                    "partial" => ConversionMode::Partial,
                    "strict" => ConversionMode::Strict,
                    other => {
                        return Err(anyhow!(
                            "Option {} value {} is not supported. Allowed values: {}, {}",
                            bold_cmd("mode"),
                            quoted_bold(other),
                            bold_cmd("strict"),
                            bold_cmd("partial")
                        ));
                    }
                }
            }
            _ => {}
        }
        source = source[..idx].trim().to_string();
    }

    let mut rule = source.clone();
    let mut target_tokens: Vec<String> = Vec::new();
    if let Some(idx) = source.rfind(" to ") {
        rule = source[..idx].trim().to_string();
        target_tokens = source[idx + 4..]
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
    }
    if rule.is_empty() {
        return Err(anyhow!(
            "Command {} requires a STIX rule",
            bold_cmd(command)
        ));
    }

    if emulate {
        let rules = [rule];
        let export_formats: &[ExportFormat] = &[];
        let mut targets = Vec::new();
        for token in target_tokens {
            let target = parse_ability_target(&token).ok_or_else(|| {
                anyhow!(
                    "Target {} is not supported for command {}",
                    quoted_bold(&token),
                    bold_cmd("emulate")
                )
            })?;
            targets.push(target);
        }
        run_emulate_command(emulate_options(
            &targets,
            &rules,
            None,
            output.as_deref(),
            description.as_deref(),
            None,
            rule_confidence,
            mode,
            export_formats,
            false,
        ))
    } else {
        let rules = [rule];
        let sigma_targets: &[String] = &[];
        let export_formats: &[ExportFormat] = &[];
        let targets = target_tokens;
        run_translate_command(translate_options(
            &targets,
            &rules,
            None,
            output.as_deref(),
            description.as_deref(),
            None,
            rule_confidence,
            sigma_targets,
            mode,
            export_formats,
            false,
        ))
    }
}

fn run_tui_rules_command(
    input: &str,
    rl: &mut SpucEditor,
    state: &mut TuiCatalogBrowserState,
) -> Result<()> {
    let rest = input.strip_prefix("rules").unwrap_or("").trim();
    if rest.is_empty() {
        print_tui_topic_help("rules");
        return Ok(());
    }
    let (catalog, _abilities, all_rules, _adversaries) = load_catalog_data()?;
    let lower = rest.to_ascii_lowercase();
    if lower == "list" || lower.starts_with("list ") {
        let limit = parse_tui_list_limit_command(rest)?;
        let results = filter_rule_entries(&all_rules, None, limit);
        state.rule_results = results.clone();
        print_rule_search_results(&results, all_rules.len(), "Rules");
        return Ok(());
    }
    if lower == "search" || lower.starts_with("search ") {
        let (query, limit) = parse_tui_search_command(rest)?;
        let results = filter_rule_entries(&all_rules, query.as_deref(), Some(limit));
        state.rule_results = results.clone();
        print_rule_search_results(&results, all_rules.len(), "Rules");
        return Ok(());
    }
    if let Some(selector) = command_suffix(rest, &lower, &["show "]) {
        let entry = resolve_rule_selector(selector, &all_rules, Some(&state.rule_results))?;
        show_rule_entry(&entry);
        return Ok(());
    }
    if let Some(payload) = command_suffix(rest, &lower, &["export "]) {
        let (selector, targets, output) = parse_tui_rule_export_command(payload)?;
        let entry = resolve_rule_selector(&selector, &all_rules, Some(&state.rule_results))?;
        export_rule_entry(&catalog, &entry, &targets, output.as_deref())?;
        return Ok(());
    }
    if let Some(payload) = command_suffix(rest, &lower, &["edit "]) {
        let edit = parse_tui_edit_command(payload)?;
        let entry = resolve_rule_selector(&edit.selector, &all_rules, Some(&state.rule_results))?;
        edit_rule_entry(
            &catalog,
            &entry,
            edit.name.as_deref(),
            edit.description.as_deref(),
            edit.confidence,
        )?;
        return Ok(());
    }
    if let Some(selector) = command_suffix(rest, &lower, &["delete "]) {
        let entry = resolve_rule_selector(selector, &all_rules, Some(&state.rule_results))?;
        let confirmation = prompt_delete_confirmation(rl, &entry.rule_id)?;
        delete_rule_entry(&catalog, &entry, Some(&confirmation))?;
        state
            .rule_results
            .retain(|item| item.rule_id != entry.rule_id);
        return Ok(());
    }
    Err(anyhow!("Command {} is not supported", bold_cmd(input)))
}

fn run_tui_adversaries_command(
    input: &str,
    rl: &mut SpucEditor,
    state: &mut TuiCatalogBrowserState,
) -> Result<()> {
    let rest = input.strip_prefix("adversaries").unwrap_or("").trim();
    if rest.is_empty() {
        print_tui_topic_help("adversaries");
        return Ok(());
    }
    let (_catalog, _abilities, _rules, all_adversaries) = load_catalog_data()?;
    let lower = rest.to_ascii_lowercase();
    if lower == "list" || lower.starts_with("list ") {
        let limit = parse_tui_list_limit_command(rest)?;
        let results = filter_adversary_entries(&all_adversaries, None, limit);
        state.adversary_results = results.clone();
        print_adversary_search_results(&results, all_adversaries.len(), "Adversaries");
        return Ok(());
    }
    if lower == "search" || lower.starts_with("search ") {
        let (query, limit) = parse_tui_search_command(rest)?;
        let results = filter_adversary_entries(&all_adversaries, query.as_deref(), Some(limit));
        state.adversary_results = results.clone();
        print_adversary_search_results(&results, all_adversaries.len(), "Adversaries");
        return Ok(());
    }
    if let Some(selector) = command_suffix(rest, &lower, &["show "]) {
        let entry =
            resolve_adversary_selector(selector, &all_adversaries, Some(&state.adversary_results))?;
        show_adversary_entry(&entry);
        return Ok(());
    }
    if let Some(payload) = command_suffix(rest, &lower, &["export "]) {
        let (selector, executor, output, show) = parse_tui_adversary_export_command(payload)?;
        let entry = resolve_adversary_selector(
            &selector,
            &all_adversaries,
            Some(&state.adversary_results),
        )?;
        export_adversary_entry(&entry, executor, output.as_deref(), &show)?;
        return Ok(());
    }
    if let Some(payload) = command_suffix(rest, &lower, &["edit "]) {
        let edit = parse_tui_edit_command(payload)?;
        let entry = resolve_adversary_selector(
            &edit.selector,
            &all_adversaries,
            Some(&state.adversary_results),
        )?;
        edit_adversary_entry(
            &entry,
            edit.name.as_deref(),
            edit.description.as_deref(),
            edit.confidence,
        )?;
        return Ok(());
    }
    if let Some(selector) = command_suffix(rest, &lower, &["delete "]) {
        let entry =
            resolve_adversary_selector(selector, &all_adversaries, Some(&state.adversary_results))?;
        let confirmation = prompt_delete_confirmation(rl, &entry.adversary_id)?;
        delete_adversary_entry(&entry, Some(&confirmation))?;
        state
            .adversary_results
            .retain(|item| item.adversary_id != entry.adversary_id);
        return Ok(());
    }
    Err(anyhow!("Command {} is not supported", bold_cmd(input)))
}

struct TuiEditInput {
    selector: String,
    name: Option<String>,
    description: Option<String>,
    confidence: Option<u8>,
}

fn parse_tui_search_command(raw: &str) -> Result<(Option<String>, usize)> {
    let mut payload = raw
        .trim()
        .strip_prefix("search")
        .unwrap_or(raw)
        .trim()
        .to_string();
    let mut limit = 200usize;
    if let Some(idx) = payload.rfind(" limit=") {
        let value = payload[idx + " limit=".len()..].trim();
        limit = value
            .parse::<usize>()
            .map_err(|_| anyhow!("Option {} must be numeric", bold_cmd("limit")))?;
        payload = payload[..idx].trim().to_string();
    }
    let query = if payload.is_empty() {
        None
    } else {
        Some(payload)
    };
    Ok((query, limit))
}

fn parse_tui_list_limit_command(raw: &str) -> Result<Option<usize>> {
    let payload = raw
        .trim()
        .strip_prefix("list")
        .unwrap_or(raw)
        .trim()
        .to_string();
    if payload.is_empty() {
        return Ok(None);
    }
    let Some(value) = payload.strip_prefix("limit=") else {
        return Err(anyhow!(
            "Unsupported list syntax. Allowed: {}",
            quoted_bold("list [limit=<n>]")
        ));
    };
    let limit = value
        .trim()
        .parse::<usize>()
        .map_err(|_| anyhow!("Option {} must be numeric", bold_cmd("limit")))?;
    Ok(Some(limit))
}

fn resolve_rule_selector_or_current(
    selector: &str,
    all_entries: &[CatalogRuleEntry],
    current_entries: Option<&[CatalogRuleEntry]>,
    current: Option<&CatalogRuleEntry>,
) -> Result<CatalogRuleEntry> {
    if selector.trim().is_empty() {
        return current
            .cloned()
            .ok_or_else(|| anyhow!("no current rule selected"));
    }
    resolve_rule_selector(selector, all_entries, current_entries)
}

fn resolve_adversary_selector_or_current(
    selector: &str,
    all_entries: &[CatalogAdversaryEntry],
    current_entries: Option<&[CatalogAdversaryEntry]>,
    current: Option<&CatalogAdversaryEntry>,
) -> Result<CatalogAdversaryEntry> {
    if selector.trim().is_empty() {
        return current
            .cloned()
            .ok_or_else(|| anyhow!("no current adversary selected"));
    }
    resolve_adversary_selector(selector, all_entries, current_entries)
}

fn parse_tui_rule_export_command(
    raw: &str,
) -> Result<(String, Vec<AbilityTarget>, Option<PathBuf>)> {
    let mut payload = raw.trim().to_string();
    let mut output = None;
    if let Some(idx) = payload.rfind(" out=") {
        let value = payload[idx + " out=".len()..].trim();
        if !value.is_empty() {
            output = Some(PathBuf::from(value));
        }
        payload = payload[..idx].trim().to_string();
    }
    let Some(idx) = payload.rfind(" to ") else {
        return Err(anyhow!(
            "Command {} requires targets. Example: {}",
            bold_cmd("rules export"),
            quoted_bold("rules export 1 to spuc-agent,bash out=./artifacts")
        ));
    };
    let selector = payload[..idx].trim().to_string();
    let targets = payload[idx + 4..]
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            parse_ability_target(value).ok_or_else(|| {
                anyhow!(
                    "Target {} is not supported. Allowed: spuc-agent, bash, powershell, atomic-red-team, mitre-caldera",
                    quoted_bold(value)
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if selector.is_empty() {
        return Err(anyhow!("rules export requires a selector"));
    }
    Ok((selector, targets, output))
}

fn parse_tui_rule_export_command_with_context(
    raw: &str,
    current: Option<&CatalogRuleEntry>,
) -> Result<(String, Vec<AbilityTarget>, Option<PathBuf>)> {
    let trimmed = raw.trim();
    if let Some(current) = current {
        if trimmed.starts_with("to ") {
            return parse_tui_rule_export_command(&format!("{} {}", current.rule_id, trimmed));
        }
        if !trimmed.is_empty() && !trimmed.contains(" to ") {
            return parse_tui_rule_export_command(&format!("{} to {}", current.rule_id, trimmed));
        }
    }
    parse_tui_rule_export_command(trimmed)
}

fn parse_tui_adversary_export_command(
    raw: &str,
) -> Result<(String, AbilityTarget, Option<PathBuf>, Vec<BuildOutput>)> {
    let mut payload = raw.trim().to_string();
    let mut output = None;
    let mut show = default_campaign_show();
    if let Some(idx) = payload.rfind(" show=") {
        let value = payload[idx + " show=".len()..].trim();
        show = parse_build_outputs(value)?;
        payload = payload[..idx].trim().to_string();
    }
    if let Some(idx) = payload.rfind(" out=") {
        let value = payload[idx + " out=".len()..].trim();
        if !value.is_empty() {
            output = Some(PathBuf::from(value));
        }
        payload = payload[..idx].trim().to_string();
    }
    let Some(idx) = payload.rfind(" to ") else {
        return Err(anyhow!(
            "Command {} requires one executor. Example: {}",
            bold_cmd("adversaries export"),
            quoted_bold("adversaries export 1 to spuc-agent out=./out")
        ));
    };
    let selector = payload[..idx].trim().to_string();
    let executor = parse_ability_target(payload[idx + 4..].trim()).ok_or_else(|| {
        anyhow!(
            "Executor {} is not supported. Allowed: spuc-agent, bash, powershell, atomic-red-team, mitre-caldera",
            quoted_bold(payload[idx + 4..].trim())
        )
    })?;
    if selector.is_empty() {
        return Err(anyhow!("adversaries export requires a selector"));
    }
    Ok((selector, executor, output, show))
}

fn parse_tui_adversary_export_command_with_context(
    raw: &str,
    current: Option<&CatalogAdversaryEntry>,
) -> Result<(String, AbilityTarget, Option<PathBuf>, Vec<BuildOutput>)> {
    let trimmed = raw.trim();
    if let Some(current) = current {
        if trimmed.starts_with("to ") {
            return parse_tui_adversary_export_command(&format!(
                "{} {}",
                current.adversary_id, trimmed
            ));
        }
        if !trimmed.is_empty() && !trimmed.contains(" to ") {
            return parse_tui_adversary_export_command(&format!(
                "{} to {}",
                current.adversary_id, trimmed
            ));
        }
    }
    parse_tui_adversary_export_command(trimmed)
}

fn parse_tui_edit_command(raw: &str) -> Result<TuiEditInput> {
    let trimmed = raw.trim();
    let selector_end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    let selector = trimmed[..selector_end].trim().to_string();
    if selector.is_empty() {
        return Err(anyhow!("edit requires an index or id"));
    }
    let mut payload = trimmed[selector_end..].trim().to_string();
    let mut confidence = None;
    let mut description = None;
    let mut name = None;

    if let Some(idx) = payload.rfind(" confidence=") {
        let value = payload[idx + " confidence=".len()..].trim();
        confidence = Some(
            value
                .parse::<u8>()
                .map_err(|_| anyhow!("confidence must be numeric (0..100)"))?,
        );
        payload = payload[..idx].trim().to_string();
    }
    if let Some(idx) = payload.rfind(" description=") {
        let value = payload[idx + " description=".len()..].trim();
        description = Some(value.to_string());
        payload = payload[..idx].trim().to_string();
    }
    if let Some(idx) = payload.rfind(" name=") {
        let value = payload[idx + " name=".len()..].trim();
        name = Some(value.to_string());
    } else if !payload.is_empty() {
        return Err(anyhow!(
            "Unsupported edit syntax. Allowed fields: name=, description=, confidence="
        ));
    }

    Ok(TuiEditInput {
        selector,
        name,
        description,
        confidence,
    })
}

fn parse_tui_edit_command_with_context(
    raw: &str,
    current_id: Option<&str>,
) -> Result<TuiEditInput> {
    let trimmed = raw.trim();
    if let Some(current_id) = current_id {
        if trimmed.starts_with("name=")
            || trimmed.starts_with("description=")
            || trimmed.starts_with("confidence=")
        {
            return parse_tui_edit_command(&format!("{current_id} {trimmed}"));
        }
    }
    parse_tui_edit_command(trimmed)
}

fn prompt_delete_confirmation(rl: &mut SpucEditor, id: &str) -> Result<String> {
    let expected = format!("DELETE {id}");
    let prompt = format!("Confirm delete ({expected})> ");
    let Some(line) = read_line_with_spacing(rl, &prompt)? else {
        return Err(anyhow!("delete cancelled"));
    };
    Ok(line.trim().to_string())
}

fn root_completion_words() -> Vec<String> {
    vec![
        "help".to_string(),
        "translate".to_string(),
        "verify".to_string(),
        "learn".to_string(),
        "emulate".to_string(),
        "plan".to_string(),
        "adversaries".to_string(),
        "rules".to_string(),
        "search".to_string(),
        "show".to_string(),
        "export".to_string(),
        "edit".to_string(),
        "delete".to_string(),
        "to".to_string(),
        "to".to_string(),
        "out=".to_string(),
        "name=".to_string(),
        "description=".to_string(),
        "limit=".to_string(),
        "show=".to_string(),
        "desc=".to_string(),
        "conf=".to_string(),
        "confidence=".to_string(),
        "mode=".to_string(),
        "strict".to_string(),
        "partial".to_string(),
        "spuc-agent".to_string(),
        "bash".to_string(),
        "powershell".to_string(),
        "atomic-red-team".to_string(),
        "mitre-caldera".to_string(),
        "sigma".to_string(),
        "eql".to_string(),
        "kql".to_string(),
        "snort".to_string(),
        "suricata".to_string(),
        "yara".to_string(),
        "summary".to_string(),
        "canonical".to_string(),
        "artifact".to_string(),
        "manifest".to_string(),
        "all".to_string(),
        "exit".to_string(),
        "quit".to_string(),
    ]
}

fn learn_completion_words() -> Vec<String> {
    let mut out = vec![
        "help".to_string(),
        "list".to_string(),
        "hint".to_string(),
        "solution".to_string(),
        "forget".to_string(),
        "back".to_string(),
        "exit".to_string(),
    ];
    for challenge in LEARN_CHALLENGES {
        out.push(challenge.id.to_string());
    }
    out
}

pub(crate) fn campaign_completion_words(state: &CampaignConsoleState) -> Vec<String> {
    let mut out = vec![
        "help".to_string(),
        "help build".to_string(),
        "help export".to_string(),
        "help list".to_string(),
        "help set".to_string(),
        "help show_selected".to_string(),
        "help show_ability".to_string(),
        "help add_sleep".to_string(),
        "help add_label".to_string(),
        "show".to_string(),
        "show_selected".to_string(),
        "show_ability".to_string(),
        "set".to_string(),
        "unset".to_string(),
        "search".to_string(),
        "filter_by".to_string(),
        "list".to_string(),
        "select".to_string(),
        "unselect".to_string(),
        "reorder".to_string(),
        "add_sleep".to_string(),
        "add_label".to_string(),
        "build".to_string(),
        "export".to_string(),
        "build spuc-agent".to_string(),
        "build bash".to_string(),
        "build powershell".to_string(),
        "build atomic-red-team".to_string(),
        "build mitre-caldera".to_string(),
        "export spuc-agent".to_string(),
        "export bash".to_string(),
        "export powershell".to_string(),
        "export atomic-red-team".to_string(),
        "export mitre-caldera".to_string(),
        "back".to_string(),
        "exit".to_string(),
        "INTRUSION_SET_ID=".to_string(),
        "NAME=".to_string(),
        "DESCRIPTION=".to_string(),
        "OUTPUT=".to_string(),
        "SHOW=".to_string(),
        "PLATFORM=".to_string(),
        "CONFIDENCE=".to_string(),
        "summary".to_string(),
        "canonical".to_string(),
        "artifact".to_string(),
        "manifest".to_string(),
        "all".to_string(),
        "SHOW=summary".to_string(),
        "SHOW=summary,manifest".to_string(),
        "SHOW=all".to_string(),
        "platform=".to_string(),
        "confidence=".to_string(),
    ];
    for platform in ALLOWED_PLATFORMS {
        out.push(platform.to_string());
        out.push(format!("PLATFORM={platform}"));
        out.push(format!("platform={platform}"));
    }
    out.push("spuc-agent".to_string());
    out.push("bash".to_string());
    out.push("powershell".to_string());
    out.push("atomic-red-team".to_string());
    out.push("mitre-caldera".to_string());
    for id in &state.selected_ids {
        out.push(id.clone());
    }
    for ability in &state.current_results {
        out.push(ability.id.clone());
    }
    out
}

pub(crate) fn new_spuc_editor() -> Result<SpucEditor> {
    Editor::new().map_err(|e| anyhow!("init line editor: {e}"))
}

pub(crate) fn load_editor_history(rl: &mut SpucEditor) {
    if let Some(path) = history_path() {
        let _ = rl.load_history(&path);
    }
}

pub(crate) fn save_editor_history(rl: &mut SpucEditor) {
    if let Some(path) = history_path() {
        let _ = rl.save_history(&path);
    }
}

pub(crate) fn set_editor_words(rl: &mut SpucEditor, words: Vec<String>) {
    rl.set_helper(Some(SpucRlHelper::with_words(words)));
}

pub(crate) fn read_line_with_spacing(rl: &mut SpucEditor, prompt: &str) -> Result<Option<String>> {
    println!();
    let line = rl.readline(prompt);
    println!();
    match line {
        Ok(line) => {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                let _ = rl.add_history_entry(trimmed);
            }
            Ok(Some(line))
        }
        Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => Ok(None),
        Err(e) => Err(anyhow!("readline failed: {e}")),
    }
}

pub(crate) fn read_line_compact(rl: &mut SpucEditor, prompt: &str) -> Result<Option<String>> {
    let line = rl.readline(prompt);
    match line {
        Ok(line) => {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                let _ = rl.add_history_entry(trimmed);
            }
            Ok(Some(line))
        }
        Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => Ok(None),
        Err(e) => Err(anyhow!("readline failed: {e}")),
    }
}

fn history_path() -> Option<PathBuf> {
    paths::spuc_config_root().map(|p| p.join("history.txt"))
}

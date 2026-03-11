#![allow(dead_code)]

use anyhow::Result;

use crate::cli::OutputTarget;
use crate::ui::ansi::{BLUE, BOLD, RED, RESET, YELLOW};

pub(crate) fn styled_var(name: &str) -> String {
    format!("{BOLD}{name}{RESET}")
}

pub(crate) fn styled_var_help(name: &str) -> String {
    format!("{YELLOW}{BOLD}{name}{RESET}")
}

pub(crate) fn print_variable_docs(title: &str, docs: &[(&str, &str)]) {
    println!("{YELLOW}{title}:{RESET}");
    for (name, doc) in docs {
        println!("  {} -> {}", styled_var_help(name), doc);
    }
}

pub(crate) fn print_variable_value(name: &str, value: impl AsRef<str>) {
    println!("{}={}", styled_var(name), value.as_ref());
}

pub(crate) fn with_period(message: &str) -> String {
    let trimmed = message.trim();
    if trimmed.ends_with('.') {
        trimmed.to_string()
    } else {
        format!("{trimmed}.")
    }
}

pub(crate) fn ui_error(message: &str) {
    println!("{RED}Error: {}{RESET}", with_period(message));
}

pub(crate) fn ui_warn(message: &str) {
    println!("{YELLOW}{}{RESET}", with_period(message));
}

pub(crate) fn bold_cmd(command: &str) -> String {
    format!("{BOLD}{command}{RESET}")
}

pub(crate) fn quoted_bold(text: &str) -> String {
    format!("'{BOLD}{text}{RESET}'")
}

pub(crate) fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    if headers.is_empty() {
        return;
    }
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (idx, cell) in row.iter().enumerate() {
            if idx < widths.len() {
                widths[idx] = widths[idx].max(cell.chars().count());
            }
        }
    }

    let header = headers
        .iter()
        .enumerate()
        .map(|(idx, title)| format!("{title:<width$}", width = widths[idx]))
        .collect::<Vec<_>>()
        .join(" | ");
    let separator = widths
        .iter()
        .map(|width| "-".repeat(*width))
        .collect::<Vec<_>>()
        .join("-+-");

    println!("{YELLOW}{BOLD}{header}{RESET}");
    println!("{YELLOW}{separator}{RESET}");
    for row in rows {
        let line = row
            .iter()
            .enumerate()
            .map(|(idx, cell)| format!("{cell:<width$}", width = widths[idx]))
            .collect::<Vec<_>>()
            .join(" | ");
        println!("{line}");
    }
}

pub(crate) fn render_rule_header(idx: usize, total: usize, rule: &str) {
    let plain = format!("Rule {}/{}: {}", idx + 1, total, rule);
    let styled = format!(
        "{BLUE}│{RESET} {PURPLE}Rule {}/{}: {BOLD}{}{RESET}{PURPLE}{RESET} {BLUE}│{RESET}",
        idx + 1,
        total,
        rule,
        PURPLE = crate::ui::ansi::PURPLE
    );
    print_boxed_line(&plain, &styled);
}

pub(crate) fn render_coverage_header(target: &OutputTarget) {
    let plain = format!("Coverage: {:?}", target);
    let styled = format!(
        "{BLUE}│{RESET} {YELLOW}Coverage: {BOLD}{:?}{RESET}{YELLOW}{RESET} {BLUE}│{RESET}",
        target
    );
    print_boxed_line(&plain, &styled);
}

pub(crate) fn print_boxed_line(plain: &str, styled: &str) {
    let width = plain.chars().count() + 2;
    println!("{BLUE}┌{}┐{RESET}", "─".repeat(width));
    println!("{styled}");
    println!("{BLUE}└{}┘{RESET}", "─".repeat(width));
}

pub(crate) fn capitalize_first(input: &str) -> String {
    let mut chars = input.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

pub(crate) fn entry_label(count: usize) -> String {
    if count == 1 {
        "1 entry".to_string()
    } else {
        format!("{count} entries")
    }
}

pub(crate) fn _noop_result(_: Result<()>) {}

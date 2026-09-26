//! CLI help text wrapping (issue #240).
//!
//! The workspace builds `clap` without terminal size detection, so long command
//! descriptions are printed on a single unwrapped line and overflow narrow
//! terminals. These helpers render the *real* command tree (via
//! `clap::CommandFactory`) and wrap every description so that help output never
//! exceeds the requested width.

use crate::cli::App;
use clap::{Command, CommandFactory};

/// Width used when the terminal size is unknown.
pub const DEFAULT_HELP_WIDTH: usize = 100;
/// Help output is never wrapped narrower than this, it becomes unreadable.
pub const MIN_HELP_WIDTH: usize = 40;
/// Narrowest description column kept for the help table.
const MIN_DESC_WIDTH: usize = 24;
/// Columns between the label column and the wrapped description.
const LABEL_GAP: usize = 2;
/// Indent of the help table.
const TABLE_INDENT: usize = 2;
/// One line summary printed above the command table.
const TAGLINE: &str = "stellar-toolkit - build, test and inspect Soroban contracts";
/// Closing hint printed below the command table.
const FOOTER: &str = "Run `stellar-toolkit <command> --help` for the options of a \
                     single command. Set COLUMNS to change the wrap width.";

/// One row of the wrapped help table: a command name and its description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelpEntry {
    pub label: String,
    pub description: String,
}

impl HelpEntry {
    pub fn new(label: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            description: description.into(),
        }
    }
}

/// Resolves the wrap width from `COLUMNS`, falling back to [`DEFAULT_HELP_WIDTH`].
///
/// The value is clamped to `[MIN_HELP_WIDTH, DEFAULT_HELP_WIDTH]` so a bogus or
/// very small `COLUMNS` cannot produce a single character per line layout.
pub fn help_width() -> usize {
    let detected = std::env::var("COLUMNS")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok());
    match detected {
        Some(cols) => cols.clamp(MIN_HELP_WIDTH, DEFAULT_HELP_WIDTH),
        None => DEFAULT_HELP_WIDTH,
    }
}

/// Wraps `text` to `width` characters per line.
///
/// Hard line breaks in the input are preserved, words longer than `width` (paths,
/// URLs) are split instead of overflowing, and a width of `0` is treated as `1`
/// so the function always terminates.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines: Vec<String> = Vec::new();

    for paragraph in text.split('\n') {
        let words: Vec<&str> = paragraph.split_whitespace().collect();
        if words.is_empty() {
            lines.push(String::new());
            continue;
        }

        let mut current = String::new();
        for word in words {
            if word.chars().count() > width {
                if !current.is_empty() {
                    lines.push(std::mem::take(&mut current));
                }
                lines.extend(split_word(word, width));
                continue;
            }
            if current.is_empty() {
                current.push_str(word);
            } else if current.chars().count() + 1 + word.chars().count() <= width {
                current.push(' ');
                current.push_str(word);
            } else {
                lines.push(std::mem::take(&mut current));
                current.push_str(word);
            }
        }
        if !current.is_empty() {
            lines.push(current);
        }
    }

    lines
}

/// Renders a two column help table where the description wraps under its own
/// column and every produced line stays within `width`.
pub fn render_entries(entries: &[HelpEntry], width: usize) -> String {
    let width = width.max(MIN_HELP_WIDTH);
    let label_width = entries
        .iter()
        .map(|entry| entry.label.chars().count())
        .max()
        .unwrap_or(0)
        .min(width.saturating_sub(TABLE_INDENT + LABEL_GAP + MIN_DESC_WIDTH));
    let desc_indent = TABLE_INDENT + label_width + LABEL_GAP;
    let desc_width = width.saturating_sub(desc_indent).max(MIN_DESC_WIDTH);
    let hanging = " ".repeat(desc_indent);

    let mut out = String::new();
    for entry in entries {
        let description = wrap(&entry.description, desc_width);
        let first = description.first().cloned().unwrap_or_default();
        out.push_str(&" ".repeat(TABLE_INDENT));
        out.push_str(&pad_to(&entry.label, label_width));
        out.push_str(&" ".repeat(LABEL_GAP));
        out.push_str(&first);
        out.push('\n');
        for line in description.iter().skip(1) {
            if line.is_empty() {
                out.push('\n');
                continue;
            }
            out.push_str(&hanging);
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Renders the wrapped command overview of the `stellar-toolkit` CLI.
pub fn render_command_help(width: usize) -> String {
    let width = width.max(MIN_HELP_WIDTH);
    let app = App::command();
    let entries: Vec<HelpEntry> = app
        .get_subcommands()
        .iter()
        .map(|sub| HelpEntry::new(sub.get_name(), command_description(sub)))
        .collect();

    let mut out = String::new();
    for line in wrap(TAGLINE, width) {
        out.push_str(&line);
        out.push('\n');
    }
    out.push('\n');

    if let Some(about) = app.get_about() {
        for line in wrap(&about.to_string(), width) {
            out.push_str(&line);
            out.push('\n');
        }
        out.push('\n');
    }

    out.push_str(&render_entries(&entries, width));

    for line in wrap(FOOTER, width) {
        out.push_str(&line);
        out.push('\n');
    }

    out
}

/// Prefers the long help of a command and falls back to its short help.
fn command_description(command: &Command) -> String {
    let text = command
        .get_long_about()
        .or_else(|| command.get_about())
        .map(ToString::to_string)
        .unwrap_or_default();
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Splits a token that cannot fit on one line into `width` sized chunks.
fn split_word(word: &str, width: usize) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    for ch in word.chars() {
        if current.chars().count() >= width {
            parts.push(std::mem::take(&mut current));
        }
        current.push(ch);
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

/// Left pads `label` with spaces up to `width`, truncating when it is longer.
fn pad_to(label: &str, width: usize) -> String {
    let mut padded: String = label.chars().take(width).collect();
    while padded.chars().count() < width {
        padded.push(' ');
    }
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_breaks_on_words_and_keeps_line_breaks() {
        let text = "build every soroban contract in the workspace";
        let lines = wrap(text, 20);
        assert!(lines.iter().all(|l| l.chars().count() <= 20));
        assert!(lines.len() > 1);
        assert_eq!(lines.join(" "), text);

        let explicit = wrap("first line\nsecond line", 40);
        assert_eq!(explicit, vec!["first line", "second line"]);
    }

    #[test]
    fn test_wrap_splits_tokens_longer_than_width() {
        let long = format!("{}tail", "x".repeat(25));
        let lines = wrap(&long, 10);
        assert_eq!(lines, vec!["xxxxxxxxxx", "xxxxxxxxxx", "xxxxxtail"]);
    }

    #[test]
    fn test_wrap_never_loops_on_zero_width() {
        let lines = wrap("abc", 0);
        assert_eq!(lines, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_render_entries_hangs_continuation_lines() {
        let entries = vec![
            HelpEntry::new("compile", "Build all Soroban contract crates to wasm"),
            HelpEntry::new("contracts", "Show local paths for compiled contracts"),
        ];
        let rendered = render_entries(&entries, 44);
        let lines: Vec<&str> = rendered.lines().collect();
        let label_width = entries
            .iter()
            .map(|entry| entry.label.chars().count())
            .max()
            .unwrap();
        let desc_indent = TABLE_INDENT + label_width + LABEL_GAP;

        assert!(lines.iter().all(|line| line.chars().count() <= 44));
        assert!(lines[0].starts_with("  compile"));
        assert!(lines[0].contains("Build all Soroban contract"));
        // Continuation lines align with the description column.
        assert!(lines[1].starts_with(&" ".repeat(desc_indent)));
        assert_eq!(lines[1].trim_start(), "to wasm");
    }

    #[test]
    fn test_render_command_help_wraps_every_line() {
        for width in [40usize, 72, 100] {
            let help = render_command_help(width);
            assert!(
                help.lines().all(|line| line.chars().count() <= width),
                "line overflow at width {width}"
            );
        }
        let help = render_command_help(72);
        for command in ["compile", "wallet", "scaffold", "gas", "inspect"] {
            assert!(help.contains(command), "missing {command} in help");
        }
    }

    #[test]
    fn test_help_width_is_clamped() {
        std::env::set_var("COLUMNS", "10");
        assert_eq!(help_width(), MIN_HELP_WIDTH);
        std::env::set_var("COLUMNS", "5000");
        assert_eq!(help_width(), DEFAULT_HELP_WIDTH);
        std::env::set_var("COLUMNS", "not-a-number");
        assert_eq!(help_width(), DEFAULT_HELP_WIDTH);
        std::env::remove_var("COLUMNS");
        assert_eq!(help_width(), DEFAULT_HELP_WIDTH);
    }
}

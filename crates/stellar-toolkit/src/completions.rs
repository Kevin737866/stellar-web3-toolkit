//! Shell completion generation for top-level `stellar-toolkit` commands (issue #310).
//!
//! # Interface
//!
//! - CLI: `stellar-toolkit completions <SHELL> [--out <PATH>]`
//! - Library: [`generate_completion`], [`generate_completion_for_command`],
//!   [`write_completion`], [`top_level_commands`], [`validate_bin_name`], and [`Shell`].
//!
//! # Supported Shells & Compatibility
//!
//! Supports `bash`, `zsh`, `fish`, and `powershell`.
//!
//! - **Bash**: Targets `bash-completion` v2 (`complete -F`). Place the output in
//!   `~/.local/share/bash-completion/completions/stellar-toolkit` or source it in `~/.bashrc`.
//! - **Zsh**: Emits a `#compdef` function using `_arguments` and `_describe`. Place it
//!   as `_stellar-toolkit` inside a directory on `$fpath`.
//! - **Fish**: Emits `complete -c` rules gated on `__fish_use_subcommand`. Place it in
//!   `~/.config/fish/completions/stellar-toolkit.fish`.
//! - **PowerShell**: Emits `Register-ArgumentCompleter -Native` for PowerShell 5.1+ and
//!   PowerShell 7+. Source it from `$PROFILE`.
//!
//! All scripts are generated dynamically from [`App::command()`] so newly added
//! top-level subcommands are included automatically without maintaining a separate list.

use crate::cli::App;
use clap::{Command, CommandFactory};
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use thiserror::Error;

/// Default binary name used in generated shell completion scripts.
pub const DEFAULT_BIN_NAME: &str = "stellar-toolkit";

/// Supported shells for top-level command completion generation.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    /// Bourne-Again SHell (`bash`).
    Bash,
    /// Z shell (`zsh`).
    Zsh,
    /// Friendly Interactive SHell (`fish`).
    Fish,
    /// PowerShell (`powershell`).
    #[value(name = "powershell")]
    PowerShell,
}

impl Shell {
    /// Returns the canonical lowercase name of the shell.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
            Self::PowerShell => "powershell",
        }
    }

    /// Returns all supported shell variants in canonical order.
    pub const fn all() -> [Self; 4] {
        [Self::Bash, Self::Zsh, Self::Fish, Self::PowerShell]
    }
}

impl fmt::Display for Shell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Shell {
    type Err = CompletionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.trim() != s {
            return Err(CompletionError::UnsupportedShell {
                input: s.to_string(),
            });
        }
        match s.to_ascii_lowercase().as_str() {
            "bash" => Ok(Self::Bash),
            "zsh" => Ok(Self::Zsh),
            "fish" => Ok(Self::Fish),
            "powershell" => Ok(Self::PowerShell),
            _ => Err(CompletionError::UnsupportedShell {
                input: s.to_string(),
            }),
        }
    }
}

/// Errors returned during shell completion validation, generation, or output.
#[derive(Error, Debug)]
pub enum CompletionError {
    /// The requested shell name is not supported.
    #[error("unsupported shell '{input}'; expected one of: bash, zsh, fish, powershell")]
    UnsupportedShell { input: String },

    /// The binary name contains unsafe or invalid characters.
    #[error("invalid binary name '{name}': {reason}")]
    InvalidBinaryName { name: String, reason: &'static str },

    /// The inspected command has no visible top-level subcommands.
    #[error("no top-level commands found to generate completions for")]
    NoTopLevelCommands,

    /// The output path is invalid or cannot be written safely.
    #[error("invalid completion output path '{}': {reason}", path.display())]
    InvalidOutputPath { path: PathBuf, reason: &'static str },

    /// An underlying I/O error occurred while writing the completion script.
    #[error("failed to write completion script: {0}")]
    Io(#[from] io::Error),
}

/// Metadata for a single top-level toolkit subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopLevelCommandSpec {
    /// Subcommand name as invoked on the CLI (for example, `"compile"`).
    pub name: String,
    /// Single-line normalized summary of the subcommand.
    pub description: String,
}

/// Validates that `bin_name` is safe to embed in shell completion scripts.
///
/// Rejects empty names, leading hyphens, whitespace, path separators, quotes,
/// and any character outside `[A-Za-z0-9_-]`.
pub fn validate_bin_name(bin_name: &str) -> Result<(), CompletionError> {
    if bin_name.is_empty() {
        return Err(CompletionError::InvalidBinaryName {
            name: bin_name.to_string(),
            reason: "binary name cannot be empty",
        });
    }
    if bin_name.starts_with('-') {
        return Err(CompletionError::InvalidBinaryName {
            name: bin_name.to_string(),
            reason: "binary name cannot start with '-'",
        });
    }
    if !bin_name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(CompletionError::InvalidBinaryName {
            name: bin_name.to_string(),
            reason: "only ASCII letters, digits, '-' and '_' are allowed",
        });
    }
    Ok(())
}

/// Returns the visible top-level commands of `stellar-toolkit` in CLI definition order.
pub fn top_level_commands() -> Vec<TopLevelCommandSpec> {
    extract_top_level_commands(&App::command())
}

/// Generates a shell completion script for all top-level `stellar-toolkit` commands.
pub fn generate_completion(shell: Shell) -> Result<String, CompletionError> {
    let command = App::command();
    generate_completion_for_command(&command, shell, DEFAULT_BIN_NAME)
}

/// Generates a shell completion script for the top-level subcommands of `command`.
///
/// Validates `bin_name` explicitly and returns [`CompletionError::NoTopLevelCommands`]
/// if `command` defines no visible subcommands.
pub fn generate_completion_for_command(
    command: &Command,
    shell: Shell,
    bin_name: &str,
) -> Result<String, CompletionError> {
    validate_bin_name(bin_name)?;
    let commands = extract_top_level_commands(command);
    if commands.is_empty() {
        return Err(CompletionError::NoTopLevelCommands);
    }

    let script = match shell {
        Shell::Bash => render_bash(bin_name, &commands),
        Shell::Zsh => render_zsh(bin_name, &commands),
        Shell::Fish => render_fish(bin_name, &commands),
        Shell::PowerShell => render_powershell(bin_name, &commands),
    };
    Ok(script)
}

/// Generates the completion script for `shell` and writes it to `out` (or stdout when `None`).
///
/// Validates the output path and generates the full script in memory before writing,
/// preventing partial or empty files on failure.
pub fn write_completion(shell: Shell, out: Option<&Path>) -> Result<(), CompletionError> {
    if let Some(path) = out {
        validate_output_path(path)?;
    }

    let script = generate_completion(shell)?;

    match out {
        Some(path) => {
            fs::write(path, script.as_bytes())?;
        }
        None => {
            let mut stdout = io::stdout().lock();
            stdout.write_all(script.as_bytes())?;
            stdout.flush()?;
        }
    }
    Ok(())
}

fn validate_output_path(path: &Path) -> Result<(), CompletionError> {
    if path.as_os_str().is_empty() {
        return Err(CompletionError::InvalidOutputPath {
            path: path.to_path_buf(),
            reason: "output path cannot be empty",
        });
    }
    if path.is_dir() {
        return Err(CompletionError::InvalidOutputPath {
            path: path.to_path_buf(),
            reason: "output path points to a directory",
        });
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            return Err(CompletionError::InvalidOutputPath {
                path: path.to_path_buf(),
                reason: "parent directory does not exist",
            });
        }
    }
    Ok(())
}

fn extract_top_level_commands(command: &Command) -> Vec<TopLevelCommandSpec> {
    command
        .get_subcommands()
        .filter(|sub| !sub.is_hide_set())
        .map(|sub| TopLevelCommandSpec {
            name: sub.get_name().to_string(),
            description: normalize_description(sub),
        })
        .collect()
}

fn normalize_description(command: &Command) -> String {
    let raw = command
        .get_about()
        .or_else(|| command.get_long_about())
        .map(ToString::to_string)
        .unwrap_or_default();
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn shell_fn_name(bin_name: &str) -> String {
    format!("_{}", bin_name.replace('-', "_"))
}

fn render_bash(bin_name: &str, commands: &[TopLevelCommandSpec]) -> String {
    let fn_name = shell_fn_name(bin_name);
    let cmd_list = commands
        .iter()
        .map(|c| c.name.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let shells = Shell::all()
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(" ");

    format!(
        "# Bash completion for {bin_name}\n\
         # Source this file or place it in your bash-completion directory.\n\
         \n\
         {fn_name}() {{\n\
         \x20   local cur prev\n\
         \x20   COMPREPLY=()\n\
         \x20   cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n\
         \x20   prev=\"${{COMP_WORDS[COMP_CWORD-1]}}\"\n\
         \n\
         \x20   local commands=\"{cmd_list}\"\n\
         \x20   local global_opts=\"-h --help -V --version\"\n\
         \n\
         \x20   if [[ ${{COMP_CWORD}} -eq 1 ]]; then\n\
         \x20       if [[ \"${{cur}}\" == -* ]]; then\n\
         \x20           COMPREPLY=( $(compgen -W \"${{global_opts}}\" -- \"${{cur}}\") )\n\
         \x20       else\n\
         \x20           COMPREPLY=( $(compgen -W \"${{commands}}\" -- \"${{cur}}\") )\n\
         \x20       fi\n\
         \x20       return 0\n\
         \x20   fi\n\
         \n\
         \x20   if [[ ${{COMP_CWORD}} -eq 2 && \"${{prev}}\" == \"completions\" ]]; then\n\
         \x20       COMPREPLY=( $(compgen -W \"{shells}\" -- \"${{cur}}\") )\n\
         \x20       return 0\n\
         \x20   fi\n\
         }}\n\
         \n\
         complete -F {fn_name} {bin_name}\n"
    )
}

fn render_zsh(bin_name: &str, commands: &[TopLevelCommandSpec]) -> String {
    let fn_name = shell_fn_name(bin_name);
    let mut entries = String::new();
    for cmd in commands {
        let name = escape_zsh(&cmd.name);
        let desc = escape_zsh(&cmd.description);
        entries.push_str(&format!("        '{name}:{desc}'\n"));
    }

    format!(
        "#compdef {bin_name}\n\
         # Zsh completion for {bin_name}\n\
         \n\
         {fn_name}() {{\n\
         \x20   local -a commands\n\
         \x20   commands=(\n\
         {entries}\
         \x20   )\n\
         \n\
         \x20   _arguments -C \\\n\
         \x20       '(-h --help)'{{-h,--help}}'[Print help]' \\\n\
         \x20       '(-V --version)'{{-V,--version}}'[Print version]' \\\n\
         \x20       '1: :->cmds' \\\n\
         \x20       '*::arg:->args'\n\
         \n\
         \x20   case \"$state\" in\n\
         \x20       cmds)\n\
         \x20           _describe -t commands '{bin_name} commands' commands\n\
         \x20           ;;\n\
         \x20   esac\n\
         }}\n\
         \n\
         {fn_name} \"$@\"\n"
    )
}

fn render_fish(bin_name: &str, commands: &[TopLevelCommandSpec]) -> String {
    let mut out = format!(
        "# Fish completion for {bin_name}\n\
         \n\
         complete -c {bin_name} -f -s h -l help -d 'Print help'\n\
         complete -c {bin_name} -f -s V -l version -d 'Print version'\n"
    );

    for cmd in commands {
        let name = escape_fish(&cmd.name);
        let desc = escape_fish(&cmd.description);
        out.push_str(&format!(
            "complete -c {bin_name} -f -n '__fish_use_subcommand' -a '{name}' -d '{desc}'\n"
        ));
    }

    for shell in Shell::all() {
        let s = shell.as_str();
        out.push_str(&format!(
            "complete -c {bin_name} -f -n '__fish_seen_subcommand_from completions' -a '{s}'\n"
        ));
    }

    out
}

fn render_powershell(bin_name: &str, commands: &[TopLevelCommandSpec]) -> String {
    let mut entries = String::new();
    for cmd in commands {
        let name = escape_powershell(&cmd.name);
        let desc = escape_powershell(&cmd.description);
        entries.push_str(&format!(
            "        @{{ Name = '{name}'; Description = '{desc}' }}\n"
        ));
    }

    format!(
        "# PowerShell completion for {bin_name}\n\
         \n\
         Register-ArgumentCompleter -Native -CommandName '{bin_name}' -ScriptBlock {{\n\
         \x20   param($wordToComplete, $commandAst, $cursorPosition)\n\
         \n\
         \x20   $tokens = $commandAst.CommandElements\n\
         \x20   if ($tokens.Count -gt 2 -or ($tokens.Count -eq 2 -and $wordToComplete -eq '')) {{\n\
         \x20       return\n\
         \x20   }}\n\
         \n\
         \x20   $commands = @(\n\
         {entries}\
         \x20   )\n\
         \n\
         \x20   $commands | Where-Object {{ $_.Name -like \"$wordToComplete*\" }} | ForEach-Object {{\n\
         \x20       [System.Management.Automation.CompletionResult]::new($_.Name, $_.Name, 'ParameterValue', $_.Description)\n\
         \x20   }}\n\
         }}\n"
    )
}

fn escape_zsh(input: &str) -> String {
    input
        .replace('\'', "'\\''")
        .replace(':', "\\:")
}

fn escape_fish(input: &str) -> String {
    input.replace('\\', "\\\\").replace('\'', "\\'")
}

fn escape_powershell(input: &str) -> String {
    input.replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_from_str_accepts_supported_shells_and_rejects_invalid() {
        assert_eq!(Shell::from_str("bash").unwrap(), Shell::Bash);
        assert_eq!(Shell::from_str("ZSH").unwrap(), Shell::Zsh);
        assert_eq!(Shell::from_str("fish").unwrap(), Shell::Fish);
        assert_eq!(Shell::from_str("PowerShell").unwrap(), Shell::PowerShell);

        for invalid in ["", "   ", " bash", "tcsh", "sh", "elvish"] {
            let err = Shell::from_str(invalid).expect_err("invalid shell must fail");
            assert!(
                matches!(err, CompletionError::UnsupportedShell { .. }),
                "unexpected error for '{invalid}': {err:?}"
            );
        }
    }

    #[test]
    fn test_validate_bin_name_rejects_unsafe_inputs() {
        assert!(validate_bin_name("stellar-toolkit").is_ok());
        assert!(validate_bin_name("stellar_toolkit_2").is_ok());

        for bad in ["", "-bad", "stellar toolkit", "a;rm -rf /", "bin/name", "a'b"] {
            let err = validate_bin_name(bad).expect_err("unsafe bin name must be rejected");
            assert!(
                matches!(err, CompletionError::InvalidBinaryName { .. }),
                "unexpected error for '{bad}': {err:?}"
            );
        }
    }

    #[test]
    fn test_generate_completion_includes_all_top_level_commands_for_every_shell() {
        let cmds = top_level_commands();
        assert!(!cmds.is_empty());
        assert!(cmds.iter().any(|c| c.name == "compile"));
        assert!(cmds.iter().any(|c| c.name == "completions"));
        assert!(cmds.iter().any(|c| c.name == "help"));

        for shell in Shell::all() {
            let script = generate_completion(shell).expect("completion generation must succeed");
            for cmd in &cmds {
                assert!(
                    script.contains(&cmd.name),
                    "shell {shell} missing top-level command '{}'",
                    cmd.name
                );
            }
        }
    }

    #[test]
    fn test_generate_completion_for_command_rejects_empty_command_tree() {
        let empty = Command::new("empty-cli");
        let err = generate_completion_for_command(&empty, Shell::Bash, "empty-cli")
            .expect_err("command without subcommands must fail");
        assert!(matches!(err, CompletionError::NoTopLevelCommands));
    }

    #[test]
    fn test_escapes_special_characters_in_descriptions() {
        let cmd = Command::new("demo").subcommand(
            Command::new("run").about("Run's task: fast\\safe"),
        );

        let zsh = generate_completion_for_command(&cmd, Shell::Zsh, "demo").unwrap();
        assert!(zsh.contains("Run'\\''s task\\: fast\\safe"));

        let fish = generate_completion_for_command(&cmd, Shell::Fish, "demo").unwrap();
        assert!(fish.contains("Run\\'s task: fast\\\\safe"));

        let ps = generate_completion_for_command(&cmd, Shell::PowerShell, "demo").unwrap();
        assert!(ps.contains("Run''s task: fast\\safe"));
    }

    #[test]
    fn test_write_completion_rejects_invalid_paths_without_creating_files() {
        let empty_path = Path::new("");
        let err = write_completion(Shell::Bash, Some(empty_path))
            .expect_err("empty output path must fail");
        assert!(matches!(err, CompletionError::InvalidOutputPath { .. }));

        let temp_dir = tempfile::tempdir().unwrap();
        let dir_err = write_completion(Shell::Zsh, Some(temp_dir.path()))
            .expect_err("directory output path must fail");
        assert!(matches!(dir_err, CompletionError::InvalidOutputPath { .. }));

        let missing_parent = temp_dir.path().join("nonexistent-dir").join("out.bash");
        let parent_err = write_completion(Shell::Bash, Some(&missing_parent))
            .expect_err("missing parent directory must fail");
        assert!(matches!(parent_err, CompletionError::InvalidOutputPath { .. }));
        assert!(!missing_parent.exists());
    }
}

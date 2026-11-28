//! Integration tests for top-level shell completion generation (issue #310).
//!
//! Exercises both the public library API and the `stellar-toolkit` CLI binary,
//! including output file creation, explicit rejection of invalid inputs, and
//! preservation of existing `help` command behavior.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use stellar_toolkit::{
    generate_completion, top_level_commands, write_completion, CompletionError, Shell,
};

#[test]
fn library_generates_and_writes_completions_for_all_supported_shells() {
    let commands = top_level_commands();
    assert!(
        commands.iter().any(|c| c.name == "completions"),
        "top-level commands must include completions"
    );

    let dir = tempfile::tempdir().expect("create temp dir");
    for shell in Shell::all() {
        let script = generate_completion(shell).expect("generate completion");
        for cmd in &commands {
            assert!(
                script.contains(&cmd.name),
                "{shell} completion missing command '{}'",
                cmd.name
            );
        }

        let out_path = dir.path().join(format!("stellar-toolkit.{shell}"));
        write_completion(shell, Some(&out_path)).expect("write completion file");
        let written = fs::read_to_string(&out_path).expect("read written completion");
        assert_eq!(written, script);
    }
}

#[test]
fn library_rejects_missing_parent_directory_without_partial_write() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let bad_path = dir.path().join("missing-subdir").join("completions.fish");

    let err = write_completion(Shell::Fish, Some(&bad_path))
        .expect_err("missing parent directory must fail");
    assert!(matches!(err, CompletionError::InvalidOutputPath { .. }));
    assert!(!bad_path.exists());
}

#[test]
fn cli_completions_prints_bash_script_to_stdout() {
    Command::cargo_bin("stellar-toolkit")
        .expect("binary exists")
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("complete -F _stellar_toolkit stellar-toolkit"))
        .stdout(predicate::str::contains("compile"))
        .stdout(predicate::str::contains("completions"));
}

#[test]
fn cli_completions_writes_zsh_script_to_out_file() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let out_file = dir.path().join("_stellar-toolkit");

    Command::cargo_bin("stellar-toolkit")
        .expect("binary exists")
        .args(["completions", "zsh", "--out"])
        .arg(&out_file)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());

    let content = fs::read_to_string(&out_file).expect("read zsh completion file");
    assert!(content.starts_with("#compdef stellar-toolkit"));
    assert!(content.contains("'completions:"));
}

#[test]
fn cli_completions_rejects_missing_or_unsupported_shell() {
    Command::cargo_bin("stellar-toolkit")
        .expect("binary exists")
        .args(["completions"])
        .assert()
        .failure();

    Command::cargo_bin("stellar-toolkit")
        .expect("binary exists")
        .args(["completions", "tcsh"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("tcsh"));
}

#[test]
fn cli_help_preserves_existing_format_and_lists_completions() {
    Command::cargo_bin("stellar-toolkit")
        .expect("binary exists")
        .args(["help", "--width", "80"])
        .assert()
        .success()
        .stdout(predicate::str::contains("stellar-toolkit - build, test and inspect Soroban contracts"))
        .stdout(predicate::str::contains("completions"));
}

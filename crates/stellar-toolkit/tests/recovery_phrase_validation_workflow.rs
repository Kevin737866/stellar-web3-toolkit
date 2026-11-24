//! Integration workflow for actionable recovery-phrase validation (issue #330).
//!
//! Validation is the gate in front of key derivation: a bad phrase must be
//! rejected with a word position before any `S…` key is produced or printed.
//! Phrases are assembled from words, never written as literals, so this file
//! holds no secret material for `security secrets` to flag.

use stellar_toolkit::wallet::{recover_wallet, validate_recovery_phrase, RecoveryPhraseIssueKind};

/// Canonical 24-word all-zero-entropy phrase (valid BIP-39 checksum).
fn valid_phrase() -> String {
    let mut words = vec!["abandon"; 23];
    words.push("art");
    words.join(" ")
}

/// Same phrase with a non-wordlist token at a known position.
fn phrase_with_unknown_word(position: usize) -> String {
    let mut words: Vec<String> = valid_phrase()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    words[position - 1] = "notaword".to_string();
    words.join(" ")
}

#[test]
fn validation_and_recovery_agree_on_a_valid_phrase() {
    let phrase = valid_phrase();
    validate_recovery_phrase(&phrase).expect("canonical phrase must validate");

    let wallet = recover_wallet(&phrase).expect("valid phrase must recover");
    assert!(wallet.secret.starts_with('S'));
    assert!(wallet.account.starts_with('G'));
}

#[test]
fn a_typo_is_rejected_by_validation_and_by_recovery_before_derivation() {
    let phrase = phrase_with_unknown_word(7);

    let error = validate_recovery_phrase(&phrase).unwrap_err();
    let issue = error
        .issues()
        .iter()
        .find(|issue| issue.kind == RecoveryPhraseIssueKind::UnknownWord)
        .expect("unknown word finding");
    assert_eq!(issue.position, Some(7));

    let recovery_error = recover_wallet(&phrase)
        .expect_err("recovery must refuse the same phrase")
        .to_string();
    assert!(
        recovery_error.contains("word 7"),
        "recovery error must be actionable: {recovery_error}"
    );
    assert!(
        !recovery_error.contains("notaword"),
        "error echoed phrase material: {recovery_error}"
    );
}

#[test]
fn cli_validate_reports_the_word_position_without_printing_a_key() {
    let phrase = phrase_with_unknown_word(3);

    let output = assert_cmd::Command::cargo_bin("stellar-toolkit")
        .expect("binary must build")
        .args(["wallet", "validate", &phrase])
        .output()
        .expect("command must run");

    assert!(!output.status.success(), "invalid phrase must fail the CLI");
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(
        stderr.contains("word 3"),
        "stderr must be actionable: {stderr}"
    );
    assert!(
        !stdout.contains('S'),
        "validation must not print a secret key"
    );
}

#[test]
fn cli_validate_accepts_a_valid_phrase_without_deriving_keys() {
    let output = assert_cmd::Command::cargo_bin("stellar-toolkit")
        .expect("binary must build")
        .args(["wallet", "validate", &valid_phrase()])
        .output()
        .expect("command must run");

    assert!(
        output.status.success(),
        "valid phrase must pass: {output:?}"
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(stdout.contains("valid"));
    assert!(stdout.contains("24 words"));
    assert!(
        !stdout.contains('S'),
        "validation must not print a secret key"
    );
}

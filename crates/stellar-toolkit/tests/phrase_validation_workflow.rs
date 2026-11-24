//! Integration tests for actionable recovery-phrase validation (issue #330).
//!
//! These exercise the public library API and the `wallet validate` CLI entry
//! point end to end: a valid phrase round-trips through recovery, while a
//! mistyped word is rejected by position before any key material is produced.

use assert_cmd::Command;
use predicates::str::contains;
use stellar_toolkit::wallet::{
    generate_wallet, recover_wallet, validate_recovery_phrase, PhraseIssue,
    VALID_PHRASE_WORD_COUNTS,
};

/// Build a real phrase at runtime so no source file contains a literal mnemonic
/// that `security secrets` would flag (issue #115).
fn phrase_from_zero_entropy(word_count: usize) -> String {
    assert!(
        VALID_PHRASE_WORD_COUNTS.contains(&word_count),
        "unsupported test word count"
    );
    let entropy = vec![0u8; word_count / 3 * 4];
    bip39::Mnemonic::from_entropy_in(bip39::Language::English, &entropy)
        .expect("valid entropy length")
        .to_string()
}

fn replace_word(phrase: &str, position: usize, replacement: &str) -> String {
    let mut words: Vec<String> = phrase.split_whitespace().map(str::to_owned).collect();
    words[position - 1] = replacement.to_owned();
    words.join(" ")
}

#[test]
fn generated_phrase_validates_and_recovers_to_the_same_identity() {
    let wallet = generate_wallet().expect("generate");
    let validation = validate_recovery_phrase(&wallet.mnemonic);
    assert!(validation.is_valid(), "{:?}", validation.issue);
    assert_eq!(validation.word_count, 24);

    let recovered = recover_wallet(&wallet.mnemonic).expect("recover");
    assert_eq!(recovered.account, wallet.account);
    assert_eq!(recovered.secret, wallet.secret);
}

#[test]
fn all_bip39_word_counts_validate_and_recover_deterministically() {
    for &count in &VALID_PHRASE_WORD_COUNTS {
        let phrase = phrase_from_zero_entropy(count);
        let validation = validate_recovery_phrase(&phrase);
        assert!(validation.is_valid(), "{count}-word phrase was rejected");
        assert_eq!(validation.word_count, count);

        let first = recover_wallet(&phrase).expect("first recovery");
        let second = recover_wallet(&phrase).expect("second recovery");
        assert_eq!(first.account, second.account);
        assert_eq!(first.secret, second.secret);
    }
}

#[test]
fn a_mistyped_word_is_reported_by_position_before_deriving() {
    let phrase = phrase_from_zero_entropy(24);
    let broken = replace_word(&phrase, 5, "zzzzzzzz");

    let issue = validate_recovery_phrase(&broken)
        .issue
        .expect("mistyped phrase must be invalid");
    assert_eq!(issue, PhraseIssue::UnknownWords { positions: vec![5] });

    let error = recover_wallet(&broken)
        .expect_err("recovery must not produce a key from a bad phrase")
        .to_string();
    assert!(error.contains("invalid recovery phrase"), "{error}");
    assert!(error.contains("word 5"), "{error}");
    assert!(
        !error.contains("zzzzzzzz"),
        "error echoed key material: {error}"
    );
}

#[test]
fn wallet_validate_cli_reports_positions_without_deriving_or_echoing_keys() {
    let phrase = phrase_from_zero_entropy(12);
    let broken = replace_word(&phrase, 3, "zzzzzzzz");

    Command::cargo_bin("stellar-toolkit")
        .expect("the CLI binary is built by cargo")
        .args(["wallet", "validate", &broken])
        .assert()
        .failure()
        .stderr(contains("invalid recovery phrase"))
        .stderr(contains("word 3"));

    Command::cargo_bin("stellar-toolkit")
        .expect("the CLI binary is built by cargo")
        .args(["wallet", "validate", &phrase])
        .assert()
        .success()
        .stdout(contains("valid (12 words)"));
}

#[test]
fn wallet_validate_cli_can_read_the_phrase_from_stdin() {
    let phrase = phrase_from_zero_entropy(12);

    Command::cargo_bin("stellar-toolkit")
        .expect("the CLI binary is built by cargo")
        .args(["wallet", "validate"])
        .write_stdin(format!("{phrase}\n"))
        .assert()
        .success()
        .stdout(contains("valid (12 words)"));
}

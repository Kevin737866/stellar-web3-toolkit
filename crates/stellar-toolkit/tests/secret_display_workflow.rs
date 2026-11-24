//! Integration tests for the secret-display confirmation (issue #328).
//!
//! `wallet generate` / `wallet recover` used to print the recovery phrase and the
//! Stellar secret key every time. Secret material now appears only after the
//! caller passes `--show-secret`, which is the explicit confirmation; the default
//! output is masked.
//!
//! These tests drive the real binary so they cover the CLI wiring (flag parsing,
//! `Debug` redaction path, rendering) rather than only the formatter.

use assert_cmd::Command;
use predicates::prelude::*;

/// Every `S…` strkey-shaped token in `text`, i.e. a potential secret key.
///
/// The tests assert on the *absence* of such a token rather than on a specific
/// value, because the key is random per run.
fn secret_key_tokens(text: &str) -> Vec<String> {
    text.split(|c: char| c.is_whitespace() || c == '"')
        .map(|token| token.trim_matches(|c: char| !c.is_ascii_alphanumeric()))
        .filter(|token| {
            token.len() == 56
                && token.starts_with('S')
                && token[1..]
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c))
        })
        .map(str::to_string)
        .collect()
}

/// A line made only of 12+ lowercase words is phrase-shaped; the hint line is not
/// (it contains capitalised words and the `--show-secret` flag).
fn looks_like_phrase_line(text: &str) -> bool {
    text.lines().any(|line| {
        let words: Vec<&str> = line.split_whitespace().collect();
        words.len() >= 12
            && words
                .iter()
                .all(|word| word.chars().all(|c| c.is_ascii_lowercase()))
    })
}

fn toolkit() -> Command {
    Command::cargo_bin("stellar-toolkit").expect("binary builds")
}

#[test]
fn generate_hides_both_secrets_without_confirmation() {
    let output = toolkit()
        .args(["wallet", "generate"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).expect("utf-8 output");

    assert!(
        stdout.contains("Account (G):"),
        "the public account id must still be printed: {stdout}"
    );
    assert!(
        stdout.contains("<hidden>"),
        "the secret values must be masked: {stdout}"
    );
    assert!(
        stdout.contains("--show-secret"),
        "the output must explain how to reveal the secret: {stdout}"
    );
    assert!(
        secret_key_tokens(&stdout).is_empty(),
        "a secret key was printed without confirmation: {stdout}"
    );
    assert!(
        !looks_like_phrase_line(&stdout),
        "a recovery phrase was printed without confirmation: {stdout}"
    );
}

#[test]
fn generate_reveals_the_wallet_only_when_confirmed() {
    let output = toolkit()
        .args(["wallet", "generate", "--show-secret"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).expect("utf-8 output");

    let secrets = secret_key_tokens(&stdout);
    assert_eq!(
        secrets.len(),
        1,
        "`--show-secret` must print exactly one secret key: {stdout}"
    );
    assert!(
        !stdout.contains("<hidden>"),
        "confirmed output must not still hide the wallet: {stdout}"
    );
    assert!(
        stdout.contains("shown only once"),
        "the confirmed output must carry the one-time warning: {stdout}"
    );
}

#[test]
fn recover_masks_the_phrase_it_was_given_until_confirmed() {
    // Generate a valid phrase through the library so the CLI has real input.
    let wallet = stellar_toolkit::wallet::generate_wallet().expect("generate wallet");

    let masked = toolkit()
        .args(["wallet", "recover", &wallet.mnemonic])
        .assert()
        .success();
    let masked_out = String::from_utf8(masked.get_output().stdout.clone()).expect("utf-8 output");
    assert!(
        !masked_out.contains(&wallet.secret),
        "recover printed the secret key without confirmation: {masked_out}"
    );
    assert!(
        !masked_out.contains(&wallet.mnemonic),
        "recover echoed the recovery phrase: {masked_out}"
    );
    assert!(masked_out.contains(&wallet.account));

    let revealed = toolkit()
        .args(["wallet", "recover", &wallet.mnemonic, "--show-secret"])
        .assert()
        .success();
    let revealed_out =
        String::from_utf8(revealed.get_output().stdout.clone()).expect("utf-8 output");
    assert!(
        revealed_out.contains(&wallet.secret),
        "--show-secret must display the derived secret key: {revealed_out}"
    );
}

#[test]
fn help_documents_the_confirmation_flag() {
    toolkit()
        .args(["wallet", "generate", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--show-secret"))
        .stdout(predicate::str::contains("explicit confirmation"));
}

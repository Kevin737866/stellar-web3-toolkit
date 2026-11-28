//! Integration tests for secret redaction in CLI error output (issue #331).
//!
//! The CLI's job is to fail *usefully* — which means naming the input that was
//! wrong without printing key material. These tests drive the real binary and
//! assert that every failing secret-bearing invocation leaves no usable secret in
//! `stderr`, and separately exercise the library redactor that backs it.

use assert_cmd::Command;

/// A strkey-shaped but checksum-invalid secret key. Assembled rather than written
/// out so this file holds no secret-looking literal.
fn secret_fixture() -> String {
    format!("S{}", "B".repeat(55))
}

/// Twelve lowercase words with no valid BIP-39 checksum.
fn phrase_shaped_input() -> String {
    [
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
        "juliet", "kilo", "lima",
    ]
    .join(" ")
}

fn toolkit() -> Command {
    Command::cargo_bin("stellar-toolkit").expect("binary builds")
}

#[test]
fn failing_signature_reports_the_problem_without_echoing_the_secret() {
    let secret = secret_fixture();
    let output = toolkit()
        .args(["wallet", "sign", &secret, "not-hex"])
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    let stderr = String::from_utf8(output).expect("utf-8 stderr");

    assert!(
        stderr.starts_with("Error: "),
        "errors should be one Display line, not a Debug dump: {stderr}"
    );
    assert!(
        stderr.contains("invalid secret key"),
        "the failure must still be actionable: {stderr}"
    );
    assert!(
        !stderr.contains(&secret),
        "the secret key was echoed in the error: {stderr}"
    );
    assert!(
        !stderr.contains("Wallet("),
        "stderr should not leak the error variant's Debug form: {stderr}"
    );
}

#[test]
fn a_secret_key_passed_where_a_phrase_belongs_is_not_echoed() {
    let secret = secret_fixture();
    let output = toolkit()
        .args(["wallet", "recover", &secret])
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    let stderr = String::from_utf8(output).expect("utf-8 stderr");

    assert!(!stderr.contains(&secret), "secret leaked: {stderr}");
}

#[test]
fn a_phrase_passed_where_a_key_belongs_is_not_echoed() {
    let phrase = phrase_shaped_input();
    let output = toolkit()
        .args(["wallet", "sign", &phrase, "00"])
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    let stderr = String::from_utf8(output).expect("utf-8 stderr");

    assert!(
        !stderr.contains(&phrase),
        "the recovery phrase was echoed in the error: {stderr}"
    );
}

#[test]
fn the_library_redactor_masks_secret_material_in_any_message() {
    use stellar_toolkit::error::{redact_secret_material, ToolkitError};

    let secret = secret_fixture();
    let phrase = phrase_shaped_input();
    let error =
        ToolkitError::ExecutionError(format!("import failed for `{secret}` and phrase {phrase}"));
    let redacted = error.redacted();

    assert!(!redacted.contains(&secret), "secret leaked: {redacted}");
    assert!(
        !redacted.contains("alpha bravo"),
        "phrase leaked: {redacted}"
    );
    assert!(redacted.contains("<redacted recovery phrase>"));
    assert!(redacted.starts_with("execution error: import failed"));

    // Ordinary identifiers are not touched.
    let plain = "account GDUMMYACCOUNTFORTESTONLYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA not funded";
    assert_eq!(redact_secret_material(plain), plain);
}

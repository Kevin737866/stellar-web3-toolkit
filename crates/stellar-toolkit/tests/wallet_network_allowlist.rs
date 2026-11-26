//! Integration tests for the network allowlist added to wallet funding (#332).
//!
//! These tests exercise the public API surface that callers interact with:
//! `AllowedNetwork` construction, passphrase lookup, and the `fund_account_on`
//! entry point. No live HTTP is made; the tests cover only the input-validation
//! and allowlist-enforcement layers.

use stellar_toolkit::wallet::{AllowedNetwork, fund_account_on, generate_wallet};

// ── AllowedNetwork construction ───────────────────────────────────────────────

#[test]
fn testnet_passphrase_resolves_to_testnet() {
    let network = AllowedNetwork::from_passphrase("Test SDF Network ; September 2015")
        .expect("testnet passphrase must be in the allowlist");
    assert_eq!(network, AllowedNetwork::Testnet);
}

#[test]
fn futurenet_passphrase_resolves_to_futurenet() {
    let network = AllowedNetwork::from_passphrase("Test SDF Future Network ; October 2022")
        .expect("futurenet passphrase must be in the allowlist");
    assert_eq!(network, AllowedNetwork::Futurenet);
}

#[test]
fn mainnet_passphrase_is_not_in_the_allowlist() {
    // The public network passphrase must be rejected: Friendbot does not exist
    // on mainnet and accidental mainnet funding is a security risk.
    let err = AllowedNetwork::from_passphrase(
        "Public Global Stellar Network ; September 2015",
    )
    .expect_err("mainnet must not be in the allowlist");

    assert!(
        err.to_string().contains("not in the funding allowlist"),
        "error should state the reason: {err}"
    );
}

#[test]
fn empty_passphrase_is_rejected_with_an_actionable_error() {
    let err = AllowedNetwork::from_passphrase("").expect_err("empty passphrase must be rejected");
    assert!(
        !err.to_string().is_empty(),
        "error must have a message: {err}"
    );
}

#[test]
fn passphrase_matching_is_exact_and_case_sensitive() {
    // A passphrase that differs only by case must not match any allowlist entry.
    let variants = [
        "test sdf network ; september 2015",
        "TEST SDF NETWORK ; SEPTEMBER 2015",
        "Test SDF Network ; September 2015 ", // trailing space
        " Test SDF Network ; September 2015", // leading space
    ];
    for variant in variants {
        assert!(
            AllowedNetwork::from_passphrase(variant).is_err(),
            "near-match passphrase should be rejected: {variant:?}"
        );
    }
}

// ── AllowedNetwork properties ─────────────────────────────────────────────────

#[test]
fn each_network_has_a_distinct_passphrase() {
    assert_ne!(
        AllowedNetwork::Testnet.passphrase(),
        AllowedNetwork::Futurenet.passphrase(),
    );
}

#[test]
fn each_network_has_a_distinct_friendbot_url() {
    assert_ne!(
        AllowedNetwork::Testnet.friendbot_url(),
        AllowedNetwork::Futurenet.friendbot_url(),
    );
}

#[test]
fn friendbot_urls_use_https() {
    for network in [AllowedNetwork::Testnet, AllowedNetwork::Futurenet] {
        assert!(
            network.friendbot_url().starts_with("https://"),
            "{network} friendbot URL must use HTTPS"
        );
    }
}

#[test]
fn display_names_are_lowercase_and_non_empty() {
    for network in [AllowedNetwork::Testnet, AllowedNetwork::Futurenet] {
        let name = network.to_string();
        assert!(!name.is_empty());
        assert_eq!(name, name.to_lowercase(), "display name must be lowercase");
    }
}

// ── fund_account_on input validation ──────────────────────────────────────────

#[test]
fn fund_account_on_rejects_an_empty_account_id() {
    let err = fund_account_on("", AllowedNetwork::Testnet)
        .expect_err("empty account id must be rejected");
    assert!(
        err.to_string().contains("invalid account id"),
        "expected address-validation error: {err}"
    );
}

#[test]
fn fund_account_on_rejects_a_garbage_string() {
    let err = fund_account_on("this-is-not-a-stellar-address", AllowedNetwork::Testnet)
        .expect_err("garbage account id must be rejected");
    assert!(
        err.to_string().contains("invalid account id"),
        "expected address-validation error: {err}"
    );
}

#[test]
fn fund_account_on_rejects_a_secret_key_as_account_id() {
    // Secret keys (S...) must not be accepted where a public key (G...) is
    // required, and must not be echoed in the error.
    let wallet = generate_wallet().expect("generate wallet");
    let err = fund_account_on(&wallet.secret, AllowedNetwork::Testnet)
        .expect_err("secret key must be rejected as account id");

    assert!(
        err.to_string().contains("invalid account id"),
        "expected address-validation error: {err}"
    );
    assert!(
        !err.to_string().contains(&wallet.secret),
        "secret key material must not appear in the error message: {err}"
    );
}

#[test]
fn fund_account_on_accepts_a_valid_stellar_account_id_format() {
    // A syntactically valid G... address must pass the local validation layer.
    // The call will fail (no live Friendbot) but the error must be a network
    // error, not an "invalid account id" error — proving that validation passed.
    let wallet = generate_wallet().expect("generate wallet");
    let err = fund_account_on(&wallet.account, AllowedNetwork::Testnet)
        .expect_err("network request will fail in a test environment");

    // The error must come from the HTTP layer, not from input validation.
    assert!(
        !err.to_string().contains("invalid account id"),
        "a valid account id must pass validation: {err}"
    );
}

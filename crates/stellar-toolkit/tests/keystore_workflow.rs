use stellar_toolkit::wallet::{export_keystore, generate_wallet, import_keystore};

#[test]
fn encrypted_keystore_preserves_wallet_identity_without_exposing_key() {
    let wallet = generate_wallet().expect("generate test wallet");
    let encoded = export_keystore(&wallet, "integration test passphrase").expect("export");
    assert!(!encoded.contains(&wallet.secret));
    let restored = import_keystore(&encoded, "integration test passphrase").expect("import");
    assert_eq!(restored.account, wallet.account);
    assert_eq!(restored.secret, wallet.secret);
}

#[test]
fn encrypted_keystore_rejects_wrong_password_and_invalid_document() {
    let wallet = generate_wallet().expect("generate test wallet");
    let encoded = export_keystore(&wallet, "integration test passphrase").expect("export");
    assert!(import_keystore(&encoded, "different integration password").is_err());
    assert!(import_keystore("{not-json", "integration test passphrase").is_err());
}

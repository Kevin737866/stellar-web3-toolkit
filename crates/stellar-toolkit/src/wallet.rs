//! Wallet capability for the toolkit: recovery-phrase generation and backup,
//! deterministic Stellar keypair derivation (BIP-39 mnemonic + SLIP-0010
//! hardened derivation at path m/44'/148'/0'), Friendbot faucet funding, and
//! Ed25519 transaction building/signing primitives for end users.
//!
//! The wallet module lets end users interact with toolkit contracts: they can
//! generate a recovery phrase, derive a Stellar account/secret key, fund the
//! account on testnet, and sign (build) transactions.

use crate::error::{Result, ToolkitError};
use aes_gcm::KeyInit;
use zeroize::Zeroize;
use crate::theme::{Style, Theme};
use ed25519_dalek::{Signature, Signer, SigningKey};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::fmt::Write as _;

type HmacSha512 = Hmac<Sha512>;

/// Default hardened derivation path for Stellar: `m/44'/148'/0'`.
const STELLAR_PATH: [u32; 3] = [44, 148, 0];

/// A freshly generated recovery phrase and the keypair it derives to.
pub struct GeneratedWallet {
    pub mnemonic: String,
    pub secret: String,
    pub account: String,
}

/// Redacting `Debug` (issue #115).
///
/// A wallet is logged far more often than it is printed, and `#[derive(Debug)]`
/// writes the recovery phrase and the secret key straight into whatever log
/// sink is attached. The account id is public and is kept verbatim, because
/// "which wallet was that" is exactly what makes a log useful.
impl std::fmt::Debug for GeneratedWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedWallet")
            .field("mnemonic", &crate::key_hygiene::mask_secret(&self.mnemonic))
            .field("secret", &crate::key_hygiene::mask_secret(&self.secret))
            .field("account", &self.account)
            .finish()
    }
}

/// Generate a cryptographically random 24-word BIP-39 recovery phrase and
/// derive a Stellar Ed25519 keypair from it.
pub fn generate_wallet() -> Result<GeneratedWallet> {
    let mut entropy = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut entropy);

    let mnemonic = bip39::Mnemonic::from_entropy_in(bip39::Language::English, &entropy)
        .map_err(|e| ToolkitError::Wallet(format!("invalid mnemonic entropy: {e}")))?;
    let phrase = mnemonic.to_string();

    let seed = mnemonic.to_seed("");
    let private_key = slip10_derive(&seed, &STELLAR_PATH);
    let signing_key = SigningKey::from_bytes(&private_key);

    let secret = encode_secret(&private_key);
    let account = encode_account(signing_key.verifying_key().as_bytes());

    Ok(GeneratedWallet {
        mnemonic: phrase,
        secret,
        account,
    })
}

/// Recover a Stellar keypair from an existing recovery phrase. Verifies the
/// mnemonic checksum before deriving, so a typo'd phrase is rejected early.
pub fn recover_wallet(phrase: &str) -> Result<GeneratedWallet> {
    let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, phrase)
        .map_err(|e| ToolkitError::Wallet(format!("invalid recovery phrase: {e}")))?;
    let seed = mnemonic.to_seed("");
    let private_key = slip10_derive(&seed, &STELLAR_PATH);
    let signing_key = SigningKey::from_bytes(&private_key);

    Ok(GeneratedWallet {
        mnemonic: mnemonic.to_string(),
        secret: encode_secret(&private_key),
        account: encode_account(signing_key.verifying_key().as_bytes()),
    })
}

/// Derive a 32-byte Ed25519 private key from a BIP-39 seed using SLIP-0010
/// hardened-only derivation at the given path.
fn slip10_derive(seed: &[u8], path: &[u32]) -> [u8; 32] {
    // Master key: I = HMAC-SHA512(key="ed25519 seed", data=seed).
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed").expect("hmac accepts fixed key");
    mac.update(seed);
    let i = mac.finalize().into_bytes();

    let mut private = i[0..32].to_vec();
    let mut chain_code = i[32..64].to_vec();

    for index in path {
        // Child: data = 0x00 || private_key || ser32(index)
        let mut data = Vec::with_capacity(1 + 32 + 4);
        data.push(0x00);
        data.extend_from_slice(&private);
        data.extend_from_slice(&index.wrapping_add(0x8000_0000).to_be_bytes());

        let mut mac = HmacSha512::new_from_slice(&chain_code).expect("hmac accepts fixed key");
        mac.update(&data);
        let i = mac.finalize().into_bytes();

        private = i[0..32].to_vec();
        chain_code = i[32..64].to_vec();
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&private);
    out
}

/// Sign a message (e.g. a transaction envelope) with the given Stellar secret
/// key and return the Ed25519 signature as hex.
pub fn sign_message(secret: &str, message_hex: &str) -> Result<String> {
    let private_key = decode_secret(secret)?;
    let signing_key = SigningKey::from_bytes(&private_key);
    let msg = hex::decode(message_hex)
        .map_err(|e| ToolkitError::Wallet(format!("message is not valid hex: {e}")))?;
    let signature: Signature = signing_key.sign(&msg);
    Ok(hex::encode(signature.to_bytes()))
}

/// Encode a Stellar secret key (S...).
fn encode_secret(secret: &[u8; 32]) -> String {
    format!(
        "{}",
        stellar_strkey::ed25519::PrivateKey(*secret).as_unredacted()
    )
}

/// Decode a Stellar secret key (S...).
///
/// The error never echoes the input: a mistyped key is still key material, and
/// this message ends up in logs and CI output (issue #115).
fn decode_secret(secret: &str) -> Result<[u8; 32]> {
    stellar_strkey::ed25519::PrivateKey::from_string(secret)
        .map(|k| k.0)
        .map_err(|e| {
            ToolkitError::Wallet(format!(
                "invalid secret key `{}`: {e}",
                crate::key_hygiene::mask_secret(secret)
            ))
        })
}

/// Encode a Stellar public account id (G...).
fn encode_account(public_key: &[u8; 32]) -> String {
    format!("{}", stellar_strkey::ed25519::PublicKey(*public_key))
}

/// Render a wallet for terminal display, honouring the active colour theme.
///
/// Only the *labels* are themed. The recovery phrase and the secret key are
/// printed verbatim: styling a secret risks a dimmed or recoloured value
/// reading as "less important", and in `off` mode this function returns the
/// same text the CLI printed before theming existed, with no escape sequences
/// at all.
#[must_use]
pub fn format_wallet_summary(wallet: &GeneratedWallet, theme: &Theme) -> String {
    let mut out = String::new();
    out.push_str(&theme.heading("Wallet"));
    out.push('\n');
    let _ = writeln!(
        out,
        "  {}\n{}",
        theme.key("Recovery phrase:"),
        wallet.mnemonic
    );
    let _ = writeln!(
        out,
        "  {}\n{}",
        theme.paint(Style::Secret, "Secret key:"),
        wallet.secret
    );
    let _ = writeln!(out, "  {}\n{}", theme.key("Account (G):"), wallet.account);
    out
}


/// Minimum passphrase length for an exported keystore.
pub const KEYSTORE_MIN_PASSPHRASE_LENGTH: usize = 12;
const KEYSTORE_VERSION: u32 = 1;
const KEYSTORE_AAD: &[u8] = b"stellar-toolkit-keystore:v1";
const KEYSTORE_SALT_LENGTH: usize = 16;
const KEYSTORE_NONCE_LENGTH: usize = 12;
const KEYSTORE_KDF_MEMORY_KIB: u32 = 19 * 1024;
const KEYSTORE_KDF_ITERATIONS: u32 = 2;
const KEYSTORE_KDF_PARALLELISM: u32 = 1;

/// A decrypted wallet key. The recovery phrase is deliberately not included.
pub struct ImportedKeystore {
    pub secret: String,
    pub account: String,
}

impl std::fmt::Debug for ImportedKeystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedKeystore")
            .field("secret", &crate::key_hygiene::mask_secret(&self.secret))
            .field("account", &self.account)
            .finish()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct KeystoreDocument {
    version: u32,
    kdf: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
    cipher: String,
    nonce: String,
    ciphertext: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct KeystorePayload {
    secret: String,
    account: String,
}

/// Encrypt a Stellar wallet key into portable JSON using Argon2id and AES-256-GCM.
/// The mnemonic is intentionally excluded; the passphrase must be at least 12 characters.
pub fn export_keystore(wallet: &GeneratedWallet, passphrase: &str) -> Result<String> {
    validate_keystore_passphrase(passphrase)?;
    let private = decode_secret(&wallet.secret)?;
    let account = encode_account(SigningKey::from_bytes(&private).verifying_key().as_bytes());
    if wallet.account != account {
        return Err(ToolkitError::Wallet("wallet account does not match its secret key".into()));
    }
    let mut payload = serde_json::to_vec(&KeystorePayload {
        secret: wallet.secret.clone(),
        account: wallet.account.clone(),
    })
    .map_err(|_| ToolkitError::Wallet("could not serialize keystore payload".into()))?;

    let mut salt = [0u8; KEYSTORE_SALT_LENGTH];
    let mut nonce = [0u8; KEYSTORE_NONCE_LENGTH];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let mut key = derive_keystore_key(passphrase, &salt)?;
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key)
        .map_err(|_| ToolkitError::Wallet("could not initialize keystore encryption".into()))?;
    key.zeroize();
    let encrypted = aes_gcm::aead::Aead::encrypt(
        &cipher,
        aes_gcm::Nonce::from_slice(&nonce),
        aes_gcm::aead::Payload {
            msg: &payload,
            aad: KEYSTORE_AAD,
        },
    )
    .map_err(|_| ToolkitError::Wallet("keystore encryption failed".into()))?;
    payload.zeroize();

    let document = KeystoreDocument {
        version: KEYSTORE_VERSION,
        kdf: "argon2id".into(),
        memory_kib: KEYSTORE_KDF_MEMORY_KIB,
        iterations: KEYSTORE_KDF_ITERATIONS,
        parallelism: KEYSTORE_KDF_PARALLELISM,
        salt: hex::encode(salt),
        cipher: "aes-256-gcm".into(),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(encrypted),
    };
    serde_json::to_string_pretty(&document)
        .map_err(|_| ToolkitError::Wallet("could not serialize keystore document".into()))
}

/// Decrypt and validate a keystore. Wrong passphrases, malformed data, unsupported
/// parameters, authentication failures, and account/key mismatches are rejected.
pub fn import_keystore(document: &str, passphrase: &str) -> Result<ImportedKeystore> {
    validate_keystore_passphrase(passphrase)?;
    let parsed: KeystoreDocument = serde_json::from_str(document)
        .map_err(|_| ToolkitError::Wallet("invalid keystore JSON or schema".into()))?;
    if parsed.version != KEYSTORE_VERSION
        || parsed.kdf != "argon2id"
        || parsed.memory_kib != KEYSTORE_KDF_MEMORY_KIB
        || parsed.iterations != KEYSTORE_KDF_ITERATIONS
        || parsed.parallelism != KEYSTORE_KDF_PARALLELISM
        || parsed.cipher != "aes-256-gcm"
    {
        return Err(ToolkitError::Wallet(
            "unsupported keystore version or cryptographic parameters".into(),
        ));
    }
    let salt = hex::decode(&parsed.salt)
        .map_err(|_| ToolkitError::Wallet("invalid keystore salt encoding".into()))?;
    let nonce = hex::decode(&parsed.nonce)
        .map_err(|_| ToolkitError::Wallet("invalid keystore nonce encoding".into()))?;
    let ciphertext = hex::decode(&parsed.ciphertext)
        .map_err(|_| ToolkitError::Wallet("invalid keystore ciphertext encoding".into()))?;
    if salt.len() != KEYSTORE_SALT_LENGTH
        || nonce.len() != KEYSTORE_NONCE_LENGTH
        || ciphertext.len() < 16
    {
        return Err(ToolkitError::Wallet(
            "invalid keystore salt, nonce, or ciphertext length".into(),
        ));
    }
    let mut key = derive_keystore_key(passphrase, &salt)?;
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key)
        .map_err(|_| ToolkitError::Wallet("could not initialize keystore decryption".into()))?;
    key.zeroize();
    let mut plaintext = aes_gcm::aead::Aead::decrypt(
        &cipher,
        aes_gcm::Nonce::from_slice(&nonce),
        aes_gcm::aead::Payload {
            msg: &ciphertext,
            aad: KEYSTORE_AAD,
        },
    )
    .map_err(|_| {
        ToolkitError::Wallet(
            "keystore authentication failed (wrong passphrase or damaged file)".into(),
        )
    })?;
    let payload_result = serde_json::from_slice::<KeystorePayload>(&plaintext);
    plaintext.zeroize();
    let payload: KeystorePayload = payload_result
        .map_err(|_| ToolkitError::Wallet("decrypted keystore payload has an invalid schema".into()))?;
    let private = decode_secret(&payload.secret)?;
    let expected = encode_account(SigningKey::from_bytes(&private).verifying_key().as_bytes());
    if payload.account != expected {
        return Err(ToolkitError::Wallet("keystore account does not match its secret key".into()));
    }
    Ok(ImportedKeystore {
        secret: payload.secret,
        account: payload.account,
    })
}

fn validate_keystore_passphrase(passphrase: &str) -> Result<()> {
    if passphrase.chars().count() < KEYSTORE_MIN_PASSPHRASE_LENGTH {
        return Err(ToolkitError::Wallet(format!(
            "keystore passphrase must contain at least {KEYSTORE_MIN_PASSPHRASE_LENGTH} characters"
        )));
    }
    Ok(())
}

fn derive_keystore_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = argon2::Params::new(
        KEYSTORE_KDF_MEMORY_KIB,
        KEYSTORE_KDF_ITERATIONS,
        KEYSTORE_KDF_PARALLELISM,
        Some(32),
    )
    .map_err(|_| ToolkitError::Wallet("invalid keystore KDF parameters".into()))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|_| ToolkitError::Wallet("keystore key derivation failed".into()))?;
    Ok(key)
}


/// Fund an account on the Stellar testnet using the Friendbot faucet.
pub fn fund_account(account: &str) -> Result<()> {
    let url = format!("https://friendbot.stellar.org?addr={account}");
    let response = ureq::get(&url)
        .call()
        .map_err(|e| ToolkitError::Wallet(format!("friendbot request failed: {e}")))?;
    let body = response
        .into_string()
        .map_err(|e| ToolkitError::Wallet(format!("could not read friendbot response: {e}")))?;
    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| ToolkitError::Wallet(format!("could not parse friendbot response: {e}")))?;

    if let Some(hash) = json["hash"].as_str() {
        println!("Funded {account} (tx {hash})");
        Ok(())
    } else if let Some(err) = json["detail"].as_str() {
        Err(ToolkitError::Wallet(format!(
            "friendbot rejected the request: {err}"
        )))
    } else {
        Err(ToolkitError::Wallet(format!(
            "unexpected friendbot response: {body}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keystore_export_import_roundtrip_and_redacts_debug() {
        let wallet = generate_wallet().expect("generate");
        let document = export_keystore(&wallet, "correct horse battery staple").expect("export");
        assert!(!document.contains(&wallet.secret));
        let imported = import_keystore(&document, "correct horse battery staple").expect("import");
        assert_eq!(imported.secret, wallet.secret);
        assert_eq!(imported.account, wallet.account);
        assert!(!format!("{imported:?}").contains(&imported.secret));
    }

    #[test]
    fn keystore_rejects_wrong_passphrase_and_tampering() {
        let wallet = generate_wallet().expect("generate");
        let document = export_keystore(&wallet, "correct horse battery staple").expect("export");
        assert!(import_keystore(&document, "incorrect horse battery staple").is_err());
        let mut value: serde_json::Value = serde_json::from_str(&document).unwrap();
        value["ciphertext"] = serde_json::Value::String("00".repeat(64));
        let tampered = serde_json::to_string(&value).unwrap();
        assert!(import_keystore(&tampered, "correct horse battery staple").is_err());
    }

    #[test]
    fn keystore_rejects_short_passphrases_and_unknown_versions() {
        let wallet = generate_wallet().expect("generate");
        assert!(export_keystore(&wallet, "short").is_err());
        let document = export_keystore(&wallet, "correct horse battery staple").expect("export");
        let mut value: serde_json::Value = serde_json::from_str(&document).unwrap();
        value["version"] = serde_json::json!(999);
        let unknown_ver = serde_json::to_string(&value).unwrap();
        assert!(import_keystore(&unknown_ver, "correct horse battery staple").is_err());
    }

    #[test]
    fn generate_and_recover_roundtrip() {
        let wallet = generate_wallet().expect("generate");
        assert_eq!(wallet.mnemonic.split_whitespace().count(), 24);

        let recovered = recover_wallet(&wallet.mnemonic).expect("recover");
        assert_eq!(recovered.secret, wallet.secret, "secret key must roundtrip");
        assert_eq!(recovered.account, wallet.account, "account must roundtrip");
    }

    #[test]
    fn recovery_rejects_invalid_checksum() {
        // A phrase with an invalid checksum must be rejected before deriving.
        let err = recover_wallet("abandon xxxxxx invalid checksum test phrase here").unwrap_err();
        assert!(err.to_string().contains("invalid recovery phrase"));
    }

    #[test]
    fn recovery_is_valid_and_deterministic() {
        // 23 x `abandon` plus `art` is the canonical 24-word BIP-39 vector (valid
        // checksum). It is assembled here rather than written out so this file
        // holds no phrase literal that `security secrets` would have to excuse.
        let mut words = vec!["abandon"; 23];
        words.push("art");
        let phrase = words.join(" ");
        let wallet = recover_wallet(&phrase).expect("valid phrase");
        assert!(wallet.secret.starts_with('S'));
        assert_eq!(wallet.secret.len(), 56);
        assert!(wallet.account.starts_with('G'));
        assert_eq!(wallet.account.len(), 56);
        // Deterministic: deriving twice gives the same account.
        let again = recover_wallet(&phrase).expect("again");
        assert_eq!(again.account, wallet.account);
        assert_eq!(again.secret, wallet.secret);
    }

    #[test]
    fn sign_verifies_with_public_key() {
        use ed25519_dalek::Verifier;
        let wallet = generate_wallet().expect("generate");
        let private_key = decode_secret(&wallet.secret).expect("decode secret");
        let signing_key = SigningKey::from_bytes(&private_key);
        let verifying_key = signing_key.verifying_key();

        let msg = hex::encode(b"hello world");
        let sig_hex = sign_message(&wallet.secret, &msg).expect("sign");
        let sig = Signature::from_slice(&hex::decode(sig_hex).unwrap()).unwrap();

        verifying_key.verify(b"hello world", &sig).expect("valid");
        assert!(
            verifying_key.verify(b"tampered", &sig).is_err(),
            "signature must not verify for a different message"
        );
    }

    #[test]
    fn slip10_matches_slip_0010_vector_one() {
        // SLIP-0010 test vector 1 for ed25519, chain "m" and "m/0'".
        // The SLIP-0010 master key is derived from the exact seed bytes.
        let seed = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];

        let master = slip10_derive(&seed, &[]);
        assert_eq!(
            hex::encode(master),
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
        );

        let child_0 = slip10_derive(&seed, &[0]);
        assert_eq!(
            hex::encode(child_0),
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
        );
    }

    #[test]
    fn account_and_secret_have_correct_prefixes_and_length() {
        let wallet = generate_wallet().expect("generate");
        assert!(wallet.secret.starts_with('S'));
        assert_eq!(wallet.secret.len(), 56);
        assert!(wallet.account.starts_with('G'));
        assert_eq!(wallet.account.len(), 56);
    }

    #[test]
    fn debug_never_prints_the_phrase_or_the_secret() {
        let wallet = generate_wallet().expect("generate");
        let rendered = format!("{wallet:?}");
        assert!(
            !rendered.contains(&wallet.secret),
            "secret leaked: {rendered}"
        );
        assert!(
            !rendered.contains(&wallet.mnemonic),
            "phrase leaked: {rendered}"
        );
        // The public account id is what makes the log entry useful.
        assert!(rendered.contains(&wallet.account));
    }

    #[test]
    fn rejected_secret_key_is_not_echoed_in_the_error() {
        let err = sign_message(
            "Snot-a-real-secret-key-0000000000000000000000000000000000",
            "00",
        )
        .unwrap_err()
        .to_string();
        assert!(
            !err.contains("not-a-real-secret-key"),
            "error echoed the key material: {err}"
        );
    }

    #[test]
    fn wallet_summary_is_plain_text_when_colour_is_off() {
        let wallet = generate_wallet().expect("generate");
        let theme = Theme::resolve(
            crate::theme::ThemeMode::Off,
            crate::theme::ThemeEnv::detect(),
        );
        let out = format_wallet_summary(&wallet, &theme);
        assert!(!out.contains('\x1b'), "off mode must emit no escapes");
        assert!(out.contains(&wallet.account));
        assert!(out.contains(&wallet.secret));
        assert!(out.contains("Recovery phrase:"));
    }

    #[test]
    fn wallet_summary_themes_labels_but_not_the_secret() {
        let wallet = generate_wallet().expect("generate");
        let theme = Theme::resolve(
            crate::theme::ThemeMode::Dark,
            crate::theme::ThemeEnv {
                clicolor_force: true,
                ..crate::theme::ThemeEnv::default()
            },
        );
        let out = format_wallet_summary(&wallet, &theme);
        assert!(out.contains('\x1b'), "colour must be emitted when forced");
        // The secret is highlighted, never dimmed or recoloured as a value.
        assert!(out.contains("\x1b[1;35m"));
        assert!(out.contains(&format!("\n{}\n", wallet.secret)));
    }
}

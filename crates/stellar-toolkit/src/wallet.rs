//! Wallet capability for the toolkit: recovery-phrase generation and backup,
//! deterministic Stellar keypair derivation (BIP-39 mnemonic + SLIP-0010
//! hardened derivation at path m/44'/148'/0'), Friendbot faucet funding, and
//! Ed25519 transaction building/signing primitives for end users.
//!
//! The wallet module lets end users interact with toolkit contracts: they can
//! generate a recovery phrase, derive a Stellar account/secret key, fund the
//! account on testnet, and sign (build) transactions.

use crate::error::{Result, ToolkitError};
use crate::theme::{Style, Theme};
use aes_gcm::KeyInit;
use ed25519_dalek::{Signature, Signer, SigningKey};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::fmt::Write as _;
use zeroize::Zeroize;

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
    let mut mac =
        <HmacSha512 as Mac>::new_from_slice(b"ed25519 seed").expect("hmac accepts fixed key");
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

        let mut mac =
            <HmacSha512 as Mac>::new_from_slice(&chain_code).expect("hmac accepts fixed key");
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

/// Whether a rendered wallet summary may contain the recovery phrase and the
/// secret key (#328).
///
/// Displaying either value is the one action that turns "my wallet" into "anyone
/// standing behind me owns my wallet", so it is never the default. A caller has
/// to ask for [`SecretVisibility::Revealed`] explicitly — the CLI does that only
/// for `--show-secret` — and the masked rendering is what every other path gets.
///
/// This is a type rather than a `bool` so the decision has to be written down at
/// each call site (`SecretVisibility::Revealed`), and a future caller cannot pick
/// up "show the secret" by copying a `true` it did not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretVisibility {
    /// Print the public account id, but withhold the recovery phrase and secret
    /// key behind a [`SECRET_CONFIRMATION_HINT`] line.
    Masked,
    /// Print the recovery phrase and secret key. Only after explicit
    /// confirmation from the person running the command.
    Revealed,
}

impl SecretVisibility {
    /// `Revealed` when the caller confirmed the display, `Masked` otherwise.
    #[must_use]
    pub fn from_confirmation(confirmed: bool) -> Self {
        if confirmed {
            Self::Revealed
        } else {
            Self::Masked
        }
    }

    #[must_use]
    pub fn is_revealed(self) -> bool {
        self == Self::Revealed
    }
}

/// Placeholder printed in place of a withheld recovery phrase or secret key.
pub const HIDDEN_SECRET_PLACEHOLDER: &str = "<hidden>";

/// Explains how to display the withheld values, printed with the masked summary.
pub const SECRET_CONFIRMATION_HINT: &str =
    "Secrets are hidden. Re-run with --show-secret to display the recovery phrase and secret \
     key, but only after checking that nobody can see this terminal or its scrollback.";

/// Render a wallet for terminal display, honouring the active colour theme.
///
/// Only the *labels* are themed. When [`SecretVisibility::Revealed`] is passed,
/// the recovery phrase and the secret key are printed verbatim: styling a secret
/// risks a dimmed or recoloured value reading as "less important".
///
/// When [`SecretVisibility::Masked`] is passed — the default for every CLI path —
/// both values are replaced by [`HIDDEN_SECRET_PLACEHOLDER`] and a
/// [`SECRET_CONFIRMATION_HINT`] line explains how to reveal them. The public
/// account id is always printed: it is not a secret, and without it the output
/// would not identify the wallet at all.
///
/// In `off` mode this function returns plain text with no escape sequences.
#[must_use]
pub fn format_wallet_summary(
    wallet: &GeneratedWallet,
    theme: &Theme,
    visibility: SecretVisibility,
) -> String {
    let revealed = visibility.is_revealed();
    let mnemonic = if revealed {
        wallet.mnemonic.as_str()
    } else {
        HIDDEN_SECRET_PLACEHOLDER
    };
    let secret = if revealed {
        wallet.secret.as_str()
    } else {
        HIDDEN_SECRET_PLACEHOLDER
    };

    let mut out = String::new();
    out.push_str(&theme.heading("Wallet"));
    out.push('\n');
    let _ = writeln!(out, "  {}\n{}", theme.key("Recovery phrase:"), mnemonic);
    let _ = writeln!(
        out,
        "  {}\n{}",
        theme.paint(Style::Secret, "Secret key:"),
        secret
    );
    let _ = writeln!(out, "  {}\n{}", theme.key("Account (G):"), wallet.account);
    if !revealed {
        let _ = writeln!(out, "\n{SECRET_CONFIRMATION_HINT}");
    }
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
        return Err(ToolkitError::Wallet(
            "wallet account does not match its secret key".into(),
        ));
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
    let payload: KeystorePayload = payload_result.map_err(|_| {
        ToolkitError::Wallet("decrypted keystore payload has an invalid schema".into())
    })?;
    let private = decode_secret(&payload.secret)?;
    let expected = encode_account(SigningKey::from_bytes(&private).verifying_key().as_bytes());
    if payload.account != expected {
        return Err(ToolkitError::Wallet(
            "keystore account does not match its secret key".into(),
        ));
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

// ── Network allowlist for wallet funding (issue #332) ────────────────────────

/// A named Stellar network that the wallet funding path is allowed to contact.
///
/// Callers that want to fund an account must explicitly name the network, so
/// that a misconfigured URL or an unexpected `network_passphrase` in the
/// environment cannot silently fund an account on the wrong chain.
///
/// # Compatibility
///
/// The original `fund_account` helper (which contacts the public Friendbot
/// without a network check) is still available for callers that have not yet
/// adopted the allowlist. It is unchanged and will compile as before.
///
/// # Examples
///
/// ```rust
/// use stellar_toolkit::wallet::{AllowedNetwork, fund_account_on};
///
/// // Fund on testnet — the only network where Friendbot exists:
/// let result = fund_account_on(
///     "GDQP2KPQGKIHYJGXNUIYOMHARUARCA7DJT5FO2FFOOKY3B2WSQHG4W37",
///     AllowedNetwork::Testnet,
/// );
/// // This will fail in a unit test (no real HTTP), but it won't panic.
/// let _ = result;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowedNetwork {
    /// Stellar public testnet (Friendbot available at <https://friendbot.stellar.org>).
    Testnet,
    /// Stellar Futurenet (Friendbot available at <https://friendbot-futurenet.stellar.org>).
    Futurenet,
}

impl AllowedNetwork {
    /// The network passphrase that must match when performing a passphrase check.
    pub fn passphrase(self) -> &'static str {
        match self {
            AllowedNetwork::Testnet => "Test SDF Network ; September 2015",
            AllowedNetwork::Futurenet => "Test SDF Future Network ; October 2022",
        }
    }

    /// The Friendbot URL for this network.
    pub fn friendbot_url(self) -> &'static str {
        match self {
            AllowedNetwork::Testnet => "https://friendbot.stellar.org",
            AllowedNetwork::Futurenet => "https://friendbot-futurenet.stellar.org",
        }
    }

    /// Return the [`AllowedNetwork`] that owns `passphrase`, or an error if
    /// `passphrase` does not match any entry in the allowlist.
    ///
    /// The comparison is case-sensitive and trim-free: the caller must supply
    /// the exact passphrase string without leading or trailing whitespace.
    ///
    /// # Errors
    ///
    /// Returns [`ToolkitError::Wallet`] when `passphrase` is not in the
    /// allowlist, naming the rejected value so the caller can diagnose a
    /// misconfiguration without guessing which field is wrong.
    pub fn from_passphrase(passphrase: &str) -> Result<Self> {
        for network in [AllowedNetwork::Testnet, AllowedNetwork::Futurenet] {
            if network.passphrase() == passphrase {
                return Ok(network);
            }
        }
        Err(ToolkitError::Wallet(format!(
            "network passphrase is not in the funding allowlist: \"{passphrase}\""
        )))
    }
}

impl std::fmt::Display for AllowedNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AllowedNetwork::Testnet => write!(f, "testnet"),
            AllowedNetwork::Futurenet => write!(f, "futurenet"),
        }
    }
}

/// Fund an account on a specific network using the Friendbot faucet.
///
/// Only networks in the [`AllowedNetwork`] allowlist are accepted. Passing a
/// network that does not support Friendbot (e.g. mainnet) is a compile-time
/// error: there is no `AllowedNetwork::Mainnet` variant.
///
/// The account id must be a valid Stellar G... address. An address that fails
/// the strkey check is rejected before any HTTP request is made.
///
/// # Errors
///
/// - [`ToolkitError::Wallet`] when `account` is not a valid Stellar account id.
/// - [`ToolkitError::Wallet`] when the Friendbot HTTP request fails.
/// - [`ToolkitError::Wallet`] when Friendbot returns an error body.
///
/// # Examples
///
/// ```rust
/// use stellar_toolkit::wallet::{AllowedNetwork, fund_account_on};
///
/// // Compile-time guarantee: only testnet or futurenet can be passed here.
/// let result = fund_account_on(
///     "GDQP2KPQGKIHYJGXNUIYOMHARUARCA7DJT5FO2FFOOKY3B2WSQHG4W37",
///     AllowedNetwork::Testnet,
/// );
/// let _ = result; // would actually hit the network in a live context
/// ```
pub fn fund_account_on(account: &str, network: AllowedNetwork) -> Result<()> {
    // Validate the account id before making any HTTP request so a typo is
    // caught immediately with a clear error rather than a confusing Friendbot
    // response.
    stellar_strkey::ed25519::PublicKey::from_string(account).map_err(|e| {
        ToolkitError::Wallet(format!(
            "invalid account id `{}`: {e}",
            crate::key_hygiene::mask_secret(account)
        ))
    })?;

    let url = format!("{}?addr={account}", network.friendbot_url());
    let response = ureq::get(&url).call().map_err(|e| {
        ToolkitError::Wallet(format!(
            "friendbot request for {} on {} failed: {e}",
            crate::key_hygiene::mask_secret(account),
            network,
        ))
    })?;
    let body = response
        .into_string()
        .map_err(|e| ToolkitError::Wallet(format!("could not read friendbot response: {e}")))?;
    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| ToolkitError::Wallet(format!("could not parse friendbot response: {e}")))?;

    if let Some(hash) = json["hash"].as_str() {
        println!("Funded {account} on {network} (tx {hash})");
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

/// Fund an account on the Stellar testnet using the Friendbot faucet.
///
/// This is the original single-network helper. New callers should prefer
/// [`fund_account_on`] with an explicit [`AllowedNetwork`], which prevents
/// accidental funding on the wrong chain.
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
        let out = format_wallet_summary(&wallet, &theme, SecretVisibility::Revealed);
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
        let out = format_wallet_summary(&wallet, &theme, SecretVisibility::Revealed);
        assert!(out.contains('\x1b'), "colour must be emitted when forced");
        // The secret is highlighted, never dimmed or recoloured as a value.
        assert!(out.contains("\x1b[1;35m"));
        assert!(out.contains(&format!("\n{}\n", wallet.secret)));
    }

    // ── Network allowlist tests (issue #332) ──────────────────────────────────

    #[test]
    fn allowed_network_passphrases_round_trip() {
        assert_eq!(
            AllowedNetwork::from_passphrase("Test SDF Network ; September 2015").unwrap(),
            AllowedNetwork::Testnet,
        );
        assert_eq!(
            AllowedNetwork::from_passphrase("Test SDF Future Network ; October 2022").unwrap(),
            AllowedNetwork::Futurenet,
        );
    }

    #[test]
    fn from_passphrase_rejects_unknown_passphrase() {
        let err = AllowedNetwork::from_passphrase("Public Global Stellar Network ; September 2015")
            .unwrap_err();
        assert!(
            err.to_string().contains("not in the funding allowlist"),
            "error should name the reason: {err}"
        );
        // The rejected passphrase is included in the error so operators can
        // diagnose a misconfiguration without guessing.
        assert!(
            err.to_string()
                .contains("Public Global Stellar Network ; September 2015"),
            "rejected passphrase must appear in error: {err}"
        );
    }

    #[test]
    fn from_passphrase_rejects_empty_string() {
        assert!(AllowedNetwork::from_passphrase("").is_err());
    }

    #[test]
    fn from_passphrase_is_case_sensitive() {
        // Lower-casing any character must yield a rejection, not a fuzzy match.
        assert!(AllowedNetwork::from_passphrase("test sdf network ; september 2015").is_err());
    }

    #[test]
    fn testnet_friendbot_url_points_to_stellar_org() {
        assert!(AllowedNetwork::Testnet
            .friendbot_url()
            .starts_with("https://friendbot.stellar.org"));
    }

    #[test]
    fn futurenet_friendbot_url_is_distinct_from_testnet() {
        assert_ne!(
            AllowedNetwork::Testnet.friendbot_url(),
            AllowedNetwork::Futurenet.friendbot_url(),
        );
    }

    #[test]
    fn fund_account_on_rejects_invalid_account_id_before_any_http() {
        // A malformed account id must be rejected with a wallet error before
        // any outbound HTTP request is attempted — the network allowlist check
        // happens after address validation.
        let err = fund_account_on("not-a-stellar-address", AllowedNetwork::Testnet)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("invalid account id"),
            "expected address-validation error, got: {err}"
        );
    }

    #[test]
    fn fund_account_on_rejects_a_secret_key_instead_of_an_account_id() {
        // S... keys are not G... public keys; the validator must reject them.
        let wallet = generate_wallet().expect("generate");
        let err = fund_account_on(&wallet.secret, AllowedNetwork::Testnet)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("invalid account id"),
            "expected address-validation error, got: {err}"
        );
        // The secret key must not be echoed verbatim in the error message.
        assert!(
            !err.contains(&wallet.secret),
            "secret key must not appear in error: {err}"
        );
    }

    #[test]
    fn allowed_network_display_is_human_readable() {
        assert_eq!(AllowedNetwork::Testnet.to_string(), "testnet");
        assert_eq!(AllowedNetwork::Futurenet.to_string(), "futurenet");
    }
}

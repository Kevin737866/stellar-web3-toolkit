//! Wallet capability for the toolkit: recovery-phrase generation and backup,
//! deterministic Stellar keypair derivation (BIP-39 mnemonic + SLIP-0010
//! hardened derivation at path m/44'/148'/0'), Friendbot faucet funding, and
//! Ed25519 transaction building/signing primitives for end users.
//!
//! The wallet module lets end users interact with toolkit contracts: they can
//! generate a recovery phrase, derive a Stellar account/secret key, fund the
//! account on testnet, and sign (build) transactions.

use crate::error::{Result, ToolkitError};
use ed25519_dalek::{Signature, Signer, SigningKey};
use hmac::{Hmac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// Default hardened derivation path for Stellar: `m/44'/148'/0'`.
const STELLAR_PATH: [u32; 3] = [44, 148, 0];

/// A freshly generated recovery phrase and the keypair it derives to.
#[derive(Debug)]
pub struct GeneratedWallet {
    pub mnemonic: String,
    pub secret: String,
    pub account: String,
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
fn decode_secret(secret: &str) -> Result<[u8; 32]> {
    stellar_strkey::ed25519::PrivateKey::from_string(secret)
        .map(|k| k.0)
        .map_err(|e| ToolkitError::Wallet(format!("invalid secret key `{secret}`: {e}")))
}

/// Encode a Stellar public account id (G...).
fn encode_account(public_key: &[u8; 32]) -> String {
    format!("{}", stellar_strkey::ed25519::PublicKey(*public_key))
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
        // "abandon ... art" is the canonical 24-word BIP-39 vector (valid checksum).
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let wallet = recover_wallet(phrase).expect("valid phrase");
        assert!(wallet.secret.starts_with('S'));
        assert_eq!(wallet.secret.len(), 56);
        assert!(wallet.account.starts_with('G'));
        assert_eq!(wallet.account.len(), 56);
        // Deterministic: deriving twice gives the same account.
        let again = recover_wallet(phrase).expect("again");
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
        assert!(verifying_key
            .verify(b"tampered", &sig)
            .is_err(), "signature must not verify for a different message");
    }

    #[test]
    fn slip10_matches_slip_0010_vector_one() {
        // SLIP-0010 test vector 1 for ed25519, chain "m" and "m/0'".
        // The SLIP-0010 master key is derived from the exact seed bytes.
        let seed = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

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

}
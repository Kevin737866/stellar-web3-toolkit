//! # Operator key and data recovery (issue #377)
//!
//! A watchtower holds the durable evidence needed to answer a breach: channel
//! subscriptions, honest channel state, alerts and justice actions. This module
//! gives an operator a signed, verifiable way to take that data off a degraded
//! node and restore it onto a fresh one without trusting the transport.
//!
//! The operator key never travels with the data. It signs a canonical JSON
//! payload with HMAC-SHA256, and restoration verifies that signature before a
//! single record is written.

use crate::justice::{ActionStatus, JusticeAction};
use crate::monitor::{ChannelMonitorState, ChannelUpdate};
use crate::storage::StorageError;
use crate::Alert;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use thiserror::Error;

/// Version of the portable recovery format. Unknown versions are rejected.
pub const RECOVERY_FORMAT_VERSION: u32 = 1;

/// Default environment variable holding the hex-encoded operator key.
pub const OPERATOR_KEY_ENV_VAR: &str = "WATCHTOWER_OPERATOR_KEY";

type HmacSha256 = Hmac<Sha256>;

/// A 32-byte secret held only by the operator.
///
/// `Debug` is redacted and the type deliberately has no serde implementation,
/// so it cannot be accidentally embedded in a config file or recovery bundle.
#[derive(Clone)]
pub struct OperatorKey([u8; 32]);

impl OperatorKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Self {
        let mut bytes = [0_u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        Self(bytes)
    }

    pub fn from_hex(value: &str) -> Result<Self, RecoveryError> {
        let value = value.trim();
        if value.len() != 64 {
            return Err(RecoveryError::InvalidKey(
                "operator key must be exactly 64 hex characters".to_string(),
            ));
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let high = hex_value(pair[0]).ok_or_else(|| {
                RecoveryError::InvalidKey(format!(
                    "operator key contains a non-hex character at position {}",
                    index * 2
                ))
            })?;
            let low = hex_value(pair[1]).ok_or_else(|| {
                RecoveryError::InvalidKey(format!(
                    "operator key contains a non-hex character at position {}",
                    index * 2 + 1
                ))
            })?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    pub fn from_env(name: &str) -> Result<Self, RecoveryError> {
        let value = std::env::var(name)
            .map_err(|_| RecoveryError::InvalidKey(format!("{name} is not set")))?;
        Self::from_hex(&value)
    }

    /// Non-secret identifier safe to put in logs and alerts.
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.0);
        format!(
            "{:02x}{:02x}{:02x}{:02x}",
            digest[0], digest[1], digest[2], digest[3]
        )
    }

    fn sign(&self, payload: &RecoveryPayload) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.0).expect("HMAC-SHA256 accepts a 32-byte key");
        mac.update(&canonical_bytes(payload));
        hex_encode(&mac.finalize().into_bytes())
    }
}

impl std::fmt::Debug for OperatorKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("OperatorKey")
            .field(&"<redacted>")
            .finish()
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn hex_decode(value: &str) -> Result<Vec<u8>, RecoveryError> {
    if value.len() != 64 {
        return Err(RecoveryError::InvalidBundle(
            "recovery signature must be 64 hex characters".to_string(),
        ));
    }
    let mut bytes = Vec::with_capacity(32);
    for pair in value.as_bytes().as_chunks::<2>().0 {
        let high = hex_value(pair[0])
            .ok_or_else(|| RecoveryError::InvalidBundle("signature is not hex".to_string()))?;
        let low = hex_value(pair[1])
            .ok_or_else(|| RecoveryError::InvalidBundle("signature is not hex".to_string()))?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn canonical_bytes(payload: &RecoveryPayload) -> Vec<u8> {
    serde_json::to_vec(payload).expect("recovery payload is serializable")
}

/// Errors returned by key handling, bundle verification and restoration.
#[derive(Error, Debug)]
pub enum RecoveryError {
    #[error("Invalid operator key: {0}")]
    InvalidKey(String),

    #[error("Invalid recovery bundle: {0}")]
    InvalidBundle(String),

    #[error("Recovery signature mismatch: {0}")]
    SignatureMismatch(String),

    #[error("Recovery storage error: {0}")]
    Storage(String),

    #[error("Recovery configuration error: {0}")]
    Configuration(String),
}

/// The portable part of a recovery snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPayload {
    pub version: u32,
    pub created_at: u64,
    pub network_passphrase: String,
    pub subscriptions: Vec<String>,
    pub channel_states: Vec<ChannelMonitorState>,
    pub channel_updates: Vec<ChannelUpdate>,
    pub alerts: Vec<Alert>,
    pub justice_actions: Vec<JusticeAction>,
}

impl RecoveryPayload {
    /// Check every invariant before any record is restored.
    pub fn validate(&self) -> Result<(), RecoveryError> {
        let reject = |reason: String| RecoveryError::InvalidBundle(reason);

        if self.version != RECOVERY_FORMAT_VERSION {
            return Err(reject(format!(
                "unsupported recovery format version {}, expected {RECOVERY_FORMAT_VERSION}",
                self.version
            )));
        }
        if self.created_at == 0 {
            return Err(reject(
                "created_at must be a non-zero timestamp".to_string(),
            ));
        }
        if self.network_passphrase.trim().is_empty() {
            return Err(reject("network_passphrase must not be empty".to_string()));
        }

        let mut subscriptions = HashSet::new();
        for channel_id in &self.subscriptions {
            if channel_id.trim().is_empty() {
                return Err(reject(
                    "subscriptions contain an empty channel id".to_string(),
                ));
            }
            if !subscriptions.insert(channel_id) {
                return Err(reject(format!(
                    "duplicate subscription for channel {channel_id}"
                )));
            }
        }

        let mut states = HashSet::new();
        for state in &self.channel_states {
            if state.channel_id.trim().is_empty() {
                return Err(reject("channel state has an empty channel id".to_string()));
            }
            if !states.insert(&state.channel_id) {
                return Err(reject(format!(
                    "duplicate channel state for {}",
                    state.channel_id
                )));
            }
            if !subscriptions.contains(&state.channel_id) {
                return Err(reject(format!(
                    "channel state for {} has no subscription",
                    state.channel_id
                )));
            }
        }

        let mut updates = HashSet::new();
        for update in &self.channel_updates {
            if update.channel_id.trim().is_empty() {
                return Err(reject("channel update has an empty channel id".to_string()));
            }
            if !updates.insert(&update.channel_id) {
                return Err(reject(format!(
                    "duplicate channel update for {}",
                    update.channel_id
                )));
            }
            if !subscriptions.contains(&update.channel_id) {
                return Err(reject(format!(
                    "channel update for {} has no subscription",
                    update.channel_id
                )));
            }
        }

        let mut alert_ids = HashSet::new();
        for alert in &self.alerts {
            if alert.id.trim().is_empty() {
                return Err(reject("alert has an empty id".to_string()));
            }
            if !alert_ids.insert(&alert.id) {
                return Err(reject(format!("duplicate alert id {}", alert.id)));
            }
            if alert.timestamp == 0 {
                return Err(reject(format!("alert {} has a zero timestamp", alert.id)));
            }
        }

        let mut action_ids = HashSet::new();
        for action in &self.justice_actions {
            if action.id.trim().is_empty() {
                return Err(reject("justice action has an empty id".to_string()));
            }
            if !action_ids.insert(&action.id) {
                return Err(reject(format!("duplicate justice action id {}", action.id)));
            }
            let evidence = &action.evidence;
            if evidence.channel_id.trim().is_empty() {
                return Err(reject(format!(
                    "justice action {} has an empty channel id",
                    action.id
                )));
            }
            if evidence.breach_tx_hash.trim().is_empty() {
                return Err(reject(format!(
                    "justice action {} has an empty breach tx hash",
                    action.id
                )));
            }
            if evidence.detected_at == 0 {
                return Err(reject(format!(
                    "justice action {} has a zero detection timestamp",
                    action.id
                )));
            }
            if evidence.new_sequence <= evidence.old_sequence {
                return Err(reject(format!(
                    "justice action {} does not advance the sequence",
                    action.id
                )));
            }
            if evidence.total_balance < 0 {
                return Err(reject(format!(
                    "justice action {} has a negative total balance",
                    action.id
                )));
            }
            if action.created_at == 0 || action.updated_at < action.created_at {
                return Err(reject(format!(
                    "justice action {} has inconsistent timestamps",
                    action.id
                )));
            }
            match action.status {
                ActionStatus::Submitted | ActionStatus::Confirmed => match &action.tx_hash {
                    Some(hash) if !hash.trim().is_empty() => {}
                    _ => {
                        return Err(reject(format!(
                            "justice action {} is {} but has no transaction hash",
                            action.id,
                            action.status_label()
                        )))
                    }
                },
                ActionStatus::Pending | ActionStatus::Failed => {
                    if action.tx_hash.is_some() {
                        return Err(reject(format!(
                            "justice action {} is {} but carries a transaction hash",
                            action.id,
                            action.status_label()
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}

impl JusticeAction {
    fn status_label(&self) -> &'static str {
        match self.status {
            ActionStatus::Pending => "Pending",
            ActionStatus::Submitted => "Submitted",
            ActionStatus::Confirmed => "Confirmed",
            ActionStatus::Failed => "Failed",
        }
    }
}

/// A signed recovery snapshot. The signature covers every field of `payload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryBundle {
    pub payload: RecoveryPayload,
    pub signature: String,
}

impl RecoveryBundle {
    pub fn new(payload: RecoveryPayload, key: &OperatorKey) -> Self {
        let signature = key.sign(&payload);
        Self { payload, signature }
    }

    /// Verify structure first, then the signature in constant time.
    pub fn verify(&self, key: &OperatorKey) -> Result<(), RecoveryError> {
        self.payload.validate()?;
        let bytes = hex_decode(&self.signature)?;
        let mut mac =
            HmacSha256::new_from_slice(&key.0).expect("HMAC-SHA256 accepts a 32-byte key");
        mac.update(&canonical_bytes(&self.payload));
        mac.verify_slice(&bytes).map_err(|_| {
            RecoveryError::SignatureMismatch(
                "signature does not match the payload or the operator key".to_string(),
            )
        })
    }

    /// Rotate the operator key by re-signing a verified bundle.
    pub fn resign(
        &mut self,
        current_key: &OperatorKey,
        next_key: &OperatorKey,
    ) -> Result<(), RecoveryError> {
        self.verify(current_key)?;
        self.signature = next_key.sign(&self.payload);
        Ok(())
    }
}

impl From<RecoveryError> for StorageError {
    fn from(error: RecoveryError) -> Self {
        StorageError::SerializationError(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::justice::BreachEvidence;
    use crate::AlertSeverity;

    fn key() -> OperatorKey {
        OperatorKey::from_bytes([7; 32])
    }

    fn evidence() -> BreachEvidence {
        BreachEvidence {
            channel_id: "channel-a".to_string(),
            breach_tx_hash: "breach-tx".to_string(),
            detected_at: 1_000,
            old_sequence: 1,
            new_sequence: 4,
            total_balance: 2_000,
        }
    }

    fn payload() -> RecoveryPayload {
        let mut action = JusticeAction::new("action-1", evidence());
        action.mark_submitted("justice_channel-a_1000");
        RecoveryPayload {
            version: RECOVERY_FORMAT_VERSION,
            created_at: 1_700_000_000,
            network_passphrase: "test network".to_string(),
            subscriptions: vec!["channel-a".to_string()],
            channel_states: vec![ChannelMonitorState {
                channel_id: "channel-a".to_string(),
                last_known_sequence: 4,
                last_update_ts: 1_000,
                is_closed: false,
                pending_htlcs: Vec::new(),
            }],
            channel_updates: Vec::new(),
            alerts: vec![Alert {
                id: "alert-1".to_string(),
                alert_type: crate::AlertType::JusticeSubmitted {
                    channel_id: "channel-a".to_string(),
                    tx_hash: "justice_channel-a_1000".to_string(),
                },
                severity: AlertSeverity::Info,
                timestamp: 1_000,
                context: serde_json::json!({}),
            }],
            justice_actions: vec![action],
        }
    }

    #[test]
    fn operator_key_parses_hex_and_never_prints_the_secret() {
        let original = key();
        let hex = hex_encode(&original.0);
        let parsed = OperatorKey::from_hex(&hex).unwrap();

        assert_eq!(parsed.0, original.0);
        assert!(!format!("{original:?}").contains('7'));
        assert_eq!(parsed.fingerprint(), original.fingerprint());
        assert_eq!(parsed.fingerprint().len(), 8);
    }

    #[test]
    fn operator_key_rejects_invalid_hex() {
        assert!(matches!(
            OperatorKey::from_hex("abcd"),
            Err(RecoveryError::InvalidKey(_))
        ));
        assert!(matches!(
            OperatorKey::from_hex(&format!("z{}", "0".repeat(63))),
            Err(RecoveryError::InvalidKey(_))
        ));
    }

    #[test]
    fn a_valid_bundle_verifies_and_tampering_is_rejected() {
        let bundle = RecoveryBundle::new(payload(), &key());
        bundle.verify(&key()).unwrap();

        let mut tampered = bundle.clone();
        tampered.payload.network_passphrase = "other network".to_string();
        assert!(matches!(
            tampered.verify(&key()),
            Err(RecoveryError::SignatureMismatch(_))
        ));

        let other_key = OperatorKey::from_bytes([9; 32]);
        assert!(matches!(
            bundle.verify(&other_key),
            Err(RecoveryError::SignatureMismatch(_))
        ));

        let mut bad_signature = bundle;
        bad_signature.signature = "not hex".to_string();
        assert!(matches!(
            bad_signature.verify(&key()),
            Err(RecoveryError::InvalidBundle(_))
        ));
    }

    #[test]
    fn resigning_requires_the_current_key() {
        let mut bundle = RecoveryBundle::new(payload(), &key());
        let next_key = OperatorKey::from_bytes([9; 32]);

        assert!(matches!(
            bundle.resign(&next_key, &next_key),
            Err(RecoveryError::SignatureMismatch(_))
        ));
        bundle.resign(&key(), &next_key).unwrap();
        bundle.verify(&next_key).unwrap();
        assert!(matches!(
            bundle.verify(&key()),
            Err(RecoveryError::SignatureMismatch(_))
        ));
    }

    #[test]
    fn an_empty_snapshot_is_valid() {
        let payload = RecoveryPayload {
            subscriptions: Vec::new(),
            channel_states: Vec::new(),
            alerts: Vec::new(),
            justice_actions: Vec::new(),
            ..payload()
        };
        RecoveryBundle::new(payload, &key()).verify(&key()).unwrap();
    }

    #[test]
    fn an_unknown_version_is_rejected_before_signature_checks() {
        let mut payload = payload();
        payload.version = RECOVERY_FORMAT_VERSION + 1;
        let bundle = RecoveryBundle::new(payload, &key());

        assert!(matches!(
            bundle.verify(&key()),
            Err(RecoveryError::InvalidBundle(reason)) if reason.contains("version")
        ));
    }

    #[test]
    fn duplicate_and_orphan_channel_records_are_rejected() {
        let mut duplicate = payload();
        duplicate.subscriptions.push("channel-a".to_string());
        assert!(matches!(
            duplicate.validate(),
            Err(RecoveryError::InvalidBundle(reason)) if reason.contains("duplicate subscription")
        ));

        let mut orphan = payload();
        orphan.channel_updates.push(ChannelUpdate {
            channel_id: "unknown".to_string(),
            sequence_number: 1,
            balance_a: 1,
            balance_b: 1,
            is_closed: false,
            close_type: None,
            block_height: 1,
            timestamp: 1,
        });
        assert!(matches!(
            orphan.validate(),
            Err(RecoveryError::InvalidBundle(reason)) if reason.contains("no subscription")
        ));
    }

    #[test]
    fn inconsistent_justice_actions_are_rejected() {
        let mut pending_with_hash = payload();
        pending_with_hash.justice_actions[0].status = ActionStatus::Pending;
        pending_with_hash.justice_actions[0].tx_hash = Some("tx".to_string());
        assert!(matches!(
            pending_with_hash.validate(),
            Err(RecoveryError::InvalidBundle(reason)) if reason.contains("carries a transaction hash")
        ));

        let mut submitted_without_hash = payload();
        submitted_without_hash.justice_actions[0].tx_hash = None;
        assert!(matches!(
            submitted_without_hash.validate(),
            Err(RecoveryError::InvalidBundle(reason)) if reason.contains("no transaction hash")
        ));

        let mut bad_evidence = payload();
        bad_evidence.justice_actions[0].evidence.new_sequence = 0;
        assert!(matches!(
            bad_evidence.validate(),
            Err(RecoveryError::InvalidBundle(reason)) if reason.contains("sequence")
        ));
    }

    #[test]
    fn duplicate_alerts_are_rejected() {
        let mut snapshot = payload();
        let alert = snapshot.alerts[0].clone();
        snapshot.alerts.push(alert);
        assert!(matches!(
            snapshot.validate(),
            Err(RecoveryError::InvalidBundle(reason)) if reason.contains("duplicate alert")
        ));
    }
}

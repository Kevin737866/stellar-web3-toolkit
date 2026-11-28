//! Key-rotation history and verification method types for DID documents (issue #345).
//!
//! Per [W3C DID Core](https://www.w3.org/TR/did-core/#verification-methods), a DID
//! document lists active `verificationMethod` entries. When a controller rotates
//! a key, [`DidDocument::rotate_key`](crate::service::DidDocument::rotate_key)
//! atomically replaces the retired key with the new [`VerificationMethod`] and
//! appends an immutable [`KeyRotationRecord`] to `key_rotation_history`.
//!
//! # Invariants
//!
//! - Every [`VerificationMethod`] has non-empty, whitespace-free `id`,
//!   `controller`, and `public_key_multibase`, plus a non-empty `key_type`.
//! - Rotation requires the `previous_key_id` to be currently active, the
//!   `new_key` ID to be distinct and unused, and the new key material to differ
//!   from the retired key.
//! - Rotation timestamps must be monotonically non-decreasing across the
//!   document's rotation history.
//! - Failed rotations return an actionable [`DidError`] without mutating the
//!   document's active keys or history.

use crate::service::DidError;
use serde::{Deserialize, Serialize};

/// A W3C DID Core verification method (public key entry) in a DID document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// DID URL identifying this key (e.g. `did:stellar:testnet:GABC#key-1`).
    pub id: String,
    /// Verification method type (e.g. `"Ed25519VerificationKey2020"`).
    pub key_type: String,
    /// DID of the controller authorized to use this key.
    pub controller: String,
    /// Multibase-encoded public key material.
    pub public_key_multibase: String,
}

impl VerificationMethod {
    /// Construct and validate a [`VerificationMethod`].
    ///
    /// # Errors
    ///
    /// Returns [`DidError::InvalidKey`] if any required field is empty, blank,
    /// or contains whitespace where disallowed.
    pub fn new(
        id: impl Into<String>,
        key_type: impl Into<String>,
        controller: impl Into<String>,
        public_key_multibase: impl Into<String>,
    ) -> Result<Self, DidError> {
        let method = Self {
            id: id.into(),
            key_type: key_type.into(),
            controller: controller.into(),
            public_key_multibase: public_key_multibase.into(),
        };
        method.validate()?;
        Ok(method)
    }

    /// Validate all fields of this verification method.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::InvalidKey`] if any field is invalid.
    pub fn validate(&self) -> Result<(), DidError> {
        if self.id.trim().is_empty() || self.id.chars().any(char::is_whitespace) {
            return Err(DidError::InvalidKey(
                "verification method `id` must be non-empty and contain no whitespace".to_string(),
            ));
        }
        if self.key_type.trim().is_empty() {
            return Err(DidError::InvalidKey(
                "verification method `key_type` must not be empty".to_string(),
            ));
        }
        if self.controller.trim().is_empty() || self.controller.chars().any(char::is_whitespace) {
            return Err(DidError::InvalidKey(
                "verification method `controller` must be non-empty and contain no whitespace"
                    .to_string(),
            ));
        }
        if self.public_key_multibase.trim().is_empty()
            || self.public_key_multibase.chars().any(char::is_whitespace)
        {
            return Err(DidError::InvalidKey(
                "verification method `public_key_multibase` must be non-empty and contain no whitespace"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// An audit record of a single key-rotation event on a [`DidDocument`](crate::service::DidDocument).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationRecord {
    /// 1-based monotonically increasing rotation sequence number.
    pub sequence: u64,
    /// ID of the key that was retired.
    pub previous_key_id: String,
    /// ID of the newly activated key.
    pub new_key_id: String,
    /// Unix timestamp (seconds) when the rotation occurred.
    pub rotated_at: u64,
    /// Optional human-readable reason for the rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

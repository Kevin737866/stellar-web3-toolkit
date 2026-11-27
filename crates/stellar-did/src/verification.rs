//! DID verification method management (issue #339).
//!
//! A DID document's `verificationMethod` array lists cryptographic keys and
//! other verification material associated with the DID subject. Per the
//! [W3C DID Core specification](https://www.w3.org/TR/did-core/#verification-methods),
//! each verification method has an `id` (a DID URL) that uniquely identifies it
//! within the document.
//!
//! Allowing duplicate verification-method identifiers (including a relative
//! fragment like `#key-1` that resolves to the same DID URL as
//! `did:stellar:testnet:GABC#key-1`) creates ambiguity during signature
//! verification and key-rotation resolution, enabling one entry to shadow
//! another. This module provides [`VerificationMethod`] and validation helpers
//! that reject empty, malformed, or duplicate verification-method identifiers.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::service::DidError;

/// A verification method entry in a DID document.
///
/// Corresponds to the
/// [W3C DID Core verification method](https://www.w3.org/TR/did-core/#verification-methods)
/// structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// DID URL identifying this verification method (e.g. `did:stellar:testnet:GABC#key-1`
    /// or relative `#key-1`).
    pub id: String,
    /// Verification method type (e.g. `"Ed25519VerificationKey2020"`).
    #[serde(rename = "type")]
    pub method_type: String,
    /// DID of the controller authorized to make changes with this method.
    pub controller: String,
    /// Optional multibase-encoded public key.
    #[serde(
        default,
        rename = "publicKeyMultibase",
        skip_serializing_if = "Option::is_none"
    )]
    pub public_key_multibase: Option<String>,
    /// Optional JSON Web Key representation of the public key.
    #[serde(
        default,
        rename = "publicKeyJwk",
        skip_serializing_if = "Option::is_none"
    )]
    pub public_key_jwk: Option<serde_json::Value>,
    /// Optional additional properties defined by specific verification method suites.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub properties: HashMap<String, serde_json::Value>,
}

impl VerificationMethod {
    /// Construct a new [`VerificationMethod`] after validating required fields.
    ///
    /// # Errors
    ///
    /// * [`DidError::EmptyVerificationMethodId`] — `id` is empty or whitespace-only.
    /// * [`DidError::InvalidVerificationMethodId`] — `id` has leading or trailing whitespace.
    /// * [`DidError::EmptyVerificationMethodType`] — `method_type` is empty or whitespace-only.
    /// * [`DidError::EmptyVerificationMethodController`] — `controller` is empty or whitespace-only.
    pub fn new(
        id: impl Into<String>,
        method_type: impl Into<String>,
        controller: impl Into<String>,
    ) -> Result<Self, DidError> {
        let method = Self {
            id: id.into(),
            method_type: method_type.into(),
            controller: controller.into(),
            public_key_multibase: None,
            public_key_jwk: None,
            properties: HashMap::new(),
        };
        validate_verification_method(&method)?;
        Ok(method)
    }

    /// Attach a `publicKeyMultibase` value to this verification method.
    #[must_use]
    pub fn with_public_key_multibase(mut self, key: impl Into<String>) -> Self {
        self.public_key_multibase = Some(key.into());
        self
    }

    /// Attach a `publicKeyJwk` value to this verification method.
    #[must_use]
    pub fn with_public_key_jwk(mut self, jwk: serde_json::Value) -> Self {
        self.public_key_jwk = Some(jwk);
        self
    }
}

/// Resolve a verification-method identifier to its canonical form within `doc_id`.
///
/// Per W3C DID Core, a relative DID URL beginning with `#` (e.g. `#key-1`)
/// resolves against the document's subject DID (`<doc_id>#key-1`). Comparing
/// canonicalized identifiers prevents `#key-1` and `did:stellar:...#key-1`
/// from colliding silently.
pub(crate) fn canonical_verification_method_id<'a>(
    doc_id: &str,
    method_id: &'a str,
) -> Cow<'a, str> {
    if method_id.starts_with('#') && !doc_id.is_empty() {
        Cow::Owned(format!("{doc_id}{method_id}"))
    } else {
        Cow::Borrowed(method_id)
    }
}

/// Validate required fields of a single [`VerificationMethod`].
pub(crate) fn validate_verification_method(method: &VerificationMethod) -> Result<(), DidError> {
    if method.id.trim().is_empty() {
        return Err(DidError::EmptyVerificationMethodId);
    }
    if method.id != method.id.trim() {
        return Err(DidError::InvalidVerificationMethodId {
            id: method.id.clone(),
            reason: "identifier must not have leading or trailing whitespace".to_string(),
        });
    }
    if method.id == "#" {
        return Err(DidError::InvalidVerificationMethodId {
            id: method.id.clone(),
            reason: "fragment identifier must not be empty".to_string(),
        });
    }
    if method.method_type.trim().is_empty() {
        return Err(DidError::EmptyVerificationMethodType);
    }
    if method.controller.trim().is_empty() {
        return Err(DidError::EmptyVerificationMethodController);
    }
    Ok(())
}

/// Validate every verification method in `methods` and reject duplicate identifiers.
pub(crate) fn ensure_unique_verification_methods(
    doc_id: &str,
    methods: &[VerificationMethod],
) -> Result<(), DidError> {
    let mut seen = HashSet::with_capacity(methods.len());
    for method in methods {
        validate_verification_method(method)?;
        let canonical = canonical_verification_method_id(doc_id, &method.id);
        if !seen.insert(canonical) {
            return Err(DidError::DuplicateVerificationMethodId(method.id.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_accepts_valid_verification_method() {
        let vm = VerificationMethod::new(
            "did:stellar:testnet:GABC#key-1",
            "Ed25519VerificationKey2020",
            "did:stellar:testnet:GABC",
        )
        .unwrap()
        .with_public_key_multibase("z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH");

        assert_eq!(vm.id, "did:stellar:testnet:GABC#key-1");
        assert_eq!(vm.method_type, "Ed25519VerificationKey2020");
        assert_eq!(vm.controller, "did:stellar:testnet:GABC");
        assert!(vm.public_key_multibase.is_some());
    }

    #[test]
    fn new_rejects_empty_fields() {
        assert!(matches!(
            VerificationMethod::new("", "Ed25519VerificationKey2020", "did:stellar:testnet:GABC"),
            Err(DidError::EmptyVerificationMethodId)
        ));
        assert!(matches!(
            VerificationMethod::new(
                "   ",
                "Ed25519VerificationKey2020",
                "did:stellar:testnet:GABC"
            ),
            Err(DidError::EmptyVerificationMethodId)
        ));
        assert!(matches!(
            VerificationMethod::new(
                "did:stellar:testnet:GABC#key-1",
                " ",
                "did:stellar:testnet:GABC"
            ),
            Err(DidError::EmptyVerificationMethodType)
        ));
        assert!(matches!(
            VerificationMethod::new(
                "did:stellar:testnet:GABC#key-1",
                "Ed25519VerificationKey2020",
                ""
            ),
            Err(DidError::EmptyVerificationMethodController)
        ));
    }

    #[test]
    fn new_rejects_whitespace_padded_or_bare_fragment_id() {
        assert!(matches!(
            VerificationMethod::new(
                " #key-1",
                "Ed25519VerificationKey2020",
                "did:stellar:testnet:GABC"
            ),
            Err(DidError::InvalidVerificationMethodId { .. })
        ));
        assert!(matches!(
            VerificationMethod::new(
                "#",
                "Ed25519VerificationKey2020",
                "did:stellar:testnet:GABC"
            ),
            Err(DidError::InvalidVerificationMethodId { .. })
        ));
    }

    #[test]
    fn canonical_id_expands_relative_fragment() {
        assert_eq!(
            canonical_verification_method_id("did:stellar:testnet:GABC", "#key-1"),
            "did:stellar:testnet:GABC#key-1"
        );
        assert_eq!(
            canonical_verification_method_id(
                "did:stellar:testnet:GABC",
                "did:stellar:testnet:GABC#key-1"
            ),
            "did:stellar:testnet:GABC#key-1"
        );
    }

    #[test]
    fn ensure_unique_rejects_relative_and_absolute_collision() {
        let m1 = VerificationMethod::new(
            "#key-1",
            "Ed25519VerificationKey2020",
            "did:stellar:testnet:GABC",
        )
        .unwrap();
        let m2 = VerificationMethod::new(
            "did:stellar:testnet:GABC#key-1",
            "Ed25519VerificationKey2020",
            "did:stellar:testnet:GABC",
        )
        .unwrap();

        let err =
            ensure_unique_verification_methods("did:stellar:testnet:GABC", &[m1, m2]).unwrap_err();
        assert!(matches!(err, DidError::DuplicateVerificationMethodId(_)));
    }
}

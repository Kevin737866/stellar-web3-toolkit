//! DID document resolution with unknown property preservation (issue #344).
//!
//! Per the [W3C DID Core specification](https://www.w3.org/TR/did-core/),
//! DID documents are extensible JSON-LD / JSON objects that may carry
//! standard properties (`@context`, `alsoKnownAs`, `controller`,
//! `verificationMethod`, `authentication`, `assertionMethod`, etc.) as well as
//! method-specific or application-specific extension fields.
//!
//! [`DidResolver`] parses and validates resolved DID documents while
//! preserving all unknown top-level properties in
//! [`DidDocument::additional_properties`]. Because `additional_properties` is
//! backed by a [`std::collections::BTreeMap`], re-serializing a resolved
//! document produces deterministic key ordering across resolver responses.
//!
//! # Invariants enforced
//!
//! - The requested DID must conform to `did:<method>:<method-specific-id>`.
//! - The resolved payload must be a valid JSON object representing a
//!   [`DidDocument`].
//! - The document's `id` must match the requested DID.
//! - All service endpoints must pass the URI scheme allowlist and have unique
//!   IDs.

use crate::service::{validate_did, DidDocument, DidError};

/// Stateless DID document resolver that validates DID Core invariants while
/// preserving unknown top-level DID document properties.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DidResolver;

impl DidResolver {
    /// Create a new [`DidResolver`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Resolve a DID from its raw JSON document representation.
    ///
    /// Unknown top-level properties (such as `@context`, `alsoKnownAs`,
    /// `verificationMethod`, `authentication`, or custom extension fields) are
    /// preserved in [`DidDocument::additional_properties`].
    ///
    /// # Errors
    ///
    /// * [`DidError::InvalidDid`] — `did` or the document's `id` is malformed.
    /// * [`DidError::InvalidDocumentJson`] — `raw_json` is not valid JSON or
    ///   not a JSON object.
    /// * [`DidError::DidMismatch`] — the document's `id` does not match `did`.
    /// * [`DidError::InvalidScheme`] / [`DidError::InvalidUri`] /
    ///   [`DidError::DuplicateServiceId`] / [`DidError::EmptyServiceId`] /
    ///   [`DidError::EmptyServiceType`] — a service entry failed validation.
    pub fn resolve_json(&self, did: &str, raw_json: &str) -> Result<DidDocument, DidError> {
        validate_did(did)?;
        let doc = DidDocument::from_json(raw_json)?;
        if doc.id != did {
            return Err(DidError::DidMismatch {
                expected: did.to_string(),
                actual: doc.id,
            });
        }
        Ok(doc)
    }

    /// Resolve a DID from a pre-parsed [`serde_json::Value`].
    ///
    /// Unknown top-level properties are preserved in
    /// [`DidDocument::additional_properties`].
    pub fn resolve_value(
        &self,
        did: &str,
        value: serde_json::Value,
    ) -> Result<DidDocument, DidError> {
        validate_did(did)?;
        if !value.is_object() {
            return Err(DidError::InvalidDocumentJson {
                reason: "DID document must be a JSON object".to_string(),
            });
        }
        let doc: DidDocument =
            serde_json::from_value(value).map_err(|e| DidError::InvalidDocumentJson {
                reason: e.to_string(),
            })?;
        doc.validate()?;
        if doc.id != did {
            return Err(DidError::DidMismatch {
                expected: did.to_string(),
                actual: doc.id,
            });
        }
        Ok(doc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const VALID_DID: &str = "did:stellar:testnet:GABC123";

    #[test]
    fn resolve_json_preserves_unknown_properties() {
        let raw = r#"{
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:stellar:testnet:GABC123",
            "alsoKnownAs": ["https://alice.example.com"],
            "controller": "did:stellar:testnet:GCTRL",
            "verificationMethod": [
                {
                    "id": "did:stellar:testnet:GABC123#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "did:stellar:testnet:GABC123"
                }
            ],
            "customExtension": { "version": 2, "enabled": true },
            "service": []
        }"#;

        let resolver = DidResolver::new();
        let doc = resolver.resolve_json(VALID_DID, raw).unwrap();

        assert_eq!(doc.id, VALID_DID);
        assert_eq!(
            doc.get_property("@context"),
            Some(&json!(["https://www.w3.org/ns/did/v1"]))
        );
        assert_eq!(
            doc.get_property("alsoKnownAs"),
            Some(&json!(["https://alice.example.com"]))
        );
        assert_eq!(
            doc.get_property("controller"),
            Some(&json!("did:stellar:testnet:GCTRL"))
        );
        assert!(doc.get_property("verificationMethod").is_some());
        assert_eq!(
            doc.get_property("customExtension"),
            Some(&json!({ "version": 2, "enabled": true }))
        );
    }

    #[test]
    fn resolve_json_produces_deterministic_output() {
        let raw_a = r#"{
            "zProp": 1,
            "id": "did:stellar:testnet:GABC123",
            "aProp": 2,
            "mProp": { "b": 2, "a": 1 }
        }"#;
        let raw_b = r#"{
            "aProp": 2,
            "mProp": { "a": 1, "b": 2 },
            "id": "did:stellar:testnet:GABC123",
            "zProp": 1
        }"#;

        let resolver = DidResolver::new();
        let doc_a = resolver.resolve_json(VALID_DID, raw_a).unwrap();
        let doc_b = resolver.resolve_json(VALID_DID, raw_b).unwrap();

        assert_eq!(doc_a.to_json().unwrap(), doc_b.to_json().unwrap());
    }

    #[test]
    fn resolve_json_rejects_mismatched_did() {
        let raw = r#"{"id": "did:stellar:testnet:GOTHER"}"#;
        let err = DidResolver::new().resolve_json(VALID_DID, raw).unwrap_err();
        assert!(matches!(
            err,
            DidError::DidMismatch { ref expected, ref actual }
                if expected == VALID_DID && actual == "did:stellar:testnet:GOTHER"
        ));
    }

    #[test]
    fn resolve_json_rejects_invalid_did_argument() {
        let raw = r#"{"id": "did:stellar:testnet:GABC123"}"#;
        let err = DidResolver::new()
            .resolve_json("not-a-did", raw)
            .unwrap_err();
        assert!(matches!(err, DidError::InvalidDid { .. }));
    }

    #[test]
    fn resolve_json_rejects_non_object_json() {
        let err = DidResolver::new()
            .resolve_json(VALID_DID, r#"["not", "an", "object"]"#)
            .unwrap_err();
        assert!(matches!(err, DidError::InvalidDocumentJson { .. }));
    }

    #[test]
    fn resolve_json_rejects_disallowed_service_scheme() {
        let raw = r#"{
            "id": "did:stellar:testnet:GABC123",
            "custom": "kept-only-on-success",
            "service": [{
                "id": "did:stellar:testnet:GABC123#bad",
                "service_type": "LinkedDomains",
                "service_endpoint": "javascript:alert(1)"
            }]
        }"#;
        let err = DidResolver::new().resolve_json(VALID_DID, raw).unwrap_err();
        assert!(matches!(err, DidError::InvalidScheme { .. }));
    }

    #[test]
    fn resolve_value_preserves_unknown_properties() {
        let val = json!({
            "id": VALID_DID,
            "@context": "https://www.w3.org/ns/did/v1",
            "authentication": ["did:stellar:testnet:GABC123#key-1"]
        });
        let doc = DidResolver::new().resolve_value(VALID_DID, val).unwrap();
        assert_eq!(
            doc.get_property("authentication"),
            Some(&json!(["did:stellar:testnet:GABC123#key-1"]))
        );
    }
}

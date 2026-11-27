//! DID Core serialization conformance for `did:stellar` documents (issue #347).
//!
//! The legacy `serde` representation of [`DidDocument`] is kept unchanged so
//! existing callers are not broken. This module adds an explicit conformance
//! surface that emits the shape required by
//! [DID Core](https://www.w3.org/TR/did-core/):
//!
//! * `@context` is `https://www.w3.org/ns/did/v1`.
//! * `service[].type` and `service[].serviceEndpoint` use the specification's
//!   field names rather than the Rust field names.
//! * extension properties are flattened into their service object.
//! * JSON object keys are emitted in a stable order, so a resolver response for
//!   the same document is byte-for-byte identical on every machine.
//!
//! Construction is validation: [`to_core_value`], [`to_json`], and
//! [`resolution_json`] reject a document instead of silently repairing it. A
//! rejected document is never partially serialized because these functions do
//! not mutate their input.

use crate::service::{DidDocument, DidError, ServiceEndpoint};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use thiserror::Error;

/// JSON-LD context every conformant DID document and resolution result carries.
pub const DID_CORE_CONTEXT: &str = "https://www.w3.org/ns/did/v1";

/// Service-object keys that callers may not override through extension properties.
pub const RESERVED_SERVICE_PROPERTIES: &[&str] = &["id", "serviceEndpoint", "type"];

/// A DID document that cannot be represented as DID Core JSON.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConformanceError {
    /// The document `id` is not a syntactically valid DID.
    #[error("DID document id `{id}` is not a valid DID")]
    InvalidDidId {
        /// The rejected identifier.
        id: String,
    },
    /// A service id is neither the subject DID nor one of its DID URLs.
    #[error("service at index {index} (`{id}`) is not scoped to subject `{subject}`")]
    ServiceIdNotScopedToSubject {
        /// Position of the service in the `service` array.
        index: usize,
        /// The rejected service id.
        id: String,
        /// The document subject the service must be scoped to.
        subject: String,
    },
    /// Two services share the same id.
    #[error("duplicate service id `{id}` at index {index}")]
    DuplicateServiceId {
        /// Position of the duplicate service.
        index: usize,
        /// The duplicated id.
        id: String,
    },
    /// A service `type` is empty or whitespace-only.
    #[error("service at index {index} has an empty type")]
    EmptyServiceType {
        /// Position of the service in the `service` array.
        index: usize,
    },
    /// A service endpoint fails the scheme allowlist or URI parser.
    #[error("service at index {index} (`{id}`) has an invalid endpoint: {source}")]
    InvalidServiceEndpoint {
        /// Position of the service in the `service` array.
        index: usize,
        /// The service whose endpoint was rejected.
        id: String,
        /// The underlying endpoint validation error.
        #[source]
        source: DidError,
    },
    /// An extension property would shadow a required DID Core field.
    #[error("service at index {index} (`{id}`) defines reserved property `{key}`")]
    ReservedProperty {
        /// Position of the service in the `service` array.
        index: usize,
        /// The service carrying the reserved property.
        id: String,
        /// The reserved property name.
        key: String,
    },
    /// Serializing the validated JSON value failed.
    #[error("DID Core serialization failed: {reason}")]
    SerializationFailed {
        /// Reason reported by the JSON serializer.
        reason: String,
    },
}

fn is_valid_did(id: &str) -> bool {
    let mut parts = id.split(':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("did"), Some(method), Some(method_specific_id))
            if !method.is_empty()
                && method
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                && !method_specific_id.is_empty()
                && !id.chars().any(char::is_whitespace) =>
        {
            method_specific_id
                .split(':')
                .all(|segment| !segment.is_empty())
        }
        _ => false,
    }
}

fn is_scoped_service_id(id: &str, subject: &str) -> bool {
    if id == subject {
        return true;
    }
    if let Some(fragment) = id.strip_prefix(subject) {
        return fragment.starts_with('#') && fragment.len() > 1;
    }
    if let Some(fragment) = id.strip_prefix('#') {
        return !fragment.is_empty();
    }
    false
}

/// Validate `doc` without serializing it.
///
/// # Errors
///
/// Returns a [`ConformanceError`] describing the first DID Core violation.
/// The document is never modified.
pub fn validate(doc: &DidDocument) -> Result<(), ConformanceError> {
    if !is_valid_did(&doc.id) {
        return Err(ConformanceError::InvalidDidId { id: doc.id.clone() });
    }

    let mut seen = BTreeSet::new();
    for (index, service) in doc.service.iter().enumerate() {
        if !is_scoped_service_id(&service.id, &doc.id) {
            return Err(ConformanceError::ServiceIdNotScopedToSubject {
                index,
                id: service.id.clone(),
                subject: doc.id.clone(),
            });
        }
        if !seen.insert(service.id.as_str()) {
            return Err(ConformanceError::DuplicateServiceId {
                index,
                id: service.id.clone(),
            });
        }
        if service.service_type.trim().is_empty() {
            return Err(ConformanceError::EmptyServiceType { index });
        }
        ServiceEndpoint::uri(service.service_endpoint.as_str()).map_err(|source| {
            ConformanceError::InvalidServiceEndpoint {
                index,
                id: service.id.clone(),
                source,
            }
        })?;
        for key in service.properties.keys() {
            if RESERVED_SERVICE_PROPERTIES.contains(&key.as_str()) {
                return Err(ConformanceError::ReservedProperty {
                    index,
                    id: service.id.clone(),
                    key: key.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Convert `doc` to a DID Core JSON value.
///
/// Object keys are emitted in sorted order because `serde_json::Map` is a
/// `BTreeMap` in this workspace, which makes resolver output deterministic.
///
/// # Errors
///
/// Returns a [`ConformanceError`] when the document violates DID Core. No
/// defaults are substituted for a missing or invalid field.
pub fn to_core_value(doc: &DidDocument) -> Result<Value, ConformanceError> {
    validate(doc)?;

    let mut root = Map::new();
    root.insert(
        "@context".to_string(),
        Value::String(DID_CORE_CONTEXT.to_string()),
    );
    root.insert("id".to_string(), Value::String(doc.id.clone()));

    if !doc.service.is_empty() {
        let mut services = Vec::with_capacity(doc.service.len());
        for service in &doc.service {
            let mut object = Map::new();
            object.insert("id".to_string(), Value::String(service.id.clone()));
            object.insert(
                "serviceEndpoint".to_string(),
                Value::String(service.service_endpoint.as_str().to_string()),
            );
            object.insert(
                "type".to_string(),
                Value::String(service.service_type.clone()),
            );
            for (key, value) in &service.properties {
                object.insert(key.clone(), value.clone());
            }
            services.push(Value::Object(object));
        }
        root.insert("service".to_string(), Value::Array(services));
    }

    Ok(Value::Object(root))
}

fn to_stable_string(value: Value) -> Result<String, ConformanceError> {
    serde_json::to_string(&value).map_err(|error| ConformanceError::SerializationFailed {
        reason: error.to_string(),
    })
}

/// Serialize `doc` as a compact, deterministic DID Core JSON document.
///
/// # Errors
///
/// Returns a [`ConformanceError`] when the document violates DID Core or JSON
/// serialization fails.
pub fn to_json(doc: &DidDocument) -> Result<String, ConformanceError> {
    to_stable_string(to_core_value(doc)?)
}

/// Build a complete DID resolution result with empty, stable metadata.
///
/// # Errors
///
/// Returns a [`ConformanceError`] when the document violates DID Core.
pub fn to_resolution_value(doc: &DidDocument) -> Result<Value, ConformanceError> {
    let mut root = Map::new();
    root.insert(
        "@context".to_string(),
        Value::String(DID_CORE_CONTEXT.to_string()),
    );
    root.insert("didDocument".to_string(), to_core_value(doc)?);
    root.insert("didDocumentMetadata".to_string(), Value::Object(Map::new()));
    root.insert(
        "didResolutionMetadata".to_string(),
        Value::Object(Map::new()),
    );
    Ok(Value::Object(root))
}

/// Serialize a complete DID resolution result as stable JSON.
///
/// # Errors
///
/// Returns a [`ConformanceError`] when the document violates DID Core or JSON
/// serialization fails.
pub fn resolution_json(doc: &DidDocument) -> Result<String, ConformanceError> {
    to_stable_string(to_resolution_value(doc)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::Service;
    use serde_json::json;

    const MINIMAL: &str = include_str!("../fixtures/minimal.json");
    const WITH_SERVICE: &str = include_str!("../fixtures/with_service.json");
    const WITH_EXTENSION: &str = include_str!("../fixtures/with_extension.json");
    const RESOLUTION: &str = include_str!("../fixtures/resolution.json");

    fn fixture(name: &str) -> String {
        name.trim().to_string()
    }

    fn sample_document() -> DidDocument {
        let endpoint = ServiceEndpoint::uri("https://hub.example.com").expect("valid endpoint");
        let service = Service::new("did:stellar:testnet:GABC#hub", "LinkedDomains", endpoint)
            .expect("valid service");
        let mut doc = DidDocument::new("did:stellar:testnet:GABC");
        doc.add_service(service).expect("valid add");
        doc
    }

    #[test]
    fn minimal_document_matches_fixture() {
        let doc = DidDocument::new("did:stellar:testnet:GABC");
        assert_eq!(to_json(&doc).expect("conformant"), fixture(MINIMAL));
    }

    #[test]
    fn service_document_matches_fixture() {
        assert_eq!(
            to_json(&sample_document()).expect("conformant"),
            fixture(WITH_SERVICE)
        );
    }

    #[test]
    fn extension_properties_are_flattened_and_stable() {
        let mut doc = sample_document();
        doc.service[0].service_type = "IdentityHub".to_string();
        doc.service[0].properties.insert(
            "routingKeys".to_string(),
            json!(["did:stellar:testnet:GABC#key-1"]),
        );
        doc.service[0].properties.insert(
            "accept".to_string(),
            json!(["application/didcomm-msg+json"]),
        );

        let expected = fixture(WITH_EXTENSION);
        assert_eq!(to_json(&doc).expect("conformant"), expected);

        let mut reordered = doc.clone();
        reordered.service[0].properties = serde_json::from_value(json!({
            "accept": ["application/didcomm-msg+json"],
            "routingKeys": ["did:stellar:testnet:GABC#key-1"]
        }))
        .expect("properties");
        assert_eq!(to_json(&reordered).expect("conformant"), expected);
    }

    #[test]
    fn resolution_result_matches_fixture_and_is_repeatable() {
        let doc = sample_document();
        let first = resolution_json(&doc).expect("conformant resolution");
        let second = resolution_json(&doc).expect("conformant resolution");
        assert_eq!(first, fixture(RESOLUTION));
        assert_eq!(first, second);
    }

    #[test]
    fn malformed_dids_are_rejected_without_a_default() {
        for id in [
            "",
            "stellar:testnet:GABC",
            "did::GABC",
            "did:stellar:",
            "did:STELLAR:GABC",
            "did:stellar:test net:GABC",
        ] {
            let doc = DidDocument::new(id);
            let error = to_json(&doc).expect_err("invalid DID must be rejected");
            assert!(
                matches!(error, ConformanceError::InvalidDidId { .. }),
                "{error:?}"
            );
        }
    }

    #[test]
    fn generic_did_methods_are_accepted() {
        let doc = DidDocument::new("did:example:123456789abcdefghi");
        assert!(to_json(&doc).is_ok());
    }

    #[test]
    fn relative_service_ids_are_accepted() {
        let mut doc = DidDocument::new("did:stellar:testnet:GABC");
        let endpoint = ServiceEndpoint::uri("https://hub.example.com").expect("valid endpoint");
        doc.add_service(Service::new("#hub", "LinkedDomains", endpoint).expect("valid service"))
            .expect("valid add");
        assert!(to_json(&doc).is_ok());
    }

    #[test]
    fn duplicate_and_unscoped_service_ids_are_rejected() {
        let mut doc = DidDocument::new("did:stellar:testnet:GABC");
        let first = ServiceEndpoint::uri("https://one.example.com").expect("valid endpoint");
        let second = ServiceEndpoint::uri("https://two.example.com").expect("valid endpoint");
        doc.add_service(
            Service::new("did:stellar:testnet:GABC#hub", "LinkedDomains", first)
                .expect("valid service"),
        )
        .expect("valid add");
        doc.service.push(
            Service::new("did:stellar:testnet:GABC#hub", "LinkedDomains", second)
                .expect("valid service"),
        );

        let duplicate = to_json(&doc).expect_err("duplicate must be rejected");
        assert!(
            matches!(
                duplicate,
                ConformanceError::DuplicateServiceId { index: 1, .. }
            ),
            "{duplicate:?}"
        );

        doc.service[1].id = "did:stellar:mainnet:GABC#hub".to_string();
        let unscoped = to_json(&doc).expect_err("unscoped id must be rejected");
        assert!(
            matches!(
                unscoped,
                ConformanceError::ServiceIdNotScopedToSubject { index: 1, .. }
            ),
            "{unscoped:?}"
        );
    }

    #[test]
    fn deserialized_documents_are_validated_before_serialization() {
        let doc: DidDocument = serde_json::from_value(json!({
            "id": "did:stellar:testnet:GABC",
            "service": [{
                "id": "did:stellar:testnet:GABC#bad",
                "service_type": "Malicious",
                "service_endpoint": "javascript:alert(1)",
                "properties": {}
            }]
        }))
        .expect("deserialize untrusted document");

        let error = to_json(&doc).expect_err("unsafe endpoint must be rejected");
        assert!(
            matches!(
                error,
                ConformanceError::InvalidServiceEndpoint { index: 0, .. }
            ),
            "{error:?}"
        );
        assert!(error.to_string().contains("javascript"));
    }

    #[test]
    fn reserved_extension_properties_are_rejected() {
        let mut doc = sample_document();
        doc.service[0]
            .properties
            .insert("type".to_string(), json!("Spoofed"));
        let error = to_json(&doc).expect_err("reserved key must be rejected");
        assert!(
            matches!(error, ConformanceError::ReservedProperty { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn empty_service_type_is_rejected() {
        let mut doc = sample_document();
        doc.service[0].service_type = "   ".to_string();
        let error = to_json(&doc).expect_err("empty type must be rejected");
        assert!(
            matches!(error, ConformanceError::EmptyServiceType { index: 0 }),
            "{error:?}"
        );
    }

    #[test]
    fn legacy_serialization_is_unchanged() {
        let doc = sample_document();
        let legacy = serde_json::to_value(&doc).expect("legacy shape");
        assert_eq!(legacy["service"][0]["service_type"], json!("LinkedDomains"));
        assert!(legacy.get("@context").is_none());
    }
}

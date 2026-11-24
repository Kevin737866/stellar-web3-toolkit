//! Integration tests for DID document id validation against the configured
//! method (issue #338).
//!
//! These exercise the full create → publish → resolve workflow, including the
//! resolver-side rejection of a document that declares a foreign method.

use stellar_did::{
    validate_did_id, DidDocument, DidError, DidMethodConfig, Service, ServiceEndpoint,
};

fn configured_method() -> DidMethodConfig {
    DidMethodConfig::default()
}

#[test]
fn create_publish_and_resolve_a_valid_document() {
    let config = configured_method();
    let did = "did:stellar:testnet:GABCDEF";

    let validated = validate_did_id(did, &config).expect("canonical stellar DID");
    assert_eq!(validated.as_str(), did);

    let mut document = DidDocument::try_new(did, &config).expect("valid document id");
    let endpoint = ServiceEndpoint::uri("https://hub.example.com").expect("valid endpoint");
    let service = Service::new(format!("{did}#hub"), "IdentityHub", endpoint).expect("service");
    document.add_service(service).expect("add service");

    let published = serde_json::to_string(&document).expect("serialize document");
    let resolved = DidDocument::from_json_str(&published, &config).expect("resolve document");

    assert_eq!(resolved.id, did);
    assert_eq!(
        resolved
            .validate_id(&config)
            .expect("id still valid")
            .as_str(),
        did
    );
    assert_eq!(resolved.service.len(), 1);
    assert_eq!(
        resolved.service[0].service_endpoint.as_str(),
        "https://hub.example.com"
    );
}

#[test]
fn resolver_gives_a_stable_rejection_for_a_foreign_method() {
    let config = configured_method();
    let stored = r#"{"id":"did:example:alice","service":[]}"#;

    let first = DidDocument::from_json_str(stored, &config).unwrap_err();
    let second = DidDocument::from_json_str(stored, &config).unwrap_err();
    assert_eq!(
        first, second,
        "the resolver response must not vary between calls"
    );
    assert!(
        matches!(first, DidError::MethodMismatch { .. }),
        "unexpected error: {first:?}"
    );

    // The same document is valid when the resolver is explicitly configured
    // for the method it declares.
    let other_config = DidMethodConfig::new("example").expect("valid method name");
    let accepted = DidDocument::from_json_str(stored, &other_config).expect("configured method");
    assert_eq!(accepted.id, "did:example:alice");
}

#[test]
fn malformed_ids_are_rejected_at_every_entry_point() {
    let config = configured_method();
    for id in [
        "did:stellar:testnet:GABC#key-1",
        "did:stellar:",
        "did:STELLAR:testnet:GABC",
        "not-a-did",
    ] {
        assert!(validate_did_id(id, &config).is_err(), "id: {id}");
        assert!(DidDocument::try_new(id, &config).is_err(), "id: {id}");

        let stored = DidDocument::new(id);
        assert!(stored.validate_id(&config).is_err(), "id: {id}");
    }
}

#[test]
fn unsafe_endpoint_is_rejected_even_when_the_id_is_valid() {
    let config = configured_method();
    let stored = r#"{
        "id": "did:stellar:testnet:GABCDEF",
        "service": [{
            "id": "did:stellar:testnet:GABCDEF#bad",
            "service_type": "Bad",
            "service_endpoint": "javascript:alert(1)"
        }]
    }"#;

    let err = DidDocument::from_json_str(stored, &config).unwrap_err();
    assert!(
        matches!(err, DidError::InvalidScheme { .. }),
        "unexpected error: {err:?}"
    );
}

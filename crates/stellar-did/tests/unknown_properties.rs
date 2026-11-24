//! Integration tests for preserving unknown DID document properties during
//! resolution and round-trip serialization (issue #344).

use serde_json::json;
use stellar_did::{DidDocument, DidError, DidResolver, Service, ServiceEndpoint};

#[test]
fn resolve_and_round_trip_preserves_standard_and_custom_properties() {
    let did = "did:stellar:public:GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ";
    let raw_document = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": did,
        "alsoKnownAs": ["https://stellar.org"],
        "controller": did,
        "verificationMethod": [
            {
                "id": format!("{did}#key-1"),
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
            }
        ],
        "authentication": [format!("{did}#key-1")],
        "assertionMethod": [format!("{did}#key-1")],
        "stellarNetwork": {
            "passphrase": "Public Global Stellar Network ; September 2015",
            "horizon": "https://horizon.stellar.org"
        },
        "service": [
            {
                "id": format!("{did}#hub"),
                "service_type": "IdentityHub",
                "service_endpoint": "https://hub.example.com"
            }
        ]
    });

    let resolver = DidResolver::new();
    let mut doc = resolver
        .resolve_json(did, &raw_document.to_string())
        .expect("valid DID document should resolve");

    // Unknown properties are accessible and preserved.
    assert_eq!(doc.get_property("@context"), raw_document.get("@context"));
    assert_eq!(
        doc.get_property("alsoKnownAs"),
        raw_document.get("alsoKnownAs")
    );
    assert_eq!(
        doc.get_property("stellarNetwork"),
        raw_document.get("stellarNetwork")
    );

    // Mutating services preserves unknown properties.
    let extra_ep = ServiceEndpoint::uri("https://messaging.example.com").unwrap();
    let extra_svc = Service::new(format!("{did}#msg"), "Messaging", extra_ep).unwrap();
    doc.add_service(extra_svc).unwrap();

    // Round-trip serialization retains every unknown property alongside services.
    let reserialized = doc.to_json().unwrap();
    let re_resolved = resolver.resolve_json(did, &reserialized).unwrap();

    assert_eq!(re_resolved.service.len(), 2);
    assert_eq!(
        re_resolved.get_property("verificationMethod"),
        raw_document.get("verificationMethod")
    );
    assert_eq!(
        re_resolved.get_property("stellarNetwork"),
        raw_document.get("stellarNetwork")
    );
}

#[test]
fn reserved_property_rejection_leaves_document_unchanged() {
    let did = "did:stellar:testnet:GABC123";
    let mut doc = DidDocument::new(did);
    doc.set_property("customFlag", json!(true)).unwrap();

    let err = doc.set_property("id", json!("did:stellar:testnet:GEVIL")).unwrap_err();
    assert!(matches!(err, DidError::ReservedProperty(ref k) if k == "id"));
    assert_eq!(doc.id, did);
    assert_eq!(doc.get_property("customFlag"), Some(&json!(true)));
}

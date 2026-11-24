//! Integration tests for rejecting duplicate verification-method identifiers
//! in DID documents (issue #339).

use stellar_did::{DidDocument, DidError, Service, ServiceEndpoint, VerificationMethod};

#[test]
fn did_document_workflow_enforces_unique_verification_method_ids() {
    let did = "did:stellar:testnet:GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    let mut doc = DidDocument::new(did);

    let key1 = VerificationMethod::new(format!("{did}#key-1"), "Ed25519VerificationKey2020", did)
        .unwrap()
        .with_public_key_multibase("z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH");
    let key2 = VerificationMethod::new("#key-2", "JsonWebKey2020", did).unwrap();

    doc.add_verification_method(key1).unwrap();
    doc.add_verification_method(key2).unwrap();
    doc.add_service(
        Service::new(
            format!("{did}#hub"),
            "IdentityHub",
            ServiceEndpoint::uri("https://hub.example.com").unwrap(),
        )
        .unwrap(),
    )
    .unwrap();

    // Attempting to add a duplicate (both absolute and relative forms) fails
    // without mutating the document.
    let dup_abs =
        VerificationMethod::new(format!("{did}#key-2"), "Ed25519VerificationKey2020", did).unwrap();
    assert!(matches!(
        doc.add_verification_method(dup_abs),
        Err(DidError::DuplicateVerificationMethodId(_))
    ));
    assert_eq!(doc.verification_method.len(), 2);

    // Valid document round-trips through JSON and passes validation.
    let json = serde_json::to_string(&doc).unwrap();
    let parsed = DidDocument::from_json(&json).unwrap();
    assert_eq!(parsed.verification_method.len(), 2);
    assert_eq!(parsed.service.len(), 1);
}

#[test]
fn untrusted_did_document_json_with_duplicate_verification_methods_is_rejected() {
    let raw = r#"{
        "id": "did:stellar:public:GABC",
        "verificationMethod": [
            {
                "id": "did:stellar:public:GABC#auth",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:stellar:public:GABC",
                "publicKeyMultibase": "z111"
            },
            {
                "id": "did:stellar:public:GABC#auth",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:stellar:public:GABC",
                "publicKeyMultibase": "z222"
            }
        ]
    }"#;

    let err = DidDocument::from_json(raw).unwrap_err();
    assert!(matches!(err, DidError::DuplicateVerificationMethodId(_)));
}

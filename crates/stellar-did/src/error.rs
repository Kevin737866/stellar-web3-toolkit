//! Error types shared by the DID document and DID identifier APIs.
//!
//! Keeping the errors in one module means a caller can handle every failure
//! from document creation, identifier validation and document resolution
//! through a single [`DidError`] type.

use thiserror::Error;

/// Errors that can occur in DID identifier, document and service operations.
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

    /// The DID identifier does not follow DID Core syntax.
    ///
    /// `input` is the rejected identifier and `reason` names the exact rule
    /// that failed, so a resolver can report the problem without echoing
    /// arbitrary document contents.
    #[error("invalid DID `{input}`: {reason}")]
    InvalidDid { input: String, reason: String },

    /// The DID's method does not match the method the resolver is configured
    /// to serve.
    #[error("DID `{input}` uses method `{actual}`, but the configured method is `{expected}`")]
    MethodMismatch {
        input: String,
        expected: String,
        actual: String,
    },

    /// A configured DID method name is not a valid DID Core `method-name`.
    #[error("invalid DID method name `{method}`: {reason}")]
    InvalidMethodName { method: String, reason: String },

    /// A serialized DID document could not be parsed.
    #[error("invalid DID document: {reason}")]
    InvalidDocument { reason: String },
}

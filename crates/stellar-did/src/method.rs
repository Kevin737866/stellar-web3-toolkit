//! DID identifier validation against the configured DID method (issue #338).
//!
//! A DID document's `id` property must be a **DID**, not a DID URL, and it must
//! belong to the method the resolver is configured to serve. Without that
//! check a document stored under `did:stellar:...` could be resolved with an
//! unrelated method in its `id`, giving callers an unstable answer: the same
//! request would sometimes return a document, sometimes a resolution error.
//!
//! This module validates the identifier before a document is created or
//! returned from a resolver. Validation follows the DID Core 1.0 ABNF:
//!
//! ```text
//! did                = "did:" method-name ":" method-specific-id
//! method-name        = 1*method-char
//! method-char        = %x61-7A / DIGIT          ; lowercase a-z, 0-9
//! method-specific-id = *( *idchar ":" ) 1*idchar
//! idchar             = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
//! pct-encoded        = "%" HEXDIG HEXDIG
//! ```
//!
//! On top of that syntax, [`DidMethodConfig`] names the single method a
//! resolver accepts. The default is `stellar`, matching the method implemented
//! by this crate; constructing a config with another valid method name is
//! supported so a resolver can be pointed at a different method explicitly.
//! Empty segments in the method-specific id are rejected even though the ABNF
//! technically permits them, because they are ambiguous and have no legitimate
//! use in this method.
//!
//! # Examples
//!
//! ```rust
//! use stellar_did::{validate_did_id, DidMethodConfig, DidError};
//!
//! let config = DidMethodConfig::default();
//! assert_eq!(config.method(), "stellar");
//! assert!(validate_did_id("did:stellar:testnet:GABC", &config).is_ok());
//! assert!(matches!(
//!     validate_did_id("did:example:alice", &config),
//!     Err(DidError::MethodMismatch { .. })
//! ));
//! ```
//!
//! # Compatibility
//!
//! Validation is opt-in for existing callers: [`DidDocument::new`](crate::DidDocument::new)
//! and direct struct construction are unchanged. Use
//! [`DidDocument::try_new`](crate::DidDocument::try_new) when creating a
//! document from untrusted input, and
//! [`DidDocument::from_json_str`](crate::DidDocument::from_json_str) when
//! parsing a document returned by a resolver or loaded from storage.

use crate::error::DidError;
use std::fmt;

/// The DID method implemented by this crate and used by [`DidMethodConfig::default`].
pub const DEFAULT_METHOD: &str = "stellar";

/// The method name a resolver accepts.
///
/// A config is the single place that decides which method a DID document must
/// declare. It is deliberately explicit: there is no environment-variable
/// fallback, so a misconfigured method fails at construction instead of
/// silently accepting documents from a different method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidMethodConfig {
    method: String,
}

impl DidMethodConfig {
    /// Configure a resolver for `method`.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::InvalidMethodName`] when `method` is empty or
    /// contains anything other than lowercase ASCII letters and digits, as
    /// required by DID Core `method-char`.
    pub fn new(method: impl Into<String>) -> Result<Self, DidError> {
        let method = method.into();
        validate_method_name(&method)?;
        Ok(Self { method })
    }

    /// The configured method name.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }
}

impl Default for DidMethodConfig {
    fn default() -> Self {
        Self {
            method: DEFAULT_METHOD.to_string(),
        }
    }
}

/// A DID identifier that has passed DID Core and configured-method validation.
///
/// The type has no public constructor, so holding one is proof that the string
/// was checked at some point. It stores the original identifier verbatim —
/// validation never rewrites or normalizes caller input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDidId {
    id: String,
    method_specific_id: String,
}

impl ValidatedDidId {
    /// The validated DID string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.id
    }

    /// The `method-specific-id` segment of the DID.
    #[must_use]
    pub fn method_specific_id(&self) -> &str {
        &self.method_specific_id
    }
}

impl fmt::Display for ValidatedDidId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.id)
    }
}

impl AsRef<str> for ValidatedDidId {
    fn as_ref(&self) -> &str {
        &self.id
    }
}

/// Validate `input` as a DID belonging to the configured method.
///
/// The input is rejected — never rewritten — when it is empty, does not start
/// with `did:`, has no method separator, uses a malformed method name or
/// method-specific id, contains DID URL components (`#`, `?`, `/`), or names a
/// method other than the configured one.
///
/// # Errors
///
/// * [`DidError::InvalidDid`] for malformed DID Core syntax.
/// * [`DidError::MethodMismatch`] when the DID is well formed but declares a
///   different method than `config`.
pub fn validate_did_id(input: &str, config: &DidMethodConfig) -> Result<ValidatedDidId, DidError> {
    let invalid = |reason: &str| DidError::InvalidDid {
        input: input.to_string(),
        reason: reason.to_string(),
    };

    if input.is_empty() {
        return Err(invalid("DID must not be empty"));
    }

    let rest = input
        .strip_prefix("did:")
        .ok_or_else(|| invalid("DID must start with `did:`"))?;
    let (method, method_specific_id) = rest
        .split_once(':')
        .ok_or_else(|| invalid("DID must contain a colon after the method name"))?;

    // Report DID URL components specifically: they are the most common way a
    // caller supplies a key or service id where a document id is required.
    if method_specific_id.contains('#') {
        return Err(invalid(
            "a DID document id must be a DID, not a DID URL; fragments (`#`) are not allowed",
        ));
    }
    if method_specific_id.contains('?') {
        return Err(invalid(
            "a DID document id must be a DID, not a DID URL; queries (`?`) are not allowed",
        ));
    }
    if method_specific_id.contains('/') {
        return Err(invalid(
            "a DID document id must be a DID, not a DID URL; paths (`/`) are not allowed",
        ));
    }

    validate_method_name(method)
        .map_err(|_| invalid("method name must contain only lowercase letters and digits"))?;

    if method != config.method() {
        return Err(DidError::MethodMismatch {
            input: input.to_string(),
            expected: config.method().to_string(),
            actual: method.to_string(),
        });
    }

    validate_method_specific_id(method_specific_id).map_err(|reason| invalid(&reason))?;

    Ok(ValidatedDidId {
        id: input.to_string(),
        method_specific_id: method_specific_id.to_string(),
    })
}

/// Check the DID Core `method-name` production.
fn validate_method_name(method: &str) -> Result<(), DidError> {
    if method.is_empty() {
        return Err(DidError::InvalidMethodName {
            method: method.to_string(),
            reason: "method name must not be empty".to_string(),
        });
    }
    if !method
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(DidError::InvalidMethodName {
            method: method.to_string(),
            reason: "method name must contain only lowercase letters and digits".to_string(),
        });
    }
    Ok(())
}

/// Check the DID Core `method-specific-id` production.
///
/// Returns a human-readable reason because every failure is surfaced through
/// [`DidError::InvalidDid`] by the caller.
fn validate_method_specific_id(method_specific_id: &str) -> Result<(), String> {
    if method_specific_id.is_empty() {
        return Err("method-specific id must not be empty".to_string());
    }

    let bytes = method_specific_id.as_bytes();
    let mut index = 0;
    // `expect_idchar` is true at the start of the string and after each `:`,
    // so empty segments and a trailing colon are rejected.
    let mut expect_idchar = true;

    while index < bytes.len() {
        let byte = bytes[index];
        match byte {
            b':' => {
                if expect_idchar {
                    return Err("method-specific id must not contain empty segments".to_string());
                }
                expect_idchar = true;
                index += 1;
            }
            b'%' => {
                if index + 2 >= bytes.len()
                    || !bytes[index + 1].is_ascii_hexdigit()
                    || !bytes[index + 2].is_ascii_hexdigit()
                {
                    return Err(
                        "percent-encoded characters must be `%` followed by two hex digits"
                            .to_string(),
                    );
                }
                expect_idchar = false;
                index += 3;
            }
            _ if is_idchar(byte) => {
                expect_idchar = false;
                index += 1;
            }
            _ => {
                return Err(format!(
                    "character `{}` is not allowed in a method-specific id",
                    char::from(byte)
                ));
            }
        }
    }

    if expect_idchar {
        return Err("method-specific id must not end with `:`".to_string());
    }
    Ok(())
}

/// DID Core `idchar`: ALPHA / DIGIT / "." / "-" / "_".
fn is_idchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stellar() -> DidMethodConfig {
        DidMethodConfig::default()
    }

    // ── Configuration ─────────────────────────────────────────────────────────

    #[test]
    fn default_config_serves_stellar() {
        assert_eq!(DEFAULT_METHOD, "stellar");
        assert_eq!(stellar().method(), "stellar");
    }

    #[test]
    fn config_accepts_another_valid_method() {
        let config = DidMethodConfig::new("example").expect("valid method name");
        assert_eq!(config.method(), "example");
        assert!(validate_did_id("did:example:alice", &config).is_ok());
    }

    #[test]
    fn config_rejects_invalid_method_names() {
        for name in ["", "Stellar", "stellar-method", "ste llar", "stellar:test"] {
            let err = DidMethodConfig::new(name).unwrap_err();
            assert!(
                matches!(err, DidError::InvalidMethodName { .. }),
                "{name:?} should be rejected, got: {err:?}"
            );
        }
    }

    #[test]
    fn config_accepts_digits_in_method_name() {
        assert!(DidMethodConfig::new("did123").is_ok());
    }

    // ── Normal cases ──────────────────────────────────────────────────────────

    #[test]
    fn canonical_stellar_did_is_accepted() {
        let id = "did:stellar:testnet:GABCDEF";
        let validated = validate_did_id(id, &stellar()).expect("valid DID");
        assert_eq!(validated.as_str(), id);
        assert_eq!(validated.method_specific_id(), "testnet:GABCDEF");
        assert_eq!(validated.to_string(), id);
        assert_eq!(validated.as_ref(), id);
    }

    #[test]
    fn uppercase_and_separators_in_method_specific_id_are_accepted() {
        // DID Core permits uppercase, '.', '-' and '_' in the method-specific id.
        assert!(validate_did_id("did:stellar:Public:GABC.def-1_x", &stellar()).is_ok());
    }

    #[test]
    fn single_character_method_specific_id_is_accepted() {
        // Boundary: the shortest identifier that satisfies `1*idchar`.
        assert!(validate_did_id("did:stellar:a", &stellar()).is_ok());
    }

    #[test]
    fn percent_encoded_idchar_is_accepted() {
        let validated = validate_did_id("did:stellar:testnet:ab%2Dcd", &stellar())
            .expect("percent-encoded idchar is valid");
        assert_eq!(validated.method_specific_id(), "testnet:ab%2Dcd");
    }

    // ── Method mismatch ───────────────────────────────────────────────────────

    #[test]
    fn foreign_method_is_rejected_with_actionable_error() {
        let err = validate_did_id("did:example:alice", &stellar()).unwrap_err();
        match &err {
            DidError::MethodMismatch {
                input,
                expected,
                actual,
            } => {
                assert_eq!(input, "did:example:alice");
                assert_eq!(expected, "stellar");
                assert_eq!(actual, "example");
            }
            other => panic!("unexpected error: {other:?}"),
        }
        let message = err.to_string();
        assert!(message.contains("example"), "{message}");
        assert!(message.contains("stellar"), "{message}");
    }

    #[test]
    fn matching_method_of_custom_config_is_accepted() {
        let config = DidMethodConfig::new("example").unwrap();
        assert!(validate_did_id("did:stellar:testnet:GABC", &config).is_err());
        assert!(validate_did_id("did:example:alice", &config).is_ok());
    }

    // ── Malformed DID Core syntax ────────────────────────────────────────────

    #[test]
    fn empty_input_is_rejected() {
        let err = validate_did_id("", &stellar()).unwrap_err();
        assert!(matches!(err, DidError::InvalidDid { .. }), "{err:?}");
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn missing_did_scheme_is_rejected() {
        let err = validate_did_id("stellar:testnet:GABC", &stellar()).unwrap_err();
        assert!(
            matches!(&err, DidError::InvalidDid { reason, .. } if reason.contains("did:")),
            "{err:?}"
        );
    }

    #[test]
    fn missing_method_separator_is_rejected() {
        let err = validate_did_id("did:stellar", &stellar()).unwrap_err();
        assert!(
            matches!(&err, DidError::InvalidDid { reason, .. } if reason.contains("colon")),
            "{err:?}"
        );
    }

    #[test]
    fn empty_method_name_is_rejected() {
        let err = validate_did_id("did::testnet:GABC", &stellar()).unwrap_err();
        assert!(matches!(err, DidError::InvalidDid { .. }), "{err:?}");
    }

    #[test]
    fn uppercase_method_name_is_rejected_as_malformed() {
        let err = validate_did_id("did:STELLAR:testnet:GABC", &stellar()).unwrap_err();
        assert!(matches!(err, DidError::InvalidDid { .. }), "{err:?}");
    }

    #[test]
    fn empty_method_specific_id_is_rejected() {
        let err = validate_did_id("did:stellar:", &stellar()).unwrap_err();
        assert!(
            matches!(&err, DidError::InvalidDid { reason, .. } if reason.contains("must not be empty")),
            "{err:?}"
        );
    }

    #[test]
    fn did_url_components_are_rejected() {
        for (input, component) in [
            ("did:stellar:testnet:GABC#key-1", "fragments"),
            ("did:stellar:testnet:GABC?service=hub", "queries"),
            ("did:stellar:testnet:GABC/path", "paths"),
        ] {
            let err = validate_did_id(input, &stellar()).unwrap_err();
            assert!(
                matches!(&err, DidError::InvalidDid { reason, .. } if reason.contains("DID URL")),
                "{input} should be rejected as a DID URL, got: {err:?}"
            );
            assert!(err.to_string().contains(component), "{err:?}");
        }
    }

    #[test]
    fn empty_segments_and_trailing_colon_are_rejected() {
        for input in [
            "did:stellar::GABC",
            "did:stellar:testnet::GABC",
            "did:stellar:GABC:",
        ] {
            let err = validate_did_id(input, &stellar()).unwrap_err();
            assert!(matches!(err, DidError::InvalidDid { .. }), "{err:?}");
        }
    }

    #[test]
    fn illegal_characters_are_rejected() {
        for input in [
            "did:stellar:testnet:GABC@evil",
            "did:stellar:testnet:GABC space",
            "did:stellar:testnet:GABC+plus",
        ] {
            let err = validate_did_id(input, &stellar()).unwrap_err();
            assert!(matches!(err, DidError::InvalidDid { .. }), "{err:?}");
        }
    }

    #[test]
    fn malformed_percent_encoding_is_rejected() {
        for input in [
            "did:stellar:testnet:%",
            "did:stellar:testnet:%2",
            "did:stellar:testnet:%ZZ",
        ] {
            let err = validate_did_id(input, &stellar()).unwrap_err();
            assert!(
                matches!(&err, DidError::InvalidDid { reason, .. } if reason.contains("hex digits")),
                "{input}: {err:?}"
            );
        }
    }

    #[test]
    fn invalid_did_error_names_the_rejected_input() {
        let input = "not-a-did";
        let err = validate_did_id(input, &stellar()).unwrap_err();
        assert!(err.to_string().contains(input));
    }
}

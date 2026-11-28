//! DID resolution and paginated history responses (issue #342).
//!
//! This module provides [`DidResolver`], an in-memory DID document store and
//! resolver that tracks document version history and supports cursor-based
//! pagination over history entries.
//!
//! # Compatibility
//!
//! Callers that do not use pagination can continue calling
//! [`DidResolver::resolve`] (latest document) and
//! [`DidResolver::resolve_history`] (full unpaginated slice).
//!
//! # Validation & Invariants
//!
//! - DIDs are validated against [W3C DID Core](https://www.w3.org/TR/did-core/#did-syntax)
//!   syntax (`did:<method>:<method-specific-id>`).
//! - Pagination parameters are validated explicitly via [`PaginationParams::new`]
//!   and [`DidResolver::resolve_history_paginated`]: `limit` must be in
//!   `1..=MAX_PAGE_LIMIT`, and cursors must be non-empty ASCII unsigned integers
//!   within the bounds of the DID's history. Invalid inputs are rejected with
//!   actionable [`DidError`] variants rather than silently clamping or
//!   substituting defaults.
//! - History entries are ordered deterministically by monotonically increasing
//!   `version` (`1, 2, ...`).

use crate::service::{DidDocument, DidError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Maximum number of history entries returned in a single page.
pub const MAX_PAGE_LIMIT: usize = 100;

/// Suggested default page limit for callers constructing [`PaginationParams`].
pub const DEFAULT_PAGE_LIMIT: usize = 20;

/// Parameters controlling a paginated history query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaginationParams {
    /// Maximum number of entries to return (`1..=MAX_PAGE_LIMIT`).
    pub limit: usize,
    /// Opaque cursor returned as `next_cursor` by a previous page, or `None`
    /// to start from the first entry.
    pub cursor: Option<String>,
}

impl PaginationParams {
    /// Construct and validate pagination parameters.
    ///
    /// # Errors
    ///
    /// - [`DidError::InvalidPaginationLimit`] if `limit == 0` or `limit > MAX_PAGE_LIMIT`.
    /// - [`DidError::InvalidCursor`] if `cursor` is `Some` and is not a valid
    ///   unsigned integer cursor.
    pub fn new(limit: usize, cursor: Option<String>) -> Result<Self, DidError> {
        let params = Self { limit, cursor };
        params.validate()?;
        Ok(params)
    }

    /// Validate `self` and return the decoded starting offset.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::InvalidPaginationLimit`] or [`DidError::InvalidCursor`]
    /// if any parameter is out of range or malformed.
    pub fn validate(&self) -> Result<usize, DidError> {
        if self.limit == 0 || self.limit > MAX_PAGE_LIMIT {
            return Err(DidError::InvalidPaginationLimit {
                limit: self.limit,
                max: MAX_PAGE_LIMIT,
            });
        }

        match &self.cursor {
            None => Ok(0),
            Some(raw) => {
                if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(DidError::InvalidCursor {
                        cursor: raw.clone(),
                        reason: "cursor must be a non-negative integer".to_string(),
                    });
                }
                raw.parse::<usize>().map_err(|e| DidError::InvalidCursor {
                    cursor: raw.clone(),
                    reason: e.to_string(),
                })
            }
        }
    }
}

/// A single versioned snapshot in a DID document's resolution history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidHistoryEntry {
    /// Monotonically increasing 1-based version number.
    pub version: u64,
    /// Unix timestamp (seconds) when this version was recorded.
    pub updated_at: u64,
    /// Snapshot of the DID document at this version.
    pub document: DidDocument,
}

/// Paginated response for DID document history queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedHistoryResponse {
    /// The resolved DID subject.
    pub did: String,
    /// History entries for the requested page, ordered by `version` ascending.
    pub items: Vec<DidHistoryEntry>,
    /// Total number of history entries recorded for `did`.
    pub total: usize,
    /// Effective page limit used for this response.
    pub limit: usize,
    /// Cursor to pass to the next query to retrieve subsequent entries, or
    /// `None` when this is the final page.
    pub next_cursor: Option<String>,
    /// `true` when additional entries exist beyond this page.
    pub has_more: bool,
}

/// Validate a DID string against W3C DID Core syntax (`did:<method>:<id>`).
///
/// # Errors
///
/// Returns [`DidError::InvalidDid`] if the DID is empty, contains whitespace,
/// lacks the `did:` scheme, has an invalid method name, or has an empty
/// method-specific identifier.
pub fn validate_did(did: &str) -> Result<(), DidError> {
    if did.is_empty() {
        return Err(DidError::InvalidDid {
            did: did.to_string(),
            reason: "DID must not be empty".to_string(),
        });
    }
    if did.chars().any(char::is_whitespace) {
        return Err(DidError::InvalidDid {
            did: did.to_string(),
            reason: "DID must not contain whitespace".to_string(),
        });
    }
    let Some(rest) = did.strip_prefix("did:") else {
        return Err(DidError::InvalidDid {
            did: did.to_string(),
            reason: "DID must start with `did:`".to_string(),
        });
    };
    let Some((method, method_id)) = rest.split_once(':') else {
        return Err(DidError::InvalidDid {
            did: did.to_string(),
            reason: "DID must have format `did:<method>:<method-specific-id>`".to_string(),
        });
    };
    if method.is_empty()
        || !method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(DidError::InvalidDid {
            did: did.to_string(),
            reason: format!("invalid DID method `{method}`"),
        });
    }
    if method_id.is_empty() {
        return Err(DidError::InvalidDid {
            did: did.to_string(),
            reason: "method-specific identifier must not be empty".to_string(),
        });
    }
    Ok(())
}

/// In-memory DID resolver that maintains versioned document history.
#[derive(Debug, Default, Clone)]
pub struct DidResolver {
    entries: HashMap<String, Vec<DidHistoryEntry>>,
}

impl DidResolver {
    /// Create a new, empty [`DidResolver`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new version of `document` at `updated_at` (Unix seconds).
    ///
    /// Returns the assigned 1-based version number. If validation fails, the
    /// resolver state is left unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::InvalidDid`] if `document.id` is not a valid DID.
    pub fn register_version(
        &mut self,
        document: DidDocument,
        updated_at: u64,
    ) -> Result<u64, DidError> {
        validate_did(&document.id)?;

        let history = self.entries.entry(document.id.clone()).or_default();
        let version = history.len() as u64 + 1;
        history.push(DidHistoryEntry {
            version,
            updated_at,
            document,
        });
        Ok(version)
    }

    /// Resolve the latest [`DidDocument`] for `did`.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::InvalidDid`] if `did` is malformed, or
    /// [`DidError::DidNotFound`] if no versions are registered for `did`.
    pub fn resolve(&self, did: &str) -> Result<&DidDocument, DidError> {
        let history = self.resolve_history(did)?;
        history
            .last()
            .map(|entry| &entry.document)
            .ok_or_else(|| DidError::DidNotFound(did.to_string()))
    }

    /// Return the complete, unpaginated version history for `did`.
    ///
    /// Preserves legacy behavior for callers that do not use pagination.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::InvalidDid`] if `did` is malformed, or
    /// [`DidError::DidNotFound`] if no versions are registered for `did`.
    pub fn resolve_history(&self, did: &str) -> Result<&[DidHistoryEntry], DidError> {
        validate_did(did)?;
        self.entries
            .get(did)
            .map(Vec::as_slice)
            .ok_or_else(|| DidError::DidNotFound(did.to_string()))
    }

    /// Return a paginated slice of the version history for `did`.
    ///
    /// # Errors
    ///
    /// - [`DidError::InvalidDid`] if `did` is malformed.
    /// - [`DidError::InvalidPaginationLimit`] if `params.limit` is `0` or
    ///   exceeds [`MAX_PAGE_LIMIT`].
    /// - [`DidError::InvalidCursor`] if `params.cursor` is malformed or points
    ///   past the end of the recorded history.
    /// - [`DidError::DidNotFound`] if no versions are registered for `did`.
    pub fn resolve_history_paginated(
        &self,
        did: &str,
        params: &PaginationParams,
    ) -> Result<PaginatedHistoryResponse, DidError> {
        validate_did(did)?;
        let offset = params.validate()?;

        let history = self
            .entries
            .get(did)
            .ok_or_else(|| DidError::DidNotFound(did.to_string()))?;

        let total = history.len();
        if offset >= total {
            return Err(DidError::InvalidCursor {
                cursor: params.cursor.clone().unwrap_or_default(),
                reason: format!(
                    "cursor offset {offset} is out of bounds for history of length {total}"
                ),
            });
        }

        let end = offset.saturating_add(params.limit).min(total);
        let items = history[offset..end].to_vec();
        let has_more = end < total;
        let next_cursor = if has_more { Some(end.to_string()) } else { None };

        Ok(PaginatedHistoryResponse {
            did: did.to_string(),
            items,
            total,
            limit: params.limit,
            next_cursor,
            has_more,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{Service, ServiceEndpoint};

    fn sample_did() -> &'static str {
        "did:stellar:testnet:GABC123"
    }

    fn seeded_resolver(count: usize) -> DidResolver {
        let mut resolver = DidResolver::new();
        for i in 1..=count {
            let mut doc = DidDocument::new(sample_did());
            let ep = ServiceEndpoint::uri(format!("https://hub.example.com/v{i}")).unwrap();
            let svc = Service::new(format!("{}#svc-{i}", sample_did()), "IdentityHub", ep).unwrap();
            doc.add_service(svc).unwrap();
            resolver.register_version(doc, 1_700_000_000 + i as u64).unwrap();
        }
        resolver
    }

    // ── Normal cases ─────────────────────────────────────────────────────────

    #[test]
    fn paginated_history_returns_first_page_and_next_cursor() {
        let resolver = seeded_resolver(5);
        let params = PaginationParams::new(2, None).unwrap();
        let page = resolver
            .resolve_history_paginated(sample_did(), &params)
            .unwrap();

        assert_eq!(page.did, sample_did());
        assert_eq!(page.total, 5);
        assert_eq!(page.limit, 2);
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].version, 1);
        assert_eq!(page.items[1].version, 2);
        assert!(page.has_more);
        assert_eq!(page.next_cursor.as_deref(), Some("2"));
    }

    #[test]
    fn unpaginated_resolve_and_history_remain_unchanged() {
        let resolver = seeded_resolver(3);
        let latest = resolver.resolve(sample_did()).unwrap();
        assert_eq!(latest.service[0].id, format!("{}#svc-3", sample_did()));

        let full = resolver.resolve_history(sample_did()).unwrap();
        assert_eq!(full.len(), 3);
        assert_eq!(full[0].version, 1);
        assert_eq!(full[2].version, 3);
    }

    // ── Boundary cases ───────────────────────────────────────────────────────

    #[test]
    fn exact_page_size_sets_has_more_false_and_no_next_cursor() {
        let resolver = seeded_resolver(3);
        let params = PaginationParams::new(3, None).unwrap();
        let page = resolver
            .resolve_history_paginated(sample_did(), &params)
            .unwrap();

        assert_eq!(page.items.len(), 3);
        assert!(!page.has_more);
        assert_eq!(page.next_cursor, None);
    }

    #[test]
    fn max_page_limit_is_accepted_and_above_is_rejected() {
        let ok = PaginationParams::new(MAX_PAGE_LIMIT, None);
        assert!(ok.is_ok());

        let err = PaginationParams::new(MAX_PAGE_LIMIT + 1, None).unwrap_err();
        assert!(matches!(
            err,
            DidError::InvalidPaginationLimit {
                limit,
                max
            } if limit == MAX_PAGE_LIMIT + 1 && max == MAX_PAGE_LIMIT
        ));
    }

    // ── Failure cases ────────────────────────────────────────────────────────

    #[test]
    fn zero_limit_is_rejected_explicitly() {
        let err = PaginationParams::new(0, None).unwrap_err();
        assert!(matches!(
            err,
            DidError::InvalidPaginationLimit { limit: 0, .. }
        ));
    }

    #[test]
    fn malformed_and_out_of_bounds_cursors_are_rejected() {
        let err = PaginationParams::new(10, Some("abc".to_string())).unwrap_err();
        assert!(matches!(err, DidError::InvalidCursor { .. }));

        let err_neg = PaginationParams::new(10, Some("-1".to_string())).unwrap_err();
        assert!(matches!(err_neg, DidError::InvalidCursor { .. }));

        let resolver = seeded_resolver(2);
        let params = PaginationParams::new(10, Some("2".to_string())).unwrap();
        let err_oob = resolver
            .resolve_history_paginated(sample_did(), &params)
            .unwrap_err();
        assert!(matches!(err_oob, DidError::InvalidCursor { .. }));
    }

    #[test]
    fn invalid_did_and_missing_did_return_actionable_errors() {
        let mut resolver = DidResolver::new();
        let bad_doc = DidDocument::new("not-a-did");
        let err = resolver.register_version(bad_doc, 100).unwrap_err();
        assert!(matches!(err, DidError::InvalidDid { .. }));
        assert!(resolver.entries.is_empty());

        let params = PaginationParams::new(10, None).unwrap();
        let not_found = resolver
            .resolve_history_paginated(sample_did(), &params)
            .unwrap_err();
        assert!(matches!(not_found, DidError::DidNotFound(_)));
    }

    // ── Integration workflow ─────────────────────────────────────────────────

    #[test]
    fn full_pagination_workflow_reconstructs_complete_history() {
        let resolver = seeded_resolver(7);
        let mut collected_versions = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let params = PaginationParams::new(3, cursor).unwrap();
            let page = resolver
                .resolve_history_paginated(sample_did(), &params)
                .unwrap();

            for entry in page.items {
                collected_versions.push(entry.version);
            }

            if !page.has_more {
                assert!(page.next_cursor.is_none());
                break;
            }
            cursor = page.next_cursor;
            assert!(cursor.is_some());
        }

        assert_eq!(collected_versions, vec![1, 2, 3, 4, 5, 6, 7]);
    }
}

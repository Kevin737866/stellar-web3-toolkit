//! Horizon record pagination (issue #191).
//!
//! Horizon never returns "all" of anything. Every collection endpoint
//! (`/accounts/{id}/payments`, `/transactions`, `/operations`, ...) answers with
//! one page of `_embedded.records` plus a `_links` block whose `next` href
//! carries the cursor for the following page. A client that reads a single
//! response therefore silently truncates: it reports the newest page and
//! behaves as though the account had no history before it.
//!
//! This module models that contract explicitly:
//!
//! * [`HorizonPage`] parses one Horizon page, including `_links.next.href`;
//! * [`Cursor`] wraps the `cursor` query parameter, rejecting an empty value
//!   rather than dropping it (a dropped cursor restarts from the newest page —
//!   an infinite loop that looks like forward progress);
//! * [`paginate`] walks pages until Horizon stops handing out a `next` link.
//!
//! # Termination
//!
//! Walking is bounded by `max_pages`, and a page whose `next` cursor repeats
//! the one just used is refused as [`HorizonPaginationError::CursorDidNotAdvance`].
//! Horizon is not supposed to do that, but a proxy that strips the cursor, or an
//! endpoint that ignores it, turns an unbounded walk into a hang — and a hang in
//! a monitor is indistinguishable from a healthy idle loop.
//!
//! # Compatibility
//!
//! Only the fields this module needs are typed. Unknown fields are ignored, so a
//! Horizon release that adds fields does not break parsing, and a missing
//! `_embedded` block (an empty collection) is treated as an empty page rather
//! than an error.

use crate::error::{Result, ToolkitError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Page size Horizon applies when the caller does not ask for one.
pub const DEFAULT_LIMIT: u32 = 50;
/// Largest page Horizon accepts; a larger `limit` is clamped by the server.
pub const MAX_LIMIT: u32 = 200;
/// Default ceiling on pages walked by [`paginate`].
pub const DEFAULT_MAX_PAGES: usize = 100;

/// The `cursor` query parameter for a Horizon collection request.
///
/// Horizon treats `cursor=` (empty) as "start from the beginning of time" and an
/// absent cursor as "start from the newest record". Those are opposite ends of
/// the collection, so an empty value is rejected here instead of being sent and
/// silently changing what the caller sees.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Cursor(String);

impl Cursor {
    /// Wrap a non-empty cursor value.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(ToolkitError::Horizon(
                "a cursor must not be empty; omit it to start from the newest record".to_string(),
            ));
        }
        Ok(Self(value))
    }

    /// The sentinel Horizon documents for "from the oldest record".
    pub fn oldest() -> Self {
        Self("0".to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Cursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One page of a Horizon collection, with the cursor for the next one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HorizonPage {
    /// The raw records, untouched, so callers can decode them into their own type.
    pub records: Vec<serde_json::Value>,
    /// Cursor to request the next page, taken from `_links.next.href`.
    pub next_cursor: Option<Cursor>,
}

impl HorizonPage {
    /// Parse a Horizon collection response body.
    ///
    /// `_embedded.records` may be absent (empty collection). `_links.next.href`
    /// is parsed for its `cursor` parameter; a `next` link without a usable
    /// cursor is an error, because continuing would re-fetch the current page.
    pub fn from_json(body: &str) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_str(body)
            .map_err(|e| ToolkitError::Horizon(format!("could not parse Horizon page: {e}")))?;

        let records = match value.get("_embedded").and_then(|e| e.get("records")) {
            None => Vec::new(),
            Some(serde_json::Value::Array(records)) => records.clone(),
            Some(other) => {
                return Err(ToolkitError::Horizon(format!(
                    "_embedded.records must be an array, got {other}"
                )))
            }
        };

        let next_href = value
            .get("_links")
            .and_then(|links| links.get("next"))
            .and_then(|next| next.get("href"))
            .and_then(|href| href.as_str());

        let next_cursor = match next_href {
            None => None,
            Some(href) => Some(cursor_from_href(href).ok_or_else(|| {
                ToolkitError::Horizon(format!("the next link has no cursor parameter: {href}"))
            })?),
        };

        Ok(Self {
            records,
            next_cursor,
        })
    }

    /// Whether Horizon says more records follow.
    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }
}

/// Extract the `cursor` query parameter from a Horizon `next` href.
///
/// Parsed by hand rather than with a full URL parser: `next` hrefs are absolute
/// but may carry characters a generic parser rejects, and only one parameter
/// matters.
pub fn cursor_from_href(href: &str) -> Option<Cursor> {
    let query = href.split_once('?').map(|(_, query)| query)?;
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("cursor=") {
            // An explicitly empty cursor is Horizon's "oldest" sentinel.
            if value.is_empty() {
                return Some(Cursor::oldest());
            }
            return Cursor::new(value).ok();
        }
    }
    None
}

/// Build the request path for one page of `collection`.
///
/// `cursor` selects the starting record and `limit` the page size (clamped to
/// [`MAX_LIMIT`]). Both are always emitted explicitly so the same call is
/// reproducible and no server-side default changes what a walk sees.
pub fn page_path(collection: &str, cursor: &Cursor, limit: u32) -> String {
    let limit = limit.clamp(1, MAX_LIMIT);
    let separator = if collection.contains('?') { '&' } else { '?' };
    format!("{collection}{separator}cursor={cursor}&limit={limit}&order=asc")
}

/// A walk that visited a page whose `next` cursor did not advance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorDidNotAdvance {
    pub cursor: Cursor,
}

/// Pagination failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HorizonPaginationError {
    #[error("Horizon kept returning cursor `{cursor}`; refusing to loop forever")]
    CursorDidNotAdvance { cursor: String },

    #[error("walked {max_pages} page(s) without reaching the end")]
    PageLimitExceeded { max_pages: usize },
}

/// Walk `collection` page by page, decoding every record with `decode`.
///
/// `fetch` performs the HTTP GET for a path and returns the response body, so
/// this stays testable without a network. The walk stops at the first page with
/// no `next` link, at `max_pages`, or when a cursor repeats.
///
/// Records are returned oldest-first, matching the `order=asc` the path asks
/// for; that is the order a monitor needs to replay state.
pub fn paginate<T, F, D>(
    collection: &str,
    limit: u32,
    max_pages: usize,
    mut fetch: F,
    decode: D,
) -> Result<Vec<T>>
where
    F: FnMut(&str) -> Result<String>,
    D: Fn(&serde_json::Value) -> Result<T>,
{
    let mut cursor = Cursor::oldest();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();

    for _ in 0..max_pages.max(1) {
        let path = page_path(collection, &cursor, limit);
        let page = HorizonPage::from_json(&fetch(&path)?)?;

        for record in &page.records {
            out.push(decode(record)?);
        }

        let Some(next) = page.next_cursor else {
            return Ok(out);
        };

        // A cursor we have already used means the server is not advancing; the
        // alternative is to keep asking for the same page forever.
        if next == cursor || !seen.insert(next.clone()) {
            return Err(HorizonPaginationError::CursorDidNotAdvance {
                cursor: next.to_string(),
            }
            .into());
        }
        cursor = next;
    }

    Err(HorizonPaginationError::PageLimitExceeded { max_pages }.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page_body(records: &[&str], next_href: Option<&str>) -> String {
        let records = records.join(",");
        let links = match next_href {
            Some(href) => format!(r#"{{"next":{{"href":"{href}"}}}}"#),
            None => "{}".to_string(),
        };
        format!(r#"{{"_embedded":{{"records":[{records}]}},"_links":{links}}}"#)
    }

    /// A fetcher that serves canned bodies and records the paths it was asked for.
    fn canned(pages: Vec<String>) -> impl FnMut(&str) -> Result<String> {
        let mut pages = pages.into_iter();
        move |_path| {
            pages
                .next()
                .ok_or_else(|| ToolkitError::Horizon("no more canned pages".to_string()))
        }
    }

    fn id(record: &serde_json::Value) -> Result<String> {
        record["id"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| ToolkitError::Horizon("record has no id".to_string()))
    }

    #[test]
    fn a_cursor_must_not_be_empty() {
        assert!(Cursor::new("").is_err());
        assert!(Cursor::new("   ").is_err());
        assert_eq!(Cursor::new("12345").unwrap().as_str(), "12345");
    }

    #[test]
    fn a_page_without_embedded_records_is_empty() {
        let page = HorizonPage::from_json(r#"{"_links":{}}"#).unwrap();
        assert!(page.records.is_empty());
        assert!(!page.has_more());
    }

    #[test]
    fn the_next_cursor_is_read_from_the_next_link() {
        let body = page_body(
            &[r#"{"id":"1"}"#],
            Some("https://horizon.stellar.org/accounts/G.../payments?cursor=123&limit=2&order=asc"),
        );
        let page = HorizonPage::from_json(&body).unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.next_cursor.unwrap().as_str(), "123");
    }

    #[test]
    fn an_empty_next_cursor_is_the_oldest_sentinel() {
        assert_eq!(
            cursor_from_href("https://h/transactions?cursor=&limit=2"),
            Some(Cursor::oldest())
        );
        assert_eq!(
            cursor_from_href("https://h/transactions?order=asc&cursor=987"),
            Some(Cursor::new("987").unwrap())
        );
        assert_eq!(cursor_from_href("https://h/transactions?limit=2"), None);
    }

    #[test]
    fn a_next_link_without_a_cursor_is_an_error() {
        let body = page_body(&[r#"{"id":"1"}"#], Some("https://h/transactions?limit=2"));
        let err = HorizonPage::from_json(&body).unwrap_err();
        assert!(err.to_string().contains("no cursor parameter"));
    }

    #[test]
    fn a_non_array_records_field_is_an_error() {
        let err = HorizonPage::from_json(r#"{"_embedded":{"records":{}}}"#).unwrap_err();
        assert!(err.to_string().contains("must be an array"));
    }

    #[test]
    fn the_page_path_pins_cursor_limit_and_order() {
        let path = page_path("/accounts/G/payments", &Cursor::new("42").unwrap(), 10);
        assert_eq!(path, "/accounts/G/payments?cursor=42&limit=10&order=asc");

        let clamped = page_path("/transactions", &Cursor::oldest(), 5_000);
        assert!(clamped.contains(&format!("limit={MAX_LIMIT}")));

        let with_query = page_path("/transactions?include_failed=true", &Cursor::oldest(), 2);
        assert!(with_query.starts_with("/transactions?include_failed=true&cursor="));
    }

    #[test]
    fn a_walk_visits_every_page_in_order() {
        let pages = vec![
            page_body(
                &[r#"{"id":"1"}"#, r#"{"id":"2"}"#],
                Some("https://h/tx?cursor=2&limit=2&order=asc"),
            ),
            page_body(
                &[r#"{"id":"3"}"#],
                Some("https://h/tx?cursor=3&limit=2&order=asc"),
            ),
            page_body(&[r#"{"id":"4"}"#], None),
        ];

        let mut requested = Vec::new();
        let mut fetch = canned(pages);
        let ids = paginate(
            "/tx",
            2,
            DEFAULT_MAX_PAGES,
            |path| {
                requested.push(path.to_string());
                fetch(path)
            },
            id,
        )
        .unwrap();

        assert_eq!(ids, vec!["1", "2", "3", "4"]);
        assert_eq!(requested.len(), 3);
        assert!(requested[0].contains("cursor=0"));
        assert!(requested[1].contains("cursor=2"));
        assert!(requested[2].contains("cursor=3"));
    }

    #[test]
    fn a_cursor_that_does_not_advance_is_refused() {
        let stuck = page_body(&[r#"{"id":"1"}"#], Some("https://h/tx?cursor=7&limit=2"));
        let pages = vec![stuck.clone(), stuck];

        // The first request starts at cursor 0; the second is handed cursor 7
        // again, so the walk must stop instead of re-reading the same page.
        let err = paginate("/tx", 2, DEFAULT_MAX_PAGES, canned(pages), id).unwrap_err();
        assert!(err.to_string().contains("refusing to loop"));
    }

    #[test]
    fn the_page_limit_bounds_an_endless_walk() {
        // Every page advertises a *new* cursor, so only `max_pages` stops it.
        let pages = vec![
            page_body(&[r#"{"id":"1"}"#], Some("https://h/tx?cursor=1&limit=2")),
            page_body(&[r#"{"id":"2"}"#], Some("https://h/tx?cursor=2&limit=2")),
            page_body(&[r#"{"id":"3"}"#], Some("https://h/tx?cursor=3&limit=2")),
        ];

        let err = paginate("/tx", 2, 2, canned(pages), id).unwrap_err();
        assert!(err.to_string().contains("without reaching the end"));
    }

    #[test]
    fn a_decode_failure_stops_the_walk() {
        let pages = vec![page_body(&[r#"{"nope":"x"}"#], None)];
        let err = paginate("/tx", 2, DEFAULT_MAX_PAGES, canned(pages), id).unwrap_err();
        assert!(err.to_string().contains("no id"));
    }
}

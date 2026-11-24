//! Paginated contract state inspector (issues #244, #313).
//!
//! Reads a contract state export (the entries returned by `getLedgerEntries` /
//! `getEvents` style queries) and serves it page by page, so that inspecting a
//! contract with thousands of keys stays readable and scriptable.
//!
//! Each page carries two cursors:
//!
//! * `next_cursor` is the legacy zero-based offset, kept for the existing
//!   `--cursor` CLI flag and its output format;
//! * `next_page_token` is an opaque [`PageCursor`] that binds the offset to the
//!   filter and page size used to issue it. Feeding that token back with
//!   `--page-cursor` resumes the walk, while a token from another filter (or a
//!   corrupted one) is rejected instead of silently starting a different page.

use crate::error::{Result, ToolkitError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::path::Path;

/// Number of entries returned when the caller does not pick a page size.
pub const DEFAULT_PAGE_SIZE: usize = 20;
/// Hard cap for a single page, keeping output (and terminals) sane.
pub const MAX_PAGE_SIZE: usize = 200;

/// Prefix of an encoded [`PageCursor`].
pub const PAGE_CURSOR_PREFIX: &str = "s1.";
/// Version encoded in a [`PageCursor`]; bump it when the payload layout changes.
const PAGE_CURSOR_VERSION: u8 = 1;
/// version + offset + page size + temp flag + two 8-byte string lengths + checksum.
const MIN_CURSOR_LEN: usize = 1 + 8 + 4 + 1 + 8 + 8 + 4;
/// Length marker for an absent optional string in a cursor payload.
const NO_STRING: u64 = u64::MAX;

/// Why a page cursor could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PageCursorError {
    #[error(
        "page cursor `{0}` is malformed; copy the `next_page_token` value from the previous page"
    )]
    Malformed(String),
    #[error("page cursor has version {found}, but this build understands version {expected}")]
    UnsupportedVersion { found: u8, expected: u8 },
    #[error("page cursor failed its integrity check; it was truncated or edited")]
    Corrupt,
    #[error(
        "page cursor was issued for {field} `{issued}`, but this query uses `{actual}`; restart the walk with the original filters"
    )]
    QueryMismatch {
        field: &'static str,
        issued: String,
        actual: String,
    },
    #[error(
        "page cursor offset {offset} is past the {total} entries matching this query; the state export may have changed since the cursor was issued"
    )]
    OffsetOutOfRange { offset: usize, total: usize },
}

/// Storage bucket an entry lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Durability {
    /// Contract instance storage (contract metadata + config).
    Instance,
    /// Persistent storage, survives ledger restore.
    Persistent,
    /// Temporary storage, restored back to its previous value.
    Temporary,
}

impl Durability {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Instance => "instance",
            Self::Persistent => "persistent",
            Self::Temporary => "temporary",
        }
    }
}

/// A single contract state entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateEntry {
    pub contract_id: String,
    pub durability: Durability,
    pub key: String,
    pub value: String,
    /// Ledger the entry was last modified in.
    pub ledger: u32,
    /// Ledger the entry expires at (temporary entries only).
    #[serde(default)]
    pub live_until_ledger: Option<u32>,
}

/// Filter and pagination parameters for a state query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateQuery {
    contract_id: Option<String>,
    key_prefix: Option<String>,
    include_temporary: bool,
    page_size: usize,
    cursor: usize,
}

impl Default for StateQuery {
    fn default() -> Self {
        Self {
            contract_id: None,
            key_prefix: None,
            include_temporary: false,
            page_size: DEFAULT_PAGE_SIZE,
            cursor: 0,
        }
    }
}

impl StateQuery {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict the query to a single contract.
    pub fn for_contract(mut self, contract_id: impl Into<String>) -> Self {
        self.contract_id = Some(contract_id.into());
        self
    }

    /// Restrict the query to keys starting with `prefix`.
    pub fn with_key_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = Some(prefix.into());
        self
    }

    /// Temporary entries are excluded by default because they are rolled back.
    #[must_use]
    pub fn including_temporary(mut self, include_temporary: bool) -> Self {
        self.include_temporary = include_temporary;
        self
    }

    /// Page size is clamped to `1..=MAX_PAGE_SIZE`.
    #[must_use]
    pub fn with_page_size(mut self, page_size: usize) -> Self {
        self.page_size = page_size.clamp(1, MAX_PAGE_SIZE);
        self
    }

    /// Cursor returned by a previous page (`0` starts at the first entry).
    #[must_use]
    pub fn with_cursor(mut self, cursor: usize) -> Self {
        self.cursor = cursor;
        self
    }

    #[must_use]
    pub fn contract_id(&self) -> Option<&str> {
        self.contract_id.as_deref()
    }

    #[must_use]
    pub fn key_prefix(&self) -> Option<&str> {
        self.key_prefix.as_deref()
    }

    #[must_use]
    pub fn include_temporary(&self) -> bool {
        self.include_temporary
    }

    #[must_use]
    pub fn page_size(&self) -> usize {
        self.page_size
    }

    #[must_use]
    pub fn cursor(&self) -> usize {
        self.cursor
    }
}

/// An opaque, self-validating cursor for the next page of a state query.
///
/// The token encodes its offset, page size, filter (`contract_id`, `key_prefix`
/// and `include_temporary`) and a checksum. It is safe to hand to another
/// process but unsafe to mix with a different query: [`PageCursor::parse`]
/// rejects a mismatch rather than returning a page the caller did not ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageCursor {
    offset: usize,
    page_size: usize,
    include_temporary: bool,
    contract_id: Option<String>,
    key_prefix: Option<String>,
    encoded: String,
}

impl PageCursor {
    /// Encodes a cursor for `offset` under `query`.
    #[must_use]
    pub fn issue(query: &StateQuery, offset: usize) -> Self {
        let mut payload = Vec::with_capacity(MIN_CURSOR_LEN + 64);
        payload.push(PAGE_CURSOR_VERSION);
        payload.extend_from_slice(&(offset as u64).to_be_bytes());
        payload.extend_from_slice(&(query.page_size() as u32).to_be_bytes());
        payload.push(u8::from(query.include_temporary()));
        push_string(&mut payload, query.contract_id());
        push_string(&mut payload, query.key_prefix());
        payload.extend_from_slice(&checksum(&payload).to_be_bytes());

        Self {
            offset,
            page_size: query.page_size(),
            include_temporary: query.include_temporary(),
            contract_id: query.contract_id().map(str::to_string),
            key_prefix: query.key_prefix().map(str::to_string),
            encoded: format!("{PAGE_CURSOR_PREFIX}{}", hex::encode(payload)),
        }
    }

    /// Decodes `token` and checks it against the query that will consume it.
    pub fn parse(token: &str, query: &StateQuery) -> Result<Self> {
        let body = token
            .strip_prefix(PAGE_CURSOR_PREFIX)
            .ok_or_else(|| malformed(token))?;
        let bytes = hex::decode(body).map_err(|_| malformed(token))?;
        if bytes.len() < MIN_CURSOR_LEN {
            return Err(malformed(token));
        }
        let (payload, tail) = bytes.split_at(bytes.len() - 4);
        let expected = u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]]);
        if checksum(payload) != expected {
            return Err(PageCursorError::Corrupt.into());
        }
        let version = payload[0];
        if version != PAGE_CURSOR_VERSION {
            return Err(PageCursorError::UnsupportedVersion {
                found: version,
                expected: PAGE_CURSOR_VERSION,
            }
            .into());
        }

        let mut rest = &payload[1..];
        let raw_offset = take_u64(&mut rest, token)?;
        let raw_page_size = take_u32(&mut rest, token)?;
        let include_temporary = match take_u8(&mut rest, token)? {
            0 => false,
            1 => true,
            _ => return Err(malformed(token)),
        };
        let contract_id = take_string(&mut rest, token)?;
        let key_prefix = take_string(&mut rest, token)?;
        if !rest.is_empty() {
            return Err(malformed(token));
        }

        let offset = usize::try_from(raw_offset).map_err(|_| malformed(token))?;
        let page_size = usize::try_from(raw_page_size).map_err(|_| malformed(token))?;
        same_scope(
            "contract",
            contract_id.as_deref(),
            query.contract_id(),
            "all contracts",
        )?;
        same_scope(
            "key prefix",
            key_prefix.as_deref(),
            query.key_prefix(),
            "no key prefix",
        )?;
        let issued_temp = if include_temporary { "true" } else { "false" };
        let actual_temp = if query.include_temporary() {
            "true"
        } else {
            "false"
        };
        same_scope(
            "include_temporary",
            Some(issued_temp),
            Some(actual_temp),
            "",
        )?;
        let issued_size = page_size.to_string();
        let actual_size = query.page_size().to_string();
        same_scope(
            "page size",
            Some(issued_size.as_str()),
            Some(actual_size.as_str()),
            "",
        )?;

        Ok(Self {
            offset,
            page_size,
            include_temporary,
            contract_id,
            key_prefix,
            encoded: token.to_string(),
        })
    }

    /// Zero-based index of the first entry on the addressed page.
    #[must_use]
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Page size the token was issued for.
    #[must_use]
    pub fn page_size(&self) -> usize {
        self.page_size
    }

    /// The encoded token, suitable for `--page-cursor`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.encoded
    }
}

impl fmt::Display for PageCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encoded)
    }
}

fn checksum(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5_u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn push_string(payload: &mut Vec<u8>, value: Option<&str>) {
    match value {
        None => payload.extend_from_slice(&NO_STRING.to_be_bytes()),
        Some(value) => {
            payload.extend_from_slice(&(value.len() as u64).to_be_bytes());
            payload.extend_from_slice(value.as_bytes());
        }
    }
}

fn malformed(token: &str) -> ToolkitError {
    PageCursorError::Malformed(token.to_string()).into()
}

fn take_u8<'a>(rest: &mut &'a [u8], token: &str) -> Result<u8> {
    if rest.is_empty() {
        return Err(malformed(token));
    }
    let value = rest[0];
    *rest = &rest[1..];
    Ok(value)
}

fn take_u64<'a>(rest: &mut &'a [u8], token: &str) -> Result<u64> {
    if rest.len() < 8 {
        return Err(malformed(token));
    }
    let (head, tail) = rest.split_at(8);
    *rest = tail;
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(head);
    Ok(u64::from_be_bytes(bytes))
}

fn take_u32<'a>(rest: &mut &'a [u8], token: &str) -> Result<u32> {
    if rest.len() < 4 {
        return Err(malformed(token));
    }
    let (head, tail) = rest.split_at(4);
    *rest = tail;
    let mut bytes = [0_u8; 4];
    bytes.copy_from_slice(head);
    Ok(u32::from_be_bytes(bytes))
}

fn take_string<'a>(rest: &mut &'a [u8], token: &str) -> Result<Option<String>> {
    let length = take_u64(rest, token)?;
    if length == NO_STRING {
        return Ok(None);
    }
    let length = usize::try_from(length).map_err(|_| malformed(token))?;
    if rest.len() < length {
        return Err(malformed(token));
    }
    let (bytes, tail) = rest.split_at(length);
    *rest = tail;
    let value = std::str::from_utf8(bytes).map_err(|_| malformed(token))?;
    Ok(Some(value.to_string()))
}

fn same_scope(
    field: &'static str,
    issued: Option<&str>,
    actual: Option<&str>,
    none_label: &str,
) -> Result<()> {
    if issued == actual {
        return Ok(());
    }
    let describe = |value: Option<&str>| {
        value
            .map(str::to_string)
            .unwrap_or_else(|| none_label.to_string())
    };
    Err(PageCursorError::QueryMismatch {
        field,
        issued: describe(issued),
        actual: describe(actual),
    }
    .into())
}

/// One page of state entries plus the cursor needed to fetch the next one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatePage {
    pub contract_id: Option<String>,
    pub page_index: usize,
    pub page_size: usize,
    /// Total number of entries matching the filter.
    pub total: usize,
    /// Zero based index of the first entry on this page.
    pub offset: usize,
    pub entries: Vec<StateEntry>,
    /// Legacy numeric cursor to pass to the next request, `None` on the last page.
    pub next_cursor: Option<usize>,
    /// Opaque cursor bound to this query, `None` on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
    pub has_more: bool,
}

impl StatePage {
    /// `true` when no further cursor is returned, i.e. this is the last page.
    #[must_use]
    pub fn is_last_page(&self) -> bool {
        !self.has_more
    }

    /// Human readable rendering used by the CLI.
    #[must_use]
    pub fn render(&self) -> String {
        let scope = self.contract_id.as_deref().unwrap_or("all contracts");
        let mut out = format!(
            "contract {scope}: page {} ({}..{} of {} entries, page size {})\n",
            self.page_index,
            self.offset,
            self.offset + self.entries.len(),
            self.total,
            self.page_size
        );
        if self.entries.is_empty() {
            out.push_str("  no entries for this page\n");
        }
        for entry in &self.entries {
            let expiry = match entry.live_until_ledger {
                Some(ledger) => format!(" (expires at ledger {ledger})"),
                None => String::new(),
            };
            let _ = writeln!(
                out,
                "  {:<10} {:<28} = {}{} (ledger {})",
                entry.durability.as_str(),
                entry.key,
                entry.value,
                expiry,
                entry.ledger
            );
        }
        if self.is_last_page() {
            out.push_str("end of results\n");
        } else if let Some(cursor) = self.next_cursor {
            let _ = writeln!(out, "next cursor: {cursor}");
            if let Some(token) = &self.next_page_token {
                let _ = writeln!(out, "next page token: {token}");
            }
        }
        out
    }

    /// JSON rendering used by `--json` and by scripts.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }
}

/// Ordered, paginated view over contract state entries.
#[derive(Debug, Clone, Default)]
pub struct StateInspector {
    entries: BTreeMap<(Durability, String, String), StateEntry>,
}

impl StateInspector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds an inspector from a JSON array of [`StateEntry`] values.
    pub fn from_json(json: &str) -> Result<Self> {
        let entries: Vec<StateEntry> = serde_json::from_str(json)
            .map_err(|e| ToolkitError::ExecutionError(format!("parse state export: {e}")))?;
        let mut inspector = Self::new();
        for entry in entries {
            inspector.insert(entry);
        }
        Ok(inspector)
    }

    /// Loads a JSON state export from disk, returning the number of entries
    /// read from the file.
    pub fn load(&mut self, path: &Path) -> Result<usize> {
        let json = std::fs::read_to_string(path)?;
        let loaded = Self::from_json(&json)?;
        let count = loaded.entries.len();
        for entry in loaded.entries.into_values() {
            self.insert(entry);
        }
        Ok(count)
    }

    /// Inserts an entry, replacing an existing one with the same contract,
    /// durability and key. Returns `true` when an entry was replaced.
    pub fn insert(&mut self, entry: StateEntry) -> bool {
        let key = (
            entry.durability,
            entry.key.clone(),
            entry.contract_id.clone(),
        );
        self.entries.insert(key, entry).is_some()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries matching the filter, in a stable
    /// (durability, key, contract) order.
    #[must_use]
    pub fn filtered(&self, query: &StateQuery) -> Vec<&StateEntry> {
        self.entries
            .values()
            .filter(|entry| matches_query(entry, query))
            .collect()
    }

    #[must_use]
    pub fn total(&self, query: &StateQuery) -> usize {
        self.filtered(query).len()
    }

    /// Returns the page addressed by the query's legacy numeric cursor. A
    /// cursor past the end yields an empty last page instead of an error.
    ///
    /// This method does not consume opaque tokens; use [`Self::page_from_token`]
    /// for those.
    pub fn page(&self, query: &StateQuery) -> StatePage {
        self.page_at(query, query.cursor().min(self.total(query)))
    }

    /// Validates an opaque token against `query` and the current result set.
    ///
    /// Call this before producing output when a token is supplied by a caller,
    /// so a rejected cursor never leaves a half-written page behind.
    pub fn validate_page_token(&self, query: &StateQuery, token: &str) -> Result<PageCursor> {
        let cursor = PageCursor::parse(token, query)?;
        let total = self.total(query);
        if cursor.offset() > total {
            return Err(PageCursorError::OffsetOutOfRange {
                offset: cursor.offset(),
                total,
            }
            .into());
        }
        Ok(cursor)
    }

    /// Returns the page addressed by a token from a previous [`StatePage`].
    pub fn page_from_token(&self, query: &StateQuery, token: &str) -> Result<StatePage> {
        let cursor = self.validate_page_token(query, token)?;
        Ok(self.page_at(query, cursor.offset()))
    }

    fn page_at(&self, query: &StateQuery, offset: usize) -> StatePage {
        let matching = self.filtered(query);
        let total = matching.len();
        let page_size = query.page_size().max(1);
        let end = offset.saturating_add(page_size).min(total);
        let entries = matching[offset..end]
            .iter()
            .map(|entry| (*entry).clone())
            .collect::<Vec<_>>();
        let next_cursor = if end < total { Some(end) } else { None };
        let next_page_token = next_cursor.map(|next| PageCursor::issue(query, next).to_string());

        StatePage {
            contract_id: query.contract_id().map(str::to_string),
            page_index: offset / page_size,
            page_size,
            total,
            offset,
            entries,
            next_cursor,
            next_page_token,
            has_more: next_cursor.is_some(),
        }
    }

    /// Every page of the query, starting from the query cursor.
    #[must_use]
    pub fn pages(&self, query: &StateQuery) -> Vec<StatePage> {
        let mut pages = Vec::new();
        let mut cursor = query.cursor();
        loop {
            // `with_cursor` takes the builder by value, and `query` is borrowed.
            let page = self.page(&query.clone().with_cursor(cursor));
            if page.entries.is_empty() {
                return pages;
            }
            // The last page has no cursor of its own, so it has to be pushed
            // here: returning before this dropped it entirely.
            let next_cursor = page.next_cursor;
            pages.push(page);
            let Some(next) = next_cursor else {
                return pages;
            };
            cursor = next;
        }
    }

    /// Built-in sample export so the CLI is usable without a live RPC query.
    #[must_use]
    pub fn sample() -> Self {
        let mut inspector = Self::new();
        for entry in sample_entries() {
            inspector.insert(entry);
        }
        inspector
    }
}

fn matches_query(entry: &StateEntry, query: &StateQuery) -> bool {
    if let Some(contract_id) = query.contract_id() {
        if entry.contract_id != contract_id {
            return false;
        }
    }
    if let Some(prefix) = query.key_prefix() {
        if !entry.key.starts_with(prefix) {
            return false;
        }
    }
    if entry.durability == Durability::Temporary && !query.include_temporary() {
        return false;
    }
    true
}

fn sample_entries() -> Vec<StateEntry> {
    let pool = "CDEMO7POOLCONTRACTID";
    let factory = "CDEMO7FACTORYCONTRCT";
    vec![
        StateEntry {
            contract_id: pool.to_string(),
            durability: Durability::Instance,
            key: "Config".to_string(),
            value: "{\"fee_bps\":30,\"admin\":\"GADMIN\"}".to_string(),
            ledger: 1_204_881,
            live_until_ledger: None,
        },
        StateEntry {
            contract_id: pool.to_string(),
            durability: Durability::Persistent,
            key: "Reserves/A".to_string(),
            value: "10000000000".to_string(),
            ledger: 1_204_870,
            live_until_ledger: None,
        },
        StateEntry {
            contract_id: pool.to_string(),
            durability: Durability::Persistent,
            key: "Reserves/B".to_string(),
            value: "25000000000".to_string(),
            ledger: 1_204_870,
            live_until_ledger: None,
        },
        StateEntry {
            contract_id: pool.to_string(),
            durability: Durability::Persistent,
            key: "Lp/Balance/GTRADER".to_string(),
            value: "4213375".to_string(),
            ledger: 1_204_879,
            live_until_ledger: None,
        },
        StateEntry {
            contract_id: factory.to_string(),
            durability: Durability::Persistent,
            key: "Pool/CDEMO7POOLCONTRC".to_string(),
            value: pool.to_string(),
            ledger: 1_204_500,
            live_until_ledger: None,
        },
        StateEntry {
            contract_id: pool.to_string(),
            durability: Durability::Temporary,
            key: "Nonce/GTRADER".to_string(),
            value: "7".to_string(),
            ledger: 1_204_881,
            live_until_ledger: Some(1_214_881),
        },
        StateEntry {
            contract_id: factory.to_string(),
            durability: Durability::Temporary,
            key: "PendingInit/2".to_string(),
            value: "true".to_string(),
            ledger: 1_204_881,
            live_until_ledger: Some(1_214_881),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> StateInspector {
        StateInspector::sample()
    }

    #[test]
    fn test_sample_orders_entries_by_durability_then_key() {
        let inspector = sample();
        assert_eq!(inspector.len(), 7);
        let keys: Vec<String> = inspector
            .filtered(&StateQuery::new().including_temporary(true))
            .into_iter()
            .map(|entry| entry.key.clone())
            .collect();
        assert_eq!(
            keys,
            vec![
                "Config",
                "Lp/Balance/GTRADER",
                "Pool/CDEMO7POOLCONTRC",
                "Reserves/A",
                "Reserves/B",
                "Nonce/GTRADER",
                "PendingInit/2",
            ]
        );
    }

    #[test]
    fn test_pagination_walks_every_entry_once() {
        let inspector = sample();
        let query = StateQuery::new().with_page_size(2);
        let pages = inspector.pages(&query);
        assert_eq!(pages.len(), 3);
        assert_eq!(pages[0].offset, 0);
        assert_eq!(pages[0].next_cursor, Some(2));
        assert!(pages[2].is_last_page());
        assert!(pages.iter().all(|page| page.total == 5));

        let visited: Vec<String> = pages
            .iter()
            .flat_map(|page| page.entries.iter().map(|e| e.key.clone()))
            .collect();
        assert_eq!(visited.len(), 5);
        assert!(!visited.contains(&"Nonce/GTRADER".to_string()));
    }

    #[test]
    fn test_cursor_resumes_from_previous_page() {
        let inspector = sample();
        let first = inspector.page(&StateQuery::new().with_page_size(2));
        let cursor = first.next_cursor.unwrap();
        let second = inspector.page(&StateQuery::new().with_page_size(2).with_cursor(cursor));
        assert_eq!(second.page_index, 1);
        // Pages are cut from the (durability, key, contract) order pinned by
        // `test_sample_orders_entries_by_durability_then_key`. Temporary entries
        // are excluded by default, which leaves
        // `Config`, `Lp/Balance/GTRADER`, `Pool/CDEMO7POOLCONTRC`, ... — so the
        // second page of two starts at the factory's pool pointer.
        assert_eq!(second.entries[0].key, "Pool/CDEMO7POOLCONTRC");
        assert_eq!(second.next_cursor, Some(4));
    }

    #[test]
    fn test_cursor_past_end_returns_empty_last_page() {
        let inspector = sample();
        let page = inspector.page(&StateQuery::new().with_page_size(2).with_cursor(999));
        assert!(page.entries.is_empty());
        assert_eq!(page.next_cursor, None);
        assert!(page.is_last_page());
        assert_eq!(page.total, 5);
    }

    #[test]
    fn test_filters_narrow_the_result_set() {
        let inspector = sample();
        let query = StateQuery::new().for_contract("CDEMO7FACTORYCONTRCT");
        assert_eq!(inspector.total(&query), 1);

        let prefixed = StateQuery::new().with_key_prefix("Reserves/");
        assert_eq!(inspector.total(&prefixed), 2);

        let with_temporary = StateQuery::new().including_temporary(true);
        assert_eq!(inspector.total(&with_temporary), 7);
    }

    #[test]
    fn test_page_size_is_clamped() {
        assert_eq!(StateQuery::new().with_page_size(0).page_size(), 1);
        assert_eq!(
            StateQuery::new().with_page_size(10_000).page_size(),
            MAX_PAGE_SIZE
        );
    }

    #[test]
    fn test_from_json_round_trip_and_error() {
        let inspector = sample();
        let all = inspector
            .filtered(&StateQuery::new().including_temporary(true))
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let json = serde_json::to_string(&all).unwrap();
        let reloaded = StateInspector::from_json(&json).unwrap();
        assert_eq!(reloaded.len(), inspector.len());
        assert_eq!(reloaded.page(&StateQuery::new()).entries.len(), 5);
        assert!(StateInspector::from_json("not json").is_err());
    }

    #[test]
    fn test_load_reads_export_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(
            &path,
            r#"[{"contract_id":"CPOOL","durability":"persistent","key":"A","value":"1","ledger":7}]"#,
        )
        .unwrap();
        let mut inspector = StateInspector::new();
        assert_eq!(inspector.load(&path).unwrap(), 1);
        assert_eq!(inspector.load(&path).unwrap(), 1);
        assert_eq!(inspector.len(), 1);
        let page = inspector.page(&StateQuery::new());
        assert_eq!(page.entries[0].key, "A");
    }

    #[test]
    fn test_same_key_in_two_contracts_is_kept() {
        let mut inspector = StateInspector::new();
        for contract_id in ["CPOOLONE", "CPOOLTWO"] {
            assert!(!inspector.insert(StateEntry {
                contract_id: contract_id.to_string(),
                durability: Durability::Persistent,
                key: "Reserves/A".to_string(),
                value: contract_id.to_string(),
                ledger: 7,
                live_until_ledger: None,
            }));
        }
        assert_eq!(inspector.len(), 2);
        let values: Vec<String> = inspector
            .filtered(&StateQuery::new())
            .into_iter()
            .map(|entry| entry.value.clone())
            .collect();
        assert_eq!(values, vec!["CPOOLONE", "CPOOLTWO"]);

        assert!(inspector.insert(StateEntry {
            contract_id: "CPOOLONE".to_string(),
            durability: Durability::Persistent,
            key: "Reserves/A".to_string(),
            value: "replaced".to_string(),
            ledger: 8,
            live_until_ledger: None,
        }));
        assert_eq!(inspector.len(), 2);
    }

    #[test]
    fn test_render_and_json_include_cursor() {
        let inspector = sample();
        let page = inspector.page(&StateQuery::new().with_page_size(2));
        let text = page.render();
        assert!(text.contains("next cursor: 2"));
        assert!(text.contains("persistent"));
        assert!(text.contains("ledger 1204881"));
        let json = page.to_json();
        assert!(json.contains("\"next_cursor\": 2"));
        assert!(json.contains("\"has_more\": true"));
    }

    fn keys(page: &StatePage) -> Vec<String> {
        page.entries.iter().map(|entry| entry.key.clone()).collect()
    }

    /// Re-encode a cursor payload, refreshing its checksum (for negative tests).
    fn reencode(mut payload: Vec<u8>) -> String {
        payload.extend_from_slice(&checksum(&payload).to_be_bytes());
        format!("{PAGE_CURSOR_PREFIX}{}", hex::encode(payload))
    }

    #[test]
    fn test_opaque_cursor_walks_every_page_once() {
        let inspector = sample();
        let query = StateQuery::new().with_page_size(2);
        let mut token: Option<String> = None;
        let mut visited = Vec::new();
        let mut pages = 0;
        loop {
            let page = match &token {
                None => inspector.page(&query),
                Some(current) => inspector.page_from_token(&query, current).unwrap(),
            };
            assert_eq!(page.page_size, 2);
            visited.extend(keys(&page));
            pages += 1;
            assert!(pages <= 5, "cursor walk failed to terminate");
            match page.next_page_token {
                Some(next) => {
                    let decoded = PageCursor::parse(&next, &query).unwrap();
                    assert_eq!(decoded.offset(), page.offset + page.entries.len());
                    token = Some(next);
                }
                None => break,
            }
        }

        assert_eq!(pages, 3);
        let expected: Vec<String> = inspector
            .filtered(&query)
            .iter()
            .map(|entry| entry.key.clone())
            .collect();
        assert_eq!(visited, expected);
    }

    #[test]
    fn test_opaque_cursor_round_trip_preserves_filters() {
        let inspector = sample();
        let query = StateQuery::new()
            .for_contract("CDEMO7POOLCONTRACTID")
            .with_key_prefix("Reserves/")
            .including_temporary(true)
            .with_page_size(1);
        let first = inspector.page(&query);
        let token = first
            .next_page_token
            .clone()
            .expect("another reserve follows");
        let decoded = PageCursor::parse(&token, &query).unwrap();
        assert_eq!(decoded.offset(), 1);
        assert_eq!(decoded.page_size(), 1);
        assert_eq!(decoded.as_str(), token);

        let second = inspector.page_from_token(&query, &token).unwrap();
        assert_eq!(keys(&second), vec!["Reserves/B".to_string()]);
        assert!(second.next_page_token.is_none());
    }

    #[test]
    fn test_page_cursor_boundaries() {
        let inspector = sample();
        let query = StateQuery::new().with_page_size(2);
        let last = inspector.page(&query.clone().with_cursor(4));
        assert_eq!(keys(&last), vec!["Reserves/B".to_string()]);
        assert!(last.next_page_token.is_none());

        // A token pointing exactly at the end yields an empty terminal page.
        let end_token = PageCursor::issue(&query, 5).to_string();
        let empty = inspector.page_from_token(&query, &end_token).unwrap();
        assert!(empty.entries.is_empty());
        assert!(empty.next_page_token.is_none());
        assert!(empty.is_last_page());

        // An empty result set never issues a cursor.
        let no_matches = StateQuery::new().with_key_prefix("no-such-key");
        let page = inspector.page(&no_matches);
        assert_eq!(page.total, 0);
        assert!(page.next_page_token.is_none());
    }

    #[test]
    fn test_page_cursor_rejects_malformed_and_tampered_tokens() {
        let inspector = sample();
        let query = StateQuery::new().with_page_size(2);
        for bad in ["", "not-a-cursor", "s1.zz", "s1.00"] {
            let err = inspector.page_from_token(&query, bad).unwrap_err();
            assert!(
                matches!(
                    err,
                    ToolkitError::StateInspection(PageCursorError::Malformed(_))
                ),
                "expected a malformed-cursor error for {bad:?}, got {err:?}"
            );
        }

        let token = inspector.page(&query).next_page_token.unwrap();
        let mut corrupted = token.clone();
        let last = corrupted.pop().unwrap();
        corrupted.push(if last == '0' { '1' } else { '0' });
        let err = inspector.page_from_token(&query, &corrupted).unwrap_err();
        assert!(matches!(
            err,
            ToolkitError::StateInspection(PageCursorError::Corrupt)
        ));

        let bytes = hex::decode(token.strip_prefix(PAGE_CURSOR_PREFIX).unwrap()).unwrap();
        let mut payload = bytes[..bytes.len() - 4].to_vec();
        payload[0] = 2; // unknown version, with a valid checksum
        let err = inspector
            .page_from_token(&query, &reencode(payload.clone()))
            .unwrap_err();
        assert!(matches!(
            err,
            ToolkitError::StateInspection(PageCursorError::UnsupportedVersion {
                found: 2,
                expected: 1
            })
        ));

        payload[0] = PAGE_CURSOR_VERSION;
        payload.push(0xFF); // trailing junk is not a valid payload
        let err = inspector
            .page_from_token(&query, &reencode(payload))
            .unwrap_err();
        assert!(matches!(
            err,
            ToolkitError::StateInspection(PageCursorError::Malformed(_))
        ));
    }

    #[test]
    fn test_page_cursor_rejects_changed_query() {
        let inspector = sample();
        let query = StateQuery::new().with_page_size(2);
        let token = inspector.page(&query).next_page_token.unwrap();

        let changed_size = query.clone().with_page_size(3);
        let err = inspector
            .page_from_token(&changed_size, &token)
            .unwrap_err();
        assert!(matches!(
            &err,
            ToolkitError::StateInspection(PageCursorError::QueryMismatch {
                field: "page size",
                ..
            })
        ));
        assert!(err.to_string().contains("page size"));

        let scoped = query.clone().for_contract("CDEMO7POOLCONTRACTID");
        let err = inspector.page_from_token(&scoped, &token).unwrap_err();
        assert!(matches!(
            &err,
            ToolkitError::StateInspection(PageCursorError::QueryMismatch {
                field: "contract",
                ..
            })
        ));
        assert!(err.to_string().contains("all contracts"));

        let prefixed = query.clone().with_key_prefix("Reserves/");
        let err = inspector.page_from_token(&prefixed, &token).unwrap_err();
        assert!(matches!(
            &err,
            ToolkitError::StateInspection(PageCursorError::QueryMismatch {
                field: "key prefix",
                ..
            })
        ));

        let with_temporary = query.including_temporary(true);
        let err = inspector
            .page_from_token(&with_temporary, &token)
            .unwrap_err();
        assert!(matches!(
            &err,
            ToolkitError::StateInspection(PageCursorError::QueryMismatch {
                field: "include_temporary",
                ..
            })
        ));
    }

    #[test]
    fn test_page_cursor_rejects_stale_offset() {
        let inspector = sample();
        let query = StateQuery::new().with_page_size(2);
        let token = PageCursor::issue(&query, 8).to_string();
        let err = inspector.page_from_token(&query, &token).unwrap_err();
        assert!(matches!(
            err,
            ToolkitError::StateInspection(PageCursorError::OffsetOutOfRange {
                offset: 8,
                total: 5
            })
        ));

        // The same token is unusable against a smaller export.
        let smaller = StateInspector::from_json(
            r#"[{"contract_id":"CPOOL","durability":"persistent","key":"A","value":"1","ledger":7}]"#,
        )
        .unwrap();
        let err = smaller.page_from_token(&query, &token).unwrap_err();
        assert!(matches!(
            err,
            ToolkitError::StateInspection(PageCursorError::OffsetOutOfRange { total: 1, .. })
        ));
    }

    #[test]
    fn test_legacy_numeric_cursor_and_output_remain_compatible() {
        let inspector = sample();
        let query = StateQuery::new().with_page_size(2);
        let page = inspector.page(&query.clone().with_cursor(999));
        assert!(page.entries.is_empty());
        assert!(page.is_last_page());

        let page = inspector.page(&query);
        assert_eq!(page.next_cursor, Some(2));
        let text = page.render();
        assert!(text.contains("next cursor: 2"));
        assert!(text.contains("next page token: s1."));
        let json = page.to_json();
        assert!(json.contains("\"next_cursor\": 2"));
        assert!(json.contains("\"next_page_token\""));

        // The last page keeps the old JSON shape: no token is emitted.
        let last = inspector.page(&query.with_cursor(4));
        assert!(!last.to_json().contains("next_page_token"));
        assert!(last.render().contains("end of results"));
    }
}

//! Paginated contract state inspector (issue #244).
//!
//! Reads a contract state export (the entries returned by `getLedgerEntries` /
//! `getEvents` style queries) and serves it page by page with an opaque cursor,
//! so that inspecting a contract with thousands of keys stays readable and
//! scriptable.

use crate::error::{Result, ToolkitError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Number of entries returned when the caller does not pick a page size.
pub const DEFAULT_PAGE_SIZE: usize = 20;
/// Hard cap for a single page, keeping output (and terminals) sane.
pub const MAX_PAGE_SIZE: usize = 200;

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
    pub fn including_temporary(mut self, include_temporary: bool) -> Self {
        self.include_temporary = include_temporary;
        self
    }

    /// Page size is clamped to `1..=MAX_PAGE_SIZE`.
    pub fn with_page_size(mut self, page_size: usize) -> Self {
        self.page_size = page_size.clamp(1, MAX_PAGE_SIZE);
        self
    }

    /// Cursor returned by a previous page (`0` starts at the first entry).
    pub fn with_cursor(mut self, cursor: usize) -> Self {
        self.cursor = cursor;
        self
    }

    pub fn contract_id(&self) -> Option<&str> {
        self.contract_id.as_deref()
    }

    pub fn key_prefix(&self) -> Option<&str> {
        self.key_prefix.as_deref()
    }

    pub fn include_temporary(&self) -> bool {
        self.include_temporary
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }
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
    /// Cursor to pass to the next request, `None` on the last page.
    pub next_cursor: Option<usize>,
    pub has_more: bool,
}

impl StatePage {
    /// `true` when no further cursor is returned, i.e. this is the last page.
    pub fn is_last_page(&self) -> bool {
        !self.has_more
    }

    /// Human readable rendering used by the CLI.
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
            out.push_str(&format!(
                "  {:<10} {:<28} = {}{} (ledger {})\n",
                entry.durability.as_str(),
                entry.key,
                entry.value,
                expiry,
                entry.ledger
            ));
        }
        if self.is_last_page() {
            out.push_str("end of results\n");
        } else if let Some(cursor) = self.next_cursor {
            out.push_str(&format!("next cursor: {cursor}\n"));
        }
        out
    }

    /// JSON rendering used by `--json` and by scripts.
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

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries matching the filter, in a stable
    /// (durability, key, contract) order.
    pub fn filtered(&self, query: &StateQuery) -> Vec<&StateEntry> {
        self.entries
            .values()
            .filter(|entry| matches_query(entry, query))
            .collect()
    }

    pub fn total(&self, query: &StateQuery) -> usize {
        self.filtered(query).len()
    }

    /// Returns the page addressed by the query cursor. A cursor past the end
    /// yields an empty last page instead of an error.
    pub fn page(&self, query: &StateQuery) -> StatePage {
        let matching = self.filtered(query);
        let total = matching.len();
        let page_size = query.page_size().max(1);
        let offset = query.cursor().min(total);
        let end = offset.saturating_add(page_size).min(total);
        let entries = matching[offset..end]
            .iter()
            .map(|entry| (*entry).clone())
            .collect::<Vec<_>>();
        let next_cursor = if end < total { Some(end) } else { None };

        StatePage {
            contract_id: query.contract_id().map(str::to_string),
            page_index: offset / page_size,
            page_size,
            total,
            offset,
            entries,
            next_cursor,
            has_more: next_cursor.is_some(),
        }
    }

    /// Every page of the query, starting from the query cursor.
    pub fn pages(&self, query: &StateQuery) -> Vec<StatePage> {
        let mut pages = Vec::new();
        let mut cursor = query.cursor();
        loop {
            // `with_cursor` takes the builder by value, and `query` is borrowed.
            let page = self.page(&query.clone().with_cursor(cursor));
            if page.entries.is_empty() {
                return pages;
            }
            match page.next_cursor {
                Some(next) => {
                    cursor = next;
                    pages.push(page);
                }
                // The last page has no cursor of its own, so it has to be
                // pushed here: returning on `None` dropped it entirely.
                None => {
                    pages.push(page);
                    return pages;
                }
            }
        }
    }

    /// Built-in sample export so the CLI is usable without a live RPC query.
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
}

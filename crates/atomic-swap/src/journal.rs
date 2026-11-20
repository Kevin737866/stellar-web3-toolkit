//! Durable swap state-transition journal (issue #390).
//!
//! # The problem
//!
//! The coordinator used to change a swap's status in memory and only then hand
//! the change to the chain. If the process died between the two — or the chain
//! call failed after the in-memory state had already moved — the record and the
//! chain disagreed, and nothing on restart said which swaps were mid-flight.
//!
//! # The mechanism
//!
//! Every state transition is appended to a [`TransitionJournal`] *before* it is
//! applied in memory and before any chain action is submitted. A record carries
//! the full [`AtomicSwap`] snapshot it produced, so a fresh coordinator can
//! rehydrate from the journal alone ([`AtomicSwapCoordinator::recover_from_journal`]).
//!
//! A chain action is bracketed by two records: `ChainActionPending` written
//! before the action is submitted, and `ChainActionConfirmed`/`ChainActionFailed`
//! written after. A journal whose last record for a swap is `ChainActionPending`
//! therefore means "submitted, outcome unknown" — exactly the set an operator has
//! to reconcile after a restart.
//!
//! # Idempotency
//!
//! Each record carries an `idempotency_key`. Appending a key that is already
//! recorded is a no-op that returns the original record, so a retried transition
//! (or a replayed chain action) never duplicates journal entries. Reusing a key
//! for a *different* transition is refused with [`JournalError::Conflict`] rather
//! than silently rewriting history.
//!
//! # Scope
//!
//! This is single-process durability: one coordinator owns one journal. It does
//! not make two coordinators share a lock, and it does not by itself retry a
//! chain action — it records intent and outcome so that a retry (or a human) can
//! act on facts instead of guesses.

use crate::error::Result;
use crate::swap::AtomicSwap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use thiserror::Error;

/// What a [`TransitionRecord`] describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransitionKind {
    /// A swap was created and stored.
    Initiated,
    /// A chain action is about to be submitted. Written *before* the action.
    ChainActionPending { operation: String },
    /// The chain accepted the action.
    ChainActionConfirmed { operation: String },
    /// The chain action failed; `detail` is the action's own error.
    ChainActionFailed { operation: String, detail: String },
    /// The swap settled and the preimage was revealed.
    Settled,
    /// The swap was refunded after its timeout ledger.
    Refunded,
    /// The swap timed out at its timeout ledger without settling or refunding.
    Expired,
    /// The swap reached a terminal failure. `code` is
    /// [`SwapFailureReason::code`](crate::swap::SwapFailureReason::code).
    Failed { code: String },
}

/// One journal entry: a transition, the swap snapshot it produced, and the key
/// that makes re-appending it a no-op.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionRecord {
    pub swap_id: String,
    /// 1-based, dense position within this swap's journal. Assigned on append.
    pub seq: u64,
    /// Stable identity of this transition. Re-appending the same key is a no-op.
    pub idempotency_key: String,
    pub kind: TransitionKind,
    /// Ledger the transition was observed at.
    pub ledger: u32,
    /// Wall-clock seconds since the Unix epoch.
    pub recorded_at: u64,
    /// The swap as it stands once this transition is applied.
    pub snapshot: AtomicSwap,
}

impl TransitionRecord {
    fn new(swap: &AtomicSwap, kind: TransitionKind, ledger: u32, idempotency_key: String) -> Self {
        Self {
            swap_id: swap.id.clone(),
            seq: 0,
            idempotency_key,
            kind,
            ledger,
            recorded_at: current_timestamp(),
            snapshot: swap.clone(),
        }
    }

    pub fn initiated(swap: &AtomicSwap, ledger: u32) -> Self {
        Self::new(
            swap,
            TransitionKind::Initiated,
            ledger,
            format!("{}:initiated", swap.id),
        )
    }

    /// Intent to submit `operation`, recorded before the action runs.
    pub fn chain_action_pending(swap: &AtomicSwap, operation: &str, ledger: u32) -> Self {
        Self::new(
            swap,
            TransitionKind::ChainActionPending {
                operation: operation.to_string(),
            },
            ledger,
            format!("{}:chain_action:{operation}:pending", swap.id),
        )
    }

    pub fn chain_action_confirmed(swap: &AtomicSwap, operation: &str, ledger: u32) -> Self {
        Self::new(
            swap,
            TransitionKind::ChainActionConfirmed {
                operation: operation.to_string(),
            },
            ledger,
            format!("{}:chain_action:{operation}:confirmed", swap.id),
        )
    }

    pub fn chain_action_failed(
        swap: &AtomicSwap,
        operation: &str,
        detail: &str,
        ledger: u32,
    ) -> Self {
        Self::new(
            swap,
            TransitionKind::ChainActionFailed {
                operation: operation.to_string(),
                detail: detail.to_string(),
            },
            ledger,
            format!("{}:chain_action:{operation}:failed", swap.id),
        )
    }

    pub fn settled(swap: &AtomicSwap, ledger: u32) -> Self {
        Self::new(
            swap,
            TransitionKind::Settled,
            ledger,
            format!("{}:settled", swap.id),
        )
    }

    pub fn refunded(swap: &AtomicSwap, ledger: u32) -> Self {
        Self::new(
            swap,
            TransitionKind::Refunded,
            ledger,
            format!("{}:refunded", swap.id),
        )
    }

    /// The swap timed out at its timeout ledger.
    pub fn expired(swap: &AtomicSwap, ledger: u32) -> Self {
        Self::new(
            swap,
            TransitionKind::Expired,
            ledger,
            format!("{}:expired", swap.id),
        )
    }

    pub fn failed(swap: &AtomicSwap, code: &str, ledger: u32) -> Self {
        Self::new(
            swap,
            TransitionKind::Failed {
                code: code.to_string(),
            },
            ledger,
            format!("{}:failed:{code}", swap.id),
        )
    }

    /// The chain operation this record is about, if any.
    pub fn operation(&self) -> Option<&str> {
        match &self.kind {
            TransitionKind::ChainActionPending { operation }
            | TransitionKind::ChainActionConfirmed { operation }
            | TransitionKind::ChainActionFailed { operation, .. } => Some(operation),
            _ => None,
        }
    }
}

/// A chain action whose outcome was never recorded: submitted, then the process
/// stopped (or the confirming write failed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnresolvedAction {
    pub swap_id: String,
    pub operation: String,
    /// Ledger the intent was recorded at.
    pub ledger: u32,
}

/// Append-only journal of swap state transitions.
///
/// Implementations must be safe to share across tasks and must make `append`
/// idempotent per `idempotency_key`.
pub trait TransitionJournal: Send + Sync {
    /// Append `record`, assigning its `seq`. Returns the stored record — the
    /// original one when `record.idempotency_key` is already present.
    fn append(&self, record: TransitionRecord) -> Result<TransitionRecord>;

    /// Every record for `swap_id`, in append order.
    fn transitions(&self, swap_id: &str) -> Result<Vec<TransitionRecord>>;

    /// Ids of every swap the journal knows about.
    fn swap_ids(&self) -> Result<Vec<String>>;

    /// Chain actions that were submitted but never confirmed or failed.
    fn unresolved_actions(&self) -> Result<Vec<UnresolvedAction>> {
        let mut out = Vec::new();
        for swap_id in self.swap_ids()? {
            let records = self.transitions(&swap_id)?;
            if let Some(TransitionRecord {
                kind: TransitionKind::ChainActionPending { operation },
                ledger,
                ..
            }) = records.last()
            {
                out.push(UnresolvedAction {
                    swap_id: swap_id.clone(),
                    operation: operation.clone(),
                    ledger: *ledger,
                });
            }
        }
        Ok(out)
    }
}

/// Bind `record` into `existing`, returning it with its `seq` and whether it was
/// newly added. Re-using a key for a different transition is a conflict.
fn bind(
    existing: &mut Vec<TransitionRecord>,
    record: TransitionRecord,
) -> Result<(TransitionRecord, bool)> {
    if let Some(found) = existing
        .iter()
        .find(|r| r.idempotency_key == record.idempotency_key)
    {
        if found.kind != record.kind {
            return Err(JournalError::Conflict {
                key: record.idempotency_key,
            }
            .into());
        }
        return Ok((found.clone(), false));
    }
    let mut stored = record;
    stored.seq = existing.len() as u64 + 1;
    existing.push(stored.clone());
    Ok((stored, true))
}

/// Process-local journal. Loses its contents on restart; use [`FileJournal`]
/// when durability across restarts is required.
#[derive(Debug, Default)]
pub struct InMemoryJournal {
    records: Mutex<HashMap<String, Vec<TransitionRecord>>>,
}

impl InMemoryJournal {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TransitionJournal for InMemoryJournal {
    fn append(&self, record: TransitionRecord) -> Result<TransitionRecord> {
        let mut records = self.records.lock().expect("journal lock poisoned");
        let (stored, _) = bind(records.entry(record.swap_id.clone()).or_default(), record)?;
        Ok(stored)
    }

    fn transitions(&self, swap_id: &str) -> Result<Vec<TransitionRecord>> {
        let records = self.records.lock().expect("journal lock poisoned");
        Ok(records.get(swap_id).cloned().unwrap_or_default())
    }

    fn swap_ids(&self) -> Result<Vec<String>> {
        let records = self.records.lock().expect("journal lock poisoned");
        Ok(records.keys().cloned().collect())
    }
}

struct FileJournalState {
    records: HashMap<String, Vec<TransitionRecord>>,
    file: File,
}

/// JSON-lines journal backed by a file, so transitions survive a restart.
///
/// One record per line; the file is opened in append mode and flushed after
/// every write, so a crash can at worst lose the write in progress — never
/// reorder what was already recorded.
pub struct FileJournal {
    path: PathBuf,
    state: Mutex<FileJournalState>,
}

impl FileJournal {
    /// Open (creating if needed) the journal at `path`, loading any records
    /// already present.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let records = Self::load(&path)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(JournalError::from)?;
        Ok(Self {
            path,
            state: Mutex::new(FileJournalState { records, file }),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(path: &Path) -> Result<HashMap<String, Vec<TransitionRecord>>> {
        let mut records: HashMap<String, Vec<TransitionRecord>> = HashMap::new();
        if !path.exists() {
            return Ok(records);
        }
        let reader = BufReader::new(File::open(path).map_err(JournalError::from)?);
        for (index, line) in reader.lines().enumerate() {
            let line = line.map_err(JournalError::from)?;
            if line.trim().is_empty() {
                continue;
            }
            let record: TransitionRecord =
                serde_json::from_str(&line).map_err(|e| JournalError::Corrupt {
                    line: index + 1,
                    detail: e.to_string(),
                })?;
            records
                .entry(record.swap_id.clone())
                .or_default()
                .push(record);
        }
        Ok(records)
    }
}

impl TransitionJournal for FileJournal {
    fn append(&self, record: TransitionRecord) -> Result<TransitionRecord> {
        let mut state = self.state.lock().expect("journal lock poisoned");
        let entry = state.records.entry(record.swap_id.clone()).or_default();
        let (stored, is_new) = bind(entry, record)?;
        if is_new {
            let mut line = serde_json::to_string(&stored)?;
            line.push('\n');
            state
                .file
                .write_all(line.as_bytes())
                .map_err(JournalError::from)?;
            state.file.flush().map_err(JournalError::from)?;
        }
        Ok(stored)
    }

    fn transitions(&self, swap_id: &str) -> Result<Vec<TransitionRecord>> {
        let state = self.state.lock().expect("journal lock poisoned");
        Ok(state.records.get(swap_id).cloned().unwrap_or_default())
    }

    fn swap_ids(&self) -> Result<Vec<String>> {
        let state = self.state.lock().expect("journal lock poisoned");
        Ok(state.records.keys().cloned().collect())
    }
}

/// Journal failures.
#[derive(Error, Debug)]
pub enum JournalError {
    #[error("journal I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("journal line {line} is corrupt: {detail}")]
    Corrupt { line: usize, detail: String },

    #[error("journal key `{key}` is already bound to a different transition")]
    Conflict { key: String },
}

fn current_timestamp() -> u64 {
    chrono::Utc::now().timestamp() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::Asset;
    use crate::swap::SwapStatus;

    fn swap() -> AtomicSwap {
        AtomicSwap::new(
            "swap-1".to_string(),
            "GINITIATOR".to_string(),
            "GPARTICIPANT".to_string(),
            Asset::XLM,
            Asset::Custom("USDC".to_string()),
            1_000,
            500,
            "a".repeat(64),
            10_000,
            1_000,
        )
    }

    #[test]
    fn appending_assigns_dense_sequence_numbers() {
        let journal = InMemoryJournal::new();
        let swap = swap();

        let first = journal
            .append(TransitionRecord::initiated(&swap, 1_000))
            .unwrap();
        let second = journal
            .append(TransitionRecord::chain_action_pending(&swap, "lock", 1_001))
            .unwrap();

        assert_eq!(first.seq, 1);
        assert_eq!(second.seq, 2);
        assert_eq!(journal.transitions(&swap.id).unwrap().len(), 2);
    }

    #[test]
    fn re_appending_the_same_key_is_a_no_op() {
        let journal = InMemoryJournal::new();
        let swap = swap();

        let first = journal
            .append(TransitionRecord::initiated(&swap, 1_000))
            .unwrap();
        let replay = journal
            .append(TransitionRecord::initiated(&swap, 1_000))
            .unwrap();

        assert_eq!(first.seq, replay.seq);
        assert_eq!(first.idempotency_key, replay.idempotency_key);
        assert_eq!(first.recorded_at, replay.recorded_at);
        assert_eq!(journal.transitions(&swap.id).unwrap().len(), 1);
    }

    #[test]
    fn a_key_reused_for_a_different_transition_is_refused() {
        let journal = InMemoryJournal::new();
        let swap = swap();

        journal
            .append(TransitionRecord::initiated(&swap, 1_000))
            .unwrap();
        let mut forged = TransitionRecord::initiated(&swap, 1_000);
        forged.kind = TransitionKind::Settled;

        assert!(matches!(
            journal.append(forged),
            Err(crate::error::AtomicSwapError::Journal(
                JournalError::Conflict { .. }
            ))
        ));
    }

    #[test]
    fn unresolved_actions_lists_only_dangling_intents() {
        let journal = InMemoryJournal::new();
        let swap = swap();

        journal
            .append(TransitionRecord::initiated(&swap, 1_000))
            .unwrap();
        journal
            .append(TransitionRecord::chain_action_pending(&swap, "lock", 1_001))
            .unwrap();
        assert_eq!(
            journal.unresolved_actions().unwrap(),
            vec![UnresolvedAction {
                swap_id: swap.id.clone(),
                operation: "lock".to_string(),
                ledger: 1_001,
            }]
        );

        journal
            .append(TransitionRecord::chain_action_confirmed(
                &swap, "lock", 1_002,
            ))
            .unwrap();
        assert!(journal.unresolved_actions().unwrap().is_empty());
    }

    #[test]
    fn a_file_journal_survives_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swap-journal.jsonl");
        let mut swap = swap();

        {
            let journal = FileJournal::open(&path).unwrap();
            journal
                .append(TransitionRecord::initiated(&swap, 1_000))
                .unwrap();
            swap.mark_completed("deadbeef".to_string(), 1_500);
            journal
                .append(TransitionRecord::settled(&swap, 1_500))
                .unwrap();
        }

        let reopened = FileJournal::open(&path).unwrap();
        let records = reopened.transitions(&swap.id).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].kind, TransitionKind::Settled);
        assert_eq!(records[1].snapshot.status, SwapStatus::Completed);
    }

    #[test]
    fn a_corrupt_line_is_reported_with_its_number() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swap-journal.jsonl");
        std::fs::write(&path, "{\"not\":\"a record\"}\n").unwrap();

        assert!(matches!(
            FileJournal::open(&path),
            Err(crate::error::AtomicSwapError::Journal(
                JournalError::Corrupt { line: 1, .. }
            ))
        ));
    }
}

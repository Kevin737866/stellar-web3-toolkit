//! # Reorg Handling Module
//!
//! Ledger-reorg safety for local payment channel state.
//!
//! Stellar ledgers can be rolled back: a validator set briefly agrees on a
//! ledger that is later replaced by a longer chain. A payment accepted at a
//! height that no longer exists must not stay applied -- otherwise a channel
//! pair diverges on the sequence number and balances, and the next on-chain
//! settlement fails (or, worse, settles the wrong thing).
//!
//! The fix is to remember what the channel looked like at each ledger height
//! and, when a reorg is announced, restore every state at or below the fork
//! height. [`ReorgLog`] is that per-channel history; [`crate::ChannelManager`]
//! records into it on every applied update and exposes
//! [`crate::ChannelManager::handle_reorg`].

use crate::LocalChannelState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// How many past heights a channel keeps by default.
///
/// A reorg deeper than the retained history cannot be reconciled locally: the
/// channel has to be re-read from chain. 32 ledgers is comfortably longer than
/// the deepest rollback Stellar has produced, while staying cheap to hold.
pub const DEFAULT_REORG_HISTORY_DEPTH: u32 = 32;

/// Errors raised while recording or replaying channel history.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ReorgError {
    #[error(
        "ledger height {height} is not after the last recorded height {last} for this channel"
    )]
    NonMonotonicHeight { last: u32, height: u32 },

    #[error("no channel state recorded at or below ledger height {height}")]
    NoSnapshotAtOrBelow { height: u32 },
}

/// A channel state as it stood at a given ledger height.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LedgerSnapshot {
    /// Height the state was observed at.
    pub ledger_height: u32,
    /// The channel state after that height was applied.
    pub state: LocalChannelState,
}

/// Ordered snapshot history for a single channel.
///
/// Heights are strictly increasing: an update that claims a height the log has
/// already passed is exactly the signal that the chain forked, so [`ReorgLog::record`]
/// refuses it instead of silently overwriting history the caller may still need.
#[derive(Debug, Clone)]
pub struct ReorgLog {
    snapshots: BTreeMap<u32, LocalChannelState>,
    max_depth: usize,
}

impl ReorgLog {
    /// Create an empty log that retains at most `max_depth` heights.
    pub fn new(max_depth: u32) -> Self {
        ReorgLog {
            snapshots: BTreeMap::new(),
            // A log with no depth could never answer a rollback question.
            max_depth: max_depth.max(1) as usize,
        }
    }

    /// Create a log with [`DEFAULT_REORG_HISTORY_DEPTH`].
    pub fn with_default_depth() -> Self {
        Self::new(DEFAULT_REORG_HISTORY_DEPTH)
    }

    /// Retained height count.
    pub fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// Number of recorded heights.
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// Whether nothing has been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    /// The most recent recorded height, if any.
    pub fn last_height(&self) -> Option<u32> {
        self.snapshots.keys().next_back().copied()
    }

    /// Record the channel state that applied at `ledger_height`.
    ///
    /// Returns `false` if history had to be trimmed to stay within
    /// `max_depth`, so callers can tell that an old rollback may no longer be
    /// answerable.
    pub fn record(
        &mut self,
        ledger_height: u32,
        state: LocalChannelState,
    ) -> Result<bool, ReorgError> {
        if let Some(last) = self.last_height() {
            if ledger_height <= last {
                return Err(ReorgError::NonMonotonicHeight {
                    last,
                    height: ledger_height,
                });
            }
        }

        self.snapshots.insert(ledger_height, state);

        let mut trimmed = false;
        while self.snapshots.len() > self.max_depth {
            // `pop_first` drops the oldest height.
            self.snapshots.pop_first();
            trimmed = true;
        }

        Ok(trimmed)
    }

    /// The newest state recorded at or below `ledger_height`.
    pub fn snapshot_at_or_below(&self, ledger_height: u32) -> Option<LedgerSnapshot> {
        self.snapshots
            .range(..=ledger_height)
            .next_back()
            .map(|(height, state)| LedgerSnapshot {
                ledger_height: *height,
                state: state.clone(),
            })
    }

    /// Drop every snapshot above `ledger_height` and return the state to
    /// restore, together with how many snapshots were discarded.
    ///
    /// `None` means there is no recorded history at or below the fork, so the
    /// caller must resync the channel from chain rather than guess.
    pub fn rollback_to(&mut self, ledger_height: u32) -> (Option<LocalChannelState>, usize) {
        let restored = self
            .snapshots
            .range(..=ledger_height)
            .next_back()
            .map(|(height, state)| LedgerSnapshot {
                ledger_height: *height,
                state: state.clone(),
            });

        let discarded_heights: Vec<u32> = self
            .snapshots
            .range((ledger_height.saturating_add(1))..)
            .map(|(height, _)| *height)
            .collect();

        for height in &discarded_heights {
            self.snapshots.remove(height);
        }

        (
            restored.map(|snapshot| snapshot.state),
            discarded_heights.len(),
        )
    }

    /// The height of the newest snapshot at or below `ledger_height`.
    pub fn height_at_or_below(&self, ledger_height: u32) -> Option<u32> {
        self.snapshots
            .range(..=ledger_height)
            .next_back()
            .map(|(h, _)| *h)
    }

    /// Recorded heights, oldest first.
    pub fn heights(&self) -> Vec<u32> {
        self.snapshots.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChannelStatus, CloseReason, HtlcDirection, HtlcState};

    fn state(sequence_number: u32, our_balance: i128) -> LocalChannelState {
        LocalChannelState {
            channel_id: "ch".to_string(),
            our_address: "alice".to_string(),
            their_address: "bob".to_string(),
            our_balance,
            their_balance: 1_000 - our_balance,
            status: ChannelStatus::Open,
            close_reason: CloseReason::NotClosed,
            sequence_number,
            funding_tx_hash: None,
            closing_tx_hash: None,
            timeout: 100,
            fee_percentage: 0,
            pending_htlcs: Vec::new(),
            local_secret: vec![1, 2, 3],
            remote_public_key: vec![4, 5, 6],
        }
    }

    #[test]
    fn records_and_restores_state_at_a_height() {
        let mut log = ReorgLog::new(8);
        log.record(10, state(1, 900)).unwrap();
        log.record(11, state(2, 800)).unwrap();
        log.record(12, state(3, 700)).unwrap();

        assert_eq!(log.last_height(), Some(12));

        let (restored, dropped) = log.rollback_to(10);
        assert_eq!(dropped, 2);
        assert_eq!(restored.unwrap().sequence_number, 1);
        assert_eq!(log.last_height(), Some(10));
    }

    #[test]
    fn rollback_between_heights_keeps_the_newest_earlier_state() {
        let mut log = ReorgLog::new(8);
        log.record(10, state(1, 900)).unwrap();
        log.record(14, state(5, 500)).unwrap();

        let (restored, dropped) = log.rollback_to(12);
        assert_eq!(dropped, 1);
        assert_eq!(restored.unwrap().sequence_number, 1);
        assert_eq!(log.height_at_or_below(12), Some(10));
    }

    #[test]
    fn rollback_before_any_history_reports_nothing_to_restore() {
        let mut log = ReorgLog::new(8);
        log.record(10, state(1, 900)).unwrap();

        // Nothing was recorded at or below the fork, so the caller has no local
        // state to fall back on -- and the snapshot above it is no longer on
        // any chain, so it is dropped too.
        let (restored, dropped) = log.rollback_to(4);
        assert!(restored.is_none());
        assert_eq!(dropped, 1);
        assert!(log.is_empty());
    }

    #[test]
    fn non_monotonic_heights_are_rejected() {
        let mut log = ReorgLog::new(8);
        log.record(10, state(1, 900)).unwrap();

        for height in [9, 10] {
            let err = log.record(height, state(2, 800)).unwrap_err();
            assert_eq!(err, ReorgError::NonMonotonicHeight { last: 10, height });
        }

        // The rejected updates left the log alone.
        assert_eq!(log.len(), 1);
        assert_eq!(log.last_height(), Some(10));
    }

    #[test]
    fn history_is_trimmed_to_max_depth_oldest_first() {
        let mut log = ReorgLog::new(3);
        for height in 1..=5 {
            log.record(height, state(height, 1_000)).unwrap();
        }

        assert_eq!(log.heights(), vec![3, 4, 5]);
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn record_reports_when_history_was_trimmed() {
        let mut log = ReorgLog::new(2);
        assert!(!log.record(1, state(1, 900)).unwrap());
        assert!(!log.record(2, state(2, 800)).unwrap());
        assert!(log.record(3, state(3, 700)).unwrap());
    }

    #[test]
    fn zero_depth_still_retains_the_latest_height() {
        let mut log = ReorgLog::new(0);
        log.record(1, state(1, 900)).unwrap();
        log.record(2, state(2, 800)).unwrap();

        assert_eq!(log.len(), 1);
        assert_eq!(log.last_height(), Some(2));
    }

    #[test]
    fn snapshot_at_or_below_matches_rollback() {
        let mut log = ReorgLog::new(8);
        log.record(3, state(1, 900)).unwrap();
        log.record(6, state(2, 800)).unwrap();

        assert_eq!(log.snapshot_at_or_below(4).unwrap().ledger_height, 3);
        assert_eq!(log.snapshot_at_or_below(6).unwrap().ledger_height, 6);
        assert!(log.snapshot_at_or_below(2).is_none());

        // Reading does not mutate the log.
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn pending_htlcs_are_rolled_back_with_the_balances() {
        let mut log = ReorgLog::new(8);
        let mut before = state(1, 900);
        log.record(10, before.clone()).unwrap();

        before.sequence_number = 2;
        before.our_balance = 400;
        before.pending_htlcs.push(HtlcState {
            htlc_id: "htlc-1".to_string(),
            amount: 500,
            hashlock: vec![9; 32],
            timelock: 50,
            is_claimed: false,
            is_refunded: false,
            preimage: None,
            direction: HtlcDirection::Outgoing,
        });
        log.record(11, before).unwrap();

        let (restored, _) = log.rollback_to(10);
        let restored = restored.unwrap();
        assert_eq!(restored.our_balance, 900);
        assert!(restored.pending_htlcs.is_empty());
    }
}

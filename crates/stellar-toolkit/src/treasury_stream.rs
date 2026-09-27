//! Treasury streaming: scheduled / vested disbursement out of a treasury.
//!
//! A [`Treasury`] holds a balance and a set of **streams**. Opening a stream
//! escrows a total amount and releases it to a recipient in equal tranches on
//! a fixed interval, rather than paying the whole amount up front.
//!
//! This is the deferred-payment primitive a payment-channel toolkit is already
//! built around: a payment channel *is* a promise to pay later, and a stream is
//! the same promise with a release schedule attached. It also mirrors the
//! time-based patterns already in this crate — [`crate::session_keys::SessionPolicy`]
//! carries an `expires_at`, and a `RecoveryRequest` carries a `created_at` —
//! with the same rule: **time is always passed in as `now: u64`, never read
//! from the clock**, so every path below is deterministic under test.
//!
//! # Granularity
//!
//! A stream splits `total_amount` evenly across `tranches` releases, the first
//! at `start_at` and each subsequent one every `interval_secs`. Linear vesting
//! is the only shape implemented: it is the common case (a team payroll, a
//! grant, a contributor vesting schedule), and a single closed form covers it.
//! Irregular per-tranche amounts would need a separate schedule type and are
//! deliberately not built here.
//!
//! # Rounding rule
//!
//! Amounts are `i128` stroops throughout. **No floating point is used anywhere**;
//! a stroop is indivisible and rounding a fractional stroop is meaningless.
//!
//! Tranche `k` (0-based) is worth:
//!
//! ```text
//! base      = total_amount / tranches      (truncating, floor for non-negative)
//! remainder = total_amount % tranches
//! tranche(k) = base          if k <  tranches - 1
//! tranche(k) = base + remainder if k == tranches - 1
//! ```
//!
//! The **sub-stroop remainder is absorbed by the final tranche**. The
//! alternative — handing one extra stroop to each of the first `remainder`
//! tranches — reconciles just as exactly, but it makes the early tranches
//! non-uniform, which in turn complicates the cumulative-release closed form
//! and the `elapsed_tranches` accounting that callers depend on. Putting the
//! dust in the last tranche keeps every tranche but the last identical, so
//! cumulative release after `v` vested tranches is simply `v * base`.
//!
//! The invariant this buys, asserted in the tests, is that the tranche amounts
//! sum to `total_amount` **exactly** — no stroop is ever lost or invented:
//!
//! ```text
//! (tranches - 1) * base + (base + remainder) == total_amount
//! ```
//!
//! # Escrow
//!
//! Opening a stream debits the treasury balance immediately. The escrowed
//! amount is not the treasury's to spend, so a balance can never be
//! double-promised across streams. `cancel_stream` returns the unvested
//! remainder to the balance.
//!
//! # Cancellation
//!
//! Cancelling stops all future releases and refunds `total - released` back to
//! the treasury. It is a normal outcome, not an error path for the *caller* —
//! cancelling an already-cancelled stream is an error, but a stream that has
//! fully vested can still be cancelled (it refunds 0). Vested-but-unclaimed
//! tranches are refunded along with the rest; a cancelled stream is not
//! "paused", it is closed, and only [`Treasury::claim`] moves funds to a
//! recipient while a stream is live.

use crate::error::{Result, ToolkitError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Lifecycle position of a stream at a given instant.
///
/// A bare `i128` releasable amount loses the difference between "nothing has
/// happened yet" and "everything has", and callers cannot tell a cancelled
/// stream from a drained one. This enum keeps those distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamStatus {
    /// `now` is before `start_at`; nothing has vested.
    NotStarted {
        /// Seconds until the first tranche vests.
        starts_in: u64,
    },
    /// Some, but not all, tranches have vested.
    Active {
        /// Tranches that have vested so far (1..tranches).
        elapsed_tranches: u32,
        /// Total tranches in the stream.
        total_tranches: u32,
        /// Amount vested so far, including anything already released.
        vested: i128,
        /// Vested amount not yet released to the recipient.
        pending: i128,
    },
    /// Every tranche has vested and been released.
    Completed {
        /// Total amount released across the stream's life.
        released: i128,
    },
    /// The stream was cancelled; no further releases will occur.
    Cancelled {
        /// Amount already released to the recipient before cancellation.
        released: i128,
        /// Unvested amount returned to the treasury balance.
        refunded: i128,
        /// The `now` at which the cancellation took effect.
        cancelled_at: u64,
    },
}

impl StreamStatus {
    /// Amount already released to the recipient, across every status.
    pub fn released(&self) -> i128 {
        match self {
            Self::NotStarted { .. } => 0,
            Self::Active {
                vested, pending, ..
            } => vested - pending,
            Self::Completed { released } => *released,
            Self::Cancelled { released, .. } => *released,
        }
    }

    /// Amount currently sitting in the stream unreleased, across every status.
    ///
    /// Zero for a cancelled stream: its unvested balance went back to the
    /// treasury rather than remaining claimable.
    pub fn pending(&self) -> i128 {
        match self {
            Self::NotStarted { .. } | Self::Completed { .. } | Self::Cancelled { .. } => 0,
            Self::Active { pending, .. } => *pending,
        }
    }
}

/// The result of claiming from a stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamRelease {
    pub stream_id: String,
    pub recipient: String,
    /// Amount moved to the recipient by *this* call. May be 0 when the
    /// recipient is not yet eligible — claiming early is not an error.
    pub amount: i128,
    /// Total released from this stream over its whole life, including this call.
    pub cumulative_released: i128,
    /// Stream position *after* this claim.
    pub status: StreamStatus,
}

/// Outcome of cancelling a stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamCancellation {
    pub stream_id: String,
    pub recipient: String,
    /// Amount returned to the treasury balance.
    pub refunded: i128,
    /// Amount already released to the recipient before cancellation.
    pub released: i128,
    pub cancelled_at: u64,
}

/// A single scheduled disbursement from the treasury.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreasuryStream {
    pub stream_id: String,
    pub recipient: String,
    /// Full amount escrowed when the stream was opened.
    pub total_amount: i128,
    /// Timestamp at which the first tranche vests.
    pub start_at: u64,
    /// Seconds between consecutive tranches. Always > 0.
    pub interval_secs: u64,
    /// Number of equal tranches. Always >= 1.
    pub tranches: u32,
    /// Amount already released to the recipient.
    pub released: i128,
    /// Set once the stream is cancelled; blocks further claims.
    pub cancelled_at: Option<u64>,
}

impl TreasuryStream {
    /// Value of every tranche but the last.
    fn base_tranche(&self) -> i128 {
        self.total_amount / i128::from(self.tranches)
    }

    /// Sub-stroop remainder absorbed by the final tranche.
    fn remainder(&self) -> i128 {
        self.total_amount % i128::from(self.tranches)
    }

    /// Value of tranche `k` (0-based). The last tranche carries the remainder.
    fn tranche_amount(&self, k: u32) -> Result<i128> {
        debug_assert!(k < self.tranches);
        let base = self.base_tranche();
        if k == self.tranches - 1 {
            base.checked_add(self.remainder()).ok_or_else(|| {
                ToolkitError::AmountOverflow(format!(
                    "tranche {} of stream {} overflows i128",
                    k, self.stream_id
                ))
            })
        } else {
            Ok(base)
        }
    }

    /// Sum of all tranche amounts — the reconciliation invariant.
    pub fn total_tranche_amounts(&self) -> Result<i128> {
        let mut sum: i128 = 0;
        for k in 0..self.tranches {
            sum = sum.checked_add(self.tranche_amount(k)?).ok_or_else(|| {
                ToolkitError::AmountOverflow(format!("tranche sum overflow for {}", self.stream_id))
            })?;
        }
        Ok(sum)
    }

    /// Number of tranches that have vested as of `now`.
    ///
    /// Tranche `k` vests at `start_at + k * interval_secs`, so tranche 0 vests
    /// the instant the stream starts. The `+ 1` accounts for that; `interval_secs`
    /// is validated to be non-zero at open time, so there is no division by zero.
    pub fn vested_tranches(&self, now: u64) -> u32 {
        if now < self.start_at {
            return 0;
        }
        let elapsed = now - self.start_at;
        // Capped at `tranches`, so the narrowing below is always lossless.
        (elapsed / self.interval_secs + 1).min(u64::from(self.tranches)) as u32
    }

    /// Total amount vested (released + pending) as of `now`.
    pub fn vested_amount(&self, now: u64) -> Result<i128> {
        let vested = self.vested_tranches(now);
        if vested == 0 {
            return Ok(0);
        }
        if vested >= self.tranches {
            // Every tranche is out, remainder included.
            return Ok(self.total_amount);
        }
        // Only uniform base tranches have vested so far.
        self.base_tranche()
            .checked_mul(i128::from(vested))
            .ok_or_else(|| {
                ToolkitError::AmountOverflow(format!(
                    "vested amount overflows i128 for stream {}",
                    self.stream_id
                ))
            })
    }
}

/// A treasury balance plus the streams drawing down it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Treasury {
    pub treasury_id: String,
    /// Spendable balance, excluding amounts escrowed in open streams.
    pub balance: i128,
    streams: HashMap<String, TreasuryStream>,
}

impl Treasury {
    /// Creates an empty treasury with the given spendable balance.
    pub fn new(treasury_id: impl Into<String>, balance: i128) -> Result<Self> {
        if balance < 0 {
            return Err(ToolkitError::Treasury(format!(
                "treasury balance must be non-negative, got {balance}"
            )));
        }
        Ok(Self {
            treasury_id: treasury_id.into(),
            balance,
            streams: HashMap::new(),
        })
    }

    /// Current spendable balance, in stroops.
    pub fn balance(&self) -> i128 {
        self.balance
    }

    /// Number of open (not yet cancelled) streams.
    pub fn open_stream_count(&self) -> usize {
        self.streams
            .values()
            .filter(|s| s.cancelled_at.is_none())
            .count()
    }

    /// Total currently escrowed across all live streams.
    pub fn escrowed(&self) -> i128 {
        self.streams
            .values()
            .filter(|s| s.cancelled_at.is_none())
            .map(|s| s.total_amount - s.released)
            .sum()
    }

    /// Borrow a stream by id.
    pub fn get_stream(&self, stream_id: &str) -> Result<&TreasuryStream> {
        self.streams
            .get(stream_id)
            .ok_or_else(|| ToolkitError::StreamNotFound(stream_id.to_string()))
    }

    /// Borrow a stream by id for mutation.
    fn get_stream_mut(&mut self, stream_id: &str) -> Result<&mut TreasuryStream> {
        self.streams
            .get_mut(stream_id)
            .ok_or_else(|| ToolkitError::StreamNotFound(stream_id.to_string()))
    }

    /// Add to the treasury balance, rejecting overflow rather than wrapping.
    pub fn deposit(&mut self, amount: i128) -> Result<i128> {
        if amount <= 0 {
            return Err(ToolkitError::Treasury(format!(
                "deposit amount must be positive, got {amount}"
            )));
        }
        self.balance = self
            .balance
            .checked_add(amount)
            .ok_or_else(|| ToolkitError::AmountOverflow("deposit overflows i128".to_string()))?;
        Ok(self.balance)
    }

    /// Open a stream, escrowing `total_amount` from the balance immediately.
    ///
    /// The first tranche vests at `start_at`; the remaining `tranches - 1` vest
    /// every `interval_secs` after that.
    pub fn open_stream(
        &mut self,
        stream_id: impl Into<String>,
        recipient: impl Into<String>,
        total_amount: i128,
        start_at: u64,
        interval_secs: u64,
        tranches: u32,
    ) -> Result<()> {
        let stream_id = stream_id.into();
        if self.streams.contains_key(&stream_id) {
            return Err(ToolkitError::Treasury(format!(
                "stream {stream_id} already exists"
            )));
        }
        if total_amount <= 0 {
            return Err(ToolkitError::InvalidSchedule(format!(
                "total_amount must be positive, got {total_amount}"
            )));
        }
        if tranches == 0 {
            return Err(ToolkitError::InvalidSchedule(
                "tranches must be at least 1".to_string(),
            ));
        }
        if interval_secs == 0 {
            return Err(ToolkitError::InvalidSchedule(
                "interval_secs must be greater than 0".to_string(),
            ));
        }
        if self.balance < total_amount {
            return Err(ToolkitError::InsufficientBalance(
                self.balance,
                total_amount,
            ));
        }

        // Escrow up front so the same balance cannot be promised twice.
        self.balance -= total_amount;
        self.streams.insert(
            stream_id.clone(),
            TreasuryStream {
                stream_id,
                recipient: recipient.into(),
                total_amount,
                start_at,
                interval_secs,
                tranches,
                released: 0,
                cancelled_at: None,
            },
        );
        Ok(())
    }

    /// Where a stream stands at `now`, without moving any funds.
    pub fn status(&self, stream_id: &str, now: u64) -> Result<StreamStatus> {
        let stream = self.get_stream(stream_id)?;
        Ok(status_of(stream, now))
    }

    /// Release everything vested to the recipient as of `now`.
    ///
    /// Claiming before the first tranche vests is **not** an error: it returns
    /// `amount == 0` and a `NotStarted` status, which is what makes the call
    /// safe to poll. Claiming a cancelled stream is an error, because the
    /// funds have gone back to the treasury and re-paying them would be a bug.
    pub fn claim(&mut self, stream_id: &str, now: u64) -> Result<StreamRelease> {
        let stream = self.get_stream_mut(stream_id)?;
        if let Some(cancelled_at) = stream.cancelled_at {
            return Err(ToolkitError::StreamCancelled(format!(
                "{stream_id} (cancelled at {cancelled_at})"
            )));
        }

        let vested = stream.vested_amount(now)?;
        let amount = vested - stream.released;
        if amount < 0 {
            return Err(ToolkitError::Treasury(format!(
                "stream {stream_id} has released more than it vested"
            )));
        }

        stream.released = stream.released.checked_add(amount).ok_or_else(|| {
            ToolkitError::AmountOverflow(format!("release overflows i128 for {stream_id}"))
        })?;
        if stream.released > stream.total_amount {
            return Err(ToolkitError::AmountOverflow(format!(
                "stream {stream_id} released {} which exceeds its total {}",
                stream.released, stream.total_amount
            )));
        }

        Ok(StreamRelease {
            stream_id: stream.stream_id.clone(),
            recipient: stream.recipient.clone(),
            amount,
            cumulative_released: stream.released,
            status: status_of(stream, now),
        })
    }

    /// Stop a stream and refund its unvested remainder to the treasury balance.
    ///
    /// The refund is `total_amount - released`, so every stroop the treasury
    /// escrowed is accounted for: released goes to the recipient, refunded
    /// goes back to the balance. Cancelling a fully-vested stream is legal and
    /// refunds 0; cancelling twice is an error.
    pub fn cancel_stream(&mut self, stream_id: &str, now: u64) -> Result<StreamCancellation> {
        // Scope the mutable stream borrow so it ends before `self.balance` is
        // touched again.
        let (refunded, released) = {
            let stream = self.get_stream_mut(stream_id)?;
            if let Some(cancelled_at) = stream.cancelled_at {
                return Err(ToolkitError::StreamCancelled(format!(
                    "{stream_id} (already cancelled at {cancelled_at})"
                )));
            }

            let refunded = stream.total_amount - stream.released;
            stream.cancelled_at = Some(now);
            (refunded, stream.released)
        };

        self.balance = self
            .balance
            .checked_add(refunded)
            .ok_or_else(|| ToolkitError::AmountOverflow("refund overflows i128".to_string()))?;

        Ok(StreamCancellation {
            stream_id: stream_id.to_string(),
            recipient: self.get_stream(stream_id)?.recipient.clone(),
            refunded,
            released,
            cancelled_at: now,
        })
    }
}

/// Derive a stream's status from its own fields. Shared by `status` and `claim`
/// so a reported status always reflects post-claim state.
fn status_of(stream: &TreasuryStream, now: u64) -> StreamStatus {
    if let Some(cancelled_at) = stream.cancelled_at {
        return StreamStatus::Cancelled {
            released: stream.released,
            refunded: stream.total_amount - stream.released,
            cancelled_at,
        };
    }
    let vested_tranches = stream.vested_tranches(now);
    if vested_tranches == 0 {
        return StreamStatus::NotStarted {
            starts_in: stream.start_at - now,
        };
    }
    let vested = stream.vested_amount(now).unwrap_or(0);
    if vested_tranches >= stream.tranches && stream.released >= stream.total_amount {
        return StreamStatus::Completed {
            released: stream.released,
        };
    }
    StreamStatus::Active {
        elapsed_tranches: vested_tranches,
        total_tranches: stream.tranches,
        vested,
        pending: vested - stream.released,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn treasury_with_stream(total: i128, start_at: u64, interval: u64, tranches: u32) -> Treasury {
        let mut t = Treasury::new("treasury_1", total + 1_000_000).unwrap();
        t.open_stream("s1", "GRECIPIENT", total, start_at, interval, tranches)
            .unwrap();
        t
    }

    #[test]
    fn test_tranche_amounts_reconcile_exactly() {
        // 100 split 3 ways does not divide evenly: 33 + 33 + 34.
        let t = treasury_with_stream(100, 0, 10, 3);
        let s = t.get_stream("s1").unwrap();
        assert_eq!(s.tranche_amount(0).unwrap(), 33);
        assert_eq!(s.tranche_amount(1).unwrap(), 33);
        assert_eq!(s.tranche_amount(2).unwrap(), 34);
        assert_eq!(s.total_tranche_amounts().unwrap(), 100);
    }

    #[test]
    fn test_no_stroop_is_lost_across_awkward_splits() {
        // Every total/interval combination must reconcile to the total exactly.
        for total in [1i128, 2, 7, 99, 100, 1_000, 1_234_567, 999_999_937] {
            for tranches in [1u32, 2, 3, 4, 7, 11, 60] {
                let mut t = Treasury::new("t", total).unwrap();
                t.open_stream("s", "r", total, 0, 60, tranches).unwrap();
                let s = t.get_stream("s").unwrap();
                assert_eq!(
                    s.total_tranche_amounts().unwrap(),
                    total,
                    "split lost or invented a stroop: total={total} tranches={tranches}"
                );
            }
        }
    }

    #[test]
    fn test_single_tranche_releases_everything_at_once() {
        let mut t = treasury_with_stream(500, 1000, 60, 1);

        // Not yet started.
        let r = t.claim("s1", 999).unwrap();
        assert_eq!(r.amount, 0);
        assert!(matches!(r.status, StreamStatus::NotStarted { .. }));

        // Single tranche vests exactly at start_at, remainder and all.
        let r = t.claim("s1", 1000).unwrap();
        assert_eq!(r.amount, 500);
        assert_eq!(r.cumulative_released, 500);
        assert_eq!(r.status, StreamStatus::Completed { released: 500 });

        // Nothing more is ever released.
        let r = t.claim("s1", 100_000).unwrap();
        assert_eq!(r.amount, 0);
    }

    #[test]
    fn test_zero_amount_is_rejected_at_open() {
        let mut t = Treasury::new("t", 1000).unwrap();
        assert!(matches!(
            t.open_stream("s", "r", 0, 0, 10, 3).unwrap_err(),
            ToolkitError::InvalidSchedule(_)
        ));
    }

    #[test]
    fn test_invalid_schedules_are_rejected() {
        let mut t = Treasury::new("t", 1000).unwrap();
        assert!(matches!(
            t.open_stream("s", "r", 100, 0, 0, 3).unwrap_err(),
            ToolkitError::InvalidSchedule(_)
        ));
        assert!(matches!(
            t.open_stream("s", "r", 100, 0, 10, 0).unwrap_err(),
            ToolkitError::InvalidSchedule(_)
        ));
        assert!(t.open_stream("s", "r", 100, 0, 10, 3).is_ok());
        // Re-opening the same id is refused.
        assert!(t.open_stream("s", "r2", 100, 0, 10, 3).is_err());
    }

    #[test]
    fn test_not_yet_eligible_recipient_gets_nothing() {
        let mut t = treasury_with_stream(900, 500, 100, 3);
        let r = t.claim("s1", 0).unwrap();
        assert_eq!(r.amount, 0);
        assert_eq!(r.cumulative_released, 0);
        assert_eq!(
            r.status,
            StreamStatus::NotStarted { starts_in: 500 },
            "status must report how long until eligibility"
        );
        // Just before eligibility.
        assert_eq!(t.claim("s1", 499).unwrap().amount, 0);
    }

    #[test]
    fn test_incremental_releases_track_tranche_boundaries() {
        // 100 over 3 tranches every 100s from t=0: 33 @0, 33 @100, 34 @200.
        let mut t = treasury_with_stream(100, 0, 100, 3);
        let s = t.get_stream("s1").unwrap().clone();

        assert_eq!(s.vested_tranches(0), 1);
        assert_eq!(s.vested_tranches(99), 1);
        assert_eq!(s.vested_tranches(100), 2);
        assert_eq!(s.vested_tranches(199), 2);
        assert_eq!(s.vested_tranches(200), 3);
        // Capped: many intervals past the end is still all 3.
        assert_eq!(s.vested_tranches(10_000), 3);

        assert_eq!(t.claim("s1", 0).unwrap().amount, 33);
        assert_eq!(t.claim("s1", 50).unwrap().amount, 0);
        assert_eq!(t.claim("s1", 100).unwrap().amount, 33);
        assert_eq!(t.claim("s1", 150).unwrap().amount, 0);
        let last = t.claim("s1", 200).unwrap();
        assert_eq!(last.amount, 34);
        assert_eq!(last.cumulative_released, 100);
        assert_eq!(last.status, StreamStatus::Completed { released: 100 });
    }

    #[test]
    fn test_partial_status_reports_vested_and_pending() {
        let mut t = treasury_with_stream(100, 0, 100, 3);
        t.claim("s1", 0).unwrap();

        let status = t.status("s1", 150).unwrap();
        assert_eq!(
            status,
            StreamStatus::Active {
                elapsed_tranches: 2,
                total_tranches: 3,
                vested: 66,
                pending: 33,
            }
        );
        assert_eq!(status.released(), 33);
        assert_eq!(status.pending(), 33);
        // Read-only: no funds moved.
        assert_eq!(t.get_stream("s1").unwrap().released, 33);
    }

    #[test]
    fn test_fully_drained_stream_is_completed_and_stays_there() {
        let mut t = treasury_with_stream(100, 0, 10, 2);
        assert_eq!(t.claim("s1", 10).unwrap().amount, 100);
        for now in [11u64, 500, 1_000_000] {
            let r = t.claim("s1", now).unwrap();
            assert_eq!(r.amount, 0);
            assert_eq!(r.cumulative_released, 100);
            assert_eq!(r.status, StreamStatus::Completed { released: 100 });
        }
    }

    #[test]
    fn test_cancellation_refunds_unvested_remainder() {
        let mut t = treasury_with_stream(100, 0, 100, 3);
        let opened_balance = t.balance(); // total + 1_000_000 - 100

        t.claim("s1", 100).unwrap(); // 66 released, 34 unvested
        let c = t.cancel_stream("s1", 150).unwrap();
        assert_eq!(c.released, 66);
        assert_eq!(c.refunded, 34);
        assert_eq!(c.cancelled_at, 150);

        // Every stroop is accounted for: released to recipient + refunded back.
        assert_eq!(c.released + c.refunded, 100);
        assert_eq!(t.balance(), opened_balance + 34);
        assert_eq!(t.open_stream_count(), 0);
        assert_eq!(t.escrowed(), 0);
    }

    #[test]
    fn test_cancelled_stream_cannot_be_claimed() {
        let mut t = treasury_with_stream(100, 0, 100, 3);
        t.cancel_stream("s1", 50).unwrap();
        assert!(matches!(
            t.claim("s1", 100).unwrap_err(),
            ToolkitError::StreamCancelled(_)
        ));
        // Cancelling twice is also refused.
        assert!(matches!(
            t.cancel_stream("s1", 60).unwrap_err(),
            ToolkitError::StreamCancelled(_)
        ));
        assert!(matches!(
            t.status("s1", 100).unwrap(),
            StreamStatus::Cancelled {
                released: 0,
                refunded: 100,
                cancelled_at: 50
            }
        ));
    }

    #[test]
    fn test_cancelling_a_fully_vested_stream_refunds_zero() {
        let mut t = treasury_with_stream(100, 0, 10, 2);
        t.claim("s1", 10).unwrap();
        let before = t.balance();
        let c = t.cancel_stream("s1", 20).unwrap();
        assert_eq!(c.refunded, 0);
        assert_eq!(c.released, 100);
        assert_eq!(t.balance(), before);
    }

    #[test]
    fn test_cancellation_before_start_refunds_everything() {
        let mut t = treasury_with_stream(100, 10_000, 100, 3);
        let c = t.cancel_stream("s1", 5).unwrap();
        assert_eq!(c.refunded, 100);
        assert_eq!(c.released, 0);
        // The helper seeds total + 1_000_000, so the full escrow comes back.
        assert_eq!(t.balance(), 1_000_000 + 100);
    }

    #[test]
    fn test_escrow_prevents_double_promising_the_balance() {
        let mut t = Treasury::new("t", 1000).unwrap();
        t.open_stream("a", "r1", 600, 0, 10, 2).unwrap();
        assert_eq!(t.balance(), 400);
        assert_eq!(t.escrowed(), 600);
        assert_eq!(t.open_stream_count(), 1);

        // Not enough left for a second 600 stream.
        assert!(matches!(
            t.open_stream("b", "r2", 600, 0, 10, 2).unwrap_err(),
            ToolkitError::InsufficientBalance(400, 600)
        ));
        // But a 400 one fits exactly.
        t.open_stream("b", "r2", 400, 0, 10, 2).unwrap();
        assert_eq!(t.balance(), 0);
        assert_eq!(t.escrowed(), 1000);
    }

    #[test]
    fn test_unknown_stream_is_a_clear_error() {
        let mut t = Treasury::new("t", 10).unwrap();
        assert!(matches!(
            t.get_stream("nope").unwrap_err(),
            ToolkitError::StreamNotFound(_)
        ));
        assert!(matches!(
            t.claim("nope", 0).unwrap_err(),
            ToolkitError::StreamNotFound(_)
        ));
        assert!(matches!(
            t.status("nope", 0).unwrap_err(),
            ToolkitError::StreamNotFound(_)
        ));
        assert!(matches!(
            t.cancel_stream("nope", 0).unwrap_err(),
            ToolkitError::StreamNotFound(_)
        ));
    }

    #[test]
    fn test_multiple_streams_are_independent() {
        let mut t = Treasury::new("t", 1000).unwrap();
        t.open_stream("early", "r1", 300, 0, 10, 3).unwrap();
        t.open_stream("late", "r2", 300, 1000, 10, 3).unwrap();

        assert_eq!(t.claim("early", 0).unwrap().amount, 100);
        assert_eq!(t.claim("late", 0).unwrap().amount, 0);
        assert_eq!(t.claim("late", 1000).unwrap().amount, 100);
        assert_eq!(t.open_stream_count(), 2);
        assert_eq!(t.escrowed(), 400);
    }

    #[test]
    fn test_deposit_overflow_is_rejected_not_wrapped() {
        let mut t = Treasury::new("t", i128::MAX).unwrap();
        assert!(matches!(
            t.deposit(1).unwrap_err(),
            ToolkitError::AmountOverflow(_)
        ));
        assert_eq!(t.balance(), i128::MAX);

        let mut t = Treasury::new("t", 0).unwrap();
        assert!(t.deposit(0).is_err());
        assert!(t.deposit(-1).is_err());
        assert!(t.deposit(5).is_ok());
        assert_eq!(t.balance(), 5);
    }

    #[test]
    fn test_negative_treasury_balance_rejected() {
        assert!(matches!(
            Treasury::new("t", -1).unwrap_err(),
            ToolkitError::Treasury(_)
        ));
    }

    #[test]
    fn test_sum_invariant_holds_across_every_claim_boundary() {
        // The headline invariant: the running total released never jumps past
        // the vested total, and the final released total equals the escrow
        // exactly, for a total that does not divide evenly.
        let total = 1_000_000_007i128; // deliberately awkward
        let tranches = 13u32;
        let interval = 7u64;
        let mut t = Treasury::new("t", total).unwrap();
        t.open_stream("s", "r", total, 100, interval, tranches)
            .unwrap();

        let mut running_released: i128 = 0;
        for now in 0u64..400 {
            let v = t.get_stream("s").unwrap().vested_amount(now).unwrap();
            assert!(
                v >= running_released,
                "vested amount went backwards at now={now}"
            );
            assert!(v <= total, "vested exceeded the total at now={now}");

            let r = t.claim("s", now).unwrap();
            assert_eq!(r.cumulative_released - running_released, r.amount);
            running_released = r.cumulative_released;
        }
        assert_eq!(
            running_released, total,
            "final release must equal the escrow"
        );
    }

    #[test]
    fn test_vested_amount_equals_the_sum_of_vested_tranches() {
        // The closed form `v * base` (and the `total` special case at the end)
        // must agree tranche-by-tranche with the explicit sum, including the
        // final tranche that carries the remainder.
        let total = 100i128;
        let tranches = 3u32;
        let mut t = Treasury::new("t", total).unwrap();
        t.open_stream("s", "r", total, 0, 10, tranches).unwrap();

        let mut running: i128 = 0;
        for v in 1..=tranches {
            // Tranche v-1 vests at start_at + (v-1) * interval.
            let now = u64::from(v - 1) * 10;
            running += t.get_stream("s").unwrap().tranche_amount(v - 1).unwrap();
            let vested = t.get_stream("s").unwrap().vested_amount(now).unwrap();
            assert_eq!(vested, running, "closed form diverged at v={v}");
            assert!(vested <= total);
        }
        assert_eq!(t.get_stream("s").unwrap().vested_amount(19).unwrap(), 66);
        // Only at the very last tranche does the remainder-inclusive amount land.
        assert_eq!(t.get_stream("s").unwrap().tranche_amount(2).unwrap(), 34);
        assert_eq!(t.get_stream("s").unwrap().vested_amount(20).unwrap(), total);
    }

    #[test]
    fn test_serde_roundtrip_preserves_streams_and_cancellation() {
        let mut t = Treasury::new("treasury_1", 5000).unwrap();
        t.open_stream("s1", "r1", 1000, 10, 20, 4).unwrap();
        t.open_stream("s2", "r2", 500, 0, 5, 2).unwrap();
        t.claim("s1", 30).unwrap();
        t.cancel_stream("s2", 40).unwrap();

        let json = serde_json::to_string(&t).unwrap();
        let back: Treasury = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
        assert_eq!(back.balance(), t.balance());
        assert_eq!(back.get_stream("s2").unwrap().cancelled_at, Some(40));
    }
}

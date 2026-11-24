//! Recovery path for channels whose funding transaction never completed (#357).
//!
//! A channel can be opened in state before both participants' funds are locked
//! on chain: one side confirms its funding transaction and the other side's
//! fails, is dropped by the network, or is never submitted. The local state
//! then claims a balance that does not exist. Spending from such a channel
//! would settle against money nobody holds.
//!
//! This module makes that situation explicit and recoverable:
//!
//! 1. [`ChannelManager::open_funding_recovery`] marks the channel
//!    [`ChannelStatus::AwaitingFunding`], records how much the other side still
//!    owes, and sets a ledger deadline. Payments and settlement are refused in
//!    this state.
//! 2. [`ChannelManager::complete_funding_recovery`] lets the pending side add
//!    exactly the outstanding amount before the deadline, returning the channel
//!    to `Open`.
//! 3. [`ChannelManager::abort_funding_recovery`] lets the funded side close the
//!    channel after the deadline, so its funds are not locked in a channel
//!    that can never be used.
//!
//! Both completions require a signature over [`FundingRecovery::digest`] from
//! the participant performing them. Every transition is anchored at a ledger
//! height, is idempotent on retry, and leaves the channel untouched when a
//! check fails. A reorg that removes the height where recovery began also
//! removes the recovery record.
//!
//! Existing callers are unaffected: channels created by
//! [`ChannelManager::create_channel`] are `Open`, and the recovery API is
//! opt-in.

use crate::PaymentChannelError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Which participant still owes funding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FundingSide {
    /// The local participant (`our_address`).
    Local,
    /// The remote participant (`their_address`).
    Remote,
}

impl FundingSide {
    /// The other side.
    #[must_use]
    pub fn other(self) -> Self {
        match self {
            Self::Local => Self::Remote,
            Self::Remote => Self::Local,
        }
    }

    /// The side that must sign a recovery action, given the side whose funds
    /// are already confirmed.
    #[must_use]
    pub fn signer_of_pending(self) -> Self {
        self.other()
    }
}

impl std::fmt::Display for FundingSide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => f.write_str("local"),
            Self::Remote => f.write_str("remote"),
        }
    }
}

/// How a funding recovery ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FundingResolution {
    /// Waiting for completion or abort.
    Pending,
    /// The pending participant supplied the outstanding funds.
    Completed,
    /// The funded participant closed the channel after the deadline.
    Aborted,
}

/// The recoverable state of a partially funded channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundingRecovery {
    /// Channel being recovered.
    pub channel_id: String,
    /// Side whose funds are confirmed on chain.
    pub funded_side: FundingSide,
    /// Amount still expected from the other side.
    pub outstanding: i128,
    /// Ledger height at which recovery was opened.
    pub opened_at: u32,
    /// Last ledger height at which completion is accepted.
    pub deadline: u32,
    /// Current resolution of the recovery.
    pub resolution: FundingResolution,
}

impl FundingRecovery {
    /// Open a recovery record.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentChannelError::InvalidState`] when `channel_id` is
    /// blank, `outstanding` is not positive, or the deadline overflows a
    /// `u32` ledger height.
    pub fn new(
        channel_id: impl Into<String>,
        funded_side: FundingSide,
        outstanding: i128,
        opened_at: u32,
        timeout: u32,
    ) -> Result<Self, PaymentChannelError> {
        let channel_id = channel_id.into();
        if channel_id.trim().is_empty() {
            return Err(PaymentChannelError::InvalidState(
                "channel id must not be empty".to_string(),
            ));
        }
        if outstanding <= 0 {
            return Err(PaymentChannelError::InvalidState(format!(
                "outstanding funding must be positive, got {outstanding}"
            )));
        }
        let deadline = opened_at.checked_add(timeout).ok_or_else(|| {
            PaymentChannelError::InvalidState(
                "funding deadline overflows the ledger height".to_string(),
            )
        })?;

        Ok(Self {
            channel_id,
            funded_side,
            outstanding,
            opened_at,
            deadline,
            resolution: FundingResolution::Pending,
        })
    }

    /// The participant expected to supply the outstanding funds.
    #[must_use]
    pub fn pending_side(&self) -> FundingSide {
        self.funded_side.other()
    }

    /// Whether `ledger_height` is past the completion deadline.
    #[must_use]
    pub fn is_expired(&self, ledger_height: u32) -> bool {
        ledger_height > self.deadline
    }

    /// The deterministic payload a recovery action must be signed over.
    ///
    /// Binding the funded side, amount and both ledger heights means a
    /// signature for one recovery cannot be replayed against another.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"STELLAR_PAYMENT_CHANNEL_FUNDING_RECOVERY:");
        hasher.update(self.channel_id.as_bytes());
        hasher.update([u8::from(self.funded_side == FundingSide::Local)]);
        hasher.update(self.outstanding.to_be_bytes());
        hasher.update(self.opened_at.to_be_bytes());
        hasher.update(self.deadline.to_be_bytes());
        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_records_the_deadline_and_pending_resolution() {
        let recovery = FundingRecovery::new("channel-1", FundingSide::Local, 500, 10, 100)
            .expect("valid recovery");
        assert_eq!(recovery.channel_id, "channel-1");
        assert_eq!(recovery.outstanding, 500);
        assert_eq!(recovery.opened_at, 10);
        assert_eq!(recovery.deadline, 110);
        assert_eq!(recovery.resolution, FundingResolution::Pending);
        assert_eq!(recovery.pending_side(), FundingSide::Remote);
    }

    #[test]
    fn side_helpers_are_symmetric() {
        assert_eq!(FundingSide::Local.other(), FundingSide::Remote);
        assert_eq!(FundingSide::Remote.other(), FundingSide::Local);
        assert_eq!(FundingSide::Local.to_string(), "local");
        assert_eq!(FundingSide::Remote.signer_of_pending(), FundingSide::Local);
    }

    #[test]
    fn zero_and_negative_outstanding_are_rejected() {
        for amount in [0, -1] {
            let err = FundingRecovery::new("c", FundingSide::Local, amount, 0, 10).unwrap_err();
            assert!(
                matches!(err, PaymentChannelError::InvalidState(_)),
                "{err:?}"
            );
        }
    }

    #[test]
    fn blank_channel_id_is_rejected() {
        let err = FundingRecovery::new("  ", FundingSide::Remote, 1, 0, 10).unwrap_err();
        assert!(
            matches!(err, PaymentChannelError::InvalidState(_)),
            "{err:?}"
        );
    }

    #[test]
    fn deadline_overflow_is_rejected() {
        let err = FundingRecovery::new("c", FundingSide::Local, 1, u32::MAX, 1).unwrap_err();
        assert!(
            matches!(&err, PaymentChannelError::InvalidState(msg) if msg.contains("overflow")),
            "{err:?}"
        );
    }

    #[test]
    fn expiry_boundary_is_exact() {
        let recovery = FundingRecovery::new("c", FundingSide::Local, 1, 100, 50).unwrap();
        assert!(!recovery.is_expired(150));
        assert!(recovery.is_expired(151));
        assert!(!recovery.is_expired(149));
    }

    #[test]
    fn digest_binds_every_recovery_field() {
        let recovery = FundingRecovery::new("c", FundingSide::Local, 1, 2, 3).unwrap();
        let same = FundingRecovery::new("c", FundingSide::Local, 1, 2, 3).unwrap();
        assert_eq!(recovery.digest(), same.digest());

        let different_amount = FundingRecovery::new("c", FundingSide::Local, 2, 2, 3).unwrap();
        let different_side = FundingRecovery::new("c", FundingSide::Remote, 1, 2, 3).unwrap();
        let different_channel = FundingRecovery::new("other", FundingSide::Local, 1, 2, 3).unwrap();
        let different_height = FundingRecovery::new("c", FundingSide::Local, 1, 4, 3).unwrap();
        assert_ne!(recovery.digest(), different_amount.digest());
        assert_ne!(recovery.digest(), different_side.digest());
        assert_ne!(recovery.digest(), different_channel.digest());
        assert_ne!(recovery.digest(), different_height.digest());
    }
}

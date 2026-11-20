//! # Signed Channel States
//!
//! A channel split both participants signed, together with the sequence number
//! it settles at (issue #352).
//!
//! # Why the sequence number is part of the signed state
//!
//! A payment channel's whole security model rests on "the newest state wins".
//! Each update replaces the split and bumps [`SignedChannelState::sequence_number`],
//! and both parties keep the signed copy. Settlement is the point where that
//! rule has to be enforced on the other side: the counterparty presents the
//! state it wants to settle on, and a state that has been superseded must be
//! refused.
//!
//! Without the sequence number in the signed payload, the settlement call has
//! nothing to compare against. The channel's stored sequence is not enough on
//! its own either: an old signed copy of a *favourable* split is
//! indistinguishable from a fresh one, so a party that kept an earlier state
//! could settle on it after the channel had moved on — moving funds backwards.
//!
//! # Scope
//!
//! This module defines the signed payload and its canonical digest. The
//! staleness rule lives in
//! [`ChannelManager::settle_signed_state`](crate::ChannelManager::settle_signed_state);
//! the on-chain twin is `PaymentChannel::settle_signed_state` in
//! `contracts/payment-channel-contract`.
//!
//! Signature *verification* against the counterparty key is the caller's job at
//! this layer: the manager asks its [`SignatureSigner`](crate::SignatureSigner)
//! to verify [`SignedChannelState::digest`] against the channel's
//! `remote_public_key`, which must be registered before settlement.

use crate::PaymentChannelError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separator for the settlement digest.
///
/// The digest is only ever compared to another digest of the same construction,
/// so the separator is not load-bearing for security. It is here so that a
/// signature over a settlement can never be confused with a signature over some
/// other 32-byte payload this crate hashes.
const DIGEST_DOMAIN: &[u8] = b"stellar-payment-channel/signed-state/v1";

/// A channel split both participants signed, stamped with its sequence number.
///
/// `balance_a` is the balance of the channel's
/// [`our_address`](crate::LocalChannelState::our_address) and `balance_b` that
/// of `their_address`. The names are positional rather than "ours"/"theirs"
/// because a settlement is a shared artifact: each side signs the same two
/// numbers, and the channel's addresses are what say who is who.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedChannelState {
    /// Channel this state belongs to.
    pub channel_id: String,
    /// Sequence number this split settles at.
    pub sequence_number: u32,
    /// Balance of the channel's `our_address` participant.
    pub balance_a: i128,
    /// Balance of the channel's `their_address` participant.
    pub balance_b: i128,
}

impl SignedChannelState {
    /// Build a signed state.
    ///
    /// No validation happens here: a state is a message that was signed
    /// elsewhere, so it is validated when it is *applied*
    /// ([`ChannelManager::settle_signed_state`](crate::ChannelManager::settle_signed_state)).
    pub fn new(
        channel_id: impl Into<String>,
        sequence_number: u32,
        balance_a: i128,
        balance_b: i128,
    ) -> Self {
        Self {
            channel_id: channel_id.into(),
            sequence_number,
            balance_a,
            balance_b,
        }
    }

    /// The two balances must add up to the channel total without overflowing.
    ///
    /// Returns the total, or [`PaymentChannelError::InvalidState`] when a side
    /// is negative or the sum overflows `i128`.
    pub fn total(&self) -> Result<i128, PaymentChannelError> {
        if self.balance_a < 0 || self.balance_b < 0 {
            return Err(PaymentChannelError::InvalidState(format!(
                "settlement for {} has a negative balance ({}, {})",
                self.channel_id, self.balance_a, self.balance_b
            )));
        }
        self.balance_a.checked_add(self.balance_b).ok_or_else(|| {
            PaymentChannelError::InvalidState(format!(
                "settlement for {} overflows: {} + {}",
                self.channel_id, self.balance_a, self.balance_b
            ))
        })
    }

    /// Canonical digest of the signed payload.
    ///
    /// Every field is length-prefixed or fixed-width and written big-endian, so
    /// two different states cannot hash to the same preimage: `"ab"` + `"c"`
    /// and `"a"` + `"bc"` produce different digests, and neither does a
    /// reordered or truncated encoding.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update((self.channel_id.len() as u64).to_be_bytes());
        hasher.update(self.channel_id.as_bytes());
        hasher.update(self.sequence_number.to_be_bytes());
        hasher.update(self.balance_a.to_be_bytes());
        hasher.update(self.balance_b.to_be_bytes());
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(sequence_number: u32, balance_a: i128, balance_b: i128) -> SignedChannelState {
        SignedChannelState::new("channel-1", sequence_number, balance_a, balance_b)
    }

    #[test]
    fn the_digest_is_deterministic() {
        let a = state(3, 1_200, 800);
        let b = state(3, 1_200, 800);
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a, b);
    }

    #[test]
    fn every_field_changes_the_digest() {
        let base = state(3, 1_200, 800).digest();

        let other_channel = SignedChannelState::new("channel-2", 3, 1_200, 800).digest();
        let other_sequence = state(4, 1_200, 800).digest();
        let other_balance_a = state(3, 1_201, 799).digest();
        let other_balance_b = state(3, 1_199, 801).digest();

        for digest in [
            other_channel,
            other_sequence,
            other_balance_a,
            other_balance_b,
        ] {
            assert_ne!(digest, base, "a changed field must change the digest");
        }
    }

    #[test]
    fn the_encoding_is_unambiguous_across_field_boundaries() {
        // A channel id that is a prefix of another must not collide, which is
        // what the length prefix buys: the boundary between the id and the
        // sequence number is explicit.
        let short = SignedChannelState::new("a", 3, 1, 2).digest();
        let long = SignedChannelState::new("ab", 3, 1, 2).digest();
        assert_ne!(short, long, "a longer id must not alias a shorter one");

        // A byte shifted from the sequence into the id must not collide either.
        let boundary = SignedChannelState::new("a\u{3}", 0, 1, 2).digest();
        assert_ne!(short, boundary, "a shifted field boundary must not collide");
    }

    #[test]
    fn the_total_is_the_sum_of_both_sides() {
        assert_eq!(state(1, 1_200, 800).total().unwrap(), 2_000);
        assert_eq!(state(1, 0, 2_000).total().unwrap(), 2_000);
    }

    #[test]
    fn a_negative_side_is_not_a_valid_total() {
        let error = state(1, -1, 2_001)
            .total()
            .expect_err("balances are non-negative");
        assert!(matches!(error, PaymentChannelError::InvalidState(_)));
    }

    #[test]
    fn an_overflowing_total_is_rejected() {
        let error = state(1, i128::MAX, 1)
            .total()
            .expect_err("the sum overflows");
        assert!(matches!(error, PaymentChannelError::InvalidState(_)));
    }
}

//! # Stellar Payment Channel Contract
//!
//! A Lightning Network-style payment channel system on Stellar for instant,
//! low-cost off-chain transactions with on-chain settlement.

#![no_std]

mod channel;
mod error;
mod htlc;
mod state;
mod types;

pub use error::PaymentChannelError;
use soroban_sdk::{
    contract, contractimpl, contractmeta, Address, Bytes, BytesN, Env, IntoVal, TryFromVal,
    Vec as SorobanVec,
};
pub use types::{ChannelState, FundingRecovery, FundingResolution, HTLCInfo, HtlcList};

/// Append an address's canonical strkey encoding to `out`.
///
/// `soroban-sdk` 21 exposes no accessor for an `Address`'s raw 32 bytes, so the
/// deterministic-id preimages below are built from the strkey form instead. That
/// is equally deterministic and equally unique per address. A strkey-encoded
/// `Address` is 'G' followed by 55 base32 characters, so 56 bytes; the buffer is
/// sized with headroom and the bound is asserted rather than assumed.
pub(crate) fn append_address(out: &mut Bytes, address: &Address) {
    const STRKEY_BUF: usize = 64;

    let encoded = address.to_string();
    let len = encoded.len() as usize;
    assert!(len <= STRKEY_BUF, "address strkey exceeds buffer");

    // `copy_into_slice` panics unless the slice length matches exactly.
    let mut buf = [0u8; STRKEY_BUF];
    encoded.copy_into_slice(&mut buf[..len]);
    out.extend_from_slice(&buf[..len]);
}

/// Refuse channel operations while a funding recovery is unresolved (#357).
fn ensure_no_pending_recovery(
    env: &Env,
    channel_id: &BytesN<32>,
) -> Result<(), PaymentChannelError> {
    if state::pending_funding_recovery(env, channel_id).is_some() {
        return Err(PaymentChannelError::ChannelAwaitingFunding);
    }
    Ok(())
}

contractmeta!(key = "name", val = "StellarPaymentChannel");

/// Payment Channel Contract
#[contract]
pub struct PaymentChannel;

#[contractimpl]
impl PaymentChannel {
    /// Initialize a new payment channel between two parties
    pub fn initialize(
        env: Env,
        participant_a: Address,
        participant_b: Address,
        initial_balance_a: i128,
        initial_balance_b: i128,
        timeout: u32,
        fee_percentage: u32,
    ) -> Result<BytesN<32>, PaymentChannelError> {
        if initial_balance_a < 0 || initial_balance_b < 0 {
            return Err(PaymentChannelError::InvalidBalance);
        }
        if timeout < 60 {
            return Err(PaymentChannelError::InvalidTimeout);
        }
        if fee_percentage > 10000 {
            return Err(PaymentChannelError::InvalidFee);
        }

        // Generate channel ID using both participant addresses
        let mut data = Bytes::new(&env);
        append_address(&mut data, &participant_a);
        append_address(&mut data, &participant_b);
        let nonce = env.ledger().sequence();
        data.extend_from_slice(&nonce.to_be_bytes());

        let channel_id: BytesN<32> = env.crypto().sha256(&data).into();

        let state = ChannelState::new(
            &env,
            channel_id.clone(),
            participant_a.clone(),
            participant_b.clone(),
            initial_balance_a,
            initial_balance_b,
            timeout,
            fee_percentage,
        );

        state::store_channel_state(&env, &channel_id, &state);

        // Store channel IDs for each participant
        let mut a_channels = state::get_participant_channels(&env, &participant_a);
        a_channels.push_back(channel_id.clone());
        state::store_participant_channels(&env, &participant_a, &a_channels);

        let mut b_channels = state::get_participant_channels(&env, &participant_b);
        b_channels.push_back(channel_id.clone());
        state::store_participant_channels(&env, &participant_b, &b_channels);

        Ok(channel_id)
    }

    /// Get the current state of a channel
    pub fn get_channel_state(
        env: Env,
        channel_id: BytesN<32>,
    ) -> Result<ChannelState, PaymentChannelError> {
        state::get_channel_state(&env, &channel_id)
    }

    /// Update the channel state with a new payment
    pub fn update_state(
        env: Env,
        channel_id: BytesN<32>,
        new_balance_a: i128,
        new_balance_b: i128,
        signature_a: BytesN<64>,
        signature_b: BytesN<64>,
    ) -> Result<(), PaymentChannelError> {
        // Both signatures are part of the channel ABI but are not verified yet.
        let _ = (signature_a, signature_b);
        let mut state = state::get_channel_state(&env, &channel_id)?;
        if state.is_cooperative_close {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }

        if state.close_time != 0 {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }

        ensure_no_pending_recovery(&env, &channel_id)?;

        if new_balance_a < 0 || new_balance_b < 0 {
            return Err(PaymentChannelError::InvalidBalance);
        }
        let new_total = new_balance_a
            .checked_add(new_balance_b)
            .ok_or(PaymentChannelError::BalanceMismatch)?;
        if new_total != state.total_balance {
            return Err(PaymentChannelError::BalanceMismatch);
        }

        state.participant_a.require_auth();
        state.participant_b.require_auth();

        state.balance_a = new_balance_a;
        state.balance_b = new_balance_b;
        state.sequence_number += 1;

        state::store_channel_state(&env, &channel_id, &state);

        env.events()
            .publish(("channel_update", channel_id), state.sequence_number);

        Ok(())
    }

    /// Create a Hash Time-Locked Contract for conditional payments
    pub fn create_htlc(
        env: Env,
        channel_id: BytesN<32>,
        hashlock: BytesN<32>,
        timelock: u32,
        amount: i128,
        receiver: Address,
    ) -> Result<BytesN<32>, PaymentChannelError> {
        let mut state = state::get_channel_state(&env, &channel_id)?;
        if state.is_cooperative_close {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }

        if state.close_time != 0 {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }

        ensure_no_pending_recovery(&env, &channel_id)?;

        if amount <= 0 {
            return Err(PaymentChannelError::InvalidHtlcAmount);
        }

        let current_block = env.ledger().sequence();
        if timelock <= current_block {
            return Err(PaymentChannelError::InvalidTimelock);
        }

        if state.balance_a < amount {
            return Err(PaymentChannelError::InsufficientBalance);
        }

        state.participant_a.require_auth();

        // Generate HTLC ID
        let mut htlc_data = Bytes::new(&env);
        htlc_data.extend_from_slice(&channel_id.to_array());
        let seq = state.sequence_number.to_be_bytes();
        htlc_data.extend_from_slice(&seq);
        let ts = env.ledger().timestamp().to_be_bytes();
        htlc_data.extend_from_slice(&ts);
        let htlc_id: BytesN<32> = env.crypto().sha256(&htlc_data).into();

        let htlc_info = HTLCInfo {
            htlc_id: htlc_id.clone(),
            hashlock,
            timelock,
            amount,
            receiver: receiver.clone(),
            sender: state.participant_a.clone(),
            is_claimed: false,
            is_refunded: false,
            created_at: env.ledger().timestamp(),
        };

        state.balance_a -= amount;

        state.htlcs.set(htlc_id.to_val(), htlc_info.into_val(&env));

        state.sequence_number += 1;
        state::store_channel_state(&env, &channel_id, &state);

        env.events()
            .publish(("htlc_created", htlc_id.clone()), (&receiver, amount));

        Ok(htlc_id)
    }

    /// Claim an HTLC by revealing the preimage
    pub fn claim_htlc(
        env: Env,
        channel_id: BytesN<32>,
        htlc_id: BytesN<32>,
        preimage: BytesN<32>,
    ) -> Result<(), PaymentChannelError> {
        let mut state = state::get_channel_state(&env, &channel_id)?;
        if state.is_cooperative_close {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }

        ensure_no_pending_recovery(&env, &channel_id)?;

        let htlc_val = state
            .htlcs
            .get(htlc_id.clone().to_val())
            .ok_or(PaymentChannelError::HtlcNotFound)?;
        let mut htlc: HTLCInfo = HTLCInfo::try_from_val(&env, &htlc_val)
            .map_err(|_| PaymentChannelError::InvalidChannelState)?;

        if htlc.is_claimed {
            return Err(PaymentChannelError::HtlcAlreadyClaimed);
        }
        if htlc.is_refunded {
            return Err(PaymentChannelError::HtlcAlreadyRefunded);
        }

        let current_block = env.ledger().sequence();
        if current_block >= htlc.timelock {
            return Err(PaymentChannelError::HtlcExpired);
        }

        htlc.receiver.require_auth();

        // Verify the preimage hashes to the hashlock
        let preimage_bytes = Bytes::from_slice(&env, &preimage.to_array());
        let computed_hash: BytesN<32> = env.crypto().sha256(&preimage_bytes).into();
        if computed_hash != htlc.hashlock {
            return Err(PaymentChannelError::InvalidPreimage);
        }

        htlc.is_claimed = true;
        state.balance_b += htlc.amount;

        state.htlcs.set(htlc_id.to_val(), htlc.into_val(&env));

        state.sequence_number += 1;
        state::store_channel_state(&env, &channel_id, &state);

        env.events().publish(("htlc_claimed", htlc_id), ());

        Ok(())
    }

    /// Refund an expired HTLC back to the sender
    pub fn refund_htlc(
        env: Env,
        channel_id: BytesN<32>,
        htlc_id: BytesN<32>,
    ) -> Result<(), PaymentChannelError> {
        let mut state = state::get_channel_state(&env, &channel_id)?;
        if state.is_cooperative_close {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }

        ensure_no_pending_recovery(&env, &channel_id)?;

        let htlc_val = state
            .htlcs
            .get(htlc_id.clone().to_val())
            .ok_or(PaymentChannelError::HtlcNotFound)?;
        let mut htlc: HTLCInfo = HTLCInfo::try_from_val(&env, &htlc_val)
            .map_err(|_| PaymentChannelError::InvalidChannelState)?;

        if htlc.is_claimed {
            return Err(PaymentChannelError::HtlcAlreadyClaimed);
        }
        if htlc.is_refunded {
            return Err(PaymentChannelError::HtlcAlreadyRefunded);
        }

        let current_block = env.ledger().sequence();
        if current_block < htlc.timelock {
            return Err(PaymentChannelError::HtlcNotExpired);
        }

        htlc.sender.require_auth();

        htlc.is_refunded = true;
        state.balance_a += htlc.amount;

        state.htlcs.set(htlc_id.to_val(), htlc.into_val(&env));

        state.sequence_number += 1;
        state::store_channel_state(&env, &channel_id, &state);

        env.events().publish(("htlc_refunded", htlc_id), ());

        Ok(())
    }

    /// Settle the channel cooperatively at an agreed final balance split.
    ///
    /// Idempotent (#351). A client that loses the response to this call and
    /// retries must not be able to corrupt the settlement, so the same close can
    /// be presented any number of times:
    ///
    /// * first call — balances are written, `is_cooperative_close` is set, the
    ///   close is stamped with the sequence number it settled at
    ///   (`close_sequence`) and one `channel_close` event is published;
    /// * retry with the same balances — `Ok(())`, no state change, no second
    ///   event, sequence number untouched;
    /// * retry with *different* balances — [`PaymentChannelError::ChannelAlreadyClosed`],
    ///   because the channel already settled on a different split.
    ///
    /// A close is refused while the channel has unsettled HTLCs
    /// ([`PaymentChannelError::ActiveHtlcsExist`]): the HTLC amounts are held
    /// outside the two balances, so closing over them would strand them.
    pub fn cooperative_close(
        env: Env,
        channel_id: BytesN<32>,
        final_balance_a: i128,
        final_balance_b: i128,
        signature_a: BytesN<64>,
        signature_b: BytesN<64>,
    ) -> Result<(), PaymentChannelError> {
        // Both signatures are part of the channel ABI but are not verified yet.
        let _ = (signature_a, signature_b);
        let mut state = state::get_channel_state(&env, &channel_id)?;

        if state.close_time != 0 {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }

        ensure_no_pending_recovery(&env, &channel_id)?;

        if final_balance_a < 0 || final_balance_b < 0 {
            return Err(PaymentChannelError::InvalidBalance);
        }
        let total = final_balance_a
            .checked_add(final_balance_b)
            .ok_or(PaymentChannelError::BalanceMismatch)?;
        if total != state.total_balance {
            return Err(PaymentChannelError::BalanceMismatch);
        }

        state.participant_a.require_auth();
        state.participant_b.require_auth();

        if state.is_cooperative_close {
            if state.balance_a == final_balance_a && state.balance_b == final_balance_b {
                return Ok(());
            }
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }

        if state::has_active_htlcs(&env, &state.htlcs) {
            return Err(PaymentChannelError::ActiveHtlcsExist);
        }

        state.balance_a = final_balance_a;
        state.balance_b = final_balance_b;
        state.is_cooperative_close = true;
        state.close_time = env.ledger().timestamp();
        state.sequence_number += 1;
        state.close_sequence = state.sequence_number;

        state::store_channel_state(&env, &channel_id, &state);

        env.events().publish(
            ("channel_close", channel_id),
            ("cooperative", state.close_time),
        );

        Ok(())
    }

    /// Settle the channel on a state both participants signed (#352).
    ///
    /// Settlement is where the "newest state wins" rule has to be enforced
    /// against the counterparty, not just locally. `signed_sequence` is part of
    /// the signed payload, so a party that kept an older, more favourable split
    /// cannot present it once the channel has moved on:
    ///
    /// * `signed_sequence` must be **strictly newer** than
    ///   `ChannelState::sequence_number`, otherwise
    ///   [`PaymentChannelError::StaleState`];
    /// * the two balances must be non-negative and sum to the channel total;
    /// * the channel must be open and free of outstanding HTLCs.
    ///
    /// On success the split is applied, the sequence number advances to
    /// `signed_sequence` (gaps are allowed, because a participant may have
    /// missed intermediate updates), and the channel is marked settled.
    ///
    /// # Signatures
    ///
    /// `signature_a` and `signature_b` are part of the channel ABI but are not
    /// verified yet, matching [`PaymentChannel::update_state`] and
    /// [`PaymentChannel::cooperative_close`]. The payload they will cover is the
    /// one [`payment_channel::signed::SignedChannelState::digest`] defines:
    ///
    /// ```text
    /// "stellar-payment-channel/signed-state/v1"
    /// || len(channel_id) as u64 BE || channel_id bytes
    /// || signed_sequence as u32 BE
    /// || new_balance_a as i128 BE
    /// || new_balance_b as i128 BE
    /// ```
    ///
    /// The staleness check does not depend on that verification landing: it is
    /// enforced against the stored sequence number, so an old state is refused
    /// whether or not its signature has been checked.
    pub fn settle_signed_state(
        env: Env,
        channel_id: BytesN<32>,
        new_balance_a: i128,
        new_balance_b: i128,
        signed_sequence: u32,
        signature_a: BytesN<64>,
        signature_b: BytesN<64>,
    ) -> Result<(), PaymentChannelError> {
        // Both signatures are part of the channel ABI but are not verified yet.
        let _ = (signature_a, signature_b);
        let mut state = state::get_channel_state(&env, &channel_id)?;

        if state.is_cooperative_close {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }

        ensure_no_pending_recovery(&env, &channel_id)?;

        if new_balance_a < 0 || new_balance_b < 0 {
            return Err(PaymentChannelError::InvalidBalance);
        }
        let total = new_balance_a
            .checked_add(new_balance_b)
            .ok_or(PaymentChannelError::BalanceMismatch)?;
        if total != state.total_balance {
            return Err(PaymentChannelError::BalanceMismatch);
        }

        if state::has_active_htlcs(&env, &state.htlcs) {
            return Err(PaymentChannelError::ActiveHtlcsExist);
        }

        // Only a strictly newer state may settle. An equal sequence would let a
        // replayed copy of the current state rewrite the split, and a lower one
        // would move funds backwards.
        if signed_sequence <= state.sequence_number {
            return Err(PaymentChannelError::StaleState);
        }

        state.balance_a = new_balance_a;
        state.balance_b = new_balance_b;
        state.sequence_number = signed_sequence;
        state.is_cooperative_close = true;
        state.close_time = env.ledger().timestamp();
        state.close_sequence = signed_sequence;

        state::store_channel_state(&env, &channel_id, &state);

        env.events().publish(
            ("channel_settled", channel_id),
            (signed_sequence, state.close_time),
        );

        Ok(())
    }

    /// Initiate unilateral close of the channel
    pub fn initiate_unilateral_close(
        env: Env,
        channel_id: BytesN<32>,
        initiator: Address,
    ) -> Result<u64, PaymentChannelError> {
        let mut state = state::get_channel_state(&env, &channel_id)?;
        if state.is_cooperative_close {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }

        if state.close_time != 0 {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }

        ensure_no_pending_recovery(&env, &channel_id)?;

        if initiator != state.participant_a && initiator != state.participant_b {
            return Err(PaymentChannelError::UnauthorizedParticipant);
        }

        initiator.require_auth();

        let has_active = state::has_active_htlcs(&env, &state.htlcs);
        if has_active {
            return Err(PaymentChannelError::ActiveHtlcsExist);
        }

        state.close_time = env.ledger().timestamp();
        state.sequence_number += 1;

        state::store_channel_state(&env, &channel_id, &state);

        let withdraw_time = state.close_time + state.timeout as u64;

        env.events().publish(
            ("channel_close_initiated", channel_id),
            (initiator.to_val(), withdraw_time),
        );

        Ok(withdraw_time)
    }

    /// Contest a unilateral close with a more recent state
    pub fn contest_close(
        env: Env,
        channel_id: BytesN<32>,
        contesting_balance_a: i128,
        contesting_balance_b: i128,
        contest_sequence: u32,
        signature: BytesN<64>,
    ) -> Result<(), PaymentChannelError> {
        // The contesting balances and signature are part of the ABI but are not
        // verified yet.
        let _ = (contesting_balance_a, contesting_balance_b, signature);
        let state = state::get_channel_state(&env, &channel_id)?;

        if contest_sequence <= state.sequence_number {
            return Err(PaymentChannelError::InvalidSequence);
        }

        env.events().publish(
            ("channel_contested", channel_id),
            (contest_sequence, env.ledger().timestamp()),
        );

        Ok(())
    }

    /// Add funds to an existing channel (top-up)
    pub fn top_up(
        env: Env,
        channel_id: BytesN<32>,
        top_up_amount: i128,
        participant: Address,
    ) -> Result<(), PaymentChannelError> {
        let mut state = state::get_channel_state(&env, &channel_id)?;
        if state.is_cooperative_close {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }

        if state.close_time != 0 {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }

        ensure_no_pending_recovery(&env, &channel_id)?;

        if top_up_amount <= 0 {
            return Err(PaymentChannelError::InvalidBalance);
        }

        if participant != state.participant_a && participant != state.participant_b {
            return Err(PaymentChannelError::UnauthorizedParticipant);
        }

        participant.require_auth();

        if participant == state.participant_a {
            state.balance_a += top_up_amount;
        } else {
            state.balance_b += top_up_amount;
        }

        state.total_balance += top_up_amount;
        state.sequence_number += 1;

        state::store_channel_state(&env, &channel_id, &state);

        env.events().publish(
            ("channel_topup", channel_id),
            (participant.to_val(), top_up_amount),
        );

        Ok(())
    }

    /// Open a recovery window for a channel whose funding did not complete (#357).
    ///
    /// `funded_participant` is the side whose funding transaction is confirmed;
    /// the other side is recorded as owing the outstanding amount. The funded
    /// side must authorise the record because its funds are the ones at risk.
    /// While the record is pending, state-changing entrypoints are refused with
    /// [`PaymentChannelError::ChannelAwaitingFunding`]. The channel state
    /// itself is not modified here, so callers that never open a recovery keep
    /// the existing behaviour. `timeout` is interpreted as a ledger count to
    /// match the deadline check.
    pub fn open_funding_recovery(
        env: Env,
        channel_id: BytesN<32>,
        funded_participant: Address,
        outstanding: i128,
    ) -> Result<FundingRecovery, PaymentChannelError> {
        let state = state::get_channel_state(&env, &channel_id)?;
        if state.is_cooperative_close || state.close_time != 0 {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }
        if state::has_active_htlcs(&env, &state.htlcs) {
            return Err(PaymentChannelError::ActiveHtlcsExist);
        }
        if state::pending_funding_recovery(&env, &channel_id).is_some() {
            return Err(PaymentChannelError::FundingRecoveryExists);
        }
        if funded_participant != state.participant_a && funded_participant != state.participant_b {
            return Err(PaymentChannelError::UnauthorizedParticipant);
        }
        funded_participant.require_auth();

        let (funded_balance, pending_participant) = if funded_participant == state.participant_a {
            (state.balance_a, state.participant_b.clone())
        } else {
            (state.balance_b, state.participant_a.clone())
        };
        if funded_balance <= 0 {
            return Err(PaymentChannelError::InvalidFundingAmount);
        }

        let recovery = FundingRecovery::new(
            &env,
            channel_id.clone(),
            funded_participant,
            pending_participant,
            outstanding,
            state.timeout,
        )?;
        state::store_funding_recovery(&env, &channel_id, &recovery);
        env.events().publish(
            ("funding_recovery_opened", channel_id),
            (recovery.opened_at_ledger, recovery.deadline_ledger),
        );
        Ok(recovery)
    }

    /// Complete a pending recovery by supplying exactly the outstanding amount.
    ///
    /// Only the pending participant may call this, and only before the
    /// deadline. A retry with the same amount after success is a no-op. The
    /// channel balances and the recovery record are written together, so a
    /// failed call cannot leave a half-applied top-up.
    pub fn complete_funding_recovery(
        env: Env,
        channel_id: BytesN<32>,
        amount: i128,
    ) -> Result<(), PaymentChannelError> {
        let recovery = state::get_funding_recovery(&env, &channel_id)?;
        match recovery.resolution {
            FundingResolution::Completed => {
                return if recovery.outstanding == amount {
                    Ok(())
                } else {
                    Err(PaymentChannelError::FundingAmountMismatch)
                };
            }
            FundingResolution::Aborted => return Err(PaymentChannelError::InvalidChannelState),
            FundingResolution::Pending => {}
        }
        if amount != recovery.outstanding {
            return Err(PaymentChannelError::FundingAmountMismatch);
        }
        if recovery.is_expired(env.ledger().sequence()) {
            return Err(PaymentChannelError::FundingRecoveryExpired);
        }
        recovery.pending_participant.require_auth();

        let mut state = state::get_channel_state(&env, &channel_id)?;
        if state.is_cooperative_close || state.close_time != 0 {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }
        if recovery.pending_participant == state.participant_a {
            state.balance_a = state
                .balance_a
                .checked_add(amount)
                .ok_or(PaymentChannelError::InvalidBalance)?;
        } else {
            state.balance_b = state
                .balance_b
                .checked_add(amount)
                .ok_or(PaymentChannelError::InvalidBalance)?;
        }
        state.total_balance = state
            .total_balance
            .checked_add(amount)
            .ok_or(PaymentChannelError::BalanceMismatch)?;
        state.sequence_number += 1;

        let mut resolved = recovery;
        resolved.resolution = FundingResolution::Completed;
        state::store_channel_state(&env, &channel_id, &state);
        state::store_funding_recovery(&env, &channel_id, &resolved);
        env.events()
            .publish(("funding_recovery_completed", channel_id), amount);
        Ok(())
    }

    /// Abort a pending recovery once its deadline has passed.
    ///
    /// Only the funded participant may call this. The channel is marked closed
    /// and the recovery is marked aborted in the same write; the actual return
    /// of the locked asset is handled by the funding transaction's own refund
    /// path, which this state change records. A retry after success is a no-op.
    pub fn abort_funding_recovery(
        env: Env,
        channel_id: BytesN<32>,
    ) -> Result<(), PaymentChannelError> {
        let recovery = state::get_funding_recovery(&env, &channel_id)?;
        match recovery.resolution {
            FundingResolution::Aborted => return Ok(()),
            FundingResolution::Completed => return Err(PaymentChannelError::InvalidChannelState),
            FundingResolution::Pending => {}
        }
        if !recovery.is_expired(env.ledger().sequence()) {
            return Err(PaymentChannelError::FundingDeadlineNotReached);
        }
        recovery.funded_participant.require_auth();

        let mut state = state::get_channel_state(&env, &channel_id)?;
        if state.is_cooperative_close || state.close_time != 0 {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }
        state.sequence_number += 1;
        state.is_cooperative_close = true;
        state.close_sequence = state.sequence_number;
        state.close_time = env.ledger().timestamp();

        let mut resolved = recovery;
        resolved.resolution = FundingResolution::Aborted;
        state::store_channel_state(&env, &channel_id, &state);
        state::store_funding_recovery(&env, &channel_id, &resolved);
        env.events()
            .publish(("funding_recovery_aborted", channel_id), state.close_time);
        Ok(())
    }

    /// The funding recovery record for a channel, if one was opened.
    pub fn get_funding_recovery(
        env: Env,
        channel_id: BytesN<32>,
    ) -> Result<FundingRecovery, PaymentChannelError> {
        state::get_funding_recovery(&env, &channel_id)
    }

    /// Get all HTLCs for a channel
    ///
    /// A contract entrypoint cannot return `Result<Vec<T>, E>`, so this returns
    /// the vector directly and propagates a missing channel as a panic, matching
    /// the other getters in this contract.
    pub fn get_htlcs(env: Env, channel_id: BytesN<32>) -> HtlcList {
        let state = state::get_channel_state(&env, &channel_id)
            .expect("channel not found: use get_channel_state to distinguish this");
        let mut entries = SorobanVec::new(&env);

        for (_key, val) in state.htlcs.iter() {
            if let Ok(htlc) = HTLCInfo::try_from_val(&env, &val) {
                entries.push_back(htlc);
            }
        }

        HtlcList { entries }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    fn setup_channel(env: &Env) -> (PaymentChannelClient<'_>, Address, Address, BytesN<32>) {
        let contract_id = env.register_contract(None, PaymentChannel);
        let client = PaymentChannelClient::new(env, &contract_id);
        let p_a = Address::generate(env);
        let p_b = Address::generate(env);
        let channel_id = client.initialize(&p_a, &p_b, &1_000, &1_000, &100, &0);
        (client, p_a, p_b, channel_id)
    }

    #[test]
    fn test_update_state_success() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _p_a, _p_b, channel_id) = setup_channel(&env);
        let dummy_sig = BytesN::from_array(&env, &[0u8; 64]);

        client.update_state(&channel_id, &1_200, &800, &dummy_sig, &dummy_sig);
        let state = client.get_channel_state(&channel_id);
        assert_eq!(state.balance_a, 1_200);
        assert_eq!(state.balance_b, 800);
        assert_eq!(state.sequence_number, 1);
    }

    #[test]
    fn test_update_state_balance_mismatch() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _p_a, _p_b, channel_id) = setup_channel(&env);
        let dummy_sig = BytesN::from_array(&env, &[0u8; 64]);

        let res = client.try_update_state(&channel_id, &1_500, &800, &dummy_sig, &dummy_sig);
        assert_eq!(res, Err(Ok(PaymentChannelError::BalanceMismatch)));
    }

    #[test]
    fn test_update_state_negative_balance() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _p_a, _p_b, channel_id) = setup_channel(&env);
        let dummy_sig = BytesN::from_array(&env, &[0u8; 64]);

        let res = client.try_update_state(&channel_id, &-100, &2_100, &dummy_sig, &dummy_sig);
        assert_eq!(res, Err(Ok(PaymentChannelError::InvalidBalance)));
    }

    #[test]
    fn test_update_state_channel_already_closed() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _p_a, _p_b, channel_id) = setup_channel(&env);
        let dummy_sig = BytesN::from_array(&env, &[0u8; 64]);

        client.cooperative_close(&channel_id, &1_000, &1_000, &dummy_sig, &dummy_sig);
        let res = client.try_update_state(&channel_id, &1_200, &800, &dummy_sig, &dummy_sig);
        assert_eq!(res, Err(Ok(PaymentChannelError::ChannelAlreadyClosed)));
    }

    #[test]
    fn test_unilateral_close_unauthorized() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _p_a, _p_b, channel_id) = setup_channel(&env);
        let stranger = Address::generate(&env);

        let res = client.try_initiate_unilateral_close(&channel_id, &stranger);
        assert_eq!(res, Err(Ok(PaymentChannelError::UnauthorizedParticipant)));
    }

    #[test]
    fn test_top_up_unauthorized() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _p_a, _p_b, channel_id) = setup_channel(&env);
        let stranger = Address::generate(&env);

        let res = client.try_top_up(&channel_id, &500, &stranger);
        assert_eq!(res, Err(Ok(PaymentChannelError::UnauthorizedParticipant)));
    }

    #[test]
    fn test_top_up_success() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, p_a, _p_b, channel_id) = setup_channel(&env);

        client.top_up(&channel_id, &500, &p_a);
        let state = client.get_channel_state(&channel_id);
        assert_eq!(state.balance_a, 1_500);
        assert_eq!(state.total_balance, 2_500);
        assert_eq!(state.sequence_number, 1);
    }
}

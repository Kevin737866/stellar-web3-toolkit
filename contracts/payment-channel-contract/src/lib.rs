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

use error::PaymentChannelError;
use soroban_sdk::{
    contract, contractimpl, contractmeta, Address, Bytes, BytesN, Env, IntoVal, TryFromVal,
    Vec as SorobanVec,
};
use types::{ChannelState, HTLCInfo, HtlcList};

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

        let _total_balance = initial_balance_a + initial_balance_b;
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
        _signature_a: BytesN<64>,
        _signature_b: BytesN<64>,
    ) -> Result<(), PaymentChannelError> {
        let mut state = state::get_channel_state(&env, &channel_id)?;

        if state.close_time != 0 {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }

        if new_balance_a < 0 || new_balance_b < 0 {
            return Err(PaymentChannelError::InvalidBalance);
        }
        let new_total = new_balance_a + new_balance_b;
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

        if state.close_time != 0 {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }

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

    /// Initiate cooperative close of the channel
    pub fn cooperative_close(
        env: Env,
        channel_id: BytesN<32>,
        final_balance_a: i128,
        final_balance_b: i128,
        _signature_a: BytesN<64>,
        _signature_b: BytesN<64>,
    ) -> Result<(), PaymentChannelError> {
        let mut state = state::get_channel_state(&env, &channel_id)?;

        if state.close_time != 0 {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }

        if final_balance_a < 0 || final_balance_b < 0 {
            return Err(PaymentChannelError::InvalidBalance);
        }
        let total = final_balance_a + final_balance_b;
        if total != state.total_balance {
            return Err(PaymentChannelError::BalanceMismatch);
        }

        state.participant_a.require_auth();
        state.participant_b.require_auth();

        state.balance_a = final_balance_a;
        state.balance_b = final_balance_b;
        state.is_cooperative_close = true;
        state.close_time = env.ledger().timestamp();
        state.sequence_number += 1;

        state::store_channel_state(&env, &channel_id, &state);

        env.events().publish(
            ("channel_close", channel_id),
            ("cooperative", state.close_time),
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

        if state.close_time != 0 {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }

        if initiator != state.participant_a && initiator != state.participant_b {
            return Err(PaymentChannelError::UnauthorizedParticipant);
        }

        initiator.require_auth();

        let has_active = state::has_active_htlcs(&env, &state.htlcs)?;
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
        _contesting_balance_a: i128,
        _contesting_balance_b: i128,
        contest_sequence: u32,
        _signature: BytesN<64>,
    ) -> Result<(), PaymentChannelError> {
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

        if state.close_time != 0 {
            return Err(PaymentChannelError::ChannelAlreadyClosed);
        }

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

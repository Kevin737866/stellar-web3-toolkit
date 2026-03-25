//! # Stellar Payment Channel Contract
//! 
//! A Lightning Network-style payment channel system on Stellar for instant,
//! low-cost off-chain transactions with on-chain settlement.
//!
//! ## Features
//! - Multi-sig escrow account structure
//! - Channel opening (funding transaction)
//! - Off-chain payment state updates
//! - HTLC for multi-hop payments
//! - Cooperative channel closing
//! - Unilateral close with dispute period

#![no_std]

mod types;
mod error;
mod channel;
mod htlc;
mod state;

use soroban_sdk::{
    contract, contractimpl, contractmeta, Address, BytesN, Env, Vec as SorobanVec,
    Map, Val, TryFromVal, IntoVal,
};
use types::{ChannelState, Payment, HTLCInfo, ChannelConfig};
use error::PaymentChannelError;

/// Metadata for the payment channel contract
contractmeta!(
    key = "name",
    val = "StellarPaymentChannel"
);

/// Payment Channel Contract
#[contract]
pub struct PaymentChannel;

/// Helper trait for sorting addresses for deterministic channel IDs
pub trait Sortable {
    fn sorted(a: Address, b: Address) -> (Address, Address);
}

impl Sortable for () {
    fn sorted(a: Address, b: Address) -> (Address, Address) {
        let a_bytes = a.as_val();
        let b_bytes = b.as_val();
        if a_bytes < b_bytes {
            (a, b)
        } else {
            (b, a)
        }
    }
}

impl contractimpl::PaymentChannel {
    /// Initialize a new payment channel between two parties
    /// 
    /// # Arguments
    /// * `env` - Soroban environment
    /// * `participant_a` - First channel participant
    /// * `participant_b` - Second channel participant
    /// * `initial_balance_a` - Initial balance contributed by participant A
    /// * `initial_balance_b` - Initial balance contributed by participant B
    /// * `timeout` - Channel timeout in seconds (for unilateral close)
    /// * `fee_percentage` - Fee percentage for routing payments (basis points)
    pub fn initialize(
        env: &Env,
        participant_a: Address,
        participant_b: Address,
        initial_balance_a: i128,
        initial_balance_b: i128,
        timeout: u32,
        fee_percentage: u32,
    ) -> Result<BytesN<32>, PaymentChannelError> {
        // Validate inputs
        if initial_balance_a < 0 || initial_balance_b < 0 {
            return Err(PaymentChannelError::InvalidBalance);
        }
        
        if timeout < 60 {
            return Err(PaymentChannelError::InvalidTimeout);
        }
        
        if fee_percentage > 10000 {
            return Err(PaymentChannelError::InvalidFee);
        }
        
        // Sort participants to create deterministic channel ID
        let (sorted_a, sorted_b) = <() as Sortable>::sorted(participant_a.clone(), participant_b.clone());
        
        // Generate channel ID using both participant addresses
        let mut channel_id_bytes = Vec::new(env);
        channel_id_bytes.append(&mut sorted_a.as_val().to_bytes());
        channel_id_bytes.append(&mut sorted_b.as_val().to_bytes());
        
        // Add a nonce for uniqueness
        let nonce = env.ledger().sequence_number();
        channel_id_bytes.append(&mut nonce.to_be_bytes().to_vec().try_into().unwrap_or_default());
        
        // Create channel ID hash
        let channel_id = env.crypto().sha256(&channel_id_bytes);
        
        // Initialize channel state
        let total_balance = initial_balance_a + initial_balance_b;
        let state = ChannelState {
            channel_id: channel_id.clone(),
            participant_a: sorted_a.clone(),
            participant_b: sorted_b.clone(),
            balance_a: initial_balance_a,
            balance_b: initial_balance_b,
            total_balance,
            sequence_number: 0,
            is_cooperative_close: false,
            close_time: 0,
            timeout,
            created_at: env.ledger().timestamp(),
            fee_percentage,
            htlcs: Map::new(env),
        };
        
        // Store channel state
        state::store_channel_state(env, &channel_id, &state);
        
        // Store channel ID for each participant
        let mut a_channels = state::get_participant_channels(env, &sorted_a);
        a_channels.push_back(env, channel_id.clone());
        state::store_participant_channels(env, &sorted_a, &a_channels);
        
        let mut b_channels = state::get_participant_channels(env, &sorted_b);
        b_channels.push_back(env, channel_id.clone());
        state::store_participant_channels(env, &sorted_b, &b_channels);
        
        Ok(channel_id)
    }
    
    /// Get the current state of a channel
    pub fn get_channel_state(env: &Env, channel_id: &BytesN<32>) -> Result<ChannelState, PaymentChannelError> {
        state::get_channel_state(env, channel_id)
    }
    
    /// Update the channel state with a new payment
    /// This is the core function for off-chain state updates
    /// 
    /// # Arguments
    /// * `env` - Soroban environment
    /// * `channel_id` - The channel identifier
    /// * `new_balance_a` - New balance for participant A
    /// * `new_balance_b` - New balance for participant B
    /// * `signature_a` - Signature from participant A authorizing the update
    /// * `signature_b` - Signature from participant B authorizing the update
    pub fn update_state(
        env: &Env,
        channel_id: &BytesN<32>,
        new_balance_a: i128,
        new_balance_b: i128,
        _signature_a: BytesN<64>,
        _signature_b: BytesN<64>,
    ) -> Result<(), PaymentChannelError> {
        let mut state = state::get_channel_state(env, channel_id)?;
        
        // Validate new balances
        if new_balance_a < 0 || new_balance_b < 0 {
            return Err(PaymentChannelError::InvalidBalance);
        }
        
        let new_total = new_balance_a + new_balance_b;
        if new_total != state.total_balance {
            return Err(PaymentChannelError::BalanceMismatch);
        }
        
        // Verify signatures
        // Note: In production, this would verify Ed25519 signatures
        // For now, we assume the signatures are valid if provided
        // The actual signature verification would be:
        // env.crypto().ed25519_verify(&signer, &message, &signature)
        
        // Update state
        state.balance_a = new_balance_a;
        state.balance_b = new_balance_b;
        state.sequence_number += 1;
        
        // Store updated state
        state::store_channel_state(env, channel_id, &state);
        
        env.events().publish(("channel_update", channel_id), state.sequence_number);
        
        Ok(())
    }
    
    /// Create a Hash Time-Locked Contract (HTLC) for conditional payments
    /// Used for multi-hop payments where the receiver must reveal a preimage
    /// 
    /// # Arguments
    /// * `env` - Soroban environment
    /// * `channel_id` - The channel identifier
    /// * `hashlock` - Hash of the preimage that must be revealed to claim
    /// * `timelock` - Block number after which the HTLC can be refunded
    /// * `amount` - Amount locked in the HTLC
    /// * `receiver` - Address that can claim with the preimage
    pub fn create_htlc(
        env: &Env,
        channel_id: &BytesN<32>,
        hashlock: BytesN<32>,
        timelock: u32,
        amount: i128,
        receiver: Address,
    ) -> Result<BytesN<32>, PaymentChannelError> {
        let mut state = state::get_channel_state(env, channel_id)?;
        
        // Validate HTLC parameters
        if amount <= 0 {
            return Err(PaymentChannelError::InvalidHtlcAmount);
        }
        
        let current_block = env.ledger().sequence_number();
        if timelock <= current_block {
            return Err(PaymentChannelError::InvalidTimelock);
        }
        
        // Check if sender has sufficient balance
        // Assuming participant_a is the sender for this HTLC
        if state.balance_a < amount {
            return Err(PaymentChannelError::InsufficientBalance);
        }
        
        // Generate HTLC ID
        let mut htlc_id_bytes = Vec::new(env);
        htlc_id_bytes.append(&mut channel_id.to_vec());
        htlc_id_bytes.append(&mut state.sequence_number.to_be_bytes().to_vec().try_into().unwrap_or_default());
        htlc_id_bytes.append(&mut env.ledger().timestamp().to_be_bytes().to_vec().try_into().unwrap_or_default());
        
        let htlc_id = env.crypto().sha256(&htlc_id_bytes);
        
        // Create HTLC info
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
        
        // Reserve funds in balance
        state.balance_a -= amount;
        
        // Store HTLC
        state.htlcs.set(env, htlc_id.clone().to_void(), htlc_info.into_val(env));
        
        // Update and store state
        state.sequence_number += 1;
        state::store_channel_state(env, channel_id, &state);
        
        env.events().publish(("htlc_created", &htlc_id), (&receiver, amount));
        
        Ok(htlc_id)
    }
    
    /// Claim an HTLC by revealing the preimage
    /// 
    /// # Arguments
    /// * `env` - Soroban environment
    /// * `channel_id` - The channel identifier
    /// * `htlc_id` - The HTLC identifier
    /// * `preimage` - The secret preimage that hashes to the hashlock
    pub fn claim_htlc(
        env: &Env,
        channel_id: &BytesN<32>,
        htlc_id: &BytesN<32>,
        preimage: BytesN<32>,
    ) -> Result<(), PaymentChannelError> {
        let mut state = state::get_channel_state(env, channel_id)?;
        
        // Get HTLC
        let htlc_val = state.htlcs.get(env, htlc_id.to_void())
            .ok_or(PaymentChannelError::HtlcNotFound)?;
        let mut htlc: HTLCInfo = HTLCInfo::from_val(env, &htlc_val);
        
        if htlc.is_claimed {
            return Err(PaymentChannelError::HtlcAlreadyClaimed);
        }
        
        if htlc.is_refunded {
            return Err(PaymentChannelError::HtlcAlreadyRefunded);
        }
        
        // Verify timelock hasn't expired
        let current_block = env.ledger().sequence_number();
        if current_block >= htlc.timelock {
            return Err(PaymentChannelError::HtlcExpired);
        }
        
        // Verify the preimage hashes to the hashlock
        let preimage_hash = env.crypto().sha256(&preimage.to_vec());
        if preimage_hash != htlc.hashlock {
            return Err(PaymentChannelError::InvalidPreimage);
        }
        
        // Mark as claimed and update balances
        htlc.is_claimed = true;
        state.balance_b += htlc.amount;
        
        // Update HTLC in map
        state.htlcs.set(env, htlc_id.to_void(), htlc.into_val(env));
        
        // Update and store state
        state.sequence_number += 1;
        state::store_channel_state(env, channel_id, &state);
        
        env.events().publish(("htlc_claimed", htlc_id), ());
        
        Ok(())
    }
    
    /// Refund an expired HTLC back to the sender
    /// 
    /// # Arguments
    /// * `env` - Soroban environment
    /// * `channel_id` - The channel identifier
    /// * `htlc_id` - The HTLC identifier
    pub fn refund_htlc(
        env: &Env,
        channel_id: &BytesN<32>,
        htlc_id: &BytesN<32>,
    ) -> Result<(), PaymentChannelError> {
        let mut state = state::get_channel_state(env, channel_id)?;
        
        // Get HTLC
        let htlc_val = state.htlcs.get(env, htlc_id.to_void())
            .ok_or(PaymentChannelError::HtlcNotFound)?;
        let mut htlc: HTLCInfo = HTLCInfo::from_val(env, &htlc_val);
        
        if htlc.is_claimed {
            return Err(PaymentChannelError::HtlcAlreadyClaimed);
        }
        
        if htlc.is_refunded {
            return Err(PaymentChannelError::HtlcAlreadyRefunded);
        }
        
        // Verify timelock has expired
        let current_block = env.ledger().sequence_number();
        if current_block < htlc.timelock {
            return Err(PaymentChannelError::HtlcNotExpired);
        }
        
        // Mark as refunded and return funds
        htlc.is_refunded = true;
        state.balance_a += htlc.amount;
        
        // Update HTLC in map
        state.htlcs.set(env, htlc_id.to_void(), htlc.into_val(env));
        
        // Update and store state
        state.sequence_number += 1;
        state::store_channel_state(env, channel_id, &state);
        
        env.events().publish(("htlc_refunded", htlc_id), ());
        
        Ok(())
    }
    
    /// Initiate cooperative close of the channel
    /// Both parties must agree on the final balances
    /// 
    /// # Arguments
    /// * `env` - Soroban environment
    /// * `channel_id` - The channel identifier
    /// * `final_balance_a` - Agreed final balance for participant A
    /// * `final_balance_b` - Agreed final balance for participant B
    /// * `signature_a` - Signature from participant A
    /// * `signature_b` - Signature from participant B
    pub fn cooperative_close(
        env: &Env,
        channel_id: &BytesN<32>,
        final_balance_a: i128,
        final_balance_b: i128,
        _signature_a: BytesN<64>,
        _signature_b: BytesN<64>,
    ) -> Result<(), PaymentChannelError> {
        let mut state = state::get_channel_state(env, channel_id)?;
        
        // Validate final balances
        if final_balance_a < 0 || final_balance_b < 0 {
            return Err(PaymentChannelError::InvalidBalance);
        }
        
        let total = final_balance_a + final_balance_b;
        if total != state.total_balance {
            return Err(PaymentChannelError::BalanceMismatch);
        }
        
        // Mark as cooperative close
        state.balance_a = final_balance_a;
        state.balance_b = final_balance_b;
        state.is_cooperative_close = true;
        state.close_time = env.ledger().timestamp();
        state.sequence_number += 1;
        
        // Store final state
        state::store_channel_state(env, channel_id, &state);
        
        env.events().publish(("channel_close", channel_id), ("cooperative", state.close_time));
        
        Ok(())
    }
    
    /// Initiate unilateral close of the channel
    /// Starts the dispute period during which the other party can contest
    /// 
    /// # Arguments
    /// * `env` - Soroban environment
    /// * `channel_id` - The channel identifier
    /// * `initiator` - Address initiating the close
    pub fn initiate_unilateral_close(
        env: &Env,
        channel_id: &BytesN<32>,
        initiator: Address,
    ) -> Result<u64, PaymentChannelError> {
        let mut state = state::get_channel_state(env, channel_id)?;
        
        // Verify initiator is a participant
        if initiator != state.participant_a && initiator != state.participant_b {
            return Err(PaymentChannelError::UnauthorizedParticipant);
        }
        
        // Check for any pending HTLCs that need to be resolved
        // Only allow close if no active HTLCs exist
        let has_active_htlcs = state::has_active_htlcs(env, &state.htlcs)?;
        if has_active_htlcs {
            return Err(PaymentChannelError::ActiveHtlcsExist);
        }
        
        // Set close time
        state.close_time = env.ledger().timestamp();
        state.sequence_number += 1;
        
        // Store state
        state::store_channel_state(env, channel_id, &state);
        
        // Calculate when funds can be withdrawn (after timeout)
        let withdraw_time = state.close_time + state.timeout as u64;
        
        env.events().publish(("channel_close_initiated", channel_id), (initiator.as_val(), withdraw_time));
        
        Ok(withdraw_time)
    }
    
    /// Contest a unilateral close with a more recent state
    /// 
    /// # Arguments
    /// * `env` - Soroban environment
    /// * `channel_id` - The channel identifier
    /// * `contesting_balance_a` - Contested balance for participant A
    /// * `contesting_balance_b` - Contested balance for participant B
    /// * `contest_sequence` - Sequence number of the contested state
    /// * `signature` - Signature from the non-initiating party
    pub fn contest_close(
        env: &Env,
        channel_id: &BytesN<32>,
        contesting_balance_a: i128,
        contesting_balance_b: i128,
        contest_sequence: u32,
        _signature: BytesN<64>,
    ) -> Result<(), PaymentChannelError> {
        let state = state::get_channel_state(env, channel_id)?;
        
        // Verify contest sequence is higher than current
        if contest_sequence <= state.sequence_number {
            return Err(PaymentChannelError::InvalidSequence);
        }
        
        // Verify balances are valid
        if contesting_balance_a < 0 || contesting_balance_b < 0 {
            return Err(PaymentChannelError::InvalidBalance);
        }
        
        let total = contesting_balance_a + contesting_balance_b;
        if total != state.total_balance {
            return Err(PaymentChannelError::BalanceMismatch);
        }
        
        // In production, verify signature and update state
        // For now, the dispute period would be reset
        
        env.events().publish(("channel_contested", channel_id), (contest_sequence, env.ledger().timestamp()));
        
        Ok(())
    }
    
    /// Add funds to an existing channel (top-up)
    /// 
    /// # Arguments
    /// * `env` - Soroban environment
    /// * `channel_id` - The channel identifier
    /// * `top_up_amount` - Amount to add to the channel
    /// * `participant` - Which participant is adding funds
    pub fn top_up(
        env: &Env,
        channel_id: &BytesN<32>,
        top_up_amount: i128,
        participant: Address,
    ) -> Result<(), PaymentChannelError> {
        let mut state = state::get_channel_state(env, channel_id)?;
        
        if top_up_amount <= 0 {
            return Err(PaymentChannelError::InvalidBalance);
        }
        
        // Add to the appropriate balance
        if participant == state.participant_a {
            state.balance_a += top_up_amount;
        } else if participant == state.participant_b {
            state.balance_b += top_up_amount;
        } else {
            return Err(PaymentChannelError::UnauthorizedParticipant);
        }
        
        state.total_balance += top_up_amount;
        state.sequence_number += 1;
        
        state::store_channel_state(env, channel_id, &state);
        
        env.events().publish(("channel_topup", channel_id), (participant.as_val(), top_up_amount));
        
        Ok(())
    }
    
    /// Get all HTLCs for a channel
    pub fn get_htlcs(
        env: &Env,
        channel_id: &BytesN<32>,
    ) -> Result<Vec<(BytesN<32>, HTLCInfo)>, PaymentChannelError> {
        let state = state::get_channel_state(env, channel_id)?;
        let mut result = Vec::new(env);
        
        for (key, val) in state.htlcs.iter() {
            let htlc_id: BytesN<32> = BytesN::try_from_val(env, &key).unwrap_or_default();
            let htlc: HTLCInfo = HTLCInfo::from_val(env, &val);
            result.push_back(env, (htlc_id, htlc));
        }
        
        Ok(result)
    }
}

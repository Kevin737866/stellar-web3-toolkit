//! # Payment Channel Module
//! 
//! Core channel management logic for the payment channel system.

use soroban_sdk::{Env, BytesN, Address, Vec, Map, Val};

use crate::types::{ChannelState, ChannelConfig, ChannelStats, RouteHop, Payment};
use crate::error::PaymentChannelError;

/// Channel manager for handling channel operations
pub struct ChannelManager;

impl ChannelManager {
    /// Create a new payment channel
    pub fn create_channel(
        env: &Env,
        participant_a: Address,
        participant_b: Address,
        initial_balance_a: i128,
        initial_balance_b: i128,
        timeout: u32,
        fee_percentage: u32,
    ) -> Result<ChannelState, PaymentChannelError> {
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
        
        // Sort participants for deterministic ordering
        let (sorted_a, sorted_b) = Self::sort_participants(participant_a.clone(), participant_b.clone());
        
        // Generate channel ID
        let channel_id = Self::generate_channel_id(env, &sorted_a, &sorted_b);
        
        // Create channel state
        let mut channel = ChannelState::new(
            env,
            channel_id,
            sorted_a,
            sorted_b,
            initial_balance_a,
            initial_balance_b,
            timeout,
            fee_percentage,
        );
        
        // Validate channel reserves
        let config = ChannelConfig::default();
        if initial_balance_a < config.channel_reserve || initial_balance_b < config.channel_reserve {
            return Err(PaymentChannelError::ReserveNotMet);
        }
        
        Ok(channel)
    }
    
    /// Sort two addresses deterministically
    fn sort_participants(a: Address, b: Address) -> (Address, Address) {
        let a_val = a.as_val();
        let b_val = b.as_val();
        if a_val < b_val {
            (a, b)
        } else {
            (b, a)
        }
    }
    
    /// Generate a unique channel ID
    fn generate_channel_id(
        env: &Env,
        participant_a: &Address,
        participant_b: &Address,
    ) -> BytesN<32> {
        let mut data = Vec::new(env);
        data.append(&mut participant_a.as_val().to_bytes());
        data.append(&mut participant_b.as_val().to_bytes());
        data.append(&mut env.ledger().sequence_number().to_be_bytes().to_vec().try_into().unwrap_or_default());
        data.append(&mut env.ledger().timestamp().to_be_bytes().to_vec().try_into().unwrap_or_default());
        
        env.crypto().sha256(&data)
    }
    
    /// Validate that a payment is valid within this channel
    pub fn validate_payment(
        channel: &ChannelState,
        amount: i128,
        from_a: bool,
        config: &ChannelConfig,
    ) -> Result<(), PaymentChannelError> {
        // Check amount limits
        if amount < config.min_htlc_value {
            return Err(PaymentChannelError::PaymentBelowDustLimit);
        }
        
        if amount > config.max_htlc_value {
            return Err(PaymentChannelError::AmountExceedsMaximum);
        }
        
        // Check sender has sufficient balance
        if from_a && channel.balance_a < amount {
            return Err(PaymentChannelError::InsufficientBalance);
        }
        
        if !from_a && channel.balance_b < amount {
            return Err(PaymentChannelError::InsufficientBalance);
        }
        
        // Check reserve is maintained
        if from_a && channel.balance_a - amount < config.channel_reserve {
            return Err(PaymentChannelError::ReserveNotMet);
        }
        
        if !from_a && channel.balance_b - amount < config.channel_reserve {
            return Err(PaymentChannelError::ReserveNotMet);
        }
        
        Ok(())
    }
    
    /// Calculate the fee for routing a payment through this channel
    pub fn calculate_fee(channel: &ChannelState, amount: i128) -> i128 {
        // Fee is calculated as a percentage of the amount
        // fee = amount * fee_percentage / 10000
        (amount * channel.fee_percentage as i128) / 10000
    }
    
    /// Calculate the fee for a multi-hop route
    pub fn calculate_route_fee(hops: &[RouteHop], amount: i128) -> i128 {
        let mut total_fee = 0i128;
        let mut remaining = amount;
        
        for hop in hops {
            let fee = Self::calculate_fee_from_amount(remaining, hop.fee, hop.cltv_delta);
            total_fee += fee;
            remaining += fee;
        }
        
        total_fee
    }
    
    /// Calculate fee from amount with CLTV delta consideration
    fn calculate_fee_from_amount(amount: i128, base_fee: i128, cltv_delta: u32) -> i128 {
        // Fee model:
        // - Base fee (covers operational costs)
        // - Proportional fee (1% default)
        let proportional_fee = (amount * 100) / 10000;
        let cltv_fee = (cltv_delta as i128 * 10) / 1440; // Roughly 1 XLM per day of timelock
        
        base_fee + proportional_fee + cltv_fee
    }
    
    /// Get the effective balance for sending from a specific direction
    pub fn get_send_capacity(channel: &ChannelState, from_a: bool, reserve: i128) -> i128 {
        if from_a {
            // Can send up to balance_a minus reserve
            (channel.balance_a - reserve).max(0)
        } else {
            // Can send up to balance_b minus reserve
            (channel.balance_b - reserve).max(0)
        }
    }
    
    /// Get the receive capacity for a specific direction
    pub fn get_receive_capacity(channel: &ChannelState, from_a: bool, reserve: i128) -> i128 {
        if from_a {
            // Can receive up to balance_b minus reserve
            (channel.balance_b - reserve).max(0)
        } else {
            // Can receive up to balance_a minus reserve
            (channel.balance_a - reserve).max(0)
        }
    }
    
    /// Check if the channel supports a payment amount
    pub fn can_support_payment(channel: &ChannelState, amount: i128, from_a: bool, reserve: i128) -> bool {
        let capacity = if from_a {
            Self::get_send_capacity(channel, true, reserve)
        } else {
            Self::get_send_capacity(channel, false, reserve)
        };
        
        capacity >= amount
    }
    
    /// Get channel age in seconds
    pub fn get_channel_age(channel: &ChannelState, current_time: u64) -> u64 {
        if channel.created_at > 0 {
            current_time - channel.created_at
        } else {
            0
        }
    }
    
    /// Check if channel is considered stale (no activity for a period)
    pub fn is_channel_stale(channel: &ChannelState, last_activity: u64, stale_threshold: u64) -> bool {
        last_activity > 0 && (Env::default().ledger().timestamp() - last_activity) > stale_threshold
    }
    
    /// Calculate channel utilization percentage
    pub fn get_utilization(channel: &ChannelState) -> u32 {
        let max_capacity = channel.total_balance;
        let used_capacity = channel.balance_a.min(channel.balance_b);
        
        if max_capacity > 0 {
            ((used_capacity as u64 * 100) / max_capacity as u64) as u32
        } else {
            0
        }
    }
    
    /// Rebalance the channel by swapping capacities
    /// This is a cooperative operation that requires both parties to sign
    pub fn rebalance(
        channel: &mut ChannelState,
        amount: i128,
    ) -> Result<(), PaymentChannelError> {
        // Both parties contribute equal amounts to increase capacity
        // This is used when one side is running low on funds
        
        if amount < 0 {
            return Err(PaymentChannelError::InvalidBalance);
        }
        
        // Add the rebalance amount to both sides
        channel.balance_a += amount;
        channel.balance_b += amount;
        channel.total_balance += amount * 2;
        channel.sequence_number += 1;
        
        Ok(())
    }
    
    /// Get a summary of channel state for debugging/monitoring
    pub fn get_channel_summary(channel: &ChannelState) -> ChannelSummary {
        ChannelSummary {
            channel_id: channel.channel_id.clone(),
            participant_a: channel.participant_a.clone(),
            participant_b: channel.participant_b.clone(),
            total_balance: channel.total_balance,
            balance_a: channel.balance_a,
            balance_b: channel.balance_b,
            utilization: Self::get_utilization(channel),
            is_open: channel.close_time == 0,
            num_htlcs: channel.htlcs.len() as u32,
        }
    }
}

/// Summary of channel state for quick overview
#[derive(Clone)]
pub struct ChannelSummary {
    pub channel_id: BytesN<32>,
    pub participant_a: Address,
    pub participant_b: Address,
    pub total_balance: i128,
    pub balance_a: i128,
    pub balance_b: i128,
    pub utilization: u32,
    pub is_open: bool,
    pub num_htlcs: u32,
}

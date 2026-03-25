//! # Payment Channel Types
//! 
//! Core data types for the Stellar payment channel system.

use soroban_sdk::{
    Address, BytesN, Env, Vec, Map, Val,
    TryFromVal, IntoVal, TryIntoVal,
};

/// Represents a payment channel between two participants
#[derive(Clone)]
pub struct ChannelState {
    /// Unique identifier for this channel
    pub channel_id: BytesN<32>,
    /// First participant's address
    pub participant_a: Address,
    /// Second participant's address
    pub participant_b: Address,
    /// Current balance of participant A
    pub balance_a: i128,
    /// Current balance of participant B
    pub balance_b: i128,
    /// Total balance in the channel (should equal balance_a + balance_b)
    pub total_balance: i128,
    /// Sequence number for state updates (for dispute resolution)
    pub sequence_number: u32,
    /// Whether this is a cooperative close
    pub is_cooperative_close: bool,
    /// Timestamp when channel was closed (0 if open)
    pub close_time: u64,
    /// Timeout in seconds for unilateral close dispute period
    pub timeout: u32,
    /// When the channel was created
    pub created_at: u64,
    /// Fee percentage for routing payments (in basis points, 10000 = 100%)
    pub fee_percentage: u32,
    /// Active HTLCs in this channel
    pub htlcs: Map<Val, Val>,
}

impl ChannelState {
    pub fn new(
        env: &Env,
        channel_id: BytesN<32>,
        participant_a: Address,
        participant_b: Address,
        initial_balance_a: i128,
        initial_balance_b: i128,
        timeout: u32,
        fee_percentage: u32,
    ) -> Self {
        ChannelState {
            channel_id,
            participant_a,
            participant_b,
            balance_a: initial_balance_a,
            balance_b: initial_balance_b,
            total_balance: initial_balance_a + initial_balance_b,
            sequence_number: 0,
            is_cooperative_close: false,
            close_time: 0,
            timeout,
            created_at: env.ledger().timestamp(),
            fee_percentage,
            htlcs: Map::new(env),
        }
    }
    
    /// Check if the channel can make a payment of given amount
    pub fn can_pay(&self, amount: i128, from_a: bool) -> bool {
        if from_a {
            self.balance_a >= amount
        } else {
            self.balance_b >= amount
        }
    }
    
    /// Execute a payment, updating balances
    pub fn execute_payment(&mut self, amount: i128, from_a: bool) -> Result<(), &'static str> {
        if from_a {
            if self.balance_a < amount {
                return Err("Insufficient balance");
            }
            self.balance_a -= amount;
            self.balance_b += amount;
        } else {
            if self.balance_b < amount {
                return Err("Insufficient balance");
            }
            self.balance_b -= amount;
            self.balance_a += amount;
        }
        self.sequence_number += 1;
        Ok(())
    }
}

/// Represents a payment between two parties
#[derive(Clone)]
pub struct Payment {
    /// Amount being transferred
    pub amount: i128,
    /// Sender's address
    pub sender: Address,
    /// Receiver's address
    pub receiver: Address,
    /// Channel ID this payment is made through
    pub channel_id: BytesN<32>,
    /// Payment sequence number
    pub sequence: u32,
    /// Timestamp of the payment
    pub timestamp: u64,
    /// Optional memo for the payment
    pub memo: Option<BytesN<32>>,
}

impl Payment {
    pub fn new(
        env: &Env,
        amount: i128,
        sender: Address,
        receiver: Address,
        channel_id: BytesN<32>,
    ) -> Self {
        Payment {
            amount,
            sender,
            receiver,
            channel_id,
            sequence: env.ledger().sequence_number(),
            timestamp: env.ledger().timestamp(),
            memo: None,
        }
    }
    
    /// Create a payment with a memo
    pub fn with_memo(
        env: &Env,
        amount: i128,
        sender: Address,
        receiver: Address,
        channel_id: BytesN<32>,
        memo: BytesN<32>,
    ) -> Self {
        Payment {
            amount,
            sender,
            receiver,
            channel_id,
            sequence: env.ledger().sequence_number(),
            timestamp: env.ledger().timestamp(),
            memo: Some(memo),
        }
    }
}

/// Hash Time-Locked Contract information
#[derive(Clone)]
pub struct HTLCInfo {
    /// Unique identifier for this HTLC
    pub htlc_id: BytesN<32>,
    /// Hash of the preimage that must be revealed
    pub hashlock: BytesN<32>,
    /// Block number after which HTLC can be refunded
    pub timelock: u32,
    /// Amount locked in the HTLC
    pub amount: i128,
    /// Address that can claim with the preimage
    pub receiver: Address,
    /// Address that created the HTLC (and can refund after timelock)
    pub sender: Address,
    /// Whether the HTLC has been claimed
    pub is_claimed: bool,
    /// Whether the HTLC has been refunded
    pub is_refunded: bool,
    /// When the HTLC was created
    pub created_at: u64,
}

impl HTLCInfo {
    pub fn new(
        env: &Env,
        hashlock: BytesN<32>,
        timelock: u32,
        amount: i128,
        receiver: Address,
        sender: Address,
    ) -> Self {
        let mut htlc_id_bytes = Vec::new(env);
        htlc_id_bytes.append(&mut hashlock.to_vec());
        htlc_id_bytes.append(&mut sender.as_val().to_bytes());
        htlc_id_bytes.append(&mut env.ledger().timestamp().to_be_bytes().to_vec().try_into().unwrap_or_default());
        
        let htlc_id = env.crypto().sha256(&htlc_id_bytes);
        
        HTLCInfo {
            htlc_id,
            hashlock,
            timelock,
            amount,
            receiver,
            sender,
            is_claimed: false,
            is_refunded: false,
            created_at: env.ledger().timestamp(),
        }
    }
    
    /// Check if HTLC is still active (not claimed or refunded)
    pub fn is_active(&self) -> bool {
        !self.is_claimed && !self.is_refunded
    }
    
    /// Check if HTLC has expired (timelock passed)
    pub fn is_expired(&self, current_block: u32) -> bool {
        current_block >= self.timelock
    }
}

/// Configuration for a payment channel
#[derive(Clone)]
pub struct ChannelConfig {
    /// Maximum number of HTLCs allowed in the channel
    pub max_htlcs: u32,
    /// Maximum HTLC value (for limiting exposure)
    pub max_htlc_value: i128,
    /// Minimum HTLC value (dust limit)
    pub min_htlc_value: i128,
    /// Channel reserve (minimum balance each party must maintain)
    pub channel_reserve: i128,
    /// Force push payment enabled
    pub force_push_enabled: bool,
    /// Whether to accept routed payments
    pub accept_routed_payments: bool,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        ChannelConfig {
            max_htlcs: 100,
            max_htlc_value: i128::MAX,
            min_htlc_value: 100, // 100 stroops minimum
            channel_reserve: 100, // Must maintain minimum balance
            force_push_enabled: false,
            accept_routed_payments: true,
        }
    }
}

/// Represents a routing hop in a multi-hop payment
#[derive(Clone)]
pub struct RouteHop {
    /// Channel ID for this hop
    pub channel_id: BytesN<32>,
    /// Node address for this hop
    pub node: Address,
    /// Amount to forward
    pub amount: i128,
    /// Fee for this hop
    pub fee: i128,
    /// CLTV expiry delta for this hop
    pub cltv_delta: u32,
}

impl RouteHop {
    pub fn new(
        channel_id: BytesN<32>,
        node: Address,
        amount: i128,
        fee: i128,
        cltv_delta: u32,
    ) -> Self {
        RouteHop {
            channel_id,
            node,
            amount,
            fee,
            cltv_delta,
        }
    }
}

/// Channel statistics and metrics
#[derive(Clone)]
pub struct ChannelStats {
    /// Total payments sent
    pub total_payments_sent: u64,
    /// Total payments received
    pub total_payments_received: u64,
    /// Total value sent (in stroops)
    pub total_value_sent: i128,
    /// Total value received (in stroops)
    pub total_value_received: i128,
    /// Average payment size
    pub average_payment_size: i128,
    /// Channel uptime in seconds
    pub uptime_seconds: u64,
    /// Number of HTLCs fulfilled
    pub htlcs_fulfilled: u32,
    /// Number of HTLCs expired
    pub htlcs_expired: u32,
}

impl Default for ChannelStats {
    fn default() -> Self {
        ChannelStats {
            total_payments_sent: 0,
            total_payments_received: 0,
            total_value_sent: 0,
            total_value_received: 0,
            average_payment_size: 0,
            uptime_seconds: 0,
            htlcs_fulfilled: 0,
            htlcs_expired: 0,
        }
    }
}

impl ChannelStats {
    pub fn update_on_send(&mut self, amount: i128) {
        self.total_payments_sent += 1;
        self.total_value_sent += amount;
        if self.total_payments_sent > 0 {
            self.average_payment_size = self.total_value_sent / (self.total_payments_sent as i128);
        }
    }
    
    pub fn update_on_receive(&mut self, amount: i128) {
        self.total_payments_received += 1;
        self.total_value_received += amount;
    }
}

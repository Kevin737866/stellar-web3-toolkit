//! # HTLC (Hashed Time-Locked Contract) Module
//! 
//! Implementation of HTLC functionality for multi-hop payments.

use soroban_sdk::{Env, BytesN, Address, Vec, Map, Val};

use crate::types::HTLCInfo;
use crate::error::PaymentChannelError;

/// HTLC manager for handling time-locked contracts
pub struct HTLCManager;

impl HTLCManager {
    /// Create a new HTLC
    pub fn create_htlc(
        env: &Env,
        channel_id: &BytesN<32>,
        sender: Address,
        receiver: Address,
        amount: i128,
        hashlock: BytesN<32>,
        timelock: u32,
        sequence: u32,
    ) -> Result<HTLCInfo, PaymentChannelError> {
        // Validate inputs
        if amount <= 0 {
            return Err(PaymentChannelError::InvalidHtlcAmount);
        }
        
        let current_block = env.ledger().sequence_number();
        if timelock <= current_block {
            return Err(PaymentChannelError::InvalidTimelock);
        }
        
        // Generate unique HTLC ID
        let htlc_id = Self::generate_htlc_id(env, channel_id, &sender, sequence);
        
        let htlc = HTLCInfo {
            htlc_id: htlc_id.clone(),
            hashlock,
            timelock,
            amount,
            receiver,
            sender,
            is_claimed: false,
            is_refunded: false,
            created_at: env.ledger().timestamp(),
        };
        
        Ok(htlc)
    }
    
    /// Generate a unique HTLC ID
    fn generate_htlc_id(
        env: &Env,
        channel_id: &BytesN<32>,
        sender: &Address,
        sequence: u32,
    ) -> BytesN<32> {
        let mut data = Vec::new(env);
        data.append(&mut channel_id.to_vec());
        data.append(&mut sender.as_val().to_bytes());
        data.append(&mut sequence.to_be_bytes().to_vec().try_into().unwrap_or_default());
        data.append(&mut env.ledger().timestamp().to_be_bytes().to_vec().try_into().unwrap_or_default());
        
        env.crypto().sha256(&data)
    }
    
    /// Verify that a preimage hashes to the expected hashlock
    pub fn verify_preimage(env: &Env, preimage: &BytesN<32>, hashlock: &BytesN<32>) -> bool {
        let computed_hash = env.crypto().sha256(&preimage.to_vec());
        computed_hash == *hashlock
    }
    
    /// Check if HTLC can be claimed (not expired, not already claimed)
    pub fn can_claim(htlc: &HTLCInfo, current_block: u32) -> bool {
        !htlc.is_claimed && !htlc.is_refunded && current_block < htlc.timelock
    }
    
    /// Check if HTLC can be refunded (timelock expired, not claimed)
    pub fn can_refund(htlc: &HTLCInfo, current_block: u32) -> bool {
        !htlc.is_claimed && !htlc.is_refunded && current_block >= htlc.timelock
    }
    
    /// Get remaining time until HTLC expires (in blocks)
    pub fn get_time_remaining(htlc: &HTLCInfo, current_block: u32) -> i32 {
        htlc.timelock as i32 - current_block as i32
    }
    
    /// Validate HTLC for routing (multi-hop)
    pub fn validate_for_routing(
        htlc: &HTLCInfo,
        outgoing_cltv_delta: u32,
        current_block: u32,
    ) -> Result<(), PaymentChannelError> {
        // HTLC must not be expired
        if current_block >= htlc.timelock {
            return Err(PaymentChannelError::HtlcExpired);
        }
        
        // The outgoing HTLC must have a timelock that accounts for the CLTV delta
        // The outgoing timelock should be: current_block + cltv_delta + incoming_cltv_delta
        let min_timelock = current_block + outgoing_cltv_delta + 144; // Minimum buffer
        if htlc.timelock < min_timelock {
            return Err(PaymentChannelError::InvalidTimelock);
        }
        
        Ok(())
    }
    
    /// Calculate expiry bucket for HTLC tracking
    /// Groups HTLCs by expiry time for efficient monitoring
    pub fn get_expiry_bucket(htlc: &HTLCInfo, bucket_size: u32) -> u32 {
        (htlc.timelock / bucket_size) * bucket_size
    }
    
    /// Get HTLC status description
    pub fn get_status(htlc: &HTLCInfo, current_block: u32) -> &'static str {
        if htlc.is_claimed {
            "claimed"
        } else if htlc.is_refunded {
            "refunded"
        } else if current_block >= htlc.timelock {
            "expired"
        } else {
            "active"
        }
    }
    
    /// Serialize HTLC info to bytes for off-chain state
    pub fn serialize(htlc: &HTLCInfo) -> Vec<u8> {
        // In production, this would use proper serialization
        // For now, return the HTLC ID as the serialized form
        htlc.htlc_id.to_vec()
    }
    
    /// Calculate HTLC timeout based on fee and amount
    pub fn calculate_timeout(amount: i128, fee_per_block: i128) -> u32 {
        // Minimum timeout of 1 day (1440 blocks on Stellar)
        let min_timeout = 1440u32;
        
        // Calculate additional timeout based on fee
        // Higher fees = shorter timeout (priority)
        let additional_timeout = (amount / fee_per_block.max(1)) as u32;
        
        (min_timeout + additional_timeout).min(20160) // Max 2 weeks
    }
}

/// HTLC routing information for multi-hop payments
#[derive(Clone)]
pub struct HTLCRouteInfo {
    /// HTLC ID
    pub htlc_id: BytesN<32>,
    /// Previous hop HTLC ID (if any)
    pub prev_htlc_id: Option<BytesN<32>>,
    /// Next hop HTLC ID (if any)
    pub next_htlc_id: Option<BytesN<32>>,
    /// The preimage (only known after claim)
    pub preimage: Option<BytesN<32>>,
    /// Whether the HTLC chain is complete
    pub is_complete: bool,
}

impl HTLCRouteInfo {
    /// Create route info for a new HTLC
    pub fn new(htlc_id: BytesN<32>) -> Self {
        HTLCRouteInfo {
            htlc_id,
            prev_htlc_id: None,
            next_htlc_id: None,
            preimage: None,
            is_complete: false,
        }
    }
    
    /// Link this HTLC to a previous hop
    pub fn link_previous(&mut self, prev_id: BytesN<32>) {
        self.prev_htlc_id = Some(prev_id);
    }
    
    /// Link this HTLC to a next hop
    pub fn link_next(&mut self, next_id: BytesN<32>) {
        self.next_htlc_id = Some(next_id);
        self.is_complete = self.prev_htlc_id.is_some();
    }
    
    /// Set the preimage after claiming
    pub fn set_preimage(&mut self, preimage: BytesN<32>) {
        self.preimage = Some(preimage);
    }
}

/// HTLC commitment for off-chain state
#[derive(Clone)]
pub struct HTLCCommitment {
    /// Hash of the HTLC parameters
    pub commitment_hash: BytesN<32>,
    /// The value the HTLC will have
    pub amount: i128,
    /// When the HTLC expires
    pub expiry: u32,
    /// Whether this is a revocation
    pub is_revocation: bool,
}

impl HTLCCommitment {
    /// Create a commitment from HTLC info
    pub fn from_htlc(env: &Env, htlc: &HTLCInfo) -> Self {
        let mut data = Vec::new(env);
        data.append(&mut htlc.hashlock.to_vec());
        data.append(&mut htlc.amount.to_be_bytes().to_vec().try_into().unwrap_or_default());
        data.append(&mut htlc.timelock.to_be_bytes().to_vec().try_into().unwrap_or_default());
        
        let commitment_hash = env.crypto().sha256(&data);
        
        HTLCCommitment {
            commitment_hash,
            amount: htlc.amount,
            expiry: htlc.timelock,
            is_revocation: false,
        }
    }
    
    /// Create a revocation commitment
    pub fn revocation(env: &Env, per_commitment_point: &BytesN<32>, htlc: &HTLCInfo) -> Self {
        let mut data = Vec::new(env);
        data.append(&mut per_commitment_point.to_vec());
        data.append(&mut htlc.htlc_id.to_vec());
        
        let commitment_hash = env.crypto().sha256(&data);
        
        HTLCCommitment {
            commitment_hash,
            amount: htlc.amount,
            expiry: htlc.timelock,
            is_revocation: true,
        }
    }
}

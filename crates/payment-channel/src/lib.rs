//! # Payment Channel Library
//! 
//! High-level library for managing Stellar payment channels.
//! This library provides a Rust API for creating, managing, and closing
//! payment channels, as well as executing off-chain payments.

pub mod channel;
pub mod multi_sig;
pub mod htlc;
pub mod client;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use parking_lot::RwLock;
use thiserror::Error;

/// Payment channel errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PaymentChannelError {
    #[error("Channel not found: {0}")]
    ChannelNotFound(String),
    
    #[error("Insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: i128, need: i128 },
    
    #[error("Invalid state: {0}")]
    InvalidState(String),
    
    #[error("Signature error: {0}")]
    SignatureError(String),
    
    #[error("HTLC error: {0}")]
    HtlcError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Timeout: {0}")]
    Timeout(String),
    
    #[error("Channel closed: {0}")]
    ChannelClosed(String),
}

/// Channel status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelStatus {
    /// Channel is open and ready for payments
    Open,
    /// Channel is being closed cooperatively
    Closing,
    /// Channel was closed cooperatively
    Closed,
    /// Channel was force-closed
    ForceClosed,
    /// Channel is in dispute
    Dispute,
}

/// Local channel state for a participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalChannelState {
    /// Channel ID
    pub channel_id: String,
    /// Our address
    pub our_address: String,
    /// Their address
    pub their_address: String,
    /// Our current balance
    pub our_balance: i128,
    /// Their current balance
    pub their_balance: i128,
    /// Channel status
    pub status: ChannelStatus,
    /// Current sequence number
    pub sequence_number: u32,
    /// Funding transaction hash
    pub funding_tx_hash: Option<String>,
    /// Closing transaction hash (if closed)
    pub closing_tx_hash: Option<String>,
    /// Channel timeout (for unilateral close)
    pub timeout: u32,
    /// Fee percentage for routing
    pub fee_percentage: u32,
    /// Pending HTLCs
    pub pending_htlcs: Vec<HtlcState>,
    /// Local secret for signing
    pub local_secret: Vec<u8>,
    /// Remote public key
    pub remote_public_key: Vec<u8>,
}

/// HTLC state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtlcState {
    /// HTLC ID
    pub htlc_id: String,
    /// Amount
    pub amount: i128,
    /// Hash lock
    pub hashlock: Vec<u8>,
    /// Time lock
    pub timelock: u32,
    /// Whether we've claimed it
    pub is_claimed: bool,
    /// Whether we've refunded it
    pub is_refunded: bool,
    /// The preimage (if we know it)
    pub preimage: Option<Vec<u8>>,
    /// Direction (incoming/outgoing)
    pub direction: HtlcDirection,
}

/// HTLC direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HtlcDirection {
    /// HTLC is incoming (they're paying us)
    Incoming,
    /// HTLC is outgoing (we're paying them)
    Outgoing,
}

/// Payment request
#[derive(Debug, Clone)]
pub struct PaymentRequest {
    /// Amount to pay
    pub amount: i128,
    /// Payment identifier (for idempotency)
    pub payment_id: Option<String>,
    /// Optional memo
    pub memo: Option<Vec<u8>>,
    /// Custom hashlock (for keysend-style payments)
    pub custom_hashlock: Option<Vec<u8>>,
    /// CLTV delta for the HTLC
    pub cltv_delta: Option<u32>,
}

/// Payment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentResult {
    /// Whether the payment succeeded
    pub success: bool,
    /// Preimage (for received HTLCs)
    pub preimage: Option<Vec<u8>>,
    /// HTLC ID (if applicable)
    pub htlc_id: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Channel manager for handling all channel operations
pub struct ChannelManager {
    /// Local channel states
    channels: RwLock<HashMap<String, LocalChannelState>>,
    /// Signer for creating signatures
    signer: Box<dyn SignatureSigner>,
}

/// Signature signer trait
pub trait SignatureSigner: Send + Sync {
    /// Sign a message
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PaymentChannelError>;
    
    /// Verify a signature
    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, PaymentChannelError>;
    
    /// Get the public key
    fn public_key(&self) -> Vec<u8>;
}

impl ChannelManager {
    /// Create a new channel manager
    pub fn new(signer: Box<dyn SignatureSigner>) -> Self {
        ChannelManager {
            channels: RwLock::new(HashMap::new()),
            signer,
        }
    }
    
    /// Create a new payment channel
    pub async fn create_channel(
        &self,
        our_address: String,
        their_address: String,
        our_initial_balance: i128,
        their_initial_balance: i128,
        timeout: u32,
        fee_percentage: u32,
    ) -> Result<LocalChannelState, PaymentChannelError> {
        // Generate channel ID
        let channel_id = Self::generate_channel_id(&our_address, &their_address);
        
        // Create local state
        let state = LocalChannelState {
            channel_id: channel_id.clone(),
            our_address: our_address.clone(),
            their_address: their_address.clone(),
            our_balance: our_initial_balance,
            their_balance: their_initial_balance,
            status: ChannelStatus::Open,
            sequence_number: 0,
            funding_tx_hash: None,
            closing_tx_hash: None,
            timeout,
            fee_percentage,
            pending_htlcs: Vec::new(),
            local_secret: self.signer.public_key(),
            remote_public_key: Vec::new(), // Will be set during handshake
        };
        
        // Store the channel
        self.channels.write().insert(channel_id, state.clone());
        
        Ok(state)
    }
    
    /// Execute an off-chain payment
    pub fn execute_payment(
        &self,
        channel_id: &str,
        amount: i128,
        direction: PaymentDirection,
    ) -> Result<LocalChannelState, PaymentChannelError> {
        let mut channels = self.channels.write();
        let state = channels.get_mut(channel_id)
            .ok_or_else(|| PaymentChannelError::ChannelNotFound(channel_id.to_string()))?;
        
        // Check if channel is open
        if state.status != ChannelStatus::Open {
            return Err(PaymentChannelError::ChannelClosed(state.status.to_string()));
        }
        
        // Update balances
        match direction {
            PaymentDirection::ToThem => {
                if state.our_balance < amount {
                    return Err(PaymentChannelError::InsufficientBalance {
                        have: state.our_balance,
                        need: amount,
                    });
                }
                state.our_balance -= amount;
                state.their_balance += amount;
            }
            PaymentDirection::ToUs => {
                if state.their_balance < amount {
                    return Err(PaymentChannelError::InsufficientBalance {
                        have: state.their_balance,
                        need: amount,
                    });
                }
                state.their_balance -= amount;
                state.our_balance += amount;
            }
        }
        
        state.sequence_number += 1;
        Ok(state.clone())
    }
    
    /// Get a channel by ID
    pub fn get_channel(&self, channel_id: &str) -> Option<LocalChannelState> {
        self.channels.read().get(channel_id).cloned()
    }
    
    /// Get all channels
    pub fn get_all_channels(&self) -> Vec<LocalChannelState> {
        self.channels.read().values().cloned().collect()
    }
    
    /// Close a channel cooperatively
    pub fn cooperative_close(
        &self,
        channel_id: &str,
    ) -> Result<LocalChannelState, PaymentChannelError> {
        let mut channels = self.channels.write();
        let state = channels.get_mut(channel_id)
            .ok_or_else(|| PaymentChannelError::ChannelNotFound(channel_id.to_string()))?;
        
        if state.status != ChannelStatus::Open {
            return Err(PaymentChannelError::InvalidState(
                format!("Cannot close channel in state {:?}", state.status)
            ));
        }
        
        state.status = ChannelStatus::Closing;
        Ok(state.clone())
    }
    
    /// Initiate a unilateral close
    pub fn initiate_unilateral_close(
        &self,
        channel_id: &str,
    ) -> Result<LocalChannelState, PaymentChannelError> {
        let mut channels = self.channels.write();
        let state = channels.get_mut(channel_id)
            .ok_or_else(|| PaymentChannelError::ChannelNotFound(channel_id.to_string()))?;
        
        state.status = ChannelStatus::ForceClosed;
        Ok(state.clone())
    }
    
    /// Rebalance a channel
    pub fn rebalance(
        &self,
        channel_id: &str,
        amount: i128,
    ) -> Result<LocalChannelState, PaymentChannelError> {
        let mut channels = self.channels.write();
        let state = channels.get_mut(channel_id)
            .ok_or_else(|| PaymentChannelError::ChannelNotFound(channel_id.to_string()))?;
        
        if state.status != ChannelStatus::Open {
            return Err(PaymentChannelError::InvalidState("Channel not open".to_string()));
        }
        
        // Add funds to both sides (requires on-chain transaction)
        state.our_balance += amount;
        state.their_balance += amount;
        state.sequence_number += 1;
        
        Ok(state.clone())
    }
    
    /// Generate a deterministic channel ID
    fn generate_channel_id(a: &str, b: &str) -> String {
        use sha2::{Sha256, Digest};
        
        let mut sorted = [a, b].to_vec();
        sorted.sort();
        
        let mut hasher = Sha256::new();
        hasher.update(sorted[0].as_bytes());
        hasher.update(sorted[1].as_bytes());
        let result = hasher.finalize();
        
        hex::encode(result)
    }
}

/// Payment direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentDirection {
    /// Payment to the other party
    ToThem,
    /// Payment from the other party
    ToUs,
}

/// Convert channel status to string
impl std::fmt::Display for ChannelStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelStatus::Open => write!(f, "Open"),
            ChannelStatus::Closing => write!(f, "Closing"),
            ChannelStatus::Closed => write!(f, "Closed"),
            ChannelStatus::ForceClosed => write!(f, "ForceClosed"),
            ChannelStatus::Dispute => write!(f, "Dispute"),
        }
    }
}

/// Hex encoding helper
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        let bytes = data.as_ref();
        let mut result = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            result.push(HEX_CHARS[(b >> 4) as usize] as char);
            result.push(HEX_CHARS[(b & 0xf) as usize] as char);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_id_generation() {
        let id1 = ChannelManager::generate_channel_id("alice", "bob");
        let id2 = ChannelManager::generate_channel_id("bob", "alice");
        
        // Should be the same regardless of order
        assert_eq!(id1, id2);
    }
    
    #[test]
    fn test_hex_encoding() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!(hex::encode(data), "deadbeef");
    }
}

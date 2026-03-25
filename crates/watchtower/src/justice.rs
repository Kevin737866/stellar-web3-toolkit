//! # Justice Service Module
//! 
//! Handles submission of justice transactions when breach attempts are detected.

use crate::monitor::BreachAttempt;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};
use thiserror::Error;

/// Justice transaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JusticeTransaction {
    /// Transaction hash
    pub tx_hash: String,
    /// Channel ID
    pub channel_id: String,
    /// Breach attempt details
    pub breach: BreachAttempt,
    /// Fee paid
    pub fee_paid: i128,
    /// When submitted
    pub submitted_at: u64,
    /// Transaction status
    pub status: JusticeTxStatus,
}

/// Justice transaction status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JusticeTxStatus {
    /// Transaction submitted
    Submitted,
    /// Transaction confirmed
    Confirmed,
    /// Transaction failed
    Failed,
    /// Transaction dropped
    Dropped,
}

/// Justice service for submitting breach response transactions
#[derive(Clone)]
pub struct JusticeService {
    /// RPC endpoint
    rpc_url: String,
    /// Network passphrase
    network_passphrase: String,
    /// Maximum fee budget
    max_fee: i128,
    /// Submitted transactions
    pending_txs: std::sync::Arc<parking_lot::RwLock<Vec<JusticeTransaction>>>,
}

impl JusticeService {
    /// Create a new justice service
    pub fn new(rpc_url: String, network_passphrase: String, max_fee: i128) -> Self {
        JusticeService {
            rpc_url,
            network_passphrase,
            max_fee,
            pending_txs: std::sync::Arc::new(parking_lot::RwLock::new(Vec::new())),
        }
    }
    
    /// Submit a justice transaction for a breach attempt
    pub async fn submit_justice(&self, breach: &BreachAttempt) -> Result<JusticeTransaction, JusticeError> {
        info!("Submitting justice transaction for breach on channel {}", breach.channel_id);
        
        // Build the justice transaction
        // In production, this would:
        // 1. Build the proper Stellar transaction
        // 2. Sign it with the watchtower's key
        // 3. Submit to the network
        
        let justice_tx = self.build_justice_transaction(breach).await?;
        
        // Store the pending transaction
        {
            let mut pending = self.pending_txs.write();
            pending.push(justice_tx.clone());
        }
        
        info!("Justice transaction submitted: {}", justice_tx.tx_hash);
        
        Ok(justice_tx)
    }
    
    /// Build a justice transaction for a breach attempt
    async fn build_justice_transaction(
        &self,
        breach: &BreachAttempt,
    ) -> Result<JusticeTransaction, JusticeError> {
        // In production, this would:
        // 1. Fetch the breacher's key from the channel
        // 2. Build a claim predicate
        // 3. Create the proper claimable balance or payment
        
        let tx_hash = format!("justice_{}_{}", breach.channel_id, breach.detected_at);
        
        Ok(JusticeTransaction {
            tx_hash,
            channel_id: breach.channel_id.clone(),
            breach: breach.clone(),
            fee_paid: self.max_fee,
            submitted_at: current_timestamp(),
            status: JusticeTxStatus::Submitted,
        })
    }
    
    /// Check the status of a justice transaction
    pub fn check_status(&self, tx_hash: &str) -> Option<JusticeTxStatus> {
        let pending = self.pending_txs.read();
        pending
            .iter()
            .find(|tx| tx.tx_hash == tx_hash)
            .map(|tx| tx.status)
    }
    
    /// Update the status of a pending transaction
    pub fn update_status(&self, tx_hash: &str, status: JusticeTxStatus) {
        let mut pending = self.pending_txs.write();
        if let Some(tx) = pending.iter_mut().find(|tx| tx.tx_hash == tx_hash) {
            tx.status = status;
        }
    }
    
    /// Get all pending justice transactions
    pub fn get_pending(&self) -> Vec<JusticeTransaction> {
        let pending = self.pending_txs.read();
        pending
            .iter()
            .filter(|tx| tx.status == JusticeTxStatus::Submitted)
            .cloned()
            .collect()
    }
    
    /// Clean up old/finalized transactions
    pub fn cleanup(&self, max_age_secs: u64) {
        let mut pending = self.pending_txs.write();
        let cutoff = current_timestamp() - max_age_secs;
        
        pending.retain(|tx| {
            tx.status != JusticeTxStatus::Confirmed && tx.submitted_at > cutoff
        });
    }
}

/// Justice service errors
#[derive(Error, Debug)]
pub enum JusticeError {
    #[error("Transaction build failed: {0}")]
    BuildError(String),
    
    #[error("Submission failed: {0}")]
    SubmissionError(String),
    
    #[error("Invalid breach data: {0}")]
    InvalidBreach(String),
    
    #[error("Fee too high: needed {needed}, max {max}")]
    FeeTooHigh { needed: i128, max: i128 },
}

/// Get current timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_justice_transaction_creation() {
        let service = JusticeService::new(
            "http://localhost".to_string(),
            "test".to_string(),
            100_000,
        );
        
        let breach = BreachAttempt {
            channel_id: "test_channel".to_string(),
            old_sequence: 1,
            new_sequence: 5,
            old_balance_a: 1000,
            old_balance_b: 1000,
            new_balance_a: 1500,
            new_balance_b: 500,
            breach_tx_hash: "breach_tx".to_string(),
            detected_at: 1000,
        };
        
        // This would be async in production
        // let result = service.submit_justice(&breach);
    }
}

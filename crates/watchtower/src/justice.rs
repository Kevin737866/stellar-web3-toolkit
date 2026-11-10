//! # Justice Service Module
//!
//! Handles validation, durable persistence, deduplication, and submission
//! of justice transactions when breach attempts are detected.

use crate::monitor::BreachAttempt;
use crate::storage::{
    retry_storage_op, InMemoryStorage, JusticeActionRecord, RetryPolicy, StorageBackend,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tracing::info;

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
    /// Persisted locally prior to network submission
    Pending,
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
    // Retained for the RPC wiring still to come.
    #[allow(dead_code)]
    rpc_url: String,
    /// Network passphrase
    // Retained for the RPC wiring still to come.
    #[allow(dead_code)]
    network_passphrase: String,
    /// Maximum fee budget
    max_fee: i128,
    /// Submitted transactions
    pending_txs: Arc<parking_lot::RwLock<Vec<JusticeTransaction>>>,
    /// Persistent backend for durable pre-submission intent logging (#368)
    storage: Arc<dyn StorageBackend>,
    /// Retry configuration for transient storage writes (#369)
    retry_policy: RetryPolicy,
}

impl JusticeService {
    /// Create a new justice service backed by an in-memory store.
    pub fn new(rpc_url: String, network_passphrase: String, max_fee: i128) -> Self {
        JusticeService {
            rpc_url,
            network_passphrase,
            max_fee,
            pending_txs: Arc::new(parking_lot::RwLock::new(Vec::new())),
            storage: Arc::new(InMemoryStorage::new()),
            retry_policy: RetryPolicy::default(),
        }
    }

    /// Attach a custom persistent storage backend (#368).
    pub fn with_storage(mut self, storage: Arc<dyn StorageBackend>) -> Self {
        self.storage = storage;
        self
    }

    /// Configure the retry policy used for storage operations (#369).
    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    /// Build the deterministic action ID used to deduplicate breach responses (#368, #376).
    pub fn action_id_for_breach(breach: &BreachAttempt) -> String {
        format!("{}:{}", breach.channel_id, breach.breach_tx_hash)
    }

    /// Validate breach evidence before building or submitting a justice response (#371).
    pub fn validate_breach(breach: &BreachAttempt) -> Result<(), JusticeError> {
        if breach.channel_id.trim().is_empty() {
            return Err(JusticeError::InvalidBreach(
                "channel_id must not be empty".to_string(),
            ));
        }
        if breach.breach_tx_hash.trim().is_empty() {
            return Err(JusticeError::InvalidBreach(
                "breach_tx_hash must not be empty".to_string(),
            ));
        }
        if breach.detected_at == 0 {
            return Err(JusticeError::InvalidBreach(
                "detected_at timestamp must be non-zero".to_string(),
            ));
        }
        if breach.old_sequence == breach.new_sequence {
            return Err(JusticeError::InvalidBreach(format!(
                "breach sequence must differ from known state (both are {})",
                breach.old_sequence
            )));
        }
        if breach.old_balance_a < 0
            || breach.old_balance_b < 0
            || breach.new_balance_a < 0
            || breach.new_balance_b < 0
        {
            return Err(JusticeError::InvalidBreach(
                "channel balances must be non-negative".to_string(),
            ));
        }
        let old_total = breach
            .old_balance_a
            .checked_add(breach.old_balance_b)
            .ok_or_else(|| {
                JusticeError::InvalidBreach("old channel balance sum overflows".to_string())
            })?;
        let new_total = breach
            .new_balance_a
            .checked_add(breach.new_balance_b)
            .ok_or_else(|| {
                JusticeError::InvalidBreach("new channel balance sum overflows".to_string())
            })?;
        if old_total != new_total {
            return Err(JusticeError::InvalidBreach(format!(
                "balance conservation violated: old total {} != new total {}",
                old_total, new_total
            )));
        }
        Ok(())
    }

    /// Submit a justice transaction for a breach attempt.
    ///
    /// Evidence is validated (#371), duplicate notifications are rejected (#376),
    /// and the justice action intent is persisted to storage (#368) with retry
    /// handling (#369) strictly before submission.
    pub async fn submit_justice(
        &self,
        breach: &BreachAttempt,
    ) -> Result<JusticeTransaction, JusticeError> {
        Self::validate_breach(breach)?;

        if self.max_fee < 0 {
            return Err(JusticeError::FeeTooHigh {
                needed: 0,
                max: self.max_fee,
            });
        }

        let action_id = Self::action_id_for_breach(breach);
        if let Some(existing) = self
            .storage
            .get_justice_action(&action_id)
            .map_err(|e| JusticeError::PersistenceFailed(e.to_string()))?
        {
            return Err(JusticeError::DuplicateBreach {
                channel_id: existing.channel_id,
                breach_tx_hash: existing.breach_tx_hash,
            });
        }

        info!(
            "Persisting justice intent and submitting tx for breach on channel {}",
            breach.channel_id
        );

        let mut justice_tx = self.build_justice_transaction(breach).await?;
        justice_tx.status = JusticeTxStatus::Pending;

        let now = current_timestamp();
        let record = JusticeActionRecord {
            action_id: action_id.clone(),
            channel_id: breach.channel_id.clone(),
            breach_tx_hash: breach.breach_tx_hash.clone(),
            tx_hash: justice_tx.tx_hash.clone(),
            status: JusticeTxStatus::Pending,
            created_at: now,
            updated_at: now,
            attempts: 1,
        };

        // Persist intent BEFORE transaction submission so crash recovery can replay safely.
        retry_storage_op(&self.retry_policy, || {
            self.storage.store_justice_action(&record)
        })
        .map_err(|e| JusticeError::PersistenceFailed(e.to_string()))?;

        // Transition persisted status and record submitted tx.
        justice_tx.status = JusticeTxStatus::Submitted;
        retry_storage_op(&self.retry_policy, || {
            self.storage
                .update_justice_action_status(&action_id, JusticeTxStatus::Submitted)
        })
        .map_err(|e| JusticeError::PersistenceFailed(e.to_string()))?;

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
            let action_id = Self::action_id_for_breach(&tx.breach);
            let _ = self
                .storage
                .update_justice_action_status(&action_id, status);
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

    /// Inspect the backing persistent storage.
    pub fn storage(&self) -> &Arc<dyn StorageBackend> {
        &self.storage
    }

    /// Clean up old/finalized transactions
    pub fn cleanup(&self, max_age_secs: u64) {
        let mut pending = self.pending_txs.write();
        let cutoff = current_timestamp().saturating_sub(max_age_secs);

        pending.retain(|tx| tx.status != JusticeTxStatus::Confirmed && tx.submitted_at > cutoff);
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

    #[error("Failed to persist justice action: {0}")]
    PersistenceFailed(String),

    #[error("Duplicate breach notification for channel {channel_id} tx {breach_tx_hash}")]
    DuplicateBreach {
        channel_id: String,
        breach_tx_hash: String,
    },
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
    use crate::monitor::{ChannelMonitorState, ChannelUpdate};
    use crate::storage::{CompactionPolicy, CompactionReport, StorageError, StorageHealth};
    use crate::Alert;

    fn valid_breach(channel_id: &str, breach_tx_hash: &str) -> BreachAttempt {
        BreachAttempt {
            channel_id: channel_id.to_string(),
            old_sequence: 5,
            new_sequence: 3,
            old_balance_a: 1000,
            old_balance_b: 1000,
            new_balance_a: 1500,
            new_balance_b: 500,
            breach_tx_hash: breach_tx_hash.to_string(),
            detected_at: 1000,
        }
    }

    #[test]
    fn test_justice_transaction_creation() {
        let _service =
            JusticeService::new("http://localhost".to_string(), "test".to_string(), 100_000);
        let breach = valid_breach("test_channel", "breach_tx");
        assert!(JusticeService::validate_breach(&breach).is_ok());
    }

    #[test]
    fn validate_breach_rejects_invalid_evidence() {
        let mut empty_chan = valid_breach("", "tx1");
        empty_chan.channel_id = "   ".to_string();
        assert!(matches!(
            JusticeService::validate_breach(&empty_chan),
            Err(JusticeError::InvalidBreach(_))
        ));

        let mut equal_seq = valid_breach("ch1", "tx1");
        equal_seq.new_sequence = equal_seq.old_sequence;
        assert!(matches!(
            JusticeService::validate_breach(&equal_seq),
            Err(JusticeError::InvalidBreach(_))
        ));

        let mut unbalanced = valid_breach("ch1", "tx1");
        unbalanced.new_balance_a = 1800; // sum 2300 != 2000
        assert!(matches!(
            JusticeService::validate_breach(&unbalanced),
            Err(JusticeError::InvalidBreach(_))
        ));

        let mut neg_bal = valid_breach("ch1", "tx1");
        neg_bal.new_balance_b = -10;
        neg_bal.new_balance_a = 2010;
        assert!(matches!(
            JusticeService::validate_breach(&neg_bal),
            Err(JusticeError::InvalidBreach(_))
        ));
    }

    struct FailingStoreBackend;

    impl StorageBackend for FailingStoreBackend {
        fn store_channel_state(
            &self,
            _: &str,
            _: &ChannelMonitorState,
        ) -> Result<(), StorageError> {
            Ok(())
        }
        fn get_channel_state(&self, _: &str) -> Result<Option<ChannelMonitorState>, StorageError> {
            Ok(None)
        }
        fn store_alert(&self, _: &Alert) -> Result<(), StorageError> {
            Ok(())
        }
        fn get_alerts(&self, _: usize) -> Result<Vec<Alert>, StorageError> {
            Ok(Vec::new())
        }
        fn store_channel_update(&self, _: &ChannelUpdate) -> Result<(), StorageError> {
            Ok(())
        }
        fn get_channel_update(&self, _: &str) -> Result<Option<ChannelUpdate>, StorageError> {
            Ok(None)
        }
        fn store_subscription(&self, _: &str) -> Result<(), StorageError> {
            Ok(())
        }
        fn get_subscriptions(&self) -> Result<Vec<String>, StorageError> {
            Ok(Vec::new())
        }
        fn remove_subscription(&self, _: &str) -> Result<(), StorageError> {
            Ok(())
        }
        fn compact(&self, _: &CompactionPolicy) -> Result<CompactionReport, StorageError> {
            Ok(CompactionReport::default())
        }
        fn store_justice_action(&self, _: &JusticeActionRecord) -> Result<(), StorageError> {
            Err(StorageError::DatabaseError("disk full".to_string()))
        }
        fn get_justice_action(&self, _: &str) -> Result<Option<JusticeActionRecord>, StorageError> {
            Ok(None)
        }
        fn get_justice_actions_for_channel(
            &self,
            _: &str,
        ) -> Result<Vec<JusticeActionRecord>, StorageError> {
            Ok(Vec::new())
        }
        fn update_justice_action_status(
            &self,
            _: &str,
            _: JusticeTxStatus,
        ) -> Result<(), StorageError> {
            Ok(())
        }
        fn health_check(&self) -> Result<StorageHealth, StorageError> {
            Err(StorageError::DatabaseError("unhealthy".to_string()))
        }
    }

    #[tokio::test]
    async fn justice_submission_aborts_if_persistence_fails() {
        let service = JusticeService::new("http://localhost".to_string(), "test".to_string(), 1000)
            .with_storage(Arc::new(FailingStoreBackend));

        let breach = valid_breach("ch1", "breach_tx_1");
        let res = service.submit_justice(&breach).await;
        assert!(matches!(res, Err(JusticeError::PersistenceFailed(_))));
        assert!(service.get_pending().is_empty());
    }

    #[tokio::test]
    async fn duplicate_breach_notifications_do_not_create_duplicate_actions() {
        let service = JusticeService::new("http://localhost".to_string(), "test".to_string(), 1000);
        let breach = valid_breach("ch1", "breach_tx_dup");

        let first = service
            .submit_justice(&breach)
            .await
            .expect("first breach submission should succeed");
        assert_eq!(first.status, JusticeTxStatus::Submitted);

        let second = service.submit_justice(&breach).await;
        assert!(matches!(second, Err(JusticeError::DuplicateBreach { .. })));

        // Exactly 1 pending tx and 1 persisted action exist.
        assert_eq!(service.get_pending().len(), 1);
        let persisted = service
            .storage()
            .get_justice_actions_for_channel("ch1")
            .unwrap();
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].status, JusticeTxStatus::Submitted);

        // Distinct breach tx on the same channel succeeds independently.
        let other = valid_breach("ch1", "breach_tx_other");
        service
            .submit_justice(&other)
            .await
            .expect("distinct breach should succeed");
        assert_eq!(
            service
                .storage()
                .get_justice_actions_for_channel("ch1")
                .unwrap()
                .len(),
            2
        );
    }
}

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::asset::{Asset, AssetInfo};
use crate::error::{AtomicSwapError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SwapStatus {
    Pending,
    Completed,
    Refunded,
    Expired,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SwapDirection {
    InitiatorToParticipant,
    ParticipantToInitiator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomicSwap {
    pub id: String,
    pub initiator: String,
    pub participant: String,
    pub initiator_asset: Asset,
    pub participant_asset: Asset,
    pub initiator_amount: i128,
    pub participant_amount: i128,
    pub hash_lock: String, // Hex encoded SHA-256 hash
    pub preimage: Option<String>, // Hex encoded preimage (revealed after completion)
    pub timeout_ledger: u32,
    pub created_at_ledger: u32,
    pub completed_at_ledger: Option<u32>,
    pub status: SwapStatus,
    pub direction: SwapDirection,
    pub contract_address: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl AtomicSwap {
    pub fn new(
        id: String,
        initiator: String,
        participant: String,
        initiator_asset: Asset,
        participant_asset: Asset,
        initiator_amount: i128,
        participant_amount: i128,
        hash_lock: String,
        timeout_ledger: u32,
        created_at_ledger: u32,
    ) -> Self {
        Self {
            id,
            initiator,
            participant,
            initiator_asset,
            participant_asset,
            initiator_amount,
            participant_amount,
            hash_lock,
            preimage: None,
            timeout_ledger,
            created_at_ledger,
            completed_at_ledger: None,
            status: SwapStatus::Pending,
            direction: SwapDirection::InitiatorToParticipant,
            contract_address: None,
            metadata: HashMap::new(),
        }
    }

    pub fn is_pending(&self) -> bool {
        matches!(self.status, SwapStatus::Pending)
    }

    pub fn is_completed(&self) -> bool {
        matches!(self.status, SwapStatus::Completed)
    }

    pub fn is_expired(&self, current_ledger: u32) -> bool {
        current_ledger > self.timeout_ledger
    }

    pub fn can_complete(&self, current_ledger: u32) -> bool {
        self.is_pending() && !self.is_expired(current_ledger)
    }

    pub fn can_refund(&self, current_ledger: u32) -> bool {
        self.is_pending() && self.is_expired(current_ledger)
    }

    pub fn mark_completed(&mut self, preimage: String, completed_at_ledger: u32) {
        self.status = SwapStatus::Completed;
        self.preimage = Some(preimage);
        self.completed_at_ledger = Some(completed_at_ledger);
    }

    pub fn mark_refunded(&mut self) {
        self.status = SwapStatus::Refunded;
    }

    pub fn mark_expired(&mut self) {
        self.status = SwapStatus::Expired;
    }

    pub fn mark_failed(&mut self) {
        self.status = SwapStatus::Failed;
    }

    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    pub fn get_swap_value(&self) -> (i128, i128) {
        (self.initiator_amount, self.participant_amount)
    }

    pub fn get_exchange_rate(&self) -> f64 {
        if self.participant_amount == 0 {
            0.0
        } else {
            self.initiator_amount as f64 / self.participant_amount as f64
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.initiator.is_empty() {
            return Err(AtomicSwapError::InvalidAddress {
                address: self.initiator.clone(),
            });
        }

        if self.participant.is_empty() {
            return Err(AtomicSwapError::InvalidAddress {
                address: self.participant.clone(),
            });
        }

        if self.initiator_amount <= 0 {
            return Err(AtomicSwapError::InvalidAmount {
                amount: self.initiator_amount,
            });
        }

        if self.participant_amount <= 0 {
            return Err(AtomicSwapError::InvalidAmount {
                amount: self.participant_amount,
            });
        }

        if self.timeout_ledger <= self.created_at_ledger {
            return Err(AtomicSwapError::InvalidTimeout {
                timeout_hours: 0,
            });
        }

        // Validate hash length (should be 64 hex chars for 32 bytes)
        if self.hash_lock.len() != 64 {
            return Err(AtomicSwapError::InvalidPreimage {
                swap_id: self.id.clone(),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapTemplate {
    pub name: String,
    pub description: String,
    pub initiator_asset: Asset,
    pub participant_asset: Asset,
    pub default_initiator_amount: i128,
    pub default_participant_amount: i128,
    pub default_timeout_hours: u32,
    pub tags: Vec<String>,
}

impl SwapTemplate {
    pub fn new(
        name: String,
        description: String,
        initiator_asset: Asset,
        participant_asset: Asset,
        default_initiator_amount: i128,
        default_participant_amount: i128,
        default_timeout_hours: u32,
    ) -> Self {
        Self {
            name,
            description,
            initiator_asset,
            participant_asset,
            default_initiator_amount,
            default_participant_amount,
            default_timeout_hours,
            tags: Vec::new(),
        }
    }

    pub fn add_tag(&mut self, tag: String) {
        self.tags.push(tag);
    }

    pub fn create_swap(
        &self,
        id: String,
        initiator: String,
        participant: String,
        hash_lock: String,
        current_ledger: u32,
    ) -> AtomicSwap {
        AtomicSwap::new(
            id,
            initiator,
            participant,
            self.initiator_asset.clone(),
            self.participant_asset.clone(),
            self.default_initiator_amount,
            self.default_participant_amount,
            hash_lock,
            current_ledger + (self.default_timeout_hours * 720), // ~720 ledgers per hour
            current_ledger,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_swap_creation() {
        let swap = AtomicSwap::new(
            "test_swap".to_string(),
            "initiator".to_string(),
            "participant".to_string(),
            Asset::XLM,
            Asset::Custom("USDC".to_string()),
            1000,
            500,
            "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            10000,
            1000,
        );

        assert_eq!(swap.id, "test_swap");
        assert!(swap.is_pending());
        assert!(!swap.is_completed());
        assert!(swap.validate().is_ok());
    }

    #[test]
    fn test_swap_status_transitions() {
        let mut swap = AtomicSwap::new(
            "test_swap".to_string(),
            "initiator".to_string(),
            "participant".to_string(),
            Asset::XLM,
            Asset::Custom("USDC".to_string()),
            1000,
            500,
            "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            10000,
            1000,
        );

        assert!(swap.can_complete(5000));
        assert!(!swap.can_complete(15000));
        assert!(!swap.can_refund(5000));
        assert!(swap.can_refund(15000));

        swap.mark_completed("preimage".to_string(), 6000);
        assert!(swap.is_completed());
        assert!(!swap.can_complete(5000));
        assert!(!swap.can_refund(5000));
    }

    #[test]
    fn test_swap_template() {
        let template = SwapTemplate::new(
            "XLM to USDC".to_string(),
            "Swap XLM for USDC".to_string(),
            Asset::XLM,
            Asset::Custom("USDC".to_string()),
            1000,
            500,
            24,
        );

        let swap = template.create_swap(
            "template_swap".to_string(),
            "initiator".to_string(),
            "participant".to_string(),
            "hash123".to_string(),
            1000,
        );

        assert_eq!(swap.initiator_amount, 1000);
        assert_eq!(swap.participant_amount, 500);
        assert_eq!(swap.timeout_ledger, 1000 + (24 * 720));
    }
}

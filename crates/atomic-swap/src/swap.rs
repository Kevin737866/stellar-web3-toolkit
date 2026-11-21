use crate::asset::Asset;
use crate::error::{AtomicSwapError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SwapStatus {
    Pending,
    Completed,
    Refunded,
    Expired,
    Failed,
}

impl SwapStatus {
    /// True once the swap can never change state again.
    ///
    /// `Failed` is terminal by definition: the swap stopped without settling and
    /// without a timeout refund, so the only useful thing left to know is *why*
    /// ([`AtomicSwap::failure`]).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SwapStatus::Completed | SwapStatus::Refunded | SwapStatus::Expired | SwapStatus::Failed
        )
    }

    /// Stable identifier used in logs, events and monitoring output.
    pub fn as_str(&self) -> &'static str {
        match self {
            SwapStatus::Pending => "pending",
            SwapStatus::Completed => "completed",
            SwapStatus::Refunded => "refunded",
            SwapStatus::Expired => "expired",
            SwapStatus::Failed => "failed",
        }
    }
}

/// Why a swap reached [`SwapStatus::Failed`] (#391).
///
/// A failed swap is a swap that neither settled nor timed out: the participant
/// funded a leg and the coordination flow stopped. `SwapStatus::Failed` alone
/// says "it did not work", which is useless to an operator deciding between
/// retrying, refunding, or escalating to the counterparty. This type is the
/// terminal answer, recorded once and never rewritten.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SwapFailureReason {
    /// The leg could not be funded or settled on chain.
    ChainActionFailed { operation: String, detail: String },
    /// The coordination retry budget for an operation was exhausted (#215).
    RetryBudgetExhausted { operation: String, attempts: u32 },
    /// The counterparty never funded its leg before the timeout ledger.
    CounterpartyTimeout,
    /// A caller or operator abandoned the swap before it settled.
    Abandoned { detail: String },
}

impl SwapFailureReason {
    /// Stable identifier for grouping failures in monitoring.
    ///
    /// Deliberately coarse: the free-form `detail` fields are for humans, this
    /// is the value a dashboard groups by.
    pub fn code(&self) -> &'static str {
        match self {
            SwapFailureReason::ChainActionFailed { .. } => "chain_action_failed",
            SwapFailureReason::RetryBudgetExhausted { .. } => "retry_budget_exhausted",
            SwapFailureReason::CounterpartyTimeout => "counterparty_timeout",
            SwapFailureReason::Abandoned { .. } => "abandoned",
        }
    }
}

impl std::fmt::Display for SwapFailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SwapFailureReason::ChainActionFailed { operation, detail } => {
                write!(f, "chain action `{operation}` failed: {detail}")
            }
            SwapFailureReason::RetryBudgetExhausted {
                operation,
                attempts,
            } => write!(
                f,
                "retry budget exhausted for `{operation}` after {attempts} attempt(s)"
            ),
            SwapFailureReason::CounterpartyTimeout => {
                write!(f, "counterparty did not fund before the timeout ledger")
            }
            SwapFailureReason::Abandoned { detail } => write!(f, "abandoned: {detail}"),
        }
    }
}

/// A terminal failure and the ledger it was recorded at.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwapFailure {
    pub reason: SwapFailureReason,
    /// Ledger the failure was observed at, not the ledger it was caused at.
    pub ledger: u32,
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
    pub hash_lock: String,        // Hex encoded SHA-256 hash
    pub preimage: Option<String>, // Hex encoded preimage (revealed after completion)
    pub timeout_ledger: u32,
    pub created_at_ledger: u32,
    pub completed_at_ledger: Option<u32>,
    pub status: SwapStatus,
    pub direction: SwapDirection,
    pub contract_address: Option<String>,
    /// Chain the initiating transfer came from, when this swap is one leg of a
    /// cross-chain flow (#238). `None` for a purely local swap.
    pub origin_chain: Option<String>,
    /// Sender-chosen nonce of that transfer, consumed once by the coordinator's
    /// replay guard. `None` for a purely local swap.
    pub origin_nonce: Option<u64>,
    pub metadata: HashMap<String, String>,
    /// Terminal reason this swap failed (#391). Set exactly once, by
    /// [`AtomicSwap::mark_failed`]; `None` for every other status.
    ///
    /// `default` so a swap serialised before #391 still deserialises; such a
    /// record reports `Failed` without a reason rather than failing to load.
    #[serde(default)]
    pub failure: Option<SwapFailure>,
}

impl AtomicSwap {
    // A swap is defined by its full parameter set; grouping them would only move
    // the same list somewhere less readable.
    #[allow(clippy::too_many_arguments)]
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
            origin_chain: None,
            origin_nonce: None,
            metadata: HashMap::new(),
            failure: None,
        }
    }

    /// Declare the cross-chain origin of this swap's initiating transfer. The
    /// coordinator consumes the nonce against the replay guard before the swap
    /// is stored.
    pub fn with_origin(mut self, chain: impl Into<String>, nonce: u64) -> Self {
        self.origin_chain = Some(chain.into());
        self.origin_nonce = Some(nonce);
        self
    }

    /// True when the swap is a leg of a cross-chain flow.
    pub fn is_cross_chain(&self) -> bool {
        self.origin_chain.is_some()
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

    /// Mark the swap failed and record *why* (#391).
    ///
    /// The first reason wins. A swap that already carries a failure keeps it, so
    /// a late, less specific observation cannot overwrite the reason an operator
    /// is acting on. Returns `false` when a reason was already recorded.
    pub fn mark_failed(&mut self, reason: SwapFailureReason, ledger: u32) -> bool {
        self.status = SwapStatus::Failed;
        if self.failure.is_some() {
            return false;
        }
        self.failure = Some(SwapFailure { reason, ledger });
        true
    }

    /// The terminal failure reason, if this swap failed (#391).
    pub fn failure(&self) -> Option<&SwapFailure> {
        self.failure.as_ref()
    }

    /// Stable, log-friendly description of why the swap stopped.
    ///
    /// `None` while the swap can still settle. For a failed swap this is the
    /// recorded reason; a swap whose status was set to `Failed` by hand (a
    /// deserialised record from before #391, say) reports that it failed without
    /// a reason rather than inventing one.
    pub fn terminal_reason(&self) -> Option<String> {
        match (&self.status, &self.failure) {
            (SwapStatus::Failed, Some(failure)) => Some(failure.reason.to_string()),
            (SwapStatus::Failed, None) => Some("failed without a recorded reason".to_string()),
            _ => None,
        }
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
            return Err(AtomicSwapError::InvalidTimeout { timeout_hours: 0 });
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
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
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
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
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

    fn sample_swap() -> AtomicSwap {
        AtomicSwap::new(
            "swap-391".to_string(),
            "initiator".to_string(),
            "participant".to_string(),
            Asset::XLM,
            Asset::Custom("USDC".to_string()),
            1_000,
            500,
            "a".repeat(64),
            10_000,
            1_000,
        )
    }

    #[test]
    fn a_failed_swap_carries_its_terminal_reason() {
        let mut swap = sample_swap();
        assert!(swap.terminal_reason().is_none());

        let reason = SwapFailureReason::RetryBudgetExhausted {
            operation: "submit_htlc".to_string(),
            attempts: 3,
        };
        assert!(swap.mark_failed(reason.clone(), 9_000));

        assert_eq!(swap.status, SwapStatus::Failed);
        assert!(swap.status.is_terminal());
        assert_eq!(swap.failure().map(|f| &f.reason), Some(&reason));
        assert_eq!(swap.failure().map(|f| f.ledger), Some(9_000));
        assert_eq!(
            swap.terminal_reason().as_deref(),
            Some("retry budget exhausted for `submit_htlc` after 3 attempt(s)")
        );
    }

    #[test]
    fn the_first_failure_reason_wins() {
        let mut swap = sample_swap();
        let first = SwapFailureReason::ChainActionFailed {
            operation: "fund".to_string(),
            detail: "sequence number too low".to_string(),
        };
        let second = SwapFailureReason::Abandoned {
            detail: "operator gave up".to_string(),
        };

        assert!(swap.mark_failed(first.clone(), 2_000));
        assert!(
            !swap.mark_failed(second, 3_000),
            "a recorded reason must not be overwritten"
        );
        assert_eq!(swap.failure().map(|f| &f.reason), Some(&first));
        assert_eq!(swap.failure().map(|f| f.ledger), Some(2_000));
    }

    #[test]
    fn a_settled_swap_has_no_terminal_reason() {
        let mut swap = sample_swap();
        swap.mark_completed("preimage".to_string(), 5_000);
        assert!(swap.terminal_reason().is_none());
        assert!(swap.failure().is_none());
    }

    #[test]
    fn a_pre_391_record_still_deserialises() {
        let mut swap = sample_swap();
        swap.mark_completed("preimage".to_string(), 5_000);
        let mut value = serde_json::to_value(&swap).unwrap();
        // A record written before the field existed.
        value.as_object_mut().unwrap().remove("failure");

        let restored: AtomicSwap = serde_json::from_value(value).unwrap();
        assert!(restored.failure().is_none());
        assert!(restored.terminal_reason().is_none());
    }

    #[test]
    fn a_failed_swap_without_a_reason_still_reports_failure() {
        let mut swap = sample_swap();
        swap.status = SwapStatus::Failed;
        assert_eq!(
            swap.terminal_reason().as_deref(),
            Some("failed without a recorded reason")
        );
    }

    #[test]
    fn every_failure_reason_has_a_stable_code_and_message() {
        let reasons = [
            SwapFailureReason::ChainActionFailed {
                operation: "fund".to_string(),
                detail: "boom".to_string(),
            },
            SwapFailureReason::RetryBudgetExhausted {
                operation: "submit_htlc".to_string(),
                attempts: 1,
            },
            SwapFailureReason::CounterpartyTimeout,
            SwapFailureReason::Abandoned {
                detail: "operator".to_string(),
            },
        ];
        let codes: Vec<&str> = reasons.iter().map(SwapFailureReason::code).collect();
        assert_eq!(
            codes,
            vec![
                "chain_action_failed",
                "retry_budget_exhausted",
                "counterparty_timeout",
                "abandoned"
            ]
        );
        assert!(reasons.iter().all(|r| !r.to_string().is_empty()));
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

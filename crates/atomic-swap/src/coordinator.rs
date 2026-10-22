use crate::asset::{Asset, AssetInfo, AssetRegistry};
use crate::error::{AtomicSwapError, Result};
use crate::idempotency::{IdempotencyKey, IdempotencyStore};
use crate::monitor::{MonitoringConfig, SwapMonitor};
use crate::preimage::PreimageManager;
use crate::replay::{ReplayError, ReplayGuard, ReplayStats};
use crate::swap::{AtomicSwap, SwapTemplate};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub struct SwapRequest {
    pub participant: String,
    pub initiator_asset: Asset,
    pub participant_asset: Asset,
    pub initiator_amount: i128,
    pub participant_amount: i128,
    pub timeout_hours: u32,
    /// Chain the initiating transfer came from, when this swap is one leg of a
    /// cross-chain flow (#238). `None` for a purely local swap.
    pub origin_chain: Option<String>,
    /// Sender-chosen nonce of that transfer. Required together with
    /// `origin_chain`, and consumed exactly once by the coordinator's replay
    /// guard.
    pub nonce: Option<u64>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SwapResponse {
    pub swap_id: String,
    pub hash_lock: String,
    pub preimage: Option<String>, // Only provided to initiator
    pub timeout_ledger: u32,
    pub contract_address: Option<String>,
}

/// Default maximum number of coordination retries allowed per swap (#215).
pub const DEFAULT_MAX_COORDINATION_RETRIES: u32 = 3;

#[derive(Debug, Clone)]
pub struct SwapConfig {
    pub default_timeout_hours: u32,
    pub max_timeout_hours: u32,
    pub min_amount: i128,
    pub max_amount: i128,
    pub enable_multi_hop: bool,
    pub fee_percentage: f64, // Fee in percentage
}

impl Default for SwapConfig {
    fn default() -> Self {
        Self {
            default_timeout_hours: 24,
            max_timeout_hours: 168, // 1 week
            min_amount: 1,
            max_amount: i128::MAX / 2, // Prevent overflow
            enable_multi_hop: true,
            fee_percentage: 0.1, // 0.1%
        }
    }
}

/// Bounded retry budget tracker for swap coordination operations (#215).
#[derive(Debug, Clone)]
pub struct RetryBudget {
    max_retries: u32,
    attempts_by_swap: HashMap<String, u32>,
}

impl RetryBudget {
    pub fn new(max_retries: u32) -> Self {
        Self {
            max_retries,
            attempts_by_swap: HashMap::new(),
        }
    }

    pub fn max_retries(&self) -> u32 {
        self.max_retries
    }

    pub fn attempts(&self, swap_id: &str) -> u32 {
        self.attempts_by_swap.get(swap_id).copied().unwrap_or(0)
    }

    pub fn remaining(&self, swap_id: &str) -> u32 {
        self.max_retries.saturating_sub(self.attempts(swap_id))
    }

    /// Consume one retry attempt for `(swap_id, operation)`, returning the
    /// 1-based attempt number or [`AtomicSwapError::RetryBudgetExhausted`] once
    /// the budget is depleted.
    pub fn try_consume(&mut self, swap_id: &str, operation: &str) -> Result<u32> {
        let used = self.attempts(swap_id);
        if used >= self.max_retries {
            return Err(AtomicSwapError::RetryBudgetExhausted {
                swap_id: swap_id.to_string(),
                operation: operation.to_string(),
                attempts: used,
                max_retries: self.max_retries,
            });
        }
        let next = used + 1;
        self.attempts_by_swap.insert(swap_id.to_string(), next);
        Ok(next)
    }

    pub fn reset(&mut self, swap_id: &str) {
        self.attempts_by_swap.remove(swap_id);
    }
}

pub struct AtomicSwapCoordinator {
    swaps: Arc<RwLock<HashMap<String, AtomicSwap>>>,
    templates: Arc<RwLock<HashMap<String, SwapTemplate>>>,
    asset_registry: Arc<RwLock<AssetRegistry>>,
    preimage_manager: Arc<RwLock<PreimageManager>>,
    /// Consumes cross-chain `(chain, sender, nonce)` triples once each (#238).
    replay: Arc<RwLock<ReplayGuard>>,
    /// Bounded retry budget per swap coordination flow (#215).
    retry_budget: Arc<RwLock<RetryBudget>>,
    /// Caller-chosen keys bound to the initiation they first produced (#212).
    idempotency: Arc<Mutex<IdempotencyStore>>,
    monitor: SwapMonitor,
    config: SwapConfig,
}

impl AtomicSwapCoordinator {
    pub fn new(config: SwapConfig) -> Self {
        Self::with_retry_budget(config, DEFAULT_MAX_COORDINATION_RETRIES)
    }

    pub fn with_retry_budget(config: SwapConfig, max_retries: u32) -> Self {
        let monitor_config = MonitoringConfig::default();
        let monitor = SwapMonitor::new(monitor_config);

        Self {
            swaps: Arc::new(RwLock::new(HashMap::new())),
            templates: Arc::new(RwLock::new(HashMap::new())),
            asset_registry: Arc::new(RwLock::new(AssetRegistry::new())),
            preimage_manager: Arc::new(RwLock::new(PreimageManager::new())),
            replay: Arc::new(RwLock::new(ReplayGuard::new())),
            retry_budget: Arc::new(RwLock::new(RetryBudget::new(max_retries))),
            idempotency: Arc::new(Mutex::new(IdempotencyStore::new())),
            monitor,
            config,
        }
    }

    /// Initialize a new swap as initiator
    pub async fn initiate_swap(
        &self,
        initiator: String,
        request: SwapRequest,
    ) -> Result<SwapResponse> {
        // Validate request
        self.validate_swap_request(&request)?;

        // Consume the cross-chain nonce before anything is created, so a
        // replayed transfer is refused while the coordinator still has no side
        // effects to undo (#238).
        self.consume_cross_chain_nonce(&initiator, &request).await?;

        // Check asset support
        let asset_registry = self.asset_registry.read().await;
        if !asset_registry.is_supported(&request.initiator_asset) {
            return Err(AtomicSwapError::UnsupportedAsset {
                asset: request.initiator_asset.to_string(),
            });
        }
        if !asset_registry.is_supported(&request.participant_asset) {
            return Err(AtomicSwapError::UnsupportedAsset {
                asset: request.participant_asset.to_string(),
            });
        }
        drop(asset_registry);

        // Generate preimage and hash
        let mut preimage_manager = self.preimage_manager.write().await;
        let preimage = preimage_manager.generate(32)?; // 32 bytes
        let hash_lock = preimage.hash_hex();
        drop(preimage_manager);

        // Generate swap ID
        let swap_id = Uuid::new_v4().to_string();

        // Calculate timeout ledger (simplified - in real implementation, get current ledger)
        let current_ledger = 100000u32; // Placeholder
        let timeout_ledger = current_ledger + (request.timeout_hours * 720); // ~720 ledgers per hour

        // Create atomic swap
        let mut swap = AtomicSwap::new(
            swap_id.clone(),
            initiator.clone(),
            request.participant.clone(),
            request.initiator_asset.clone(),
            request.participant_asset.clone(),
            request.initiator_amount,
            request.participant_amount,
            hash_lock.clone(),
            timeout_ledger,
            current_ledger,
        );

        // Record where the transfer came from, so a later audit can tie the
        // swap back to the nonce that authorised it.
        if let (Some(chain), Some(nonce)) = (&request.origin_chain, request.nonce) {
            swap = swap.with_origin(chain.clone(), nonce);
        }

        // Add metadata
        for (key, value) in request.metadata {
            swap.add_metadata(key, value);
        }

        // Store swap
        let mut swaps = self.swaps.write().await;
        swaps.insert(swap_id.clone(), swap.clone());
        drop(swaps);

        // Add to monitor
        self.monitor.add_swap(swap.clone()).await?;

        info!(
            "Initiated swap {} between {} and {}",
            swap_id, initiator, request.participant
        );

        Ok(SwapResponse {
            swap_id,
            hash_lock,
            preimage: Some(preimage.data_hex()),
            timeout_ledger,
            contract_address: None, // Will be set after contract deployment
        })
    }

    /// Participate in an existing swap
    pub async fn participate_swap(
        &self,
        participant: String,
        swap_id: String,
    ) -> Result<AtomicSwap> {
        let swaps = self.swaps.read().await;
        let swap = swaps
            .get(&swap_id)
            .ok_or_else(|| AtomicSwapError::SwapNotFound {
                swap_id: swap_id.clone(),
            })?;

        // Verify participant matches
        if swap.participant != participant {
            return Err(AtomicSwapError::InvalidAddress {
                address: participant,
            });
        }

        // Verify swap is pending
        if !swap.is_pending() {
            return Err(AtomicSwapError::SwapAlreadyCompleted { swap_id });
        }

        Ok(swap.clone())
    }

    /// Complete a swap by providing the preimage
    pub async fn complete_swap(
        &self,
        swap_id: String,
        preimage: String,
        current_ledger: u32,
    ) -> Result<()> {
        let mut swaps = self.swaps.write().await;
        let swap = swaps
            .get_mut(&swap_id)
            .ok_or_else(|| AtomicSwapError::SwapNotFound {
                swap_id: swap_id.clone(),
            })?;

        // Verify swap can be completed
        if !swap.can_complete(current_ledger) {
            return if swap.is_expired(current_ledger) {
                Err(AtomicSwapError::SwapExpired { swap_id })
            } else {
                Err(AtomicSwapError::SwapAlreadyCompleted { swap_id })
            };
        }

        // Verify preimage hash
        let preimage_bytes =
            hex::decode(&preimage).map_err(|_| AtomicSwapError::InvalidPreimage {
                swap_id: swap_id.clone(),
            })?;

        let computed_hash = hex::encode(crate::preimage::Preimage::compute_hash(&preimage_bytes)?);
        if computed_hash != swap.hash_lock {
            return Err(AtomicSwapError::InvalidPreimage { swap_id });
        }

        // Mark swap as completed
        swap.mark_completed(preimage, current_ledger);

        // Update monitor
        self.monitor.remove_swap(&swap_id).await?;

        info!("Completed swap: {}", swap_id);
        Ok(())
    }

    /// Refund a swap after timeout
    pub async fn refund_swap(&self, swap_id: String, current_ledger: u32) -> Result<()> {
        let mut swaps = self.swaps.write().await;
        let swap = swaps
            .get_mut(&swap_id)
            .ok_or_else(|| AtomicSwapError::SwapNotFound {
                swap_id: swap_id.clone(),
            })?;

        // Verify swap can be refunded
        if !swap.can_refund(current_ledger) {
            return Err(AtomicSwapError::SwapExpired { swap_id });
        }

        // Mark swap as refunded
        swap.mark_refunded();

        // Update monitor
        self.monitor.remove_swap(&swap_id).await?;

        info!("Refunded swap: {}", swap_id);
        Ok(())
    }

    /// Create a multi-hop swap through intermediary assets
    // A multi-hop route legitimately carries one set of arguments per hop.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_multi_hop_swap(
        &self,
        initiator: String,
        participant: String,
        initiator_asset: Asset,
        participant_asset: Asset,
        initiator_amount: i128,
        participant_amount: i128,
        timeout_hours: u32,
    ) -> Result<Vec<SwapResponse>> {
        if !self.config.enable_multi_hop {
            return Err(AtomicSwapError::ConfigError(
                "Multi-hop swaps are disabled".to_string(),
            ));
        }

        // Find intermediary assets (simplified - in real implementation, use path finding)
        let intermediary_assets = self
            .find_intermediary_path(&initiator_asset, &participant_asset)
            .await?;

        if intermediary_assets.is_empty() {
            // Direct swap if no intermediary needed
            //
            // A multi-hop route is assembled out of internal legs: each leg
            // moves value between hop accounts rather than across chains, so no
            // leg consumes a cross-chain nonce. The nonce belongs to the
            // transfer that entered the route, which the operator presents to
            // `initiate_swap` directly.
            let request = SwapRequest {
                participant,
                initiator_asset: initiator_asset.clone(),
                participant_asset: participant_asset.clone(),
                initiator_amount,
                participant_amount,
                timeout_hours,
                origin_chain: None,
                nonce: None,
                metadata: HashMap::new(),
            };

            let response = self.initiate_swap(initiator, request).await?;
            return Ok(vec![response]);
        }

        // Create multi-hop swaps
        let mut responses = Vec::new();
        let mut current_initiator = initiator;
        let mut current_amount = initiator_amount;
        let mut current_asset = initiator_asset;

        for (i, intermediary_asset) in intermediary_assets.iter().enumerate() {
            let is_last_hop = i == intermediary_assets.len() - 1;
            let next_participant = if is_last_hop {
                participant.clone()
            } else {
                format!("hop_{}", i)
            };
            let next_asset = if is_last_hop {
                participant_asset.clone()
            } else {
                intermediary_asset.clone()
            };

            // Calculate exchange rate (simplified)
            let next_amount = self
                .calculate_exchange_amount(current_amount, &current_asset, &next_asset)
                .await?;

            let request = SwapRequest {
                participant: next_participant.clone(),
                initiator_asset: current_asset.clone(),
                participant_asset: next_asset.clone(),
                initiator_amount: current_amount,
                participant_amount: next_amount,
                timeout_hours,
                origin_chain: None,
                nonce: None,
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("hop_index".to_string(), i.to_string());
                    meta.insert(
                        "total_hops".to_string(),
                        intermediary_assets.len().to_string(),
                    );
                    if is_last_hop {
                        meta.insert("final_destination".to_string(), participant.clone());
                    }
                    meta
                },
            };

            let response = self
                .initiate_swap(current_initiator.clone(), request)
                .await?;
            responses.push(response);

            current_initiator = next_participant;
            current_amount = next_amount;
            current_asset = next_asset;
        }

        Ok(responses)
    }

    /// Initiate a swap at most once for `key` (#212).
    ///
    /// The first successful call with a given key behaves exactly like
    /// [`AtomicSwapCoordinator::initiate_swap`] and records its response under
    /// the key. Presenting the same key again with the same initiator and the
    /// same request returns that recorded response — same swap id, same hash
    /// lock, same preimage — without creating or funding a second swap.
    ///
    /// A key already bound to a different initiator or a different request is
    /// refused with [`AtomicSwapError::IdempotencyConflict`]. A failed
    /// initiation records nothing, so the caller may retry the same key with a
    /// corrected request.
    ///
    /// The key lock is held across initiation, which serialises idempotent
    /// initiation calls: two concurrent retries of the same key cannot both
    /// miss the store and create a swap. Initiation is in-memory work (plus the
    /// monitor fan-out), so the critical section stays bounded; non-idempotent
    /// [`AtomicSwapCoordinator::initiate_swap`] calls are unaffected.
    pub async fn initiate_swap_idempotent(
        &self,
        initiator: String,
        request: SwapRequest,
        key: IdempotencyKey,
    ) -> Result<SwapResponse> {
        let mut store = self.idempotency.lock().await;

        if let Some(result) = store.lookup(&key, &initiator, &request) {
            return result;
        }

        let response = self
            .initiate_swap(initiator.clone(), request.clone())
            .await?;
        store.record(&key, initiator, request, response.clone());
        Ok(response)
    }

    /// Number of idempotency keys bound to an initiation (#212).
    pub async fn idempotency_entries(&self) -> usize {
        self.idempotency.lock().await.len()
    }

    /// Forget a key, returning whether it was bound (#212).
    ///
    /// Only safe once the caller has independently established that the
    /// original swap will never be used: after this, the same key initiates a
    /// new swap.
    pub async fn forget_idempotency_key(&self, key: &IdempotencyKey) -> bool {
        self.idempotency.lock().await.forget(key)
    }

    /// Get swap information
    pub async fn get_swap(&self, swap_id: String) -> Result<AtomicSwap> {
        let swaps = self.swaps.read().await;
        swaps
            .get(&swap_id)
            .cloned()
            .ok_or_else(|| AtomicSwapError::SwapNotFound { swap_id })
    }

    /// List all swaps for a participant
    pub async fn list_swaps_for_participant(&self, participant: String) -> Result<Vec<AtomicSwap>> {
        let swaps = self.swaps.read().await;
        Ok(swaps
            .values()
            .filter(|swap| swap.initiator == participant || swap.participant == participant)
            .cloned()
            .collect())
    }

    /// Replay-protection counters plus the number of domains being tracked.
    pub async fn replay_stats(&self) -> ReplayStats {
        self.replay.read().await.stats()
    }

    /// Stop tracking `(chain, sender)`. Only safe once that nonce sequence is
    /// closed on every chain it can reach.
    pub async fn forget_replay_domain(&self, chain: &str, sender: &str) -> bool {
        self.replay.write().await.forget(chain, sender)
    }

    /// True when this `(chain, sender, nonce)` triple has been consumed.
    pub async fn nonce_is_recorded(&self, chain: &str, sender: &str, nonce: u64) -> bool {
        self.replay.read().await.is_recorded(chain, sender, nonce)
    }

    /// Consume one retry from the swap's coordination retry budget (#215).
    pub async fn record_coordination_retry(&self, swap_id: &str, operation: &str) -> Result<u32> {
        self.retry_budget
            .write()
            .await
            .try_consume(swap_id, operation)
    }

    /// Remaining retry attempts available for `swap_id` (#215).
    pub async fn remaining_retries(&self, swap_id: &str) -> u32 {
        self.retry_budget.read().await.remaining(swap_id)
    }

    /// Clear recorded retry attempts for `swap_id` (#215).
    pub async fn reset_retry_budget(&self, swap_id: &str) {
        self.retry_budget.write().await.reset(swap_id);
    }

    /// Register a new asset
    pub async fn register_asset(&self, asset_info: AssetInfo) -> Result<()> {
        let mut asset_registry = self.asset_registry.write().await;
        asset_registry.register(asset_info);
        Ok(())
    }

    /// Create a swap template
    pub async fn create_template(&self, template: SwapTemplate) -> Result<()> {
        let mut templates = self.templates.write().await;
        templates.insert(template.name.clone(), template);
        Ok(())
    }

    /// Get monitoring statistics
    pub async fn get_statistics(&self) -> Result<crate::monitor::MonitoringStats> {
        Ok(self.monitor.get_statistics().await)
    }

    /// Start the monitoring service
    pub async fn start_monitoring(&self) -> Result<()> {
        self.monitor.start_monitoring().await
    }

    // Private helper methods

    /// Consume the request's cross-chain nonce, if it declares one.
    ///
    /// A local swap carries neither field; a cross-chain swap carries both. Half
    /// an origin is a caller bug and is rejected rather than guessed at, because
    /// guessing wrong means either a replayed transfer or a legitimate one
    /// refused.
    async fn consume_cross_chain_nonce(
        &self,
        initiator: &str,
        request: &SwapRequest,
    ) -> Result<()> {
        match (&request.origin_chain, request.nonce) {
            (Some(chain), Some(nonce)) => {
                let mut replay = self.replay.write().await;
                replay.check_and_record(chain, initiator, nonce)?;
                Ok(())
            }
            (Some(_), None) => Err(ReplayError::IncompleteIntent { missing: "nonce" }.into()),
            (None, Some(_)) => Err(ReplayError::IncompleteIntent {
                missing: "origin chain",
            }
            .into()),
            (None, None) => Ok(()),
        }
    }

    fn validate_swap_request(&self, request: &SwapRequest) -> Result<()> {
        if request.initiator_amount < self.config.min_amount {
            return Err(AtomicSwapError::InvalidAmount {
                amount: request.initiator_amount,
            });
        }

        if request.participant_amount < self.config.min_amount {
            return Err(AtomicSwapError::InvalidAmount {
                amount: request.participant_amount,
            });
        }

        if request.timeout_hours == 0 || request.timeout_hours > self.config.max_timeout_hours {
            return Err(AtomicSwapError::InvalidTimeout {
                timeout_hours: request.timeout_hours,
            });
        }

        Ok(())
    }

    async fn find_intermediary_path(
        &self,
        from_asset: &Asset,
        to_asset: &Asset,
    ) -> Result<Vec<Asset>> {
        let _asset_registry = self.asset_registry.read().await;

        // Simplified path finding - in real implementation, use graph algorithms
        if from_asset == to_asset {
            return Ok(vec![]);
        }

        // For now, assume XLM is a universal intermediary
        if *from_asset != Asset::XLM && *to_asset != Asset::XLM {
            return Ok(vec![Asset::XLM]);
        }

        Ok(vec![])
    }

    async fn calculate_exchange_amount(
        &self,
        amount: i128,
        from_asset: &Asset,
        to_asset: &Asset,
    ) -> Result<i128> {
        // Simplified exchange rate calculation
        // In real implementation, query DEX or price oracle
        if from_asset == to_asset {
            return Ok(amount);
        }

        // Apply fee
        let fee_amount = (amount as f64 * self.config.fee_percentage / 100.0) as i128;
        Ok(amount - fee_amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::Asset;

    #[tokio::test]
    async fn test_swap_initiation() {
        let config = SwapConfig::default();
        let coordinator = AtomicSwapCoordinator::new(config);

        coordinator
            .register_asset(AssetInfo::custom(
                "USDC".to_string(),
                "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_string(),
                7,
            ))
            .await
            .expect("registering USDC should succeed");

        let request = SwapRequest {
            participant: "participant".to_string(),
            initiator_asset: Asset::XLM,
            participant_asset: Asset::Custom("USDC".to_string()),
            initiator_amount: 1000,
            participant_amount: 500,
            timeout_hours: 24,
            origin_chain: None,
            nonce: None,
            metadata: HashMap::new(),
        };

        let response = coordinator
            .initiate_swap("initiator".to_string(), request)
            .await
            .unwrap();
        assert!(!response.swap_id.is_empty());
        assert!(!response.hash_lock.is_empty());
        assert!(response.preimage.is_some());
    }

    #[tokio::test]
    async fn test_swap_completion() {
        let config = SwapConfig::default();
        let coordinator = AtomicSwapCoordinator::new(config);

        // Only XLM is registered by default, so USDC has to be added before it can
        // be swapped against.
        coordinator
            .register_asset(AssetInfo::custom(
                "USDC".to_string(),
                "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_string(),
                7,
            ))
            .await
            .expect("registering USDC should succeed");

        // First initiate a swap
        let request = SwapRequest {
            participant: "participant".to_string(),
            initiator_asset: Asset::XLM,
            participant_asset: Asset::Custom("USDC".to_string()),
            initiator_amount: 1000,
            participant_amount: 500,
            timeout_hours: 24,
            origin_chain: None,
            nonce: None,
            metadata: HashMap::new(),
        };

        let response = coordinator
            .initiate_swap("initiator".to_string(), request)
            .await
            .unwrap();
        let preimage = response.preimage.unwrap();
        let swap_id = response.swap_id.clone();

        // Complete the swap
        coordinator
            .complete_swap(response.swap_id, preimage, 101000)
            .await
            .unwrap();

        // Verify swap is completed
        let swap = coordinator.get_swap(swap_id).await.unwrap();
        assert!(swap.is_completed());
    }

    /// A coordinator with USDC registered, so an XLM/USDC swap clears asset
    /// validation and the cross-chain tests can focus on the nonce.
    async fn coordinator_with_usdc() -> AtomicSwapCoordinator {
        let coordinator = AtomicSwapCoordinator::new(SwapConfig::default());
        coordinator
            .register_asset(AssetInfo::custom(
                "USDC".to_string(),
                "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_string(),
                7,
            ))
            .await
            .expect("registering USDC should succeed");
        coordinator
    }

    /// A swap request carrying an optional `(origin chain, nonce)`.
    fn request_with_origin(origin: Option<(&str, u64)>) -> SwapRequest {
        SwapRequest {
            participant: "participant".to_string(),
            initiator_asset: Asset::XLM,
            participant_asset: Asset::Custom("USDC".to_string()),
            initiator_amount: 1000,
            participant_amount: 500,
            timeout_hours: 24,
            origin_chain: origin.map(|(chain, _)| chain.to_string()),
            nonce: origin.map(|(_, nonce)| nonce),
            metadata: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn a_cross_chain_nonce_is_consumed_exactly_once() {
        let coordinator = coordinator_with_usdc().await;

        let accepted = coordinator
            .initiate_swap(
                "initiator".to_string(),
                request_with_origin(Some(("testnet", 7))),
            )
            .await
            .expect("the first presentation of a nonce is accepted");

        let swap = coordinator.get_swap(accepted.swap_id).await.unwrap();
        assert!(swap.is_cross_chain());
        assert_eq!(swap.origin_chain.as_deref(), Some("testnet"));
        assert_eq!(swap.origin_nonce, Some(7));

        let error = coordinator
            .initiate_swap(
                "initiator".to_string(),
                request_with_origin(Some(("testnet", 7))),
            )
            .await
            .expect_err("a replayed nonce is refused");
        assert!(matches!(
            error,
            AtomicSwapError::Replay(ReplayError::Replayed { .. })
        ));

        // The replay must not have created a swap of its own.
        assert_eq!(
            coordinator
                .list_swaps_for_participant("initiator".to_string())
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            coordinator
                .nonce_is_recorded("testnet", "initiator", 7)
                .await
        );
        assert_eq!(coordinator.replay_stats().await.replayed, 1);
    }

    #[tokio::test]
    async fn the_next_nonce_for_the_same_sender_is_still_accepted() {
        let coordinator = coordinator_with_usdc().await;
        for nonce in [1, 2, 3] {
            coordinator
                .initiate_swap(
                    "initiator".to_string(),
                    request_with_origin(Some(("testnet", nonce))),
                )
                .await
                .unwrap_or_else(|e| panic!("nonce {nonce} rejected: {e}"));
        }
        // A different sender reuses nonce 1 legitimately: its own sequence.
        coordinator
            .initiate_swap(
                "other-initiator".to_string(),
                request_with_origin(Some(("testnet", 1))),
            )
            .await
            .expect("another sender has its own nonce sequence");
        assert_eq!(coordinator.replay_stats().await.accepted, 4);
    }

    #[tokio::test]
    async fn a_local_swap_needs_no_nonce() {
        let coordinator = coordinator_with_usdc().await;
        coordinator
            .initiate_swap("initiator".to_string(), request_with_origin(None))
            .await
            .expect("a local swap is not affected by replay protection");
        assert_eq!(coordinator.replay_stats().await.accepted, 0);
    }

    #[tokio::test]
    async fn half_an_origin_is_refused() {
        let coordinator = coordinator_with_usdc().await;

        let mut without_nonce = request_with_origin(Some(("testnet", 1)));
        without_nonce.nonce = None;
        let error = coordinator
            .initiate_swap("initiator".to_string(), without_nonce)
            .await
            .expect_err("an origin chain without a nonce cannot be replayed safely");
        assert!(matches!(
            error,
            AtomicSwapError::Replay(ReplayError::IncompleteIntent { missing: "nonce" })
        ));

        let mut without_chain = request_with_origin(Some(("testnet", 1)));
        without_chain.origin_chain = None;
        let error = coordinator
            .initiate_swap("initiator".to_string(), without_chain)
            .await
            .expect_err("a nonce without a chain has no domain to be consumed in");
        assert!(matches!(
            error,
            AtomicSwapError::Replay(ReplayError::IncompleteIntent {
                missing: "origin chain"
            })
        ));
    }

    fn idempotency_key(value: &str) -> IdempotencyKey {
        IdempotencyKey::new(value).expect("test key should be valid")
    }

    #[tokio::test]
    async fn retrying_an_idempotent_initiation_replays_the_first_swap() {
        let coordinator = coordinator_with_usdc().await;
        let request = request_with_origin(None);

        let first = coordinator
            .initiate_swap_idempotent(
                "initiator".to_string(),
                request.clone(),
                idempotency_key("retry-1"),
            )
            .await
            .expect("the first attempt must succeed");
        let second = coordinator
            .initiate_swap_idempotent("initiator".to_string(), request, idempotency_key("retry-1"))
            .await
            .expect("a retry with the same key and request must succeed");

        assert_eq!(first, second, "the retry must replay the original response");
        assert_eq!(
            coordinator
                .list_swaps_for_participant("initiator".to_string())
                .await
                .unwrap()
                .len(),
            1,
            "a retry must not fund a second swap"
        );
        assert_eq!(coordinator.idempotency_entries().await, 1);
    }

    #[tokio::test]
    async fn the_same_key_with_a_different_request_conflicts_and_creates_nothing() {
        let coordinator = coordinator_with_usdc().await;
        let key = idempotency_key("retry-1");
        let original = request_with_origin(None);

        let first = coordinator
            .initiate_swap_idempotent("initiator".to_string(), original.clone(), key.clone())
            .await
            .expect("the first attempt must succeed");

        let mut different = original.clone();
        different.initiator_amount = 2_000;
        let error = coordinator
            .initiate_swap_idempotent("initiator".to_string(), different, key.clone())
            .await
            .expect_err("reusing a key for a different intent must be refused");
        assert!(matches!(error, AtomicSwapError::IdempotencyConflict { .. }));

        // The conflict did not create a swap, and the original is still
        // reachable through its key.
        assert_eq!(
            coordinator
                .list_swaps_for_participant("initiator".to_string())
                .await
                .unwrap()
                .len(),
            1
        );
        let replayed = coordinator
            .initiate_swap_idempotent("initiator".to_string(), original, key)
            .await
            .unwrap();
        assert_eq!(replayed.swap_id, first.swap_id);
    }

    #[tokio::test]
    async fn a_failed_initiation_does_not_consume_the_key() {
        let coordinator = coordinator_with_usdc().await;
        let key = idempotency_key("retry-1");

        let mut invalid = request_with_origin(None);
        invalid.timeout_hours = 0;
        let error = coordinator
            .initiate_swap_idempotent("initiator".to_string(), invalid, key.clone())
            .await
            .expect_err("a zero timeout is rejected");
        assert!(matches!(
            error,
            AtomicSwapError::InvalidTimeout { timeout_hours: 0 }
        ));
        assert_eq!(
            coordinator.idempotency_entries().await,
            0,
            "a rejected initiation must not bind its key"
        );

        // Fixing the request and retrying with the same key must now be
        // allowed: the failed attempt created nothing to replay.
        let accepted = coordinator
            .initiate_swap_idempotent("initiator".to_string(), request_with_origin(None), key)
            .await
            .expect("a corrected request may reuse the key");
        assert!(!accepted.swap_id.is_empty());
        assert_eq!(coordinator.idempotency_entries().await, 1);
    }

    #[tokio::test]
    async fn concurrent_retries_of_the_same_key_create_one_swap() {
        let coordinator = coordinator_with_usdc().await;

        let (first, second) = tokio::join!(
            coordinator.initiate_swap_idempotent(
                "initiator".to_string(),
                request_with_origin(None),
                idempotency_key("retry-1"),
            ),
            coordinator.initiate_swap_idempotent(
                "initiator".to_string(),
                request_with_origin(None),
                idempotency_key("retry-1"),
            ),
        );
        let (first, second) = (
            first.expect("the first concurrent attempt must succeed"),
            second.expect("the second concurrent attempt must replay it"),
        );
        assert_eq!(first, second);
        assert_eq!(
            coordinator
                .list_swaps_for_participant("initiator".to_string())
                .await
                .unwrap()
                .len(),
            1,
            "only one of the concurrent attempts may create a swap"
        );
    }

    #[tokio::test]
    async fn forgetting_a_key_allows_a_new_initiation() {
        let coordinator = coordinator_with_usdc().await;
        let key = idempotency_key("retry-1");

        let first = coordinator
            .initiate_swap_idempotent(
                "initiator".to_string(),
                request_with_origin(None),
                key.clone(),
            )
            .await
            .unwrap();
        assert!(coordinator.forget_idempotency_key(&key).await);

        let second = coordinator
            .initiate_swap_idempotent(
                "initiator".to_string(),
                request_with_origin(None),
                key.clone(),
            )
            .await
            .unwrap();
        assert_ne!(
            first.swap_id, second.swap_id,
            "a forgotten key may initiate again"
        );
        assert!(
            coordinator.forget_idempotency_key(&key).await,
            "the second initiation bound the key again"
        );
        assert!(
            !coordinator.forget_idempotency_key(&key).await,
            "forgetting a key twice reports the second call as a no-op"
        );
    }

    #[tokio::test]
    async fn coordination_retry_budget_enforces_cap_and_resets() {
        let coordinator = AtomicSwapCoordinator::with_retry_budget(SwapConfig::default(), 2);
        let swap_id = "swap-budget-test";

        assert_eq!(coordinator.remaining_retries(swap_id).await, 2);
        assert_eq!(
            coordinator
                .record_coordination_retry(swap_id, "submit_htlc")
                .await
                .unwrap(),
            1
        );
        assert_eq!(coordinator.remaining_retries(swap_id).await, 1);
        assert_eq!(
            coordinator
                .record_coordination_retry(swap_id, "submit_htlc")
                .await
                .unwrap(),
            2
        );
        assert_eq!(coordinator.remaining_retries(swap_id).await, 0);

        let err = coordinator
            .record_coordination_retry(swap_id, "submit_htlc")
            .await
            .expect_err("3rd retry must exceed budget of 2");
        assert!(matches!(
            err,
            AtomicSwapError::RetryBudgetExhausted {
                attempts: 2,
                max_retries: 2,
                ..
            }
        ));

        coordinator.reset_retry_budget(swap_id).await;
        assert_eq!(coordinator.remaining_retries(swap_id).await, 2);
    }
}

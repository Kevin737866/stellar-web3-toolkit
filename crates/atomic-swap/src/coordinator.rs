use crate::asset::{Asset, AssetInfo, AssetRegistry};
use crate::error::{AtomicSwapError, Result};
use crate::idempotency::{IdempotencyKey, IdempotencyStore};
use crate::journal::{InMemoryJournal, TransitionJournal, TransitionRecord, UnresolvedAction};
use crate::monitor::{MonitoringConfig, SwapMonitor};
use crate::preimage::PreimageManager;
use crate::replay::{ReplayError, ReplayGuard, ReplayStats};
use crate::swap::{AtomicSwap, SwapFailureReason, SwapTemplate};
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
    /// Durable record of every state transition, written before it is applied
    /// and before any chain action is submitted (#390).
    journal: Arc<dyn TransitionJournal>,
    monitor: SwapMonitor,
    config: SwapConfig,
}

impl AtomicSwapCoordinator {
    pub fn new(config: SwapConfig) -> Self {
        Self::with_retry_budget(config, DEFAULT_MAX_COORDINATION_RETRIES)
    }

    pub fn with_retry_budget(config: SwapConfig, max_retries: u32) -> Self {
        Self::with_journal(config, max_retries, Arc::new(InMemoryJournal::new()))
    }

    /// Build a coordinator that persists transitions to `journal` (#390).
    ///
    /// Pass a [`crate::FileJournal`] to survive a restart; the process-local
    /// [`InMemoryJournal`] is used by the shorter constructors.
    pub fn with_journal(
        config: SwapConfig,
        max_retries: u32,
        journal: Arc<dyn TransitionJournal>,
    ) -> Self {
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
            journal,
            monitor,
            config,
        }
    }

    /// The journal backing this coordinator's transitions (#390).
    pub fn journal(&self) -> &Arc<dyn TransitionJournal> {
        &self.journal
    }

    /// Initialize a new swap as initiator
    pub async fn initiate_swap(
        &self,
        initiator: String,
        request: SwapRequest,
    ) -> Result<SwapResponse> {
        // Validate request
        self.validate_swap_request(&request)?;

        // Reject a replayed cross-chain transfer before anything is created, so
        // a rejected initiation has no side effects to undo (#238). The nonce is
        // only *consumed* further down, immediately before the swap becomes
        // visible: consuming it here would burn it for good if a later step
        // failed, and the caller could then never retry (#394).
        self.preflight_cross_chain_nonce(&initiator, &request)
            .await?;

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
        let current_ledger = 100_000u32; // Placeholder
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
        for (key, value) in &request.metadata {
            swap.add_metadata(key.clone(), value.clone());
        }

        // Record the creation before it becomes visible in memory, so a restart
        // can rebuild the swap from the journal alone (#390).
        self.journal
            .append(TransitionRecord::initiated(&swap, current_ledger))?;

        // Consume the cross-chain nonce last, right before the swap is
        // published. Every fallible step above has succeeded, so the nonce is
        // only spent on an initiation that actually produced a swap. If the
        // monitor fan-out below fails, the swap is withdrawn and the nonce
        // released, so the caller can retry the same intent (#394).
        self.consume_cross_chain_nonce(&initiator, &request).await?;

        // Store swap
        let mut swaps = self.swaps.write().await;
        swaps.insert(swap_id.clone(), swap.clone());
        drop(swaps);

        // Add to monitor
        if let Err(error) = self.monitor.add_swap(swap.clone()).await {
            let mut swaps = self.swaps.write().await;
            swaps.remove(&swap_id);
            drop(swaps);
            self.release_cross_chain_nonce(&initiator, &request).await;
            return Err(error);
        }

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

    /// Complete a swap by revealing its preimage.
    ///
    /// The preimage path stays open through the timeout ledger: at
    /// `current_ledger == timeout_ledger` the swap has not expired yet, so
    /// completion still succeeds and reveals the preimage; at
    /// `timeout_ledger + 1` it is refused with [`AtomicSwapError::SwapExpired`].
    /// A swap that already settled is refused with
    /// [`AtomicSwapError::SwapAlreadyCompleted`], and a preimage that does not
    /// hash to the swap's lock with [`AtomicSwapError::InvalidPreimage`] (#396).
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

        // Persist the settled state before it is applied in memory, so a crash
        // mid-settlement cannot lose the preimage the chain already revealed
        // (#390).
        let mut settled = swap.clone();
        settled.mark_completed(preimage.clone(), current_ledger);
        self.journal
            .append(TransitionRecord::settled(&settled, current_ledger))?;

        // Mark swap as completed
        swap.mark_completed(preimage, current_ledger);

        // Update monitor
        self.monitor.remove_swap(&swap_id).await?;

        info!("Completed swap: {}", swap_id);
        Ok(())
    }

    /// Refund a swap after its timeout ledger has passed.
    ///
    /// The refund path opens only *after* the timeout ledger: at
    /// `current_ledger == timeout_ledger` the swap can still settle, so
    /// refunding then would let a participant claw back funds while the
    /// counterparty could still reveal the preimage. A pending swap refunded
    /// before its timeout is refused with [`AtomicSwapError::RefundBeforeTimeout`]
    /// (#396); a swap that already reached a terminal state is refused with
    /// [`AtomicSwapError::SwapExpired`].
    pub async fn refund_swap(&self, swap_id: String, current_ledger: u32) -> Result<()> {
        let mut swaps = self.swaps.write().await;
        let swap = swaps
            .get_mut(&swap_id)
            .ok_or_else(|| AtomicSwapError::SwapNotFound {
                swap_id: swap_id.clone(),
            })?;

        // Verify swap can be refunded. `can_refund` is `is_pending() &&
        // is_expired(current_ledger)`, so the two ways it fails get distinct,
        // actionable errors: a pending swap inside its window is too early to
        // refund, and a swap that already settled/timed out has nothing left
        // to refund (#396).
        if !swap.can_refund(current_ledger) {
            if swap.is_pending() {
                return Err(AtomicSwapError::RefundBeforeTimeout {
                    swap_id,
                    timeout_ledger: swap.timeout_ledger,
                    current_ledger,
                });
            }
            return Err(AtomicSwapError::SwapExpired { swap_id });
        }

        // Persist the refund before it is applied in memory (#390).
        let mut refunded = swap.clone();
        refunded.mark_refunded();
        self.journal
            .append(TransitionRecord::refunded(&refunded, current_ledger))?;

        // Mark swap as refunded
        swap.mark_refunded();

        // Update monitor
        self.monitor.remove_swap(&swap_id).await?;

        info!("Refunded swap: {}", swap_id);
        Ok(())
    }

    /// Record why `swap_id` failed, so the swap carries a terminal reason (#391).
    ///
    /// This is the only way a swap reaches [`SwapStatus::Failed`](crate::SwapStatus::Failed)
    /// through the coordinator: a status without a reason tells an operator
    /// nothing, and a settlement flow that stopped is exactly the case where they
    /// need to know whether to retry, refund or escalate.
    ///
    /// Returns `true` when the reason was recorded, `false` when the swap is
    /// unknown or already carries one — the first reason is never overwritten.
    pub async fn fail_swap(
        &self,
        swap_id: &str,
        reason: SwapFailureReason,
        current_ledger: u32,
    ) -> Result<bool> {
        let mut swaps = self.swaps.write().await;
        let swap = swaps
            .get_mut(swap_id)
            .ok_or_else(|| AtomicSwapError::SwapNotFound {
                swap_id: swap_id.to_string(),
            })?;

        // A swap that already settled or timed out is not a failure: refusing
        // here keeps `Completed`/`Refunded`/`Expired` from being overwritten by a
        // late error report. `Failed` is excluded so a swap marked failed
        // without a reason (an older record) can still be given one.
        if swap.status.is_terminal() && !matches!(swap.status, crate::swap::SwapStatus::Failed) {
            return Err(AtomicSwapError::SwapAlreadyCompleted {
                swap_id: swap_id.to_string(),
            });
        }

        // Only the first reason is recorded, so only the first one is journalled
        // (#390): appending a second `failed` record would claim a transition
        // that never happens.
        let already_failed = swap.failure.is_some();
        if !already_failed {
            let mut failed = swap.clone();
            failed.mark_failed(reason.clone(), current_ledger);
            self.journal.append(TransitionRecord::failed(
                &failed,
                reason.code(),
                current_ledger,
            ))?;
        }

        let recorded = swap.mark_failed(reason.clone(), current_ledger);
        drop(swaps);

        if recorded {
            // The monitor keeps its own copy; propagate the reason there too so
            // status output and the `Failed` event agree with the coordinator.
            info!("Failed swap {}: {}", swap_id, reason);
            self.monitor
                .fail_swap(swap_id, reason, current_ledger)
                .await;
        }
        Ok(recorded)
    }

    /// Mark a pending swap expired once its timeout ledger has passed (#390).
    ///
    /// The monitor can flip its own copy to `Expired`, but that copy is not the
    /// coordinator's record — without this path an expired swap stayed `Pending`
    /// in the journal and would come back as refundable after a restart.
    ///
    /// Returns `true` when the swap was marked expired, `false` when it is not
    /// pending or the timeout has not passed yet.
    pub async fn expire_swap(&self, swap_id: &str, current_ledger: u32) -> Result<bool> {
        let mut swaps = self.swaps.write().await;
        let swap = swaps
            .get_mut(swap_id)
            .ok_or_else(|| AtomicSwapError::SwapNotFound {
                swap_id: swap_id.to_string(),
            })?;

        if !swap.is_pending() || !swap.is_expired(current_ledger) {
            return Ok(false);
        }

        // Journal first: a restart that saw `Pending` would let a refund race a
        // swap the chain has already timed out (#390).
        let mut expired = swap.clone();
        expired.mark_expired();
        self.journal
            .append(TransitionRecord::expired(&expired, current_ledger))?;

        swap.mark_expired();
        drop(swaps);

        info!("Expired swap: {} at ledger {}", swap_id, current_ledger);
        Ok(true)
    }

    /// The terminal reason recorded for a failed swap (#391).
    ///
    /// `None` while the swap can still settle, or when it settled/timed out.
    pub async fn terminal_reason(&self, swap_id: &str) -> Result<Option<String>> {
        let swaps = self.swaps.read().await;
        let swap = swaps
            .get(swap_id)
            .ok_or_else(|| AtomicSwapError::SwapNotFound {
                swap_id: swap_id.to_string(),
            })?;
        Ok(swap.terminal_reason())
    }

    /// Record that `operation` is about to be submitted to the chain (#390).
    ///
    /// Call this *before* the chain action. The intent is durable first, so a
    /// process that dies while the action is in flight leaves an
    /// [`UnresolvedAction`] behind instead of a swap that silently claims the
    /// action never happened.
    ///
    /// Returns the `seq` of the recorded transition. Re-recording the same
    /// `(swap, operation)` is a no-op.
    pub async fn record_chain_action_pending(
        &self,
        swap_id: &str,
        operation: &str,
        current_ledger: u32,
    ) -> Result<u64> {
        let swap = self.get_swap(swap_id.to_string()).await?;
        let record = self.journal.append(TransitionRecord::chain_action_pending(
            &swap,
            operation,
            current_ledger,
        ))?;
        Ok(record.seq)
    }

    /// Record that the chain accepted `operation` (#390).
    pub async fn record_chain_action_confirmed(
        &self,
        swap_id: &str,
        operation: &str,
        current_ledger: u32,
    ) -> Result<u64> {
        let swap = self.get_swap(swap_id.to_string()).await?;
        let record = self
            .journal
            .append(TransitionRecord::chain_action_confirmed(
                &swap,
                operation,
                current_ledger,
            ))?;
        Ok(record.seq)
    }

    /// Record that the chain rejected `operation`, with the action's own error
    /// (#390).
    pub async fn record_chain_action_failed(
        &self,
        swap_id: &str,
        operation: &str,
        detail: &str,
        current_ledger: u32,
    ) -> Result<u64> {
        let swap = self.get_swap(swap_id.to_string()).await?;
        let record = self.journal.append(TransitionRecord::chain_action_failed(
            &swap,
            operation,
            detail,
            current_ledger,
        ))?;
        Ok(record.seq)
    }

    /// Chain actions that were started but whose outcome was never recorded.
    ///
    /// After a restart these are the swaps an operator (or a retry loop) must
    /// reconcile against the chain before doing anything else (#390).
    pub fn unresolved_chain_actions(&self) -> Result<Vec<UnresolvedAction>> {
        self.journal.unresolved_actions()
    }

    /// Rebuild in-memory state from the journal (#390).
    ///
    /// Every swap is restored to the state its last record describes, so a
    /// coordinator started against a [`crate::FileJournal`] sees exactly the
    /// swaps that had been initiated and their latest transition. Returns the
    /// number of swaps restored.
    ///
    /// Swaps already present in memory are left alone: recovery fills gaps, it
    /// never overwrites live state.
    pub async fn recover_from_journal(&self) -> Result<usize> {
        let mut restored = 0;
        for swap_id in self.journal.swap_ids()? {
            let Some(latest) = self.journal.transitions(&swap_id)?.pop() else {
                continue;
            };
            let mut swaps = self.swaps.write().await;
            if swaps.contains_key(&swap_id) {
                continue;
            }
            swaps.insert(swap_id.clone(), latest.snapshot);
            restored += 1;
        }
        Ok(restored)
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
                format!("hop_{i}")
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

    /// Reject the request's cross-chain nonce if it could not be consumed,
    /// without consuming it (#238, #394).
    ///
    /// A local swap carries neither field; a cross-chain swap carries both. Half
    /// an origin is a caller bug and is rejected rather than guessed at, because
    /// guessing wrong means either a replayed transfer or a legitimate one
    /// refused.
    ///
    /// Shares the shape checks with [`Self::consume_cross_chain_nonce`] so the
    /// two cannot disagree about what a well-formed intent is.
    async fn preflight_cross_chain_nonce(
        &self,
        initiator: &str,
        request: &SwapRequest,
    ) -> Result<()> {
        match (&request.origin_chain, request.nonce) {
            (Some(chain), Some(nonce)) => {
                let mut replay = self.replay.write().await;
                replay.preflight(chain, initiator, nonce)?;
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

    /// Consume the request's cross-chain nonce, if it declares one.
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

    /// Give back a nonce consumed by an initiation that then failed (#394).
    async fn release_cross_chain_nonce(&self, initiator: &str, request: &SwapRequest) {
        if let (Some(chain), Some(nonce)) = (&request.origin_chain, request.nonce) {
            self.replay.write().await.release(chain, initiator, nonce);
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

    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)] // kept async so the oracle lookup can be awaited later
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
    use crate::journal::TransitionKind;
    use crate::swap::SwapStatus;

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
            .complete_swap(response.swap_id, preimage, 101_000)
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
    async fn a_failed_initiation_does_not_burn_the_cross_chain_nonce() {
        let coordinator = coordinator_with_usdc().await;

        // A request that is well formed enough to pass the nonce preflight but
        // is refused later, when its asset is checked.
        let mut unsupported = request_with_origin(Some(("testnet", 7)));
        unsupported.participant_asset = Asset::Custom("DOGE".to_string());

        let error = coordinator
            .initiate_swap("initiator".to_string(), unsupported)
            .await
            .expect_err("an unsupported asset is refused");
        assert!(matches!(error, AtomicSwapError::UnsupportedAsset { .. }));
        assert!(
            !coordinator
                .nonce_is_recorded("testnet", "initiator", 7)
                .await,
            "a failed initiation must not spend the nonce"
        );

        // The caller retries the same intent with a supported asset and the
        // same nonce: it must be accepted, not reported as a replay.
        let accepted = coordinator
            .initiate_swap(
                "initiator".to_string(),
                request_with_origin(Some(("testnet", 7))),
            )
            .await
            .expect("the nonce was never consumed, so the retry is accepted");
        assert!(!accepted.swap_id.is_empty());
        assert!(
            coordinator
                .nonce_is_recorded("testnet", "initiator", 7)
                .await,
            "the successful initiation consumes the nonce"
        );
    }

    #[tokio::test]
    async fn a_nonce_is_only_spent_once_even_after_a_failed_attempt() {
        let coordinator = coordinator_with_usdc().await;

        let mut unsupported = request_with_origin(Some(("testnet", 3)));
        unsupported.initiator_asset = Asset::Custom("NOPE".to_string());
        coordinator
            .initiate_swap("initiator".to_string(), unsupported)
            .await
            .expect_err("an unsupported asset is refused");

        coordinator
            .initiate_swap(
                "initiator".to_string(),
                request_with_origin(Some(("testnet", 3))),
            )
            .await
            .expect("the retry is accepted");

        // Now that a swap exists for it, the nonce really is spent.
        let error = coordinator
            .initiate_swap(
                "initiator".to_string(),
                request_with_origin(Some(("testnet", 3))),
            )
            .await
            .expect_err("a nonce that produced a swap is replayed");
        assert!(matches!(
            error,
            AtomicSwapError::Replay(ReplayError::Replayed { .. })
        ));
    }

    #[tokio::test]
    async fn a_replayed_nonce_is_refused_before_anything_is_created() {
        let coordinator = coordinator_with_usdc().await;
        coordinator
            .initiate_swap(
                "initiator".to_string(),
                request_with_origin(Some(("testnet", 9))),
            )
            .await
            .unwrap();

        let error = coordinator
            .initiate_swap(
                "initiator".to_string(),
                request_with_origin(Some(("testnet", 9))),
            )
            .await
            .expect_err("a replayed nonce is refused");
        assert!(matches!(
            error,
            AtomicSwapError::Replay(ReplayError::Replayed { .. })
        ));
        assert_eq!(
            coordinator
                .list_swaps_for_participant("initiator".to_string())
                .await
                .unwrap()
                .len(),
            1,
            "the rejected replay created nothing"
        );
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
    async fn a_failed_swap_exposes_a_terminal_reason_through_the_coordinator() {
        use crate::swap::SwapFailureReason;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let coordinator = coordinator_with_usdc().await;
        let swap_id = coordinator
            .initiate_swap("initiator".to_string(), request_with_origin(None))
            .await
            .unwrap()
            .swap_id;

        assert!(
            coordinator
                .terminal_reason(&swap_id)
                .await
                .unwrap()
                .is_none(),
            "a pending swap has no terminal reason"
        );

        let failed_events = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&failed_events);
        coordinator
            .monitor
            .add_event_handler(move |event| {
                if let crate::monitor::SwapEvent::Failed { reason_code, .. } = event {
                    assert_eq!(reason_code, "retry_budget_exhausted");
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            })
            .await;

        let reason = SwapFailureReason::RetryBudgetExhausted {
            operation: "submit_htlc".to_string(),
            attempts: 3,
        };
        assert!(coordinator
            .fail_swap(&swap_id, reason.clone(), 101_500)
            .await
            .unwrap());

        let swap = coordinator.get_swap(swap_id.clone()).await.unwrap();
        assert_eq!(swap.status, crate::swap::SwapStatus::Failed);
        assert_eq!(swap.failure().map(|f| &f.reason), Some(&reason));
        assert_eq!(swap.failure().map(|f| f.ledger), Some(101_500));
        assert_eq!(
            coordinator.terminal_reason(&swap_id).await.unwrap(),
            Some(reason.to_string())
        );
        assert_eq!(
            failed_events.load(Ordering::SeqCst),
            1,
            "a recorded failure emits exactly one Failed event"
        );

        // A second report is a no-op: the first reason is the terminal one.
        let late = SwapFailureReason::Abandoned {
            detail: "operator".to_string(),
        };
        assert!(!coordinator
            .fail_swap(&swap_id, late, 101_600)
            .await
            .unwrap());
        assert_eq!(
            coordinator.terminal_reason(&swap_id).await.unwrap(),
            Some(reason.to_string())
        );
        assert_eq!(
            failed_events.load(Ordering::SeqCst),
            1,
            "a duplicate report must not emit a second event"
        );
    }

    #[tokio::test]
    async fn a_settled_swap_cannot_be_marked_failed() {
        use crate::swap::SwapFailureReason;

        let coordinator = coordinator_with_usdc().await;
        let response = coordinator
            .initiate_swap("initiator".to_string(), request_with_origin(None))
            .await
            .unwrap();
        coordinator
            .complete_swap(
                response.swap_id.clone(),
                response.preimage.clone().unwrap(),
                101_000,
            )
            .await
            .unwrap();

        let error = coordinator
            .fail_swap(
                &response.swap_id,
                SwapFailureReason::Abandoned {
                    detail: "too late".to_string(),
                },
                101_100,
            )
            .await
            .expect_err("a completed swap must not be overwritten by a failure");
        assert!(matches!(
            error,
            AtomicSwapError::SwapAlreadyCompleted { .. }
        ));
        assert!(coordinator
            .terminal_reason(&response.swap_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn failing_an_unknown_swap_is_an_error_not_a_silent_success() {
        use crate::swap::SwapFailureReason;

        let coordinator = coordinator_with_usdc().await;
        let error = coordinator
            .fail_swap("does-not-exist", SwapFailureReason::CounterpartyTimeout, 1)
            .await
            .expect_err("an unknown swap cannot be failed");
        assert!(matches!(error, AtomicSwapError::SwapNotFound { .. }));
        assert!(coordinator.terminal_reason("does-not-exist").await.is_err());
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

    // ---- Durable state transitions (#390) ----

    fn journal_entries(
        coordinator: &AtomicSwapCoordinator,
        swap_id: &str,
    ) -> Vec<TransitionRecord> {
        coordinator.journal().transitions(swap_id).unwrap()
    }

    #[tokio::test]
    async fn initiation_is_journalled_before_the_swap_is_stored() {
        let coordinator = coordinator_with_usdc().await;

        let response = coordinator
            .initiate_swap("initiator".to_string(), request_with_origin(None))
            .await
            .unwrap();

        let entries = journal_entries(&coordinator, &response.swap_id);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, TransitionKind::Initiated);
        assert_eq!(entries[0].seq, 1);
        assert_eq!(entries[0].snapshot.id, response.swap_id);
    }

    #[tokio::test]
    async fn a_chain_action_is_bracketed_by_intent_and_outcome() {
        let coordinator = coordinator_with_usdc().await;
        let swap_id = coordinator
            .initiate_swap("initiator".to_string(), request_with_origin(None))
            .await
            .unwrap()
            .swap_id;

        coordinator
            .record_chain_action_pending(&swap_id, "lock", 100_001)
            .await
            .unwrap();
        assert_eq!(
            coordinator.unresolved_chain_actions().unwrap(),
            vec![UnresolvedAction {
                swap_id: swap_id.clone(),
                operation: "lock".to_string(),
                ledger: 100_001,
            }],
            "an intent with no outcome must be reported as unresolved"
        );

        coordinator
            .record_chain_action_confirmed(&swap_id, "lock", 100_002)
            .await
            .unwrap();
        assert!(coordinator.unresolved_chain_actions().unwrap().is_empty());

        let kinds: Vec<_> = journal_entries(&coordinator, &swap_id)
            .into_iter()
            .map(|r| r.kind)
            .collect();
        assert_eq!(kinds.len(), 3);
        assert_eq!(
            kinds[1],
            TransitionKind::ChainActionPending {
                operation: "lock".to_string()
            }
        );
        assert_eq!(
            kinds[2],
            TransitionKind::ChainActionConfirmed {
                operation: "lock".to_string()
            }
        );
    }

    #[tokio::test]
    async fn a_failed_chain_action_records_the_reason() {
        let coordinator = coordinator_with_usdc().await;
        let swap_id = coordinator
            .initiate_swap("initiator".to_string(), request_with_origin(None))
            .await
            .unwrap()
            .swap_id;

        coordinator
            .record_chain_action_pending(&swap_id, "lock", 100_001)
            .await
            .unwrap();
        coordinator
            .record_chain_action_failed(&swap_id, "lock", "tx_bad_seq", 100_002)
            .await
            .unwrap();

        assert!(coordinator.unresolved_chain_actions().unwrap().is_empty());
        let entries = journal_entries(&coordinator, &swap_id);
        assert_eq!(
            entries.last().unwrap().kind,
            TransitionKind::ChainActionFailed {
                operation: "lock".to_string(),
                detail: "tx_bad_seq".to_string()
            }
        );
    }

    #[tokio::test]
    async fn settlement_and_refund_are_journalled() {
        let coordinator = coordinator_with_usdc().await;

        let settled = coordinator
            .initiate_swap("initiator".to_string(), request_with_origin(None))
            .await
            .unwrap();
        let preimage = settled.preimage.clone().unwrap();
        coordinator
            .complete_swap(settled.swap_id.clone(), preimage, 100_500)
            .await
            .unwrap();
        let entries = journal_entries(&coordinator, &settled.swap_id);
        assert_eq!(entries.last().unwrap().kind, TransitionKind::Settled);
        assert_eq!(
            entries.last().unwrap().snapshot.status,
            SwapStatus::Completed
        );

        let refundable = coordinator
            .initiate_swap("initiator".to_string(), request_with_origin(None))
            .await
            .unwrap();
        // `initiate_swap` opens the swap at ledger 100_000 with a 24h timeout.
        coordinator
            .refund_swap(refundable.swap_id.clone(), 200_000)
            .await
            .unwrap();
        let entries = journal_entries(&coordinator, &refundable.swap_id);
        assert_eq!(entries.last().unwrap().kind, TransitionKind::Refunded);
        assert_eq!(
            entries.last().unwrap().snapshot.status,
            SwapStatus::Refunded
        );
    }

    #[tokio::test]
    async fn a_failure_is_journalled_once_and_keeps_the_first_reason() {
        let coordinator = coordinator_with_usdc().await;
        let swap_id = coordinator
            .initiate_swap("initiator".to_string(), request_with_origin(None))
            .await
            .unwrap()
            .swap_id;

        let first = SwapFailureReason::ChainActionFailed {
            operation: "lock".to_string(),
            detail: "tx_bad_seq".to_string(),
        };
        assert!(coordinator
            .fail_swap(&swap_id, first, 100_200)
            .await
            .unwrap());
        let second = SwapFailureReason::Abandoned {
            detail: "operator gave up".to_string(),
        };
        assert!(!coordinator
            .fail_swap(&swap_id, second, 100_300)
            .await
            .unwrap());

        let failures: Vec<_> = journal_entries(&coordinator, &swap_id)
            .into_iter()
            .filter(|r| matches!(r.kind, TransitionKind::Failed { .. }))
            .collect();
        assert_eq!(
            failures.len(),
            1,
            "the overwritten reason must not be journalled"
        );
        assert_eq!(
            failures[0].kind,
            TransitionKind::Failed {
                code: "chain_action_failed".to_string()
            }
        );
    }

    #[tokio::test]
    async fn expiry_is_journalled_and_only_after_the_timeout() {
        let coordinator = coordinator_with_usdc().await;
        let swap_id = coordinator
            .initiate_swap("initiator".to_string(), request_with_origin(None))
            .await
            .unwrap()
            .swap_id;

        // Still inside the 24h window: nothing happens.
        assert!(!coordinator.expire_swap(&swap_id, 100_001).await.unwrap());
        assert_eq!(
            coordinator.get_swap(swap_id.clone()).await.unwrap().status,
            SwapStatus::Pending
        );
        assert_eq!(journal_entries(&coordinator, &swap_id).len(), 1);

        assert!(coordinator.expire_swap(&swap_id, 200_000).await.unwrap());
        assert_eq!(
            coordinator.get_swap(swap_id.clone()).await.unwrap().status,
            SwapStatus::Expired
        );
        let entries = journal_entries(&coordinator, &swap_id);
        assert_eq!(entries.last().unwrap().kind, TransitionKind::Expired);
        assert_eq!(entries.last().unwrap().snapshot.status, SwapStatus::Expired);

        // Expiring twice is a no-op, not a second record.
        assert!(!coordinator.expire_swap(&swap_id, 200_001).await.unwrap());
        assert_eq!(journal_entries(&coordinator, &swap_id).len(), 2);
    }

    #[tokio::test]
    async fn recovery_restores_swaps_from_a_durable_journal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.jsonl");

        let (swap_id, hash_lock) = {
            let journal = std::sync::Arc::new(crate::journal::FileJournal::open(&path).unwrap());
            let coordinator =
                AtomicSwapCoordinator::with_journal(SwapConfig::default(), 3, journal);
            coordinator
                .register_asset(AssetInfo::custom(
                    "USDC".to_string(),
                    "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_string(),
                    7,
                ))
                .await
                .unwrap();
            let response = coordinator
                .initiate_swap("initiator".to_string(), request_with_origin(None))
                .await
                .unwrap();
            coordinator
                .record_chain_action_pending(&response.swap_id, "lock", 100_010)
                .await
                .unwrap();
            (response.swap_id, response.hash_lock)
        };

        // A fresh coordinator over the same journal is a restart.
        let journal = std::sync::Arc::new(crate::journal::FileJournal::open(&path).unwrap());
        let restarted = AtomicSwapCoordinator::with_journal(SwapConfig::default(), 3, journal);
        assert_eq!(restarted.recover_from_journal().await.unwrap(), 1);

        let recovered = restarted.get_swap(swap_id.clone()).await.unwrap();
        assert_eq!(recovered.id, swap_id);
        assert_eq!(recovered.hash_lock, hash_lock);
        assert_eq!(recovered.status, SwapStatus::Pending);
        assert_eq!(
            restarted.unresolved_chain_actions().unwrap(),
            vec![UnresolvedAction {
                swap_id,
                operation: "lock".to_string(),
                ledger: 100_010,
            }],
            "the restart must surface the in-flight chain action"
        );
    }

    #[tokio::test]
    async fn recovery_does_not_overwrite_live_state() {
        let coordinator = coordinator_with_usdc().await;
        let swap_id = coordinator
            .initiate_swap("initiator".to_string(), request_with_origin(None))
            .await
            .unwrap()
            .swap_id;

        assert_eq!(coordinator.recover_from_journal().await.unwrap(), 0);
        assert_eq!(
            coordinator.get_swap(swap_id).await.unwrap().status,
            SwapStatus::Pending
        );
    }

    // ---- Timeout boundary for the preimage and refund paths (#396) ----
    //
    // `initiate_swap` opens a swap at ledger 100_000 with a 24h timeout, i.e.
    // `timeout_ledger = 100_000 + 24 * 720 = 117_280`. Rather than hard-code that
    // arithmetic, each test reads the boundary straight off the created swap.

    /// The timeout ledger a just-initiated swap was opened with.
    async fn timeout_ledger_of(coordinator: &AtomicSwapCoordinator, swap_id: &str) -> u32 {
        coordinator
            .get_swap(swap_id.to_string())
            .await
            .expect("swap should exist")
            .timeout_ledger
    }

    /// Preimage path, boundary success: completing at exactly the timeout
    /// ledger reveals the preimage and is recorded as settled.
    #[tokio::test]
    async fn the_preimage_can_be_revealed_at_the_timeout_ledger() {
        let coordinator = coordinator_with_usdc().await;
        let response = coordinator
            .initiate_swap("initiator".to_string(), request_with_origin(None))
            .await
            .unwrap();
        let swap_id = response.swap_id.clone();
        let preimage = response.preimage.clone().unwrap();
        let boundary = timeout_ledger_of(&coordinator, &swap_id).await;

        coordinator
            .complete_swap(swap_id.clone(), preimage.clone(), boundary)
            .await
            .expect("completion at the timeout ledger must succeed");

        let swap = coordinator.get_swap(swap_id.clone()).await.unwrap();
        assert!(swap.is_completed());
        assert_eq!(swap.preimage.as_deref(), Some(preimage.as_str()));
        assert_eq!(swap.completed_at_ledger, Some(boundary));

        let entries = journal_entries(&coordinator, &swap_id);
        assert_eq!(entries.last().unwrap().kind, TransitionKind::Settled);
        assert_eq!(entries.last().unwrap().ledger, boundary);
        assert_eq!(
            entries.last().unwrap().snapshot.status,
            SwapStatus::Completed
        );
    }

    /// Preimage path, boundary failure: one ledger past the timeout, completion
    /// is refused with `SwapExpired` and leaves no partial state behind.
    #[tokio::test]
    async fn the_preimage_path_closes_one_ledger_past_the_timeout() {
        let coordinator = coordinator_with_usdc().await;
        let response = coordinator
            .initiate_swap("initiator".to_string(), request_with_origin(None))
            .await
            .unwrap();
        let swap_id = response.swap_id.clone();
        let preimage = response.preimage.clone().unwrap();
        let boundary = timeout_ledger_of(&coordinator, &swap_id).await;

        let error = coordinator
            .complete_swap(swap_id.clone(), preimage, boundary + 1)
            .await
            .expect_err("completing after the timeout must be refused");
        assert!(matches!(error, AtomicSwapError::SwapExpired { .. }));

        // No partial state: the swap is untouched and nothing was journalled as
        // settled, so a restart cannot pretend it settled (#390, #396).
        let swap = coordinator.get_swap(swap_id.clone()).await.unwrap();
        assert!(swap.is_pending());
        assert!(swap.preimage.is_none());
        let entries = journal_entries(&coordinator, &swap_id);
        assert!(
            !entries.iter().any(|r| r.kind == TransitionKind::Settled),
            "a refused completion must leave no settled record"
        );
    }

    /// Preimage path, failure case: a preimage that does not match the hash lock
    /// is refused without changing state.
    #[tokio::test]
    async fn a_wrong_preimage_is_refused_without_changing_state() {
        let coordinator = coordinator_with_usdc().await;
        let response = coordinator
            .initiate_swap("initiator".to_string(), request_with_origin(None))
            .await
            .unwrap();
        let swap_id = response.swap_id.clone();
        // A well-formed 32-byte preimage that does not hash to the swap's lock.
        let wrong = hex::encode(vec![0u8; 32]);

        let error = coordinator
            .complete_swap(swap_id.clone(), wrong, 100_500)
            .await
            .expect_err("a preimage that does not match the lock must be refused");
        assert!(matches!(error, AtomicSwapError::InvalidPreimage { .. }));

        let swap = coordinator.get_swap(swap_id.clone()).await.unwrap();
        assert!(swap.is_pending());
        assert!(swap.preimage.is_none());
    }

    /// Refund path, boundary failure: refunding at exactly the timeout ledger
    /// is refused with `RefundBeforeTimeout` (the preimage path is still open)
    /// and leaves no partial state.
    #[tokio::test]
    async fn the_refund_path_is_closed_at_the_timeout_ledger() {
        let coordinator = coordinator_with_usdc().await;
        let response = coordinator
            .initiate_swap("initiator".to_string(), request_with_origin(None))
            .await
            .unwrap();
        let swap_id = response.swap_id.clone();
        let boundary = timeout_ledger_of(&coordinator, &swap_id).await;

        let error = coordinator
            .refund_swap(swap_id.clone(), boundary)
            .await
            .expect_err("refunding at the timeout ledger must be refused");
        assert!(matches!(
            error,
            AtomicSwapError::RefundBeforeTimeout {
                timeout_ledger,
                current_ledger,
                swap_id: _,
            } if timeout_ledger == boundary && current_ledger == boundary
        ));

        // No partial state: the swap is still pending, the preimage path is
        // still open at this ledger, and no refund was recorded.
        let swap = coordinator.get_swap(swap_id.clone()).await.unwrap();
        assert!(swap.is_pending());
        assert!(swap.can_complete(boundary));
        let entries = journal_entries(&coordinator, &swap_id);
        assert!(
            !entries.iter().any(|r| r.kind == TransitionKind::Refunded),
            "a refused refund must leave no refunded record"
        );
    }

    /// Refund path, boundary success: refunding one ledger past the timeout
    /// settles the swap as refunded and records it.
    #[tokio::test]
    async fn the_refund_path_opens_one_ledger_past_the_timeout() {
        let coordinator = coordinator_with_usdc().await;
        let response = coordinator
            .initiate_swap("initiator".to_string(), request_with_origin(None))
            .await
            .unwrap();
        let swap_id = response.swap_id.clone();
        let boundary = timeout_ledger_of(&coordinator, &swap_id).await;

        coordinator
            .refund_swap(swap_id.clone(), boundary + 1)
            .await
            .expect("refunding just past the timeout must succeed");

        let swap = coordinator.get_swap(swap_id.clone()).await.unwrap();
        assert_eq!(swap.status, SwapStatus::Refunded);
        let entries = journal_entries(&coordinator, &swap_id);
        assert_eq!(entries.last().unwrap().kind, TransitionKind::Refunded);
        assert_eq!(entries.last().unwrap().ledger, boundary + 1);
        assert_eq!(
            entries.last().unwrap().snapshot.status,
            SwapStatus::Refunded
        );
    }

    /// Refund path, failure case: a swap that already settled is terminal, so a
    /// later refund is refused (with `SwapExpired`, the pre-existing error for an
    /// already-terminal swap) and the completed state is left intact.
    #[tokio::test]
    async fn a_completed_swap_cannot_be_refunded() {
        let coordinator = coordinator_with_usdc().await;
        let response = coordinator
            .initiate_swap("initiator".to_string(), request_with_origin(None))
            .await
            .unwrap();
        let swap_id = response.swap_id.clone();
        let boundary = timeout_ledger_of(&coordinator, &swap_id).await;

        coordinator
            .complete_swap(
                swap_id.clone(),
                response.preimage.clone().unwrap(),
                boundary,
            )
            .await
            .unwrap();

        let error = coordinator
            .refund_swap(swap_id.clone(), boundary + 1)
            .await
            .expect_err("a completed swap cannot be refunded");
        assert!(matches!(error, AtomicSwapError::SwapExpired { .. }));

        // The completed state is intact; no refund record was appended.
        let swap = coordinator.get_swap(swap_id.clone()).await.unwrap();
        assert!(swap.is_completed());
        let entries = journal_entries(&coordinator, &swap_id);
        assert_eq!(entries.last().unwrap().kind, TransitionKind::Settled);
    }

    /// Restart recovery preserves the timeout boundary: a swap restored from a
    /// durable journal keeps its original timeout ledger, so the preimage path
    /// is still open at the boundary and the refund path still closed, exactly
    /// as before the restart (#390, #396).
    #[tokio::test]
    async fn recovery_preserves_the_timeout_boundary_for_both_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boundary-journal.jsonl");

        let (swap_id, preimage, boundary) = {
            let journal = std::sync::Arc::new(crate::journal::FileJournal::open(&path).unwrap());
            let coordinator =
                AtomicSwapCoordinator::with_journal(SwapConfig::default(), 3, journal);
            coordinator
                .register_asset(AssetInfo::custom(
                    "USDC".to_string(),
                    "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4ZLLFLA5".to_string(),
                    7,
                ))
                .await
                .unwrap();
            let response = coordinator
                .initiate_swap("initiator".to_string(), request_with_origin(None))
                .await
                .unwrap();
            (
                response.swap_id,
                response.preimage.unwrap(),
                response.timeout_ledger,
            )
        };

        // A fresh coordinator over the same journal is a restart.
        let journal = std::sync::Arc::new(crate::journal::FileJournal::open(&path).unwrap());
        let restarted = AtomicSwapCoordinator::with_journal(SwapConfig::default(), 3, journal);
        assert_eq!(restarted.recover_from_journal().await.unwrap(), 1);

        let recovered = restarted.get_swap(swap_id.clone()).await.unwrap();
        assert_eq!(recovered.status, SwapStatus::Pending);
        assert_eq!(recovered.timeout_ledger, boundary);

        // The boundary is unchanged: settle at `boundary`, refund only after it.
        assert!(recovered.can_complete(boundary));
        assert!(!recovered.can_refund(boundary));
        assert!(!recovered.can_complete(boundary + 1));
        assert!(recovered.can_refund(boundary + 1));

        // The recovered swap can actually be settled at the boundary.
        restarted
            .complete_swap(swap_id.clone(), preimage, boundary)
            .await
            .expect("the recovered swap can still settle at the timeout ledger");
        let settled = restarted.get_swap(swap_id).await.unwrap();
        assert!(settled.is_completed());
    }
}

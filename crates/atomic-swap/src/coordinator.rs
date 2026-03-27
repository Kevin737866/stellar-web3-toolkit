use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;
use crate::asset::{Asset, AssetRegistry, AssetInfo};
use crate::preimage::{Preimage, PreimageManager};
use crate::swap::{AtomicSwap, SwapStatus, SwapTemplate};
use crate::monitor::{SwapMonitor, MonitoringConfig, SwapEvent};
use crate::error::{AtomicSwapError, Result};

#[derive(Debug, Clone)]
pub struct SwapRequest {
    pub participant: String,
    pub initiator_asset: Asset,
    pub participant_asset: Asset,
    pub initiator_amount: i128,
    pub participant_amount: i128,
    pub timeout_hours: u32,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct SwapResponse {
    pub swap_id: String,
    pub hash_lock: String,
    pub preimage: Option<String>, // Only provided to initiator
    pub timeout_ledger: u32,
    pub contract_address: Option<String>,
}

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

pub struct AtomicSwapCoordinator {
    swaps: Arc<RwLock<HashMap<String, AtomicSwap>>>,
    templates: Arc<RwLock<HashMap<String, SwapTemplate>>>,
    asset_registry: Arc<RwLock<AssetRegistry>>,
    preimage_manager: Arc<RwLock<PreimageManager>>,
    monitor: SwapMonitor,
    config: SwapConfig,
}

impl AtomicSwapCoordinator {
    pub fn new(config: SwapConfig) -> Self {
        let monitor_config = MonitoringConfig::default();
        let monitor = SwapMonitor::new(monitor_config);
        
        Self {
            swaps: Arc::new(RwLock::new(HashMap::new())),
            templates: Arc::new(RwLock::new(HashMap::new())),
            asset_registry: Arc::new(RwLock::new(AssetRegistry::new())),
            preimage_manager: Arc::new(RwLock::new(PreimageManager::new())),
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

        info!("Initiated swap {} between {} and {}", swap_id, initiator, request.participant);

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
        let swap = swaps.get(&swap_id)
            .ok_or_else(|| AtomicSwapError::SwapNotFound { swap_id: swap_id.clone() })?;

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
        let swap = swaps.get_mut(&swap_id)
            .ok_or_else(|| AtomicSwapError::SwapNotFound { swap_id: swap_id.clone() })?;

        // Verify swap can be completed
        if !swap.can_complete(current_ledger) {
            return if swap.is_expired(current_ledger) {
                Err(AtomicSwapError::SwapExpired { swap_id })
            } else {
                Err(AtomicSwapError::SwapAlreadyCompleted { swap_id })
            };
        }

        // Verify preimage hash
        let preimage_bytes = hex::decode(&preimage)
            .map_err(|_| AtomicSwapError::InvalidPreimage { swap_id: swap_id.clone() })?;
        
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
    pub async fn refund_swap(
        &self,
        swap_id: String,
        current_ledger: u32,
    ) -> Result<()> {
        let mut swaps = self.swaps.write().await;
        let swap = swaps.get_mut(&swap_id)
            .ok_or_else(|| AtomicSwapError::SwapNotFound { swap_id: swap_id.clone() })?;

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
                "Multi-hop swaps are disabled".to_string()
            ));
        }

        // Find intermediary assets (simplified - in real implementation, use path finding)
        let intermediary_assets = self.find_intermediary_path(&initiator_asset, &participant_asset).await?;
        
        if intermediary_assets.is_empty() {
            // Direct swap if no intermediary needed
            let request = SwapRequest {
                participant,
                initiator_asset: initiator_asset.clone(),
                participant_asset: participant_asset.clone(),
                initiator_amount,
                participant_amount,
                timeout_hours,
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
            let next_participant = if is_last_hop { participant.clone() } else { format!("hop_{}", i) };
            let next_asset = if is_last_hop { participant_asset.clone() } else { intermediary_asset.clone() };
            
            // Calculate exchange rate (simplified)
            let next_amount = self.calculate_exchange_amount(current_amount, &current_asset, &next_asset).await?;

            let request = SwapRequest {
                participant: next_participant.clone(),
                initiator_asset: current_asset.clone(),
                participant_asset: next_asset.clone(),
                initiator_amount: current_amount,
                participant_amount: next_amount,
                timeout_hours,
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("hop_index".to_string(), i.to_string());
                    meta.insert("total_hops".to_string(), intermediary_assets.len().to_string());
                    if is_last_hop {
                        meta.insert("final_destination".to_string(), participant);
                    }
                    meta
                },
            };

            let response = self.initiate_swap(current_initiator.clone(), request).await?;
            responses.push(response);

            current_initiator = next_participant;
            current_amount = next_amount;
            current_asset = next_asset;
        }

        Ok(responses)
    }

    /// Get swap information
    pub async fn get_swap(&self, swap_id: String) -> Result<AtomicSwap> {
        let swaps = self.swaps.read().await;
        swaps.get(&swap_id)
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
        let asset_registry = self.asset_registry.read().await;
        
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
        
        let request = SwapRequest {
            participant: "participant".to_string(),
            initiator_asset: Asset::XLM,
            participant_asset: Asset::Custom("USDC".to_string()),
            initiator_amount: 1000,
            participant_amount: 500,
            timeout_hours: 24,
            metadata: HashMap::new(),
        };

        let response = coordinator.initiate_swap("initiator".to_string(), request).await.unwrap();
        assert!(!response.swap_id.is_empty());
        assert!(!response.hash_lock.is_empty());
        assert!(response.preimage.is_some());
    }

    #[tokio::test]
    async fn test_swap_completion() {
        let config = SwapConfig::default();
        let coordinator = AtomicSwapCoordinator::new(config);
        
        // First initiate a swap
        let request = SwapRequest {
            participant: "participant".to_string(),
            initiator_asset: Asset::XLM,
            participant_asset: Asset::Custom("USDC".to_string()),
            initiator_amount: 1000,
            participant_amount: 500,
            timeout_hours: 24,
            metadata: HashMap::new(),
        };

        let response = coordinator.initiate_swap("initiator".to_string(), request).await.unwrap();
        let preimage = response.preimage.unwrap();

        // Complete the swap
        coordinator.complete_swap(response.swap_id, preimage, 101000).await.unwrap();

        // Verify swap is completed
        let swap = coordinator.get_swap(response.swap_id).await.unwrap();
        assert!(swap.is_completed());
    }
}

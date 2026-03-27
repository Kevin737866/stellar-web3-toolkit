use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;
use crate::swap::{AtomicSwap, SwapStatus};
use crate::error::{AtomicSwapError, Result};

#[derive(Debug, Clone)]
pub enum SwapEvent {
    Created { swap_id: String, timestamp: u64 },
    Completed { swap_id: String, timestamp: u64 },
    Refunded { swap_id: String, timestamp: u64 },
    Expired { swap_id: String, timestamp: u64 },
    Failed { swap_id: String, error: String, timestamp: u64 },
    TimeoutWarning { swap_id: String, time_remaining: Duration, timestamp: u64 },
}

#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    pub check_interval: Duration,
    pub timeout_warning_threshold: Duration,
    pub max_retries: u32,
    pub enable_auto_refund: bool,
    pub enable_timeout_warnings: bool,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(30),
            timeout_warning_threshold: Duration::from_secs(3600), // 1 hour
            max_retries: 3,
            enable_auto_refund: false,
            enable_timeout_warnings: true,
        }
    }
}

pub type EventHandler = Arc<dyn Fn(SwapEvent) + Send + Sync>;

#[derive(Clone)]
pub struct SwapMonitor {
    swaps: Arc<RwLock<HashMap<String, AtomicSwap>>>,
    event_handlers: Arc<RwLock<Vec<EventHandler>>>,
    config: MonitoringConfig,
    current_ledger: Arc<RwLock<u32>>,
}

impl SwapMonitor {
    pub fn new(config: MonitoringConfig) -> Self {
        Self {
            swaps: Arc::new(RwLock::new(HashMap::new())),
            event_handlers: Arc::new(RwLock::new(Vec::new())),
            config,
            current_ledger: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn add_swap(&self, swap: AtomicSwap) -> Result<()> {
        let mut swaps = self.swaps.write().await;
        swaps.insert(swap.id.clone(), swap);
        
        // Emit creation event
        let event = SwapEvent::Created {
            swap_id: swap.id,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        self.emit_event(event).await;
        
        Ok(())
    }

    pub async fn remove_swap(&self, swap_id: &str) -> Result<()> {
        let mut swaps = self.swaps.write().await;
        swaps.remove(swap_id);
        Ok(())
    }

    pub async fn get_swap(&self, swap_id: &str) -> Option<AtomicSwap> {
        let swaps = self.swaps.read().await;
        swaps.get(swap_id).cloned()
    }

    pub async fn list_swaps(&self) -> Vec<AtomicSwap> {
        let swaps = self.swaps.read().await;
        swaps.values().cloned().collect()
    }

    pub async fn list_pending_swaps(&self) -> Vec<AtomicSwap> {
        let swaps = self.swaps.read().await;
        swaps
            .values()
            .filter(|swap| swap.is_pending())
            .cloned()
            .collect()
    }

    pub async fn update_ledger(&self, ledger: u32) {
        let mut current_ledger = self.current_ledger.write().await;
        *current_ledger = ledger;
    }

    pub async fn add_event_handler<F>(&self, handler: F)
    where
        F: Fn(SwapEvent) + Send + Sync + 'static,
    {
        let mut handlers = self.event_handlers.write().await;
        handlers.push(Arc::new(handler));
    }

    pub async fn start_monitoring(&self) -> Result<()> {
        info!("Starting swap monitoring service");
        
        let monitor = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(monitor.config.check_interval);
            
            loop {
                interval.tick().await;
                if let Err(e) = monitor.check_swaps().await {
                    error!("Error during swap monitoring: {}", e);
                }
            }
        });

        Ok(())
    }

    async fn check_swaps(&self) -> Result<()> {
        let current_ledger = *self.current_ledger.read().await;
        let mut swaps = self.swaps.write().await;
        let mut swaps_to_update = Vec::new();

        for (swap_id, swap) in swaps.iter_mut() {
            if !swap.is_pending() {
                continue;
            }

            // Check for timeout
            if current_ledger > swap.timeout_ledger {
                warn!("Swap {} has expired at ledger {}", swap_id, current_ledger);
                swap.mark_expired();
                
                let event = SwapEvent::Expired {
                    swap_id: swap_id.clone(),
                    timestamp: chrono::Utc::now().timestamp() as u64,
                };
                swaps_to_update.push((swap_id.clone(), event));
                
                // Auto-refund if enabled
                if self.config.enable_auto_refund {
                    info!("Auto-refunding expired swap: {}", swap_id);
                    swap.mark_refunded();
                    
                    let refund_event = SwapEvent::Refunded {
                        swap_id: swap_id.clone(),
                        timestamp: chrono::Utc::now().timestamp() as u64,
                    };
                    swaps_to_update.push((swap_id.clone(), refund_event));
                }
            }
            // Check for timeout warnings
            else if self.config.enable_timeout_warnings {
                let ledgers_remaining = swap.timeout_ledger - current_ledger;
                let time_remaining = Duration::from_secs(ledgers_remaining as u64 * 5); // ~5 seconds per ledger
                
                if time_remaining <= self.config.timeout_warning_threshold {
                    warn!("Swap {} approaching timeout: {} remaining", swap_id, time_remaining.as_secs());
                    
                    let event = SwapEvent::TimeoutWarning {
                        swap_id: swap_id.clone(),
                        time_remaining,
                        timestamp: chrono::Utc::now().timestamp() as u64,
                    };
                    swaps_to_update.push((swap_id.clone(), event));
                }
            }
        }

        // Emit all events
        for (_, event) in swaps_to_update {
            self.emit_event(event).await;
        }

        Ok(())
    }

    async fn emit_event(&self, event: SwapEvent) {
        let handlers = self.event_handlers.read().await;
        for handler in handlers.iter() {
            handler(event.clone());
        }
    }

    pub async fn get_statistics(&self) -> MonitoringStats {
        let swaps = self.swaps.read().await;
        let mut stats = MonitoringStats::default();
        
        for swap in swaps.values() {
            stats.total_swaps += 1;
            match swap.status {
                SwapStatus::Pending => stats.pending_swaps += 1,
                SwapStatus::Completed => stats.completed_swaps += 1,
                SwapStatus::Refunded => stats.refunded_swaps += 1,
                SwapStatus::Expired => stats.expired_swaps += 1,
                SwapStatus::Failed => stats.failed_swaps += 1,
            }
        }
        
        stats
    }

    pub async fn generate_report(&self) -> MonitoringReport {
        let stats = self.get_statistics().await;
        let swaps = self.swaps.read().await;
        let current_ledger = *self.current_ledger.read().await;
        
        let mut expiring_soon = Vec::new();
        let mut failed_swaps = Vec::new();
        
        for swap in swaps.values() {
            if swap.is_pending() {
                let ledgers_remaining = swap.timeout_ledger - current_ledger;
                if ledgers_remaining < 1000 { // Within ~5000 seconds
                    expiring_soon.push(swap.clone());
                }
            } else if matches!(swap.status, SwapStatus::Failed) {
                failed_swaps.push(swap.clone());
            }
        }
        
        MonitoringReport {
            stats,
            current_ledger,
            expiring_soon,
            failed_swaps,
            generated_at: chrono::Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MonitoringStats {
    pub total_swaps: u64,
    pub pending_swaps: u64,
    pub completed_swaps: u64,
    pub refunded_swaps: u64,
    pub expired_swaps: u64,
    pub failed_swaps: u64,
}

#[derive(Debug, Clone)]
pub struct MonitoringReport {
    pub stats: MonitoringStats,
    pub current_ledger: u32,
    pub expiring_soon: Vec<AtomicSwap>,
    pub failed_swaps: Vec<AtomicSwap>,
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

impl MonitoringReport {
    pub fn success_rate(&self) -> f64 {
        if self.stats.total_swaps == 0 {
            0.0
        } else {
            (self.stats.completed_swaps as f64 / self.stats.total_swaps as f64) * 100.0
        }
    }

    pub fn completion_rate(&self) -> f64 {
        let completed = self.stats.completed_swaps + self.stats.refunded_swaps;
        if self.stats.total_swaps == 0 {
            0.0
        } else {
            (completed as f64 / self.stats.total_swaps as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::Asset;

    #[tokio::test]
    async fn test_swap_monitor() {
        let config = MonitoringConfig::default();
        let monitor = SwapMonitor::new(config);
        
        let swap = AtomicSwap::new(
            "test_swap".to_string(),
            "initiator".to_string(),
            "participant".to_string(),
            Asset::XLM,
            Asset::Custom("USDC".to_string()),
            1000,
            500,
            "hash123".to_string(),
            10000,
            1000,
        );
        
        monitor.add_swap(swap.clone()).await.unwrap();
        
        let retrieved = monitor.get_swap("test_swap").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, "test_swap");
        
        let pending = monitor.list_pending_swaps().await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "test_swap");
    }

    #[tokio::test]
    async fn test_monitoring_stats() {
        let config = MonitoringConfig::default();
        let monitor = SwapMonitor::new(config);
        
        // Add some test swaps
        for i in 0..5 {
            let mut swap = AtomicSwap::new(
                format!("swap_{}", i),
                "initiator".to_string(),
                "participant".to_string(),
                Asset::XLM,
                Asset::Custom("USDC".to_string()),
                1000,
                500,
                "hash123".to_string(),
                10000,
                1000,
            );
            
            // Set different statuses
            match i {
                0 => swap.mark_completed("preimage".to_string(), 2000),
                1 => swap.mark_refunded(),
                2 => swap.mark_expired(),
                3 => swap.mark_failed(),
                _ => {} // Keep one pending
            }
            
            monitor.add_swap(swap).await.unwrap();
        }
        
        let stats = monitor.get_statistics().await;
        assert_eq!(stats.total_swaps, 5);
        assert_eq!(stats.completed_swaps, 1);
        assert_eq!(stats.refunded_swaps, 1);
        assert_eq!(stats.expired_swaps, 1);
        assert_eq!(stats.failed_swaps, 1);
        assert_eq!(stats.pending_swaps, 1);
    }
}

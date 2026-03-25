//! # Watchtower Service
//! 
//! A service that monitors Stellar payment channels for suspicious activity
//! and can respond to channel breach attempts by publishing justice
//! transactions on behalf of channel participants.
//!
//! ## Features
//! - Continuous monitoring of subscribed channels
//! - Detection of breach attempts (old state publication)
//! - HTLC timeout monitoring and refund triggering
//! - Automated justice transaction submission
//! - Alert notification system

pub mod monitor;
pub mod scanner;
pub mod justice;
pub mod storage;

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{info, warn, error};

/// Watchtower configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchtowerConfig {
    /// RPC endpoint for Stellar
    pub stellar_rpc_url: String,
    /// Network passphrase
    pub network_passphrase: String,
    /// How often to scan for updates (in seconds)
    pub scan_interval_secs: u64,
    /// Maximum HTLC timeout to monitor (in blocks)
    pub max_htlc_timeout: u32,
    /// Minimum stake required to monitor channels
    pub min_stake: i128,
    /// Whether to auto-submit justice transactions
    pub auto_justice: bool,
    /// Justice transaction fee budget
    pub justice_fee_budget: i128,
    /// Database path for persistent storage
    pub db_path: Option<String>,
    /// Alert webhook URL
    pub alert_webhook_url: Option<String>,
}

impl Default for WatchtowerConfig {
    fn default() -> Self {
        WatchtowerConfig {
            stellar_rpc_url: "https://horizon.stellar.org".to_string(),
            network_passphrase: "Public Global Stellar Network ; September 2015".to_string(),
            scan_interval_secs: 60,
            max_htlc_timeout: 2016, // ~2 weeks
            min_stake: 0,
            auto_justice: true,
            justice_fee_budget: 100_000, // 0.1 XLM
            db_path: None,
            alert_webhook_url: None,
        }
    }
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertSeverity {
    /// Low priority alert
    Info,
    /// Warning alert
    Warning,
    /// Critical alert requiring immediate action
    Critical,
}

/// Alert type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertType {
    /// Breach attempt detected
    BreachAttempt {
        channel_id: String,
        old_sequence: u32,
        new_sequence: u32,
    },
    /// HTLC timeout approaching
    HtlcTimeoutWarning {
        channel_id: String,
        htlc_id: String,
        blocks_remaining: u32,
    },
    /// Justice transaction submitted
    JusticeSubmitted {
        channel_id: String,
        tx_hash: String,
    },
    /// Channel closed unexpectedly
    UnexpectedClose {
        channel_id: String,
        reason: String,
    },
    /// Watchtower health check failed
    HealthCheckFailed {
        component: String,
        error: String,
    },
}

/// Alert message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Unique alert ID
    pub id: String,
    /// Alert type and details
    pub alert_type: AlertType,
    /// Severity level
    pub severity: AlertSeverity,
    /// When the alert was created
    pub timestamp: u64,
    /// Additional context
    pub context: serde_json::Value,
}

impl Alert {
    /// Create a new breach attempt alert
    pub fn breach_attempt(
        channel_id: String,
        old_sequence: u32,
        new_sequence: u32,
    ) -> Self {
        Alert {
            id: uuid_v4(),
            alert_type: AlertType::BreachAttempt {
                channel_id,
                old_sequence,
                new_sequence,
            },
            severity: AlertSeverity::Critical,
            timestamp: current_timestamp(),
            context: serde_json::json!({}),
        }
    }
    
    /// Create an HTLC timeout warning
    pub fn htlc_timeout_warning(
        channel_id: String,
        htlc_id: String,
        blocks_remaining: u32,
    ) -> Self {
        Alert {
            id: uuid_v4(),
            alert_type: AlertType::HtlcTimeoutWarning {
                channel_id,
                htlc_id,
                blocks_remaining,
            },
            severity: if blocks_remaining < 144 {
                AlertSeverity::Critical
            } else {
                AlertSeverity::Warning
            },
            timestamp: current_timestamp(),
            context: serde_json::json!({}),
        }
    }
    
    /// Create a justice submitted alert
    pub fn justice_submitted(channel_id: String, tx_hash: String) -> Self {
        Alert {
            id: uuid_v4(),
            alert_type: AlertType::JusticeSubmitted { channel_id, tx_hash },
            severity: AlertSeverity::Info,
            timestamp: current_timestamp(),
            context: serde_json::json!({}),
        }
    }
    
    /// Get the message body for this alert
    pub fn message(&self) -> String {
        match &self.alert_type {
            AlertType::BreachAttempt { channel_id, old_sequence, new_sequence } => {
                format!(
                    "BREACH ATTEMPT DETECTED on channel {}! Old seq: {}, New seq: {}",
                    channel_id, old_sequence, new_sequence
                )
            }
            AlertType::HtlcTimeoutWarning { channel_id, htlc_id, blocks_remaining } => {
                format!(
                    "HTLC {} in channel {} will timeout in {} blocks",
                    htlc_id, channel_id, blocks_remaining
                )
            }
            AlertType::JusticeSubmitted { channel_id, tx_hash } => {
                format!(
                    "Justice transaction submitted for channel {}. Tx: {}",
                    channel_id, tx_hash
                )
            }
            AlertType::UnexpectedClose { channel_id, reason } => {
                format!("Channel {} closed unexpectedly: {}", channel_id, reason)
            }
            AlertType::HealthCheckFailed { component, error } => {
                format!("Health check failed for {}: {}", component, error)
            }
        }
    }
}

/// Watchtower state
pub struct WatchtowerState {
    /// Subscribed channel IDs
    pub subscribed_channels: RwLock<std::collections::HashSet<String>>,
    /// Known channel states (for breach detection)
    pub channel_states: RwLock<std::collections::HashMap<String, monitor::ChannelMonitorState>>,
    /// Recent alerts
    pub recent_alerts: RwLock<Vec<Alert>>,
    /// Whether the watchtower is running
    pub is_running: RwLock<bool>,
    /// Statistics
    pub stats: RwLock<WatchtowerStats>,
}

/// Watchtower statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WatchtowerStats {
    /// Total channels monitored
    pub channels_monitored: u64,
    /// Total breach attempts detected
    pub breach_attempts_detected: u64,
    /// Total justice transactions submitted
    pub justice_txs_submitted: u64,
    /// Total alerts generated
    pub alerts_generated: u64,
    /// Last scan timestamp
    pub last_scan_ts: u64,
    /// Uptime in seconds
    pub uptime_secs: u64,
}

/// Watchtower service
pub struct Watchtower {
    /// Configuration
    config: WatchtowerConfig,
    /// State
    state: Arc<WatchtowerState>,
    /// Channel monitor
    monitor: monitor::ChannelMonitor,
    /// Justice service
    justice: justice::JusticeService,
    /// Storage backend
    storage: Arc<dyn storage::StorageBackend>,
}

impl Watchtower {
    /// Create a new watchtower with the given configuration
    pub fn new(config: WatchtowerConfig) -> Result<Self, WatchtowerError> {
        let storage: Arc<dyn storage::StorageBackend> = match &config.db_path {
            Some(path) => Arc::new(storage::SqliteStorage::new(path)?),
            None => Arc::new(storage::InMemoryStorage::new()),
        };
        
        let monitor = monitor::ChannelMonitor::new(
            config.stellar_rpc_url.clone(),
            config.network_passphrase.clone(),
        );
        
        let justice = justice::JusticeService::new(
            config.stellar_rpc_url.clone(),
            config.network_passphrase.clone(),
            config.justice_fee_budget,
        );
        
        let state = Arc::new(WatchtowerState {
            subscribed_channels: RwLock::new(std::collections::HashSet::new()),
            channel_states: RwLock::new(std::collections::HashMap::new()),
            recent_alerts: RwLock::new(Vec::new()),
            is_running: RwLock::new(false),
            stats: RwLock::new(WatchtowerStats::default()),
        });
        
        Ok(Watchtower {
            config,
            state,
            monitor,
            justice,
            storage,
        })
    }
    
    /// Start the watchtower service
    pub async fn start(&self) -> Result<(), WatchtowerError> {
        *self.state.is_running.write() = true;
        
        info!("Watchtower service started");
        
        // Start the monitoring loop
        let state = Arc::clone(&self.state);
        let config = self.config.clone();
        let monitor = self.monitor.clone();
        let justice = self.justice.clone();
        
        tokio::spawn(async move {
            loop {
                if !*state.is_running.read() {
                    break;
                }
                
                // Scan subscribed channels
                let channels: Vec<String> = state.subscribed_channels.read().iter().cloned().collect();
                
                for channel_id in channels {
                    match monitor.check_channel(&channel_id).await {
                        Ok(Some(update)) => {
                            // Check for breach attempt
                            if let Some(breach) = monitor.detect_breach(&channel_id, &update) {
                                warn!("Breach attempt detected on channel {}", channel_id);
                                
                                // Generate alert
                                let alert = Alert::breach_attempt(
                                    channel_id.clone(),
                                    breach.old_sequence,
                                    breach.new_sequence,
                                );
                                state.add_alert(alert);
                                
                                // Submit justice if enabled
                                if config.auto_justice {
                                    if let Err(e) = justice.submit_justice(&breach).await {
                                        error!("Failed to submit justice: {:?}", e);
                                    }
                                }
                            }
                            
                            // Update stored state
                            state.update_channel_state(&channel_id, update);
                        }
                        Ok(None) => {
                            // Channel closed or not found
                            info!("Channel {} no longer exists", channel_id);
                            state.remove_channel(&channel_id);
                        }
                        Err(e) => {
                            error!("Error checking channel {}: {:?}", channel_id, e);
                        }
                    }
                }
                
                // Update stats
                {
                    let mut stats = state.stats.write();
                    stats.last_scan_ts = current_timestamp();
                    stats.channels_monitored = state.subscribed_channels.read().len() as u64;
                }
                
                tokio::time::sleep(tokio::time::Duration::from_secs(config.scan_interval_secs)).await;
            }
        });
        
        Ok(())
    }
    
    /// Stop the watchtower service
    pub fn stop(&self) {
        *self.state.is_running.write() = false;
        info!("Watchtower service stopped");
    }
    
    /// Subscribe to monitor a channel
    pub fn subscribe(&self, channel_id: String) -> Result<(), WatchtowerError> {
        self.state.subscribed_channels.write().insert(channel_id.clone());
        
        // Initialize monitoring state
        let monitor_state = monitor::ChannelMonitorState {
            channel_id: channel_id.clone(),
            last_known_sequence: 0,
            last_update_ts: current_timestamp(),
            is_closed: false,
            pending_htlcs: Vec::new(),
        };
        
        self.state.channel_states.write().insert(channel_id, monitor_state);
        
        info!("Subscribed to channel");
        Ok(())
    }
    
    /// Unsubscribe from a channel
    pub fn unsubscribe(&self, channel_id: &str) {
        self.state.subscribed_channels.write().remove(channel_id);
        self.state.channel_states.write().remove(channel_id);
        info!("Unsubscribed from channel");
    }
    
    /// Get current watchtower status
    pub fn status(&self) -> WatchtowerStatus {
        let stats = self.state.stats.read();
        let alerts = self.state.recent_alerts.read();
        
        WatchtowerStatus {
            is_running: *self.state.is_running.read(),
            channels_monitored: self.state.subscribed_channels.read().len() as u64,
            breach_attempts_detected: stats.breach_attempts_detected,
            justice_txs_submitted: stats.justice_txs_submitted,
            recent_alerts_count: alerts.len(),
        }
    }
    
    /// Get recent alerts
    pub fn get_alerts(&self, limit: usize) -> Vec<Alert> {
        self.state.recent_alerts.read()
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
}

impl WatchtowerState {
    /// Add an alert to the recent alerts list
    pub fn add_alert(&self, alert: Alert) {
        let mut alerts = self.recent_alerts.write();
        alerts.push(alert);
        
        // Keep only last 1000 alerts
        if alerts.len() > 1000 {
            alerts.drain(0..500);
        }
    }
    
    /// Update channel state
    pub fn update_channel_state(&self, channel_id: &str, update: monitor::ChannelUpdate) {
        let mut states = self.channel_states.write();
        if let Some(state) = states.get_mut(channel_id) {
            state.last_known_sequence = update.sequence_number;
            state.last_update_ts = current_timestamp();
        }
    }
    
    /// Remove a channel
    pub fn remove_channel(&self, channel_id: &str) {
        let mut states = self.channel_states.write();
        if let Some(state) = states.get_mut(channel_id) {
            state.is_closed = true;
        }
    }
}

/// Watchtower status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchtowerStatus {
    pub is_running: bool,
    pub channels_monitored: u64,
    pub breach_attempts_detected: u64,
    pub justice_txs_submitted: u64,
    pub recent_alerts_count: usize,
}

/// Errors that can occur in the watchtower
#[derive(Error, Debug)]
pub enum WatchtowerError {
    #[error("Failed to connect to Stellar network: {0}")]
    NetworkError(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Invalid channel: {0}")]
    InvalidChannel(String),
    
    #[error("Justice transaction failed: {0}")]
    JusticeFailed(String),
    
    #[error("Watchtower not running")]
    NotRunning,
}

/// Generate a UUID v4
fn uuid_v4() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        (bytes[6] & 0x0f) | 0x40, bytes[7],
        (bytes[8] & 0x3f) | 0x80, bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

/// Get current Unix timestamp
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
    fn test_watchtower_config() {
        let config = WatchtowerConfig::default();
        assert_eq!(config.scan_interval_secs, 60);
        assert!(config.auto_justice);
    }
    
    #[test]
    fn test_alert_message() {
        let alert = Alert::breach_attempt(
            "channel123".to_string(),
            1,
            5,
        );
        assert!(alert.message().contains("BREACH"));
    }
}

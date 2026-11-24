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
//! - Retry of transient storage failures without duplicate actions

pub mod justice;
pub mod monitor;
pub mod storage;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tracing::{error, info, warn};

/// Retry policy for transient watchtower storage failures.
///
/// Retries are only attempted for errors classified as transient by
/// [`WatchtowerError::is_transient`]. Each retry reuses the same idempotency
/// key so that a write which actually landed before the error was reported is
/// not applied twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageRetryPolicy {
    /// Maximum number of attempts, including the first. Must be at least 1.
    pub max_attempts: u32,
    /// Backoff before the second attempt, in milliseconds. Doubles each retry.
    pub initial_backoff_ms: u64,
    /// Upper bound on any single backoff, in milliseconds.
    pub max_backoff_ms: u64,
}

impl Default for StorageRetryPolicy {
    fn default() -> Self {
        StorageRetryPolicy {
            max_attempts: 3,
            initial_backoff_ms: 50,
            max_backoff_ms: 1_000,
        }
    }
}

impl StorageRetryPolicy {
    /// Validate the policy, rejecting values that would silently misbehave.
    pub fn validate(&self) -> Result<(), WatchtowerError> {
        if self.max_attempts == 0 {
            return Err(WatchtowerError::InvalidConfig(
                "storage retry max_attempts must be at least 1".to_string(),
            ));
        }
        if self.max_backoff_ms < self.initial_backoff_ms {
            return Err(WatchtowerError::InvalidConfig(format!(
                "storage retry max_backoff_ms ({}) must be >= initial_backoff_ms ({})",
                self.max_backoff_ms, self.initial_backoff_ms
            )));
        }
        Ok(())
    }

    /// Backoff to sleep before retry number `retry` (1-based).
    pub fn backoff_for(&self, retry: u32) -> std::time::Duration {
        let shift = retry.saturating_sub(1).min(63);
        let ms = self
            .initial_backoff_ms
            .saturating_mul(1u64.checked_shl(shift).unwrap_or(u64::MAX))
            .min(self.max_backoff_ms);
        std::time::Duration::from_millis(ms)
    }
}

/// Run a storage operation with retries for transient failures.
///
/// The closure is invoked once per attempt and must be idempotent (keyed by a
/// stable identifier) so that retrying after an ambiguous failure cannot
/// produce duplicate durable actions. Non-transient errors are returned
/// immediately without retrying.
pub fn retry_storage<T, F>(policy: &StorageRetryPolicy, mut op: F) -> Result<T, WatchtowerError>
where
    F: FnMut() -> Result<T, WatchtowerError>,
{
    policy.validate()?;
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match op() {
            Ok(value) => return Ok(value),
            Err(err) => {
                if !err.is_transient() || attempt >= policy.max_attempts {
                    return Err(err);
                }
                let backoff = policy.backoff_for(attempt);
                warn!(
                    attempt,
                    max_attempts = policy.max_attempts,
                    ?backoff,
                    error = %err,
                    "transient storage failure, retrying with same idempotency key"
                );
                std::thread::sleep(backoff);
            }
        }
    }
}

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
    /// Retention rules applied when the store is compacted
    #[serde(default)]
    pub compaction: storage::CompactionPolicy,
    /// How often to compact storage, in seconds. Zero disables the automatic
    /// pass, leaving [`Watchtower::compact_storage`] as the only entry point.
    #[serde(default = "default_compaction_interval_secs")]
    pub compaction_interval_secs: u64,
    /// Retry policy for transient storage failures. Defaults preserve the
    /// previous single-attempt behavior only when `max_attempts` is 1.
    #[serde(default)]
    pub storage_retry: StorageRetryPolicy,
}

/// Default automatic compaction interval: hourly.
fn default_compaction_interval_secs() -> u64 {
    3_600
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
            compaction: storage::CompactionPolicy::default(),
            compaction_interval_secs: default_compaction_interval_secs(),
            storage_retry: StorageRetryPolicy::default(),
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
    JusticeSubmitted { channel_id: String, tx_hash: String },
    /// Channel closed unexpectedly
    UnexpectedClose { channel_id: String, reason: String },
    /// Watchtower health check failed
    HealthCheckFailed { component: String, error: String },
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
    pub fn breach_attempt(channel_id: String, old_sequence: u32, new_sequence: u32) -> Self {
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
            alert_type: AlertType::JusticeSubmitted {
                channel_id,
                tx_hash,
            },
            severity: AlertSeverity::Info,
            timestamp: current_timestamp(),
            context: serde_json::json!({}),
        }
    }

    /// Get the message body for this alert
    pub fn message(&self) -> String {
        match &self.alert_type {
            AlertType::BreachAttempt {
                channel_id,
                old_sequence,
                new_sequence,
            } => {
                format!(
                    "BREACH ATTEMPT DETECTED on channel {channel_id}! Old seq: {old_sequence}, New seq: {new_sequence}"
                )
            }
            AlertType::HtlcTimeoutWarning {
                channel_id,
                htlc_id,
                blocks_remaining,
            } => {
                format!(
                    "HTLC {htlc_id} in channel {channel_id} will timeout in {blocks_remaining} blocks"
                )
            }
            AlertType::JusticeSubmitted {
                channel_id,
                tx_hash,
            } => {
                format!("Justice transaction submitted for channel {channel_id}. Tx: {tx_hash}")
            }
            AlertType::UnexpectedClose { channel_id, reason } => {
                format!("Channel {channel_id} closed unexpectedly: {reason}")
            }
            AlertType::HealthCheckFailed { component, error } => {
                format!("Health check failed for {component}: {error}")
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
    /// Unix timestamp of the last storage compaction
    pub last_compaction_ts: RwLock<u64>,
    /// Storage backend, shared with the owning [`Watchtower`]
    storage: Arc<dyn storage::StorageBackend>,
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
    /// Total justice actions persisted before submission (issue #368).
    ///
    /// This counter is incremented when a [`justice::JusticeAction`] is
    /// durably stored to the backend. It differs from `justice_txs_submitted`
    /// because a persisted action is not always immediately submitted (e.g. on
    /// a network error the action stays `Pending` and can be retried).
    pub justice_actions_persisted: u64,
    /// Total alerts generated
    pub alerts_generated: u64,
    /// Last scan timestamp
    pub last_scan_ts: u64,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Total storage compaction passes run
    pub compactions_run: u64,
    /// Total records removed by compaction
    pub records_compacted: u64,
    /// Total storage operations that were retried after a transient failure
    pub storage_retries: u64,
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
    /// Persistent storage for subscriptions, channel state and alerts
    storage: Arc<dyn storage::StorageBackend>,
}

impl Watchtower {
    /// Create a new watchtower with the given configuration
    pub fn new(config: WatchtowerConfig) -> Result<Self, WatchtowerError> {
        config.storage_retry.validate()?;

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
            Arc::clone(&storage),
        );

        let state = Arc::new(WatchtowerState {
            subscribed_channels: RwLock::new(std::collections::HashSet::new()),
            channel_states: RwLock::new(std::collections::HashMap::new()),
            recent_alerts: RwLock::new(Vec::new()),
            is_running: RwLock::new(false),
            stats: RwLock::new(WatchtowerStats::default()),
            last_compaction_ts: RwLock::new(current_timestamp()),
            storage: Arc::clone(&storage),
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
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)] // public API; the loop it spawns is what awaits
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
                let channels: Vec<String> =
                    state.subscribed_channels.read().iter().cloned().collect();

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
                                state.add_
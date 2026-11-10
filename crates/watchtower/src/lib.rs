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

pub mod justice;
pub mod monitor;
pub mod storage;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tracing::{error, info, warn};

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
    /// Retention limits for encrypted watchtower channel state blobs (#372)
    #[serde(default)]
    pub encrypted_retention: EncryptedStateRetentionPolicy,
    /// Maximum retry attempts for alert delivery (#373)
    #[serde(default = "default_alert_max_retries")]
    pub alert_max_retries: u32,
}

fn default_alert_max_retries() -> u32 {
    3
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
            encrypted_retention: EncryptedStateRetentionPolicy::default(),
            alert_max_retries: default_alert_max_retries(),
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
                    "BREACH ATTEMPT DETECTED on channel {}! Old seq: {}, New seq: {}",
                    channel_id, old_sequence, new_sequence
                )
            }
            AlertType::HtlcTimeoutWarning {
                channel_id,
                htlc_id,
                blocks_remaining,
            } => {
                format!(
                    "HTLC {} in channel {} will timeout in {} blocks",
                    htlc_id, channel_id, blocks_remaining
                )
            }
            AlertType::JusticeSubmitted {
                channel_id,
                tx_hash,
            } => {
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

/// Retention limits for encrypted watchtower state blobs (#372).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedStateRetentionPolicy {
    /// Maximum encrypted entries retained across channels.
    pub max_entries: usize,
    /// Maximum age in seconds before an encrypted blob expires.
    pub max_age_secs: u64,
    /// Maximum aggregate ciphertext bytes allowed in the store.
    pub max_total_bytes: usize,
}

impl Default for EncryptedStateRetentionPolicy {
    fn default() -> Self {
        EncryptedStateRetentionPolicy {
            max_entries: 10_000,
            max_age_secs: 30 * 24 * 60 * 60,
            max_total_bytes: 64 * 1024 * 1024,
        }
    }
}

impl EncryptedStateRetentionPolicy {
    /// Validate retention bounds explicitly, rejecting unsafe zero limits (#372).
    pub fn validate(&self) -> Result<(), WatchtowerError> {
        if self.max_entries == 0 {
            return Err(WatchtowerError::InvalidRetentionPolicy(
                "max_entries must be greater than zero".to_string(),
            ));
        }
        if self.max_total_bytes == 0 {
            return Err(WatchtowerError::InvalidRetentionPolicy(
                "max_total_bytes must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}

/// Encrypted watchtower blob persisted for a monitored channel (#372).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedChannelBlob {
    pub channel_id: String,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub stored_at: u64,
}

/// Summary of entries pruned while enforcing encrypted state retention (#372).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetentionPruneReport {
    pub evicted_expired: usize,
    pub evicted_overflow: usize,
    pub remaining_entries: usize,
    pub remaining_bytes: usize,
}

/// Bounded in-memory store for encrypted channel recovery blobs (#372).
pub struct EncryptedStateStore {
    policy: EncryptedStateRetentionPolicy,
    entries: RwLock<Vec<EncryptedChannelBlob>>,
}

impl EncryptedStateStore {
    /// Construct a validated encrypted state store (#372).
    pub fn new(policy: EncryptedStateRetentionPolicy) -> Result<Self, WatchtowerError> {
        policy.validate()?;
        Ok(EncryptedStateStore {
            policy,
            entries: RwLock::new(Vec::new()),
        })
    }

    /// Store or refresh an encrypted channel blob, enforcing byte and entry caps (#372).
    pub fn store_blob(
        &self,
        blob: EncryptedChannelBlob,
    ) -> Result<RetentionPruneReport, WatchtowerError> {
        if blob.ciphertext.len() > self.policy.max_total_bytes {
            return Err(WatchtowerError::InvalidRetentionPolicy(format!(
                "blob size {} exceeds max_total_bytes {}",
                blob.ciphertext.len(),
                self.policy.max_total_bytes
            )));
        }

        let now = blob.stored_at;
        let mut entries = self.entries.write();
        entries.retain(|existing| existing.channel_id != blob.channel_id);
        entries.push(blob);
        Ok(Self::prune_locked(&mut entries, &self.policy, now))
    }

    /// Retrieve an encrypted blob if present and not expired (#372).
    pub fn get_blob(&self, channel_id: &str, now: u64) -> Option<EncryptedChannelBlob> {
        let cutoff = now.saturating_sub(self.policy.max_age_secs);
        self.entries
            .read()
            .iter()
            .find(|b| b.channel_id == channel_id && b.stored_at >= cutoff)
            .cloned()
    }

    /// Enforce age, entry-count, and total-byte caps explicitly (#372).
    pub fn enforce_retention(&self, now: u64) -> RetentionPruneReport {
        let mut entries = self.entries.write();
        Self::prune_locked(&mut entries, &self.policy, now)
    }

    fn prune_locked(
        entries: &mut Vec<EncryptedChannelBlob>,
        policy: &EncryptedStateRetentionPolicy,
        now: u64,
    ) -> RetentionPruneReport {
        let before_age = entries.len();
        let cutoff = now.saturating_sub(policy.max_age_secs);
        entries.retain(|b| b.stored_at >= cutoff);
        let evicted_expired = before_age.saturating_sub(entries.len());

        // Oldest entries first so newest encrypted states survive eviction.
        entries.sort_by_key(|b| b.stored_at);

        let mut evicted_overflow = 0usize;
        let mut total_bytes: usize = entries.iter().map(|b| b.ciphertext.len()).sum();
        while !entries.is_empty()
            && (entries.len() > policy.max_entries || total_bytes > policy.max_total_bytes)
        {
            let removed = entries.remove(0);
            total_bytes = total_bytes.saturating_sub(removed.ciphertext.len());
            evicted_overflow += 1;
        }

        RetentionPruneReport {
            evicted_expired,
            evicted_overflow,
            remaining_entries: entries.len(),
            remaining_bytes: total_bytes,
        }
    }

    /// Number of retained encrypted blobs.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Whether the encrypted store is currently empty.
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Aggregate ciphertext bytes currently held.
    pub fn total_bytes(&self) -> usize {
        self.entries.read().iter().map(|b| b.ciphertext.len()).sum()
    }
}

/// Delivery lifecycle state for an alert webhook/notification (#373).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertDeliveryStatus {
    Pending,
    Retrying,
    Delivered,
    Failed,
}

/// Tracked alert delivery item keyed by deterministic `delivery_id` (#373).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDeliveryRecord {
    pub delivery_id: String,
    pub alert_id: String,
    pub destination: String,
    pub attempts: u32,
    pub max_attempts: u32,
    pub status: AlertDeliveryStatus,
    pub last_error: Option<String>,
}

/// Manages idempotent alert enqueueing and retryable delivery (#373).
pub struct AlertDeliveryManager {
    max_attempts: u32,
    records: RwLock<std::collections::HashMap<String, AlertDeliveryRecord>>,
}

impl AlertDeliveryManager {
    /// Create a delivery manager enforcing at least one attempt.
    pub fn new(max_attempts: u32) -> Self {
        AlertDeliveryManager {
            max_attempts: max_attempts.max(1),
            records: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Compute deterministic delivery ID for `(alert_id, destination)` (#373).
    pub fn deterministic_delivery_id(alert_id: &str, destination: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(alert_id.as_bytes());
        hasher.update(b":");
        hasher.update(destination.as_bytes());
        let digest = hasher.finalize();
        format!(
            "dlv_{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]
        )
    }

    /// Enqueue an alert idempotently, returning its stable `delivery_id` (#373).
    pub fn enqueue(&self, alert: &Alert, destination: &str) -> String {
        let delivery_id = Self::deterministic_delivery_id(&alert.id, destination);
        let mut records = self.records.write();
        records
            .entry(delivery_id.clone())
            .or_insert_with(|| AlertDeliveryRecord {
                delivery_id: delivery_id.clone(),
                alert_id: alert.id.clone(),
                destination: destination.to_string(),
                attempts: 0,
                max_attempts: self.max_attempts,
                status: AlertDeliveryStatus::Pending,
                last_error: None,
            });
        delivery_id
    }

    /// Attempt delivery using the caller-supplied transport closure (#373).
    pub fn attempt_delivery<F>(
        &self,
        delivery_id: &str,
        mut transport: F,
    ) -> Result<AlertDeliveryRecord, WatchtowerError>
    where
        F: FnMut(&str) -> Result<(), String>,
    {
        let mut records = self.records.write();
        let record = records.get_mut(delivery_id).ok_or_else(|| {
            WatchtowerError::AlertDeliveryFailed(format!("unknown delivery_id {}", delivery_id))
        })?;

        if record.status == AlertDeliveryStatus::Delivered {
            return Ok(record.clone());
        }
        if record.attempts >= record.max_attempts {
            record.status = AlertDeliveryStatus::Failed;
            return Ok(record.clone());
        }

        record.attempts += 1;
        match transport(delivery_id) {
            Ok(()) => {
                record.status = AlertDeliveryStatus::Delivered;
                record.last_error = None;
            }
            Err(err) => {
                record.last_error = Some(err);
                record.status = if record.attempts >= record.max_attempts {
                    AlertDeliveryStatus::Failed
                } else {
                    AlertDeliveryStatus::Retrying
                };
            }
        }
        Ok(record.clone())
    }

    /// Fetch delivery state by `delivery_id`.
    pub fn get_record(&self, delivery_id: &str) -> Option<AlertDeliveryRecord> {
        self.records.read().get(delivery_id).cloned()
    }
}

/// Outcome of scanning all subscribed channels once (#374).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanCycleReport {
    /// Channels scanned cleanly without errors.
    pub succeeded: Vec<String>,
    /// Per-channel failures `(channel_id, error_message)` (#374).
    pub failed: Vec<(String, String)>,
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
    /// Per-channel latest monitoring error messages (#374)
    pub per_channel_failures: RwLock<std::collections::HashMap<String, String>>,
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
    /// Bounded encrypted channel state store (#372)
    encrypted_state: EncryptedStateStore,
    /// Retryable alert delivery queue (#373)
    alert_deliveries: AlertDeliveryManager,
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

        let encrypted_state = EncryptedStateStore::new(config.encrypted_retention)?;
        let alert_deliveries = AlertDeliveryManager::new(config.alert_max_retries);

        let state = Arc::new(WatchtowerState {
            subscribed_channels: RwLock::new(std::collections::HashSet::new()),
            channel_states: RwLock::new(std::collections::HashMap::new()),
            recent_alerts: RwLock::new(Vec::new()),
            is_running: RwLock::new(false),
            stats: RwLock::new(WatchtowerStats::default()),
            last_compaction_ts: RwLock::new(current_timestamp()),
            per_channel_failures: RwLock::new(std::collections::HashMap::new()),
            storage: Arc::clone(&storage),
        });

        Ok(Watchtower {
            config,
            state,
            monitor,
            justice,
            storage,
            encrypted_state,
            alert_deliveries,
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
                                state.add_alert(alert);

                                // Submit justice if enabled
                                if config.auto_justice {
                                    if let Err(e) = justice.submit_justice(&breach).await {
                                        error!("Failed to submit justice: {:?}", e);
                                    }
                                }
                            }

                            // Update stored state, mirroring it to storage so it
                            // survives a restart and can be compacted.
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

                // Compact on a schedule: the store grows per scan, so leaving
                // retention to an operator's manual call means it never runs.
                if let Some(report) = state.compact_if_due(&config) {
                    let mut stats = state.stats.write();
                    stats.compactions_run += 1;
                    stats.records_compacted += report.total_removed() as u64;
                }

                tokio::time::sleep(tokio::time::Duration::from_secs(config.scan_interval_secs))
                    .await;
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
        self.state
            .subscribed_channels
            .write()
            .insert(channel_id.clone());

        // Initialize monitoring state
        let monitor_state = monitor::ChannelMonitorState {
            channel_id: channel_id.clone(),
            last_known_sequence: 0,
            last_update_ts: current_timestamp(),
            is_closed: false,
            pending_htlcs: Vec::new(),
        };

        self.state
            .channel_states
            .write()
            .insert(channel_id.clone(), monitor_state.clone());

        // A subscription that only lives in memory is lost on restart, and the
        // channel would then be watched by nobody.
        self.storage.store_subscription(&channel_id)?;
        self.storage
            .store_channel_state(&channel_id, &monitor_state)?;

        info!("Subscribed to channel");
        Ok(())
    }

    /// Unsubscribe from a channel
    pub fn unsubscribe(&self, channel_id: &str) {
        self.state.subscribed_channels.write().remove(channel_id);
        self.state.channel_states.write().remove(channel_id);
        let _ = self.storage.remove_subscription(channel_id);
        info!("Unsubscribed from channel");
    }

    /// Channels the watchtower is subscribed to and would reload on restart.
    pub fn persisted_subscriptions(&self) -> Result<Vec<String>, storage::StorageError> {
        self.storage.get_subscriptions()
    }

    /// Run a compaction pass with the configured retention rules.
    pub fn compact_storage(&self) -> Result<storage::CompactionReport, WatchtowerError> {
        let report = self.storage.compact(&self.config.compaction)?;

        let mut stats = self.state.stats.write();
        stats.compactions_run += 1;
        stats.records_compacted += report.total_removed() as u64;
        *self.state.last_compaction_ts.write() = current_timestamp();

        info!(
            "Storage compaction removed {} records ({} alerts, {} channel updates)",
            report.total_removed(),
            report.alerts_removed(),
            report.channel_updates_removed()
        );

        Ok(report)
    }

    /// Scan all subscribed channels once, isolating failures per channel (#374).
    pub async fn scan_channels_once(&self) -> ScanCycleReport {
        let mut channels: Vec<String> = self
            .state
            .subscribed_channels
            .read()
            .iter()
            .cloned()
            .collect();
        channels.sort();

        let mut report = ScanCycleReport::default();

        for channel_id in channels {
            match self.monitor.check_channel(&channel_id).await {
                Ok(Some(update)) => {
                    self.state.per_channel_failures.write().remove(&channel_id);
                    if let Some(breach) = self.monitor.detect_breach(&channel_id, &update) {
                        warn!("Breach attempt detected on channel {}", channel_id);
                        let alert = Alert::breach_attempt(
                            channel_id.clone(),
                            breach.old_sequence,
                            breach.new_sequence,
                        );
                        self.state.add_alert(alert);
                        if self.config.auto_justice {
                            if let Err(e) = self.justice.submit_justice(&breach).await {
                                error!("Failed to submit justice: {:?}", e);
                            }
                        }
                    }
                    self.state.update_channel_state(&channel_id, update);
                    report.succeeded.push(channel_id);
                }
                Ok(None) => {
                    self.state.per_channel_failures.write().remove(&channel_id);
                    self.state.remove_channel(&channel_id);
                    report.succeeded.push(channel_id);
                }
                Err(e) => {
                    let msg = e.to_string();
                    error!("Error checking channel {}: {}", channel_id, msg);
                    self.state
                        .per_channel_failures
                        .write()
                        .insert(channel_id.clone(), msg.clone());
                    self.state.add_alert(Alert {
                        id: uuid_v4(),
                        alert_type: AlertType::HealthCheckFailed {
                            component: format!("channel:{}", channel_id),
                            error: msg.clone(),
                        },
                        severity: AlertSeverity::Warning,
                        timestamp: current_timestamp(),
                        context: serde_json::json!({ "channel_id": channel_id }),
                    });
                    report.failed.push((channel_id, msg));
                }
            }
        }

        let mut stats = self.state.stats.write();
        stats.last_scan_ts = current_timestamp();
        stats.channels_monitored = self.state.subscribed_channels.read().len() as u64;
        report
    }

    /// Access the underlying channel monitor (#370, #374).
    pub fn monitor(&self) -> &monitor::ChannelMonitor {
        &self.monitor
    }

    /// Access the bounded encrypted state store (#372).
    pub fn encrypted_state(&self) -> &EncryptedStateStore {
        &self.encrypted_state
    }

    /// Access the retryable alert delivery manager (#373).
    pub fn alert_deliveries(&self) -> &AlertDeliveryManager {
        &self.alert_deliveries
    }

    /// Get current watchtower status including monitoring lag & per-channel failures (#370, #374)
    pub fn status(&self) -> WatchtowerStatus {
        let stats = self.state.stats.read();
        let alerts = self.state.recent_alerts.read();

        WatchtowerStatus {
            is_running: *self.state.is_running.read(),
            channels_monitored: self.state.subscribed_channels.read().len() as u64,
            breach_attempts_detected: stats.breach_attempts_detected,
            justice_txs_submitted: stats.justice_txs_submitted,
            recent_alerts_count: alerts.len(),
            last_seen_ledger: self.monitor.last_seen_ledger(),
            monitoring_lag_ledgers: self.monitor.monitoring_lag_ledgers(),
            per_channel_failures: self.state.per_channel_failures.read().clone(),
        }
    }

    /// Shared watchtower state, for embedders that need to inspect or seed it.
    pub fn state(&self) -> Arc<WatchtowerState> {
        Arc::clone(&self.state)
    }

    /// Get recent alerts
    pub fn get_alerts(&self, limit: usize) -> Vec<Alert> {
        self.state
            .recent_alerts
            .read()
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// The configuration this watchtower was built with.
    pub fn config(&self) -> &WatchtowerConfig {
        &self.config
    }

    /// The storage backend backing this watchtower.
    pub fn storage(&self) -> &Arc<dyn storage::StorageBackend> {
        &self.storage
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

    /// Apply a channel update to the in-memory state and persist both the
    /// update and the resulting state.
    pub fn update_channel_state(&self, channel_id: &str, update: monitor::ChannelUpdate) {
        {
            let mut states = self.channel_states.write();
            if let Some(state) = states.get_mut(channel_id) {
                state.last_known_sequence = update.sequence_number;
                state.last_update_ts = current_timestamp();
            }
        }

        // Persisting is deliberately best-effort: a storage failure must not
        // stop the monitor loop from checking the next channel.
        if let Some(state) = self.channel_states.read().get(channel_id).cloned() {
            let _ = self.storage.store_channel_state(channel_id, &state);
        }
        let _ = self.storage.store_channel_update(&update);
    }

    /// Run a compaction pass if `compaction_interval_secs` has elapsed.
    ///
    /// Returns the report when a pass ran, `None` when it was not due (or when
    /// automatic compaction is disabled).
    pub fn compact_if_due(&self, config: &WatchtowerConfig) -> Option<storage::CompactionReport> {
        if config.compaction_interval_secs == 0 {
            return None;
        }

        let now = current_timestamp();
        let last = *self.last_compaction_ts.read();
        if now.saturating_sub(last) < config.compaction_interval_secs {
            return None;
        }

        // Stamp before compacting so a failing backend cannot make every scan
        // retry the same expensive pass.
        *self.last_compaction_ts.write() = now;

        match self.storage.compact(&config.compaction) {
            Ok(report) => Some(report),
            Err(e) => {
                error!("Storage compaction failed: {:?}", e);
                None
            }
        }
    }

    /// The storage backend shared by this state and its watchtower.
    pub fn storage(&self) -> &Arc<dyn storage::StorageBackend> {
        &self.storage
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
    /// Highest ledger height observed by the monitor (#370)
    pub last_seen_ledger: u32,
    /// Ledgers elapsed between network head and `last_seen_ledger` (#370)
    pub monitoring_lag_ledgers: u32,
    /// Most recent per-channel check errors keyed by channel ID (#374)
    pub per_channel_failures: std::collections::HashMap<String, String>,
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

    #[error("Invalid encrypted state retention policy: {0}")]
    InvalidRetentionPolicy(String),

    #[error("Alert delivery failed: {0}")]
    AlertDeliveryFailed(String),
}

impl From<storage::StorageError> for WatchtowerError {
    fn from(e: storage::StorageError) -> Self {
        WatchtowerError::StorageError(e.to_string())
    }
}

impl From<monitor::MonitorError> for WatchtowerError {
    fn from(e: monitor::MonitorError) -> Self {
        WatchtowerError::NetworkError(e.to_string())
    }
}

impl From<justice::JusticeError> for WatchtowerError {
    fn from(e: justice::JusticeError) -> Self {
        WatchtowerError::JusticeFailed(e.to_string())
    }
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
    use crate::storage::CompactionPolicy;

    #[test]
    fn test_watchtower_config() {
        let config = WatchtowerConfig::default();
        assert_eq!(config.scan_interval_secs, 60);
        assert!(config.auto_justice);
        assert_eq!(config.compaction_interval_secs, 3_600);
    }

    #[test]
    fn test_alert_message() {
        let alert = Alert::breach_attempt("channel123".to_string(), 1, 5);
        assert!(alert.message().contains("BREACH"));
    }

    #[test]
    fn subscriptions_survive_a_restart() {
        let watchtower = Watchtower::new(WatchtowerConfig::default()).unwrap();

        watchtower.subscribe("channel-a".to_string()).unwrap();
        watchtower.subscribe("channel-b".to_string()).unwrap();
        assert_eq!(
            watchtower.persisted_subscriptions().unwrap(),
            vec!["channel-a".to_string(), "channel-b".to_string()]
        );

        watchtower.unsubscribe("channel-a");
        assert_eq!(
            watchtower.persisted_subscriptions().unwrap(),
            vec!["channel-b".to_string()]
        );
    }

    #[test]
    fn compact_storage_applies_the_configured_policy() {
        let config = WatchtowerConfig {
            compaction: CompactionPolicy {
                alert_retention_secs: 0,
                ..CompactionPolicy::default()
            },
            ..Default::default()
        };
        let watchtower = Watchtower::new(config).unwrap();

        let mut stale = Alert::breach_attempt("channel-a".to_string(), 1, 2);
        stale.timestamp = current_timestamp() - 60;
        watchtower.storage().store_alert(&stale).unwrap();
        watchtower
            .storage()
            .store_alert(&Alert::breach_attempt("channel-a".to_string(), 2, 3))
            .unwrap();

        let report = watchtower.compact_storage().unwrap();
        assert_eq!(report.alerts_removed(), 1);
        assert_eq!(watchtower.storage().get_alerts(10).unwrap().len(), 1);

        let stats = watchtower.state().stats.read().clone();
        assert_eq!(stats.compactions_run, 1);
        assert_eq!(stats.records_compacted, 1);
    }

    #[test]
    fn automatic_compaction_only_runs_when_due() {
        // A fresh watchtower has just compacted, so no pass is due yet.
        let watchtower = Watchtower::new(WatchtowerConfig::default()).unwrap();
        assert!(watchtower
            .state()
            .compact_if_due(watchtower.config())
            .is_none());

        // Rewinding the last-pass timestamp makes the interval elapse.
        *watchtower.state().last_compaction_ts.write() = 0;
        assert!(watchtower
            .state()
            .compact_if_due(watchtower.config())
            .is_some());

        // ...and then stamps it again, so the next scan does not re-run it.
        assert!(watchtower
            .state()
            .compact_if_due(watchtower.config())
            .is_none());
    }

    #[test]
    fn automatic_compaction_can_be_disabled() {
        let config = WatchtowerConfig {
            compaction_interval_secs: 0,
            ..Default::default()
        };
        let watchtower = Watchtower::new(config).unwrap();
        *watchtower.state().last_compaction_ts.write() = 0;

        assert!(watchtower
            .state()
            .compact_if_due(watchtower.config())
            .is_none());
    }

    #[test]
    fn channel_updates_are_persisted_for_later_compaction() {
        let watchtower = Watchtower::new(WatchtowerConfig::default()).unwrap();
        watchtower.subscribe("channel-a".to_string()).unwrap();

        let update = monitor::ChannelUpdate {
            channel_id: "channel-a".to_string(),
            sequence_number: 4,
            balance_a: 10,
            balance_b: 20,
            is_closed: false,
            close_type: None,
            block_height: 100,
            timestamp: current_timestamp(),
        };
        watchtower.state().update_channel_state("channel-a", update);

        let stored = watchtower
            .storage()
            .get_channel_update("channel-a")
            .unwrap()
            .expect("update should be persisted");
        assert_eq!(stored.sequence_number, 4);

        let state = watchtower
            .storage()
            .get_channel_state("channel-a")
            .unwrap()
            .expect("state should be persisted");
        assert_eq!(state.last_known_sequence, 4);
    }

    #[test]
    fn encrypted_state_retention_enforces_age_count_and_byte_limits() {
        assert!(EncryptedStateStore::new(EncryptedStateRetentionPolicy {
            max_entries: 0,
            ..Default::default()
        })
        .is_err());

        let store = EncryptedStateStore::new(EncryptedStateRetentionPolicy {
            max_entries: 2,
            max_age_secs: 60,
            max_total_bytes: 16,
        })
        .unwrap();

        let oversized = EncryptedChannelBlob {
            channel_id: "too-big".to_string(),
            ciphertext: vec![1u8; 32],
            nonce: [0u8; 12],
            stored_at: 100,
        };
        assert!(store.store_blob(oversized).is_err());

        store
            .store_blob(EncryptedChannelBlob {
                channel_id: "c1".to_string(),
                ciphertext: vec![1u8; 6],
                nonce: [0u8; 12],
                stored_at: 100,
            })
            .unwrap();
        store
            .store_blob(EncryptedChannelBlob {
                channel_id: "c2".to_string(),
                ciphertext: vec![2u8; 6],
                nonce: [0u8; 12],
                stored_at: 120,
            })
            .unwrap();
        let report = store
            .store_blob(EncryptedChannelBlob {
                channel_id: "c3".to_string(),
                ciphertext: vec![3u8; 6],
                nonce: [0u8; 12],
                stored_at: 140,
            })
            .unwrap();

        assert_eq!(report.evicted_overflow, 1);
        assert_eq!(store.len(), 2);
        assert!(store.get_blob("c1", 150).is_none());
        assert!(store.get_blob("c2", 150).is_some());

        let pruned = store.enforce_retention(300);
        assert_eq!(pruned.evicted_expired, 2);
        assert!(store.is_empty());
    }

    #[test]
    fn alert_delivery_is_retryable_with_stable_delivery_id() {
        let manager = AlertDeliveryManager::new(3);
        let alert = Alert::breach_attempt("ch1".to_string(), 1, 5);
        let id1 = manager.enqueue(&alert, "https://ops.example/webhook");
        let id2 = manager.enqueue(&alert, "https://ops.example/webhook");
        assert_eq!(id1, id2);

        let r1 = manager
            .attempt_delivery(&id1, |_| Err("503 unavailable".to_string()))
            .unwrap();
        assert_eq!(r1.status, AlertDeliveryStatus::Retrying);
        assert_eq!(r1.attempts, 1);

        let r2 = manager.attempt_delivery(&id1, |_| Ok(())).unwrap();
        assert_eq!(r2.status, AlertDeliveryStatus::Delivered);
        assert_eq!(r2.attempts, 2);
        assert!(r2.last_error.is_none());
    }

    #[tokio::test]
    async fn per_channel_monitoring_failures_do_not_stop_other_channels() {
        let wt = Watchtower::new(WatchtowerConfig::default()).unwrap();
        wt.subscribe("ch-bad".to_string()).unwrap();
        wt.subscribe("ch-good".to_string()).unwrap();

        wt.monitor().set_network_head_ledger(200);
        wt.monitor().seed_channel_update(monitor::ChannelUpdate {
            channel_id: "ch-good".to_string(),
            sequence_number: 2,
            balance_a: 500,
            balance_b: 500,
            is_closed: false,
            close_type: None,
            block_height: 192,
            timestamp: current_timestamp(),
        });
        wt.monitor().set_simulated_failure("ch-bad", "rpc timeout");

        let cycle = wt.scan_channels_once().await;
        assert_eq!(cycle.succeeded, vec!["ch-good".to_string()]);
        assert_eq!(cycle.failed.len(), 1);
        assert_eq!(cycle.failed[0].0, "ch-bad");

        let status = wt.status();
        assert_eq!(status.last_seen_ledger, 192);
        assert_eq!(status.monitoring_lag_ledgers, 8);
        assert_eq!(
            status
                .per_channel_failures
                .get("ch-bad")
                .map(String::as_str),
            Some("Network error: rpc timeout")
        );

        // Clearing the transient error allows ch-bad to recover on next scan.
        wt.monitor().clear_simulated_failure("ch-bad");
        let recovery = wt.scan_channels_once().await;
        assert_eq!(recovery.failed.len(), 0);
        assert!(wt.status().per_channel_failures.is_empty());
    }
}

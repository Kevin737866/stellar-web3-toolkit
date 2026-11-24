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
//! - Per-channel failure reporting that isolates one channel's failure from the rest

pub mod failure_report;
pub mod justice;
pub mod monitor;
pub mod storage;

pub use failure_report::{ChannelFailureRegistry, ChannelFailureReport, MAX_FAILURE_REASON_LEN};

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
    /// A single channel's monitoring scan failed (issue #374)
    ChannelMonitorFailed {
        channel_id: String,
        error: String,
        consecutive_failures: u32,
    },
    /// A channel that had been failing has been monitored successfully again
    ChannelMonitorRecovered {
        channel_id: String,
        after_failures: u32,
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

    /// Create an alert for one channel's failed monitor scan.
    pub fn channel_monitor_failed(report: &ChannelFailureReport) -> Self {
        let severity = if report.consecutive_failures >= 3 {
            AlertSeverity::Critical
        } else {
            AlertSeverity::Warning
        };
        Alert {
            id: uuid_v4(),
            alert_type: AlertType::ChannelMonitorFailed {
                channel_id: report.channel_id.clone(),
                error: report.error.clone(),
                consecutive_failures: report.consecutive_failures,
            },
            severity,
            timestamp: current_timestamp(),
            context: serde_json::json!({
                "channel_id": report.channel_id,
                "consecutive_failures": report.consecutive_failures,
                "message": report.message(),
            }),
        }
    }

    /// Create an alert for a channel that recovered after failing.
    pub fn channel_monitor_recovered(report: &ChannelFailureReport) -> Self {
        Alert {
            id: uuid_v4(),
            alert_type: AlertType::ChannelMonitorRecovered {
                channel_id: report.channel_id.clone(),
                after_failures: report.consecutive_failures,
            },
            severity: AlertSeverity::Info,
            timestamp: current_timestamp(),
            context: serde_json::json!({ "channel_id": report.channel_id }),
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
            AlertType::ChannelMonitorFailed {
                channel_id,
                error,
                consecutive_failures,
            } => {
                format!(
                    "Monitoring failed for channel {channel_id} ({consecutive_failures} consecutive): {error}. Retry with Watchtower::retry_channel."
                )
            }
            AlertType::ChannelMonitorRecovered {
                channel_id,
                after_failures,
            } => {
                format!("Channel {channel_id} recovered after {after_failures} failed scan(s)")
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
    /// Per-channel monitoring failure reports (issue #374)
    failures: Arc<RwLock<failure_report::ChannelFailureRegistry>>,
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
            failures: Arc::new(RwLock::new(
                failure_report::ChannelFailureRegistry::default(),
            )),
        })
    }

    /// Start the watchtower service
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)] // public API; the loop it spawns is what awaits
    pub async fn start(&self) -> Result<(), WatchtowerError> {
        *self.state.is_running.write() = true;

        info!("Watchtower service started");

        // Start the monitoring loop. Each channel is scanned independently:
        // a failure is recorded for that channel only and never breaks the
        // loop or prevents the remaining channels from being checked.
        let state = Arc::clone(&self.state);
        let config = self.config.clone();
        let monitor = self.monitor.clone();
        let justice = self.justice.clone();
        let failures = Arc::clone(&self.failures);

        tokio::spawn(async move {
            loop {
                if !*state.is_running.read() {
                    break;
                }

                // Scan subscribed channels
                let channels: Vec<String> =
                    state.subscribed_channels.read().iter().cloned().collect();

                for channel_id in channels {
                    let outcome =
                        Self::scan_channel(&state, &monitor, &config, &justice, &channel_id).await;

                    match outcome {
                        Ok(()) => {
                            let now = current_timestamp();
                            if let Some(recovered) =
                                failures.write().record_success(&channel_id, now)
                            {
                                let alert = Alert::channel_monitor_recovered(&recovered);
                                state.add_alert(alert.clone());
                                // Best effort: a storage error must never stop the
                                // loop or roll back the in-memory recovery.
                                if let Err(e) = state.storage().store_alert(&alert) {
                                    error!("Failed to persist recovery alert: {:?}", e);
                                }
                            }
                        }
                        Err(e) => {
                            let detail = e.to_string();
                            let now = current_timestamp();
                            let report = failures.write().record_failure(&channel_id, &detail, now);
                            match report {
                                Ok(report) => {
                                    error!("{}", report.message());
                                    let alert = Alert::channel_monitor_failed(&report);
                                    state.add_alert(alert.clone());
                                    if let Err(e) = state.storage().store_alert(&alert) {
                                        error!("Failed to persist failure alert: {:?}", e);
                                    }
                                }
                                Err(e) => error!("Could not report channel failure: {:?}", e),
                            }
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

    /// Scan one channel. All state changes complete before an error is returned
    /// so a failed scan can be reported without leaving a half-applied update.
    async fn scan_channel(
        state: &Arc<WatchtowerState>,
        monitor: &monitor::ChannelMonitor,
        config: &WatchtowerConfig,
        justice: &justice::JusticeService,
        channel_id: &str,
    ) -> Result<(), WatchtowerError> {
        let update = match monitor.check_channel(channel_id).await {
            Ok(Some(update)) => update,
            Ok(None) => {
                info!("Channel {} no longer exists", channel_id);
                state.remove_channel(channel_id);
                return Ok(());
            }
            Err(e) => return Err(WatchtowerError::from(e)),
        };

        let mut failure = None;
        if let Some(breach) = monitor.detect_breach(channel_id, &update) {
            warn!("Breach attempt detected on channel {}", channel_id);

            let alert = Alert::breach_attempt(
                channel_id.to_string(),
                breach.old_sequence,
                breach.new_sequence,
            );
            state.add_alert(alert);

            if config.auto_justice {
                match justice.submit_justice(&breach).await {
                    Ok(_) => {
                        // submit_justice persists before submitting;
                        // bump the persisted counter on success (issue #368).
                        let mut stats = state.stats.write();
                        stats.justice_actions_persisted += 1;
                    }
                    Err(e) => {
                        // Evidence validation and persistence happen inside
                        // submit_justice; a rejected breach must not interrupt
                        // this channel's state update or any other channel.
                        error!("Failed to submit justice: {:?}", e);
                        failure = Some(WatchtowerError::from(e));
                    }
                }
            }
        }

        state.update_channel_state(channel_id, update);
        if let Some(e) = failure {
            return Err(e);
        }
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

    /// Retrieve all justice actions that are still `Pending` from storage.
    ///
    /// An operator calls this after a process restart or network outage to find
    /// breach responses that were persisted but not yet submitted, then passes
    /// the results to [`Self::retry_pending_justice`] to replay them.
    pub fn pending_justice_actions(&self) -> Result<Vec<justice::JusticeAction>, WatchtowerError> {
        self.storage
            .get_pending_justice_actions()
            .map_err(|e| WatchtowerError::StorageError(e.to_string()))
    }

    /// Replay all `Pending` justice actions (issue #368 operator recovery path).
    ///
    /// Returns the count of actions successfully submitted on this call.
    pub async fn retry_pending_justice(&self) -> usize {
        self.justice.retry_pending_actions().await
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

    /// The channel monitor. Exposed so embedders and simulation tests can
    /// inject a failure for one channel without affecting any other.
    pub fn monitor(&self) -> &monitor::ChannelMonitor {
        &self.monitor
    }

    /// Explicitly report a failed scan for a subscribed channel (issue #374).
    ///
    /// The alert is persisted before the in-memory registry is changed, so a
    /// storage failure returns an error and leaves no partial update.
    pub fn report_channel_failure(
        &self,
        channel_id: String,
        reason: String,
    ) -> Result<ChannelFailureReport, WatchtowerError> {
        failure_report::ChannelFailureRegistry::validate_channel_id(&channel_id)?;
        failure_report::ChannelFailureRegistry::validate_reason(&reason)?;
        if !self.state.subscribed_channels.read().contains(&channel_id) {
            return Err(WatchtowerError::InvalidChannel(format!(
                "channel {channel_id} is not subscribed"
            )));
        }

        let now = current_timestamp();
        let preview = self
            .failures
            .read()
            .preview_failure(&channel_id, &reason, now)?;
        let alert = Alert::channel_monitor_failed(&preview);
        self.storage.store_alert(&alert)?;
        self.state.add_alert(alert);
        self.failures
            .write()
            .record_failure(&channel_id, &reason, now)
    }

    /// Latest failure report for a channel, including recovered incidents.
    pub fn channel_failure_report(&self, channel_id: &str) -> Option<ChannelFailureReport> {
        self.failures.read().get(channel_id)
    }

    /// All failure reports, sorted by channel id.
    pub fn channel_failure_reports(&self) -> Vec<ChannelFailureReport> {
        self.failures.read().all()
    }

    /// Reports for channels that are still failing.
    pub fn active_channel_failure_reports(&self) -> Vec<ChannelFailureReport> {
        self.failures.read().active()
    }

    /// Total consecutive failures across all current incidents.
    pub fn total_monitor_failures(&self) -> u64 {
        self.failures.read().total_failures()
    }

    /// Forget a channel's failure report (operator recovery). Returns whether
    /// a report existed. This never touches justice actions or subscriptions.
    pub fn clear_channel_failure(&self, channel_id: &str) -> Result<bool, WatchtowerError> {
        failure_report::ChannelFailureRegistry::validate_channel_id(channel_id)?;
        Ok(self.failures.write().clear(channel_id))
    }

    /// Re-check one failing channel and mark it recovered on success.
    ///
    /// Returns `Some(report)` when an active failure was cleared, or `None`
    /// when the channel had no active failure. A failed retry increments that
    /// channel's consecutive failures and returns an actionable error; it does
    /// not change any other channel's state or any persisted justice action.
    pub async fn retry_channel(
        &self,
        channel_id: &str,
    ) -> Result<Option<ChannelFailureReport>, WatchtowerError> {
        failure_report::ChannelFailureRegistry::validate_channel_id(channel_id)?;
        if !self.state.subscribed_channels.read().contains(channel_id) {
            return Err(WatchtowerError::InvalidChannel(format!(
                "channel {channel_id} is not subscribed"
            )));
        }

        match self.monitor.check_channel(channel_id).await {
            Ok(_) => Ok(self
                .failures
                .write()
                .record_success(channel_id, current_timestamp())),
            Err(e) => {
                let reason = format!("retry failed for channel {channel_id}: {e}");
                let now = current_timestamp();
                let report = self
                    .failures
                    .write()
                    .record_failure(channel_id, &reason, now)?;
                let alert = Alert::channel_monitor_failed(&report);
                self.state.add_alert(alert.clone());
                let _ = self.storage.store_alert(&alert);
                Err(WatchtowerError::NetworkError(report.message()))
            }
        }
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

    #[error("Invalid failure report: {0}")]
    InvalidFailureReason(String),

    #[error("Justice transaction failed: {0}")]
    JusticeFailed(String),

    #[error("Watchtower not running")]
    NotRunning,
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

    fn watchtower_with_channels() -> Watchtower {
        let watchtower = Watchtower::new(WatchtowerConfig::default()).unwrap();
        watchtower.subscribe("alpha".to_string()).unwrap();
        watchtower.subscribe("beta".to_string()).unwrap();
        watchtower
    }

    #[test]
    fn failure_reports_are_scoped_to_one_channel() {
        let watchtower = watchtower_with_channels();
        watchtower
            .report_channel_failure("alpha".to_string(), "rpc timeout".to_string())
            .unwrap();
        watchtower
            .report_channel_failure("alpha".to_string(), "rpc timeout".to_string())
            .unwrap();

        assert_eq!(
            watchtower
                .channel_failure_report("alpha")
                .unwrap()
                .consecutive_failures,
            2
        );
        assert!(watchtower.channel_failure_report("beta").is_none());
        assert_eq!(watchtower.active_channel_failure_reports().len(), 1);
        assert_eq!(watchtower.total_monitor_failures(), 2);
        assert_eq!(watchtower.channel_failure_reports().len(), 1);

        let alerts = watchtower.get_alerts(10);
        assert!(alerts.iter().all(|alert| alert.message().contains("alpha")));
        assert!(watchtower.storage().get_alerts(10).unwrap().len() >= 2);
    }

    #[test]
    fn invalid_failure_reports_change_no_state() {
        let watchtower = watchtower_with_channels();
        assert!(matches!(
            watchtower.report_channel_failure(" ".to_string(), "boom".to_string()),
            Err(WatchtowerError::InvalidChannel(_))
        ));
        assert!(matches!(
            watchtower.report_channel_failure("alpha".to_string(), "".to_string()),
            Err(WatchtowerError::InvalidFailureReason(_))
        ));
        assert!(matches!(
            watchtower.report_channel_failure("unknown".to_string(), "boom".to_string()),
            Err(WatchtowerError::InvalidChannel(_))
        ));
        assert_eq!(watchtower.total_monitor_failures(), 0);
        assert!(watchtower.channel_failure_reports().is_empty());
        assert!(watchtower.get_alerts(10).is_empty());
    }

    #[test]
    fn failure_alert_escalates_and_carries_a_retry_hint() {
        let mut registry = ChannelFailureRegistry::default();
        let report = registry.record_failure("alpha", "rpc timeout", 10).unwrap();
        let low = Alert::channel_monitor_failed(&report);
        assert_eq!(low.severity, AlertSeverity::Warning);
        assert!(low.message().contains("retry_channel"));

        registry.record_failure("alpha", "rpc timeout", 20).unwrap();
        let report = registry.record_failure("alpha", "rpc timeout", 30).unwrap();
        let high = Alert::channel_monitor_failed(&report);
        assert_eq!(high.severity, AlertSeverity::Critical);
    }

    #[test]
    fn clearing_a_failure_affects_only_the_named_channel() {
        let watchtower = watchtower_with_channels();
        watchtower
            .report_channel_failure("alpha".to_string(), "boom".to_string())
            .unwrap();
        watchtower
            .report_channel_failure("beta".to_string(), "boom".to_string())
            .unwrap();

        assert!(watchtower.clear_channel_failure("alpha").unwrap());
        assert!(!watchtower.clear_channel_failure("alpha").unwrap());
        assert!(watchtower.channel_failure_report("alpha").is_none());
        assert!(watchtower.channel_failure_report("beta").is_some());
        assert!(matches!(
            watchtower.clear_channel_failure(" "),
            Err(WatchtowerError::InvalidChannel(_))
        ));
    }

    #[tokio::test]
    async fn injected_monitor_failure_is_isolated_to_one_channel() {
        let watchtower = watchtower_with_channels();
        watchtower.monitor().inject_failure(
            "alpha",
            monitor::MonitorError::NetworkError("boom".to_string()),
        );

        assert!(watchtower.monitor().check_channel("alpha").await.is_err());
        assert!(watchtower.monitor().check_channel("beta").await.is_ok());

        assert!(watchtower.monitor().clear_injected_failure("alpha"));
        assert!(watchtower.monitor().check_channel("alpha").await.is_ok());
    }
}

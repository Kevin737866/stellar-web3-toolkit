//! # Storage Module
//!
//! Persistent storage backends for the watchtower.

use crate::monitor::{ChannelMonitorState, ChannelUpdate};
use crate::Alert;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, info};

/// Retention rules applied by [`StorageBackend::compact`].
///
/// A watchtower writes continuously -- a state and an update per channel per
/// scan, plus an alert per incident -- so without retention the store grows
/// with uptime rather than with the number of channels being watched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionPolicy {
    /// Keep at most this many alerts, newest first.
    pub max_alerts: usize,
    /// Drop alerts older than this, in seconds.
    pub alert_retention_secs: u64,
    /// Drop the cached update of a channel not refreshed within this, in
    /// seconds. A channel that keeps being scanned keeps its update fresh, so
    /// only unsubscribed or abandoned channels age out.
    pub update_retention_secs: u64,
    /// Keep at most this many cached channel updates, newest first.
    pub max_channel_updates: usize,
}

impl Default for CompactionPolicy {
    fn default() -> Self {
        CompactionPolicy {
            max_alerts: 1_000,
            alert_retention_secs: 7 * 24 * 60 * 60, // one week
            update_retention_secs: 24 * 60 * 60,    // one day
            max_channel_updates: 10_000,
        }
    }
}

/// What a compaction pass removed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionReport {
    /// Alerts before the pass.
    pub alerts_before: usize,
    /// Alerts after the pass.
    pub alerts_after: usize,
    /// Cached channel updates before the pass.
    pub channel_updates_before: usize,
    /// Cached channel updates after the pass.
    pub channel_updates_after: usize,
    /// Duplicate subscriptions collapsed during the pass.
    pub subscriptions_deduplicated: usize,
}

impl CompactionReport {
    /// Alerts removed by the pass.
    pub fn alerts_removed(&self) -> usize {
        self.alerts_before.saturating_sub(self.alerts_after)
    }

    /// Cached channel updates removed by the pass.
    pub fn channel_updates_removed(&self) -> usize {
        self.channel_updates_before
            .saturating_sub(self.channel_updates_after)
    }

    /// Everything the pass removed.
    pub fn total_removed(&self) -> usize {
        self.alerts_removed() + self.channel_updates_removed() + self.subscriptions_deduplicated
    }

    /// Whether the pass changed anything.
    pub fn is_noop(&self) -> bool {
        self.total_removed() == 0
    }
}

/// Overall state reported by a storage health probe.
///
/// `Degraded` means the backend answered but could not meet the requested
/// guarantees (for example, a slow response or a backend that cannot verify
/// persistence). `Unhealthy` means a probe actually failed, so the backend
/// cannot currently be trusted to hold breach evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageHealthState {
    /// Every enabled probe succeeded within the configured latency budget.
    Healthy,
    /// Probes succeeded, but a guarantee requested by the caller was not met.
    Degraded,
    /// At least one required probe failed.
    Unhealthy,
}

impl StorageHealthState {
    /// Whether this state represents a backend that can be relied upon.
    pub fn is_healthy(self) -> bool {
        matches!(self, StorageHealthState::Healthy)
    }

    /// Stable label suitable for logs and alerts.
    pub fn as_str(self) -> &'static str {
        match self {
            StorageHealthState::Healthy => "healthy",
            StorageHealthState::Degraded => "degraded",
            StorageHealthState::Unhealthy => "unhealthy",
        }
    }
}

/// Options for a storage health probe.
///
/// Invalid options are rejected with [`StorageError::HealthCheckError`] instead
/// of being silently replaced with defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageHealthCheckOptions {
    /// Maximum acceptable duration of the whole probe, in milliseconds.
    /// Must be at least 1; a zero budget would make every backend fail.
    pub max_latency_ms: u64,
    /// Also perform a write/read/delete round-trip using a sentinel
    /// subscription. The sentinel is removed on every path, including failures.
    pub probe_writes: bool,
}

impl Default for StorageHealthCheckOptions {
    fn default() -> Self {
        StorageHealthCheckOptions {
            max_latency_ms: 1_000,
            probe_writes: false,
        }
    }
}

impl StorageHealthCheckOptions {
    /// Reject options that cannot describe a meaningful probe.
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.max_latency_ms == 0 {
            return Err(StorageError::HealthCheckError(
                "max_latency_ms must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}

/// Result of a storage health probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageHealthReport {
    /// Name of the backend that was probed (`in-memory`, `sqlite`, or a custom
    /// backend's [`StorageBackend::backend_name`]).
    pub backend: String,
    /// Overall outcome of the probe.
    pub state: StorageHealthState,
    /// Unix timestamp at which the probe finished.
    pub checked_at: u64,
    /// Wall-clock duration of the probe in milliseconds.
    pub elapsed_ms: u64,
    /// Whether the read probe succeeded.
    pub read_ok: bool,
    /// Outcome of the write/read/delete probe, or `None` when it was not
    /// requested (or was skipped because the read probe had already failed).
    pub write_probe_ok: Option<bool>,
    /// Actionable messages explaining a degraded or unhealthy result.
    pub details: Vec<String>,
}

impl StorageHealthReport {
    /// Whether the probed backend can be relied upon.
    pub fn is_healthy(&self) -> bool {
        self.state.is_healthy()
    }

    /// One-line summary suitable for an alert or log entry.
    pub fn summary(&self) -> String {
        let mut summary = format!(
            "{} storage backend is {}: read_ok={}",
            self.backend,
            self.state.as_str(),
            self.read_ok
        );
        if let Some(write_ok) = self.write_probe_ok {
            summary.push_str(&format!(", write_probe_ok={write_ok}"));
        }
        for detail in &self.details {
            summary.push_str(&format!("; {detail}"));
        }
        summary
    }
}

/// Storage backend trait
pub trait StorageBackend: Send + Sync {
    /// Stable name used in health reports and alerts.
    ///
    /// Existing implementations keep compiling with the default value.
    fn backend_name(&self) -> &'static str {
        "custom"
    }

    /// Probe the backend with the default options.
    fn check_health(&self) -> Result<StorageHealthReport, StorageError> {
        self.check_health_with(&StorageHealthCheckOptions::default())
    }

    /// Probe the backend with caller-supplied options.
    ///
    /// Returns `Err` only for invalid options or an internal probe failure. A
    /// failing backend is reported as an [`StorageHealthState::Unhealthy`]
    /// report carrying the backend's error in [`StorageHealthReport::details`].
    /// The default implementation works for any backend; implementations may
    /// override it to add backend-specific checks.
    fn check_health_with(
        &self,
        options: &StorageHealthCheckOptions,
    ) -> Result<StorageHealthReport, StorageError> {
        options.validate()?;
        probe_health(self, self.backend_name(), options)
    }

    /// Store a channel state
    fn store_channel_state(
        &self,
        channel_id: &str,
        state: &ChannelMonitorState,
    ) -> Result<(), StorageError>;

    /// Get a channel state
    fn get_channel_state(
        &self,
        channel_id: &str,
    ) -> Result<Option<ChannelMonitorState>, StorageError>;

    /// Store an alert
    fn store_alert(&self, alert: &Alert) -> Result<(), StorageError>;

    /// Get alerts
    fn get_alerts(&self, limit: usize) -> Result<Vec<Alert>, StorageError>;

    /// Store a cached channel update
    fn store_channel_update(&self, update: &ChannelUpdate) -> Result<(), StorageError>;

    /// Get cached channel update
    fn get_channel_update(&self, channel_id: &str) -> Result<Option<ChannelUpdate>, StorageError>;

    /// Store a channel we're subscribed to
    fn store_subscription(&self, channel_id: &str) -> Result<(), StorageError>;

    /// Get all subscriptions
    fn get_subscriptions(&self) -> Result<Vec<String>, StorageError>;

    /// Remove a subscription
    fn remove_subscription(&self, channel_id: &str) -> Result<(), StorageError>;

    /// Apply `policy` to the stored data and report what was removed.
    ///
    /// Compaction must never drop data a monitor still depends on: a channel
    /// that is still subscribed keeps its state and cached update regardless
    /// of age.
    fn compact(&self, policy: &CompactionPolicy) -> Result<CompactionReport, StorageError>;

    /// Apply the default retention rules.
    fn compact_with_defaults(&self) -> Result<CompactionReport, StorageError> {
        self.compact(&CompactionPolicy::default())
    }

    // ── Justice action persistence (issue #368) ───────────────────────────────

    /// Persist a justice action record.
    ///
    /// Called **before** the justice transaction is submitted so that the
    /// breach evidence is never silently lost on a failed submission.
    fn store_justice_action(
        &self,
        action: &crate::justice::JusticeAction,
    ) -> Result<(), StorageError>;

    /// Retrieve a justice action by its ID.
    fn get_justice_action(
        &self,
        id: &str,
    ) -> Result<Option<crate::justice::JusticeAction>, StorageError>;

    /// Retrieve every persisted justice action, regardless of status.
    ///
    /// Recovery export needs submitted and failed records as well as pending
    /// ones. Backends that do not override this fail explicitly instead of
    /// silently producing a partial snapshot.
    fn get_all_justice_actions(&self) -> Result<Vec<crate::justice::JusticeAction>, StorageError> {
        Err(StorageError::QueryError(
            "backend does not support full justice action export".to_string(),
        ))
    }

    /// Retrieve all justice actions whose status is `Pending`.
    ///
    /// Used by the operator recovery path: after a restart, any `Pending`
    /// action can be retried via [`crate::justice::JusticeService::retry_pending_actions`].
    fn get_pending_justice_actions(
        &self,
    ) -> Result<Vec<crate::justice::JusticeAction>, StorageError>;

    /// Update the status and optional transaction hash of a persisted action.
    ///
    /// A no-op when the `id` is not found (the in-process record is the
    /// authoritative source; storage is best-effort for durability).
    fn update_justice_action_status(
        &self,
        id: &str,
        status: crate::justice::ActionStatus,
        tx_hash: Option<&str>,
    ) -> Result<(), StorageError>;
}

/// In-memory storage backend
pub struct InMemoryStorage {
    channel_states: parking_lot::RwLock<HashMap<String, ChannelMonitorState>>,
    channel_updates: parking_lot::RwLock<HashMap<String, ChannelUpdate>>,
    alerts: parking_lot::RwLock<Vec<Alert>>,
    subscriptions: parking_lot::RwLock<Vec<String>>,
    /// Justice action records, keyed by action ID (issue #368).
    justice_actions: parking_lot::RwLock<HashMap<String, crate::justice::JusticeAction>>,
}

impl InMemoryStorage {
    /// Create a new in-memory storage
    pub fn new() -> Self {
        InMemoryStorage {
            channel_states: parking_lot::RwLock::new(HashMap::new()),
            channel_updates: parking_lot::RwLock::new(HashMap::new()),
            alerts: parking_lot::RwLock::new(Vec::new()),
            subscriptions: parking_lot::RwLock::new(Vec::new()),
            justice_actions: parking_lot::RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for InMemoryStorage {
    fn backend_name(&self) -> &'static str {
        "in-memory"
    }

    fn store_channel_state(
        &self,
        channel_id: &str,
        state: &ChannelMonitorState,
    ) -> Result<(), StorageError> {
        let mut states = self.channel_states.write();
        states.insert(channel_id.to_string(), state.clone());
        Ok(())
    }

    fn get_channel_state(
        &self,
        channel_id: &str,
    ) -> Result<Option<ChannelMonitorState>, StorageError> {
        let states = self.channel_states.read();
        Ok(states.get(channel_id).cloned())
    }

    fn store_alert(&self, alert: &Alert) -> Result<(), StorageError> {
        let mut alerts = self.alerts.write();
        alerts.push(alert.clone());

        // Keep only last 1000
        if alerts.len() > 1000 {
            alerts.drain(0..500);
        }

        Ok(())
    }

    fn get_alerts(&self, limit: usize) -> Result<Vec<Alert>, StorageError> {
        let alerts = self.alerts.read();
        Ok(alerts.iter().rev().take(limit).cloned().collect())
    }

    fn store_channel_update(&self, update: &ChannelUpdate) -> Result<(), StorageError> {
        let mut updates = self.channel_updates.write();
        updates.insert(update.channel_id.clone(), update.clone());
        Ok(())
    }

    fn get_channel_update(&self, channel_id: &str) -> Result<Option<ChannelUpdate>, StorageError> {
        let updates = self.channel_updates.read();
        Ok(updates.get(channel_id).cloned())
    }

    fn store_subscription(&self, channel_id: &str) -> Result<(), StorageError> {
        let mut subs = self.subscriptions.write();
        if !subs.contains(&channel_id.to_string()) {
            subs.push(channel_id.to_string());
        }
        Ok(())
    }

    fn get_subscriptions(&self) -> Result<Vec<String>, StorageError> {
        let subs = self.subscriptions.read();
        Ok(subs.clone())
    }

    fn remove_subscription(&self, channel_id: &str) -> Result<(), StorageError> {
        let mut subs = self.subscriptions.write();
        subs.retain(|s| s != channel_id);
        Ok(())
    }

    fn compact(&self, policy: &CompactionPolicy) -> Result<CompactionReport, StorageError> {
        let now = current_timestamp();
        let mut report = CompactionReport::default();

        // Subscriptions first: the set of channels still being watched decides
        // what the other passes are allowed to drop.
        let mut subscriptions: Vec<String> = {
            let subs = self.subscriptions.read();
            subs.clone()
        };
        let before = subscriptions.len();
        let mut seen = std::collections::HashSet::with_capacity(before);
        subscriptions.retain(|id| seen.insert(id.clone()));
        report.subscriptions_deduplicated = before - subscriptions.len();
        if report.subscriptions_deduplicated > 0 {
            *self.subscriptions.write() = subscriptions;
        }

        let subscribed: std::collections::HashSet<String> = {
            let subs = self.subscriptions.read();
            subs.iter().cloned().collect()
        };

        // Alerts: drop the aged-out ones, then the overflow beyond max_alerts.
        {
            let mut alerts = self.alerts.write();
            report.alerts_before = alerts.len();

            let cutoff = now.saturating_sub(policy.alert_retention_secs);
            alerts.retain(|alert| alert.timestamp >= cutoff);

            if alerts.len() > policy.max_alerts {
                // Evict by timestamp rather than by position: a backend that
                // reloaded from disk is not guaranteed to hold alerts in the
                // order they arrived, and "the last 1000" must mean the newest.
                let mut by_age: Vec<(usize, u64)> = alerts
                    .iter()
                    .enumerate()
                    .map(|(index, alert)| (index, alert.timestamp))
                    .collect();
                by_age.sort_by_key(|(_, timestamp)| *timestamp);

                let mut evicted: Vec<usize> = by_age
                    .into_iter()
                    .take(alerts.len() - policy.max_alerts)
                    .map(|(index, _)| index)
                    .collect();
                // Remove from the back so the earlier indices stay valid.
                evicted.sort_unstable_by(|a, b| b.cmp(a));
                for index in evicted {
                    alerts.remove(index);
                }
            }

            report.alerts_after = alerts.len();
        }

        // Channel updates: keep the freshest `max_channel_updates` among those
        // that are neither stale nor still subscribed.
        {
            let mut updates = self.channel_updates.write();
            report.channel_updates_before = updates.len();

            let cutoff = now.saturating_sub(policy.update_retention_secs);
            updates.retain(|channel_id, update| {
                subscribed.contains(channel_id) || update.timestamp >= cutoff
            });

            if updates.len() > policy.max_channel_updates {
                let mut by_age: Vec<(String, u64)> = updates
                    .iter()
                    .map(|(id, update)| (id.clone(), update.timestamp))
                    .collect();
                by_age.sort_by_key(|(_, timestamp)| *timestamp);

                let excess = updates.len() - policy.max_channel_updates;
                for (channel_id, _) in by_age.into_iter().take(excess) {
                    // Never evict a channel we are still watching.
                    if subscribed.contains(&channel_id) {
                        continue;
                    }
                    updates.remove(&channel_id);
                }
            }

            report.channel_updates_after = updates.len();
        }

        debug!(
            "Compacted watchtower storage: {} alerts, {} channel updates removed",
            report.alerts_removed(),
            report.channel_updates_removed()
        );

        Ok(report)
    }

    fn store_justice_action(
        &self,
        action: &crate::justice::JusticeAction,
    ) -> Result<(), StorageError> {
        let mut actions = self.justice_actions.write();
        actions.insert(action.id.clone(), action.clone());
        Ok(())
    }

    fn get_justice_action(
        &self,
        id: &str,
    ) -> Result<Option<crate::justice::JusticeAction>, StorageError> {
        let actions = self.justice_actions.read();
        Ok(actions.get(id).cloned())
    }

    fn get_all_justice_actions(&self) -> Result<Vec<crate::justice::JusticeAction>, StorageError> {
        let actions = self.justice_actions.read();
        Ok(actions.values().cloned().collect())
    }

    fn get_pending_justice_actions(
        &self,
    ) -> Result<Vec<crate::justice::JusticeAction>, StorageError> {
        let actions = self.justice_actions.read();
        Ok(actions
            .values()
            .filter(|a| a.status == crate::justice::ActionStatus::Pending)
            .cloned()
            .collect())
    }

    fn update_justice_action_status(
        &self,
        id: &str,
        status: crate::justice::ActionStatus,
        tx_hash: Option<&str>,
    ) -> Result<(), StorageError> {
        let mut actions = self.justice_actions.write();
        if let Some(action) = actions.get_mut(id) {
            action.status = status;
            if let Some(hash) = tx_hash {
                action.tx_hash = Some(hash.to_string());
            }
            action.updated_at = current_timestamp();
        }
        Ok(())
    }
}

/// SQLite storage backend (placeholder implementation)
pub struct SqliteStorage {
    // Retained for the RPC/storage wiring still to come.
    #[allow(dead_code)]
    path: String,
}

impl SqliteStorage {
    /// Create a new SQLite storage backend
    pub fn new(path: &str) -> Result<Self, StorageError> {
        // In production, this would initialize SQLite connection
        Ok(SqliteStorage {
            path: path.to_string(),
        })
    }
}

impl StorageBackend for SqliteStorage {
    fn backend_name(&self) -> &'static str {
        "sqlite"
    }

    fn check_health_with(
        &self,
        options: &StorageHealthCheckOptions,
    ) -> Result<StorageHealthReport, StorageError> {
        options.validate()?;

        // This backend is a placeholder: operations report success but no rows
        // are persisted, so a write/read-back probe would always fail. Report
        // that limitation explicitly rather than claiming full health or
        // inventing a failing probe.
        let read_only = StorageHealthCheckOptions {
            probe_writes: false,
            ..*options
        };
        let mut report = probe_health(self, self.backend_name(), &read_only)?;
        if report.state == StorageHealthState::Healthy {
            report.state = StorageHealthState::Degraded;
        }
        report.details.push(
            "SQLite backend is a placeholder: persistence is not implemented, so durability cannot be verified".to_string(),
        );
        Ok(report)
    }

    fn store_channel_state(
        &self,
        channel_id: &str,
        _state: &ChannelMonitorState,
    ) -> Result<(), StorageError> {
        // In production: INSERT INTO channel_states VALUES (?, ?)
        info!("SQLite: storing channel state for {}", channel_id);
        Ok(())
    }

    fn get_channel_state(
        &self,
        channel_id: &str,
    ) -> Result<Option<ChannelMonitorState>, StorageError> {
        // In production: SELECT * FROM channel_states WHERE channel_id = ?
        info!("SQLite: getting channel state for {}", channel_id);
        Ok(None)
    }

    fn store_alert(&self, alert: &Alert) -> Result<(), StorageError> {
        // In production: INSERT INTO alerts VALUES (?, ?)
        info!("SQLite: storing alert {}", alert.id);
        Ok(())
    }

    fn get_alerts(&self, limit: usize) -> Result<Vec<Alert>, StorageError> {
        // In production: SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?
        info!("SQLite: getting {} alerts", limit);
        Ok(Vec::new())
    }

    fn store_channel_update(&self, update: &ChannelUpdate) -> Result<(), StorageError> {
        // In production: INSERT OR REPLACE INTO channel_updates VALUES (?, ?)
        info!("SQLite: storing channel update for {}", update.channel_id);
        Ok(())
    }

    fn get_channel_update(&self, channel_id: &str) -> Result<Option<ChannelUpdate>, StorageError> {
        // In production: SELECT * FROM channel_updates WHERE channel_id = ?
        info!("SQLite: getting channel update for {}", channel_id);
        Ok(None)
    }

    fn store_subscription(&self, channel_id: &str) -> Result<(), StorageError> {
        // In production: INSERT OR IGNORE INTO subscriptions VALUES (?)
        info!("SQLite: storing subscription for {}", channel_id);
        Ok(())
    }

    fn get_subscriptions(&self) -> Result<Vec<String>, StorageError> {
        // In production: SELECT channel_id FROM subscriptions
        info!("SQLite: getting all subscriptions");
        Ok(Vec::new())
    }

    fn remove_subscription(&self, channel_id: &str) -> Result<(), StorageError> {
        // In production: DELETE FROM subscriptions WHERE channel_id = ?
        info!("SQLite: removing subscription for {}", channel_id);
        Ok(())
    }

    fn compact(&self, policy: &CompactionPolicy) -> Result<CompactionReport, StorageError> {
        // No rows are persisted yet, so there is nothing to reclaim. The
        // signature still has to exist: callers schedule compaction
        // unconditionally, and a silent no-op here is preferable to making
        // every caller check which backend is in use.
        info!(
            "SQLite: compact requested (max_alerts={}, alert_retention={}s, update_retention={}s)",
            policy.max_alerts, policy.alert_retention_secs, policy.update_retention_secs
        );
        Ok(CompactionReport::default())
    }

    fn store_justice_action(
        &self,
        action: &crate::justice::JusticeAction,
    ) -> Result<(), StorageError> {
        // In production: INSERT OR REPLACE INTO justice_actions VALUES (?, ?, ?)
        info!("SQLite: storing justice action {}", action.id);
        Ok(())
    }

    fn get_justice_action(
        &self,
        id: &str,
    ) -> Result<Option<crate::justice::JusticeAction>, StorageError> {
        // In production: SELECT * FROM justice_actions WHERE id = ?
        info!("SQLite: getting justice action {}", id);
        Ok(None)
    }

    fn get_all_justice_actions(&self) -> Result<Vec<crate::justice::JusticeAction>, StorageError> {
        // The placeholder backend persists no rows, so an empty snapshot here
        // is accurate rather than a partial result.
        info!("SQLite: getting all justice actions");
        Ok(Vec::new())
    }

    fn get_pending_justice_actions(
        &self,
    ) -> Result<Vec<crate::justice::JusticeAction>, StorageError> {
        // In production: SELECT * FROM justice_actions WHERE status = 'pending'
        info!("SQLite: getting pending justice actions");
        Ok(Vec::new())
    }

    fn update_justice_action_status(
        &self,
        id: &str,
        status: crate::justice::ActionStatus,
        tx_hash: Option<&str>,
    ) -> Result<(), StorageError> {
        // In production: UPDATE justice_actions SET status = ?, tx_hash = ? WHERE id = ?
        info!(
            "SQLite: updating justice action {} to {:?} (tx: {:?})",
            id, status, tx_hash
        );
        Ok(())
    }
}

/// Run the generic health probe against any backend.
///
/// A write probe uses a sentinel subscription so it never touches a real
/// channel subscription or a pending justice action. Cleanup is attempted on
/// every path, including a failed write or a failed verification, so a probe
/// cannot leave durable state behind.
fn probe_health<B: StorageBackend + ?Sized>(
    backend: &B,
    backend_name: &str,
    options: &StorageHealthCheckOptions,
) -> Result<StorageHealthReport, StorageError> {
    let started = std::time::Instant::now();
    let mut state = StorageHealthState::Healthy;
    let mut details = Vec::new();

    // Read probe: any storage error is a health result, not an API error.
    let read_ok = match backend.get_subscriptions() {
        Ok(_) => true,
        Err(e) => {
            state = StorageHealthState::Unhealthy;
            details.push(format!("read probe failed: {e}"));
            false
        }
    };

    let mut write_probe_ok = None;
    if options.probe_writes {
        if !read_ok {
            details.push("write probe skipped because the read probe failed".to_string());
        } else {
            let sentinel = format!("__watchtower_health_probe__{:x}", rand::random::<u128>());

            match backend.store_subscription(&sentinel) {
                Ok(()) => {
                    let visible = match backend.get_subscriptions() {
                        Ok(subscriptions) => subscriptions.iter().any(|id| id == &sentinel),
                        Err(e) => {
                            details.push(format!("write probe verification failed: {e}"));
                            false
                        }
                    };

                    // Always try to remove the sentinel, even if verification
                    // failed: a probe must not leave partial state behind.
                    if let Err(e) = backend.remove_subscription(&sentinel) {
                        state = StorageHealthState::Unhealthy;
                        details.push(format!("write probe cleanup failed for {sentinel}: {e}"));
                    }

                    if visible {
                        write_probe_ok = Some(true);
                    } else {
                        state = StorageHealthState::Unhealthy;
                        details.push(
                            "write probe: sentinel subscription was not readable back".to_string(),
                        );
                        write_probe_ok = Some(false);
                    }
                }
                Err(e) => {
                    // The write may have partially succeeded, so still attempt
                    // cleanup before reporting.
                    if let Err(cleanup) = backend.remove_subscription(&sentinel) {
                        details.push(format!(
                            "write probe cleanup failed for {sentinel}: {cleanup}"
                        ));
                    }
                    state = StorageHealthState::Unhealthy;
                    details.push(format!("write probe failed: {e}"));
                    write_probe_ok = Some(false);
                }
            }
        }
    }

    let elapsed_ms = started.elapsed().as_millis() as u64;
    if elapsed_ms > options.max_latency_ms {
        if state == StorageHealthState::Healthy {
            state = StorageHealthState::Degraded;
        }
        details.push(format!(
            "probe took {elapsed_ms}ms, exceeding the {}ms budget",
            options.max_latency_ms
        ));
    }

    debug!(
        backend = backend_name,
        state = state.as_str(),
        elapsed_ms,
        "storage health probe completed"
    );

    Ok(StorageHealthReport {
        backend: backend_name.to_string(),
        state,
        checked_at: current_timestamp(),
        elapsed_ms,
        read_ok,
        write_probe_ok,
        details,
    })
}

/// Seconds since the Unix epoch.
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Storage errors
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Query error: {0}")]
    QueryError(String),

    /// Invalid health-check options or a failure to run the probe itself.
    /// A backend that answers but is unhealthy is reported as a
    /// [`StorageHealthReport`] instead.
    #[error("Health check error: {0}")]
    HealthCheckError(String),
}

#[cfg(test)]
impl InMemoryStorage {
    /// Insert a duplicate subscription without deduplicating.
    ///
    /// Stands in for a backend that does not deduplicate on insert, so the
    /// compaction pass can be exercised on data it actually has to fix.
    fn push_raw_subscription(&self, channel_id: &str) {
        self.subscriptions.write().push(channel_id.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AlertSeverity;

    const DAY: u64 = 24 * 60 * 60;

    fn monitor_state(channel_id: &str, last_update_ts: u64) -> ChannelMonitorState {
        ChannelMonitorState {
            channel_id: channel_id.to_string(),
            last_known_sequence: 1,
            last_update_ts,
            is_closed: false,
            pending_htlcs: Vec::new(),
        }
    }

    fn update(channel_id: &str, timestamp: u64) -> ChannelUpdate {
        ChannelUpdate {
            channel_id: channel_id.to_string(),
            sequence_number: 1,
            balance_a: 100,
            balance_b: 100,
            is_closed: false,
            close_type: None,
            block_height: 1,
            timestamp,
        }
    }

    fn alert_at(timestamp: u64) -> Alert {
        let mut alert = Alert::breach_attempt("channel1".to_string(), 1, 2);
        alert.timestamp = timestamp;
        alert
    }

    #[test]
    fn compaction_drops_alerts_past_the_retention_window() {
        let storage = InMemoryStorage::new();
        let now = current_timestamp();

        storage.store_alert(&alert_at(now)).unwrap();
        storage.store_alert(&alert_at(now - 2 * DAY)).unwrap();

        let report = storage
            .compact(&CompactionPolicy {
                alert_retention_secs: DAY,
                ..CompactionPolicy::default()
            })
            .unwrap();

        assert_eq!(report.alerts_before, 2);
        assert_eq!(report.alerts_after, 1);
        assert_eq!(report.alerts_removed(), 1);
        assert_eq!(storage.get_alerts(10).unwrap().len(), 1);
    }

    #[test]
    fn compaction_keeps_the_newest_alerts_up_to_the_limit() {
        let storage = InMemoryStorage::new();
        let now = current_timestamp();

        // Appended oldest first, the way alerts actually arrive.
        for i in (0..5).rev() {
            storage.store_alert(&alert_at(now - i)).unwrap();
        }

        let report = storage
            .compact(&CompactionPolicy {
                max_alerts: 2,
                ..CompactionPolicy::default()
            })
            .unwrap();

        assert_eq!(report.alerts_removed(), 3);

        let remaining = storage.get_alerts(10).unwrap();
        assert_eq!(remaining.len(), 2);
        // Returned newest first, and the two newest timestamps survived.
        assert_eq!(remaining[0].timestamp, now);
        assert_eq!(remaining[1].timestamp, now - 1);
    }

    #[test]
    fn compaction_drops_stale_updates_but_keeps_subscribed_channels() {
        let storage = InMemoryStorage::new();
        let now = current_timestamp();

        storage.store_subscription("watched").unwrap();
        storage
            .store_channel_update(&update("watched", now - 30 * DAY))
            .unwrap();
        storage
            .store_channel_update(&update("abandoned", now - 30 * DAY))
            .unwrap();
        storage.store_channel_update(&update("fresh", now)).unwrap();

        let report = storage
            .compact(&CompactionPolicy {
                update_retention_secs: DAY,
                ..CompactionPolicy::default()
            })
            .unwrap();

        assert_eq!(report.channel_updates_before, 3);
        assert_eq!(report.channel_updates_after, 2);
        assert!(storage.get_channel_update("watched").unwrap().is_some());
        assert!(storage.get_channel_update("abandoned").unwrap().is_none());
        assert!(storage.get_channel_update("fresh").unwrap().is_some());
    }

    #[test]
    fn compaction_evicts_the_oldest_updates_beyond_the_limit() {
        let storage = InMemoryStorage::new();
        let now = current_timestamp();

        for i in 0..5 {
            storage
                .store_channel_update(&update(&format!("ch{i}"), now - i))
                .unwrap();
        }

        let report = storage
            .compact(&CompactionPolicy {
                max_channel_updates: 2,
                ..CompactionPolicy::default()
            })
            .unwrap();

        assert_eq!(report.channel_updates_removed(), 3);
        assert!(storage.get_channel_update("ch0").unwrap().is_some());
        assert!(storage.get_channel_update("ch1").unwrap().is_some());
        assert!(storage.get_channel_update("ch4").unwrap().is_none());
    }

    #[test]
    fn compaction_never_evicts_a_subscribed_channel_to_meet_the_limit() {
        let storage = InMemoryStorage::new();
        let now = current_timestamp();

        storage.store_subscription("watched").unwrap();
        // The watched channel has the oldest update of the set.
        storage
            .store_channel_update(&update("watched", now - 100))
            .unwrap();
        for i in 0..3 {
            storage
                .store_channel_update(&update(&format!("ch{i}"), now - i))
                .unwrap();
        }

        let report = storage
            .compact(&CompactionPolicy {
                max_channel_updates: 1,
                update_retention_secs: 365 * DAY,
                ..CompactionPolicy::default()
            })
            .unwrap();

        assert!(storage.get_channel_update("watched").unwrap().is_some());
        // The limit is a target, not a guarantee: the subscribed channel stays
        // even though it is the oldest entry.
        assert_eq!(report.channel_updates_after, 2);
    }

    #[test]
    fn compaction_collapses_duplicate_subscriptions() {
        let storage = InMemoryStorage::new();
        storage.store_subscription("ch1").unwrap();
        storage.push_raw_subscription("ch1");
        storage.push_raw_subscription("ch2");

        let report = storage.compact(&CompactionPolicy::default()).unwrap();

        assert_eq!(report.subscriptions_deduplicated, 1);
        assert_eq!(storage.get_subscriptions().unwrap().len(), 2);
    }

    #[test]
    fn compaction_on_clean_storage_is_a_noop() {
        let storage = InMemoryStorage::new();
        storage.store_subscription("ch1").unwrap();
        storage.store_alert(&alert_at(current_timestamp())).unwrap();

        let report = storage.compact_with_defaults().unwrap();

        assert!(report.is_noop());
        assert_eq!(report.total_removed(), 0);
    }

    #[test]
    fn compaction_leaves_channel_states_and_subscriptions_intact() {
        let storage = InMemoryStorage::new();
        storage.store_subscription("ch1").unwrap();
        storage
            .store_channel_state("ch1", &monitor_state("ch1", 0))
            .unwrap();

        storage.compact_with_defaults().unwrap();

        assert!(storage.get_channel_state("ch1").unwrap().is_some());
        assert_eq!(storage.get_subscriptions().unwrap(), vec!["ch1"]);
    }

    #[test]
    fn sqlite_backend_compaction_is_a_safe_noop() {
        let storage = SqliteStorage::new(":memory:").unwrap();
        let report = storage.compact_with_defaults().unwrap();
        assert!(report.is_noop());
    }

    #[test]
    fn alert_severity_is_preserved_across_compaction() {
        let storage = InMemoryStorage::new();
        storage.store_alert(&alert_at(current_timestamp())).unwrap();
        storage.compact_with_defaults().unwrap();

        let alerts = storage.get_alerts(1).unwrap();
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
    }

    #[test]
    fn test_in_memory_storage() {
        let storage = InMemoryStorage::new();

        // Test subscription
        storage.store_subscription("channel1").unwrap();
        let subs = storage.get_subscriptions().unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0], "channel1");

        // Test alert
        let alert = Alert::breach_attempt("channel1".to_string(), 1, 5);
        storage.store_alert(&alert).unwrap();
        let alerts = storage.get_alerts(10).unwrap();
        assert_eq!(alerts.len(), 1);
    }

    // ── Storage backend health checks ─────────────────────────────────────────

    /// A backend that can be made to fail individual probe steps. Everything
    /// else is delegated to a real in-memory store so failures are isolated.
    struct FlakyStorage {
        inner: InMemoryStorage,
        fail_read: std::sync::atomic::AtomicBool,
        fail_write: std::sync::atomic::AtomicBool,
        fail_cleanup: std::sync::atomic::AtomicBool,
        slow_read: std::sync::atomic::AtomicBool,
    }

    impl FlakyStorage {
        fn new() -> Self {
            FlakyStorage {
                inner: InMemoryStorage::new(),
                fail_read: std::sync::atomic::AtomicBool::new(false),
                fail_write: std::sync::atomic::AtomicBool::new(false),
                fail_cleanup: std::sync::atomic::AtomicBool::new(false),
                slow_read: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn set_fail_read(&self, value: bool) {
            self.fail_read
                .store(value, std::sync::atomic::Ordering::SeqCst);
        }

        fn set_fail_write(&self, value: bool) {
            self.fail_write
                .store(value, std::sync::atomic::Ordering::SeqCst);
        }

        fn set_fail_cleanup(&self, value: bool) {
            self.fail_cleanup
                .store(value, std::sync::atomic::Ordering::SeqCst);
        }

        fn set_slow_read(&self, value: bool) {
            self.slow_read
                .store(value, std::sync::atomic::Ordering::SeqCst);
        }

        fn probe_error(step: &str) -> StorageError {
            StorageError::DatabaseError(format!("injected {step} failure"))
        }
    }

    impl StorageBackend for FlakyStorage {
        fn backend_name(&self) -> &'static str {
            "flaky"
        }

        fn store_channel_state(
            &self,
            channel_id: &str,
            state: &ChannelMonitorState,
        ) -> Result<(), StorageError> {
            self.inner.store_channel_state(channel_id, state)
        }

        fn get_channel_state(
            &self,
            channel_id: &str,
        ) -> Result<Option<ChannelMonitorState>, StorageError> {
            self.inner.get_channel_state(channel_id)
        }

        fn store_alert(&self, alert: &Alert) -> Result<(), StorageError> {
            self.inner.store_alert(alert)
        }

        fn get_alerts(&self, limit: usize) -> Result<Vec<Alert>, StorageError> {
            self.inner.get_alerts(limit)
        }

        fn store_channel_update(&self, update: &ChannelUpdate) -> Result<(), StorageError> {
            self.inner.store_channel_update(update)
        }

        fn get_channel_update(
            &self,
            channel_id: &str,
        ) -> Result<Option<ChannelUpdate>, StorageError> {
            self.inner.get_channel_update(channel_id)
        }

        fn store_subscription(&self, channel_id: &str) -> Result<(), StorageError> {
            if self.fail_write.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(Self::probe_error("write"));
            }
            self.inner.store_subscription(channel_id)
        }

        fn get_subscriptions(&self) -> Result<Vec<String>, StorageError> {
            if self.slow_read.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if self.fail_read.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(Self::probe_error("read"));
            }
            self.inner.get_subscriptions()
        }

        fn remove_subscription(&self, channel_id: &str) -> Result<(), StorageError> {
            if self.fail_cleanup.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(Self::probe_error("cleanup"));
            }
            self.inner.remove_subscription(channel_id)
        }

        fn compact(&self, policy: &CompactionPolicy) -> Result<CompactionReport, StorageError> {
            self.inner.compact(policy)
        }

        fn store_justice_action(
            &self,
            action: &crate::justice::JusticeAction,
        ) -> Result<(), StorageError> {
            self.inner.store_justice_action(action)
        }

        fn get_justice_action(
            &self,
            id: &str,
        ) -> Result<Option<crate::justice::JusticeAction>, StorageError> {
            self.inner.get_justice_action(id)
        }

        fn get_pending_justice_actions(
            &self,
        ) -> Result<Vec<crate::justice::JusticeAction>, StorageError> {
            self.inner.get_pending_justice_actions()
        }

        fn update_justice_action_status(
            &self,
            id: &str,
            status: crate::justice::ActionStatus,
            tx_hash: Option<&str>,
        ) -> Result<(), StorageError> {
            self.inner.update_justice_action_status(id, status, tx_hash)
        }
    }

    #[test]
    fn in_memory_probe_is_healthy_and_read_only_by_default() {
        let report = InMemoryStorage::new().check_health().unwrap();
        assert_eq!(report.backend, "in-memory");
        assert_eq!(report.state, StorageHealthState::Healthy);
        assert!(report.is_healthy());
        assert!(report.read_ok);
        assert_eq!(report.write_probe_ok, None);
        assert!(report.details.is_empty());
    }

    #[test]
    fn write_probe_verifies_and_removes_the_sentinel() {
        let storage = InMemoryStorage::new();
        storage.store_subscription("channel1").unwrap();

        let report = storage
            .check_health_with(&StorageHealthCheckOptions {
                probe_writes: true,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(report.state, StorageHealthState::Healthy);
        assert_eq!(report.write_probe_ok, Some(true));
        // The probe must not disturb real subscriptions or leave its sentinel.
        assert_eq!(storage.get_subscriptions().unwrap(), vec!["channel1"]);
    }

    #[test]
    fn invalid_health_check_options_are_rejected() {
        let options = StorageHealthCheckOptions {
            max_latency_ms: 0,
            probe_writes: true,
        };
        let error = InMemoryStorage::new()
            .check_health_with(&options)
            .unwrap_err();
        assert!(error.to_string().contains("max_latency_ms"));

        // Validation is available on its own so callers can reject bad config
        // before constructing a watchtower.
        assert!(options.validate().is_err());
    }

    #[test]
    fn a_failing_read_is_reported_as_unhealthy_without_a_write_probe() {
        let storage = FlakyStorage::new();
        storage.set_fail_read(true);

        let report = storage
            .check_health_with(&StorageHealthCheckOptions {
                probe_writes: true,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(report.state, StorageHealthState::Unhealthy);
        assert!(!report.read_ok);
        assert_eq!(report.write_probe_ok, None);
        assert!(report
            .details
            .iter()
            .any(|d| d.contains("read probe failed") && d.contains("injected read failure")));
        assert!(storage.get_subscriptions().is_err());
    }

    #[test]
    fn a_failed_write_probe_leaves_no_subscription_behind() {
        let storage = FlakyStorage::new();
        storage.set_fail_write(true);

        let report = storage
            .check_health_with(&StorageHealthCheckOptions {
                probe_writes: true,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(report.state, StorageHealthState::Unhealthy);
        assert_eq!(report.write_probe_ok, Some(false));
        assert!(report
            .details
            .iter()
            .any(|d| d.contains("write probe failed")));
        assert!(
            storage.inner.get_subscriptions().unwrap().is_empty(),
            "a failed probe must not leave partial state"
        );
    }

    #[test]
    fn a_failed_cleanup_is_actionable() {
        let storage = FlakyStorage::new();
        storage.set_fail_cleanup(true);

        let report = storage
            .check_health_with(&StorageHealthCheckOptions {
                probe_writes: true,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(report.state, StorageHealthState::Unhealthy);
        assert_eq!(report.write_probe_ok, Some(true));
        assert!(report.details.iter().any(|d| d.contains("cleanup failed")));
        // The sentinel is still visible; the error tells the operator which
        // key to remove rather than failing silently.
        assert!(report.summary().contains("cleanup failed"));
    }

    #[test]
    fn exceeding_the_latency_budget_degrades_the_report() {
        let storage = FlakyStorage::new();
        storage.set_slow_read(true);

        let report = storage
            .check_health_with(&StorageHealthCheckOptions {
                max_latency_ms: 1,
                probe_writes: false,
            })
            .unwrap();

        assert_eq!(report.state, StorageHealthState::Degraded);
        assert!(report.read_ok, "the read itself succeeded");
        assert!(report.details.iter().any(|d| d.contains("1ms budget")));
    }

    #[test]
    fn sqlite_probe_reports_that_durability_cannot_be_verified() {
        let storage = SqliteStorage::new(":memory:").unwrap();
        let report = storage
            .check_health_with(&StorageHealthCheckOptions {
                probe_writes: true,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(report.backend, "sqlite");
        assert_eq!(report.state, StorageHealthState::Degraded);
        assert_eq!(report.write_probe_ok, None);
        assert!(report.details.iter().any(|d| d.contains("placeholder")));
    }
}

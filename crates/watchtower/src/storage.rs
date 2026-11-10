//! # Storage Module
//!
//! Persistent storage backends for the watchtower.

use crate::justice::JusticeTxStatus;
use crate::monitor::{ChannelMonitorState, ChannelUpdate};
use crate::Alert;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, info};

/// Persisted record of a watchtower justice action written prior to submission (#368).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JusticeActionRecord {
    /// Deterministic action identifier `(channel_id, breach_tx_hash)` for idempotency.
    pub action_id: String,
    /// Target channel ID.
    pub channel_id: String,
    /// Offending breach transaction hash.
    pub breach_tx_hash: String,
    /// Justice transaction hash generated for submission.
    pub tx_hash: String,
    /// Current lifecycle status.
    pub status: JusticeTxStatus,
    /// Creation Unix timestamp.
    pub created_at: u64,
    /// Last status update Unix timestamp.
    pub updated_at: u64,
    /// Number of submission/storage attempts.
    pub attempts: u32,
}

/// Health check result for a watchtower storage backend (#375).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageHealth {
    /// Whether the backend passed read/write availability checks.
    pub healthy: bool,
    /// Backend identifier (`in_memory`, `sqlite`, etc.).
    pub backend: String,
    /// Measured check latency in milliseconds.
    pub latency_ms: u64,
    /// Diagnostic summary.
    pub details: String,
}

/// Retry policy for transient storage errors (#369).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum retry attempts after an initial failure.
    pub max_retries: u32,
    /// Initial backoff delay in milliseconds (doubles per attempt).
    pub base_backoff_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            max_retries: 3,
            base_backoff_ms: 5,
        }
    }
}

/// Execute a storage closure with bounded retries on transient errors (#369).
pub fn retry_storage_op<T, F>(policy: &RetryPolicy, mut op: F) -> Result<T, StorageError>
where
    F: FnMut() -> Result<T, StorageError>,
{
    let mut attempt = 0u32;
    loop {
        match op() {
            Ok(value) => return Ok(value),
            Err(err) if err.is_transient() && attempt < policy.max_retries => {
                let shift = attempt.min(10);
                let delay_ms = policy.base_backoff_ms.saturating_mul(1u64 << shift);
                if delay_ms > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                }
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

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

/// Storage backend trait
pub trait StorageBackend: Send + Sync {
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

    /// Persist a justice action idempotently before network submission (#368, #369).
    fn store_justice_action(&self, action: &JusticeActionRecord) -> Result<(), StorageError>;

    /// Fetch a persisted justice action by its deterministic `action_id` (#368).
    fn get_justice_action(
        &self,
        action_id: &str,
    ) -> Result<Option<JusticeActionRecord>, StorageError>;

    /// List all persisted justice actions for a given channel (#368).
    fn get_justice_actions_for_channel(
        &self,
        channel_id: &str,
    ) -> Result<Vec<JusticeActionRecord>, StorageError>;

    /// Update the status of an already-persisted justice action (#368).
    fn update_justice_action_status(
        &self,
        action_id: &str,
        status: JusticeTxStatus,
    ) -> Result<(), StorageError>;

    /// Verify backend availability and responsiveness (#375).
    fn health_check(&self) -> Result<StorageHealth, StorageError>;
}

/// In-memory storage backend
pub struct InMemoryStorage {
    channel_states: parking_lot::RwLock<HashMap<String, ChannelMonitorState>>,
    channel_updates: parking_lot::RwLock<HashMap<String, ChannelUpdate>>,
    alerts: parking_lot::RwLock<Vec<Alert>>,
    subscriptions: parking_lot::RwLock<Vec<String>>,
    justice_actions: parking_lot::RwLock<HashMap<String, JusticeActionRecord>>,
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

    fn store_justice_action(&self, action: &JusticeActionRecord) -> Result<(), StorageError> {
        let mut actions = self.justice_actions.write();
        // Upsert keyed by action_id so storage retries never duplicate actions (#369).
        actions.insert(action.action_id.clone(), action.clone());
        Ok(())
    }

    fn get_justice_action(
        &self,
        action_id: &str,
    ) -> Result<Option<JusticeActionRecord>, StorageError> {
        let actions = self.justice_actions.read();
        Ok(actions.get(action_id).cloned())
    }

    fn get_justice_actions_for_channel(
        &self,
        channel_id: &str,
    ) -> Result<Vec<JusticeActionRecord>, StorageError> {
        let actions = self.justice_actions.read();
        let mut list: Vec<JusticeActionRecord> = actions
            .values()
            .filter(|a| a.channel_id == channel_id)
            .cloned()
            .collect();
        list.sort_by_key(|a| a.created_at);
        Ok(list)
    }

    fn update_justice_action_status(
        &self,
        action_id: &str,
        status: JusticeTxStatus,
    ) -> Result<(), StorageError> {
        let mut actions = self.justice_actions.write();
        let record = actions.get_mut(action_id).ok_or_else(|| {
            StorageError::QueryError(format!("justice action {} not found", action_id))
        })?;
        record.status = status;
        record.updated_at = current_timestamp();
        Ok(())
    }

    fn health_check(&self) -> Result<StorageHealth, StorageError> {
        let start = std::time::Instant::now();
        let subs = self.subscriptions.read().len();
        let actions = self.justice_actions.read().len();
        Ok(StorageHealth {
            healthy: true,
            backend: "in_memory".to_string(),
            latency_ms: start.elapsed().as_millis() as u64,
            details: format!("subscriptions={}, justice_actions={}", subs, actions),
        })
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
        if path.trim().is_empty() {
            return Err(StorageError::DatabaseError(
                "sqlite database path must not be empty".to_string(),
            ));
        }
        // In production, this would initialize SQLite connection
        Ok(SqliteStorage {
            path: path.to_string(),
        })
    }
}

impl StorageBackend for SqliteStorage {
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

    fn store_justice_action(&self, action: &JusticeActionRecord) -> Result<(), StorageError> {
        info!(
            "SQLite: persisting justice action {} for channel {}",
            action.action_id, action.channel_id
        );
        Ok(())
    }

    fn get_justice_action(
        &self,
        action_id: &str,
    ) -> Result<Option<JusticeActionRecord>, StorageError> {
        info!("SQLite: getting justice action {}", action_id);
        Ok(None)
    }

    fn get_justice_actions_for_channel(
        &self,
        channel_id: &str,
    ) -> Result<Vec<JusticeActionRecord>, StorageError> {
        info!("SQLite: listing justice actions for {}", channel_id);
        Ok(Vec::new())
    }

    fn update_justice_action_status(
        &self,
        action_id: &str,
        status: JusticeTxStatus,
    ) -> Result<(), StorageError> {
        info!(
            "SQLite: updating justice action {} to {:?}",
            action_id, status
        );
        Ok(())
    }

    fn health_check(&self) -> Result<StorageHealth, StorageError> {
        let start = std::time::Instant::now();
        if self.path.trim().is_empty() {
            return Err(StorageError::DatabaseError(
                "sqlite path is empty".to_string(),
            ));
        }
        Ok(StorageHealth {
            healthy: true,
            backend: "sqlite".to_string(),
            latency_ms: start.elapsed().as_millis() as u64,
            details: format!("path={}", self.path),
        })
    }
}

/// Seconds since the Unix epoch.
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

    #[error("Transient storage error: {0}")]
    TransientError(String),
}

impl StorageError {
    /// Whether this error is transient and safe to retry idempotently (#369).
    pub fn is_transient(&self) -> bool {
        matches!(self, StorageError::TransientError(_))
    }
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

    struct FlakyJusticeStorage {
        inner: InMemoryStorage,
        remaining_transient_failures: parking_lot::Mutex<u32>,
    }

    impl FlakyJusticeStorage {
        fn new(failures: u32) -> Self {
            FlakyJusticeStorage {
                inner: InMemoryStorage::new(),
                remaining_transient_failures: parking_lot::Mutex::new(failures),
            }
        }
    }

    impl StorageBackend for FlakyJusticeStorage {
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
            self.inner.store_subscription(channel_id)
        }

        fn get_subscriptions(&self) -> Result<Vec<String>, StorageError> {
            self.inner.get_subscriptions()
        }

        fn remove_subscription(&self, channel_id: &str) -> Result<(), StorageError> {
            self.inner.remove_subscription(channel_id)
        }

        fn compact(&self, policy: &CompactionPolicy) -> Result<CompactionReport, StorageError> {
            self.inner.compact(policy)
        }

        fn store_justice_action(&self, action: &JusticeActionRecord) -> Result<(), StorageError> {
            let mut rem = self.remaining_transient_failures.lock();
            if *rem > 0 {
                *rem -= 1;
                return Err(StorageError::TransientError(
                    "temporary lock timeout".to_string(),
                ));
            }
            self.inner.store_justice_action(action)
        }

        fn get_justice_action(
            &self,
            action_id: &str,
        ) -> Result<Option<JusticeActionRecord>, StorageError> {
            self.inner.get_justice_action(action_id)
        }

        fn get_justice_actions_for_channel(
            &self,
            channel_id: &str,
        ) -> Result<Vec<JusticeActionRecord>, StorageError> {
            self.inner.get_justice_actions_for_channel(channel_id)
        }

        fn update_justice_action_status(
            &self,
            action_id: &str,
            status: JusticeTxStatus,
        ) -> Result<(), StorageError> {
            self.inner.update_justice_action_status(action_id, status)
        }

        fn health_check(&self) -> Result<StorageHealth, StorageError> {
            self.inner.health_check()
        }
    }

    #[test]
    fn storage_retry_handles_transient_failures_without_duplicates() {
        let storage = FlakyJusticeStorage::new(2);
        let policy = RetryPolicy {
            max_retries: 3,
            base_backoff_ms: 1,
        };
        let record = JusticeActionRecord {
            action_id: "ch1:breach_1".to_string(),
            channel_id: "ch1".to_string(),
            breach_tx_hash: "breach_1".to_string(),
            tx_hash: "justice_ch1_100".to_string(),
            status: JusticeTxStatus::Pending,
            created_at: 100,
            updated_at: 100,
            attempts: 1,
        };

        retry_storage_op(&policy, || storage.store_justice_action(&record))
            .expect("should succeed on 3rd attempt");

        // Re-running must remain idempotent with exactly 1 persisted action.
        retry_storage_op(&policy, || storage.store_justice_action(&record))
            .expect("idempotent retry should succeed");

        let actions = storage.get_justice_actions_for_channel("ch1").unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action_id, "ch1:breach_1");
    }

    #[test]
    fn storage_retry_stops_when_budget_exhausted() {
        let storage = FlakyJusticeStorage::new(5);
        let policy = RetryPolicy {
            max_retries: 2,
            base_backoff_ms: 1,
        };
        let record = JusticeActionRecord {
            action_id: "ch1:breach_2".to_string(),
            channel_id: "ch1".to_string(),
            breach_tx_hash: "breach_2".to_string(),
            tx_hash: "justice_ch1_200".to_string(),
            status: JusticeTxStatus::Pending,
            created_at: 200,
            updated_at: 200,
            attempts: 1,
        };

        let err = retry_storage_op(&policy, || storage.store_justice_action(&record)).unwrap_err();
        assert!(err.is_transient());
        assert!(storage
            .get_justice_actions_for_channel("ch1")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn storage_health_checks_report_status_for_backends() {
        let mem = InMemoryStorage::new();
        let mem_health = mem.health_check().unwrap();
        assert!(mem_health.healthy);
        assert_eq!(mem_health.backend, "in_memory");

        let sqlite = SqliteStorage::new(":memory:").unwrap();
        let sqlite_health = sqlite.health_check().unwrap();
        assert!(sqlite_health.healthy);
        assert_eq!(sqlite_health.backend, "sqlite");

        assert!(SqliteStorage::new("   ").is_err());
    }
}

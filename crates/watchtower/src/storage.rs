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

    // ── Retryable alert delivery persistence (issue #373) ────────────────────

    /// Persist a new alert delivery record before attempting delivery.
    fn store_alert_delivery(
        &self,
        delivery: &crate::alert::AlertDelivery,
    ) -> Result<(), StorageError>;

    /// Retrieve an alert delivery record by its [`crate::alert::DeliveryId`].
    fn get_alert_delivery(
        &self,
        delivery_id: &str,
    ) -> Result<Option<crate::alert::AlertDelivery>, StorageError>;

    /// Retrieve all alert deliveries in [`crate::alert::DeliveryStatus::Pending`].
    fn get_pending_alert_deliveries(
        &self,
    ) -> Result<Vec<crate::alert::AlertDelivery>, StorageError>;

    /// Persist an updated alert delivery record (attempts, status, backoff).
    fn update_alert_delivery(
        &self,
        delivery: &crate::alert::AlertDelivery,
    ) -> Result<(), StorageError>;
}

/// In-memory storage backend
pub struct InMemoryStorage {
    channel_states: parking_lot::RwLock<HashMap<String, ChannelMonitorState>>,
    channel_updates: parking_lot::RwLock<HashMap<String, ChannelUpdate>>,
    alerts: parking_lot::RwLock<Vec<Alert>>,
    subscriptions: parking_lot::RwLock<Vec<String>>,
    /// Justice action records, keyed by action ID (issue #368).
    justice_actions:
        parking_lot::RwLock<HashMap<String, crate::justice::JusticeAction>>,
    /// Alert delivery records, keyed by delivery ID (issue #373).
    alert_deliveries:
        parking_lot::RwLock<HashMap<String, crate::alert::AlertDelivery>>,
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
            alert_deliveries: parking_lot::RwLock::new(HashMap::new()),
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

    fn store_alert_delivery(
        &self,
        delivery: &crate::alert::AlertDelivery,
    ) -> Result<(), StorageError> {
        let mut deliveries = self.alert_deliveries.write();
        let key = delivery.delivery_id.as_str();
        if deliveries.contains_key(key) {
            return Err(StorageError::QueryError(format!(
                "alert delivery {key} already exists"
            )));
        }
        deliveries.insert(key.to_string(), delivery.clone());
        Ok(())
    }

    fn get_alert_delivery(
        &self,
        delivery_id: &str,
    ) -> Result<Option<crate::alert::AlertDelivery>, StorageError> {
        let deliveries = self.alert_deliveries.read();
        Ok(deliveries.get(delivery_id).cloned())
    }

    fn get_pending_alert_deliveries(
        &self,
    ) -> Result<Vec<crate::alert::AlertDelivery>, StorageError> {
        let deliveries = self.alert_deliveries.read();
        let mut pending: Vec<_> = deliveries
            .values()
            .filter(|d| d.status == crate::alert::DeliveryStatus::Pending)
            .cloned()
            .collect();
        pending.sort_by_key(|d| (d.next_retry_at, d.created_at));
        Ok(pending)
    }

    fn update_alert_delivery(
        &self,
        delivery: &crate::alert::AlertDelivery,
    ) -> Result<(), StorageError> {
        let mut deliveries = self.alert_deliveries.write();
        let key = delivery.delivery_id.as_str();
        let slot = deliveries.get_mut(key).ok_or_else(|| {
            StorageError::QueryError(format!("alert delivery {key} not found"))
        })?;
        *slot = delivery.clone();
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

    fn store_alert_delivery(
        &self,
        delivery: &crate::alert::AlertDelivery,
    ) -> Result<(), StorageError> {
        info!("SQLite: storing alert delivery {}", delivery.delivery_id);
        Ok(())
    }

    fn get_alert_delivery(
        &self,
        delivery_id: &str,
    ) -> Result<Option<crate::alert::AlertDelivery>, StorageError> {
        info!("SQLite: getting alert delivery {}", delivery_id);
        Ok(None)
    }

    fn get_pending_alert_deliveries(
        &self,
    ) -> Result<Vec<crate::alert::AlertDelivery>, StorageError> {
        info!("SQLite: getting pending alert deliveries");
        Ok(Vec::new())
    }

    fn update_alert_delivery(
        &self,
        delivery: &crate::alert::AlertDelivery,
    ) -> Result<(), StorageError> {
        info!(
            "SQLite: updating alert delivery {} to {:?} (attempts={})",
            delivery.delivery_id, delivery.status, delivery.attempts
        );
        Ok(())
    }
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

    #[test]
    fn alert_delivery_store_update_and_pending_query() {
        let storage = InMemoryStorage::new();
        let alert = Alert::breach_attempt("channel-dlv".to_string(), 1, 2);
        let dest = "https://hooks.example.com/alerts";
        let delivery_id = crate::alert::DeliveryId::for_alert(&alert.id, dest).unwrap();
        let mut delivery =
            crate::alert::AlertDelivery::new(delivery_id.clone(), alert, dest, 3, 100).unwrap();

        storage.store_alert_delivery(&delivery).unwrap();
        assert!(storage.store_alert_delivery(&delivery).is_err());
        assert_eq!(storage.get_pending_alert_deliveries().unwrap().len(), 1);

        delivery.mark_delivered(101);
        storage.update_alert_delivery(&delivery).unwrap();
        assert!(storage.get_pending_alert_deliveries().unwrap().is_empty());

        let loaded = storage
            .get_alert_delivery(delivery_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(loaded.status, crate::alert::DeliveryStatus::Delivered);
        assert_eq!(loaded.attempts, 1);
    }
}

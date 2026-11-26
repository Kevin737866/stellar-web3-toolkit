//! Integration tests for storage health checks and the justice recovery path.
//!
//! A watchtower that cannot read from or write to its storage backend cannot
//! be trusted to protect channel state. These tests exercise the full flow:
//! detect an unhealthy backend, alert the operator, keep durable justice
//! actions intact, and replay them once the backend recovers.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use watchtower::justice::{ActionStatus, BreachEvidence, JusticeAction};
use watchtower::monitor::{ChannelMonitorState, ChannelUpdate};
use watchtower::storage::{
    CompactionPolicy, CompactionReport, InMemoryStorage, StorageBackend, StorageError,
    StorageHealthCheckOptions, StorageHealthState,
};
use watchtower::{Alert, AlertType, Watchtower, WatchtowerConfig, WatchtowerError};

/// A backend whose reads or writes can be made to fail on demand. All other
/// operations delegate to a real in-memory store so the tests isolate health
/// probe behaviour from unrelated storage logic.
struct FailingStorage {
    inner: InMemoryStorage,
    fail_read: AtomicBool,
    fail_write: AtomicBool,
}

impl FailingStorage {
    fn new() -> Self {
        FailingStorage {
            inner: InMemoryStorage::new(),
            fail_read: AtomicBool::new(false),
            fail_write: AtomicBool::new(false),
        }
    }

    fn set_fail_read(&self, value: bool) {
        self.fail_read.store(value, Ordering::SeqCst);
    }

    fn set_fail_write(&self, value: bool) {
        self.fail_write.store(value, Ordering::SeqCst);
    }
}

/// Coerce the concrete backend to the trait object expected by `Watchtower`.
fn shared(storage: &Arc<FailingStorage>) -> Arc<dyn StorageBackend> {
    let concrete: Arc<FailingStorage> = Arc::clone(storage);
    concrete
}

impl StorageBackend for FailingStorage {
    fn backend_name(&self) -> &'static str {
        "failing-test-backend"
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

    fn get_channel_update(&self, channel_id: &str) -> Result<Option<ChannelUpdate>, StorageError> {
        self.inner.get_channel_update(channel_id)
    }

    fn store_subscription(&self, channel_id: &str) -> Result<(), StorageError> {
        if self.fail_write.load(Ordering::SeqCst) {
            return Err(StorageError::DatabaseError(
                "injected write failure".to_string(),
            ));
        }
        self.inner.store_subscription(channel_id)
    }

    fn get_subscriptions(&self) -> Result<Vec<String>, StorageError> {
        if self.fail_read.load(Ordering::SeqCst) {
            return Err(StorageError::DatabaseError(
                "injected read failure".to_string(),
            ));
        }
        self.inner.get_subscriptions()
    }

    fn remove_subscription(&self, channel_id: &str) -> Result<(), StorageError> {
        self.inner.remove_subscription(channel_id)
    }

    fn compact(&self, policy: &CompactionPolicy) -> Result<CompactionReport, StorageError> {
        self.inner.compact(policy)
    }

    fn store_justice_action(&self, action: &JusticeAction) -> Result<(), StorageError> {
        self.inner.store_justice_action(action)
    }

    fn get_justice_action(&self, id: &str) -> Result<Option<JusticeAction>, StorageError> {
        self.inner.get_justice_action(id)
    }

    fn get_pending_justice_actions(&self) -> Result<Vec<JusticeAction>, StorageError> {
        self.inner.get_pending_justice_actions()
    }

    fn update_justice_action_status(
        &self,
        id: &str,
        status: watchtower::justice::ActionStatus,
        tx_hash: Option<&str>,
    ) -> Result<(), StorageError> {
        self.inner.update_justice_action_status(id, status, tx_hash)
    }
}

fn probe_options() -> StorageHealthCheckOptions {
    StorageHealthCheckOptions {
        max_latency_ms: 1_000,
        probe_writes: true,
    }
}

fn config() -> WatchtowerConfig {
    WatchtowerConfig {
        storage_health_check: probe_options(),
        ..Default::default()
    }
}

fn pending_action() -> JusticeAction {
    JusticeAction::new(
        "recovery-action",
        BreachEvidence {
            channel_id: "channel-a".to_string(),
            breach_tx_hash: "breach-tx".to_string(),
            detected_at: 1_000,
            old_sequence: 1,
            new_sequence: 2,
            total_balance: 2_000,
        },
    )
}

fn health_alerts(watchtower: &Watchtower) -> Vec<String> {
    watchtower
        .get_alerts(100)
        .into_iter()
        .filter_map(|alert| match alert.alert_type {
            AlertType::HealthCheckFailed { component, error } => {
                assert_eq!(component, "storage");
                Some(error)
            }
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn health_probe_alerts_and_preserves_pending_justice_until_recovery() {
    let storage = Arc::new(FailingStorage::new());
    storage.set_fail_read(true);
    let watchtower = Watchtower::with_storage(config(), shared(&storage)).unwrap();

    // A durable, retryable action must survive an unhealthy storage report.
    watchtower.subscribe("channel-a".to_string()).unwrap();
    storage.store_justice_action(&pending_action()).unwrap();

    let unhealthy = watchtower.check_storage_health().unwrap();
    assert_eq!(unhealthy.state, StorageHealthState::Unhealthy);
    assert!(!unhealthy.read_ok);
    assert_eq!(unhealthy.write_probe_ok, None);
    assert!(unhealthy
        .details
        .iter()
        .any(|detail| detail.contains("injected read failure")));

    let alerts = health_alerts(&watchtower);
    assert_eq!(alerts.len(), 1, "an unhealthy backend must raise an alert");
    assert!(alerts[0].contains("unhealthy"));
    assert!(!watchtower.last_storage_health().unwrap().is_healthy());

    assert_eq!(storage.get_pending_justice_actions().unwrap().len(), 1);
    assert_eq!(
        storage.inner.get_subscriptions().unwrap(),
        vec!["channel-a"]
    );

    // Operator recovery: the backend comes back, a new probe is healthy, and
    // the previously persisted action can now be replayed exactly once.
    storage.set_fail_read(false);
    let healthy = watchtower.check_storage_health().unwrap();
    assert_eq!(healthy.state, StorageHealthState::Healthy);
    assert_eq!(healthy.write_probe_ok, Some(true));
    assert_eq!(health_alerts(&watchtower).len(), 1, "old alert is retained");
    assert_eq!(
        storage.inner.get_subscriptions().unwrap(),
        vec!["channel-a"]
    );

    let submitted = watchtower.retry_pending_justice().await;
    assert_eq!(submitted, 1);
    assert!(storage.get_pending_justice_actions().unwrap().is_empty());
    let action = storage
        .get_justice_action("recovery-action")
        .unwrap()
        .expect("the retry must keep the durable action record");
    assert_eq!(action.status, ActionStatus::Submitted);
    assert!(action.tx_hash.is_some());
}

#[test]
fn a_failed_write_probe_does_not_disturb_real_data() {
    let storage = Arc::new(FailingStorage::new());
    storage.set_fail_write(true);
    let watchtower = Watchtower::with_storage(config(), shared(&storage)).unwrap();
    storage.store_justice_action(&pending_action()).unwrap();

    let report = watchtower.check_storage_health().unwrap();
    assert_eq!(report.state, StorageHealthState::Unhealthy);
    assert_eq!(report.write_probe_ok, Some(false));
    assert!(report
        .details
        .iter()
        .any(|d| d.contains("write probe failed")));

    assert!(
        storage.inner.get_subscriptions().unwrap().is_empty(),
        "the sentinel subscription must be cleaned up on failure"
    );
    assert_eq!(storage.get_pending_justice_actions().unwrap().len(), 1);
    assert_eq!(health_alerts(&watchtower).len(), 1);
}

#[test]
fn invalid_options_are_rejected_without_partial_updates() {
    let storage = Arc::new(FailingStorage::new());
    let watchtower = Watchtower::with_storage(config(), shared(&storage)).unwrap();
    storage.store_justice_action(&pending_action()).unwrap();

    let error = watchtower
        .check_storage_health_with(&StorageHealthCheckOptions {
            max_latency_ms: 0,
            probe_writes: true,
        })
        .unwrap_err();
    assert!(matches!(error, WatchtowerError::InvalidConfiguration(_)));
    assert!(error.to_string().contains("max_latency_ms"));

    assert!(watchtower.last_storage_health().is_none());
    assert!(health_alerts(&watchtower).is_empty());
    assert_eq!(storage.get_pending_justice_actions().unwrap().len(), 1);
    assert!(storage.inner.get_subscriptions().unwrap().is_empty());

    // A valid check still works and leaves no diagnostics behind.
    assert!(watchtower.check_storage_health().unwrap().is_healthy());
    assert!(health_alerts(&watchtower).is_empty());
}

#[tokio::test]
async fn the_monitor_loop_reports_unhealthy_storage() {
    let storage = Arc::new(FailingStorage::new());
    storage.set_fail_read(true);
    let watchtower = Watchtower::with_storage(
        WatchtowerConfig {
            storage_health_check_interval_secs: 1,
            ..config()
        },
        shared(&storage),
    )
    .unwrap();

    watchtower.start().await.unwrap();
    // The loop probes immediately on its first iteration, before sleeping.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    watchtower.stop();

    let alerts = health_alerts(&watchtower);
    assert_eq!(alerts.len(), 1, "the monitor loop must alert on failure");
    assert!(alerts[0].contains("unhealthy"));
}

//! Integration tests for duplicate breach notifications (issue #376).

use std::sync::Arc;
use watchtower::justice::{JusticeAction, JusticeError, JusticeService};
use watchtower::monitor::BreachAttempt;
use watchtower::storage::{InMemoryStorage, StorageBackend};
use watchtower::{Alert, Watchtower, WatchtowerConfig};

fn sample_breach(channel_id: &str, tx_hash: &str) -> BreachAttempt {
    BreachAttempt {
        channel_id: channel_id.to_string(),
        old_sequence: 4,
        new_sequence: 9,
        old_balance_a: 1_000,
        old_balance_b: 500,
        new_balance_a: 1_300,
        new_balance_b: 200,
        breach_tx_hash: tx_hash.to_string(),
        detected_at: 1_700_000_000,
    }
}

#[tokio::test]
async fn duplicate_breach_notifications_are_deduplicated_across_alerts_and_justice() {
    let watchtower = Watchtower::new(WatchtowerConfig::default()).unwrap();
    let storage = Arc::clone(watchtower.storage());
    let justice = JusticeService::new(
        "http://localhost".to_string(),
        "Test SDF Network ; September 2015".to_string(),
        100_000,
        storage,
    );

    let breach = sample_breach("ch-dup-integration", "tx-breach-1");

    // First notification: alert is recorded and justice tx is submitted.
    assert!(watchtower.state().add_alert_dedup(Alert::breach_attempt(
        breach.channel_id.clone(),
        breach.old_sequence,
        breach.new_sequence,
    )));
    let first_tx = justice.submit_justice(&breach).await.unwrap();
    assert_eq!(first_tx.channel_id, "ch-dup-integration");

    // Duplicate notification: alert is suppressed and justice submission fails cleanly.
    assert!(!watchtower.state().add_alert_dedup(Alert::breach_attempt(
        breach.channel_id.clone(),
        breach.old_sequence,
        breach.new_sequence,
    )));
    let dup_err = justice.submit_justice(&breach).await.unwrap_err();
    assert!(matches!(dup_err, JusticeError::DuplicateBreach { .. }));

    assert_eq!(watchtower.get_alerts(10).len(), 1);
    assert_eq!(justice.get_pending().len(), 1);
}

#[tokio::test]
async fn invalid_breach_does_not_block_subsequent_valid_breach_notification() {
    let storage = Arc::new(InMemoryStorage::new());
    let justice = JusticeService::new(
        "http://localhost".to_string(),
        "Test SDF Network ; September 2015".to_string(),
        100_000,
        Arc::clone(&storage) as Arc<dyn StorageBackend>,
    );

    let mut invalid = sample_breach("ch-recovery", "tx-breach-2");
    invalid.new_balance_a = 9_999; // violates conservation
    let err = justice.submit_justice(&invalid).await.unwrap_err();
    assert!(matches!(err, JusticeError::InvalidBreach(_)));
    assert!(storage.get_pending_justice_actions().unwrap().is_empty());

    let valid = sample_breach("ch-recovery", "tx-breach-2");
    let tx = justice.submit_justice(&valid).await.unwrap();
    assert_eq!(tx.channel_id, "ch-recovery");
    assert_eq!(justice.get_pending().len(), 1);
}

#[tokio::test]
async fn pending_action_blocks_duplicate_notification_until_operator_recovery() {
    let storage = Arc::new(InMemoryStorage::new());
    let justice = JusticeService::new(
        "http://localhost".to_string(),
        "Test SDF Network ; September 2015".to_string(),
        100_000,
        Arc::clone(&storage) as Arc<dyn StorageBackend>,
    );

    let breach = sample_breach("ch-pending", "tx-breach-3");
    let evidence = justice.validate_breach(&breach).unwrap();
    storage
        .store_justice_action(&JusticeAction::new("pending-op-1", evidence))
        .unwrap();

    // Duplicate notification while Pending exists is rejected.
    let err = justice.submit_justice(&breach).await.unwrap_err();
    assert!(matches!(err, JusticeError::DuplicateBreach { .. }));
    assert_eq!(storage.get_pending_justice_actions().unwrap().len(), 1);

    // Operator recovery replays the single Pending action.
    assert_eq!(justice.retry_pending_actions().await, 1);
    assert!(storage.get_pending_justice_actions().unwrap().is_empty());
    assert_eq!(justice.get_pending().len(), 1);
}

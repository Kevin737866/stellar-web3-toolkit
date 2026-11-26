//! Integration tests for operator key and data recovery (issue #377).
//!
//! These exercise the full workflow through the public API: export a signed
//! bundle from a running node, restore it onto a fresh backend, and replay the
//! pending justice action. They also pin the failure paths that must leave the
//! recovery target untouched.

use std::sync::Arc;

use watchtower::justice::{ActionStatus, BreachEvidence, JusticeAction};
use watchtower::monitor::ChannelUpdate;
use watchtower::recovery::{OperatorKey, RecoveryBundle};
use watchtower::storage::{InMemoryStorage, StorageBackend};
use watchtower::{Alert, Watchtower, WatchtowerConfig, WatchtowerError};

fn config() -> WatchtowerConfig {
    WatchtowerConfig {
        network_passphrase: "recovery test network".to_string(),
        ..WatchtowerConfig::default()
    }
}

fn pending_action() -> JusticeAction {
    JusticeAction::new(
        "action-1",
        BreachEvidence {
            channel_id: "channel-a".to_string(),
            breach_tx_hash: "breach-tx".to_string(),
            detected_at: 1_000,
            old_sequence: 1,
            new_sequence: 4,
            total_balance: 2_000,
        },
    )
}

fn source_watchtower() -> Watchtower {
    let watchtower = Watchtower::with_storage(config(), Arc::new(InMemoryStorage::new())).unwrap();
    watchtower.subscribe("channel-a".to_string()).unwrap();

    watchtower.state().update_channel_state(
        "channel-a",
        ChannelUpdate {
            channel_id: "channel-a".to_string(),
            sequence_number: 4,
            balance_a: 1_000,
            balance_b: 1_000,
            is_closed: false,
            close_type: None,
            block_height: 100,
            timestamp: 1_000,
        },
    );
    watchtower
        .storage()
        .store_justice_action(&pending_action())
        .unwrap();
    watchtower
        .storage()
        .store_alert(&Alert::justice_submitted(
            "channel-a".to_string(),
            "justice_channel-a_1000".to_string(),
        ))
        .unwrap();
    watchtower
}

#[tokio::test]
async fn a_signed_bundle_restores_state_and_retry_safety() {
    let key = OperatorKey::generate();
    let source = source_watchtower();
    let bundle = source.export_recovery_bundle(&key).unwrap();

    bundle.verify(&key).unwrap();
    assert_eq!(bundle.payload.subscriptions, vec!["channel-a".to_string()]);
    assert_eq!(bundle.payload.channel_states.len(), 1);
    assert_eq!(bundle.payload.channel_updates.len(), 1);
    assert_eq!(bundle.payload.alerts.len(), 1);
    assert_eq!(bundle.payload.justice_actions.len(), 1);

    let target: Arc<dyn StorageBackend> = Arc::new(InMemoryStorage::new());
    let restored =
        Watchtower::restore_from_bundle_with_storage(config(), &key, &bundle, Arc::clone(&target))
            .unwrap();

    assert_eq!(
        restored.persisted_subscriptions().unwrap(),
        vec!["channel-a".to_string()]
    );
    assert_eq!(restored.status().channels_monitored, 1);
    assert_eq!(restored.get_alerts(10).len(), 1);
    assert_eq!(
        target
            .get_channel_update("channel-a")
            .unwrap()
            .unwrap()
            .sequence_number,
        4
    );

    let pending = restored.pending_justice_actions().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].status, ActionStatus::Pending);
    assert_eq!(pending[0].attempts, 0);

    assert_eq!(restored.retry_pending_justice().await, 1);
    let stored = target.get_justice_action("action-1").unwrap().unwrap();
    assert_eq!(stored.status, ActionStatus::Submitted);
    assert!(stored.tx_hash.is_some());
    assert_eq!(target.get_all_justice_actions().unwrap().len(), 1);
    assert!(restored.pending_justice_actions().unwrap().is_empty());
}

#[test]
fn a_tampered_bundle_is_rejected_without_writing_to_the_target() {
    let key = OperatorKey::generate();
    let mut bundle = source_watchtower().export_recovery_bundle(&key).unwrap();
    bundle.payload.subscriptions.push("channel-b".to_string());

    let target: Arc<dyn StorageBackend> = Arc::new(InMemoryStorage::new());
    let error =
        Watchtower::restore_from_bundle_with_storage(config(), &key, &bundle, Arc::clone(&target))
            .err()
            .expect("restore should be rejected");

    assert!(matches!(
        &error,
        WatchtowerError::InvalidConfiguration(reason) if reason.contains("signature")
    ));
    assert!(target.get_subscriptions().unwrap().is_empty());
    assert!(target.get_all_justice_actions().unwrap().is_empty());
}

#[test]
fn a_wrong_operator_key_is_rejected_without_writing_to_the_target() {
    let key = OperatorKey::generate();
    let bundle = source_watchtower().export_recovery_bundle(&key).unwrap();
    let wrong_key = OperatorKey::generate();

    let target: Arc<dyn StorageBackend> = Arc::new(InMemoryStorage::new());
    let error = Watchtower::restore_from_bundle_with_storage(
        config(),
        &wrong_key,
        &bundle,
        Arc::clone(&target),
    )
    .err()
    .expect("restore should be rejected");

    assert!(matches!(
        &error,
        WatchtowerError::InvalidConfiguration(reason) if reason.contains("signature")
    ));
    assert!(target.get_subscriptions().unwrap().is_empty());
}

#[test]
fn a_bundle_for_another_network_is_rejected() {
    let key = OperatorKey::generate();
    let bundle = source_watchtower().export_recovery_bundle(&key).unwrap();
    let mut other_config = config();
    other_config.network_passphrase = "another network".to_string();

    let target: Arc<dyn StorageBackend> = Arc::new(InMemoryStorage::new());
    let error = Watchtower::restore_from_bundle_with_storage(
        other_config,
        &key,
        &bundle,
        Arc::clone(&target),
    )
    .err()
    .expect("restore should be rejected");

    assert!(matches!(
        &error,
        WatchtowerError::InvalidConfiguration(reason) if reason.contains("network")
    ));
    assert!(target.get_subscriptions().unwrap().is_empty());
}

#[test]
fn a_non_empty_recovery_target_is_refused() {
    let key = OperatorKey::generate();
    let bundle = source_watchtower().export_recovery_bundle(&key).unwrap();
    let target: Arc<dyn StorageBackend> = Arc::new(InMemoryStorage::new());
    target.store_subscription("existing-channel").unwrap();

    let error =
        Watchtower::restore_from_bundle_with_storage(config(), &key, &bundle, Arc::clone(&target))
            .err()
            .expect("restore should be rejected");

    assert!(matches!(
        &error,
        WatchtowerError::StorageError(reason) if reason.contains("fresh")
    ));
    assert_eq!(
        target.get_subscriptions().unwrap(),
        vec!["existing-channel".to_string()]
    );
}

#[test]
fn a_rotated_key_restores_the_same_bundle() {
    let old_key = OperatorKey::generate();
    let new_key = OperatorKey::generate();
    let source = source_watchtower();
    let mut bundle: RecoveryBundle = source.export_recovery_bundle(&old_key).unwrap();

    bundle.resign(&old_key, &new_key).unwrap();

    let restored = Watchtower::restore_from_bundle_with_storage(
        config(),
        &new_key,
        &bundle,
        Arc::new(InMemoryStorage::new()),
    )
    .unwrap();
    assert_eq!(
        restored.persisted_subscriptions().unwrap(),
        vec!["channel-a".to_string()]
    );
    assert_eq!(restored.pending_justice_actions().unwrap().len(), 1);

    let wrong = Watchtower::restore_from_bundle_with_storage(
        config(),
        &old_key,
        &bundle,
        Arc::new(InMemoryStorage::new()),
    );
    assert!(matches!(
        wrong,
        Err(WatchtowerError::InvalidConfiguration(_))
    ));
}

#[test]
fn restore_without_a_callers_backend_uses_the_configured_store() {
    let key = OperatorKey::generate();
    let bundle = source_watchtower().export_recovery_bundle(&key).unwrap();

    let restored = Watchtower::restore_from_bundle(config(), &key, &bundle).unwrap();

    assert_eq!(restored.status().channels_monitored, 1);
    assert_eq!(restored.pending_justice_actions().unwrap().len(), 1);
}

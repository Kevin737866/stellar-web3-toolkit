//! Integration tests for encrypted watchtower state retention limits (#372).
//!
//! These tests exercise the full retention workflow end-to-end: justice
//! actions are written through the public `StorageBackend` API, a compaction
//! pass is applied through `Watchtower::compact_storage`, and the resulting
//! state is inspected to confirm the invariants hold.
//!
//! Invariants under test:
//! - Finalised actions (Submitted / Confirmed / Failed) expire by age and by
//!   count when limits are configured.
//! - Pending actions are never dropped by any retention pass, regardless of
//!   age or how many finalised records are present.
//! - After compaction the `CompactionReport` correctly reflects what was
//!   removed, and `is_noop()` returns `true` only when nothing changed.
//! - The `Watchtower` statistics counter `records_compacted` is updated to
//!   include justice action removals.

use std::sync::Arc;
use watchtower::{
    storage::{CompactionPolicy, InMemoryStorage, StorageBackend},
    Watchtower, WatchtowerConfig,
};
use watchtower::justice::{ActionStatus, BreachEvidence, JusticeAction};

const DAY: u64 = 24 * 60 * 60;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn evidence(channel_id: &str) -> BreachEvidence {
    BreachEvidence {
        channel_id: channel_id.to_string(),
        breach_tx_hash: "btx123".to_string(),
        detected_at: 1_000_000,
        old_sequence: 1,
        new_sequence: 3,
        total_balance: 10_000,
    }
}

fn submitted_action(id: &str, updated_at: u64) -> JusticeAction {
    let mut action = JusticeAction::new(id, evidence("channel-a"));
    action.status = ActionStatus::Submitted;
    action.tx_hash = Some(format!("tx_{id}"));
    action.updated_at = updated_at;
    action
}

fn confirmed_action(id: &str, updated_at: u64) -> JusticeAction {
    let mut action = submitted_action(id, updated_at);
    action.status = ActionStatus::Confirmed;
    action
}

fn failed_action(id: &str, updated_at: u64) -> JusticeAction {
    let mut action = JusticeAction::new(id, evidence("channel-b"));
    action.status = ActionStatus::Failed;
    action.updated_at = updated_at;
    action
}

fn pending_action(id: &str, updated_at: u64) -> JusticeAction {
    let mut action = JusticeAction::new(id, evidence("channel-c"));
    // updated_at is set by new(); overwrite for a reproducible timestamp.
    action.updated_at = updated_at;
    action
}

// ── Age-based retention ───────────────────────────────────────────────────────

#[test]
fn age_based_retention_expires_old_finalised_actions() {
    let now = now();
    let config = WatchtowerConfig {
        compaction: CompactionPolicy {
            justice_action_retention_secs: DAY,
            ..CompactionPolicy::default()
        },
        ..Default::default()
    };
    let watchtower = Watchtower::new(config).unwrap();

    watchtower
        .storage()
        .store_justice_action(&submitted_action("stale", now - 2 * DAY))
        .unwrap();
    watchtower
        .storage()
        .store_justice_action(&submitted_action("fresh", now))
        .unwrap();

    let report = watchtower.compact_storage().unwrap();

    assert_eq!(report.justice_actions_removed(), 1, "one stale action must be removed");
    assert!(
        watchtower.storage().get_justice_action("stale").unwrap().is_none(),
        "stale action must not remain after compaction"
    );
    assert!(
        watchtower.storage().get_justice_action("fresh").unwrap().is_some(),
        "fresh action must survive compaction"
    );
}

#[test]
fn age_based_retention_handles_all_finalised_statuses() {
    // Submitted, Confirmed, and Failed must all be subject to age expiry.
    let now = now();
    let config = WatchtowerConfig {
        compaction: CompactionPolicy {
            justice_action_retention_secs: DAY,
            ..CompactionPolicy::default()
        },
        ..Default::default()
    };
    let watchtower = Watchtower::new(config).unwrap();

    watchtower
        .storage()
        .store_justice_action(&submitted_action("sub-old", now - 2 * DAY))
        .unwrap();
    watchtower
        .storage()
        .store_justice_action(&confirmed_action("con-old", now - 2 * DAY))
        .unwrap();
    watchtower
        .storage()
        .store_justice_action(&failed_action("fail-old", now - 2 * DAY))
        .unwrap();

    let report = watchtower.compact_storage().unwrap();
    assert_eq!(report.justice_actions_removed(), 3);
}

// ── Pending actions are never dropped ────────────────────────────────────────

#[test]
fn pending_actions_survive_age_based_compaction() {
    let config = WatchtowerConfig {
        compaction: CompactionPolicy {
            justice_action_retention_secs: 1, // expire anything older than 1 second
            ..CompactionPolicy::default()
        },
        ..Default::default()
    };
    let watchtower = Watchtower::new(config).unwrap();

    // Plant a Pending action with an ancient timestamp.
    watchtower
        .storage()
        .store_justice_action(&pending_action("ancient-pending", 0))
        .unwrap();

    let report = watchtower.compact_storage().unwrap();

    assert_eq!(report.justice_actions_removed(), 0, "pending action must not be removed");
    assert!(
        watchtower
            .storage()
            .get_justice_action("ancient-pending")
            .unwrap()
            .is_some(),
        "pending action must remain after compaction"
    );
}

#[test]
fn pending_actions_survive_count_based_compaction() {
    let now = now();
    let config = WatchtowerConfig {
        compaction: CompactionPolicy {
            max_justice_actions: 1,
            justice_action_retention_secs: 365 * DAY,
            ..CompactionPolicy::default()
        },
        ..Default::default()
    };
    let watchtower = Watchtower::new(config).unwrap();

    // Three finalised + one pending. The limit allows 1 finalised record.
    for i in 0..3u64 {
        watchtower
            .storage()
            .store_justice_action(&submitted_action(&format!("fin-{i}"), now - i))
            .unwrap();
    }
    watchtower
        .storage()
        .store_justice_action(&pending_action("pend", 0))
        .unwrap();

    let report = watchtower.compact_storage().unwrap();

    // Two finalised records evicted; the pending one stays.
    assert_eq!(report.justice_actions_removed(), 2);
    assert!(
        watchtower
            .storage()
            .get_justice_action("pend")
            .unwrap()
            .is_some(),
        "pending action must not be evicted by count-based compaction"
    );
}

// ── Count-based retention ─────────────────────────────────────────────────────

#[test]
fn count_based_retention_keeps_the_newest_finalised_actions() {
    let now = now();
    let config = WatchtowerConfig {
        compaction: CompactionPolicy {
            max_justice_actions: 2,
            justice_action_retention_secs: 365 * DAY,
            ..CompactionPolicy::default()
        },
        ..Default::default()
    };
    let watchtower = Watchtower::new(config).unwrap();

    // Five finalised actions; newest = now, oldest = now - 4.
    for i in (0..5u64).rev() {
        watchtower
            .storage()
            .store_justice_action(&submitted_action(&format!("a{i}"), now - i))
            .unwrap();
    }

    let report = watchtower.compact_storage().unwrap();

    assert_eq!(report.justice_actions_removed(), 3);
    assert!(watchtower.storage().get_justice_action("a0").unwrap().is_some()); // newest
    assert!(watchtower.storage().get_justice_action("a1").unwrap().is_some()); // second newest
    assert!(watchtower.storage().get_justice_action("a4").unwrap().is_none()); // oldest
}

// ── Disabled limits ───────────────────────────────────────────────────────────

#[test]
fn zero_retention_secs_disables_age_expiry() {
    let config = WatchtowerConfig {
        compaction: CompactionPolicy {
            justice_action_retention_secs: 0,
            max_justice_actions: 0, // also disabled
            ..CompactionPolicy::default()
        },
        ..Default::default()
    };
    let watchtower = Watchtower::new(config).unwrap();

    watchtower
        .storage()
        .store_justice_action(&submitted_action("ancient", 0))
        .unwrap();

    let report = watchtower.compact_storage().unwrap();
    assert_eq!(report.justice_actions_removed(), 0, "both limits disabled: nothing must be removed");
}

// ── Report and statistics ─────────────────────────────────────────────────────

#[test]
fn compaction_report_includes_justice_action_counts() {
    let now = now();
    let config = WatchtowerConfig {
        compaction: CompactionPolicy {
            justice_action_retention_secs: DAY,
            ..CompactionPolicy::default()
        },
        ..Default::default()
    };
    let watchtower = Watchtower::new(config).unwrap();

    watchtower
        .storage()
        .store_justice_action(&submitted_action("old1", now - 2 * DAY))
        .unwrap();
    watchtower
        .storage()
        .store_justice_action(&submitted_action("old2", now - 2 * DAY))
        .unwrap();
    watchtower
        .storage()
        .store_justice_action(&submitted_action("new1", now))
        .unwrap();

    let report = watchtower.compact_storage().unwrap();
    assert_eq!(report.justice_actions_before, 3);
    assert_eq!(report.justice_actions_after, 1);
    assert_eq!(report.justice_actions_removed(), 2);
    assert!(!report.is_noop());
}

#[test]
fn records_compacted_statistic_includes_justice_action_removals() {
    let now = now();
    let config = WatchtowerConfig {
        compaction: CompactionPolicy {
            justice_action_retention_secs: DAY,
            ..CompactionPolicy::default()
        },
        ..Default::default()
    };
    let watchtower = Watchtower::new(config).unwrap();

    watchtower
        .storage()
        .store_justice_action(&submitted_action("old", now - 2 * DAY))
        .unwrap();

    watchtower.compact_storage().unwrap();

    let stats = watchtower.state().stats.read().clone();
    assert!(
        stats.records_compacted >= 1,
        "records_compacted must include the removed justice action"
    );
}

#[test]
fn clean_storage_compaction_is_a_noop() {
    let now = now();
    let config = WatchtowerConfig::default();
    let watchtower = Watchtower::new(config).unwrap();

    // One fresh finalised action — well within any default retention window.
    watchtower
        .storage()
        .store_justice_action(&submitted_action("recent", now))
        .unwrap();

    let report = watchtower.compact_storage().unwrap();
    assert_eq!(report.justice_actions_removed(), 0);
}

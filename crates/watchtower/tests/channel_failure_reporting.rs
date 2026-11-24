//! Integration coverage for issue #374: one channel's monitoring failure must
//! be reported without stopping the monitoring of other channels.

use std::time::Duration;
use watchtower::{monitor::MonitorError, AlertType, Watchtower, WatchtowerConfig, WatchtowerError};

fn watchtower_with_two_channels() -> Watchtower {
    let config = WatchtowerConfig {
        scan_interval_secs: 0,
        auto_justice: false,
        ..Default::default()
    };
    let watchtower = Watchtower::new(config).expect("watchtower should initialize");
    watchtower.subscribe("alpha".to_string()).unwrap();
    watchtower.subscribe("beta".to_string()).unwrap();
    watchtower
}

#[tokio::test]
async fn failed_channel_is_reported_while_other_channels_keep_scanning() {
    let watchtower = watchtower_with_two_channels();
    watchtower.monitor().inject_failure(
        "alpha",
        MonitorError::NetworkError("rpc endpoint unavailable".to_string()),
    );

    watchtower.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    watchtower.stop();

    let alpha = watchtower
        .channel_failure_report("alpha")
        .expect("alpha failure should be reported");
    assert!(alpha.is_active());
    assert!(alpha.error.contains("rpc endpoint unavailable"));
    assert!(alpha.message().contains("retry_channel"));

    // beta was never injected and must have been scanned normally.
    assert!(watchtower.channel_failure_report("beta").is_none());
    let beta_state = watchtower
        .state()
        .channel_states
        .read()
        .get("beta")
        .cloned()
        .expect("beta state should exist");
    assert!(beta_state.last_update_ts > 0);

    let alerts = watchtower.get_alerts(50);
    assert!(
        alerts
            .iter()
            .any(|alert| matches!(alert.alert_type, AlertType::ChannelMonitorFailed { .. })),
        "a per-channel failure alert should be published"
    );
    assert!(
        alerts
            .iter()
            .all(|alert| !alert.message().contains("channel beta monitoring failed")),
        "beta must not be reported as failed"
    );
    assert!(
        watchtower.storage().get_alerts(50).unwrap().len() >= 1,
        "failure alerts should be durable"
    );
}

#[tokio::test]
async fn operator_retry_recovers_only_the_failed_channel() {
    let watchtower = watchtower_with_two_channels();
    watchtower
        .monitor()
        .inject_failure("alpha", MonitorError::NetworkError("boom".to_string()));

    watchtower.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    watchtower.stop();

    assert!(watchtower.monitor().clear_injected_failure("alpha"));
    let recovered = watchtower
        .retry_channel("alpha")
        .await
        .expect("retry should complete")
        .expect("an active failure should be recovered");
    assert!(recovered.recovered);
    assert!(recovered.last_recovered_at.is_some());
    assert!(watchtower.active_channel_failure_reports().is_empty());
    assert!(watchtower.channel_failure_report("beta").is_none());
    assert_eq!(watchtower.persisted_subscriptions().unwrap().len(), 2);
}

#[tokio::test]
async fn failed_retry_is_reported_actionably_and_is_retry_safe() {
    let watchtower = watchtower_with_two_channels();
    watchtower.monitor().inject_failure(
        "alpha",
        MonitorError::NetworkError("still down".to_string()),
    );

    watchtower.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    watchtower.stop();

    let error = watchtower
        .retry_channel("alpha")
        .await
        .expect_err("retry while the channel is still down must fail");
    assert!(error.to_string().contains("alpha"));
    assert!(error.to_string().contains("retry failed"));

    let report = watchtower.channel_failure_report("alpha").unwrap();
    assert!(report.consecutive_failures >= 2);
    assert!(report.error.contains("retry failed"));
    assert!(watchtower.channel_failure_report("beta").is_none());
}

#[tokio::test]
async fn invalid_failure_reports_are_rejected_without_partial_state() {
    let watchtower = watchtower_with_two_channels();

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
    assert!(watchtower.active_channel_failure_reports().is_empty());
    assert!(watchtower.get_alerts(10).is_empty());
}

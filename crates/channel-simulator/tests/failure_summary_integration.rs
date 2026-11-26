//! Integration tests for failed-payment summaries in `channel-simulator` (#386).

use channel_simulator::{FailureCategory, Simulator, SimulatorConfig, MAX_FAILURE_SAMPLES};

/// A network with no channels cannot route anything, so every payment fails
/// with a categorised reason and the summary must account for all of them.
#[tokio::test]
async fn a_fully_disconnected_network_reports_every_failure() {
    let config = SimulatorConfig {
        num_nodes: 4,
        avg_channels_per_node: 0.0,
        num_payments: 50,
        seed: Some(386),
        ..Default::default()
    };

    let simulator = Simulator::new(config);
    simulator.initialize_network().unwrap();
    assert_eq!(simulator.get_network().read().num_channels(), 0);

    let stats = simulator.run_simulation().await.unwrap();
    let summary = simulator.failure_summary();

    assert_eq!(stats.total_payments, stats.failed_payments);
    assert_eq!(summary.total_failed, stats.failed_payments);
    assert!(!summary.is_empty());

    // An isolated network can only fail because no path exists.
    assert_eq!(
        summary.category_count(FailureCategory::NoPathFound),
        stats.failed_payments
    );
    assert_eq!(
        stats.failures_by_category.get("no_path_found").copied(),
        Some(stats.failed_payments)
    );

    // Counts are exact even though the retained examples are bounded.
    assert_eq!(
        summary.samples.len(),
        MAX_FAILURE_SAMPLES.min(stats.failed_payments)
    );
    let sample = &summary.samples[0];
    assert_ne!(sample.source, sample.destination);
    assert_eq!(sample.category, FailureCategory::NoPathFound);
    assert!(sample.reason.contains("No path found"));
}

/// A healthy network's summary agrees with the run's own failure count, and a
/// second run replaces rather than accumulates the first run's failures.
#[tokio::test]
async fn the_summary_tracks_the_last_run_only() {
    let config = SimulatorConfig {
        num_nodes: 12,
        avg_channels_per_node: 4.0,
        num_payments: 40,
        seed: Some(2026),
        ..Default::default()
    };

    let simulator = Simulator::new(config);
    simulator.initialize_network().unwrap();

    let first = simulator.run_simulation().await.unwrap();
    let first_summary = simulator.failure_summary();
    assert_eq!(first_summary.total_failed, first.failed_payments);

    let second = simulator.run_simulation().await.unwrap();
    let second_summary = simulator.failure_summary();
    assert_eq!(second_summary.total_failed, second.failed_payments);
    assert_eq!(second_summary, simulator.failure_summary());
}

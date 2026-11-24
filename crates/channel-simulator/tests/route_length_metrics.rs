//! Integration test for payment success-rate metrics by route length
//! (issue #383).
//!
//! Runs a full seeded simulation and checks the reported breakdown against the
//! aggregate counters, so the per-length view can never disagree with the
//! totals it is a decomposition of.

use channel_simulator::{PaymentSuccessMetrics, Simulator, SimulatorConfig};

fn config(seed: u64) -> SimulatorConfig {
    SimulatorConfig {
        num_nodes: 18,
        avg_channels_per_node: 3.5,
        num_payments: 120,
        seed: Some(seed),
        ..Default::default()
    }
}

async fn run(seed: u64) -> channel_simulator::SimulationStats {
    let simulator = Simulator::new(config(seed));
    simulator.initialize_network().unwrap();
    simulator.run_simulation().await.unwrap()
}

#[tokio::test]
async fn the_breakdown_adds_up_to_the_aggregate_counters() {
    let stats = run(4242).await;
    let metrics = &stats.success_by_route_length;

    assert_eq!(
        metrics.total_attempted(),
        stats.total_payments,
        "every attempted payment must land in exactly one place"
    );
    assert_eq!(metrics.total_successful(), stats.successful_payments);
    assert_eq!(
        metrics.total_attempted() - metrics.total_successful(),
        stats.failed_payments
    );
    assert_eq!(metrics.unroutable, 0, "the generated network is connected");
}

#[tokio::test]
async fn every_bucket_is_self_consistent_and_length_ordered() {
    let stats = run(99).await;
    let metrics = &stats.success_by_route_length;

    assert!(
        metrics.by_route_length.len() > 1,
        "expected payments of several lengths, got {:?}",
        metrics.route_lengths().collect::<Vec<_>>()
    );

    let mut previous = 0;
    for (length, bucket) in &metrics.by_route_length {
        assert_eq!(bucket.route_length, *length);
        assert!(*length >= 1, "a route always has at least one hop");
        assert!(*length > previous, "buckets must be in ascending order");
        previous = *length;

        assert_eq!(bucket.attempted, bucket.successful + bucket.failed);
        assert!(bucket.attempted > 0);
        assert!((0.0..=100.0).contains(&bucket.success_rate()));
        if bucket.successful == 0 {
            assert_eq!(bucket.value_routed, 0);
        } else {
            assert!(bucket.value_routed > 0);
        }
    }

    assert_eq!(metrics.min_route_length(), Some(1));
    assert!(metrics.max_route_length().unwrap() >= metrics.min_route_length().unwrap());
    assert!((0.0..=100.0).contains(&metrics.overall_success_rate()));
}

#[tokio::test]
async fn successful_value_per_bucket_sums_to_the_total_routed() {
    let stats = run(7).await;
    let routed: i128 = stats
        .success_by_route_length
        .by_route_length
        .values()
        .map(|bucket| bucket.value_routed)
        .sum();

    assert_eq!(routed, stats.total_value_routed);
}

#[tokio::test]
async fn the_same_seed_reports_the_same_breakdown() {
    let first = run(2026).await;
    let second = run(2026).await;

    assert_eq!(
        first.success_by_route_length,
        second.success_by_route_length
    );
    assert_eq!(
        first.success_by_route_length.success_rate_for(1),
        second.success_by_route_length.success_rate_for(1)
    );
}

#[test]
fn recording_rejects_invalid_inputs_instead_of_bucketing_them() {
    let mut metrics = PaymentSuccessMetrics::new();

    assert!(metrics.record(Some(0), true, 10).is_err());
    assert!(metrics.record(Some(2), true, 0).is_err());
    assert!(metrics.record(Some(2), false, -5).is_err());

    assert_eq!(metrics.total_attempted(), 0);
    assert!(metrics.by_route_length.is_empty());
    assert_eq!(metrics.unroutable, 0);
}

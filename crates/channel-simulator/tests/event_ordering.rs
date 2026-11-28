//! Integration tests for deterministic event ordering of concurrent simulation
//! inputs (issue #385).
//!
//! The workflow under test is the one a concurrent harness uses: many producers
//! submit payments, their completion order varies, and the simulation result
//! must not.

// Comparing whole `SimulationStats` values is the point of these tests.
#![allow(clippy::float_cmp)]

use channel_simulator::{
    order_events, SimulationEvent, Simulator, SimulatorConfig, SimulatorError,
};

fn simulator(seed: u64) -> Simulator {
    let simulator = Simulator::new(SimulatorConfig {
        num_nodes: 12,
        avg_channels_per_node: 3.0,
        num_payments: 0,
        seed: Some(seed),
        ..Default::default()
    });
    simulator.initialize_network().unwrap();
    simulator
}

/// The same input set assembled in a "concurrent completion" order: producers
/// finish out of submission order, which is what `order_events` must absorb.
fn interleaved_events() -> Vec<SimulationEvent> {
    let mut events = Vec::new();
    let mut sequence = 0;
    for timestamp in 0..4u64 {
        for producer in 0..5u64 {
            let source = format!("node_{:03}", (timestamp * 5 + producer) % 12);
            let destination = format!("node_{:03}", (timestamp * 7 + producer + 1) % 12);
            if source == destination {
                sequence += 1;
                continue;
            }
            events.push(SimulationEvent {
                timestamp,
                sequence,
                source,
                destination,
                amount: 500 + i128::from(sequence % 17) * 10,
            });
            sequence += 1;
        }
    }
    events
}

#[tokio::test]
async fn the_same_events_in_any_arrival_order_give_identical_results() {
    let events = interleaved_events();
    assert!(events.len() > 10);

    // Three different "thread completion" orders of the same work.
    let arrival_a = events.clone();
    let mut arrival_b = events.clone();
    arrival_b.reverse();
    let mut arrival_c = events.clone();
    arrival_c.rotate_left(11);

    // One simulator, so this isolates ordering from any tie-breaking inside the
    // router: the only thing that differs between the three calls is the order
    // the inputs arrived in.
    let same_simulator = simulator(9001);
    let stats_a = same_simulator.run_events(arrival_a.clone()).await.unwrap();
    let stats_b = same_simulator.run_events(arrival_b).await.unwrap();
    let stats_c = same_simulator.run_events(arrival_c.clone()).await.unwrap();

    assert_eq!(stats_a.total_payments, events.len());
    assert_eq!(stats_a, stats_b);
    assert_eq!(stats_a, stats_c);

    // Canonical ordering does not depend on the input order either.
    let mut reversed = arrival_a;
    reversed.reverse();
    assert_eq!(order_events(reversed), order_events(arrival_c));

    // A fresh simulator with the same seed processes the same inputs, i.e. the
    // seed plus the input set determines the run.
    let fresh = simulator(9001);
    let fresh_stats = fresh.run_events(events.clone()).await.unwrap();
    assert_eq!(stats_a.total_payments, fresh_stats.total_payments);
    assert_eq!(stats_a.successful_payments, fresh_stats.successful_payments);
    assert_eq!(stats_a.total_value_routed, fresh_stats.total_value_routed);
}

#[tokio::test]
async fn concurrent_producers_are_deterministic() {
    let simulator = Simulator::new(SimulatorConfig {
        num_nodes: 12,
        avg_channels_per_node: 3.0,
        num_payments: 150,
        seed: Some(123_456),
        ..Default::default()
    });
    simulator.initialize_network().unwrap();

    let first = simulator.run_stress_test(8).await.unwrap();
    let second = simulator.run_stress_test(8).await.unwrap();

    assert_eq!(first.successful_payments, second.successful_payments);
    assert_eq!(first.total_value_routed, second.total_value_routed);
    assert_eq!(first.avg_path_length, second.avg_path_length);
    assert_eq!(first.total_payments, second.total_payments);
}

#[tokio::test]
async fn the_drawn_seed_is_reported_and_replays_the_run() {
    let simulator = Simulator::new(SimulatorConfig {
        num_nodes: 8,
        num_payments: 40,
        seed: None,
        ..Default::default()
    });
    assert_ne!(simulator.seed(), 0, "a seed is always drawn");
    simulator.initialize_network().unwrap();
    let first = simulator.run_simulation().await.unwrap();

    let replay = Simulator::new(SimulatorConfig {
        num_nodes: 8,
        num_payments: 40,
        seed: Some(simulator.seed()),
        ..Default::default()
    });
    replay.initialize_network().unwrap();
    let second = replay.run_simulation().await.unwrap();

    assert_eq!(first.successful_payments, second.successful_payments);
    assert_eq!(first.total_value_routed, second.total_value_routed);
}

#[tokio::test]
async fn invalid_events_are_rejected_with_an_actionable_message() {
    let simulator = simulator(1);

    let cases = [
        SimulationEvent {
            timestamp: 0,
            sequence: 0,
            source: "node_000".to_string(),
            destination: "node_000".to_string(),
            amount: 10,
        },
        SimulationEvent {
            timestamp: 0,
            sequence: 1,
            source: "node_000".to_string(),
            destination: "node_001".to_string(),
            amount: 0,
        },
        SimulationEvent {
            timestamp: 0,
            sequence: 2,
            source: "node_404".to_string(),
            destination: "node_001".to_string(),
            amount: 10,
        },
    ];

    for event in cases {
        let err = simulator.run_events(vec![event]).await.unwrap_err();
        assert!(matches!(err, SimulatorError::InvalidEvent(_)), "{err}");
    }

    let err = simulator.run_events(Vec::new()).await.unwrap_err();
    assert!(err.to_string().contains("no simulation events"), "{err}");
}

//! Integration tests for temporary node disconnection and recovery in
//! `channel-simulator`.

use channel_router::pathfinder::Pathfinder;
use channel_router::{Channel, NetworkGraph, Node, NodeFeatures, RouteRequest};
use channel_simulator::fuzz::{verify_topology, TopologyFuzzConfig, TopologyFuzzer};
use channel_simulator::{
    DisconnectionConfig, SimulatedNode, Simulator, SimulatorConfig, SimulatorError,
};
use std::collections::{HashMap, HashSet};

#[tokio::test]
async fn end_to_end_simulation_with_disconnection_and_recovery() {
    let config = SimulatorConfig {
        num_nodes: 16,
        avg_channels_per_node: 4.0,
        num_payments: 40,
        seed: Some(2026),
        disconnection: Some(DisconnectionConfig {
            disconnect_probability: 0.12,
            min_downtime_steps: 2,
            max_downtime_steps: 6,
            max_concurrent_disconnections: Some(4),
            recover_at_end: true,
        }),
        ..Default::default()
    };

    let simulator = Simulator::new(config.clone());
    simulator.initialize_network().unwrap();

    let initial_channels = simulator.get_network().read().num_channels();
    let stats = simulator.run_simulation().await.unwrap();

    assert_eq!(
        stats.total_payments,
        stats.successful_payments + stats.failed_payments
    );
    assert!(stats.node_disconnections > 0);
    assert_eq!(stats.node_disconnections, stats.node_recoveries);
    assert!(simulator.disconnected_nodes().is_empty());
    assert_eq!(
        simulator.get_network().read().num_channels(),
        initial_channels
    );

    // Reproducibility check with the same seed
    let replay = Simulator::new(config);
    replay.initialize_network().unwrap();
    let replay_stats = replay.run_simulation().await.unwrap();
    assert_eq!(stats.successful_payments, replay_stats.successful_payments);
    assert_eq!(stats.node_disconnections, replay_stats.node_disconnections);
    assert_eq!(stats.node_recoveries, replay_stats.node_recoveries);
}

#[test]
fn routing_blocks_disconnected_node_and_resumes_after_recovery() {
    // Build a deterministic 3-node line: a -- b -- c
    let mut graph = NetworkGraph::new();
    let mut nodes = HashMap::new();

    for id in ["a", "b", "c"] {
        let node = Node {
            id: id.to_string(),
            public_key: vec![1; 32],
            alias: None,
            online: true,
            last_seen: 0,
            features: NodeFeatures::default(),
        };
        graph.add_node(node.clone());
        nodes.insert(
            id.to_string(),
            SimulatedNode {
                node,
                balance: 0,
                channels: HashSet::new(),
            },
        );
    }

    for (cid, u, v) in [("ch_ab", "a", "b"), ("ch_bc", "b", "c")] {
        graph.add_channel(Channel {
            id: cid.to_string(),
            node_a: u.to_string(),
            node_b: v.to_string(),
            capacity_a_to_b: 1_000_000,
            capacity_b_to_a: 1_000_000,
            base_fee: 1,
            fee_rate: 100,
            cltv_delta: 10,
            min_htlc_size: 1,
            max_htlc_size: 1_000_000,
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 0,
        });
        nodes.get_mut(u).unwrap().channels.insert(v.to_string());
        nodes.get_mut(v).unwrap().channels.insert(u.to_string());
    }

    let request = RouteRequest {
        source: "a".to_string(),
        destination: "c".to_string(),
        amount: 1_000,
        max_fee_budget: None,
        max_hops: None,
        find_any: false,
        payment_metadata: None,
    };

    let pathfinder = Pathfinder::new();
    assert!(pathfinder.find_route_dijkstra(&graph, &request).is_ok());

    let mut tracker = channel_simulator::DisconnectionTracker::new();
    assert_eq!(
        tracker
            .disconnect_node(&mut graph, &mut nodes, "b", 1, Some(3))
            .unwrap(),
        2
    );
    verify_topology(&graph, &nodes).unwrap();
    assert!(pathfinder.find_route_dijkstra(&graph, &request).is_err());

    assert_eq!(
        tracker
            .recover_due_nodes(&mut graph, &mut nodes, 3)
            .unwrap(),
        1
    );
    verify_topology(&graph, &nodes).unwrap();
    assert!(pathfinder.find_route_dijkstra(&graph, &request).is_ok());
}

#[test]
fn fuzzer_workflow_with_disconnection_is_clean() {
    let fuzzer = TopologyFuzzer::try_new(TopologyFuzzConfig {
        iterations: 21,
        seed: 0x1234_5678,
        min_nodes: 3,
        max_nodes: 20,
        payments_per_topology: 8,
        disconnection: Some(DisconnectionConfig {
            disconnect_probability: 0.2,
            min_downtime_steps: 1,
            max_downtime_steps: 4,
            max_concurrent_disconnections: Some(3),
            recover_at_end: true,
        }),
        ..TopologyFuzzConfig::default()
    })
    .unwrap();

    let report = fuzzer.try_run().unwrap();
    assert!(report.is_clean(), "{}", report.summarize());
    assert!(report.disconnections_simulated > 0);
    assert_eq!(report.disconnections_simulated, report.recoveries_simulated);
}

#[test]
fn invalid_disconnection_config_is_rejected_explicitly() {
    let invalid = DisconnectionConfig {
        disconnect_probability: -0.01,
        ..Default::default()
    };
    assert!(matches!(
        invalid.validate(),
        Err(SimulatorError::InvalidConfig(_))
    ));
}

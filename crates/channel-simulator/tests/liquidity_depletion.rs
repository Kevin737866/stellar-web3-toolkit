//! Integration tests for channel liquidity depletion (issue #384).
//!
//! Exercises the full simulation workflow: a seeded network, hundreds of
//! payments, and the balances afterwards.

use channel_router::{Channel, NetworkGraph, Node, NodeFeatures, Route, RouteHop, RouteMetadata};
use channel_simulator::liquidity::{apply_route_liquidity, LiquidityUpdate};
use channel_simulator::{LiquidityModel, Simulator, SimulatorConfig};

fn config(model: LiquidityModel) -> SimulatorConfig {
    SimulatorConfig {
        num_nodes: 6,
        avg_channels_per_node: 2.5,
        min_channel_capacity: 1_000,
        max_channel_capacity: 3_000,
        num_payments: 200,
        max_payment_amount: 1_500,
        seed: Some(31337),
        liquidity_model: model,
        ..Default::default()
    }
}

fn balances(simulator: &Simulator) -> Vec<(String, i128, i128)> {
    let mut channels: Vec<(String, i128, i128)> = simulator
        .get_network()
        .read()
        .channels
        .values()
        .map(|c| (c.id.clone(), c.capacity_a_to_b, c.capacity_b_to_a))
        .collect();
    channels.sort();
    channels
}

fn capacity(simulator: &Simulator) -> i128 {
    balances(simulator)
        .iter()
        .map(|(_, a, b)| a + b)
        .sum::<i128>()
}

#[tokio::test]
async fn depleting_liquidity_changes_balances_without_creating_value() {
    let simulator = Simulator::new(config(LiquidityModel::Depleting));
    simulator.initialize_network().unwrap();

    let before = balances(&simulator);
    let capacity_before = capacity(&simulator);
    let stats = simulator.run_simulation().await.unwrap();

    assert!(stats.successful_payments > 0);
    assert!(
        stats.failed_payments > 0,
        "thin channels must fail some payments"
    );

    let after = balances(&simulator);
    assert_ne!(before, after, "successful payments must move balances");
    assert_eq!(
        capacity_before,
        capacity(&simulator),
        "a payment moves value across a channel; it does not create it"
    );
    assert_eq!(stats.depleted_channels, simulator.depleted_channels());
    assert_eq!(
        stats.total_payments,
        stats.successful_payments + stats.failed_payments
    );

    // Every channel keeps a non-negative balance in both directions.
    for (id, a_to_b, b_to_a) in &after {
        assert!(*a_to_b >= 0, "{id} went negative a->b");
        assert!(*b_to_a >= 0, "{id} went negative b->a");
    }
}

#[tokio::test]
async fn the_static_model_never_touches_balances() {
    let simulator = Simulator::new(config(LiquidityModel::Static));
    simulator.initialize_network().unwrap();

    let before = balances(&simulator);
    simulator.run_simulation().await.unwrap();

    assert_eq!(before, balances(&simulator));
    assert_eq!(simulator.depleted_channels(), 0);
}

#[tokio::test]
async fn depletion_is_reproducible_from_the_seed() {
    let first = Simulator::new(config(LiquidityModel::Depleting));
    first.initialize_network().unwrap();
    let first_stats = first.run_simulation().await.unwrap();

    let second = Simulator::new(config(LiquidityModel::Depleting));
    second.initialize_network().unwrap();
    let second_stats = second.run_simulation().await.unwrap();

    assert_eq!(
        first_stats.successful_payments,
        second_stats.successful_payments
    );
    assert_eq!(
        first_stats.total_value_routed,
        second_stats.total_value_routed
    );
    assert_eq!(
        first_stats.depleted_channels,
        second_stats.depleted_channels
    );
    assert_eq!(balances(&first), balances(&second));
}

#[test]
fn a_partially_applied_route_leaves_no_trace() {
    let mut graph = NetworkGraph::new();
    for id in ["a", "b", "c"] {
        graph.add_node(Node {
            id: id.to_string(),
            public_key: vec![],
            alias: None,
            online: true,
            last_seen: 0,
            features: NodeFeatures::default(),
        });
    }
    for (id, a, b, a_to_b) in [("ab", "a", "b", 1_000i128), ("bc", "b", "c", 50)] {
        graph.add_channel(Channel {
            id: id.to_string(),
            node_a: a.to_string(),
            node_b: b.to_string(),
            capacity_a_to_b: a_to_b,
            capacity_b_to_a: 1_000,
            base_fee: 1,
            fee_rate: 1_000,
            cltv_delta: 0,
            min_htlc_size: 1,
            max_htlc_size: a_to_b + 1_000,
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 0,
        });
    }

    let route = Route {
        hops: vec![
            RouteHop {
                channel_id: "ab".to_string(),
                node_id: "b".to_string(),
                amount: 500,
                fee: 0,
                cltv_delta: 0,
                hashlock: None,
                expiry_height: 0,
            },
            RouteHop {
                channel_id: "bc".to_string(),
                node_id: "c".to_string(),
                amount: 500,
                fee: 0,
                cltv_delta: 0,
                hashlock: None,
                expiry_height: 0,
            },
        ],
        total_fees: 0,
        total_amount: 500,
        success_probability: 1.0,
        metadata: RouteMetadata::default(),
    };

    let err = apply_route_liquidity(&mut graph, &route).unwrap_err();
    assert!(err.to_string().contains("bc"), "{err}");

    // Nothing moved: the first hop would have succeeded on its own.
    let ab = graph.get_channel("ab").unwrap();
    assert_eq!((ab.capacity_a_to_b, ab.capacity_b_to_a), (1_000, 1_000));
}

#[test]
fn liquidity_update_reports_what_moved() {
    let mut graph = NetworkGraph::new();
    for id in ["a", "b"] {
        graph.add_node(Node {
            id: id.to_string(),
            public_key: vec![],
            alias: None,
            online: true,
            last_seen: 0,
            features: NodeFeatures::default(),
        });
    }
    graph.add_channel(Channel {
        id: "ab".to_string(),
        node_a: "a".to_string(),
        node_b: "b".to_string(),
        capacity_a_to_b: 400,
        capacity_b_to_a: 400,
        base_fee: 0,
        fee_rate: 0,
        cltv_delta: 0,
        min_htlc_size: 1,
        max_htlc_size: 800,
        htlcs_in_flight: 0,
        enabled: true,
        age_seconds: 0,
    });

    let route = Route {
        hops: vec![RouteHop {
            channel_id: "ab".to_string(),
            node_id: "b".to_string(),
            amount: 400,
            fee: 0,
            cltv_delta: 0,
            hashlock: None,
            expiry_height: 0,
        }],
        total_fees: 0,
        total_amount: 400,
        success_probability: 1.0,
        metadata: RouteMetadata::default(),
    };

    let update: LiquidityUpdate = apply_route_liquidity(&mut graph, &route).unwrap();
    assert_eq!(update.hops_applied, 1);
    assert_eq!(update.value_moved, 400);
    assert_eq!(update.channels_emptied, 1);

    let channel = graph.get_channel("ab").unwrap();
    assert_eq!(channel.capacity_a_to_b, 0);
    assert_eq!(channel.capacity_b_to_a, 800);
}

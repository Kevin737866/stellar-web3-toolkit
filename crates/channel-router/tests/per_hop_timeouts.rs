//! Integration tests for per-hop timeout requirements in route results
//! (issue #362).

use channel_router::pathfinder::Pathfinder;
use channel_router::policy::RoutingPolicy;
use channel_router::{
    find_best_route, Channel, NetworkGraph, Node, NodeFeatures, PaymentMetadata, PaymentType,
    RouteRequest, RoutingError,
};

fn build_three_hop_graph() -> NetworkGraph {
    let mut graph = NetworkGraph::new();
    for id in ["alice", "bob", "carol", "dave"] {
        graph.add_node(Node {
            id: id.to_string(),
            public_key: vec![1],
            alias: None,
            online: true,
            last_seen: 1_000,
            features: NodeFeatures::default(),
        });
    }

    for (id, a, b, cltv_delta) in [
        ("ch1", "alice", "bob", 30),
        ("ch2", "bob", "carol", 40),
        ("ch3", "carol", "dave", 50),
    ] {
        graph.add_channel(Channel {
            id: id.to_string(),
            node_a: a.to_string(),
            node_b: b.to_string(),
            capacity_a_to_b: 5_000_000,
            capacity_b_to_a: 5_000_000,
            base_fee: 1,
            fee_rate: 500,
            cltv_delta,
            min_htlc_size: 1,
            max_htlc_size: 5_000_000,
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 3_600,
        });
    }

    graph
}

#[test]
fn end_to_end_route_search_and_policy_expose_consistent_hop_timeouts() {
    let graph = build_three_hop_graph();
    let request = RouteRequest {
        source: "alice".to_string(),
        destination: "dave".to_string(),
        amount: 10_000,
        max_fee_budget: Some(1_000),
        max_hops: Some(5),
        find_any: false,
        payment_metadata: Some(PaymentMetadata {
            payment_type: PaymentType::Regular,
            required_cltv_delta: Some(15),
            payment_expiry: Some(150),
        }),
    };

    let route = find_best_route(&graph, &request).expect("route should succeed");
    let pathfinder_route = Pathfinder::new()
        .find_route_dijkstra(&graph, &request)
        .expect("pathfinder dijkstra should succeed");

    // Both entry points produce identical per-hop timeout requirements:
    // ch3: 50 + 15 = 65; ch2: 40 + 65 = 105; ch1: 30 + 105 = 135
    assert_eq!(route.total_cltv_delta(), 135);
    assert_eq!(pathfinder_route.total_cltv_delta(), 135);
    assert_eq!(route.hop_timeouts(), pathfinder_route.hop_timeouts());

    let timeouts = route.hop_timeouts();
    assert_eq!(timeouts.len(), 3);
    assert_eq!(timeouts[0].incoming_cltv_delta, 135);
    assert_eq!(timeouts[0].outgoing_cltv_delta, 105);
    assert_eq!(timeouts[1].incoming_cltv_delta, 105);
    assert_eq!(timeouts[1].outgoing_cltv_delta, 65);
    assert_eq!(timeouts[2].incoming_cltv_delta, 65);
    assert_eq!(timeouts[2].outgoing_cltv_delta, 15);

    // Policy evaluation accepts within budget and rejects above budget.
    let policy = RoutingPolicy::default();
    assert!(policy.route_meets_requirements(&route, &request).is_ok());

    let tight_request = RouteRequest {
        payment_metadata: Some(PaymentMetadata {
            payment_type: PaymentType::Regular,
            required_cltv_delta: Some(15),
            payment_expiry: Some(134),
        }),
        ..request
    };
    let err = policy
        .route_meets_requirements(&route, &tight_request)
        .unwrap_err();
    assert!(matches!(
        err,
        RoutingError::TimeoutExceedsBudget {
            required: 135,
            max_allowed: 134
        }
    ));
}

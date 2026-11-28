//! Integration tests for route search across disconnected network components (issue #366).

use channel_router::graph::{GraphView, TopologyAnalyzer};
use channel_router::pathfinder::Pathfinder;
use channel_router::{
    find_best_route, find_k_routes, Channel, NetworkGraph, Node, NodeFeatures, RouteRequest,
    RoutingError,
};

fn add_node(graph: &mut NetworkGraph, id: &str) {
    graph.add_node(Node {
        id: id.to_string(),
        public_key: vec![1],
        alias: None,
        online: true,
        last_seen: 0,
        features: NodeFeatures::default(),
    });
}

fn add_channel(graph: &mut NetworkGraph, id: &str, a: &str, b: &str) {
    graph.add_channel(Channel {
        id: id.to_string(),
        node_a: a.to_string(),
        node_b: b.to_string(),
        capacity_a_to_b: 5_000_000,
        capacity_b_to_a: 5_000_000,
        base_fee: 1,
        fee_rate: 1_000,
        cltv_delta: 40,
        min_htlc_size: 1,
        max_htlc_size: 5_000_000,
        htlcs_in_flight: 0,
        enabled: true,
        age_seconds: 0,
    });
}

fn route_request(source: &str, destination: &str) -> RouteRequest {
    RouteRequest {
        source: source.to_string(),
        destination: destination.to_string(),
        amount: 100_000,
        max_fee_budget: None,
        max_hops: None,
        find_any: false,
        payment_metadata: None,
    }
}

#[test]
fn disconnected_components_partition_and_heal_workflow() {
    let mut graph = NetworkGraph::new();
    for id in ["a1", "a2", "b1", "b2"] {
        add_node(&mut graph, id);
    }
    add_channel(&mut graph, "ch_a", "a1", "a2");
    add_channel(&mut graph, "ch_b", "b1", "b2");

    // Graph starts disconnected: topology, reachability, and routing all agree.
    assert!(!TopologyAnalyzer::is_connected(&graph));

    let view = GraphView::new(&graph);
    let reachable = view.get_reachable_nodes("a1", 10);
    assert!(reachable.contains("a2"));
    assert!(!reachable.contains("b1"));
    assert!(!reachable.contains("b2"));
    assert!(view.find_all_paths("a1", "b2", 10, 100_000).is_empty());

    let cross = route_request("a1", "b2");
    assert!(matches!(
        find_best_route(&graph, &cross),
        Err(RoutingError::NoPathFound { .. })
    ));
    assert!(find_k_routes(&graph, &cross, 3).unwrap().is_empty());

    let pf = Pathfinder::new();
    assert!(matches!(
        pf.find_route_dijkstra(&graph, &cross),
        Err(RoutingError::NoPathFound { .. })
    ));

    // Heal the partition with a bridge channel.
    add_channel(&mut graph, "bridge", "a2", "b1");
    assert!(TopologyAnalyzer::is_connected(&graph));

    let route = find_best_route(&graph, &cross).unwrap();
    assert_eq!(route.hops.len(), 3);
    assert!(!find_k_routes(&graph, &cross, 2).unwrap().is_empty());

    // Unknown node still returns NodeNotFound rather than NoPathFound.
    let missing = route_request("a1", "nonexistent");
    assert!(matches!(
        find_best_route(&graph, &missing),
        Err(RoutingError::NodeNotFound { .. })
    ));
}

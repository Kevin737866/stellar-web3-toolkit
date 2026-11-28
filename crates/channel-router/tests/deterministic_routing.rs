//! Integration tests for deterministic equal-cost route tie-breaking.

use channel_router::pathfinder::Pathfinder;
use channel_router::policy::{RoutingPolicy, SelectionStrategy};
use channel_router::{
    find_best_route, find_best_route_with_tie_breaker, Channel, FeeCap, NetworkGraph, Node,
    NodeFeatures, RouteRequest, RoutingError, TieBreaker,
};

fn add_node(graph: &mut NetworkGraph, id: &str) {
    graph.add_node(Node {
        id: id.to_string(),
        public_key: vec![1],
        alias: None,
        online: true,
        last_seen: 1_000,
        features: NodeFeatures::default(),
    });
}

fn add_channel(
    graph: &mut NetworkGraph,
    id: &str,
    a: &str,
    b: &str,
    capacity: i128,
    base_fee: i128,
    fee_rate: u32,
    cltv_delta: u32,
) {
    graph.add_channel(Channel {
        id: id.to_string(),
        node_a: a.to_string(),
        node_b: b.to_string(),
        capacity_a_to_b: capacity,
        capacity_b_to_a: capacity,
        base_fee,
        fee_rate,
        cltv_delta,
        min_htlc_size: 1,
        max_htlc_size: capacity,
        htlcs_in_flight: 0,
        enabled: true,
        age_seconds: 3_600,
    });
}

fn build_multi_path_graph(reverse_insertion: bool) -> NetworkGraph {
    let mut graph = NetworkGraph::new();
    for id in ["alice", "bob", "carol", "dave", "erin"] {
        add_node(&mut graph, id);
    }

    // Two 2-hop paths and one 3-hop path, all with equal total fees for amount = 100:
    // - alice -> bob -> erin (2 hops, total CLTV 80, channels ch_b1, ch_b2)
    // - alice -> carol -> erin (2 hops, total CLTV 40, channels ch_c1, ch_c2)
    // - alice -> dave -> bob -> erin (3 hops, total fee equal via 0 base fee on first two)
    let mut channels = vec![
        ("ch_b1", "alice", "bob", 10_000, 1, 0, 40),
        ("ch_b2", "bob", "erin", 10_000, 1, 0, 40),
        ("ch_c1", "alice", "carol", 10_000, 1, 0, 20),
        ("ch_c2", "carol", "erin", 10_000, 1, 0, 20),
        ("ch_d1", "alice", "dave", 10_000, 0, 0, 10),
        ("ch_d2", "dave", "bob", 10_000, 1, 0, 10),
    ];

    if reverse_insertion {
        channels.reverse();
    }

    for (id, a, b, cap, base, rate, cltv) in channels {
        add_channel(&mut graph, id, a, b, cap, base, rate, cltv);
    }

    graph
}

#[test]
fn end_to_end_deterministic_routing_and_policy_selection() {
    let g_forward = build_multi_path_graph(false);
    let g_reverse = build_multi_path_graph(true);

    let request = RouteRequest {
        source: "alice".to_string(),
        destination: "erin".to_string(),
        amount: 100,
        max_fee_budget: Some(10),
        max_hops: Some(5),
        find_any: false,
        payment_metadata: None,
    };

    // 1. Crate-level entry point is deterministic across insertion orders.
    let route_fwd = find_best_route(&g_forward, &request).unwrap();
    let route_rev = find_best_route(&g_reverse, &request).unwrap();
    assert_eq!(route_fwd.hops, route_rev.hops);
    assert_eq!(route_fwd.hops[0].node_id, "carol");

    // 2. Pathfinder search algorithms agree on deterministic tie-breaking.
    let pf = Pathfinder::new().with_tie_breaker(TieBreaker::Canonical);
    let pf_fwd = pf.find_route_dijkstra(&g_forward, &request).unwrap();
    let pf_rev = pf.find_route_dijkstra(&g_reverse, &request).unwrap();
    assert_eq!(pf_fwd.hops, pf_rev.hops);
    assert_eq!(pf_fwd.hops[0].node_id, "carol");

    let astar_fwd = pf.find_route_astar(&g_forward, &request).unwrap();
    let astar_rev = pf.find_route_astar(&g_reverse, &request).unwrap();
    assert_eq!(astar_fwd.hops, astar_rev.hops);

    let bfs_fwd = pf.find_route_bfs(&g_forward, &request).unwrap();
    let bfs_rev = pf.find_route_bfs(&g_reverse, &request).unwrap();
    assert_eq!(bfs_fwd.hops, bfs_rev.hops);

    // 3. Configurable tie-breaker changes selection deterministically.
    let lex_route = find_best_route_with_tie_breaker(
        &g_reverse,
        &request,
        &FeeCap::protocol(),
        TieBreaker::Lexicographical,
    )
    .unwrap();
    assert_eq!(lex_route.hops[0].channel_id, "ch_b1");

    // 4. Policy evaluation ranks and selects deterministically regardless of slice order.
    let policy = RoutingPolicy::default().with_tie_breaker(TieBreaker::Canonical);
    let candidates_a = vec![lex_route.clone(), route_fwd.clone()];
    let candidates_b = vec![route_fwd.clone(), lex_route.clone()];

    let ranked_a = policy.rank_routes(&candidates_a, &request).unwrap();
    let ranked_b = policy.rank_routes(&candidates_b, &request).unwrap();
    assert_eq!(ranked_a[0].hops, ranked_b[0].hops);
    assert_eq!(ranked_a[0].hops[0].node_id, "carol");

    let selected_a = SelectionStrategy::Cheapest
        .select(&candidates_a, &policy)
        .unwrap();
    let selected_b = SelectionStrategy::Cheapest
        .select(&candidates_b, &policy)
        .unwrap();
    assert_eq!(selected_a.hops, selected_b.hops);
    assert_eq!(selected_a.hops[0].node_id, "carol");

    // 5. Invalid inputs fail explicitly.
    let mut invalid = request;
    invalid.amount = 0;
    assert!(matches!(
        find_best_route(&g_forward, &invalid).unwrap_err(),
        RoutingError::BelowDustLimit { .. }
    ));
}

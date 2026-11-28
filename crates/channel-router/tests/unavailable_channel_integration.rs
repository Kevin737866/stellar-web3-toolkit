//! Integration tests for the temporarily-unavailable channel exclusion feature.
//!
//! These tests exercise the full routing workflow end-to-end:
//! [`find_best_route`] / [`find_best_route_with_cap`] accept a
//! [`RouteRequest`] that may carry an `excluded_unavailable` list; the router
//! must skip those channels for this attempt while leaving the
//! [`NetworkGraph`] unchanged, and must return actionable errors when the
//! exclusion list itself is invalid.
//!
//! # Scenario
//!
//! ```
//!   alice ─── ch_ab ─── bob ─── ch_bc ─── carol
//!     │                                     │
//!     └─────── ch_ad ─── dave ─── ch_dc ───┘
//! ```
//!
//! Both paths are healthy to begin with.  Tests temporarily exclude channels
//! to exercise the routing fallback logic and boundary conditions.

use channel_router::{
    find_best_route, find_best_route_with_cap,
    pathfinder::Pathfinder,
    FeeCap, NetworkGraph, RouteRequest, RoutingError, UnavailabilityReason, UnavailableChannel,
    {Channel, Node, NodeFeatures},
};

// ── helpers ──────────────────────────────────────────────────────────────────

fn node(id: &str) -> Node {
    Node {
        id: id.to_string(),
        public_key: vec![1],
        alias: None,
        online: true,
        last_seen: 1_000,
        features: NodeFeatures::default(),
    }
}

fn channel(id: &str, a: &str, b: &str, fee_rate: u32) -> Channel {
    Channel {
        id: id.to_string(),
        node_a: a.to_string(),
        node_b: b.to_string(),
        capacity_a_to_b: 5_000_000,
        capacity_b_to_a: 5_000_000,
        base_fee: 1,
        fee_rate,
        cltv_delta: 40,
        min_htlc_size: 1,
        max_htlc_size: 5_000_000,
        htlcs_in_flight: 0,
        enabled: true,
        age_seconds: 3_600,
    }
}

/// Build the diamond-shaped graph described in the module doc comment.
fn diamond_graph() -> NetworkGraph {
    let mut g = NetworkGraph::new();
    for id in ["alice", "bob", "carol", "dave"] {
        g.add_node(node(id));
    }
    g.add_channel(channel("ch_ab", "alice", "bob", 1_000));
    g.add_channel(channel("ch_bc", "bob", "carol", 1_000));
    g.add_channel(channel("ch_ad", "alice", "dave", 1_000));
    g.add_channel(channel("ch_dc", "dave", "carol", 1_000));
    g
}

fn req(source: &str, destination: &str, amount: i128) -> RouteRequest {
    RouteRequest {
        source: source.to_string(),
        destination: destination.to_string(),
        amount,
        max_fee_budget: None,
        max_hops: None,
        find_any: false,
        payment_metadata: None,
        excluded_unavailable: vec![],
    }
}

fn exclude(channel_id: &str, reason: UnavailabilityReason) -> UnavailableChannel {
    UnavailableChannel::until(channel_id.to_string(), reason, None)
}

// ── normal-case tests ─────────────────────────────────────────────────────────

/// With no exclusions, both paths are available and the router picks one.
#[test]
fn baseline_route_succeeds_with_no_exclusions() {
    let graph = diamond_graph();
    let route = find_best_route(&graph, &req("alice", "carol", 100_000)).unwrap();
    assert!(!route.hops.is_empty());
    assert_eq!(route.total_amount, 100_000);
}

/// When only the top path is excluded, the router takes the bottom path.
#[test]
fn router_uses_alternative_path_when_one_path_excluded() {
    let graph = diamond_graph();

    let route = find_best_route(
        &graph,
        &RouteRequest {
            excluded_unavailable: vec![exclude("ch_ab", UnavailabilityReason::ForwardingFailure)],
            ..req("alice", "carol", 100_000)
        },
    )
    .unwrap();

    // Route must only use the dave leg.
    for hop in &route.hops {
        assert_ne!(hop.channel_id, "ch_ab", "ch_ab must be skipped");
        assert_ne!(
            hop.channel_id, "ch_bc",
            "ch_bc must be skipped (unreachable via bob)"
        );
    }
    let channel_ids: Vec<_> = route.hops.iter().map(|h| h.channel_id.as_str()).collect();
    assert!(
        channel_ids.contains(&"ch_ad") && channel_ids.contains(&"ch_dc"),
        "expected route via dave, got: {channel_ids:?}"
    );
}

/// When both paths are excluded, the router returns `NoPathFound`.
#[test]
fn no_path_found_when_all_alternatives_excluded() {
    let graph = diamond_graph();

    let err = find_best_route(
        &graph,
        &RouteRequest {
            excluded_unavailable: vec![
                exclude("ch_ab", UnavailabilityReason::PeerOffline),
                exclude("ch_ad", UnavailabilityReason::ChannelOffline),
            ],
            ..req("alice", "carol", 100_000)
        },
    )
    .unwrap_err();

    assert!(
        matches!(err, RoutingError::NoPathFound { .. }),
        "expected NoPathFound, got {err}"
    );
}

/// Excluding a channel does not modify the graph; the same graph can route
/// successfully in a subsequent call.
#[test]
fn exclusion_is_per_request_and_does_not_modify_graph() {
    let graph = diamond_graph();
    let channel_count_before = graph.num_channels();

    // First attempt: exclude ch_ab.
    let _ = find_best_route(
        &graph,
        &RouteRequest {
            excluded_unavailable: vec![exclude("ch_ab", UnavailabilityReason::Other)],
            ..req("alice", "carol", 100_000)
        },
    );

    // Graph is unchanged.
    assert_eq!(graph.num_channels(), channel_count_before);
    assert!(graph.has_channel("ch_ab"));

    // Second attempt with no exclusions succeeds normally.
    assert!(find_best_route(&graph, &req("alice", "carol", 100_000)).is_ok());
}

// ── boundary-case tests ───────────────────────────────────────────────────────

/// A channel ID that is not in the graph is silently ignored.
#[test]
fn excluding_nonexistent_channel_is_harmless() {
    let graph = diamond_graph();

    let route = find_best_route(
        &graph,
        &RouteRequest {
            excluded_unavailable: vec![exclude("ch_does_not_exist", UnavailabilityReason::Other)],
            ..req("alice", "carol", 100_000)
        },
    )
    .unwrap();

    assert!(!route.hops.is_empty());
}

/// An exclusion entry with `unavailable_until = Some(expiry)` is accepted and
/// the channel is still skipped.
#[test]
fn exclusion_with_expiry_timestamp_is_respected() {
    let graph = diamond_graph();

    let route = find_best_route(
        &graph,
        &RouteRequest {
            excluded_unavailable: vec![UnavailableChannel::until(
                "ch_ab".to_string(),
                UnavailabilityReason::ForwardingFailure,
                Some(1_700_000_060), // non-zero expiry
            )],
            ..req("alice", "carol", 100_000)
        },
    )
    .unwrap();

    assert!(
        route.hops.iter().all(|h| h.channel_id != "ch_ab"),
        "ch_ab must not appear in the route"
    );
}

// ── failure-case tests ────────────────────────────────────────────────────────

/// An empty channel ID in the exclusion list is rejected before any traversal.
#[test]
fn empty_channel_id_in_exclusion_is_rejected() {
    let graph = diamond_graph();

    let err = find_best_route(
        &graph,
        &RouteRequest {
            excluded_unavailable: vec![UnavailableChannel::until(
                String::new(),
                UnavailabilityReason::Other,
                None,
            )],
            ..req("alice", "carol", 100_000)
        },
    )
    .unwrap_err();

    assert!(
        matches!(err, RoutingError::ChannelNotFound { .. }),
        "expected ChannelNotFound for empty channel ID, got {err}"
    );
}

/// `unavailable_until = Some(0)` is unambiguously invalid and must be
/// rejected.
#[test]
fn zero_expiry_in_exclusion_is_rejected() {
    let graph = diamond_graph();

    let err = find_best_route(
        &graph,
        &RouteRequest {
            excluded_unavailable: vec![UnavailableChannel::until(
                "ch_ab".to_string(),
                UnavailabilityReason::Other,
                Some(0), // invalid
            )],
            ..req("alice", "carol", 100_000)
        },
    )
    .unwrap_err();

    assert!(
        matches!(err, RoutingError::InvalidNodeAddress),
        "expected InvalidNodeAddress for zero expiry, got {err}"
    );
}

// ── integration with FeeCap and Pathfinder ───────────────────────────────────

/// Exclusions and the fee cap are enforced together: an excluded channel is
/// skipped even when it would otherwise satisfy the fee cap.
#[test]
fn exclusion_and_fee_cap_are_both_enforced() {
    let graph = diamond_graph();
    let cap = FeeCap::protocol();

    // Exclude the top path; the bottom path exists and is within the cap.
    let route = find_best_route_with_cap(
        &graph,
        &RouteRequest {
            excluded_unavailable: vec![exclude("ch_bc", UnavailabilityReason::PeerOffline)],
            ..req("alice", "carol", 100_000)
        },
        &cap,
    )
    .unwrap();

    assert!(route.hops.iter().all(|h| h.channel_id != "ch_bc"));
}

/// `Pathfinder` respects exclusions from `RouteRequest` for all three main
/// deterministic algorithms.
#[test]
fn pathfinder_algorithms_all_respect_excluded_unavailable() {
    let graph = diamond_graph();
    let pathfinder = Pathfinder::new();

    let request = RouteRequest {
        excluded_unavailable: vec![exclude("ch_ab", UnavailabilityReason::ForwardingFailure)],
        ..req("alice", "carol", 100_000)
    };

    for route in [
        pathfinder.find_route_dijkstra(&graph, &request).unwrap(),
        pathfinder.find_route_astar(&graph, &request).unwrap(),
        pathfinder.find_route_bfs(&graph, &request).unwrap(),
    ] {
        assert!(
            route.hops.iter().all(|h| h.channel_id != "ch_ab"),
            "ch_ab must not appear in the route"
        );
    }
}

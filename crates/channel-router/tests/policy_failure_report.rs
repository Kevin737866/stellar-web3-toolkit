//! Integration coverage for issue #365: policy rejections must explain which
//! candidate route failed and which rule rejected it.

use channel_router::policy::RoutingPolicy;
use channel_router::{
    evaluate_route_policy, find_best_route_with_policy, Channel, Node, NodeFeatures,
    PaymentMetadata, PaymentType, PolicyFailureReason, RoutePolicyError, RouteRequest,
};

fn node(id: &str, byte: u8) -> Node {
    Node {
        id: id.to_string(),
        public_key: vec![byte],
        alias: None,
        online: true,
        last_seen: 1_000,
        features: NodeFeatures::default(),
    }
}

fn channel(id: &str, a: &str, b: &str, fee_rate: u32, cltv: u32) -> Channel {
    Channel {
        id: id.to_string(),
        node_a: a.to_string(),
        node_b: b.to_string(),
        capacity_a_to_b: 100_000,
        capacity_b_to_a: 100_000,
        base_fee: 0,
        fee_rate,
        cltv_delta: cltv,
        min_htlc_size: 1,
        max_htlc_size: 100_000,
        htlcs_in_flight: 0,
        enabled: true,
        age_seconds: 3_600,
    }
}

fn graph(channels: Vec<Channel>) -> channel_router::NetworkGraph {
    let mut graph = channel_router::NetworkGraph::new();
    for (byte, id) in ["alice", "bob", "carol", "dave"].iter().enumerate() {
        graph.add_node(node(id, byte as u8 + 1));
    }
    for item in channels {
        graph.add_channel(item);
    }
    graph
}

fn request(source: &str, destination: &str) -> RouteRequest {
    RouteRequest {
        source: source.to_string(),
        destination: destination.to_string(),
        amount: 1_000,
        max_fee_budget: None,
        max_hops: None,
        find_any: false,
        payment_metadata: None,
        excluded_unavailable: Vec::new(),
    }
}

#[test]
fn every_rejected_candidate_reports_its_rule() {
    let graph = graph(vec![
        // Above the protocol fee-rate cap: rejected at hop 0.
        channel("greedy", "alice", "bob", 6_000, 0),
        // Within fee caps, but too little CLTV for the payment.
        channel("via_carol", "alice", "carol", 0, 20),
        channel("last_hop", "carol", "bob", 0, 20),
    ]);
    let mut request = request("alice", "bob");
    request.payment_metadata = Some(PaymentMetadata {
        payment_type: PaymentType::Regular,
        required_cltv_delta: Some(100),
        payment_expiry: None,
    });

    let report = evaluate_route_policy(&graph, &request, &RoutingPolicy::default()).unwrap();
    assert_eq!(report.candidates_evaluated, 2);
    assert_eq!(report.accepted, 0);
    assert!(!report.has_route());

    let fee_failure = report
        .failures
        .iter()
        .find(|failure| failure.route.channel_ids == ["greedy"])
        .expect("fee-capped candidate should be reported");
    assert_eq!(fee_failure.hop_index, Some(0));
    assert!(matches!(
        fee_failure.reason,
        PolicyFailureReason::FeeRateTooHigh { .. }
    ));

    let timeout_failure = report
        .failures
        .iter()
        .find(|failure| failure.route.channel_ids == ["via_carol", "last_hop"])
        .expect("timeout-unsafe candidate should be reported");
    assert_eq!(
        timeout_failure.reason,
        PolicyFailureReason::UnsafeTimeout {
            channel_id: "via_carol".to_string(),
            cltv_delta: 20,
            required: 100,
        }
    );
    assert!(fee_failure.message().contains("greedy"));
    assert!(
        report.message().contains("last_hop") || timeout_failure.message().contains("last_hop")
    );
}

#[test]
fn rejected_search_returns_an_actionable_error() {
    let graph = graph(vec![channel("greedy", "alice", "bob", 6_000, 0)]);
    let result =
        find_best_route_with_policy(&graph, &request("alice", "bob"), &RoutingPolicy::default());

    match result {
        Err(RoutePolicyError::Rejected(report)) => {
            assert!(report.message().contains("greedy"));
            assert!(report.message().contains("ppm"));
        }
        other => panic!("expected a Rejected report, got {other:?}"),
    }
}

#[test]
fn a_valid_route_is_returned_with_a_clean_report() {
    let graph = graph(vec![channel("ok", "alice", "bob", 1_000, 0)]);
    let request = request("alice", "bob");

    let report = evaluate_route_policy(&graph, &request, &RoutingPolicy::default()).unwrap();
    assert!(report.has_route());
    assert!(report.failures.is_empty());

    let route = find_best_route_with_policy(&graph, &request, &RoutingPolicy::default()).unwrap();
    assert_eq!(route.hops[0].channel_id, "ok");
    assert_eq!(route.total_amount, 1_000);
}

#[test]
fn selection_is_deterministic_for_equal_cost_routes() {
    let graph = graph(vec![
        channel("zeta", "alice", "carol", 0, 10),
        channel("carol_bob", "carol", "bob", 0, 10),
        channel("alpha", "alice", "dave", 0, 10),
        channel("dave_bob", "dave", "bob", 0, 10),
    ]);
    let request = request("alice", "bob");
    let first = find_best_route_with_policy(&graph, &request, &RoutingPolicy::default()).unwrap();
    let second = find_best_route_with_policy(&graph, &request, &RoutingPolicy::default()).unwrap();

    let first_ids: Vec<_> = first
        .hops
        .iter()
        .map(|hop| hop.channel_id.clone())
        .collect();
    let second_ids: Vec<_> = second
        .hops
        .iter()
        .map(|hop| hop.channel_id.clone())
        .collect();
    assert_eq!(first_ids, second_ids);
    assert_eq!(first_ids, ["alpha", "dave_bob"]);
}

#[test]
fn invalid_inputs_are_rejected_without_touching_the_graph() {
    let graph = graph(vec![channel("ok", "alice", "bob", 0, 0)]);
    let channels_before = graph.num_channels();

    let mut blank = request(" ", "bob");
    assert!(matches!(
        evaluate_route_policy(&graph, &blank, &RoutingPolicy::default()),
        Err(RoutePolicyError::InvalidRequest(_))
    ));
    blank.source = "alice".to_string();
    blank.destination = "alice".to_string();
    assert!(matches!(
        find_best_route_with_policy(&graph, &blank, &RoutingPolicy::default()),
        Err(RoutePolicyError::InvalidRequest(_))
    ));

    let bad_policy = RoutingPolicy {
        max_fee_bps: 0,
        ..RoutingPolicy::default()
    };
    assert!(matches!(
        evaluate_route_policy(&graph, &request("alice", "bob"), &bad_policy),
        Err(RoutePolicyError::InvalidPolicy(_))
    ));
    assert_eq!(graph.num_channels(), channels_before);
}

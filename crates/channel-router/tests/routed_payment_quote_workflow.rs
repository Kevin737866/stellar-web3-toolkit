//! Integration test for the routed-payment fee and timeout workflow.
//!
//! This exercises the public entry point documented in
//! `docs/ROUTED_PAYMENT_FEES_AND_TIMEOUTS.md` end to end: build a graph, ask
//! for an exact-delivery quote, and feed the resulting route back through the
//! existing fee-cap validator.

use channel_router::{
    calculate_channel_fee, plan_route, Channel, FeeCap, NetworkGraph, Node, NodeFeatures,
    QuoteOptions, RouteRequest,
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

fn add_channel(
    graph: &mut NetworkGraph,
    id: &str,
    node_a: &str,
    node_b: &str,
    base_fee: i128,
    fee_rate: u32,
    cltv_delta: u32,
    capacity: i128,
) {
    graph.add_channel(Channel {
        id: id.to_string(),
        node_a: node_a.to_string(),
        node_b: node_b.to_string(),
        capacity_a_to_b: capacity,
        capacity_b_to_a: capacity,
        base_fee,
        fee_rate,
        cltv_delta,
        min_htlc_size: 1,
        max_htlc_size: capacity,
        htlcs_in_flight: 0,
        enabled: true,
        age_seconds: 0,
    });
}

#[test]
fn routed_payment_quote_workflow_is_consistent_with_fee_caps() {
    let mut graph = NetworkGraph::new();
    for id in ["alice", "bob", "carol"] {
        add_node(&mut graph, id);
    }
    add_channel(&mut graph, "ch1", "alice", "bob", 10, 500, 40, 2_000_000);
    add_channel(&mut graph, "ch2", "bob", "carol", 5, 1_000, 30, 2_000_000);

    let request = RouteRequest {
        source: "alice".to_string(),
        destination: "carol".to_string(),
        amount: 1_000_000,
        max_fee_budget: Some(1_515),
        max_hops: Some(3),
        find_any: false,
        payment_metadata: None,
    };
    let options = QuoteOptions::new(900, 1_000).with_deadline(1_200);

    let plan = plan_route(&graph, &request, options).expect("documented route should be quotable");

    // The quote is the worked example: 1_005 for the final hop, then 510 on
    // the amount that hop must forward.
    assert_eq!(plan.quote.total_fee, 1_515);
    assert_eq!(plan.quote.sender_amount, 1_001_515);
    assert_eq!(plan.quote.hops[0].expiry_height, 1_070);
    assert_eq!(plan.quote.hops[1].expiry_height, 1_030);

    // The route is built from the quote, so its summary and hops agree.
    let hop_sum: i128 = plan.route.hops.iter().map(|hop| hop.fee).sum();
    assert_eq!(plan.route.total_fees, hop_sum);
    assert_eq!(plan.route.hops[1].amount, 1_000_000);
    assert_eq!(plan.route.hops[0].amount, 1_001_005);
    assert_eq!(
        calculate_channel_fee(1_000_000, 5, 1_000, 30),
        plan.quote.hops[1].fee
    );

    // The existing protocol validator accepts the new route unchanged.
    FeeCap::protocol()
        .check_route(request.amount, &plan.route)
        .expect("quoted route should satisfy the protocol fee cap");
}

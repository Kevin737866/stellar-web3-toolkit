//! Routing regression tests against the baseline network fixture (#387).

use channel_router::pathfinder::Pathfinder;
use channel_router::RoutingError;
use channel_simulator::{
    baseline_network, validate_baseline_specs, BaselineChannelSpec, BaselineNodeSpec,
    BASELINE_CHANNELS, BASELINE_NODES, BASELINE_ROUTES, BASELINE_UNROUTABLE,
};

#[test]
fn the_baseline_fixture_loads_with_the_expected_shape() {
    let graph = baseline_network().expect("the committed fixture must build");

    assert_eq!(graph.num_nodes(), BASELINE_NODES.len());
    assert_eq!(graph.num_channels(), BASELINE_CHANNELS.len());
    assert_eq!(graph.num_nodes(), 7);
    assert_eq!(graph.num_channels(), 7);

    // Isolated nodes are part of the fixture: they pin "no route" behaviour.
    assert!(graph.adjacency["grace"].is_empty());
}

#[test]
fn every_pinned_route_still_resolves_to_the_same_hops_and_fees() {
    let graph = baseline_network().unwrap();
    let pathfinder = Pathfinder::new();

    for case in BASELINE_ROUTES {
        let route = pathfinder
            .find_route_dijkstra(&graph, &case.request())
            .unwrap_or_else(|error| panic!("{}: route disappeared: {error}", case.name));

        let hops: Vec<&str> = route.hops.iter().map(|hop| hop.node_id.as_str()).collect();
        assert_eq!(
            hops, case.expected_hops,
            "{}: router chose different hops",
            case.name
        );
        assert_eq!(
            route.total_fees, case.expected_total_fees,
            "{}: router charged different fees",
            case.name
        );
        assert_eq!(route.total_amount, case.amount);
    }
}

#[test]
fn pinned_failures_keep_failing() {
    let graph = baseline_network().unwrap();
    let pathfinder = Pathfinder::new();

    for case in BASELINE_UNROUTABLE {
        let error = pathfinder
            .find_route_dijkstra(&graph, &case.request())
            .expect_err(&format!("{}: expected no route", case.name));
        assert!(
            matches!(error, RoutingError::NoPathFound { .. }),
            "{}: expected NoPathFound, got {error:?}",
            case.name
        );
    }
}

#[test]
fn the_fixture_is_deterministic_across_builds() {
    let first = baseline_network().unwrap();
    let second = baseline_network().unwrap();

    assert_eq!(first.num_nodes(), second.num_nodes());
    assert_eq!(first.num_channels(), second.num_channels());

    let pathfinder = Pathfinder::new();
    for case in BASELINE_ROUTES {
        let a = pathfinder
            .find_route_dijkstra(&first, &case.request())
            .unwrap();
        let b = pathfinder
            .find_route_dijkstra(&second, &case.request())
            .unwrap();
        assert_eq!(a, b, "{}: fixture is not deterministic", case.name);
    }
}

#[test]
fn invalid_fixtures_are_rejected_with_the_offending_id() {
    let nodes = [BaselineNodeSpec {
        id: "a",
        alias: "A",
    }];
    let good_channel = BaselineChannelSpec {
        id: "ch",
        node_a: "a",
        node_b: "a",
        capacity_a_to_b: 1,
        capacity_b_to_a: 1,
        base_fee: 0,
        fee_rate: 0,
        cltv_delta: 1,
    };

    // Self-loop.
    let error = validate_baseline_specs(&nodes, &[good_channel]).unwrap_err();
    assert!(error.to_string().contains("self-loop"));

    // Unknown endpoint.
    let mut dangling = good_channel;
    dangling.node_b = "missing";
    let error = validate_baseline_specs(&nodes, &[dangling]).unwrap_err();
    assert!(error.to_string().contains("missing"));

    // Duplicate node id.
    let duplicate_nodes = [
        BaselineNodeSpec {
            id: "a",
            alias: "A",
        },
        BaselineNodeSpec {
            id: "a",
            alias: "A again",
        },
    ];
    let error = validate_baseline_specs(&duplicate_nodes, &[]).unwrap_err();
    assert!(error.to_string().contains("duplicate node id"));

    // Duplicate channel id.
    let mut two_nodes = nodes.to_vec();
    two_nodes.push(BaselineNodeSpec {
        id: "b",
        alias: "B",
    });
    let mut first = good_channel;
    first.node_b = "b";
    let mut second = good_channel;
    second.node_b = "b";
    let error = validate_baseline_specs(&two_nodes, &[first, second]).unwrap_err();
    assert!(error.to_string().contains("duplicate channel id"));

    // Negative capacity.
    let mut negative = good_channel;
    negative.node_b = "b";
    negative.capacity_a_to_b = -1;
    let error = validate_baseline_specs(&two_nodes, &[negative]).unwrap_err();
    assert!(error.to_string().contains("negative capacity"));
}

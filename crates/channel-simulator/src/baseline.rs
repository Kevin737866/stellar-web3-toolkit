//! # Baseline Network Fixture
//!
//! A small, hand-written payment-channel network used by routing regression
//! tests. It is the counterpart to the random topologies: those are good at
//! finding new invariants, but they cannot pin the *answer* a router gives,
//! because every run produces a different graph.
//!
//! The fixture is defined in code as [`BASELINE_NODES`] and
//! [`BASELINE_CHANNELS`] so it is readable, reviewable and independent of any
//! ambient entropy. [`BASELINE_ROUTES`] records the exact hops and fees the
//! router is expected to choose, and [`BASELINE_UNROUTABLE`] records requests
//! that must keep failing. A routing change that alters any pinned answer shows
//! up as a single named test failure.
//!
//! ## Topology
//!
//! ```text
//!        base 1            base 1            base 1
//! alice --------- bob ------------ dave ------------ frank
//!   \             |                 |                  /
//!    \ base 5     | base 10         | base 1          / base 5
//!     \           |                 |                /
//!      +------ carol ---------------+         erin --+
//!                                       (dave-erin cap 100_000)
//! grace (isolated, with no channels)
//! ```
//!
//! Fee rates are zero on purpose: with only flat base fees the cheapest route
//! is unambiguous, so the pinned hops do not depend on how the router breaks
//! ties between equal-cost neighbours.

use crate::{SimulatedNode, SimulatorError};
use channel_router::{Channel, NetworkGraph, Node, RouteRequest};
use std::collections::{HashMap, HashSet};

/// Name and version of this fixture, stable so tests can report which baseline
/// they ran against.
pub const BASELINE_NETWORK_NAME: &str = "baseline-routing-v1";

/// The default payment amount for [`BASELINE_ROUTES`].
pub const BASELINE_AMOUNT: i128 = 1_000;

/// A node in the baseline fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineNodeSpec {
    /// Node id used as the routing address.
    pub id: &'static str,
    /// Human-readable alias.
    pub alias: &'static str,
}

/// A channel in the baseline fixture.
///
/// Capacities are directional: `capacity_a_to_b` is available from `node_a` to
/// `node_b` only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineChannelSpec {
    /// Channel id, unique within the fixture.
    pub id: &'static str,
    /// First endpoint.
    pub node_a: &'static str,
    /// Second endpoint.
    pub node_b: &'static str,
    /// Capacity from `node_a` to `node_b`.
    pub capacity_a_to_b: i128,
    /// Capacity from `node_b` to `node_a`.
    pub capacity_b_to_a: i128,
    /// Flat fee per hop, in stroops.
    pub base_fee: i128,
    /// Proportional fee in ppm. Zero for every fixture channel on purpose.
    pub fee_rate: u32,
    /// CLTV delta for the hop.
    pub cltv_delta: u32,
}

impl BaselineChannelSpec {
    /// Materialise the fixture channel for a [`NetworkGraph`].
    pub fn to_channel(self) -> Channel {
        Channel {
            id: self.id.to_string(),
            node_a: self.node_a.to_string(),
            node_b: self.node_b.to_string(),
            capacity_a_to_b: self.capacity_a_to_b,
            capacity_b_to_a: self.capacity_b_to_a,
            base_fee: self.base_fee,
            fee_rate: self.fee_rate,
            cltv_delta: self.cltv_delta,
            min_htlc_size: 1,
            max_htlc_size: self.capacity_a_to_b.max(self.capacity_b_to_a),
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 0,
        }
    }
}

/// A routing case whose answer is pinned by this fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineRouteCase {
    /// Short name used in test messages.
    pub name: &'static str,
    /// Payment source.
    pub source: &'static str,
    /// Payment destination.
    pub destination: &'static str,
    /// Amount to route.
    pub amount: i128,
    /// Node ids of the hops after the source, in order.
    pub expected_hops: &'static [&'static str],
    /// Expected `Route::total_fees`.
    pub expected_total_fees: i128,
}

impl BaselineRouteCase {
    /// Build the [`RouteRequest`] this case describes.
    pub fn request(self) -> RouteRequest {
        RouteRequest {
            source: self.source.to_string(),
            destination: self.destination.to_string(),
            amount: self.amount,
            max_fee_budget: None,
            max_hops: None,
            find_any: false,
            payment_metadata: None,
        }
    }
}

/// A request that must keep failing, with the category it must fail for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineFailureCase {
    /// Short name used in test messages.
    pub name: &'static str,
    /// Payment source.
    pub source: &'static str,
    /// Payment destination.
    pub destination: &'static str,
    /// Amount to attempt.
    pub amount: i128,
}

impl BaselineFailureCase {
    /// Build the [`RouteRequest`] this case describes.
    pub fn request(self) -> RouteRequest {
        RouteRequest {
            source: self.source.to_string(),
            destination: self.destination.to_string(),
            amount: self.amount,
            max_fee_budget: None,
            max_hops: None,
            find_any: false,
            payment_metadata: None,
        }
    }
}

/// Nodes in the baseline fixture.
pub const BASELINE_NODES: &[BaselineNodeSpec] = &[
    BaselineNodeSpec {
        id: "alice",
        alias: "Alice",
    },
    BaselineNodeSpec {
        id: "bob",
        alias: "Bob",
    },
    BaselineNodeSpec {
        id: "carol",
        alias: "Carol",
    },
    BaselineNodeSpec {
        id: "dave",
        alias: "Dave",
    },
    BaselineNodeSpec {
        id: "erin",
        alias: "Erin",
    },
    BaselineNodeSpec {
        id: "frank",
        alias: "Frank",
    },
    BaselineNodeSpec {
        id: "grace",
        alias: "Grace (isolated)",
    },
];

/// Channels in the baseline fixture.
pub const BASELINE_CHANNELS: &[BaselineChannelSpec] = &[
    BaselineChannelSpec {
        id: "ch_alice_bob",
        node_a: "alice",
        node_b: "bob",
        capacity_a_to_b: 1_000_000,
        capacity_b_to_a: 1_000_000,
        base_fee: 1,
        fee_rate: 0,
        cltv_delta: 10,
    },
    BaselineChannelSpec {
        id: "ch_bob_dave",
        node_a: "bob",
        node_b: "dave",
        capacity_a_to_b: 1_000_000,
        capacity_b_to_a: 1_000_000,
        base_fee: 1,
        fee_rate: 0,
        cltv_delta: 10,
    },
    BaselineChannelSpec {
        id: "ch_dave_frank",
        node_a: "dave",
        node_b: "frank",
        capacity_a_to_b: 1_000_000,
        capacity_b_to_a: 1_000_000,
        base_fee: 1,
        fee_rate: 0,
        cltv_delta: 10,
    },
    BaselineChannelSpec {
        id: "ch_alice_carol",
        node_a: "alice",
        node_b: "carol",
        capacity_a_to_b: 1_000_000,
        capacity_b_to_a: 1_000_000,
        base_fee: 5,
        fee_rate: 0,
        cltv_delta: 10,
    },
    BaselineChannelSpec {
        id: "ch_carol_frank",
        node_a: "carol",
        node_b: "frank",
        capacity_a_to_b: 1_000_000,
        capacity_b_to_a: 1_000_000,
        base_fee: 5,
        fee_rate: 0,
        cltv_delta: 10,
    },
    BaselineChannelSpec {
        id: "ch_bob_carol",
        node_a: "bob",
        node_b: "carol",
        capacity_a_to_b: 1_000_000,
        capacity_b_to_a: 1_000_000,
        base_fee: 10,
        fee_rate: 0,
        cltv_delta: 10,
    },
    BaselineChannelSpec {
        id: "ch_dave_erin",
        node_a: "dave",
        node_b: "erin",
        capacity_a_to_b: 100_000,
        capacity_b_to_a: 100_000,
        base_fee: 1,
        fee_rate: 0,
        cltv_delta: 10,
    },
];

/// Routing answers pinned by the fixture.
pub const BASELINE_ROUTES: &[BaselineRouteCase] = &[
    BaselineRouteCase {
        name: "alice_to_frank_prefers_cheapest_three_hops",
        source: "alice",
        destination: "frank",
        amount: BASELINE_AMOUNT,
        expected_hops: &["bob", "dave", "frank"],
        expected_total_fees: 3,
    },
    BaselineRouteCase {
        name: "alice_to_carol_uses_the_direct_channel",
        source: "alice",
        destination: "carol",
        amount: BASELINE_AMOUNT,
        expected_hops: &["carol"],
        expected_total_fees: 5,
    },
    BaselineRouteCase {
        name: "alice_to_erin_uses_the_capacity_limited_spur",
        source: "alice",
        destination: "erin",
        amount: 50_000,
        expected_hops: &["bob", "dave", "erin"],
        expected_total_fees: 3,
    },
];

/// Requests that must keep failing against the fixture.
pub const BASELINE_UNROUTABLE: &[BaselineFailureCase] = &[
    BaselineFailureCase {
        name: "isolated_node_has_no_route",
        source: "alice",
        destination: "grace",
        amount: BASELINE_AMOUNT,
    },
    BaselineFailureCase {
        name: "amount_above_the_spur_capacity_has_no_route",
        source: "alice",
        destination: "erin",
        amount: 200_000,
    },
    BaselineFailureCase {
        name: "unknown_destination_has_no_route",
        source: "alice",
        destination: "nobody",
        amount: BASELINE_AMOUNT,
    },
];

/// Reject a fixture that is not a valid network.
///
/// Exposed so tests can prove the checks work on broken input; the committed
/// constants must always pass. Returns [`SimulatorError::InvalidConfig`] with
/// the offending id.
pub fn validate_baseline_specs(
    nodes: &[BaselineNodeSpec],
    channels: &[BaselineChannelSpec],
) -> Result<(), SimulatorError> {
    if nodes.is_empty() {
        return Err(SimulatorError::InvalidConfig(
            "baseline fixture must contain at least one node".to_string(),
        ));
    }

    let mut node_ids = HashSet::with_capacity(nodes.len());
    for node in nodes {
        if node.id.is_empty() {
            return Err(SimulatorError::InvalidConfig(
                "baseline fixture contains a node with an empty id".to_string(),
            ));
        }
        if !node_ids.insert(node.id) {
            return Err(SimulatorError::InvalidConfig(format!(
                "baseline fixture contains duplicate node id '{}'",
                node.id
            )));
        }
    }

    let mut channel_ids = HashSet::with_capacity(channels.len());
    for channel in channels {
        if channel.id.is_empty() {
            return Err(SimulatorError::InvalidConfig(
                "baseline fixture contains a channel with an empty id".to_string(),
            ));
        }
        if !channel_ids.insert(channel.id) {
            return Err(SimulatorError::InvalidConfig(format!(
                "baseline fixture contains duplicate channel id '{}'",
                channel.id
            )));
        }
        if channel.node_a == channel.node_b {
            return Err(SimulatorError::InvalidConfig(format!(
                "baseline channel '{}' is a self-loop on '{}'",
                channel.id, channel.node_a
            )));
        }
        for endpoint in [channel.node_a, channel.node_b] {
            if !node_ids.contains(endpoint) {
                return Err(SimulatorError::InvalidConfig(format!(
                    "baseline channel '{}' references unknown node '{endpoint}'",
                    channel.id
                )));
            }
        }
        if channel.capacity_a_to_b < 0 || channel.capacity_b_to_a < 0 {
            return Err(SimulatorError::InvalidConfig(format!(
                "baseline channel '{}' has a negative capacity",
                channel.id
            )));
        }
        if channel.base_fee < 0 {
            return Err(SimulatorError::InvalidConfig(format!(
                "baseline channel '{}' has a negative base fee",
                channel.id
            )));
        }
    }

    Ok(())
}

/// Build the baseline [`NetworkGraph`] used by routing regression tests.
///
/// Fails with [`SimulatorError::InvalidConfig`] if the constants have been
/// edited into an invalid network; the returned graph is otherwise fully
/// deterministic.
pub fn baseline_network() -> Result<NetworkGraph, SimulatorError> {
    validate_baseline_specs(BASELINE_NODES, BASELINE_CHANNELS)?;

    let mut graph = NetworkGraph::new();
    for node in baseline_nodes() {
        graph.add_node(node);
    }
    for spec in BASELINE_CHANNELS {
        graph.add_channel(spec.to_channel());
    }
    Ok(graph)
}

/// The fixture nodes as router [`Node`] values.
///
/// Public keys are derived from the node's position so the fixture carries no
/// random material, while still giving every node a distinct 32-byte key.
pub fn baseline_nodes() -> Vec<Node> {
    BASELINE_NODES
        .iter()
        .enumerate()
        .map(|(index, spec)| {
            let mut public_key = vec![0u8; 32];
            public_key[31] = u8::try_from(index).unwrap_or(u8::MAX);
            Node {
                id: spec.id.to_string(),
                public_key,
                alias: Some(spec.alias.to_string()),
                online: true,
                last_seen: 0,
                features: channel_router::NodeFeatures::default(),
            }
        })
        .collect()
}

/// The fixture nodes as [`SimulatedNode`] values, for code paths that require
/// the simulator's node bookkeeping (for example disconnection tracking).
pub fn baseline_simulated_nodes() -> HashMap<String, SimulatedNode> {
    let mut nodes = HashMap::new();
    for node in baseline_nodes() {
        let id = node.id.clone();
        nodes.insert(
            id,
            SimulatedNode {
                node,
                balance: 0,
                channels: HashSet::new(),
            },
        );
    }
    for channel in BASELINE_CHANNELS {
        if let Some(node) = nodes.get_mut(channel.node_a) {
            node.channels.insert(channel.node_b.to_string());
        }
        if let Some(node) = nodes.get_mut(channel.node_b) {
            node.channels.insert(channel.node_a.to_string());
        }
    }
    nodes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_committed_fixture_is_a_valid_network() {
        validate_baseline_specs(BASELINE_NODES, BASELINE_CHANNELS)
            .expect("the committed baseline fixture must be valid");
    }

    #[test]
    fn simulated_nodes_mirror_the_graph_adjacency() {
        let graph = baseline_network().unwrap();
        let nodes = baseline_simulated_nodes();

        assert_eq!(nodes.len(), BASELINE_NODES.len());
        for (node_id, simulated) in &nodes {
            let graph_neighbours = graph
                .adjacency
                .get(node_id)
                .map_or(0, std::collections::HashMap::len);
            assert_eq!(
                simulated.channels.len(),
                graph_neighbours,
                "node '{node_id}' has a different channel set than the graph"
            );
        }
    }
}

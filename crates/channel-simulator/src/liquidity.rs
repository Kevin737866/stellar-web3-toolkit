//! # Channel Liquidity Depletion
//!
//! Models the effect of routed payments on channel balances.
//!
//! Without this, a simulation routes every payment against the balances the
//! network was generated with: a single well-connected channel can carry an
//! unbounded number of payments, so the reported success rate says nothing about
//! whether the network could actually settle them. Real channels are finite and
//! directional — sending value from A to B empties the A→B side and fills the
//! B→A side — so the payments a network can carry are bounded by how much
//! liquidity sits on the right side of the right channels.
//!
//! [`LiquidityModel::Depleting`] applies each routed payment to the channels it
//! uses, moving value from the sending side to the receiving side at every hop.
//! A payment whose route no longer has enough capacity is rejected with an
//! actionable error instead of being counted as a success.
//!
//! The default, [`LiquidityModel::Static`], keeps the previous behavior:
//! balances are generated once and never change.
//!
//! ## Invariants
//!
//! * Per channel, `capacity_a_to_b + capacity_b_to_a` is conserved: value moves
//!   across the channel, it is not created or destroyed.
//! * Capacities never go negative; a hop that would overdraw is rejected.
//! * Updates are applied atomically: if any hop is invalid, no channel is
//!   modified, so a rejected payment cannot leave the network half-updated.

use crate::SimulatorError;
use channel_router::{Direction, NetworkGraph, Route};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// How the simulator treats channel balances across payments.
///
/// # Compatibility
///
/// [`SimulatorConfig::liquidity_model`](crate::SimulatorConfig::liquidity_model)
/// defaults to [`LiquidityModel::Static`], so callers that do not opt in observe
/// exactly the same results and RNG sequence as before depletion was modeled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum LiquidityModel {
    /// Balances are fixed at network generation time; payments do not move them.
    #[default]
    Static,
    /// Each routed payment moves value across every channel it uses.
    Depleting,
}

impl LiquidityModel {
    /// Stable name for reports and logs.
    pub fn name(self) -> &'static str {
        match self {
            LiquidityModel::Static => "static",
            LiquidityModel::Depleting => "depleting",
        }
    }
}

/// What a single payment did to channel balances.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LiquidityUpdate {
    /// Hops whose balances were changed.
    pub hops_applied: usize,
    /// Channels this payment left with no capacity in at least one direction.
    pub channels_emptied: usize,
    /// Total value moved across the channels by this payment.
    pub value_moved: i128,
}

/// Capacity available on `channel_id` in the direction leaving `from`.
///
/// Returns `None` if the channel does not exist or does not touch `from`.
pub fn available_liquidity(graph: &NetworkGraph, channel_id: &str, from: &str) -> Option<i128> {
    let channel = graph.get_channel(channel_id)?;
    if channel.node_a == from {
        Some(channel.capacity_a_to_b)
    } else if channel.node_b == from {
        Some(channel.capacity_b_to_a)
    } else {
        None
    }
}

/// Number of channels with no capacity left in at least one direction.
///
/// A channel that is dry in one direction can still route in the other, which is
/// why this counts "channels with a dry side" rather than unusable channels.
pub fn depleted_channels(graph: &NetworkGraph) -> usize {
    graph
        .channels
        .values()
        .filter(|channel| channel.capacity_a_to_b == 0 || channel.capacity_b_to_a == 0)
        .count()
}

/// Apply a routed payment to the channel balances it traverses.
///
/// At each hop, `hop.amount` is moved from the sending side of the channel to the
/// receiving side, so the sender's remaining capacity drops and the receiver's
/// grows by the same value.
///
/// # Errors
///
/// Returns an error without modifying the graph when:
///
/// * the route is empty,
/// * a hop's channel is missing or does not connect the previous node to the
///   hop's node ([`SimulatorError::InvalidRouteHop`]),
/// * a hop forwards a non-positive amount, or
/// * a hop needs more capacity than the channel has in that direction
///   ([`SimulatorError::InsufficientLiquidity`]).
pub fn apply_route_liquidity(
    graph: &mut NetworkGraph,
    route: &Route,
) -> Result<LiquidityUpdate, SimulatorError> {
    if route.hops.is_empty() {
        return Err(SimulatorError::SimulationError(
            "cannot apply an empty route to channel balances".to_string(),
        ));
    }

    // Validate and compute every new balance first, in a scratch map, so a
    // rejected hop cannot leave the earlier hops of the same route applied.
    let mut planned: HashMap<String, (i128, i128)> = HashMap::new();
    let mut current: Option<String> = None;
    let mut update = LiquidityUpdate::default();

    for (index, hop) in route.hops.iter().enumerate() {
        if hop.amount <= 0 {
            return Err(SimulatorError::InvalidConfig(format!(
                "hop {index} forwards a non-positive amount ({})",
                hop.amount
            )));
        }

        let channel =
            graph
                .get_channel(&hop.channel_id)
                .ok_or_else(|| SimulatorError::InvalidRouteHop {
                    hop: index,
                    from: current.clone().unwrap_or_default(),
                    to: hop.node_id.clone(),
                })?;

        // The sending side of the first hop is the channel endpoint that is not
        // the hop's destination; after that it is the previous hop's node.
        let from = match current.clone() {
            Some(node) => node,
            None => {
                if channel.node_b == hop.node_id {
                    channel.node_a.clone()
                } else if channel.node_a == hop.node_id {
                    channel.node_b.clone()
                } else {
                    return Err(SimulatorError::InvalidRouteHop {
                        hop: index,
                        from: String::new(),
                        to: hop.node_id.clone(),
                    });
                }
            }
        };

        let connects = (channel.node_a == from && channel.node_b == hop.node_id)
            || (channel.node_b == from && channel.node_a == hop.node_id);
        if !connects {
            return Err(SimulatorError::InvalidRouteHop {
                hop: index,
                from,
                to: hop.node_id.clone(),
            });
        }

        let (a_to_b, b_to_a) = planned
            .get(&hop.channel_id)
            .copied()
            .unwrap_or((channel.capacity_a_to_b, channel.capacity_b_to_a));

        let from_is_a = channel.node_a == from;
        let available = if from_is_a { a_to_b } else { b_to_a };
        if available < hop.amount {
            return Err(SimulatorError::InsufficientLiquidity {
                channel_id: hop.channel_id.clone(),
                needed: hop.amount,
                available,
            });
        }

        let new_balances = if from_is_a {
            (a_to_b - hop.amount, b_to_a + hop.amount)
        } else {
            (a_to_b + hop.amount, b_to_a - hop.amount)
        };
        planned.insert(hop.channel_id.clone(), new_balances);

        update.hops_applied += 1;
        update.value_moved = update.value_moved.saturating_add(hop.amount);
        current = Some(hop.node_id.clone());
    }

    // Commit. Every hop was validated above, so this cannot fail partway.
    update.channels_emptied = planned
        .values()
        .filter(|(a_to_b, b_to_a)| *a_to_b == 0 || *b_to_a == 0)
        .count();

    for (channel_id, (a_to_b, b_to_a)) in planned {
        graph.update_capacity(&channel_id, Direction::AToB, a_to_b);
        graph.update_capacity(&channel_id, Direction::BToA, b_to_a);
    }

    Ok(update)
}

#[cfg(test)]
mod tests {
    use super::*;
    use channel_router::{Channel, Node, NodeFeatures, RouteHop, RouteMetadata};

    fn channel(id: &str, a: &str, b: &str, a_to_b: i128, b_to_a: i128) -> Channel {
        Channel {
            id: id.to_string(),
            node_a: a.to_string(),
            node_b: b.to_string(),
            capacity_a_to_b: a_to_b,
            capacity_b_to_a: b_to_a,
            base_fee: 1,
            fee_rate: 1_000,
            cltv_delta: 0,
            min_htlc_size: 1,
            max_htlc_size: a_to_b + b_to_a,
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 0,
        }
    }

    fn line_graph() -> NetworkGraph {
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
        graph.add_channel(channel("ch_ab", "a", "b", 1_000, 1_000));
        graph.add_channel(channel("ch_bc", "b", "c", 1_000, 1_000));
        graph
    }

    fn route(hops: &[(&str, &str, i128, i128)]) -> Route {
        Route {
            hops: hops
                .iter()
                .map(|(channel_id, node_id, amount, fee)| RouteHop {
                    channel_id: (*channel_id).to_string(),
                    node_id: (*node_id).to_string(),
                    amount: *amount,
                    fee: *fee,
                    cltv_delta: 0,
                    hashlock: None,
                    expiry_height: 0,
                })
                .collect(),
            total_fees: hops.iter().map(|(_, _, _, fee)| *fee).sum(),
            total_amount: hops.first().map_or(0, |(_, _, amount, _)| *amount),
            success_probability: 1.0,
            metadata: RouteMetadata::default(),
        }
    }

    #[test]
    fn a_payment_moves_value_across_every_hop() {
        let mut graph = line_graph();
        let update = apply_route_liquidity(
            &mut graph,
            &route(&[("ch_ab", "b", 400, 0), ("ch_bc", "c", 400, 0)]),
        )
        .unwrap();

        assert_eq!(update.hops_applied, 2);
        assert_eq!(update.value_moved, 800);
        assert_eq!(update.channels_emptied, 0);

        let ab = graph.get_channel("ch_ab").unwrap();
        assert_eq!(ab.capacity_a_to_b, 600);
        assert_eq!(ab.capacity_b_to_a, 1_400);

        let bc = graph.get_channel("ch_bc").unwrap();
        assert_eq!(bc.capacity_a_to_b, 600);
        assert_eq!(bc.capacity_b_to_a, 1_400);
    }

    #[test]
    fn channel_capacity_is_conserved_by_every_payment() {
        let mut graph = line_graph();
        let before: i128 = graph
            .channels
            .values()
            .map(|c| c.capacity_a_to_b + c.capacity_b_to_a)
            .sum();

        apply_route_liquidity(&mut graph, &route(&[("ch_ab", "b", 250, 0)])).unwrap();

        let after: i128 = graph
            .channels
            .values()
            .map(|c| c.capacity_a_to_b + c.capacity_b_to_a)
            .sum();
        assert_eq!(before, after);
    }

    #[test]
    fn a_route_that_overdraws_a_channel_is_rejected_atomically() {
        let mut graph = line_graph();
        graph.update_capacity("ch_bc", Direction::AToB, 100);

        let err = apply_route_liquidity(
            &mut graph,
            &route(&[("ch_ab", "b", 500, 0), ("ch_bc", "c", 500, 0)]),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            SimulatorError::InsufficientLiquidity {
                needed: 500,
                available: 100,
                ..
            }
        ));
        assert!(err.to_string().contains("ch_bc"), "{err}");

        // The first hop must not have been applied.
        let ab = graph.get_channel("ch_ab").unwrap();
        assert_eq!(ab.capacity_a_to_b, 1_000);
        assert_eq!(ab.capacity_b_to_a, 1_000);
    }

    #[test]
    fn draining_a_channel_reports_it_as_emptied_and_depleted() {
        let mut graph = line_graph();
        let update =
            apply_route_liquidity(&mut graph, &route(&[("ch_ab", "b", 1_000, 0)])).unwrap();

        assert_eq!(update.channels_emptied, 1);
        let ab = graph.get_channel("ch_ab").unwrap();
        assert_eq!(ab.capacity_a_to_b, 0);
        assert_eq!(ab.capacity_b_to_a, 2_000);
        assert_eq!(depleted_channels(&graph), 1);
        assert_eq!(available_liquidity(&graph, "ch_ab", "a"), Some(0));
        assert_eq!(available_liquidity(&graph, "ch_ab", "b"), Some(2_000));
    }

    #[test]
    fn liquidity_can_only_be_spent_once() {
        let mut graph = line_graph();
        apply_route_liquidity(&mut graph, &route(&[("ch_ab", "b", 800, 0)])).unwrap();

        // 200 is left in the a -> b direction, so 300 must fail.
        let err = apply_route_liquidity(&mut graph, &route(&[("ch_ab", "b", 300, 0)])).unwrap_err();
        assert!(matches!(
            err,
            SimulatorError::InsufficientLiquidity { available: 200, .. }
        ));

        // And 200 still succeeds, leaving the channel dry.
        apply_route_liquidity(&mut graph, &route(&[("ch_ab", "b", 200, 0)])).unwrap();
        assert_eq!(graph.get_channel("ch_ab").unwrap().capacity_a_to_b, 0);
    }

    #[test]
    fn a_hop_that_does_not_connect_the_previous_node_is_rejected() {
        let mut graph = line_graph();
        // ch_bc does not touch a, so it cannot follow from a.
        let err = apply_route_liquidity(
            &mut graph,
            &route(&[("ch_ab", "b", 10, 0), ("ch_bc", "a", 10, 0)]),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            SimulatorError::InvalidRouteHop { hop: 1, .. }
        ));
        assert_eq!(graph.get_channel("ch_ab").unwrap().capacity_a_to_b, 1_000);
    }

    #[test]
    fn an_unknown_channel_is_rejected() {
        let mut graph = line_graph();
        let err =
            apply_route_liquidity(&mut graph, &route(&[("ch_missing", "b", 10, 0)])).unwrap_err();
        assert!(matches!(
            err,
            SimulatorError::InvalidRouteHop { hop: 0, .. }
        ));
    }

    #[test]
    fn non_positive_amounts_are_rejected() {
        let mut graph = line_graph();
        let err = apply_route_liquidity(&mut graph, &route(&[("ch_ab", "b", 0, 0)])).unwrap_err();
        assert!(matches!(err, SimulatorError::InvalidConfig(_)));
        assert_eq!(graph.get_channel("ch_ab").unwrap().capacity_a_to_b, 1_000);
    }

    #[test]
    fn an_empty_route_is_rejected() {
        let mut graph = line_graph();
        assert!(apply_route_liquidity(&mut graph, &route(&[])).is_err());
    }

    #[test]
    fn the_default_model_is_static() {
        assert_eq!(LiquidityModel::default(), LiquidityModel::Static);
        assert_eq!(LiquidityModel::Depleting.name(), "depleting");
        assert_eq!(LiquidityModel::Static.name(), "static");
    }
}

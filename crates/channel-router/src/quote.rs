//! Fee and CLTV timeout calculation examples for routed payments.
//!
//! This module is additive: [`crate::find_best_route`] and
//! [`crate::pathfinder::Pathfinder`] keep their existing forward fee estimates.
//! [`PaymentPlanner`] instead prices a payment with an exact delivery amount:
//! each hop's fee is computed from the amount it must forward to the next node,
//! working backwards from the destination. That makes the worked example in
//! `docs/ROUTED_PAYMENT_FEES_AND_TIMEOUTS.md` executable.
//!
//! The planner never mutates the graph. It enumerates simple paths in a stable
//! order, rejects a path as soon as it breaks liquidity, fee, or timeout
//! safety, and selects the cheapest surviving quote with a deterministic
//! tie-break.
//!
//! ```no_run
//! use channel_router::{plan_route, NetworkGraph, QuoteOptions, RouteRequest};
//!
//! let graph = NetworkGraph::new();
//! let request = RouteRequest {
//!     source: "alice".to_string(),
//!     destination: "carol".to_string(),
//!     amount: 1_000_000,
//!     max_fee_budget: None,
//!     max_hops: None,
//!     find_any: false,
//!     payment_metadata: None,
//! };
//! let options = QuoteOptions::new(900, 1_000);
//! // The graph is empty here; a real caller adds nodes and channels first.
//! let _ = plan_route(&graph, &request, options);
//! ```

use crate::{
    Channel, Direction, FeeCap, NetworkGraph, Route, RouteHop, RouteMetadata, RouteRequest,
    RoutingError, MAX_ROUTE_AMOUNT, MAX_ROUTE_HOPS,
};
use fxhash::FxHashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const PPM_DIVISOR: u128 = 1_000_000;
const TIME_LOCK_FEE_COEFFICIENT: i128 = 10;
const TIME_LOCK_FEE_DIVISOR: i128 = 1_440;

/// Configuration for a routed-payment fee and timeout quote.
///
/// `current_ledger` and `final_expiry` are required: a quote without a ledger
/// context cannot say whether an HTLC is still safe to forward. There is no
/// implicit expiry default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteOptions {
    /// Ledger height at which the quote is being produced.
    pub current_ledger: u32,
    /// Ledger height at which the destination is expected to claim the payment.
    pub final_expiry: u32,
    /// Ceiling applied to every hop and to the route total.
    pub fee_cap: FeeCap,
    /// Latest ledger by which the *upstream* HTLC may expire.
    ///
    /// When `None`, `RouteRequest::payment_metadata.payment_expiry` is used.
    pub deadline: Option<u32>,
    /// Smallest CLTV delta a channel may advertise to be usable.
    pub min_cltv_delta: u32,
}

impl QuoteOptions {
    /// Create explicit quote parameters using the protocol fee ceiling.
    ///
    /// A zero `min_cltv_delta` is rejected by [`PaymentPlanner::new`] rather
    /// than being silently raised to one.
    pub fn new(current_ledger: u32, final_expiry: u32) -> Self {
        Self {
            current_ledger,
            final_expiry,
            fee_cap: FeeCap::protocol(),
            deadline: None,
            min_cltv_delta: 1,
        }
    }

    /// Apply a stricter or more permissive fee ceiling.
    pub fn with_fee_cap(mut self, fee_cap: FeeCap) -> Self {
        self.fee_cap = fee_cap;
        self
    }

    /// Set the latest acceptable upstream expiry.
    pub fn with_deadline(mut self, deadline: u32) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Set the smallest acceptable per-channel CLTV delta.
    pub fn with_min_cltv_delta(mut self, min_cltv_delta: u32) -> Self {
        self.min_cltv_delta = min_cltv_delta;
        self
    }

    fn validate(&self) -> Result<(), RoutingError> {
        if self.final_expiry <= self.current_ledger {
            return Err(RoutingError::PaymentExpired {
                current_ledger: self.current_ledger,
                expiry: self.final_expiry,
            });
        }

        if self.min_cltv_delta == 0 {
            return Err(RoutingError::InvalidRequest {
                reason: "min_cltv_delta must be at least one ledger".to_string(),
            });
        }

        if let Some(deadline) = self.deadline {
            if deadline < self.final_expiry {
                return Err(RoutingError::DeadlineExceeded {
                    deadline,
                    expiry: self.final_expiry,
                });
            }
        }

        Ok(())
    }
}

/// One hop of an exact-delivery payment quote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteHop {
    /// Channel used for the hop.
    pub channel_id: String,
    /// Node sending the HTLC.
    pub from: String,
    /// Node receiving the HTLC.
    pub to: String,
    /// Amount that must be forwarded into the next node (excluding this fee).
    pub forward_amount: i128,
    /// Fee earned by the next node for forwarding this hop.
    pub fee: i128,
    /// Channel capacity required by this hop: [`Self::forward_amount`] + [`Self::fee`].
    pub required_capacity: i128,
    /// CLTV delta advertised by the channel.
    pub cltv_delta: u32,
    /// Expiry height of this hop's HTLC.
    pub expiry_height: u32,
}

/// A deterministic fee and timeout calculation for one routed payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteQuote {
    /// Source node of the payment.
    pub source: String,
    /// Destination node of the payment.
    pub destination: String,
    /// Amount the destination receives; this is `RouteRequest::amount`.
    pub delivered_amount: i128,
    /// Amount the source must pay, including every hop's fee.
    pub sender_amount: i128,
    /// Sum of all hop fees.
    pub total_fee: i128,
    /// Sum of all channel CLTV deltas.
    pub total_cltv_delta: u32,
    /// Destination claim height supplied in [`QuoteOptions`].
    pub final_expiry: u32,
    /// Hops in source-to-destination order.
    pub hops: Vec<QuoteHop>,
}

/// A selected route together with its worked calculation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaymentPlan {
    /// Route whose hop amounts, fees, and expiries match the quote.
    pub route: Route,
    /// Exact-delivery calculation used to select the route.
    pub quote: RouteQuote,
}

/// Deterministic ordering for candidate quotes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct QuoteKey {
    total_fee: i128,
    total_cltv_delta: u32,
    hop_count: usize,
    channel_ids: Vec<String>,
}

type SortedAdjacency = FxHashMap<String, Vec<(String, String)>>;

/// Produces worked fee and timeout calculations for routed payments.
pub struct PaymentPlanner<'a> {
    graph: &'a NetworkGraph,
    options: QuoteOptions,
}

impl<'a> PaymentPlanner<'a> {
    /// Create a planner, rejecting an expiry or CLTV configuration that could
    /// never describe a safe payment.
    pub fn new(graph: &'a NetworkGraph, options: QuoteOptions) -> Result<Self, RoutingError> {
        options.validate()?;
        Ok(Self { graph, options })
    }

    /// Select the cheapest safe simple path and return its route and quote.
    ///
    /// Candidates are compared by total fee, total CLTV delta, hop count, then
    /// channel IDs. Neighbours are visited in channel-ID order, so both the
    /// search and the tie-break are independent of hash-map iteration order.
    pub fn plan(&self, request: &RouteRequest) -> Result<PaymentPlan, RoutingError> {
        validate_request(self.graph, request)?;

        let deadline = self.options.deadline.or_else(|| {
            request
                .payment_metadata
                .as_ref()
                .and_then(|m| m.payment_expiry)
        });
        if let Some(deadline) = deadline {
            if deadline < self.options.final_expiry {
                return Err(RoutingError::DeadlineExceeded {
                    deadline,
                    expiry: self.options.final_expiry,
                });
            }
        }

        let max_hops = request.max_hops.unwrap_or(MAX_ROUTE_HOPS);
        let adjacency = self.sorted_adjacency();
        let mut visited = HashSet::new();
        visited.insert(request.source.clone());
        let mut nodes = vec![request.source.clone()];
        let mut channels = Vec::new();
        let mut best: Option<(QuoteKey, PaymentPlan)> = None;
        let mut last_error: Option<RoutingError> = None;

        self.enumerate_paths(
            request,
            deadline,
            max_hops,
            &adjacency,
            &mut visited,
            &mut nodes,
            &mut channels,
            &mut best,
            &mut last_error,
        );

        match best {
            Some((_, plan)) => Ok(plan),
            None => Err(last_error.unwrap_or_else(|| RoutingError::NoPathFound {
                origin: request.source.clone(),
                destination: request.destination.clone(),
            })),
        }
    }

    fn sorted_adjacency(&self) -> SortedAdjacency {
        let mut adjacency: SortedAdjacency = FxHashMap::default();
        for (node, neighbors) in &self.graph.adjacency {
            let mut edges: Vec<(String, String)> = neighbors
                .iter()
                .map(|(neighbor, channel_id)| (channel_id.clone(), neighbor.clone()))
                .collect();
            edges.sort();
            adjacency.insert(node.clone(), edges);
        }
        adjacency
    }

    #[allow(clippy::too_many_arguments)]
    fn enumerate_paths(
        &self,
        request: &RouteRequest,
        deadline: Option<u32>,
        max_hops: usize,
        adjacency: &SortedAdjacency,
        visited: &mut HashSet<String>,
        nodes: &mut Vec<String>,
        channels: &mut Vec<String>,
        best: &mut Option<(QuoteKey, PaymentPlan)>,
        last_error: &mut Option<RoutingError>,
    ) {
        let current = nodes
            .last()
            .expect(" every path starts with the source node")
            .clone();

        if current == request.destination {
            match self.quote_path(request, deadline, nodes, channels) {
                Ok(quote) => {
                    let key = QuoteKey {
                        total_fee: quote.total_fee,
                        total_cltv_delta: quote.total_cltv_delta,
                        hop_count: quote.hops.len(),
                        channel_ids: quote.hops.iter().map(|h| h.channel_id.clone()).collect(),
                    };
                    let is_better = best
                        .as_ref()
                        .map_or(true, |(current_key, _)| key < *current_key);
                    if is_better {
                        *best = Some((key, self.into_plan(request, quote)));
                    }
                }
                Err(error) => *last_error = Some(error),
            }
            return;
        }

        if channels.len() >= max_hops {
            return;
        }

        let Some(edges) = adjacency.get(&current) else {
            return;
        };

        for (channel_id, neighbor) in edges {
            if visited.contains(neighbor) {
                continue;
            }
            if self
                .graph
                .get_channel(channel_id)
                .is_none_or(|channel| !channel.enabled)
            {
                continue;
            }

            visited.insert(neighbor.clone());
            nodes.push(neighbor.clone());
            channels.push(channel_id.clone());

            self.enumerate_paths(
                request, deadline, max_hops, adjacency, visited, nodes, channels, best, last_error,
            );

            channels.pop();
            nodes.pop();
            visited.remove(neighbor);
        }
    }

    fn quote_path(
        &self,
        request: &RouteRequest,
        deadline: Option<u32>,
        nodes: &[String],
        channels: &[String],
    ) -> Result<RouteQuote, RoutingError> {
        let delivered_amount = request.amount;
        let mut forward_amount = delivered_amount;
        let mut total_fee = 0i128;
        let mut total_cltv_delta = 0u32;
        let mut hops = Vec::with_capacity(channels.len());

        for index in (0..channels.len()).rev() {
            let channel_id = &channels[index];
            let from = &nodes[index];
            let to = &nodes[index + 1];
            let channel = self.graph.get_channel(channel_id).ok_or_else(|| {
                RoutingError::ChannelNotFound {
                    channel_id: channel_id.clone(),
                }
            })?;

            if !channel.enabled {
                return Err(RoutingError::InvalidRequest {
                    reason: format!("channel {channel_id} is disabled"),
                });
            }

            self.options.fee_cap.check_channel(channel)?;

            if channel.cltv_delta < self.options.min_cltv_delta {
                return Err(RoutingError::UnsafeCltvDelta {
                    channel_id: channel_id.clone(),
                    delta: channel.cltv_delta,
                });
            }

            let fee = checked_channel_fee(forward_amount, channel)?;
            if fee < 0 {
                return Err(RoutingError::NegativeFee {
                    channel_id: channel_id.clone(),
                    fee,
                });
            }
            self.options.fee_cap.check_hop_fee(
                channel_id,
                forward_amount,
                channel.cltv_delta,
                fee,
            )?;

            let required_capacity = forward_amount.checked_add(fee).ok_or_else(|| {
                RoutingError::ArithmeticOverflow {
                    context: "hop required capacity".to_string(),
                }
            })?;
            if required_capacity < channel.min_htlc_size {
                return Err(RoutingError::BelowDustLimit {
                    amount: required_capacity,
                    dust_limit: channel.min_htlc_size,
                });
            }
            if required_capacity > channel.max_htlc_size {
                return Err(RoutingError::HtlcSizeExceeded {
                    channel_id: channel_id.clone(),
                    amount: required_capacity,
                    max: channel.max_htlc_size,
                });
            }

            let direction = direction_between(channel, from, to)?;
            let capacity = capacity_for(channel, direction);
            if capacity < required_capacity {
                return Err(RoutingError::InsufficientCapacity {
                    needed: required_capacity,
                    available: capacity,
                    channel_id: channel_id.clone(),
                });
            }

            total_fee =
                total_fee
                    .checked_add(fee)
                    .ok_or_else(|| RoutingError::ArithmeticOverflow {
                        context: "route fee".to_string(),
                    })?;
            total_cltv_delta = total_cltv_delta
                .checked_add(channel.cltv_delta)
                .ok_or_else(|| RoutingError::ExpiryOverflow {
                    expiry: total_cltv_delta,
                    delta: channel.cltv_delta,
                })?;

            hops.push(QuoteHop {
                channel_id: channel_id.clone(),
                from: from.clone(),
                to: to.clone(),
                forward_amount,
                fee,
                required_capacity,
                cltv_delta: channel.cltv_delta,
                expiry_height: 0,
            });

            forward_amount = required_capacity;
        }

        hops.reverse();

        self.options
            .fee_cap
            .check_route_fee(delivered_amount, total_fee)?;
        if let Some(budget) = request.max_fee_budget {
            if total_fee > budget {
                return Err(RoutingError::FeeExceedsBudget {
                    fee: total_fee,
                    budget,
                });
            }
        }

        // Expiries are chained from the destination backwards: the last hop
        // covers the destination's claim window and each upstream hop adds its
        // own safety delta to the expiry it must cover.
        let mut expiry = self.options.final_expiry;
        for hop in hops.iter_mut().rev() {
            expiry =
                expiry
                    .checked_add(hop.cltv_delta)
                    .ok_or_else(|| RoutingError::ExpiryOverflow {
                        expiry,
                        delta: hop.cltv_delta,
                    })?;
            hop.expiry_height = expiry;
        }

        let first_expiry = hops
            .first()
            .map_or(self.options.final_expiry, |hop| hop.expiry_height);
        if self.options.final_expiry <= self.options.current_ledger {
            return Err(RoutingError::PaymentExpired {
                current_ledger: self.options.current_ledger,
                expiry: self.options.final_expiry,
            });
        }
        if let Some(deadline) = deadline {
            if first_expiry > deadline {
                return Err(RoutingError::DeadlineExceeded {
                    deadline,
                    expiry: first_expiry,
                });
            }
        }
        if let Some(required) = request
            .payment_metadata
            .as_ref()
            .and_then(|metadata| metadata.required_cltv_delta)
        {
            let available = first_expiry - self.options.current_ledger;
            if available < required {
                return Err(RoutingError::InsufficientCltvDelta {
                    available,
                    required,
                });
            }
        }

        let sender_amount = delivered_amount.checked_add(total_fee).ok_or_else(|| {
            RoutingError::ArithmeticOverflow {
                context: "sender amount".to_string(),
            }
        })?;

        Ok(RouteQuote {
            source: request.source.clone(),
            destination: request.destination.clone(),
            delivered_amount,
            sender_amount,
            total_fee,
            total_cltv_delta,
            final_expiry: self.options.final_expiry,
            hops,
        })
    }

    fn into_plan(&self, request: &RouteRequest, quote: RouteQuote) -> PaymentPlan {
        let hops = quote
            .hops
            .iter()
            .map(|hop| RouteHop {
                channel_id: hop.channel_id.clone(),
                node_id: hop.to.clone(),
                amount: hop.forward_amount,
                fee: hop.fee,
                cltv_delta: hop.cltv_delta,
                hashlock: None,
                expiry_height: hop.expiry_height,
            })
            .collect();
        let is_direct = quote.hops.len() == 1;

        PaymentPlan {
            route: Route {
                hops,
                total_fees: quote.total_fee,
                total_amount: request.amount,
                success_probability: 0.95,
                metadata: RouteMetadata {
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    num_nodes: quote.hops.len() + 1,
                    estimated_time_ms: u64::from(quote.total_cltv_delta) * 5,
                    is_direct,
                },
            },
            quote,
        }
    }
}

/// Convenience wrapper around [`PaymentPlanner::plan`].
pub fn plan_route(
    graph: &NetworkGraph,
    request: &RouteRequest,
    options: QuoteOptions,
) -> Result<PaymentPlan, RoutingError> {
    PaymentPlanner::new(graph, options)?.plan(request)
}

fn validate_request(graph: &NetworkGraph, request: &RouteRequest) -> Result<(), RoutingError> {
    if request.amount <= 0 {
        return Err(RoutingError::BelowDustLimit {
            amount: request.amount,
            dust_limit: 1,
        });
    }
    if request.amount > MAX_ROUTE_AMOUNT {
        return Err(RoutingError::AmountExceedsMaximum {
            amount: request.amount,
            max_amount: MAX_ROUTE_AMOUNT,
        });
    }
    if request.source == request.destination {
        return Err(RoutingError::InvalidRequest {
            reason: "source and destination must be different nodes".to_string(),
        });
    }
    if !graph.has_node(&request.source) {
        return Err(RoutingError::NodeNotFound {
            node: request.source.clone(),
        });
    }
    if !graph.has_node(&request.destination) {
        return Err(RoutingError::NodeNotFound {
            node: request.destination.clone(),
        });
    }

    let max_hops = request.max_hops.unwrap_or(MAX_ROUTE_HOPS);
    if max_hops == 0 || max_hops > MAX_ROUTE_HOPS {
        return Err(RoutingError::InvalidRequest {
            reason: format!("max_hops must be between 1 and {MAX_ROUTE_HOPS}"),
        });
    }

    if let Some(budget) = request.max_fee_budget {
        if budget < 0 {
            return Err(RoutingError::InvalidRequest {
                reason: "max_fee_budget cannot be negative".to_string(),
            });
        }
    }

    Ok(())
}

fn direction_between(channel: &Channel, from: &str, to: &str) -> Result<Direction, RoutingError> {
    if channel.node_a == from && channel.node_b == to {
        Ok(Direction::AToB)
    } else if channel.node_b == from && channel.node_a == to {
        Ok(Direction::BToA)
    } else {
        Err(RoutingError::InvalidRequest {
            reason: format!(
                "channel {} does not connect {} and {}",
                channel.id, from, to
            ),
        })
    }
}

fn capacity_for(channel: &Channel, direction: Direction) -> i128 {
    match direction {
        Direction::AToB => channel.capacity_a_to_b,
        Direction::BToA => channel.capacity_b_to_a,
    }
}

fn checked_channel_fee(amount: i128, channel: &Channel) -> Result<i128, RoutingError> {
    let amount_u128 = u128::try_from(amount).map_err(|_| RoutingError::InvalidRequest {
        reason: "forwarded amount must not be negative".to_string(),
    })?;
    let proportional = amount_u128
        .checked_mul(u128::from(channel.fee_rate))
        .ok_or_else(|| RoutingError::ArithmeticOverflow {
            context: "proportional fee".to_string(),
        })?
        / PPM_DIVISOR;
    let proportional =
        i128::try_from(proportional).map_err(|_| RoutingError::ArithmeticOverflow {
            context: "proportional fee conversion".to_string(),
        })?;
    let time_lock = i128::from(channel.cltv_delta)
        .checked_mul(TIME_LOCK_FEE_COEFFICIENT)
        .ok_or_else(|| RoutingError::ArithmeticOverflow {
            context: "time-lock fee".to_string(),
        })?
        / TIME_LOCK_FEE_DIVISOR;

    channel
        .base_fee
        .checked_add(proportional)
        .and_then(|fee| fee.checked_add(time_lock))
        .ok_or_else(|| RoutingError::ArithmeticOverflow {
            context: "total hop fee".to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Node, NodeFeatures, PaymentMetadata, PaymentType};

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

    fn two_hop_graph() -> NetworkGraph {
        let mut graph = NetworkGraph::new();
        for id in ["alice", "bob", "carol"] {
            add_node(&mut graph, id);
        }
        add_channel(&mut graph, "ch1", "alice", "bob", 10, 500, 40, 2_000_000);
        add_channel(&mut graph, "ch2", "bob", "carol", 5, 1_000, 30, 2_000_000);
        graph
    }

    fn request() -> RouteRequest {
        RouteRequest {
            source: "alice".to_string(),
            destination: "carol".to_string(),
            amount: 1_000_000,
            max_fee_budget: None,
            max_hops: None,
            find_any: false,
            payment_metadata: None,
        }
    }

    #[test]
    fn two_hop_quote_matches_the_documented_example() {
        let graph = two_hop_graph();
        let plan = plan_route(&graph, &request(), QuoteOptions::new(900, 1_000)).unwrap();

        assert_eq!(plan.quote.delivered_amount, 1_000_000);
        assert_eq!(plan.quote.total_fee, 510 + 1_005);
        assert_eq!(plan.quote.sender_amount, 1_001_515);
        assert_eq!(plan.quote.total_cltv_delta, 70);
        assert_eq!(plan.quote.hops[0].channel_id, "ch1");
        assert_eq!(plan.quote.hops[0].fee, 510);
        assert_eq!(plan.quote.hops[0].forward_amount, 1_001_005);
        assert_eq!(plan.quote.hops[0].required_capacity, 1_001_515);
        assert_eq!(plan.quote.hops[0].expiry_height, 1_070);
        assert_eq!(plan.quote.hops[1].fee, 1_005);
        assert_eq!(plan.quote.hops[1].expiry_height, 1_030);

        assert_eq!(plan.route.total_fees, plan.quote.total_fee);
        assert_eq!(plan.route.hops[0].expiry_height, 1_070);
    }

    #[test]
    fn fee_budget_and_route_cap_boundaries_are_inclusive() {
        let graph = two_hop_graph();

        let mut exact_budget = request();
        exact_budget.max_fee_budget = Some(1_515);
        assert!(plan_route(&graph, &exact_budget, QuoteOptions::new(900, 1_000)).is_ok());

        let mut tight_budget = request();
        tight_budget.max_fee_budget = Some(1_514);
        assert!(matches!(
            plan_route(&graph, &tight_budget, QuoteOptions::new(900, 1_000)).unwrap_err(),
            RoutingError::FeeExceedsBudget {
                fee: 1_515,
                budget: 1_514
            }
        ));

        let exact_cap = QuoteOptions::new(900, 1_000).with_fee_cap(FeeCap {
            max_route_fee_ppm: 1_515,
            max_route_fee_abs: 0,
            ..FeeCap::protocol()
        });
        assert!(plan_route(&graph, &request(), exact_cap).is_ok());

        let tight_cap = QuoteOptions::new(900, 1_000).with_fee_cap(FeeCap {
            max_route_fee_ppm: 1_514,
            max_route_fee_abs: 0,
            ..FeeCap::protocol()
        });
        assert!(matches!(
            plan_route(&graph, &request(), tight_cap).unwrap_err(),
            RoutingError::RouteFeeCapExceeded { .. }
        ));
    }

    #[test]
    fn a_hop_without_enough_directional_capacity_is_rejected() {
        let mut graph = two_hop_graph();
        graph.channels.get_mut("ch2").unwrap().capacity_a_to_b = 1_000_000;

        assert!(matches!(
            plan_route(&graph, &request(), QuoteOptions::new(900, 1_000)).unwrap_err(),
            RoutingError::InsufficientCapacity {
                needed: 1_001_005,
                available: 1_000_000,
                ..
            }
        ));
    }

    #[test]
    fn timeout_constraints_are_enforced() {
        let graph = two_hop_graph();

        assert!(matches!(
            PaymentPlanner::new(&graph, QuoteOptions::new(1_000, 1_000))
                .err()
                .expect("planner should reject an expired payment"),
            RoutingError::PaymentExpired { .. }
        ));

        let mut need_more_time = request();
        need_more_time.payment_metadata = Some(PaymentMetadata {
            payment_type: PaymentType::Regular,
            required_cltv_delta: Some(200),
            payment_expiry: None,
        });
        assert!(matches!(
            plan_route(&graph, &need_more_time, QuoteOptions::new(900, 1_000)).unwrap_err(),
            RoutingError::InsufficientCltvDelta {
                available: 170,
                required: 200
            }
        ));

        assert!(matches!(
            plan_route(
                &graph,
                &request(),
                QuoteOptions::new(900, 1_000).with_deadline(1_069),
            )
            .unwrap_err(),
            RoutingError::DeadlineExceeded {
                deadline: 1_069,
                expiry: 1_070
            }
        ));

        let mut unsafe_graph = two_hop_graph();
        unsafe_graph.channels.get_mut("ch1").unwrap().cltv_delta = 0;
        assert!(matches!(
            plan_route(&unsafe_graph, &request(), QuoteOptions::new(900, 1_000)).unwrap_err(),
            RoutingError::UnsafeCltvDelta { .. }
        ));
    }

    #[test]
    fn route_selection_is_deterministic() {
        let mut graph = NetworkGraph::new();
        for id in ["alice", "bob", "carol", "dave"] {
            add_node(&mut graph, id);
        }
        add_channel(&mut graph, "a_b", "alice", "bob", 1, 0, 10, 10_000);
        add_channel(&mut graph, "b_d", "bob", "dave", 2, 0, 10, 10_000);
        add_channel(&mut graph, "a_c", "alice", "carol", 5, 0, 10, 10_000);
        add_channel(&mut graph, "c_d", "carol", "dave", 5, 0, 10, 10_000);

        let mut diamond = request();
        diamond.destination = "dave".to_string();
        diamond.amount = 1_000;

        let first = plan_route(&graph, &diamond, QuoteOptions::new(900, 1_000)).unwrap();
        assert_eq!(first.quote.total_fee, 3);
        let first_ids: Vec<_> = first
            .quote
            .hops
            .iter()
            .map(|hop| hop.channel_id.as_str())
            .collect();
        assert_eq!(first_ids, ["a_b", "b_d"]);

        // With equal fees the lexicographically smaller channel list wins,
        // and repeated calls return the same route regardless of hash order.
        graph.channels.get_mut("a_c").unwrap().base_fee = 1;
        graph.channels.get_mut("c_d").unwrap().base_fee = 2;
        let second = plan_route(&graph, &diamond, QuoteOptions::new(900, 1_000)).unwrap();
        let third = plan_route(&graph, &diamond, QuoteOptions::new(900, 1_000)).unwrap();
        let second_ids: Vec<_> = second
            .quote
            .hops
            .iter()
            .map(|hop| hop.channel_id.as_str())
            .collect();
        assert_eq!(second_ids, ["a_b", "b_d"]);
        assert_eq!(second.quote, third.quote);
    }

    #[test]
    fn invalid_requests_are_rejected_explicitly() {
        let graph = two_hop_graph();
        let options = QuoteOptions::new(900, 1_000);

        let mut zero = request();
        zero.amount = 0;
        assert!(matches!(
            plan_route(&graph, &zero, options).unwrap_err(),
            RoutingError::BelowDustLimit { .. }
        ));

        let mut huge = request();
        huge.amount = MAX_ROUTE_AMOUNT + 1;
        assert!(matches!(
            plan_route(&graph, &huge, options).unwrap_err(),
            RoutingError::AmountExceedsMaximum { .. }
        ));

        let mut missing = request();
        missing.destination = "nobody".to_string();
        assert!(matches!(
            plan_route(&graph, &missing, options).unwrap_err(),
            RoutingError::NodeNotFound { .. }
        ));

        let mut same = request();
        same.destination = same.source.clone();
        assert!(matches!(
            plan_route(&graph, &same, options).unwrap_err(),
            RoutingError::InvalidRequest { .. }
        ));

        let mut zero_hops = request();
        zero_hops.max_hops = Some(0);
        assert!(matches!(
            plan_route(&graph, &zero_hops, options).unwrap_err(),
            RoutingError::InvalidRequest { .. }
        ));

        let mut negative_budget = request();
        negative_budget.max_fee_budget = Some(-1);
        assert!(matches!(
            plan_route(&graph, &negative_budget, options).unwrap_err(),
            RoutingError::InvalidRequest { .. }
        ));

        assert!(matches!(
            PaymentPlanner::new(&graph, QuoteOptions::new(900, 1_000).with_min_cltv_delta(0))
                .err()
                .expect("planner should reject a zero CLTV delta"),
            RoutingError::InvalidRequest { .. }
        ));
    }
}

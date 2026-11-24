//! # Routing Policy Module
//!
//! Routing policies and constraints for the payment channel router.

use crate::{Channel, NetworkGraph, Route, RouteHop, RouteRequest, RoutingError, MAX_ROUTE_HOPS};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashSet;

/// Deterministic tie-breaking strategy for equal-cost payment routes.
///
/// When multiple routes (or partial paths during search) have identical
/// primary cost (for example equal `total_fees` in cheapest-route search),
/// `TieBreaker` defines a strict total order so route selection is reproducible
/// regardless of graph insertion order or hash map iteration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TieBreaker {
    /// Canonical deterministic order (default):
    /// 1. Fewer hops
    /// 2. Lower total CLTV delta (timeout safety)
    /// 3. Lexicographically smallest `(channel_id, node_id)` hop sequence
    #[default]
    Canonical,
    /// Prefer fewer hops first, then lexicographically smallest hop sequence.
    FewestHops,
    /// Prefer lower total CLTV delta (timeout safety) first, then fewer hops,
    /// then lexicographically smallest hop sequence.
    LowestCltv,
    /// Break ties directly by lexicographically smallest `(channel_id, node_id)`
    /// hop sequence.
    Lexicographical,
}

impl TieBreaker {
    /// Compare two hop slices according to this tie-breaking strategy.
    ///
    /// Distinct routes always have a strict total order because the fallback
    /// compares the full `(channel_id, node_id)` sequence lexicographically.
    pub fn compare_hops(&self, a: &[RouteHop], b: &[RouteHop]) -> Ordering {
        let total_cltv = |hops: &[RouteHop]| -> u64 {
            hops.iter()
                .fold(0u64, |acc, hop| acc.saturating_add(hop.cltv_delta as u64))
        };
        let lex_cmp = || {
            a.iter()
                .map(|h| (&h.channel_id, &h.node_id))
                .cmp(b.iter().map(|h| (&h.channel_id, &h.node_id)))
        };

        match self {
            TieBreaker::Canonical => a
                .len()
                .cmp(&b.len())
                .then_with(|| total_cltv(a).cmp(&total_cltv(b)))
                .then_with(lex_cmp),
            TieBreaker::FewestHops => a.len().cmp(&b.len()).then_with(lex_cmp),
            TieBreaker::LowestCltv => total_cltv(a)
                .cmp(&total_cltv(b))
                .then_with(|| a.len().cmp(&b.len()))
                .then_with(lex_cmp),
            TieBreaker::Lexicographical => lex_cmp(),
        }
    }

    /// Compare two routes according to this tie-breaking strategy.
    pub fn compare_routes(&self, a: &Route, b: &Route) -> Ordering {
        self.compare_hops(&a.hops, &b.hops)
    }
}

/// Composite search key for deterministic route selection during graph search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SearchKey {
    pub primary_cost: i128,
    pub hops: usize,
    pub total_cltv: u64,
    pub path: Vec<(String, String)>,
    pub tie_breaker: TieBreaker,
}

impl SearchKey {
    pub fn root(primary_cost: i128, tie_breaker: TieBreaker) -> Self {
        Self {
            primary_cost,
            hops: 0,
            total_cltv: 0,
            path: Vec::new(),
            tie_breaker,
        }
    }

    pub fn extend(
        &self,
        new_primary_cost: i128,
        channel_id: &str,
        node_id: &str,
        cltv_delta: u32,
    ) -> Self {
        let mut path = self.path.clone();
        path.push((channel_id.to_string(), node_id.to_string()));
        Self {
            primary_cost: new_primary_cost,
            hops: self.hops + 1,
            total_cltv: self.total_cltv.saturating_add(cltv_delta as u64),
            path,
            tie_breaker: self.tie_breaker,
        }
    }
}

impl Ord for SearchKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.primary_cost
            .cmp(&other.primary_cost)
            .then_with(|| match self.tie_breaker {
                TieBreaker::Canonical => self
                    .hops
                    .cmp(&other.hops)
                    .then_with(|| self.total_cltv.cmp(&other.total_cltv))
                    .then_with(|| self.path.cmp(&other.path)),
                TieBreaker::FewestHops => self
                    .hops
                    .cmp(&other.hops)
                    .then_with(|| self.path.cmp(&other.path)),
                TieBreaker::LowestCltv => self
                    .total_cltv
                    .cmp(&other.total_cltv)
                    .then_with(|| self.hops.cmp(&other.hops))
                    .then_with(|| self.path.cmp(&other.path)),
                TieBreaker::Lexicographical => self.path.cmp(&other.path),
            })
    }
}

impl PartialOrd for SearchKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Return a node's `(neighbor_id, channel_id)` pairs in sorted deterministic order.
pub(crate) fn sorted_neighbors<'a>(
    graph: &'a NetworkGraph,
    node_id: &str,
) -> Vec<(&'a String, &'a String)> {
    let mut neighbors: Vec<(&String, &String)> = graph
        .adjacency
        .get(node_id)
        .map(|m| m.iter().collect())
        .unwrap_or_default();
    neighbors.sort_unstable_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.cmp(b.1)));
    neighbors
}

/// Routing preferences and constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingPolicy {
    /// Maximum number of hops
    pub max_hops: usize,
    /// Maximum fee as percentage of amount (basis points)
    pub max_fee_bps: u32,
    /// Maximum base fee
    pub max_base_fee: i128,
    /// Maximum fee rate (ppm)
    pub max_fee_rate: u32,
    /// Excluded node IDs
    pub excluded_nodes: HashSet<String>,
    /// Excluded channel IDs
    pub excluded_channels: HashSet<String>,
    /// Preferred nodes (favor these in routing)
    pub preferred_nodes: HashSet<String>,
    /// Whether to allow MPP (multi-path payments)
    pub allow_mpp: bool,
    /// Whether to allow trampoline routing
    pub allow_trampoline: bool,
    /// Cltv delta preference
    pub prefer_low_cltv: bool,
    /// Minimum amount (dust threshold)
    pub min_amount: i128,
    /// Maximum amount
    pub max_amount: i128,
    /// Deterministic tie-breaking strategy for equal-cost routes
    #[serde(default)]
    pub tie_breaker: TieBreaker,
}

impl Default for RoutingPolicy {
    fn default() -> Self {
        RoutingPolicy {
            max_hops: MAX_ROUTE_HOPS,
            max_fee_bps: 1000, // 10%
            max_base_fee: 1000,
            max_fee_rate: 10000, // 1%
            excluded_nodes: HashSet::new(),
            excluded_channels: HashSet::new(),
            preferred_nodes: HashSet::new(),
            allow_mpp: true,
            allow_trampoline: false,
            prefer_low_cltv: true,
            min_amount: 1,
            max_amount: i128::MAX / 2,
            tie_breaker: TieBreaker::default(),
        }
    }
}

impl RoutingPolicy {
    /// Create a policy for high-value payments
    pub fn high_value() -> Self {
        RoutingPolicy {
            max_hops: 10,
            max_fee_bps: 500,       // 5% max
            prefer_low_cltv: false, // Prefer security over speed
            ..Default::default()
        }
    }

    /// Create a policy for micropayments
    pub fn micropayment() -> Self {
        RoutingPolicy {
            max_hops: 5,
            max_fee_bps: 5000, // 50% max (micropayments can have high fees)
            max_base_fee: 100,
            ..Default::default()
        }
    }

    /// Create a policy for privacy-focused routing
    pub fn privacy_focused() -> Self {
        RoutingPolicy {
            max_hops: MAX_ROUTE_HOPS,
            preferred_nodes: HashSet::new(), // Avoid specific nodes
            prefer_low_cltv: false,
            ..Default::default()
        }
    }

    /// Check if a channel meets the policy requirements
    pub fn channel_meets_requirements(&self, channel: &Channel) -> Result<(), RoutingError> {
        // Check excluded channels
        if self.excluded_channels.contains(&channel.id) {
            return Err(RoutingError::ChannelNotFound {
                channel_id: channel.id.clone(),
            });
        }

        // Check excluded nodes
        if self.excluded_nodes.contains(&channel.node_a)
            || self.excluded_nodes.contains(&channel.node_b)
        {
            return Err(RoutingError::NodeNotFound {
                node: "excluded".to_string(),
            });
        }

        // Check fee rate
        if channel.fee_rate > self.max_fee_rate {
            return Err(RoutingError::FeeExceedsBudget {
                fee: channel.fee_rate as i128,
                budget: self.max_fee_rate as i128,
            });
        }

        // Check base fee
        if channel.base_fee > self.max_base_fee {
            return Err(RoutingError::FeeExceedsBudget {
                fee: channel.base_fee,
                budget: self.max_base_fee,
            });
        }

        Ok(())
    }

    /// Check if a route meets the policy requirements
    pub fn route_meets_requirements(
        &self,
        route: &Route,
        request: &RouteRequest,
    ) -> Result<(), RoutingError> {
        // Check hop limit
        if route.hops.len() > self.max_hops {
            return Err(RoutingError::PathTooLong {
                length: route.hops.len(),
                max: self.max_hops,
            });
        }

        // Check fee percentage
        let fee_percent = (route.total_fees as f64 / request.amount as f64 * 10000.0) as u32;
        if fee_percent > self.max_fee_bps {
            return Err(RoutingError::FeeExceedsBudget {
                fee: route.total_fees,
                budget: (request.amount as f64 * self.max_fee_bps as f64 / 10000.0) as i128,
            });
        }

        // Check amount limits
        if request.amount < self.min_amount {
            return Err(RoutingError::BelowDustLimit {
                amount: request.amount,
                dust_limit: self.min_amount,
            });
        }

        if request.amount > self.max_amount {
            return Err(RoutingError::AmountExceedsMaximum {
                amount: request.amount,
                max_amount: self.max_amount,
            });
        }

        // Check excluded nodes
        for hop in &route.hops {
            if self.excluded_nodes.contains(&hop.node_id) {
                return Err(RoutingError::NodeNotFound {
                    node: hop.node_id.clone(),
                });
            }
        }

        // Check excluded channels
        for hop in &route.hops {
            if self.excluded_channels.contains(&hop.channel_id) {
                return Err(RoutingError::ChannelNotFound {
                    channel_id: hop.channel_id.clone(),
                });
            }
        }

        Ok(())
    }

    /// Apply policy to a route request
    pub fn apply_to_request(&self, mut request: RouteRequest) -> RouteRequest {
        // Apply hop limit
        if request.max_hops.is_none() || request.max_hops > Some(self.max_hops) {
            request.max_hops = Some(self.max_hops);
        }

        // Apply fee budget if not set
        if request.max_fee_budget.is_none() {
            let max_fee = (request.amount as f64 * self.max_fee_bps as f64 / 10000.0) as i128;
            request.max_fee_budget = Some(max_fee);
        }

        request
    }

    /// Calculate a score for a route (lower is better)
    pub fn score_route(&self, route: &Route) -> f64 {
        let mut score = 0.0;

        // Fee score (normalized)
        let fee_score = route.total_fees as f64;
        score += fee_score * 1.0;

        // Hop count score
        let hop_score = route.hops.len() as f64 * 10.0;
        score += hop_score;

        // CLTV delta score (if preferred)
        if self.prefer_low_cltv {
            let cltv_score: i128 = route.hops.iter().map(|h| h.cltv_delta as i128).sum();
            score += cltv_score as f64 * 0.5;
        }

        // Preferred nodes bonus
        for hop in &route.hops {
            if self.preferred_nodes.contains(&hop.node_id) {
                score -= 5.0;
            }
        }

        score
    }

    /// Configure the tie-breaking strategy for equal-cost routes.
    pub fn with_tie_breaker(mut self, tie_breaker: TieBreaker) -> Self {
        self.tie_breaker = tie_breaker;
        self
    }

    /// Rank candidate routes deterministically using [`Self::score_route`]
    /// and [`Self::tie_breaker`], after validating each route against `self`
    /// and `request`.
    pub fn rank_routes<'a>(
        &self,
        routes: &'a [Route],
        request: &RouteRequest,
    ) -> Result<Vec<&'a Route>, RoutingError> {
        let mut eligible = Vec::with_capacity(routes.len());
        for route in routes {
            self.route_meets_requirements(route, request)?;
            eligible.push(route);
        }

        eligible.sort_by(|a, b| {
            self.score_route(a)
                .total_cmp(&self.score_route(b))
                .then_with(|| self.tie_breaker.compare_routes(a, b))
        });

        Ok(eligible)
    }
}

/// Fee estimation for routing
pub struct FeeEstimator;

impl FeeEstimator {
    /// Estimate the fee for a route
    pub fn estimate_route_fee(
        graph: &NetworkGraph,
        hops: &[RouteHop],
        amount: i128,
    ) -> Result<i128, RoutingError> {
        let mut total_fee = 0i128;
        let mut remaining = amount;

        for hop in hops {
            let channel =
                graph
                    .get_channel(&hop.channel_id)
                    .ok_or(RoutingError::ChannelNotFound {
                        channel_id: hop.channel_id.clone(),
                    })?;

            let fee = Self::calculate_channel_fee(
                remaining,
                channel.base_fee,
                channel.fee_rate,
                channel.cltv_delta,
            );

            total_fee += fee;
            remaining += fee;
        }

        Ok(total_fee)
    }

    /// Calculate the fee for a single channel
    pub fn calculate_channel_fee(
        amount: i128,
        base_fee: i128,
        fee_rate_ppm: u32,
        cltv_delta: u32,
    ) -> i128 {
        // Fee = base_fee + (amount * fee_rate / 1,000,000) + time_lock_fee
        let proportional = (amount as u128 * fee_rate_ppm as u128 / 1_000_000) as i128;
        let time_lock = (cltv_delta as i128 * 10) / 1440; // ~1 XLM per day

        base_fee + proportional + time_lock
    }

    /// Estimate the fee for routing to a destination
    pub fn estimate_destination_fee(
        _graph: &NetworkGraph,
        _destination: &str,
        amount: i128,
    ) -> Option<i128> {
        // This is a rough estimate based on typical fees
        // In production, you'd use actual pathfinding
        let avg_hops = 3;
        let avg_fee_per_hop = Self::calculate_channel_fee(amount, 1, 1000, 40);

        Some(avg_fee_per_hop * avg_hops as i128)
    }
}

/// Channel selection strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionStrategy {
    /// Select the cheapest route
    Cheapest,
    /// Select the fastest route (fewest hops)
    Fastest,
    /// Select the most reliable route
    MostReliable,
    /// Random selection
    Random,
    /// Privacy-focused selection
    PrivacyFocused,
}

impl SelectionStrategy {
    /// Select the best route according to this strategy.
    ///
    /// Equal-cost routes are broken deterministically using
    /// `policy.tie_breaker` for all deterministic strategies (`Cheapest`,
    /// `Fastest`, `MostReliable`, and `PrivacyFocused`).
    pub fn select<'a>(&self, routes: &'a [Route], policy: &RoutingPolicy) -> Option<&'a Route> {
        match self {
            SelectionStrategy::Cheapest => routes.iter().min_by(|a, b| {
                a.total_fees
                    .cmp(&b.total_fees)
                    .then_with(|| policy.tie_breaker.compare_routes(a, b))
            }),
            SelectionStrategy::Fastest => routes.iter().min_by(|a, b| {
                a.hops
                    .len()
                    .cmp(&b.hops.len())
                    .then_with(|| a.total_fees.cmp(&b.total_fees))
                    .then_with(|| policy.tie_breaker.compare_routes(a, b))
            }),
            SelectionStrategy::MostReliable => routes.iter().min_by(|a, b| {
                b.success_probability
                    .total_cmp(&a.success_probability)
                    .then_with(|| a.total_fees.cmp(&b.total_fees))
                    .then_with(|| policy.tie_breaker.compare_routes(a, b))
            }),
            SelectionStrategy::Random => {
                use rand::seq::SliceRandom;
                routes.choose(&mut rand::thread_rng())
            }
            SelectionStrategy::PrivacyFocused => routes.iter().min_by(|a, b| {
                b.hops
                    .len()
                    .cmp(&a.hops.len())
                    .then_with(|| a.total_fees.cmp(&b.total_fees))
                    .then_with(|| policy.tie_breaker.compare_routes(a, b))
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_defaults() {
        let policy = RoutingPolicy::default();
        assert_eq!(policy.max_hops, MAX_ROUTE_HOPS);
        assert!(policy.allow_mpp);
    }

    #[test]
    fn test_high_value_policy() {
        let policy = RoutingPolicy::high_value();
        assert!(policy.max_fee_bps < 1000);
        assert!(!policy.prefer_low_cltv);
    }

    fn make_route(hops: Vec<(&str, &str, i128, u32)>, prob: f64) -> Route {
        let total_fees = hops.iter().map(|h| h.2).sum();
        let route_hops = hops
            .into_iter()
            .map(|(ch, node, fee, cltv)| {
                RouteHop::new(ch.to_string(), node.to_string(), 1_000, fee, cltv)
            })
            .collect();
        Route {
            hops: route_hops,
            total_fees,
            total_amount: 1_000,
            success_probability: prob,
            metadata: Default::default(),
        }
    }

    #[test]
    fn selection_strategy_breaks_ties_deterministically_independent_of_slice_order() {
        let r_high_cltv = make_route(vec![("ch_a", "bob", 5, 40), ("ch_b", "carol", 5, 40)], 0.95);
        let r_low_cltv = make_route(vec![("ch_c", "dave", 5, 10), ("ch_d", "carol", 5, 10)], 0.95);

        let policy = RoutingPolicy::default();
        let order_1 = vec![r_high_cltv.clone(), r_low_cltv.clone()];
        let order_2 = vec![r_low_cltv.clone(), r_high_cltv.clone()];

        for strategy in [
            SelectionStrategy::Cheapest,
            SelectionStrategy::Fastest,
            SelectionStrategy::MostReliable,
            SelectionStrategy::PrivacyFocused,
        ] {
            let s1 = strategy.select(&order_1, &policy).unwrap();
            let s2 = strategy.select(&order_2, &policy).unwrap();
            assert_eq!(s1.hops, s2.hops);
            assert_eq!(s1.hops[0].channel_id, "ch_c");
        }

        // Lexicographical tie-breaker picks ch_a < ch_c instead.
        let lex_policy = RoutingPolicy::default().with_tie_breaker(TieBreaker::Lexicographical);
        let selected = SelectionStrategy::Cheapest
            .select(&order_2, &lex_policy)
            .unwrap();
        assert_eq!(selected.hops[0].channel_id, "ch_a");
    }

    #[test]
    fn rank_routes_orders_deterministically_and_rejects_policy_violations() {
        let r1 = make_route(vec![("ch_b", "bob", 5, 20)], 0.9);
        let r2 = make_route(vec![("ch_a", "dave", 5, 20)], 0.9);
        let policy = RoutingPolicy::default();
        let req = RouteRequest {
            source: "alice".to_string(),
            destination: "dave".to_string(),
            amount: 1_000,
            max_fee_budget: None,
            max_hops: None,
            find_any: false,
            payment_metadata: None,
        };

        let ranked = policy.rank_routes(&[r1, r2], &req).unwrap();
        assert_eq!(ranked[0].hops[0].channel_id, "ch_a");
        assert_eq!(ranked[1].hops[0].channel_id, "ch_b");

        let mut excluded = policy.clone();
        excluded.excluded_channels.insert("ch_a".to_string());
        let r_excluded = make_route(vec![("ch_a", "dave", 5, 20)], 0.9);
        assert!(matches!(
            excluded.rank_routes(&[r_excluded], &req).unwrap_err(),
            RoutingError::ChannelNotFound { .. }
        ));
    }
}

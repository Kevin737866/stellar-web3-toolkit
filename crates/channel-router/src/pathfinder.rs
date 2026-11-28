//! # Pathfinding Module
//!
//! Advanced pathfinding algorithms for payment channel routing.

use crate::fee_cap::FeeCap;
use crate::{
    build_exclusion_set, compute_hop_timeouts, NetworkGraph, PaymentMetadata, Route, RouteHop,
    RouteRequest, RoutingError, MAX_ROUTE_HOPS,
};
use fxhash::FxHashMap;
use priority_queue::PriorityQueue;
use std::cmp::Reverse;
use std::collections::HashSet;

/// Pathfinding engine for finding optimal payment routes
pub struct Pathfinder {
    /// Maximum number of hops to consider
    max_hops: usize,
    /// Maximum fee as percentage of amount
    max_fee_percent: f64,
    /// Whether to use obfuscation (mix nodes)
    obfuscate: bool,
    /// Ceiling on per-channel and per-route fees
    fee_cap: FeeCap,
    /// Deterministic tie-breaking strategy for equal-cost routes
    tie_breaker: TieBreaker,
}

impl Pathfinder {
    /// Create a new pathfinder with default settings
    pub fn new() -> Self {
        Pathfinder {
            max_hops: MAX_ROUTE_HOPS,
            max_fee_percent: 10.0,
            obfuscate: false,
            fee_cap: FeeCap::protocol(),
            tie_breaker: TieBreaker::default(),
        }
    }

    /// Configure maximum hops
    pub fn with_max_hops(mut self, hops: usize) -> Self {
        self.max_hops = hops.min(MAX_ROUTE_HOPS);
        self
    }

    /// Configure maximum fee percentage
    pub fn with_max_fee_percent(mut self, percent: f64) -> Self {
        self.max_fee_percent = percent;
        self
    }

    /// Enable route obfuscation
    pub fn with_obfuscation(mut self, enabled: bool) -> Self {
        self.obfuscate = enabled;
        self
    }

    /// Apply a specific fee cap instead of the protocol default
    pub fn with_fee_cap(mut self, cap: FeeCap) -> Self {
        self.fee_cap = cap;
        self
    }

    /// The fee cap this pathfinder enforces
    pub fn fee_cap(&self) -> &FeeCap {
        &self.fee_cap
    }

    /// Configure deterministic tie-breaking for equal-cost routes
    pub fn with_tie_breaker(mut self, tie_breaker: TieBreaker) -> Self {
        self.tie_breaker = tie_breaker;
        self
    }

    /// The tie-breaking strategy this pathfinder uses
    pub fn tie_breaker(&self) -> TieBreaker {
        self.tie_breaker
    }

    fn validate_request(
        &self,
        graph: &NetworkGraph,
        request: &RouteRequest,
    ) -> Result<(), RoutingError> {
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

        if let Some(budget) = request.max_fee_budget {
            if budget < 0 {
                return Err(RoutingError::FeeExceedsBudget { fee: 0, budget });
            }
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

        Ok(())
    }

    fn effective_max_hops(&self, request: &RouteRequest) -> usize {
        request
            .max_hops
            .map_or(self.max_hops, |h| h.min(self.max_hops))
    }

    /// Find a route using Dijkstra's algorithm with deterministic tie-breaking
    pub fn find_route_dijkstra(
        &self,
        graph: &NetworkGraph,
        request: &RouteRequest,
    ) -> Result<Route, RoutingError> {
        let excluded = build_exclusion_set(&request.excluded_unavailable)?;

        let mut dist: FxHashMap<String, (i128, Vec<RouteHop>)> = FxHashMap::default();
        let mut pq: PriorityQueue<String, Reverse<i128>> = PriorityQueue::new();

        let mut best: FxHashMap<String, (SearchKey, Vec<RouteHop>)> = FxHashMap::default();
        let mut pq: PriorityQueue<String, Reverse<SearchKey>> = PriorityQueue::new();

        let root_key = SearchKey::root(0, self.tie_breaker);
        best.insert(request.source.clone(), (root_key.clone(), Vec::new()));
        pq.push(request.source.clone(), Reverse(root_key));

        while let Some((node, Reverse(current_key))) = pq.pop() {
            let (final_key, path) = best.get(&node).unwrap().clone();

            if node == request.destination {
                return self.build_route_with_metadata(
                    path,
                    request.amount,
                    request.payment_metadata.as_ref(),
                );
            }

            if current_key > final_key {
                continue;
            }

            // Check hop limit (Issue #364)
            let effective_max_hops = request
                .max_hops
                .map_or(self.max_hops, |h| h.min(self.max_hops));
            if path.len() >= effective_max_hops {
                continue;
            }

            let current_amount = self.calculate_amount_at_node(&path, request.amount);
            let cost = current_key.primary_cost;

            if let Some(neighbors) = graph.adjacency.get(&node) {
                for (neighbor, channel_id) in neighbors {
                    if let Some(channel) = graph.channels.get(channel_id) {
                        // Skip temporarily unavailable channels.
                        if excluded.contains(channel_id.as_str()) {
                            continue;
                        }

                        if self.fee_cap.check_channel(channel).is_err() {
                            continue;
                        }

                    // `neighbor` is the destination of this hop, so the
                    // capacity that matters is the one leaving the current
                    // node -- the opposite direction's capacity says
                    // nothing about whether this hop can forward the
                    // payment.
                    let capacity = if &channel.node_a == neighbor {
                        channel.capacity_b_to_a
                    } else {
                        channel.capacity_a_to_b
                    };

                    if capacity < current_amount {
                        continue;
                    }

                    if channel.base_fee < 0 {
                        continue;
                    }

                    let fee = self.calculate_fee(channel, current_amount);
                    if fee < 0 {
                        continue;
                    }

                    let Some(new_cost) = cost.checked_add(fee) else {
                        continue;
                    };

                    // Fee budget check against accumulated route fee
                    if let Some(max_fee) = request.max_fee_budget {
                        if new_cost > max_fee {
                            continue;
                        }
                    }

                    let next_key =
                        current_key.extend(new_cost, channel_id, neighbor, channel.cltv_delta);

                    let is_better = match best.get(neighbor) {
                        None => true,
                        Some((existing_key, _)) => next_key < *existing_key,
                    };

                    if is_better {
                        let mut new_path = path.clone();
                        new_path.push(RouteHop::new(
                            (*channel_id).clone(),
                            (*neighbor).clone(),
                            current_amount,
                            fee,
                            channel.cltv_delta,
                        ));
                        best.insert((*neighbor).clone(), (next_key.clone(), new_path));
                        pq.push((*neighbor).clone(), Reverse(next_key));
                    }
                }
            }
        }

        Err(RoutingError::NoPathFound {
            origin: request.source.clone(),
            destination: request.destination.clone(),
        })
    }

    /// Find a route using A* algorithm with deterministic tie-breaking
    pub fn find_route_astar(
        &self,
        graph: &NetworkGraph,
        request: &RouteRequest,
    ) -> Result<Route, RoutingError> {
        let excluded = build_exclusion_set(&request.excluded_unavailable)?;

        let mut open_set: PriorityQueue<String, Reverse<i128>> = PriorityQueue::new();
        let mut g_score: FxHashMap<String, i128> = FxHashMap::default();
        let mut f_score: FxHashMap<String, i128> = FxHashMap::default();
        let mut came_from: FxHashMap<String, (String, RouteHop)> = FxHashMap::default();

        let heuristic = |node: &str| -> i128 {
            // Simple heuristic: assume minimum fee per hop
            let hops = i32::from(node != request.destination);
            hops as i128 * 10 // Minimum 10 units per hop
        };

        let root_g = SearchKey::root(0, self.tie_breaker);
        let root_f = SearchKey::root(heuristic(&request.source), self.tie_breaker);
        g_keys.insert(request.source.clone(), root_g);
        open_set.push(request.source.clone(), Reverse(root_f));

        while let Some((current, Reverse(_))) = open_set.pop() {
            if current == request.destination {
                return self.reconstruct_route_astar(
                    &came_from,
                    &request.source,
                    &request.destination,
                    request.amount,
                    request.payment_metadata.as_ref(),
                );
            }

            let current_g_key = g_keys.get(&current).unwrap().clone();
            if current_g_key.hops >= max_hops {
                continue;
            }
            let current_g = current_g_key.primary_cost;
            let current_amount = self.get_amount_for_node(&current, &came_from, request.amount);

            for (neighbor, channel_id) in sorted_neighbors(graph, &current) {
                let Some(channel) = graph.channels.get(channel_id) else {
                    continue;
                };

                    // Skip temporarily unavailable channels.
                    if excluded.contains(channel_id.as_str()) {
                        continue;
                    }

                    if self.fee_cap.check_channel(channel).is_err() {
                        continue;
                    }

                let capacity = if &channel.node_a == neighbor {
                    channel.capacity_b_to_a
                } else {
                    channel.capacity_a_to_b
                };

                if capacity < current_amount {
                    continue;
                }

                if channel.base_fee < 0 {
                    continue;
                }

                let fee = self.calculate_fee(channel, current_amount);
                if fee < 0 {
                    continue;
                }

                let Some(tentative_g) = current_g.checked_add(fee) else {
                    continue;
                };

                if let Some(max_fee) = request.max_fee_budget {
                    if tentative_g > max_fee {
                        continue;
                    }
                }

                let tentative_g_key =
                    current_g_key.extend(tentative_g, channel_id, neighbor, channel.cltv_delta);

                let is_better = match g_keys.get(neighbor) {
                    None => true,
                    Some(existing) => tentative_g_key < *existing,
                };

                if is_better {
                    let hop = RouteHop::new(
                        (*channel_id).clone(),
                        (*neighbor).clone(),
                        current_amount,
                        fee,
                        channel.cltv_delta,
                    );
                    came_from.insert((*neighbor).clone(), (current.clone(), hop));
                    g_keys.insert((*neighbor).clone(), tentative_g_key.clone());

                    let mut f_key = tentative_g_key;
                    f_key.primary_cost = tentative_g.saturating_add(heuristic(neighbor));
                    open_set.push((*neighbor).clone(), Reverse(f_key));
                }
            }
        }

        Err(RoutingError::NoPathFound {
            origin: request.source.clone(),
            destination: request.destination.clone(),
        })
    }

    /// Find route using BFS (fewest hops) with deterministic tie-breaking
    pub fn find_route_bfs(
        &self,
        graph: &NetworkGraph,
        request: &RouteRequest,
    ) -> Result<Route, RoutingError> {
        let excluded = build_exclusion_set(&request.excluded_unavailable)?;

        let mut queue: VecDeque<(String, Vec<RouteHop>)> = VecDeque::new();
        let mut visited: HashSet<String> = HashSet::new();

        while let Some((current, Reverse(current_key))) = pq.pop() {
            let (final_key, path) = best.get(&current).unwrap().clone();

            if current == request.destination {
                return self.build_route_with_metadata(
                    path,
                    request.amount,
                    request.payment_metadata.as_ref(),
                );
            }

            let effective_max_hops = request
                .max_hops
                .map_or(self.max_hops, |h| h.min(self.max_hops));
            if path.len() >= effective_max_hops {
                continue;
            }

            let current_amount = self.calculate_amount_at_node(&path, request.amount);

            for (neighbor, channel_id) in sorted_neighbors(graph, &current) {
                if let Some(channel) = graph.channels.get(channel_id) {
                    if self.fee_cap.check_channel(channel).is_err() {
                        continue;
                    }

                    if let Some(channel) = graph.channels.get(channel_id) {
                        // Skip temporarily unavailable channels.
                        if excluded.contains(channel_id.as_str()) {
                            continue;
                        }

                        if self.fee_cap.check_channel(channel).is_err() {
                            continue;
                        }

                    if capacity < current_amount || channel.base_fee < 0 {
                        continue;
                    }

                    let fee = self.calculate_fee(channel, current_amount);
                    if fee < 0 {
                        continue;
                    }

                    let next_hops = (path.len() + 1) as i128;
                    let next_key =
                        current_key.extend(next_hops, channel_id, neighbor, channel.cltv_delta);

                    let is_better = match best.get(neighbor) {
                        None => true,
                        Some((existing_key, _)) => next_key < *existing_key,
                    };

                    if is_better {
                        let mut new_path = path.clone();
                        new_path.push(RouteHop::new(
                            (*channel_id).clone(),
                            (*neighbor).clone(),
                            current_amount,
                            fee,
                            channel.cltv_delta,
                        ));
                        best.insert((*neighbor).clone(), (next_key.clone(), new_path));
                        pq.push((*neighbor).clone(), Reverse(next_key));
                    }
                }
            }
        }

        Err(RoutingError::NoPathFound {
            origin: request.source.clone(),
            destination: request.destination.clone(),
        })
    }

    /// Find cheapest route
    pub fn find_cheapest_route(
        &self,
        graph: &NetworkGraph,
        request: &RouteRequest,
    ) -> Result<Route, RoutingError> {
        self.find_route_dijkstra(graph, request)
    }

    /// Find fastest route (fewest hops)
    pub fn find_fastest_route(
        &self,
        graph: &NetworkGraph,
        request: &RouteRequest,
    ) -> Result<Route, RoutingError> {
        self.find_route_bfs(graph, request)
    }

    /// Find a random route (for privacy)
    pub fn find_random_route(
        &self,
        graph: &NetworkGraph,
        request: &RouteRequest,
    ) -> Result<Route, RoutingError> {
        use rand::seq::SliceRandom;

        let excluded = build_exclusion_set(&request.excluded_unavailable)?;

        let mut visited: HashSet<String> = HashSet::new();
        let mut path: Vec<RouteHop> = Vec::new();
        let mut current = request.source.clone();
        let amount = request.amount;

        visited.insert(current.clone());

        while current != request.destination && path.len() < self.max_hops {
            let neighbors: Vec<(&String, &String)> = graph
                .adjacency
                .get(&current)
                .map(|n| n.iter().collect::<Vec<_>>())
                .unwrap_or_default();

            // Filter out visited nodes, excluded channels, and nodes without capacity
            let valid_neighbors: Vec<_> = neighbors
                .into_iter()
                .filter(|(node_id, channel_id)| {
                    if visited.contains(*node_id) {
                        return false;
                    }
                    // Skip temporarily unavailable channels.
                    if excluded.contains(channel_id.as_str()) {
                        return false;
                    }
                    if let Some(channel) = graph.channels.get(*channel_id) {
                        if self.fee_cap.check_channel(channel).is_err() {
                            return false;
                        }
                        // `node_id` is the neighbour being moved to.
                        let capacity = if &channel.node_a == *node_id {
                            channel.capacity_b_to_a
                        } else {
                            channel.capacity_a_to_b
                        };
                        capacity >= amount
                    } else {
                        false
                    }
                })
                .collect();

            if valid_neighbors.is_empty() {
                break;
            }

            // Pick a random neighbor
            let (next_node, channel_id) = valid_neighbors.choose(&mut rand::thread_rng()).unwrap();

            let channel = graph.channels.get(*channel_id).unwrap();
            let fee = self.calculate_fee(channel, amount);

            path.push(RouteHop::new(
                (*channel_id).clone(),
                (*next_node).clone(),
                amount,
                fee,
                channel.cltv_delta,
            ));

            current = (**next_node).clone();
            visited.insert(current.clone());
        }

        if current != request.destination {
            return Err(RoutingError::NoPathFound {
                origin: request.source.clone(),
                destination: request.destination.clone(),
            });
        }

        self.build_route_with_metadata(path, request.amount, request.payment_metadata.as_ref())
    }

    fn calculate_fee(&self, channel: &crate::Channel, amount: i128) -> i128 {
        let proportional_fee = (amount as u128 * channel.fee_rate as u128 / 1_000_000) as i128;
        let time_lock_fee = (channel.cltv_delta as i128 * 10) / 1440;
        channel.base_fee + proportional_fee + time_lock_fee
    }

    /// Reject a path whose hops or total break the fee cap.
    ///
    /// Every search above filters out offensive *channels*, but that alone
    /// does not bound a route: twenty hops each charging just under the
    /// per-hop cap still overpay for the payment.
    fn enforce_fee_cap(&self, amount: i128, path: &[RouteHop]) -> Result<(), RoutingError> {
        self.fee_cap.check_hops(amount, path)
    }

    fn calculate_amount_at_node(&self, path: &[RouteHop], initial_amount: i128) -> i128 {
        // Amount grows as we pay fees along the path
        let mut amount = initial_amount;
        for hop in path {
            amount += hop.fee;
        }
        amount
    }

    /// Amount arriving at `node`: the payment plus the fees of every hop that
    /// precedes it. Walking the `came_from` chain backwards is what makes the
    /// fee of a hop depend on the amount that actually reaches it.
    fn get_amount_for_node(
        &self,
        node: &str,
        came_from: &FxHashMap<String, (String, RouteHop)>,
        initial_amount: i128,
    ) -> i128 {
        let mut amount = initial_amount;
        let mut current = node.to_string();
        let mut steps = 0usize;

        while let Some((prev, hop)) = came_from.get(&current) {
            amount += hop.fee;

            // A cycle in `came_from` would otherwise spin forever; stop after
            // the longest path the router could ever build.
            steps += 1;
            if *prev == current || steps > MAX_ROUTE_HOPS {
                break;
            }

            current = prev.clone();
        }

        amount
    }

    fn build_route_with_metadata(
        &self,
        mut path: Vec<RouteHop>,
        amount: i128,
        payment_metadata: Option<&PaymentMetadata>,
    ) -> Result<Route, RoutingError> {
        if path.is_empty() {
            return Err(RoutingError::NoPathFound {
                origin: "unknown".to_string(),
                destination: "unknown".to_string(),
            });
        }

        let total_fees: i128 = path.iter().map(|h| h.fee).sum();
        let max_fee = (amount as f64 * self.max_fee_percent / 100.0) as i128;

        if total_fees > max_fee {
            return Err(RoutingError::FeeExceedsBudget {
                fee: total_fees,
                budget: max_fee,
            });
        }

        self.enforce_fee_cap(amount, &path)?;

        let (final_cltv_delta, max_cltv_budget) = match payment_metadata {
            Some(meta) => (meta.required_cltv_delta.unwrap_or(0), meta.payment_expiry),
            None => (0, None),
        };
        let (total_cltv_delta, hop_timeouts) =
            compute_hop_timeouts(&mut path, final_cltv_delta, max_cltv_budget)?;
        let num_hops = path.len();

        Ok(Route {
            hops: path,
            total_fees,
            total_amount: amount,
            success_probability: 0.9,
            metadata: crate::RouteMetadata {
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                num_nodes: num_hops,
                estimated_time_ms: 100,
                is_direct: num_hops == 1,
                total_cltv_delta,
                hop_timeouts,
            },
        })
    }

    fn reconstruct_route_astar(
        &self,
        came_from: &FxHashMap<String, (String, RouteHop)>,
        source: &str,
        destination: &str,
        amount: i128,
        payment_metadata: Option<&PaymentMetadata>,
    ) -> Result<Route, RoutingError> {
        let mut path = Vec::new();
        let mut current = destination.to_string();

        while let Some((prev, hop)) = came_from.get(&current) {
            path.push(hop.clone());

            if prev == source {
                break;
            }
            current = prev.clone();
        }

        path.reverse();

        if path.is_empty() {
            return Err(RoutingError::NoPathFound {
                origin: source.to_string(),
                destination: destination.to_string(),
            });
        }

        self.build_route_with_metadata(path, amount, payment_metadata)
    }
}

impl Default for Pathfinder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fee_cap::MAX_CHANNEL_FEE_RATE_PPM;
    use crate::{Channel, Node, NodeFeatures};

    fn graph_with(fee_rates: &[(&str, &str, &str, u32)]) -> NetworkGraph {
        let mut graph = NetworkGraph::new();
        for id in ["alice", "bob", "carol"] {
            graph.add_node(Node {
                id: id.to_string(),
                public_key: vec![1],
                alias: None,
                online: true,
                last_seen: 0,
                features: NodeFeatures::default(),
            });
        }

        for (id, a, b, fee_rate) in fee_rates {
            graph.add_channel(Channel {
                id: id.to_string(),
                node_a: a.to_string(),
                node_b: b.to_string(),
                // Headroom for the fees each hop adds on top of the payment.
                capacity_a_to_b: 5_000_000,
                capacity_b_to_a: 5_000_000,
                base_fee: 1,
                fee_rate: *fee_rate,
                cltv_delta: 40,
                min_htlc_size: 1,
                max_htlc_size: 5_000_000,
                htlcs_in_flight: 0,
                enabled: true,
                age_seconds: 0,
            });
        }

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
            excluded_unavailable: vec![],
        }
    }

    #[test]
    fn default_pathfinder_enforces_protocol_cap() {
        let pathfinder = Pathfinder::new();
        assert_eq!(pathfinder.fee_cap(), &FeeCap::protocol());
    }

    #[test]
    fn all_search_algorithms_skip_channels_above_the_fee_rate_cap() {
        let graph = graph_with(&[
            ("ch1", "alice", "bob", 1_000),
            ("ch2", "bob", "carol", MAX_CHANNEL_FEE_RATE_PPM + 1),
        ]);

        let pathfinder = Pathfinder::new();
        assert!(pathfinder.find_route_dijkstra(&graph, &request()).is_err());
        assert!(pathfinder.find_route_astar(&graph, &request()).is_err());
        assert!(pathfinder.find_route_bfs(&graph, &request()).is_err());
        assert!(pathfinder.find_random_route(&graph, &request()).is_err());
    }

    #[test]
    fn changing_the_cap_changes_which_channels_are_usable() {
        let graph = graph_with(&[
            ("ch1", "alice", "bob", 1_000),
            ("ch2", "bob", "carol", MAX_CHANNEL_FEE_RATE_PPM + 1),
        ]);

        // Widen the per-channel rate cap and the greedy hop becomes usable.
        let permissive = FeeCap {
            max_channel_fee_rate_ppm: MAX_CHANNEL_FEE_RATE_PPM * 2,
            ..FeeCap::protocol()
        };
        let pathfinder = Pathfinder::new().with_fee_cap(permissive);
        assert!(pathfinder.find_route_dijkstra(&graph, &request()).is_ok());
    }

    #[test]
    fn multi_hop_route_total_is_capped() {
        let graph = graph_with(&[
            ("ch1", "alice", "bob", MAX_CHANNEL_FEE_RATE_PPM),
            ("ch2", "bob", "carol", MAX_CHANNEL_FEE_RATE_PPM),
        ]);

        // Both hops are legal on their own, but a route budget of zero rejects
        // the route even though no single hop broke its own cap.
        let strict = Pathfinder::new().with_fee_cap(FeeCap {
            max_route_fee_ppm: 0,
            max_route_fee_abs: 0,
            ..FeeCap::protocol()
        });
        assert!(matches!(
            strict.find_route_dijkstra(&graph, &request()).unwrap_err(),
            RoutingError::RouteFeeCapExceeded { .. }
        ));

        // The protocol cap accepts the very same route.
        assert!(Pathfinder::new()
            .find_route_dijkstra(&graph, &request())
            .is_ok());
    }

    #[test]
    fn test_max_hops_enforcement_in_request() {
        // Issue #364: Request max_hops strictly limits path length
        let make_node = |id: &str| Node {
            id: id.to_string(),
            public_key: vec![1],
            alias: None,
            online: true,
            last_seen: 0,
            features: NodeFeatures::default(),
        };

        let mut graph = NetworkGraph::new();
        for i in 0..5 {
            graph.add_node(make_node(&format!("n{i}")));
        }

        // Linear path n0 -> n1 -> n2 -> n3 -> n4 (4 hops)
        for i in 0..4 {
            graph.add_channel(Channel {
                id: format!("c{i}"),
                node_a: format!("n{i}"),
                node_b: format!("n{}", i + 1),
                capacity_a_to_b: 10_000,
                capacity_b_to_a: 10_000,
                base_fee: 1,
                fee_rate: 10,
                cltv_delta: 10,
                min_htlc_size: 1,
                max_htlc_size: 10_000,
                htlcs_in_flight: 0,
                enabled: true,
                age_seconds: 0,
            });
        }

        let pathfinder = Pathfinder::new();

        // 4 hops requested allowed: succeeds
        let req_ok = RouteRequest::new("n0".to_string(), "n4".to_string(), 100).with_max_hops(4);
        let route = pathfinder
            .find_route_dijkstra(&graph, &req_ok)
            .expect("route with 4 hops should succeed");
        assert_eq!(route.hops.len(), 4);

        // 3 hops requested: must fail since path requires 4 hops
        let req_too_short =
            RouteRequest::new("n0".to_string(), "n4".to_string(), 100).with_max_hops(3);
        let err = pathfinder.find_route_dijkstra(&graph, &req_too_short);
        assert!(err.is_err(), "route exceeding request max_hops must fail");
    }

    #[test]
    fn test_route_search_disconnected_network_components() {
        // Issue #366: Route search between disconnected network components
        let make_node = |id: &str| Node {
            id: id.to_string(),
            public_key: vec![1],
            alias: None,
            online: true,
            last_seen: 0,
            features: NodeFeatures::default(),
        };

        let mut graph = NetworkGraph::new();

        // Component A: n0 <-> n1
        graph.add_node(make_node("n0"));
        graph.add_node(make_node("n1"));
        graph.add_channel(Channel {
            id: "c_a".to_string(),
            node_a: "n0".to_string(),
            node_b: "n1".to_string(),
            capacity_a_to_b: 5_000,
            capacity_b_to_a: 5_000,
            base_fee: 1,
            fee_rate: 10,
            cltv_delta: 10,
            min_htlc_size: 1,
            max_htlc_size: 5_000,
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 0,
        });

        // Component B: n2 <-> n3 (disconnected from Component A)
        graph.add_node(make_node("n2"));
        graph.add_node(make_node("n3"));
        graph.add_channel(Channel {
            id: "c_b".to_string(),
            node_a: "n2".to_string(),
            node_b: "n3".to_string(),
            capacity_a_to_b: 5_000,
            capacity_b_to_a: 5_000,
            base_fee: 1,
            fee_rate: 10,
            cltv_delta: 10,
            min_htlc_size: 1,
            max_htlc_size: 5_000,
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 0,
        });

        // Isolated node: n_iso with 0 channels
        graph.add_node(make_node("n_iso"));

        let pathfinder = Pathfinder::new();

        // Cross-component search (n0 -> n3) must fail cleanly with NoPathFound
        let req_disconnected = RouteRequest::new("n0".to_string(), "n3".to_string(), 500);
        let res_disc = pathfinder.find_route_dijkstra(&graph, &req_disconnected);
        assert!(matches!(res_disc, Err(RoutingError::NoPathFound { .. })));

        // Search from isolated node must fail cleanly
        let req_iso = RouteRequest::new("n_iso".to_string(), "n1".to_string(), 500);
        let res_iso = pathfinder.find_route_dijkstra(&graph, &req_iso);
        assert!(matches!(res_iso, Err(RoutingError::NoPathFound { .. })));
    }
}

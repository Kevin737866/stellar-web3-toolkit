//! # Pathfinding Module
//!
//! Advanced pathfinding algorithms for payment channel routing.

use crate::fee_cap::FeeCap;
use crate::policy::{sorted_neighbors, SearchKey, TieBreaker};
use crate::{
    NetworkGraph, Route, RouteHop, RouteRequest, RoutingError, MAX_ROUTE_AMOUNT, MAX_ROUTE_HOPS,
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
        self.validate_request(graph, request)?;
        let max_hops = self.effective_max_hops(request);

        let mut best: FxHashMap<String, (SearchKey, Vec<RouteHop>)> = FxHashMap::default();
        let mut pq: PriorityQueue<String, Reverse<SearchKey>> = PriorityQueue::new();

        let root_key = SearchKey::root(0, self.tie_breaker);
        best.insert(request.source.clone(), (root_key.clone(), Vec::new()));
        pq.push(request.source.clone(), Reverse(root_key));

        while let Some((node, Reverse(current_key))) = pq.pop() {
            let (final_key, path) = best.get(&node).unwrap().clone();

            if node == request.destination {
                if path.is_empty() {
                    break;
                }
                return self.build_route(path, request.amount);
            }

            if current_key > final_key {
                continue;
            }

            // Check hop limit
            if path.len() >= max_hops {
                continue;
            }

            let current_amount = self.calculate_amount_at_node(&path, request.amount);
            let cost = current_key.primary_cost;

            for (neighbor, channel_id) in sorted_neighbors(graph, &node) {
                if let Some(channel) = graph.channels.get(channel_id) {
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
        self.validate_request(graph, request)?;
        let max_hops = self.effective_max_hops(request);

        let mut open_set: PriorityQueue<String, Reverse<SearchKey>> = PriorityQueue::new();
        let mut g_keys: FxHashMap<String, SearchKey> = FxHashMap::default();
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
        self.validate_request(graph, request)?;
        let max_hops = self.effective_max_hops(request);

        let mut best: FxHashMap<String, (SearchKey, Vec<RouteHop>)> = FxHashMap::default();
        let mut pq: PriorityQueue<String, Reverse<SearchKey>> = PriorityQueue::new();

        let root_key = SearchKey::root(0, self.tie_breaker);
        best.insert(request.source.clone(), (root_key.clone(), Vec::new()));
        pq.push(request.source.clone(), Reverse(root_key));

        while let Some((current, Reverse(current_key))) = pq.pop() {
            let (final_key, path) = best.get(&current).unwrap().clone();

            if current == request.destination {
                if path.is_empty() {
                    break;
                }
                return self.build_route(path, request.amount);
            }

            if current_key > final_key {
                continue;
            }

            if path.len() >= max_hops {
                continue;
            }

            let current_amount = self.calculate_amount_at_node(&path, request.amount);

            for (neighbor, channel_id) in sorted_neighbors(graph, &current) {
                if let Some(channel) = graph.channels.get(channel_id) {
                    if self.fee_cap.check_channel(channel).is_err() {
                        continue;
                    }

                    let capacity = if &channel.node_a == neighbor {
                        channel.capacity_b_to_a
                    } else {
                        channel.capacity_a_to_b
                    };

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

            // Filter out visited nodes and nodes without capacity
            let valid_neighbors: Vec<_> = neighbors
                .into_iter()
                .filter(|(node_id, channel_id)| {
                    if visited.contains(*node_id) {
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

        self.build_route(path, request.amount)
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

    fn build_route(&self, path: Vec<RouteHop>, amount: i128) -> Result<Route, RoutingError> {
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
                num_nodes: 0, // Will be set correctly
                estimated_time_ms: 100,
                is_direct: false,
            },
        })
    }

    fn reconstruct_route_astar(
        &self,
        came_from: &FxHashMap<String, (String, RouteHop)>,
        source: &str,
        destination: &str,
        amount: i128,
    ) -> Result<Route, RoutingError> {
        let mut path = Vec::new();
        let mut current = destination.to_string();
        let mut total_fees = 0i128;

        while let Some((prev, hop)) = came_from.get(&current) {
            path.push(hop.clone());
            total_fees += hop.fee;

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

        self.enforce_fee_cap(amount, &path)?;

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
                num_nodes: 0,
                estimated_time_ms: 100,
                is_direct: false,
            },
        })
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
    fn pathfinder_algorithms_are_deterministic_for_equal_cost_routes() {
        let build_graph = |reverse: bool| {
            let mut graph = NetworkGraph::new();
            for id in ["alice", "bob", "dave", "carol"] {
                graph.add_node(Node {
                    id: id.to_string(),
                    public_key: vec![1],
                    alias: None,
                    online: true,
                    last_seen: 0,
                    features: NodeFeatures::default(),
                });
            }
            let mut channels = vec![
                ("ch_z1", "alice", "bob", 40u32),
                ("ch_z2", "bob", "carol", 40),
                ("ch_a1", "alice", "dave", 40),
                ("ch_a2", "dave", "carol", 40),
            ];
            if reverse {
                channels.reverse();
            }
            for (id, a, b, cltv) in channels {
                graph.add_channel(Channel {
                    id: id.to_string(),
                    node_a: a.to_string(),
                    node_b: b.to_string(),
                    capacity_a_to_b: 5_000_000,
                    capacity_b_to_a: 5_000_000,
                    base_fee: 1,
                    fee_rate: 1_000,
                    cltv_delta: cltv,
                    min_htlc_size: 1,
                    max_htlc_size: 5_000_000,
                    htlcs_in_flight: 0,
                    enabled: true,
                    age_seconds: 0,
                });
            }
            graph
        };

        let pf = Pathfinder::new();
        let req = request();
        let g1 = build_graph(false);
        let g2 = build_graph(true);

        let d1 = pf.find_route_dijkstra(&g1, &req).unwrap();
        let d2 = pf.find_route_dijkstra(&g2, &req).unwrap();
        assert_eq!(d1.hops, d2.hops);
        assert_eq!(d1.hops[0].channel_id, "ch_a1");

        let a1 = pf.find_route_astar(&g1, &req).unwrap();
        let a2 = pf.find_route_astar(&g2, &req).unwrap();
        assert_eq!(a1.hops, a2.hops);
        assert_eq!(a1.hops[0].channel_id, "ch_a1");

        let b1 = pf.find_route_bfs(&g1, &req).unwrap();
        let b2 = pf.find_route_bfs(&g2, &req).unwrap();
        assert_eq!(b1.hops, b2.hops);
        assert_eq!(b1.hops[0].channel_id, "ch_a1");
    }

    #[test]
    fn pathfinder_rejects_invalid_requests() {
        let graph = graph_with(&[("ch1", "alice", "bob", 1_000)]);
        let pf = Pathfinder::new();

        let mut bad_amount = request();
        bad_amount.amount = 0;
        assert!(matches!(
            pf.find_route_dijkstra(&graph, &bad_amount).unwrap_err(),
            RoutingError::BelowDustLimit { .. }
        ));

        let mut missing_node = request();
        missing_node.destination = "unknown".to_string();
        assert!(matches!(
            pf.find_route_astar(&graph, &missing_node).unwrap_err(),
            RoutingError::NodeNotFound { .. }
        ));
    }
}

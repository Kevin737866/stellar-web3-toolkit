//! # Pathfinding Module
//! 
//! Advanced pathfinding algorithms for payment channel routing.

use crate::{NetworkGraph, Route, RouteRequest, RouteHop, RoutingError, MAX_ROUTE_HOPS};
use crate::graph::GraphView;
use std::collections::{HashMap, HashSet, VecDeque};
use std::cmp::Reverse;
use priority_queue::PriorityQueue;
use fxhash::FxHashMap;

/// Pathfinding engine for finding optimal payment routes
pub struct Pathfinder {
    /// Maximum number of hops to consider
    max_hops: usize,
    /// Maximum fee as percentage of amount
    max_fee_percent: f64,
    /// Whether to use obfuscation (mix nodes)
    obfuscate: bool,
}

impl Pathfinder {
    /// Create a new pathfinder with default settings
    pub fn new() -> Self {
        Pathfinder {
            max_hops: MAX_ROUTE_HOPS,
            max_fee_percent: 10.0,
            obfuscate: false,
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
    
    /// Find a route using Dijkstra's algorithm
    pub fn find_route_dijkstra(
        &self,
        graph: &NetworkGraph,
        request: &RouteRequest,
    ) -> Result<Route, RoutingError> {
        let mut dist: FxHashMap<String, (i128, Vec<RouteHop>)> = FxHashMap::default();
        let mut pq: PriorityQueue<String, Reverse<i128>, fxhash::FxBuildHasher> = PriorityQueue::new();
        
        dist.insert(request.source.clone(), (0, Vec::new()));
        pq.push(request.source.clone(), Reverse(0));
        
        while let Some((node, Reverse(cost))) = pq.pop() {
            let (final_cost, path) = dist.get(&node).unwrap().clone();
            
            if node == request.destination {
                return self.build_route(path, request.amount);
            }
            
            if cost > final_cost {
                continue;
            }
            
            // Check hop limit
            if path.len() >= self.max_hops {
                continue;
            }
            
            let current_amount = self.calculate_amount_at_node(&path, request.amount);
            
            if let Some(neighbors) = graph.adjacency.get(&node) {
                for (neighbor, channel_id) in neighbors {
                    if let Some(channel) = graph.channels.get(channel_id) {
                        let (capacity, _) = if &channel.node_a == neighbor {
                            (channel.capacity_a_to_b, "a_to_b")
                        } else {
                            (channel.capacity_b_to_a, "b_to_a")
                        };
                        
                        if capacity < current_amount {
                            continue;
                        }
                        
                        let fee = self.calculate_fee(channel, current_amount);
                        let new_cost = cost + fee;
                        
                        // Fee budget check
                        if let Some(max_fee) = request.max_fee_budget {
                            if fee > max_fee {
                                continue;
                            }
                        }
                        
                        let mut new_path = path.clone();
                        new_path.push(RouteHop::new(
                            channel_id.clone(),
                            neighbor.clone(),
                            current_amount,
                            fee,
                            channel.cltv_delta,
                        ));
                        
                        if new_cost < *dist.get(neighbor).map(|(c, _)| c).unwrap_or(&i128::MAX) {
                            dist.insert(neighbor.clone(), (new_cost, new_path));
                            pq.push(neighbor.clone(), Reverse(new_cost));
                        }
                    }
                }
            }
        }
        
        Err(RoutingError::NoPathFound {
            source: request.source.clone(),
            destination: request.destination.clone(),
        })
    }
    
    /// Find a route using A* algorithm
    pub fn find_route_astar(
        &self,
        graph: &NetworkGraph,
        request: &RouteRequest,
    ) -> Result<Route, RoutingError> {
        let mut open_set: PriorityQueue<String, Reverse<i64>, fxhash::FxBuildHasher> = PriorityQueue::new();
        let mut g_score: FxHashMap<String, i128> = FxHashMap::default();
        let mut f_score: FxHashMap<String, i128> = FxHashMap::default();
        let mut came_from: FxHashMap<String, (String, RouteHop)> = FxHashMap::default();
        
        let heuristic = |node: &str| -> i128 {
            // Simple heuristic: assume minimum fee per hop
            let hops = if node == &request.destination { 0 } else { 1 };
            hops as i128 * 10 // Minimum 10 units per hop
        };
        
        g_score.insert(request.source.clone(), 0);
        f_score.insert(request.source.clone(), heuristic(&request.source));
        open_set.push(request.source.clone(), Reverse(heuristic(&request.source)));
        
        while let Some((current, Reverse(_))) = open_set.pop() {
            if current == request.destination {
                return self.reconstruct_route_astar(&came_from, &request.source, &request.destination, request.amount);
            }
            
            let current_g = *g_score.get(&current).unwrap();
            
            if let Some(neighbors) = graph.adjacency.get(&current) {
                for (neighbor, channel_id) in neighbors {
                    let channel = match graph.channels.get(channel_id) {
                        Some(c) => c,
                        None => continue,
                    };
                    
                    let current_amount = self.get_amount_for_node(&current, &came_from, request.amount);
                    let (capacity, _) = if &channel.node_a == neighbor {
                        (channel.capacity_a_to_b, "a_to_b")
                    } else {
                        (channel.capacity_b_to_a, "b_to_a")
                    };
                    
                    if capacity < current_amount {
                        continue;
                    }
                    
                    let fee = self.calculate_fee(channel, current_amount);
                    let tentative_g = current_g + fee;
                    
                    if tentative_g < *g_score.get(neighbor).unwrap_or(&i128::MAX) {
                        let hop = RouteHop::new(
                            channel_id.clone(),
                            neighbor.clone(),
                            current_amount,
                            fee,
                            channel.cltv_delta,
                        );
                        came_from.insert(neighbor.clone(), (current.clone(), hop));
                        g_score.insert(neighbor.clone(), tentative_g);
                        let f = tentative_g + heuristic(neighbor);
                        f_score.insert(neighbor.clone(), f);
                        open_set.push(neighbor.clone(), Reverse(f));
                    }
                }
            }
        }
        
        Err(RoutingError::NoPathFound {
            source: request.source.clone(),
            destination: request.destination.clone(),
        })
    }
    
    /// Find route using BFS (for finding any path quickly)
    pub fn find_route_bfs(
        &self,
        graph: &NetworkGraph,
        request: &RouteRequest,
    ) -> Result<Route, RoutingError> {
        let mut queue: VecDeque<(String, Vec<RouteHop>)> = VecDeque::new();
        let mut visited: HashSet<String> = HashSet::new();
        
        queue.push_back((request.source.clone(), Vec::new()));
        visited.insert(request.source.clone());
        
        while let Some((current, mut path)) = queue.pop_front() {
            if current == request.destination {
                return self.build_route(path, request.amount);
            }
            
            if path.len() >= self.max_hops {
                continue;
            }
            
            let current_amount = self.calculate_amount_at_node(&path, request.amount);
            
            if let Some(neighbors) = graph.adjacency.get(&current) {
                for (neighbor, channel_id) in neighbors {
                    if visited.contains(neighbor) {
                        continue;
                    }
                    
                    if let Some(channel) = graph.channels.get(channel_id) {
                        let (capacity, _) = if &channel.node_a == neighbor {
                            (channel.capacity_a_to_b, "a_to_b")
                        } else {
                            (channel.capacity_b_to_a, "b_to_a")
                        };
                        
                        if capacity >= current_amount {
                            let fee = self.calculate_fee(channel, current_amount);
                            let mut new_path = path.clone();
                            new_path.push(RouteHop::new(
                                channel_id.clone(),
                                neighbor.clone(),
                                current_amount,
                                fee,
                                channel.cltv_delta,
                            ));
                            queue.push_back((neighbor.clone(), new_path));
                            visited.insert(neighbor.clone());
                        }
                    }
                }
            }
        }
        
        Err(RoutingError::NoPathFound {
            source: request.source.clone(),
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
        let mut amount = request.amount;
        
        visited.insert(current.clone());
        
        while current != request.destination && path.len() < self.max_hops {
            let neighbors: Vec<_> = graph.adjacency
                .get(&current)
                .map(|n| n.iter().collect::<Vec<_>>())
                .unwrap_or_default();
            
            // Filter out visited nodes and nodes without capacity
            let valid_neighbors: Vec<_> = neighbors
                .into_iter()
                .filter(|(node_id, channel_id)| {
                    if visited.contains(node_id) {
                        return false;
                    }
                    if let Some(channel) = graph.channels.get(channel_id) {
                        let capacity = if &channel.node_a == *node_id {
                            channel.capacity_a_to_b
                        } else {
                            channel.capacity_b_to_a
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
            let (next_node, channel_id) = valid_neighbors
                .choose(&mut rand::thread_rng())
                .unwrap();
            
            let channel = graph.channels.get(channel_id).unwrap();
            let fee = self.calculate_fee(channel, amount);
            
            path.push(RouteHop::new(
                (*channel_id).clone(),
                (*next_node).clone(),
                amount,
                fee,
                channel.cltv_delta,
            ));
            
            current = (*next_node).clone();
            visited.insert(current.clone());
        }
        
        if current != request.destination {
            return Err(RoutingError::NoPathFound {
                source: request.source,
                destination: request.destination,
            });
        }
        
        self.build_route(path, request.amount)
    }
    
    fn calculate_fee(&self, channel: &crate::Channel, amount: i128) -> i128 {
        let proportional_fee = (amount as u128 * channel.fee_rate as u128 / 1_000_000) as i128;
        let time_lock_fee = (channel.cltv_delta as i128 * 10) / 1440;
        channel.base_fee + proportional_fee + time_lock_fee
    }
    
    fn calculate_amount_at_node(&self, path: &[RouteHop], initial_amount: i128) -> i128 {
        // Amount grows as we pay fees along the path
        let mut amount = initial_amount;
        for hop in path {
            amount += hop.fee;
        }
        amount
    }
    
    fn get_amount_for_node(
        &self,
        _node: &str,
        came_from: &FxHashMap<String, (String, RouteHop)>,
        initial_amount: i128,
    ) -> i128 {
        let mut amount = initial_amount;
        let mut current = _node.to_string();
        
        while let Some((_, hop)) = came_from.get(&current) {
            amount += hop.fee;
            current = current.clone();
        }
        
        amount
    }
    
    fn build_route(&self, path: Vec<RouteHop>, amount: i128) -> Result<Route, RoutingError> {
        if path.is_empty() {
            return Err(RoutingError::NoPathFound {
                source: "unknown".to_string(),
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
                source: source.to_string(),
                destination: destination.to_string(),
            });
        }
        
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

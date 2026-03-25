//! # Channel Router
//! 
//! Multi-hop payment routing for Stellar payment channels.
//! Implements path-finding algorithms for routing payments through
//! the payment channel network.

pub mod graph;
pub mod pathfinder;
pub mod policy;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use fxhash::FxHashMap;
use priority_queue::PriorityQueue;
use std::cmp::Reverse;

/// Maximum number of hops allowed in a route
pub const MAX_ROUTE_HOPS: usize = 20;

/// Maximum amount we'll attempt to route (to prevent overflow)
pub const MAX_ROUTE_AMOUNT: i128 = i128::MAX / 2;

/// Errors that can occur during routing
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RoutingError {
    #[error("No path found from {source} to {destination}")]
    NoPathFound { source: String, destination: String },
    
    #[error("Source node {node} has no channels")]
    NoChannelsForNode { node: String },
    
    #[error("Insufficient capacity: needed {needed}, available {available} on channel {channel_id}")]
    InsufficientCapacity { needed: i128, available: i128, channel_id: String },
    
    #[error("Amount below dust limit: {amount} < {dust_limit}")]
    BelowDustLimit { amount: i128, dust_limit: i128 },
    
    #[error("Amount exceeds maximum: {amount} > {max_amount}")]
    AmountExceedsMaximum { amount: i128, max_amount: i128 },
    
    #[error("Path too long: {length} hops, maximum is {max}")]
    PathTooLong { length: usize, max: usize },
    
    #[error("Fee exceeds budget: {fee} > {budget}")]
    FeeExceedsBudget { fee: i128, budget: i128 },
    
    #[error("Node not found: {node}")]
    NodeNotFound { node: String },
    
    #[error("Channel not found: {channel_id}")]
    ChannelNotFound { channel_id: String },
    
    #[error("Invalid node address")]
    InvalidNodeAddress,
}

/// Represents a node in the payment channel network
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Node {
    /// Unique identifier for the node
    pub id: String,
    /// Public key / address
    pub public_key: Vec<u8>,
    /// Node alias (optional)
    pub alias: Option<String>,
    /// Whether this node is online
    pub online: bool,
    /// Last time this node was seen
    pub last_seen: u64,
    /// Feature flags
    pub features: NodeFeatures,
}

/// Node feature flags
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeFeatures {
    /// Supports variable size HTLCs
    pub variable_size_htlcs: bool,
    /// Supports payment secrets
    pub payment_secrets: bool,
    /// Supports multi-path payments
    pub multi_path_payments: bool,
    /// Supports trampoline routing
    pub trampoline_routing: bool,
}

/// Represents a payment channel between two nodes
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Channel {
    /// Unique identifier for this channel
    pub id: String,
    /// First node's ID
    pub node_a: String,
    /// Second node's ID
    pub node_b: String,
    /// Available capacity from A to B
    pub capacity_a_to_b: i128,
    /// Available capacity from B to A
    pub capacity_b_to_a: i128,
    /// Base fee for routing through this channel
    pub base_fee: i128,
    /// Fee rate (ppm - parts per million)
    pub fee_rate: u32,
    /// CLTV delta (time-lock delta)
    pub cltv_delta: u32,
    /// Minimum HTLC size
    pub min_htlc_size: i128,
    /// Maximum HTLC size
    pub max_htlc_size: i128,
    /// HTLCs currently in flight
    pub htlcs_in_flight: u32,
    /// Whether the channel is enabled
    pub enabled: bool,
    /// Channel age in seconds
    pub age_seconds: u64,
}

/// Direction for capacity checks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// From node A to node B
    AToB,
    /// From node B to node A
    BToA,
}

/// Represents a route through the network
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// The hops in this route
    pub hops: Vec<RouteHop>,
    /// Total fees for this route
    pub total_fees: i128,
    /// Total amount being routed
    pub total_amount: i128,
    /// Probability of success (estimated)
    pub success_probability: f64,
    /// Route metadata
    pub metadata: RouteMetadata,
}

/// A single hop in a route
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteHop {
    /// Channel ID for this hop
    pub channel_id: String,
    /// Node ID we're routing through
    pub node_id: String,
    /// Amount being forwarded
    pub amount: i128,
    /// Fee for this hop
    pub fee: i128,
    /// CLTV delta for this hop
    pub cltv_delta: u32,
    /// The preimage hash for HTLC
    pub hashlock: Option<Vec<u8>>,
    /// Expiry height for this hop
    pub expiry_height: u32,
}

impl RouteHop {
    /// Create a new route hop
    pub fn new(
        channel_id: String,
        node_id: String,
        amount: i128,
        fee: i128,
        cltv_delta: u32,
    ) -> Self {
        RouteHop {
            channel_id,
            node_id,
            amount,
            fee,
            cltv_delta,
            hashlock: None,
            expiry_height: 0,
        }
    }
    
    /// Calculate the total amount for this hop (forward + fee)
    pub fn total_amount(&self) -> i128 {
        self.amount + self.fee
    }
}

/// Additional metadata for a route
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteMetadata {
    /// Route creation time
    pub created_at: u64,
    /// Number of nodes in the route
    pub num_nodes: usize,
    /// Estimated time to complete
    pub estimated_time_ms: u64,
    /// Whether this is a direct route
    pub is_direct: bool,
}

/// Route request parameters
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRequest {
    /// Source node ID
    pub source: String,
    /// Destination node ID
    pub destination: String,
    /// Amount to route
    pub amount: i128,
    /// Maximum fee budget (optional)
    pub max_fee_budget: Option<i128>,
    /// Maximum hops (optional)
    pub max_hops: Option<usize>,
    /// Whether to find any route (not necessarily optimal)
    pub find_any: bool,
    /// Payment metadata
    pub payment_metadata: Option<PaymentMetadata>,
}

/// Payment metadata for routing decisions
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentMetadata {
    /// Payment type
    pub payment_type: PaymentType,
    /// Required CLTV delta
    pub required_cltv_delta: Option<u32>,
    /// Payment expiry
    pub payment_expiry: Option<u32>,
}

/// Type of payment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PaymentType {
    /// Regular payment
    #[default]
    Regular,
    /// Keysend (spontaneous payment)
    Keysend,
    /// Multi-path payment
    MultiPath,
    /// Trampoline payment
    Trampoline,
}

/// The network graph representing all channels and nodes
pub struct NetworkGraph {
    /// Map of node ID to Node
    nodes: FxHashMap<String, Node>,
    /// Map of channel ID to Channel
    channels: FxHashMap<String, Channel>,
    /// Map of node ID to set of channel IDs they're in
    node_channels: FxHashMap<String, HashSet<String>>,
    /// Adjacency list: node ID -> (neighbor ID -> channel ID)
    adjacency: FxHashMap<String, FxHashMap<String, String>>,
    /// Graph version for invalidation
    version: u64,
}

impl NetworkGraph {
    /// Create a new empty network graph
    pub fn new() -> Self {
        NetworkGraph {
            nodes: FxHashMap::default(),
            channels: FxHashMap::default(),
            node_channels: FxHashMap::default(),
            adjacency: FxHashMap::default(),
            version: 0,
        }
    }
    
    /// Add a node to the graph
    pub fn add_node(&mut self, node: Node) {
        self.nodes.insert(node.id.clone(), node);
        self.node_channels.entry(node.id.clone()).or_insert_with(HashSet::new);
        self.adjacency.entry(node.id.clone()).or_insert_with(FxHashMap::default);
    }
    
    /// Add a channel to the graph
    pub fn add_channel(&mut self, channel: Channel) {
        // Add to channels map
        self.channels.insert(channel.id.clone(), channel.clone());
        
        // Update node_channels
        self.node_channels
            .entry(channel.node_a.clone())
            .or_insert_with(HashSet::new)
            .insert(channel.id.clone());
        self.node_channels
            .entry(channel.node_b.clone())
            .or_insert_with(HashSet::new)
            .insert(channel.id.clone());
        
        // Update adjacency
        self.adjacency
            .entry(channel.node_a.clone())
            .or_insert_with(FxHashMap::default)
            .insert(channel.node_b.clone(), channel.id.clone());
        self.adjacency
            .entry(channel.node_b.clone())
            .or_insert_with(FxHashMap::default)
            .insert(channel.node_a.clone(), channel.id.clone());
        
        self.version += 1;
    }
    
    /// Remove a channel from the graph
    pub fn remove_channel(&mut self, channel_id: &str) {
        if let Some(channel) = self.channels.remove(channel_id) {
            // Remove from node_channels
            if let Some(channels) = self.node_channels.get_mut(&channel.node_a) {
                channels.remove(channel_id);
            }
            if let Some(channels) = self.node_channels.get_mut(&channel.node_b) {
                channels.remove(channel_id);
            }
            
            // Remove from adjacency
            if let Some(neighbors) = self.adjacency.get_mut(&channel.node_a) {
                neighbors.remove(&channel.node_b);
            }
            if let Some(neighbors) = self.adjacency.get_mut(&channel.node_b) {
                neighbors.remove(&channel.node_a);
            }
            
            self.version += 1;
        }
    }
    
    /// Update channel capacity
    pub fn update_capacity(&mut self, channel_id: &str, direction: Direction, new_capacity: i128) {
        if let Some(channel) = self.channels.get_mut(channel_id) {
            match direction {
                Direction::AToB => channel.capacity_a_to_b = new_capacity,
                Direction::BToA => channel.capacity_b_to_a = new_capacity,
            }
        }
    }
    
    /// Get a node by ID
    pub fn get_node(&self, node_id: &str) -> Option<&Node> {
        self.nodes.get(node_id)
    }
    
    /// Get a channel by ID
    pub fn get_channel(&self, channel_id: &str) -> Option<&Channel> {
        self.channels.get(channel_id)
    }
    
    /// Get channels for a node
    pub fn get_node_channels(&self, node_id: &str) -> Vec<&Channel> {
        self.node_channels
            .get(node_id)
            .map(|channel_ids| {
                channel_ids
                    .iter()
                    .filter_map(|id| self.channels.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }
    
    /// Get neighbors of a node
    pub fn get_neighbors(&self, node_id: &str) -> Vec<&Node> {
        self.adjacency
            .get(node_id)
            .map(|neighbors| {
                neighbors
                    .keys()
                    .filter_map(|id| self.nodes.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }
    
    /// Check if a node exists
    pub fn has_node(&self, node_id: &str) -> bool {
        self.nodes.contains_key(node_id)
    }
    
    /// Check if a channel exists
    pub fn has_channel(&self, channel_id: &str) -> bool {
        self.channels.contains_key(channel_id)
    }
    
    /// Get the number of nodes
    pub fn num_nodes(&self) -> usize {
        self.nodes.len()
    }
    
    /// Get the number of channels
    pub fn num_channels(&self) -> usize {
        self.channels.len()
    }
    
    /// Get graph version (for caching)
    pub fn version(&self) -> u64 {
        self.version
    }
}

impl Default for NetworkGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate the fee for routing through a channel
pub fn calculate_channel_fee(
    amount: i128,
    base_fee: i128,
    fee_rate_ppm: u32,
    cltv_delta: u32,
) -> i128 {
    // Fee = base_fee + (amount * fee_rate_ppm / 1,000,000) + (cltv_delta * time_lock_fee)
    let proportional_fee = (amount as u128 * fee_rate_ppm as u128 / 1_000_000) as i128;
    let time_lock_fee = (cltv_delta as i128 * 10) / 1440; // ~1 XLM per day
    
    base_fee + proportional_fee + time_lock_fee
}

/// Find the best route using Dijkstra's algorithm with fees
pub fn find_best_route(
    graph: &NetworkGraph,
    request: &RouteRequest,
) -> Result<Route, RoutingError> {
    // Validate inputs
    if request.amount <= 0 {
        return Err(RoutingError::BelowDustLimit {
            amount: request.amount,
            dust_limit: 1,
        });
    }
    
    if !graph.has_node(&request.source) {
        return Err(RoutingError::NodeNotFound {
            node: request.source.clone()
        });
    }
    
    if !graph.has_node(&request.destination) {
        return Err(RoutingError::NodeNotFound {
            node: request.destination.clone()
        });
    }
    
    let max_hops = request.max_hops.unwrap_or(MAX_ROUTE_HOPS);
    
    // Dijkstra's algorithm with weighted edges (fees)
    let mut dist: FxHashMap<String, i128> = FxHashMap::default();
    let mut prev: FxHashMap<String, (String, String, i128, i128)> = FxHashMap::default(); // node -> (prev_node, channel_id, amount, fee)
    let mut pq: PriorityQueue<String, Reverse<i128>, fxhash::FxBuildHasher> = PriorityQueue::new();
    
    dist.insert(request.source.clone(), 0);
    pq.push(request.source.clone(), Reverse(0));
    
    while let Some((node_id, Reverse(dist_cost))) = pq.pop() {
        // Found destination
        if node_id == request.destination {
            break;
        }
        
        // Skip if we've found a better path
        if dist_cost > *dist.get(&node_id).unwrap_or(&i128::MAX) {
            continue;
        }
        
        // Get current amount being routed (from fees accumulated)
        let current_amount = if node_id == request.source {
            request.amount
        } else {
            // Calculate the amount at this node based on fees paid so far
            dist_cost
        };
        
        // Check all neighbors
        if let Some(neighbors) = graph.adjacency.get(&node_id) {
            for (neighbor_id, channel_id) in neighbors {
                if let Some(channel) = graph.channels.get(channel_id) {
                    // Determine direction and available capacity
                    let (available_capacity, direction) = if &channel.node_a == neighbor_id {
                        (channel.capacity_a_to_b, Direction::AToB)
                    } else {
                        (channel.capacity_b_to_a, Direction::BToA)
                    };
                    
                    // Skip if channel doesn't have enough capacity
                    let amount_at_next_hop = current_amount;
                    if available_capacity < amount_at_next_hop {
                        continue;
                    }
                    
                    // Calculate fee for this hop
                    let fee = calculate_channel_fee(
                        amount_at_next_hop,
                        channel.base_fee,
                        channel.fee_rate,
                        channel.cltv_delta,
                    );
                    
                    let next_dist = dist_cost + fee;
                    
                    // Check if this is a better path
                    if next_dist < *dist.get(neighbor_id).unwrap_or(&i128::MAX) {
                        dist.insert(neighbor_id.clone(), next_dist);
                        prev.insert(neighbor_id.clone(), (node_id.clone(), channel_id.clone(), current_amount, fee));
                        pq.push(neighbor_id.clone(), Reverse(next_dist));
                    }
                }
            }
        }
    }
    
    // Reconstruct route
    if !prev.contains_key(&request.destination) {
        return Err(RoutingError::NoPathFound {
            source: request.source,
            destination: request.destination,
        });
    }
    
    let mut hops = Vec::new();
    let mut current = request.destination.clone();
    let mut total_fees = 0i128;
    
    while let Some((prev_node, channel_id, amount, fee)) = prev.get(&current) {
        if let Some(channel) = graph.channels.get(channel_id) {
            let node_id = if &channel.node_a == prev_node {
                channel.node_b.clone()
            } else {
                channel.node_a.clone()
            };
            
            hops.push(RouteHop::new(
                channel_id.clone(),
                node_id,
                amount,
                fee,
                channel.cltv_delta,
            ));
            total_fees += fee;
        }
        
        if current == request.source {
            break;
        }
        current = prev_node.clone();
    }
    
    hops.reverse();
    
    // Check path length
    if hops.len() > max_hops {
        return Err(RoutingError::PathTooLong {
            length: hops.len(),
            max: max_hops,
        });
    }
    
    // Check fee budget
    if let Some(max_fee) = request.max_fee_budget {
        if total_fees > max_fee {
            return Err(RoutingError::FeeExceedsBudget {
                fee: total_fees,
                budget: max_fee,
            });
        }
    }
    
    Ok(Route {
        hops,
        total_fees,
        total_amount: request.amount,
        success_probability: 0.95, // Placeholder
        metadata: RouteMetadata {
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            num_nodes: hops.len(),
            estimated_time_ms: 100,
            is_direct: hops.len() == 1,
        },
    })
}

/// Find multiple routes using k-shortest paths
pub fn find_k_routes(
    graph: &NetworkGraph,
    request: &RouteRequest,
    k: usize,
) -> Result<Vec<Route>, RoutingError> {
    let mut routes = Vec::new();
    
    // For simplicity, we find k routes by slightly modifying the request
    // In production, you'd use Yen's k-shortest paths algorithm
    for i in 0..k {
        let mut modified_request = request.clone();
        // Add small random variation to fee rates
        if i > 0 {
            modified_request.max_hops = Some(request.max_hops.unwrap_or(MAX_ROUTE_HOPS) + i);
        }
        
        if let Ok(route) = find_best_route(graph, &modified_request) {
            // Avoid duplicates
            if !routes.iter().any(|r: &Route| r.hops == route.hops) {
                routes.push(route);
            }
        }
    }
    
    Ok(routes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_graph() {
        let mut graph = NetworkGraph::new();
        
        // Add nodes
        graph.add_node(Node {
            id: "alice".to_string(),
            public_key: vec![1, 2, 3],
            alias: Some("Alice's Node".to_string()),
            online: true,
            last_seen: 1000,
            features: NodeFeatures::default(),
        });
        
        graph.add_node(Node {
            id: "bob".to_string(),
            public_key: vec![4, 5, 6],
            alias: Some("Bob's Node".to_string()),
            online: true,
            last_seen: 1000,
            features: NodeFeatures::default(),
        });
        
        // Add channel
        graph.add_channel(Channel {
            id: "ch1".to_string(),
            node_a: "alice".to_string(),
            node_b: "bob".to_string(),
            capacity_a_to_b: 1000,
            capacity_b_to_a: 1000,
            base_fee: 1,
            fee_rate: 1000,
            cltv_delta: 40,
            min_htlc_size: 1,
            max_htlc_size: 1000,
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 3600,
        });
        
        assert_eq!(graph.num_nodes(), 2);
        assert_eq!(graph.num_channels(), 1);
        assert!(graph.has_node("alice"));
        assert!(graph.has_node("bob"));
    }
    
    #[test]
    fn test_route_finding() {
        let mut graph = NetworkGraph::new();
        
        // Create a simple network: alice -> bob -> carol
        for (id, pk) in [("alice", 1), ("bob", 2), ("carol", 3)] {
            graph.add_node(Node {
                id: id.to_string(),
                public_key: vec![pk],
                alias: None,
                online: true,
                last_seen: 1000,
                features: NodeFeatures::default(),
            });
        }
        
        graph.add_channel(Channel {
            id: "ch1".to_string(),
            node_a: "alice".to_string(),
            node_b: "bob".to_string(),
            capacity_a_to_b: 1000,
            capacity_b_to_a: 1000,
            base_fee: 1,
            fee_rate: 1000,
            cltv_delta: 40,
            min_htlc_size: 1,
            max_htlc_size: 1000,
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 3600,
        });
        
        graph.add_channel(Channel {
            id: "ch2".to_string(),
            node_a: "bob".to_string(),
            node_b: "carol".to_string(),
            capacity_a_to_b: 1000,
            capacity_b_to_a: 1000,
            base_fee: 1,
            fee_rate: 1000,
            cltv_delta: 40,
            min_htlc_size: 1,
            max_htlc_size: 1000,
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 3600,
        });
        
        let request = RouteRequest {
            source: "alice".to_string(),
            destination: "carol".to_string(),
            amount: 100,
            max_fee_budget: Some(10),
            max_hops: Some(3),
            find_any: false,
            payment_metadata: None,
        };
        
        let route = find_best_route(&graph, &request).unwrap();
        assert_eq!(route.hops.len(), 2);
        assert_eq!(route.total_amount, 100);
    }
}

//! # Graph Module
//! 
//! Graph data structures and utilities for the payment channel network.

use crate::{NetworkGraph, Node, Channel, Direction, RouteHop, RoutingError};
use fxhash::FxHashMap;
use std::collections::{HashMap, HashSet};

/// A view of the network graph optimized for pathfinding
pub struct GraphView<'a> {
    /// Reference to the underlying graph
    graph: &'a NetworkGraph,
    /// Cached adjacency list for faster lookups
    adjacency_cache: FxHashMap<String, Vec<GraphEdge>>,
    /// Version of the graph when this view was created
    version: u64,
}

/// An edge in the graph view (with direction information)
#[derive(Debug, Clone)]
pub struct GraphEdge {
    /// Target node ID
    pub target: String,
    /// Channel ID
    pub channel_id: String,
    /// Direction from source to target
    pub direction: Direction,
    /// Capacity in this direction
    pub capacity: i128,
    /// Fee for this direction
    pub fee: i128,
    /// CLTV delta
    pub cltv_delta: u32,
}

impl<'a> GraphView<'a> {
    /// Create a new graph view from a network graph
    pub fn new(graph: &'a NetworkGraph) -> Self {
        let mut view = GraphView {
            graph,
            adjacency_cache: FxHashMap::default(),
            version: graph.version(),
        };
        view.build_cache();
        view
    }
    
    /// Build the adjacency cache
    fn build_cache(&mut self) {
        self.adjacency_cache.clear();
        
        for (node_id, neighbors) in &self.graph.adjacency {
            let mut edges = Vec::new();
            
            for (neighbor_id, channel_id) in neighbors {
                if let Some(channel) = self.graph.channels.get(channel_id) {
                    // Add edge from node_id to neighbor
                    let (capacity, fee, cltv) = if &channel.node_a == node_id {
                        (channel.capacity_a_to_b, channel.base_fee, channel.cltv_delta)
                    } else {
                        (channel.capacity_b_to_a, channel.base_fee, channel.cltv_delta)
                    };
                    
                    edges.push(GraphEdge {
                        target: neighbor_id.clone(),
                        channel_id: channel_id.clone(),
                        direction: Direction::AToB, // Relative to the source
                        capacity,
                        fee,
                        cltv_delta: cltv,
                    });
                }
            }
            
            self.adjacency_cache.insert(node_id.clone(), edges);
        }
    }
    
    /// Get edges from a node
    pub fn get_edges(&self, node_id: &str) -> &[GraphEdge] {
        self.adjacency_cache.get(node_id).map(|v| v.as_slice()).unwrap_or(&[])
    }
    
    /// Check if the view is still valid
    pub fn is_valid(&self) -> bool {
        self.version == self.graph.version()
    }
    
    /// Refresh the view if stale
    pub fn refresh(&mut self) {
        if !self.is_valid() {
            self.build_cache();
            self.version = self.graph.version();
        }
    }
    
    /// Get nodes reachable within a certain number of hops
    pub fn get_reachable_nodes(&self, source: &str, max_hops: usize) -> HashSet<String> {
        let mut reachable = HashSet::new();
        let mut frontier = vec![(source.to_string(), 0)];
        let mut visited = HashSet::new();
        visited.insert(source.to_string());
        
        while let Some((node, depth)) = frontier.pop() {
            if depth >= max_hops {
                continue;
            }
            
            for edge in self.get_edges(&node) {
                if !visited.contains(&edge.target) {
                    reachable.insert(edge.target.clone());
                    visited.insert(edge.target.clone());
                    frontier.push((edge.target.clone(), depth + 1));
                }
            }
        }
        
        reachable
    }
    
    /// Find all paths from source to destination up to max_length
    pub fn find_all_paths(
        &self,
        source: &str,
        destination: &str,
        max_length: usize,
        max_amount: i128,
    ) -> Vec<Vec<GraphEdge>> {
        let mut all_paths = Vec::new();
        let mut current_path = Vec::new();
        let mut visited = HashSet::new();
        
        self.dfs_paths(source, destination, max_length, max_amount, &mut current_path, &mut visited, &mut all_paths);
        
        all_paths
    }
    
    fn dfs_paths(
        &self,
        current: &str,
        destination: &str,
        remaining_hops: usize,
        remaining_amount: i128,
        current_path: &mut Vec<GraphEdge>,
        visited: &mut HashSet<String>,
        all_paths: &mut Vec<Vec<GraphEdge>>,
    ) {
        if remaining_hops == 0 || remaining_amount <= 0 {
            return;
        }
        
        if current == destination {
            all_paths.push(current_path.clone());
            return;
        }
        
        for edge in self.get_edges(current) {
            if visited.contains(&edge.target) || edge.capacity < remaining_amount {
                continue;
            }
            
            visited.insert(edge.target.clone());
            current_path.push(edge.clone());
            
            self.dfs_paths(
                &edge.target,
                destination,
                remaining_hops - 1,
                remaining_amount - edge.fee,
                current_path,
                visited,
                all_paths,
            );
            
            current_path.pop();
            visited.remove(&edge.target);
        }
    }
    
    /// Get the minimum capacity along a path
    pub fn get_path_min_capacity(path: &[RouteHop], graph: &NetworkGraph) -> i128 {
        let mut min_capacity = i128::MAX;
        
        for hop in path {
            if let Some(channel) = graph.channels.get(&hop.channel_id) {
                let capacity = channel.capacity_a_to_b.min(channel.capacity_b_to_a);
                min_capacity = min_capacity.min(capacity);
            }
        }
        
        min_capacity
    }
    
    /// Calculate total fee for a path
    pub fn get_path_total_fee(path: &[RouteHop]) -> i128 {
        path.iter().map(|h| h.fee).sum()
    }
}

/// Network topology analyzer
pub struct TopologyAnalyzer;

impl TopologyAnalyzer {
    /// Calculate the diameter of the network (longest shortest path)
    pub fn calculate_diameter(graph: &NetworkGraph) -> Option<usize> {
        let nodes: Vec<String> = graph.nodes.keys().cloned().collect();
        if nodes.is_empty() {
            return None;
        }
        
        let mut max_distance = 0;
        
        // BFS from each node (inefficient but correct)
        for source in &nodes {
            let distances = Self::bfs_distances(graph, source);
            if let Some(max) = distances.values().max() {
                max_distance = max_distance.max(*max as usize);
            }
        }
        
        Some(max_distance)
    }
    
    /// Calculate the average shortest path length
    pub fn calculate_average_path_length(graph: &NetworkGraph) -> Option<f64> {
        let nodes: Vec<String> = graph.nodes.keys().cloned().collect();
        if nodes.len() < 2 {
            return None;
        }
        
        let mut total_distance = 0i64;
        let mut count = 0i64;
        
        for source in &nodes {
            let distances = Self::bfs_distances(graph, source);
            for dest in &nodes {
                if source != dest {
                    if let Some(d) = distances.get(dest) {
                        total_distance += *d as i64;
                        count += 1;
                    }
                }
            }
        }
        
        if count > 0 {
            Some(total_distance as f64 / count as f64)
        } else {
            None
        }
    }
    
    /// BFS to calculate distances from a source
    fn bfs_distances(graph: &NetworkGraph, source: &str) -> HashMap<String, u32> {
        use std::collections::VecDeque;
        
        let mut distances = HashMap::new();
        let mut queue = VecDeque::new();
        
        distances.insert(source.to_string(), 0);
        queue.push_back(source.to_string());
        
        while let Some(node) = queue.pop_front() {
            let current_dist = *distances.get(&node).unwrap();
            
            if let Some(neighbors) = graph.adjacency.get(&node) {
                for (neighbor, _) in neighbors {
                    if !distances.contains_key(neighbor) {
                        distances.insert(neighbor.clone(), current_dist + 1);
                        queue.push_back(neighbor.clone());
                    }
                }
            }
        }
        
        distances
    }
    
    /// Find articulation points (nodes whose removal disconnects the graph)
    pub fn find_articulation_points(graph: &NetworkGraph) -> HashSet<String> {
        let nodes: Vec<String> = graph.nodes.keys().cloned().collect();
        let mut articulation_points = HashSet::new();
        
        for node in &nodes {
            // Temporarily remove the node
            let mut test_graph = graph.clone();
            test_graph.nodes.remove(node);
            
            // Check if graph is still connected
            if !Self::is_connected(&test_graph) {
                articulation_points.insert(node.clone());
            }
        }
        
        articulation_points
    }
    
    /// Check if the graph is connected
    pub fn is_connected(graph: &NetworkGraph) -> bool {
        if graph.nodes.is_empty() {
            return true;
        }
        
        let first_node = graph.nodes.keys().next().unwrap();
        let visited = Self::bfs_distances(graph, first_node);
        
        visited.len() == graph.nodes.len()
    }
    
    /// Get the degree (number of connections) for each node
    pub fn get_node_degrees(graph: &NetworkGraph) -> HashMap<String, usize> {
        let mut degrees = HashMap::new();
        
        for (node, neighbors) in &graph.adjacency {
            degrees.insert(node.clone(), neighbors.len());
        }
        
        degrees
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NetworkGraph, Node, Channel};

    #[test]
    fn test_graph_view() {
        let mut graph = NetworkGraph::new();
        
        // Add test nodes
        for (id, pk) in [("a", 1u8), ("b", 2), ("c", 3)] {
            graph.add_node(Node {
                id: id.to_string(),
                public_key: vec![pk],
                alias: None,
                online: true,
                last_seen: 0,
                features: crate::NodeFeatures::default(),
            });
        }
        
        // Add channels
        graph.add_channel(Channel {
            id: "ch1".to_string(),
            node_a: "a".to_string(),
            node_b: "b".to_string(),
            capacity_a_to_b: 1000,
            capacity_b_to_a: 1000,
            base_fee: 1,
            fee_rate: 1000,
            cltv_delta: 40,
            min_htlc_size: 1,
            max_htlc_size: 1000,
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 0,
        });
        
        graph.add_channel(Channel {
            id: "ch2".to_string(),
            node_a: "b".to_string(),
            node_b: "c".to_string(),
            capacity_a_to_b: 1000,
            capacity_b_to_a: 1000,
            base_fee: 1,
            fee_rate: 1000,
            cltv_delta: 40,
            min_htlc_size: 1,
            max_htlc_size: 1000,
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 0,
        });
        
        let view = GraphView::new(&graph);
        let edges = view.get_edges("a");
        
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].target, "b");
    }
}

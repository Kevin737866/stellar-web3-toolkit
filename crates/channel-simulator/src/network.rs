//! # Network Module
//! 
//! Network topology generation and management for the simulator.

use crate::{SimulatorConfig, SimulatedNode};
use channel_router::{NetworkGraph, Node, Channel};
use std::collections::{HashMap, HashSet};
use rand::Rng;
use serde::{Deserialize, Serialize};

/// Network topology types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TopologyType {
    /// Random graph topology
    Random,
    /// Scale-free network (preferential attachment)
    ScaleFree,
    /// Small-world network
    SmallWorld,
    /// Grid topology
    Grid,
    /// Star topology (hub and spokes)
    Star,
    /// Line topology
    Line,
    /// Ring topology
    Ring,
}

/// Network topology generator
pub struct NetworkTopology {
    /// Configuration
    config: SimulatorConfig,
    /// Topology type
    topology_type: TopologyType,
}

impl NetworkTopology {
    /// Create a new network topology generator
    pub fn new(config: SimulatorConfig, topology_type: TopologyType) -> Self {
        NetworkTopology {
            config,
            topology_type,
        }
    }
    
    /// Generate a network with the specified topology
    pub fn generate<R: Rng>(&self, rng: &mut R) -> (NetworkGraph, HashMap<String, SimulatedNode>) {
        match self.topology_type {
            TopologyType::Random => self.generate_random(rng),
            TopologyType::ScaleFree => self.generate_scale_free(rng),
            TopologyType::SmallWorld => self.generate_small_world(rng),
            TopologyType::Grid => self.generate_grid(rng),
            TopologyType::Star => self.generate_star(rng),
            TopologyType::Line => self.generate_line(rng),
            TopologyType::Ring => self.generate_ring(rng),
        }
    }
    
    /// Generate a random topology
    fn generate_random<R: Rng>(&self, rng: &mut R) -> (NetworkGraph, HashMap<String, SimulatedNode>) {
        let mut graph = NetworkGraph::new();
        let mut nodes = HashMap::new();
        let mut node_ids = Vec::new();
        
        // Create nodes
        for i in 0..self.config.num_nodes {
            let node_id = format!("node_{:03}", i);
            let node = Node {
                id: node_id.clone(),
                public_key: Self::random_bytes(32, rng),
                alias: Some(format!("Node {}", i)),
                online: true,
                last_seen: 0,
                features: channel_router::NodeFeatures::default(),
            };
            
            graph.add_node(node.clone());
            nodes.insert(node_id.clone(), SimulatedNode {
                node,
                balance: 0,
                channels: HashSet::new(),
            });
            node_ids.push(node_id);
        }
        
        // Create random edges
        let target_edges = (self.config.num_nodes as f64 * self.config.avg_channels_per_node / 2.0) as usize;
        let mut edges_created = 0;
        
        while edges_created < target_edges {
            let a = rng.gen_range(0..node_ids.len());
            let b = rng.gen_range(0..node_ids.len());
            
            if a == b {
                continue;
            }
            
            let node_a = &node_ids[a];
            let node_b = &node_ids[b];
            
            // Check if edge exists
            if nodes.get(node_a).map(|n| n.channels.contains(node_b)).unwrap_or(false) {
                continue;
            }
            
            // Create channel
            let capacity = self.random_capacity(rng);
            let balance = (capacity as f64 * self.config.avg_balance_percent) as i128;
            
            let channel = self.create_channel(
                format!("ch_{:06}", edges_created),
                node_a.clone(),
                node_b.clone(),
                balance,
                capacity - balance,
            );
            
            graph.add_channel(channel.clone());
            
            nodes.get_mut(node_a).unwrap().channels.insert(node_b.clone());
            nodes.get_mut(node_b).unwrap().channels.insert(node_a.clone());
            
            edges_created += 1;
        }
        
        (graph, nodes)
    }
    
    /// Generate a scale-free network (Barabási-Albert model)
    fn generate_scale_free<R: Rng>(&self, rng: &mut R) -> (NetworkGraph, HashMap<String, SimulatedNode>) {
        let mut graph = NetworkGraph::new();
        let mut nodes = HashMap::new();
        let node_ids: Vec<String> = (0..self.config.num_nodes)
            .map(|i| {
                let id = format!("node_{:03}", i);
                let node = Node {
                    id: id.clone(),
                    public_key: Self::random_bytes(32, rng),
                    alias: Some(format!("Node {}", i)),
                    online: true,
                    last_seen: 0,
                    features: channel_router::NodeFeatures::default(),
                };
                graph.add_node(node.clone());
                nodes.insert(id.clone(), SimulatedNode {
                    node,
                    balance: 0,
                    channels: HashSet::new(),
                });
                id
            })
            .collect();
        
        // Start with a small complete graph
        let m0 = 3.min(self.config.num_nodes);
        for i in 0..m0 {
            for j in (i + 1)..m0 {
                self.add_edge(&node_ids[i], &node_ids[j], &mut graph, &mut nodes, rng);
            }
        }
        
        // Add remaining nodes with preferential attachment
        let m = 2.min(self.config.avg_channels_per_node as usize / 2);
        for i in m0..self.config.num_nodes {
            let mut targets = HashSet::new();
            
            while targets.len() < m {
                // Select target with probability proportional to degree
                let total_degree: usize = nodes.values()
                    .map(|n| n.channels.len())
                    .sum();
                
                if total_degree == 0 {
                    // Fallback to random
                    let j = rng.gen_range(0..i);
                    targets.insert(j);
                } else {
                    let mut r = rng.gen_range(0..total_degree);
                    for (j, node) in nodes.iter().take(i) {
                        r -= node.channels.len();
                        if r < 0 {
                            targets.insert(j.clone());
                            break;
                        }
                    }
                }
            }
            
            for target in targets {
                self.add_edge(&node_ids[i], &target, &mut graph, &mut nodes, rng);
            }
        }
        
        (graph, nodes)
    }
    
    /// Generate a small-world network (Watts-Strogatz model)
    fn generate_small_world<R: Rng>(&self, rng: &mut R) -> (NetworkGraph, HashMap<String, SimulatedNode>) {
        let mut graph = NetworkGraph::new();
        let mut nodes = HashMap::new();
        let node_ids: Vec<String> = (0..self.config.num_nodes)
            .map(|i| {
                let id = format!("node_{:03}", i);
                let node = Node {
                    id: id.clone(),
                    public_key: Self::random_bytes(32, rng),
                    alias: Some(format!("Node {}", i)),
                    online: true,
                    last_seen: 0,
                    features: channel_router::NodeFeatures::default(),
                };
                graph.add_node(node.clone());
                nodes.insert(id.clone(), SimulatedNode {
                    node,
                    balance: 0,
                    channels: HashSet::new(),
                });
                id
            })
            .collect();
        
        // Create ring lattice
        let k = (2.0 * self.config.avg_channels_per_node).ceil() as usize;
        for i in 0..self.config.num_nodes {
            for j in 1..=k / 2 {
                let target = (i + j) % self.config.num_nodes;
                self.add_edge(&node_ids[i], &node_ids[target], &mut graph, &mut nodes, rng);
            }
        }
        
        // Rewire edges with probability
        let p = 0.1; // Rewiring probability
        let edges: Vec<(String, String)> = nodes.values()
            .flat_map(|n| n.channels.iter().map(|c| (n.node.id.clone(), c.clone())))
            .collect();
        
        for (source, target) in edges {
            if rng.gen::<f64>() < p {
                // Remove edge
                nodes.get_mut(&source).unwrap().channels.remove(&target);
                nodes.get_mut(&target).unwrap().channels.remove(&source);
                graph.remove_channel(&format!("{}_{}", source, target));
                
                // Add random new edge
                let new_target = node_ids[rng.gen_range(0..self.config.num_nodes)].clone();
                if new_target != source && !nodes.get(&source).unwrap().channels.contains(&new_target) {
                    self.add_edge(&source, &new_target, &mut graph, &mut nodes, rng);
                }
            }
        }
        
        (graph, nodes)
    }
    
    /// Generate a grid topology
    fn generate_grid<R: Rng>(&self, rng: &mut R) -> (NetworkGraph, HashMap<String, SimulatedNode>) {
        let mut graph = NetworkGraph::new();
        let mut nodes = HashMap::new();
        
        let size = (self.config.num_nodes as f64).sqrt().ceil() as usize;
        let mut node_ids = Vec::new();
        
        // Create nodes in a grid
        for i in 0..self.config.num_nodes {
            let node_id = format!("node_{:03}", i);
            let node = Node {
                id: node_id.clone(),
                public_key: Self::random_bytes(32, rng),
                alias: Some(format!("Node ({}, {})", i / size, i % size)),
                online: true,
                last_seen: 0,
                features: channel_router::NodeFeatures::default(),
            };
            
            graph.add_node(node.clone());
            nodes.insert(node_id.clone(), SimulatedNode {
                node,
                balance: 0,
                channels: HashSet::new(),
            });
            node_ids.push(node_id);
        }
        
        // Connect to neighbors
        for i in 0..self.config.num_nodes {
            let row = i / size;
            let col = i % size;
            
            // Right neighbor
            if col + 1 < size {
                self.add_edge(&node_ids[i], &node_ids[i + 1], &mut graph, &mut nodes, rng);
            }
            
            // Bottom neighbor
            if row + 1 < size {
                self.add_edge(&node_ids[i], &node_ids[i + size], &mut graph, &mut nodes, rng);
            }
        }
        
        (graph, nodes)
    }
    
    /// Generate a star topology
    fn generate_star<R: Rng>(&self, rng: &mut R) -> (NetworkGraph, HashMap<String, SimulatedNode>) {
        let mut graph = NetworkGraph::new();
        let mut nodes = HashMap::new();
        
        // Create hub node
        let hub_id = "node_000".to_string();
        let hub = Node {
            id: hub_id.clone(),
            public_key: Self::random_bytes(32, rng),
            alias: Some("Hub".to_string()),
            online: true,
            last_seen: 0,
            features: channel_router::NodeFeatures::default(),
        };
        graph.add_node(hub.clone());
        nodes.insert(hub_id.clone(), SimulatedNode {
            node: hub,
            balance: 0,
            channels: HashSet::new(),
        });
        
        // Create spoke nodes
        for i in 1..self.config.num_nodes {
            let node_id = format!("node_{:03}", i);
            let node = Node {
                id: node_id.clone(),
                public_key: Self::random_bytes(32, rng),
                alias: Some(format!("Spoke {}", i)),
                online: true,
                last_seen: 0,
                features: channel_router::NodeFeatures::default(),
            };
            
            graph.add_node(node.clone());
            nodes.insert(node_id.clone(), SimulatedNode {
                node,
                balance: 0,
                channels: HashSet::new(),
            });
            
            // Connect to hub
            self.add_edge(&hub_id, &node_id, &mut graph, &mut nodes, rng);
        }
        
        (graph, nodes)
    }
    
    /// Generate a line topology
    fn generate_line<R: Rng>(&self, rng: &mut R) -> (NetworkGraph, HashMap<String, SimulatedNode>) {
        let mut graph = NetworkGraph::new();
        let mut nodes = HashMap::new();
        
        for i in 0..self.config.num_nodes {
            let node_id = format!("node_{:03}", i);
            let node = Node {
                id: node_id.clone(),
                public_key: Self::random_bytes(32, rng),
                alias: Some(format!("Node {}", i)),
                online: true,
                last_seen: 0,
                features: channel_router::NodeFeatures::default(),
            };
            
            graph.add_node(node.clone());
            nodes.insert(node_id.clone(), SimulatedNode {
                node,
                balance: 0,
                channels: HashSet::new(),
            });
            
            // Connect to previous node
            if i > 0 {
                self.add_edge(
                    &format!("node_{:03}", i - 1),
                    &node_id,
                    &mut graph,
                    &mut nodes,
                    rng,
                );
            }
        }
        
        (graph, nodes)
    }
    
    /// Generate a ring topology
    fn generate_ring<R: Rng>(&self, rng: &mut R) -> (NetworkGraph, HashMap<String, SimulatedNode>) {
        let mut graph = NetworkGraph::new();
        let mut nodes = HashMap::new();
        
        for i in 0..self.config.num_nodes {
            let node_id = format!("node_{:03}", i);
            let node = Node {
                id: node_id.clone(),
                public_key: Self::random_bytes(32, rng),
                alias: Some(format!("Node {}", i)),
                online: true,
                last_seen: 0,
                features: channel_router::NodeFeatures::default(),
            };
            
            graph.add_node(node.clone());
            nodes.insert(node_id.clone(), SimulatedNode {
                node,
                balance: 0,
                channels: HashSet::new(),
            });
        }
        
        // Connect in a ring
        for i in 0..self.config.num_nodes {
            let next = (i + 1) % self.config.num_nodes;
            self.add_edge(
                &format!("node_{:03}", i),
                &format!("node_{:03}", next),
                &mut graph,
                &mut nodes,
                rng,
            );
        }
        
        (graph, nodes)
    }
    
    /// Add an edge between two nodes
    fn add_edge<R: Rng>(
        &self,
        node_a: &str,
        node_b: &str,
        graph: &mut NetworkGraph,
        nodes: &mut HashMap<String, SimulatedNode>,
        rng: &mut R,
    ) {
        if node_a == node_b {
            return;
        }
        
        let capacity = self.random_capacity(rng);
        let balance = (capacity as f64 * self.config.avg_balance_percent) as i128;
        
        let channel = self.create_channel(
            format!("ch_{}_{}", node_a, node_b),
            node_a.to_string(),
            node_b.to_string(),
            balance,
            capacity - balance,
        );
        
        graph.add_channel(channel);
        nodes.get_mut(node_a).unwrap().channels.insert(node_b.to_string());
        nodes.get_mut(node_b).unwrap().channels.insert(node_a.to_string());
    }
    
    /// Create a channel with the given parameters
    fn create_channel(
        &self,
        id: String,
        node_a: String,
        node_b: String,
        balance_a: i128,
        balance_b: i128,
    ) -> Channel {
        Channel {
            id,
            node_a,
            node_b,
            capacity_a_to_b: balance_a,
            capacity_b_to_a: balance_b,
            base_fee: self.config.base_fee,
            fee_rate: self.config.fee_rate,
            cltv_delta: self.config.cltv_delta,
            min_htlc_size: 1,
            max_htlc_size: balance_a + balance_b,
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 0,
        }
    }
    
    /// Generate a random capacity
    fn random_capacity<R: Rng>(&self, rng: &mut R) -> i128 {
        rng.gen_range(self.config.min_channel_capacity..self.config.max_channel_capacity)
    }
    
    /// Generate random bytes
    fn random_bytes(len: usize, rng: &mut impl Rng) -> Vec<u8> {
        (0..len).map(|_| rng.gen()).collect()
    }
}

//! # Network Module
//!
//! Network topology generation and management for the simulator.

use crate::{SimulatedNode, SimulatorConfig};
use channel_router::{Channel, NetworkGraph, Node};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Network topology types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    fn generate_random<R: Rng>(
        &self,
        rng: &mut R,
    ) -> (NetworkGraph, HashMap<String, SimulatedNode>) {
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
            nodes.insert(
                node_id.clone(),
                SimulatedNode {
                    node,
                    balance: 0,
                    channels: HashSet::new(),
                },
            );
            node_ids.push(node_id);
        }

        // Create random edges. A random pair can only be drawn once, so the
        // target is capped at the number of distinct pairs and the retry loop
        // is bounded: asking for more edges than the node count allows would
        // otherwise spin forever once the space of pairs is exhausted.
        let max_possible_edges =
            self.config.num_nodes * self.config.num_nodes.saturating_sub(1) / 2;
        let target_edges =
            ((self.config.num_nodes as f64 * self.config.avg_channels_per_node / 2.0) as usize)
                .min(max_possible_edges);
        let max_attempts = target_edges * 20 + 100;
        let mut edges_created = 0;
        let mut attempts = 0;

        while edges_created < target_edges && attempts < max_attempts {
            attempts += 1;

            let a = rng.gen_range(0..node_ids.len());
            let b = rng.gen_range(0..node_ids.len());

            if a == b {
                continue;
            }

            let node_a = &node_ids[a];
            let node_b = &node_ids[b];

            // Check whether the two endpoints are already joined. Testing
            // whether *any* node is connected to both of them would reject
            // pairs that are in fact unconnected, and would not stop a
            // duplicate edge from being created.
            if nodes
                .get(node_a)
                .map(|n| n.channels.contains(node_b))
                .unwrap_or(false)
            {
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

            nodes
                .get_mut(node_a)
                .unwrap()
                .channels
                .insert(node_b.clone());
            nodes
                .get_mut(node_b)
                .unwrap()
                .channels
                .insert(node_a.clone());

            edges_created += 1;
        }

        (graph, nodes)
    }

    /// Generate a scale-free network (Barabási-Albert model)
    fn generate_scale_free<R: Rng>(
        &self,
        rng: &mut R,
    ) -> (NetworkGraph, HashMap<String, SimulatedNode>) {
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
                nodes.insert(
                    id.clone(),
                    SimulatedNode {
                        node,
                        balance: 0,
                        channels: HashSet::new(),
                    },
                );
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

        // Add remaining nodes with preferential attachment.
        //
        // Candidates are drawn from `node_ids[..i]` rather than from the node
        // map: `HashMap` iteration order is randomly seeded per process, so
        // drawing from it made the same seed produce a different topology on
        // every run, which is fatal for a fuzzer whose failures have to be
        // replayable.
        let m = 2.min(self.config.avg_channels_per_node as usize / 2);
        for i in m0..self.config.num_nodes {
            let mut targets: Vec<String> = Vec::with_capacity(m);

            while targets.len() < m {
                // Only nodes that have not been picked yet may be drawn, and
                // the draw is weighted by degree. Selecting from all eligible
                // nodes instead can return the same node forever -- a single
                // hub can hold every edge, giving it probability 1 -- so the
                // loop would never collect `m` distinct targets.
                let eligible: Vec<&String> = node_ids[..i]
                    .iter()
                    .filter(|id| !targets.contains(id))
                    .collect();

                if eligible.is_empty() {
                    break;
                }

                let total_degree: usize = eligible.iter().map(|id| nodes[*id].channels.len()).sum();

                let chosen = if total_degree == 0 {
                    // Nothing is connected yet: pick uniformly.
                    eligible[rng.gen_range(0..eligible.len())].clone()
                } else {
                    // Walk the eligible nodes in order and take the one whose
                    // slice contains the draw. The bound must be tested
                    // *before* subtracting: `r` is unsigned, so the previous
                    // `r -= degree; if r < 0` underflowed and its `< 0` test
                    // could never be true, leaving this branch a guaranteed
                    // panic in debug builds and a silently biased choice in
                    // release.
                    let mut r = rng.gen_range(0..total_degree);
                    let mut picked = None;
                    for id in &eligible {
                        let degree = nodes[*id].channels.len();
                        if r < degree {
                            picked = Some((*id).clone());
                            break;
                        }
                        r -= degree;
                    }

                    // Defensive: a zero-degree node cannot absorb the draw, so
                    // fall back rather than spin.
                    picked.unwrap_or_else(|| eligible[rng.gen_range(0..eligible.len())].clone())
                };

                targets.push(chosen);
            }

            for target in targets {
                self.add_edge(&node_ids[i], &target, &mut graph, &mut nodes, rng);
            }
        }

        (graph, nodes)
    }

    /// Generate a small-world network (Watts-Strogatz model)
    fn generate_small_world<R: Rng>(
        &self,
        rng: &mut R,
    ) -> (NetworkGraph, HashMap<String, SimulatedNode>) {
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
                nodes.insert(
                    id.clone(),
                    SimulatedNode {
                        node,
                        balance: 0,
                        channels: HashSet::new(),
                    },
                );
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

        // Rewire edges with probability.
        //
        // Each undirected edge appears twice in the per-node channel sets, so
        // it has to be visited once: iterating every half-edge would remove the
        // same edge twice and pick two unrelated new neighbours for it.
        let p = 0.1; // Rewiring probability
        let mut edges: Vec<(String, String)> = nodes
            .values()
            .flat_map(|n| n.channels.iter().map(|c| (n.node.id.clone(), c.clone())))
            .filter(|(a, b)| a < b)
            .collect();
        edges.sort();

        for (source, target) in edges {
            // A previous rewire may already have removed this edge.
            if !nodes
                .get(&source)
                .map(|n| n.channels.contains(&target))
                .unwrap_or(false)
            {
                continue;
            }

            if rng.gen::<f64>() < p {
                // Remove the edge, taking the channel id from the adjacency
                // list rather than rebuilding it: `add_edge` names channels
                // after the endpoint order it was called with, so a
                // reconstructed id can point at the wrong channel (or at
                // nothing) and leave the edge in the graph.
                let channel_id = graph
                    .adjacency
                    .get(&source)
                    .and_then(|neighbours| neighbours.get(&target))
                    .cloned();

                nodes.get_mut(&source).unwrap().channels.remove(&target);
                nodes.get_mut(&target).unwrap().channels.remove(&source);

                if let Some(channel_id) = channel_id {
                    graph.remove_channel(&channel_id);
                }

                // Add random new edge
                let new_target = node_ids[rng.gen_range(0..self.config.num_nodes)].clone();
                if new_target != source
                    && !nodes.get(&source).unwrap().channels.contains(&new_target)
                {
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
            nodes.insert(
                node_id.clone(),
                SimulatedNode {
                    node,
                    balance: 0,
                    channels: HashSet::new(),
                },
            );
            node_ids.push(node_id);
        }

        // Connect to neighbors.
        //
        // The grid is row-major with a possibly partial last row, so being in
        // the last column does not imply the node to the right exists: the
        // index still has to be inside `num_nodes`. Testing `col + 1 < size`
        // alone indexes past the end of `node_ids` whenever the last row is
        // short (or whenever there is only one row).
        for i in 0..self.config.num_nodes {
            // Right neighbor
            if i + 1 < self.config.num_nodes && (i % size) + 1 < size {
                self.add_edge(&node_ids[i], &node_ids[i + 1], &mut graph, &mut nodes, rng);
            }

            // Bottom neighbor
            if i + size < self.config.num_nodes {
                self.add_edge(
                    &node_ids[i],
                    &node_ids[i + size],
                    &mut graph,
                    &mut nodes,
                    rng,
                );
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
        nodes.insert(
            hub_id.clone(),
            SimulatedNode {
                node: hub,
                balance: 0,
                channels: HashSet::new(),
            },
        );

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
            nodes.insert(
                node_id.clone(),
                SimulatedNode {
                    node,
                    balance: 0,
                    channels: HashSet::new(),
                },
            );

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
            nodes.insert(
                node_id.clone(),
                SimulatedNode {
                    node,
                    balance: 0,
                    channels: HashSet::new(),
                },
            );

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
            nodes.insert(
                node_id.clone(),
                SimulatedNode {
                    node,
                    balance: 0,
                    channels: HashSet::new(),
                },
            );
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

        // Idempotent: the lattice, ring and grid generators all reach the same
        // pair from both ends, and a second channel between a pair leaves the
        // adjacency map (one entry per neighbour) disagreeing with the channel
        // set about how the network is wired.
        if nodes
            .get(node_a)
            .map(|node| node.channels.contains(node_b))
            .unwrap_or(false)
        {
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
        nodes
            .get_mut(node_a)
            .unwrap()
            .channels
            .insert(node_b.to_string());
        nodes
            .get_mut(node_b)
            .unwrap()
            .channels
            .insert(node_a.to_string());
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


// =========================================================================
// Network Fixtures for Routing Regression Tests (Issue #387)
// =========================================================================

/// Deterministic network fixtures for reproducible routing regression tests
pub struct NetworkFixture;

impl NetworkFixture {
    /// Create a linear chain of nodes: node_0 <-> node_1 <-> ... <-> node_N
    pub fn linear(hops: usize, capacity: i128) -> (NetworkGraph, HashMap<String, SimulatedNode>) {
        assert!(hops >= 1, "hops must be at least 1");
        let num_nodes = hops + 1;
        let mut graph = NetworkGraph::new();
        let mut nodes = HashMap::new();

        for i in 0..num_nodes {
            let id = format!("node_{}", i);
            let node = Node {
                id: id.clone(),
                public_key: vec![i as u8; 32],
                alias: Some(format!("Linear Node {}", i)),
                online: true,
                last_seen: 0,
                features: channel_router::NodeFeatures::default(),
            };
            graph.add_node(node.clone());
            nodes.insert(
                id.clone(),
                SimulatedNode {
                    node,
                    balance: 0,
                    channels: HashSet::new(),
                },
            );
        }

        for i in 0..hops {
            let u = format!("node_{}", i);
            let v = format!("node_{}", i + 1);
            let half = capacity / 2;
            let ch = Channel {
                id: format!("ch_{}_{}", u, v),
                node_a: u.clone(),
                node_b: v.clone(),
                capacity_a_to_b: half,
                capacity_b_to_a: capacity - half,
                base_fee: 1,
                fee_rate: 100,
                cltv_delta: 40,
                min_htlc_size: 1,
                max_htlc_size: capacity,
                htlcs_in_flight: 0,
                enabled: true,
                age_seconds: 0,
            };
            graph.add_channel(ch);
            nodes.get_mut(&u).unwrap().channels.insert(v.clone());
            nodes.get_mut(&v).unwrap().channels.insert(u.clone());
        }

        (graph, nodes)
    }

    /// Create a diamond topology: source -> {upper, lower} -> dest
    pub fn diamond(
        capacity: i128,
        fee_rate_upper: u32,
        fee_rate_lower: u32,
    ) -> (NetworkGraph, HashMap<String, SimulatedNode>) {
        let mut graph = NetworkGraph::new();
        let mut nodes = HashMap::new();

        let node_names = ["source", "upper", "lower", "dest"];
        for (i, name) in node_names.iter().enumerate() {
            let node = Node {
                id: name.to_string(),
                public_key: vec![i as u8; 32],
                alias: Some(format!("Node {}", name)),
                online: true,
                last_seen: 0,
                features: channel_router::NodeFeatures::default(),
            };
            graph.add_node(node.clone());
            nodes.insert(
                name.to_string(),
                SimulatedNode {
                    node,
                    balance: 0,
                    channels: HashSet::new(),
                },
            );
        }

        let half = capacity / 2;
        let edges = [
            ("source", "upper", fee_rate_upper, half),
            ("upper", "dest", fee_rate_upper, half),
            ("source", "lower", fee_rate_lower, half),
            ("lower", "dest", fee_rate_lower, half),
        ];

        for (u, v, fee_rate, cap) in edges {
            let ch = Channel {
                id: format!("ch_{}_{}", u, v),
                node_a: u.to_string(),
                node_b: v.to_string(),
                capacity_a_to_b: cap,
                capacity_b_to_a: cap,
                base_fee: 1,
                fee_rate,
                cltv_delta: 40,
                min_htlc_size: 1,
                max_htlc_size: cap * 2,
                htlcs_in_flight: 0,
                enabled: true,
                age_seconds: 0,
            };
            graph.add_channel(ch);
            nodes.get_mut(u).unwrap().channels.insert(v.to_string());
            nodes.get_mut(v).unwrap().channels.insert(u.to_string());
        }

        (graph, nodes)
    }

    /// Baseline 6-node fixture for comprehensive regression testing of pathfinding
    pub fn baseline_routing_regression_fixture() -> (NetworkGraph, HashMap<String, SimulatedNode>) {
        let mut graph = NetworkGraph::new();
        let mut nodes = HashMap::new();

        let node_names = ["src", "relay_a", "relay_b", "hub_c", "gw_d", "dst"];
        for (i, name) in node_names.iter().enumerate() {
            let node = Node {
                id: name.to_string(),
                public_key: vec![i as u8; 32],
                alias: Some(format!("Regression Node {}", name)),
                online: true,
                last_seen: 0,
                features: channel_router::NodeFeatures::default(),
            };
            graph.add_node(node.clone());
            nodes.insert(
                name.to_string(),
                SimulatedNode {
                    node,
                    balance: 0,
                    channels: HashSet::new(),
                },
            );
        }

        // Channels:
        // Path 1 (Short, 2 hops): src -> relay_a -> dst (cap 50,000, fee 10)
        // Path 2 (Deep, 3 hops): src -> relay_b -> hub_c -> dst (cap 200,000, fee 50)
        // Path 3 (Bottleneck): src -> gw_d -> dst (cap 500, fee 5)
        let channels_spec = [
            ("src", "relay_a", 25_000, 25_000, 10),
            ("relay_a", "dst", 25_000, 25_000, 10),
            ("src", "relay_b", 100_000, 100_000, 50),
            ("relay_b", "hub_c", 100_000, 100_000, 50),
            ("hub_c", "dst", 100_000, 100_000, 50),
            ("src", "gw_d", 250, 250, 5),
            ("gw_d", "dst", 250, 250, 5),
        ];

        for (u, v, cap_ab, cap_ba, fee_rate) in channels_spec {
            let ch = Channel {
                id: format!("ch_{}_{}", u, v),
                node_a: u.to_string(),
                node_b: v.to_string(),
                capacity_a_to_b: cap_ab,
                capacity_b_to_a: cap_ba,
                base_fee: 1,
                fee_rate,
                cltv_delta: 20,
                min_htlc_size: 1,
                max_htlc_size: cap_ab + cap_ba,
                htlcs_in_flight: 0,
                enabled: true,
                age_seconds: 0,
            };
            graph.add_channel(ch);
            nodes.get_mut(u).unwrap().channels.insert(v.to_string());
            nodes.get_mut(v).unwrap().channels.insert(u.to_string());
        }

        (graph, nodes)
    }
}

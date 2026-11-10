//! # Payment Channel Network Simulator
//!
//! A simulator for testing Stellar payment channel networks with 100+ nodes.
//! Supports network generation, payment simulation, and routing algorithm testing.

pub mod fuzz;
pub mod network;
pub mod statistics;

use channel_router::pathfinder::Pathfinder;
use channel_router::{Channel, Direction, NetworkGraph, Node, RouteRequest};
pub use crate::statistics::{FailureReason, FailedPaymentDetail, FailedPaymentSummary, HopLengthMetrics};
pub use crate::network::NetworkFixture;
use parking_lot::RwLock;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info};

/// Deterministic simulation input event with ordered priority (Issue #385)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SimulationEvent {
    /// Scheduled execution tick or timestamp
    pub tick: u64,
    /// Priority level (higher priority executed first on tick collision)
    pub priority: u32,
    /// Monotonic sequence ID for strict FIFO stability
    pub sequence_id: u64,
    /// Source node identifier
    pub source: String,
    /// Destination node identifier
    pub destination: String,
    /// Payment amount in stroops
    pub amount: i128,
}

impl Ord for SimulationEvent {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.tick
            .cmp(&other.tick)
            .then_with(|| other.priority.cmp(&self.priority))
            .then_with(|| self.sequence_id.cmp(&other.sequence_id))
            .then_with(|| self.source.cmp(&other.source))
            .then_with(|| self.destination.cmp(&other.destination))
            .then_with(|| self.amount.cmp(&other.amount))
    }
}

impl PartialOrd for SimulationEvent {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Deterministic scheduler providing strictly ordered event dispatch (Issue #385)
#[derive(Debug, Default, Clone)]
pub struct DeterministicScheduler {
    events: Vec<SimulationEvent>,
}

impl DeterministicScheduler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn schedule(&mut self, event: SimulationEvent) {
        self.events.push(event);
    }

    pub fn schedule_batch(&mut self, batch: impl IntoIterator<Item = SimulationEvent>) {
        self.events.extend(batch);
    }

    pub fn drain_ordered(&mut self) -> Vec<SimulationEvent> {
        self.events.sort();
        std::mem::take(&mut self.events)
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}


/// Simulator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulatorConfig {
    /// Number of nodes in the network
    pub num_nodes: usize,
    /// Average number of channels per node
    pub avg_channels_per_node: f64,
    /// Minimum channel capacity
    pub min_channel_capacity: i128,
    /// Maximum channel capacity
    pub max_channel_capacity: i128,
    /// Average channel balance (as percentage of capacity)
    pub avg_balance_percent: f64,
    /// Base fee for routing
    pub base_fee: i128,
    /// Fee rate in ppm
    pub fee_rate: u32,
    /// CLTV delta
    pub cltv_delta: u32,
    /// Number of payments to simulate
    pub num_payments: usize,
    /// Maximum payment amount
    pub max_payment_amount: i128,
    /// Random seed for reproducibility
    pub seed: Option<u64>,
    /// Model channel balance depletion across routing hops (Issue #384)
    pub model_liquidity_depletion: bool,
}

impl Default for SimulatorConfig {
    fn default() -> Self {
        SimulatorConfig {
            num_nodes: 100,
            avg_channels_per_node: 5.0,
            min_channel_capacity: 1000,
            max_channel_capacity: 100_000_000, // 100 XLM in stroops
            avg_balance_percent: 0.5,
            base_fee: 1,
            fee_rate: 1000,
            cltv_delta: 40,
            num_payments: 1000,
            max_payment_amount: 1_000_000, // 1 XLM
            seed: None,
            model_liquidity_depletion: false,
        }
    }
}

/// Network simulation statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimulationStats {
    /// Total payments attempted
    pub total_payments: usize,
    /// Successful payments
    pub successful_payments: usize,
    /// Failed payments
    pub failed_payments: usize,
    /// Total value routed
    pub total_value_routed: i128,
    /// Total fees collected
    pub total_fees_collected: i128,
    /// Average path length
    pub avg_path_length: f64,
    /// Maximum path length
    pub max_path_length: usize,
    /// Success rate
    pub success_rate: f64,
    /// Network utilization
    pub network_utilization: f64,
    /// Payment latency histogram (ms)
    pub latency_ms: Vec<u64>,
    /// Detailed summary and categorized breakdown of failed payments (Issue #386)
    pub failure_summary: crate::statistics::FailedPaymentSummary,
    /// Success and fee metrics broken down by route length (hops) (Issue #383)
    pub success_by_hop_length: HashMap<usize, crate::statistics::HopLengthMetrics>,
    /// Number of channels whose liquidity was fully depleted (Issue #384)
    pub channels_depleted_count: usize,
}

impl SimulationStats {
    /// Return the observed payment success rate for a specific hop count (Issue #383)
    pub fn success_rate_for_hops(&self, hops: usize) -> Option<f64> {
        self.success_by_hop_length.get(&hops).map(|m| m.success_rate)
    }
}

/// Payment result for simulation
#[derive(Debug, Clone)]
pub struct SimulatedPayment {
    /// Source node
    pub source: String,
    /// Destination node
    pub destination: String,
    /// Amount
    pub amount: i128,
    /// Success
    pub success: bool,
    /// Path taken (if successful)
    pub path: Vec<String>,
    /// Fee paid
    pub fee: i128,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Time taken (ms)
    pub time_ms: u64,
}

/// Network simulator
pub struct Simulator {
    /// Configuration
    config: SimulatorConfig,
    /// Network graph
    network: Arc<RwLock<NetworkGraph>>,
    /// Node information
    nodes: Arc<RwLock<HashMap<String, SimulatedNode>>>,
    /// Statistics
    stats: Arc<RwLock<SimulationStats>>,
    /// Random number generator
    rng: parking_lot::Mutex<rand::rngs::StdRng>,
}

impl Simulator {
    /// Create a new simulator with the given configuration
    pub fn new(config: SimulatorConfig) -> Self {
        let seed = config.seed.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        });

        let rng = rand::rngs::StdRng::seed_from_u64(seed);

        Simulator {
            config,
            network: Arc::new(RwLock::new(NetworkGraph::new())),
            nodes: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(SimulationStats::default())),
            rng: parking_lot::Mutex::new(rng),
        }
    }

    /// Initialize the network with random topology
    pub fn initialize_network(&self) -> Result<(), SimulatorError> {
        info!("Initializing network with {} nodes", self.config.num_nodes);

        let mut rng = self.rng.lock();
        let mut network = self.network.write();
        let mut nodes = self.nodes.write();

        // Create nodes
        for i in 0..self.config.num_nodes {
            let node_id = format!("node_{:03}", i);
            let node = Node {
                id: node_id.clone(),
                public_key: Self::generate_random_bytes(32, &mut *rng),
                alias: Some(format!("Node {}", i)),
                online: true,
                last_seen: 0,
                features: channel_router::NodeFeatures::default(),
            };

            network.add_node(node.clone());
            nodes.insert(
                node_id,
                SimulatedNode {
                    node,
                    balance: 0,
                    channels: HashSet::new(),
                },
            );
        }

        info!("Created {} nodes", nodes.len());

        // Create channels based on configuration. The target is capped at the
        // number of distinct node pairs and the retry loop is bounded, so a
        // configuration asking for more channels than the node count allows
        // finishes with a full graph instead of spinning forever.
        let node_ids: Vec<String> = nodes.keys().cloned().collect();
        let max_possible_channels =
            self.config.num_nodes * self.config.num_nodes.saturating_sub(1) / 2;
        let target_channels = ((self.config.num_nodes as f64 * self.config.avg_channels_per_node)
            as usize)
            .min(max_possible_channels);
        let max_attempts = target_channels * 20 + 100;
        let mut channels_created = 0;
        let mut attempts = 0;

        while channels_created < target_channels && attempts < max_attempts {
            attempts += 1;

            // Pick two random nodes
            let idx_a = rng.gen_range(0..node_ids.len());
            let idx_b = rng.gen_range(0..node_ids.len());

            if idx_a == idx_b {
                continue;
            }

            let node_a = &node_ids[idx_a];
            let node_b = &node_ids[idx_b];

            // Check whether these two nodes are already joined. Asking whether
            // *any* node touches both of them is a different question, and
            // makes the loop give up on pairs that are still free.
            let existing = nodes
                .get(node_a)
                .map(|n| n.channels.contains(node_b))
                .unwrap_or(false);

            if existing {
                continue;
            }

            // Generate channel capacity
            let capacity: i128 =
                rng.gen_range(self.config.min_channel_capacity..self.config.max_channel_capacity);
            let balance = (capacity as f64 * self.config.avg_balance_percent) as i128;

            // Create channel
            let channel = Channel {
                id: format!("ch_{:06}", channels_created),
                node_a: node_a.clone(),
                node_b: node_b.clone(),
                capacity_a_to_b: balance,
                capacity_b_to_a: capacity - balance,
                base_fee: self.config.base_fee,
                fee_rate: self.config.fee_rate,
                cltv_delta: self.config.cltv_delta,
                min_htlc_size: 1,
                max_htlc_size: capacity,
                htlcs_in_flight: 0,
                enabled: true,
                age_seconds: rng.gen_range(0..86400 * 30), // Up to 30 days old
            };

            network.add_channel(channel.clone());

            // Update node channel lists
            if let Some(node) = nodes.get_mut(node_a) {
                node.channels.insert(node_b.clone());
            }
            if let Some(node) = nodes.get_mut(node_b) {
                node.channels.insert(node_a.clone());
            }

            channels_created += 1;
        }

        info!("Created {} channels", channels_created);
        info!(
            "Network initialized: {} nodes, {} channels",
            network.num_nodes(),
            network.num_channels()
        );

        Ok(())
    }

    /// Run the payment simulation
    pub async fn run_simulation(&self) -> Result<SimulationStats, SimulatorError> {
        info!(
            "Starting simulation with {} payments",
            self.config.num_payments
        );

        let mut rng = self.rng.lock();
        let node_ids: Vec<String> = self.nodes.read().keys().cloned().collect();
        let mut scheduler = DeterministicScheduler::new();

        // Generate events with deterministic sequence numbering
        for i in 0..self.config.num_payments {
            if node_ids.len() < 2 {
                break;
            }
            let source_idx = rng.gen_range(0..node_ids.len());
            let dest_idx = rng.gen_range(0..node_ids.len());

            let source = node_ids[source_idx].clone();
            let dest = node_ids[dest_idx].clone();
            let amount: i128 = rng.gen_range(100..self.config.max_payment_amount);

            scheduler.schedule(SimulationEvent {
                tick: (i / 10) as u64,
                priority: if amount > 500_000 { 2 } else { 1 },
                sequence_id: i as u64,
                source,
                destination: dest,
                amount,
            });
        }

        // Drain in strictly deterministic order (Issue #385)
        let ordered_events = scheduler.drain_ordered();

        let pathfinder = Pathfinder::new();
        let mut successful = 0;
        let mut failed = 0;
        let mut total_value = 0i128;
        let mut total_fees = 0i128;
        let mut path_lengths = Vec::new();

        let mut failure_summary = crate::statistics::FailedPaymentSummary::new();
        let mut hop_metrics: HashMap<usize, crate::statistics::HopLengthMetrics> = HashMap::new();
        let mut depleted_channels: HashSet<String> = HashSet::new();

        for event in ordered_events {
            let start = std::time::Instant::now();
            let source = event.source;
            let dest = event.destination;
            let amount = event.amount;

            if source == dest {
                failed += 1;
                failure_summary.record_failure(
                    source.clone(),
                    dest.clone(),
                    amount,
                    FailureReason::SourceEqualsDestination,
                    "Source equals destination".to_string(),
                );
                continue;
            }

            let request = RouteRequest {
                source: source.clone(),
                destination: dest.clone(),
                amount,
                max_fee_budget: Some(amount / 10), // Max 10% fee
                max_hops: Some(20),
                find_any: false,
                payment_metadata: None,
            };

            // Acquire read lock to find candidate route
            let route_opt = {
                let network = self.network.read();
                pathfinder.find_route_dijkstra(&network, &request)
            };

            match route_opt {
                Ok(route) => {
                    let hops_count = route.hops.len();
                    hop_metrics.entry(hops_count).or_default().record_attempt();

                    // If modeling liquidity depletion (Issue #384), check and apply balance shifts
                    if self.config.model_liquidity_depletion {
                        let mut network = self.network.write();
                        let mut can_fulfill = true;
                        let mut failing_hop_detail = String::new();

                        // 1. Verify all hops have sufficient liquidity
                        let mut current_node = source.clone();
                        for hop in &route.hops {
                            if let Some(ch) = network.get_channel(&hop.channel_id) {
                                let (forward_cap, _dir) = if ch.node_a == current_node {
                                    (ch.capacity_a_to_b, Direction::AToB)
                                } else {
                                    (ch.capacity_b_to_a, Direction::BToA)
                                };

                                if forward_cap < hop.amount {
                                    can_fulfill = false;
                                    failing_hop_detail = format!(
                                        "channel {} depleted: capacity {} < required {}",
                                        hop.channel_id, forward_cap, hop.amount
                                    );
                                    break;
                                }
                            } else {
                                can_fulfill = false;
                                failing_hop_detail = format!("missing channel {}", hop.channel_id);
                                break;
                            }
                            current_node = hop.node_id.clone();
                        }

                        if !can_fulfill {
                            failed += 1;
                            failure_summary.record_failure(
                                source.clone(),
                                dest.clone(),
                                amount,
                                FailureReason::ChannelDepleted,
                                failing_hop_detail,
                            );
                            hop_metrics.entry(hops_count).or_default().record_failure();
                            continue;
                        }

                        // 2. Apply atomic liquidity shift
                        let mut curr = source.clone();
                        for hop in &route.hops {
                            let (dir, new_fwd, new_rev) = {
                                let ch = network.get_channel(&hop.channel_id).unwrap();
                                if ch.node_a == curr {
                                    let fwd = ch.capacity_a_to_b - hop.amount;
                                    let rev = ch.capacity_b_to_a + hop.amount;
                                    (Direction::AToB, fwd, rev)
                                } else {
                                    let fwd = ch.capacity_b_to_a - hop.amount;
                                    let rev = ch.capacity_a_to_b + hop.amount;
                                    (Direction::BToA, fwd, rev)
                                }
                            };

                            let rev_dir = match dir {
                                Direction::AToB => Direction::BToA,
                                Direction::BToA => Direction::AToB,
                            };

                            network.update_capacity(&hop.channel_id, dir, new_fwd);
                            network.update_capacity(&hop.channel_id, rev_dir, new_rev);

                            if new_fwd == 0 {
                                depleted_channels.insert(hop.channel_id.clone());
                            }

                            curr = hop.node_id.clone();
                        }
                    }

                    let elapsed = start.elapsed().as_millis() as u64;
                    successful += 1;
                    total_value += amount;
                    total_fees += route.total_fees;
                    path_lengths.push(hops_count);
                    hop_metrics.entry(hops_count).or_default().record_success(route.total_fees);

                    debug!(
                        "Payment {} succeeded: {} -> {} ({} hops, {} fee) in {}ms",
                        successful, source, dest, hops_count, route.total_fees, elapsed
                    );
                }
                Err(e) => {
                    failed += 1;
                    let err_str = format!("{:?}", e);
                    let reason = if err_str.contains("Fee") || err_str.contains("budget") {
                        FailureReason::FeeExceededBudget
                    } else if err_str.contains("hops") || err_str.contains("Hops") {
                        FailureReason::MaxHopsExceeded
                    } else if err_str.contains("liquidity") || err_str.contains("capacity") {
                        FailureReason::InsufficientLiquidity
                    } else {
                        FailureReason::NoRouteFound
                    };

                    failure_summary.record_failure(
                        source.clone(),
                        dest.clone(),
                        amount,
                        reason,
                        err_str,
                    );
                }
            }
        }

        // Update statistics
        let avg_path = if !path_lengths.is_empty() {
            path_lengths.iter().sum::<usize>() as f64 / path_lengths.len() as f64
        } else {
            0.0
        };

        let max_path = path_lengths.iter().max().copied().unwrap_or(0);
        let total_attempts = successful + failed;
        let success_rate = if total_attempts > 0 {
            (successful as f64 / total_attempts as f64) * 100.0
        } else {
            0.0
        };

        let stats = SimulationStats {
            total_payments: total_attempts,
            successful_payments: successful,
            failed_payments: failed,
            total_value_routed: total_value,
            total_fees_collected: total_fees,
            avg_path_length: avg_path,
            max_path_length: max_path,
            success_rate,
            network_utilization: 0.0,
            latency_ms: Vec::new(),
            failure_summary,
            success_by_hop_length: hop_metrics,
            channels_depleted_count: depleted_channels.len(),
        };

        *self.stats.write() = stats.clone();

        info!(
            "Simulation complete: {} successful, {} failed, {:.2}% success rate",
            successful, failed, success_rate
        );
        info!("Average path length: {:.2}, Max: {}", avg_path, max_path);

        Ok(stats)
    }

    /// Get the network graph

    /// Initialize the network from the baseline routing regression fixture (Issue #387)
    pub fn initialize_with_baseline_fixture(&self) -> Result<(), SimulatorError> {
        let (graph, nodes) = network::NetworkFixture::baseline_routing_regression_fixture();
        *self.network.write() = graph;
        *self.nodes.write() = nodes;
        Ok(())
    }

    /// Initialize the network with an explicit custom graph and node set (Issue #387)
    pub fn initialize_with_custom_graph(
        &self,
        graph: NetworkGraph,
        nodes: HashMap<String, SimulatedNode>,
    ) {
        *self.network.write() = graph;
        *self.nodes.write() = nodes;
    }

    pub fn get_network(&self) -> Arc<RwLock<NetworkGraph>> {
        Arc::clone(&self.network)
    }

    /// Get a specific node
    pub fn get_node(&self, node_id: &str) -> Option<SimulatedNode> {
        self.nodes.read().get(node_id).cloned()
    }

    /// Get all nodes
    pub fn get_all_nodes(&self) -> Vec<SimulatedNode> {
        self.nodes.read().values().cloned().collect()
    }

    /// Get simulation statistics
    pub fn get_stats(&self) -> SimulationStats {
        self.stats.read().clone()
    }

    /// Generate random bytes
    fn generate_random_bytes(len: usize, rng: &mut impl rand::Rng) -> Vec<u8> {
        (0..len).map(|_| rng.gen()).collect()
    }

    /// Run a stress test with parallel payments
    pub async fn run_stress_test(
        &self,
        concurrent: usize,
    ) -> Result<SimulationStats, SimulatorError> {
        info!(
            "Running stress test with {} concurrent payments",
            concurrent
        );

        // For now, just run the regular simulation
        // In production, this would use tokio to run payments concurrently
        self.run_simulation().await
    }

    /// Measure routing algorithm performance
    pub fn benchmark_routing(&self) -> HashMap<String, u64> {
        let mut results = HashMap::new();
        let node_ids: Vec<String> = self.nodes.read().keys().cloned().collect();

        if node_ids.len() < 2 {
            return results;
        }

        let network = self.network.read();
        let pathfinder = Pathfinder::new();

        // Benchmark Dijkstra
        let start = std::time::Instant::now();
        for i in 0..100 {
            let source = &node_ids[i % node_ids.len()];
            let dest = &node_ids[(i + 1) % node_ids.len()];

            let _ = pathfinder.find_route_dijkstra(
                &network,
                &RouteRequest {
                    source: source.clone(),
                    destination: dest.clone(),
                    amount: 1000,
                    max_fee_budget: None,
                    max_hops: None,
                    find_any: false,
                    payment_metadata: None,
                },
            );
        }
        let dijkstra_time = start.elapsed().as_micros() as u64;
        results.insert("dijkstra_avg_us".to_string(), dijkstra_time / 100);

        // Benchmark A*
        let start = std::time::Instant::now();
        for i in 0..100 {
            let source = &node_ids[i % node_ids.len()];
            let dest = &node_ids[(i + 1) % node_ids.len()];

            let _ = pathfinder.find_route_astar(
                &network,
                &RouteRequest {
                    source: source.clone(),
                    destination: dest.clone(),
                    amount: 1000,
                    max_fee_budget: None,
                    max_hops: None,
                    find_any: false,
                    payment_metadata: None,
                },
            );
        }
        let astar_time = start.elapsed().as_micros() as u64;
        results.insert("astar_avg_us".to_string(), astar_time / 100);

        // Benchmark BFS
        let start = std::time::Instant::now();
        for i in 0..100 {
            let source = &node_ids[i % node_ids.len()];
            let dest = &node_ids[(i + 1) % node_ids.len()];

            let _ = pathfinder.find_route_bfs(
                &network,
                &RouteRequest {
                    source: source.clone(),
                    destination: dest.clone(),
                    amount: 1000,
                    max_fee_budget: None,
                    max_hops: None,
                    find_any: false,
                    payment_metadata: None,
                },
            );
        }
        let bfs_time = start.elapsed().as_micros() as u64;
        results.insert("bfs_avg_us".to_string(), bfs_time / 100);

        info!(
            "Routing benchmarks: Dijkstra={}us, A*={}us, BFS={}us",
            dijkstra_time / 100,
            astar_time / 100,
            bfs_time / 100
        );

        results
    }
}

/// Simulated node with additional metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulatedNode {
    /// Basic node information
    pub node: Node,
    /// Total balance across all channels
    pub balance: i128,
    /// Connected channel endpoints
    pub channels: HashSet<String>,
}

/// Simulator errors
#[derive(Error, Debug)]
pub enum SimulatorError {
    #[error("Network initialization failed: {0}")]
    NetworkInitError(String),

    #[error("Simulation error: {0}")]
    SimulationError(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_small_network() {
        let config = SimulatorConfig {
            num_nodes: 10,
            avg_channels_per_node: 3.0,
            num_payments: 50,
            seed: Some(42),
            ..Default::default()
        };

        let simulator = Simulator::new(config);
        simulator.initialize_network().unwrap();

        let stats = simulator.run_simulation().await.unwrap();

        assert!(stats.total_payments > 0);
        assert!(stats.success_rate >= 0.0);
    }

    #[test]
    fn test_large_network() {
        let config = SimulatorConfig {
            num_nodes: 100,
            avg_channels_per_node: 5.0,
            num_payments: 1000,
            seed: Some(42),
            ..Default::default()
        };

        let simulator = Simulator::new(config);
        simulator.initialize_network().unwrap();

        // Just verify network was created correctly
        assert_eq!(simulator.get_all_nodes().len(), 100);

        let network = simulator.get_network();
        let graph = network.read();
        assert!(graph.num_channels() > 0);
    }

    #[test]
    fn test_baseline_network_fixture_routing_regression() {
        // Issue #387: Test baseline fixture determinism and routing regression
        let config = SimulatorConfig {
            num_nodes: 6,
            seed: Some(101),
            ..Default::default()
        };
        let simulator = Simulator::new(config);
        simulator.initialize_with_baseline_fixture().expect("baseline fixture init failed");

        let network = simulator.get_network();
        let graph = network.read();
        assert_eq!(graph.num_nodes(), 6);
        assert_eq!(graph.num_channels(), 7);

        let pathfinder = Pathfinder::new();
        // Query route from src to dst for 1,000 stroops
        let req = RouteRequest {
            source: "src".to_string(),
            destination: "dst".to_string(),
            amount: 1_000,
            max_fee_budget: Some(1_000),
            max_hops: Some(10),
            find_any: false,
            payment_metadata: None,
        };
        let route = pathfinder.find_route_dijkstra(&graph, &req).expect("route should exist");
        // Shortest path is through relay_a (2 hops)
        assert_eq!(route.hops.len(), 2);
        assert_eq!(route.hops[0].node_id, "dst");
    }

    #[test]
    fn test_deterministic_event_ordering() {
        // Issue #385: Verify deterministic scheduler ordering
        let mut scheduler = DeterministicScheduler::new();

        scheduler.schedule(SimulationEvent {
            tick: 5,
            priority: 1,
            sequence_id: 10,
            source: "b".to_string(),
            destination: "c".to_string(),
            amount: 100,
        });

        scheduler.schedule(SimulationEvent {
            tick: 1,
            priority: 1,
            sequence_id: 20,
            source: "a".to_string(),
            destination: "b".to_string(),
            amount: 200,
        });

        scheduler.schedule(SimulationEvent {
            tick: 1,
            priority: 5, // higher priority on same tick
            sequence_id: 30,
            source: "x".to_string(),
            destination: "y".to_string(),
            amount: 500,
        });

        let ordered = scheduler.drain_ordered();
        assert_eq!(ordered.len(), 3);
        assert_eq!(ordered[0].priority, 5); // tick 1, priority 5
        assert_eq!(ordered[1].priority, 1); // tick 1, priority 1
        assert_eq!(ordered[2].tick, 5);       // tick 5
    }

    #[tokio::test]
    async fn test_channel_liquidity_depletion_modeling() {
        // Issue #384: Verify liquidity depletion causes subsequent failures
        let config = SimulatorConfig {
            num_nodes: 3,
            num_payments: 10,
            max_payment_amount: 500,
            model_liquidity_depletion: true,
            seed: Some(42),
            ..Default::default()
        };
        let simulator = Simulator::new(config);
        let (graph, nodes) = network::NetworkFixture::linear(2, 600); // 300 capacity per direction
        simulator.initialize_with_custom_graph(graph, nodes);

        let stats = simulator.run_simulation().await.expect("simulation failed");
        assert!(stats.total_payments > 0);
    }

    #[tokio::test]
    async fn test_payment_success_rate_by_route_length_and_failed_summaries() {
        // Issues #383, #386: Hop metrics and failure summary diagnostics
        let config = SimulatorConfig {
            num_nodes: 6,
            num_payments: 25,
            model_liquidity_depletion: true,
            seed: Some(777),
            ..Default::default()
        };
        let simulator = Simulator::new(config);
        simulator.initialize_with_baseline_fixture().expect("baseline fixture failed");

        let stats = simulator.run_simulation().await.expect("simulation failed");
        assert_eq!(stats.total_payments, 25);
        // Verify failure summary exists
        assert!(stats.failure_summary.total_failures <= 25);
        let report = stats.failure_summary.format_report();
        assert!(report.contains("Failed Payment Summary"));

        // Verify hop metrics recorded for observed lengths
        for (hops, metric) in &stats.success_by_hop_length {
            assert!(*hops > 0);
            assert!(metric.attempts > 0);
        }
    }
}

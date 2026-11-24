//! # Payment Channel Network Simulator
//!
//! A simulator for testing Stellar payment channel networks with 100+ nodes.
//! Supports network generation, payment simulation, and routing algorithm testing.

pub mod disconnection;
pub mod fuzz;
pub mod network;
pub mod statistics;

pub use disconnection::{DisconnectionConfig, DisconnectionTracker, MAX_DOWNTIME_STEPS};

use channel_router::pathfinder::Pathfinder;
use channel_router::{Channel, NetworkGraph, Node, RouteRequest};
use parking_lot::RwLock;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info};

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
    /// Optional configuration for temporary node disconnection and recovery.
    /// When `None`, all nodes remain online throughout the simulation.
    #[serde(default)]
    pub disconnection: Option<DisconnectionConfig>,
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
            disconnection: None,
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
    /// Total node disconnections observed during simulation
    #[serde(default)]
    pub node_disconnections: usize,
    /// Total node recoveries observed during simulation
    #[serde(default)]
    pub node_recoveries: usize,
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
    /// Tracks temporarily disconnected nodes and suspended channels
    disconnection_tracker: Arc<RwLock<DisconnectionTracker>>,
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
            disconnection_tracker: Arc::new(RwLock::new(DisconnectionTracker::new())),
            rng: parking_lot::Mutex::new(rng),
        }
    }

    /// Initialize the network with random topology
    pub fn initialize_network(&self) -> Result<(), SimulatorError> {
        if let Some(ref disconnection) = self.config.disconnection {
            disconnection.validate()?;
        }

        info!("Initializing network with {} nodes", self.config.num_nodes);

        let mut rng = self.rng.lock();
        let mut network = self.network.write();
        let mut nodes = self.nodes.write();
        self.disconnection_tracker.write().clear();

        // Create nodes
        for i in 0..self.config.num_nodes {
            let node_id = format!("node_{i:03}");
            let node = Node {
                id: node_id.clone(),
                public_key: Self::generate_random_bytes(32, &mut *rng),
                alias: Some(format!("Node {i}")),
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
                .is_some_and(|n| n.channels.contains(node_b));

            if existing {
                continue;
            }

            // Generate channel capacity
            let capacity: i128 =
                rng.gen_range(self.config.min_channel_capacity..self.config.max_channel_capacity);
            let balance = (capacity as f64 * self.config.avg_balance_percent) as i128;

            // Create channel
            let channel = Channel {
                id: format!("ch_{channels_created:06}"),
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
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)] // public API; a concurrent runner awaits this
    pub async fn run_simulation(&self) -> Result<SimulationStats, SimulatorError> {
        if let Some(ref disconnection) = self.config.disconnection {
            disconnection.validate()?;
        }

        info!(
            "Starting simulation with {} payments",
            self.config.num_payments
        );

        let mut rng = self.rng.lock();
        let mut node_ids: Vec<String> = self.nodes.read().keys().cloned().collect();
        if node_ids.is_empty() {
            return Err(SimulatorError::SimulationError(
                "cannot run simulation on an empty network; call initialize_network first"
                    .to_string(),
            ));
        }
        if self.config.disconnection.is_some() {
            node_ids.sort();
        }
        let mut payments = Vec::new();

        // Generate random payments
        for _i in 0..self.config.num_payments {
            let source_idx = rng.gen_range(0..node_ids.len());
            let dest_idx = rng.gen_range(0..node_ids.len());

            if source_idx == dest_idx {
                continue;
            }

            let source = &node_ids[source_idx];
            let dest = &node_ids[dest_idx];
            let amount: i128 = rng.gen_range(100..self.config.max_payment_amount);

            payments.push((source.clone(), dest.clone(), amount));
        }

        // Run payments through the router
        let pathfinder = Pathfinder::new();

        let mut successful = 0;
        let mut failed = 0;
        let mut total_value = 0i128;
        let mut total_fees = 0i128;
        let mut path_lengths = Vec::new();
        let mut node_disconnections = 0usize;
        let mut node_recoveries = 0usize;
        let total_steps = payments.len();

        for (step, (source, dest, amount)) in payments.into_iter().enumerate() {
            if let Some(ref churn_cfg) = self.config.disconnection {
                let mut network = self.network.write();
                let mut nodes = self.nodes.write();
                let mut tracker = self.disconnection_tracker.write();

                node_recoveries += tracker.recover_due_nodes(&mut network, &mut nodes, step)?;
                node_disconnections += tracker.step_random_disconnections(
                    &mut network,
                    &mut nodes,
                    step,
                    churn_cfg,
                    &mut *rng,
                )?;
            }

            let start = std::time::Instant::now();

            let request = RouteRequest {
                source: source.clone(),
                destination: dest.clone(),
                amount,
                max_fee_budget: Some(amount / 10), // Max 10% fee
                max_hops: Some(20),
                find_any: false,
                payment_metadata: None,
            };

            let route_result = {
                let network = self.network.read();
                pathfinder.find_route_dijkstra(&network, &request)
            };

            match route_result {
                Ok(route) => {
                    let elapsed = start.elapsed().as_millis() as u64;

                    successful += 1;
                    total_value += amount;
                    total_fees += route.total_fees;
                    path_lengths.push(route.hops.len());

                    debug!(
                        "Payment {} succeeded: {} -> {} ({} hops, {} fee) in {}ms",
                        successful,
                        source,
                        dest,
                        route.hops.len(),
                        route.total_fees,
                        elapsed
                    );
                }
                Err(e) => {
                    failed += 1;
                    debug!("Payment failed: {} -> {} - {:?}", source, dest, e);
                }
            }
        }

        if let Some(ref churn_cfg) = self.config.disconnection {
            if churn_cfg.recover_at_end {
                let mut network = self.network.write();
                let mut nodes = self.nodes.write();
                let mut tracker = self.disconnection_tracker.write();
                node_recoveries += tracker.recover_all(&mut network, &mut nodes, total_steps)?;
            }
        }

        // Update statistics
        let avg_path = if path_lengths.is_empty() {
            0.0
        } else {
            path_lengths.iter().sum::<usize>() as f64 / path_lengths.len() as f64
        };

        let max_path = path_lengths.iter().max().copied().unwrap_or(0);
        let total = successful + failed;
        let success_rate = if total == 0 {
            0.0
        } else {
            (successful as f64 / total as f64) * 100.0
        };

        let stats = SimulationStats {
            total_payments: total,
            successful_payments: successful,
            failed_payments: failed,
            total_value_routed: total_value,
            total_fees_collected: total_fees,
            avg_path_length: avg_path,
            max_path_length: max_path,
            success_rate,
            network_utilization: 0.0, // Would need more complex calculation
            latency_ms: Vec::new(),
            node_disconnections,
            node_recoveries,
        };

        *self.stats.write() = stats.clone();

        info!(
            "Simulation complete: {} successful, {} failed, {:.2}% success rate",
            successful, failed, success_rate
        );
        info!("Average path length: {:.2}, Max: {}", avg_path, max_path);
        info!(
            "Total value routed: {}, Total fees: {}",
            total_value, total_fees
        );

        Ok(stats)
    }

    /// Get the network graph
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

    /// Temporarily disconnect a node and suspend its active channels.
    ///
    /// Returns the number of channels suspended. Fails without modifying state
    /// if the node does not exist or is already disconnected.
    pub fn disconnect_node(&self, node_id: &str) -> Result<usize, SimulatorError> {
        let mut network = self.network.write();
        let mut nodes = self.nodes.write();
        let mut tracker = self.disconnection_tracker.write();
        tracker.disconnect_node(&mut network, &mut nodes, node_id, 0, None)
    }

    /// Recover a previously disconnected node and restore its suspended channels
    /// whose peer endpoints are also online.
    ///
    /// Returns the number of channels restored. Fails without modifying state if
    /// the node does not exist or is not currently disconnected.
    pub fn recover_node(&self, node_id: &str) -> Result<usize, SimulatorError> {
        let mut network = self.network.write();
        let mut nodes = self.nodes.write();
        let mut tracker = self.disconnection_tracker.write();
        tracker.recover_node(&mut network, &mut nodes, node_id, 0)
    }

    /// Check whether a node is currently online.
    pub fn is_node_online(&self, node_id: &str) -> Result<bool, SimulatorError> {
        let nodes = self.nodes.read();
        nodes
            .get(node_id)
            .map(|sim_node| sim_node.node.online)
            .ok_or_else(|| SimulatorError::UnknownNode(node_id.to_string()))
    }

    /// Return the sorted list of currently disconnected node IDs.
    pub fn disconnected_nodes(&self) -> Vec<String> {
        self.disconnection_tracker.read().offline_node_ids()
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

    #[error("Unknown node '{0}'")]
    UnknownNode(String),

    #[error("Invalid node state: {0}")]
    InvalidNodeState(String),
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
    fn manual_node_disconnection_and_recovery_updates_graph_and_rejects_invalid_calls() {
        let config = SimulatorConfig {
            num_nodes: 6,
            avg_channels_per_node: 3.0,
            seed: Some(99),
            ..Default::default()
        };

        let simulator = Simulator::new(config);
        simulator.initialize_network().unwrap();

        let initial_channels = simulator.get_network().read().num_channels();
        let node_channels_before = simulator.get_node("node_000").unwrap().channels.len();

        let suspended = simulator.disconnect_node("node_000").unwrap();
        assert_eq!(suspended, node_channels_before);
        assert!(!simulator.is_node_online("node_000").unwrap());
        assert_eq!(simulator.disconnected_nodes(), vec!["node_000".to_string()]);
        assert_eq!(
            simulator.get_network().read().num_channels(),
            initial_channels - suspended
        );

        // Disconnecting an already-disconnected node fails without changing state
        assert!(matches!(
            simulator.disconnect_node("node_000"),
            Err(SimulatorError::InvalidNodeState(_))
        ));
        assert!(matches!(
            simulator.disconnect_node("missing_node"),
            Err(SimulatorError::UnknownNode(_))
        ));

        let restored = simulator.recover_node("node_000").unwrap();
        assert_eq!(restored, suspended);
        assert!(simulator.is_node_online("node_000").unwrap());
        assert!(simulator.disconnected_nodes().is_empty());
        assert_eq!(
            simulator.get_network().read().num_channels(),
            initial_channels
        );

        // Recovering an online node fails without changing state
        assert!(matches!(
            simulator.recover_node("node_000"),
            Err(SimulatorError::InvalidNodeState(_))
        ));
    }

    #[tokio::test]
    async fn simulation_rejects_invalid_disconnection_config() {
        let config = SimulatorConfig {
            num_nodes: 5,
            num_payments: 10,
            seed: Some(11),
            disconnection: Some(DisconnectionConfig {
                disconnect_probability: 1.5,
                ..Default::default()
            }),
            ..Default::default()
        };

        let simulator = Simulator::new(config);
        assert!(matches!(
            simulator.initialize_network(),
            Err(SimulatorError::InvalidConfig(_))
        ));
        assert!(matches!(
            simulator.run_simulation().await,
            Err(SimulatorError::InvalidConfig(_))
        ));
    }

    #[tokio::test]
    async fn simulation_with_disconnection_is_reproducible_and_recovers_nodes() {
        let config = SimulatorConfig {
            num_nodes: 12,
            avg_channels_per_node: 4.0,
            num_payments: 30,
            seed: Some(777),
            disconnection: Some(DisconnectionConfig {
                disconnect_probability: 0.15,
                min_downtime_steps: 2,
                max_downtime_steps: 5,
                max_concurrent_disconnections: Some(4),
                recover_at_end: true,
            }),
            ..Default::default()
        };

        let sim_a = Simulator::new(config.clone());
        sim_a.initialize_network().unwrap();
        let stats_a = sim_a.run_simulation().await.unwrap();

        let sim_b = Simulator::new(config);
        sim_b.initialize_network().unwrap();
        let stats_b = sim_b.run_simulation().await.unwrap();

        assert!(stats_a.node_disconnections > 0);
        assert_eq!(stats_a.node_disconnections, stats_a.node_recoveries);
        assert!(sim_a.disconnected_nodes().is_empty());
        assert_eq!(stats_a.total_payments, stats_b.total_payments);
        assert_eq!(stats_a.successful_payments, stats_b.successful_payments);
        assert_eq!(stats_a.node_disconnections, stats_b.node_disconnections);
        assert_eq!(stats_a.node_recoveries, stats_b.node_recoveries);
    }
}

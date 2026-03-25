//! # Payment Channel Network Simulator
//! 
//! A simulator for testing Stellar payment channel networks with 100+ nodes.
//! Supports network generation, payment simulation, and routing algorithm testing.

pub mod network;
pub mod statistics;

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{info, warn, debug};
use channel_router::{NetworkGraph, Node, Channel, RouteRequest, RoutingError};
use channel_router::pathfinder::Pathfinder;

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
            nodes.insert(node_id, SimulatedNode {
                node,
                balance: 0,
                channels: HashSet::new(),
            });
        }
        
        info!("Created {} nodes", nodes.len());
        
        // Create channels based on configuration
        let node_ids: Vec<String> = nodes.keys().cloned().collect();
        let target_channels = (self.config.num_nodes as f64 * self.config.avg_channels_per_node) as usize;
        let mut channels_created = 0;
        
        while channels_created < target_channels {
            // Pick two random nodes
            let idx_a = rng.gen_range(0..node_ids.len());
            let idx_b = rng.gen_range(0..node_ids.len());
            
            if idx_a == idx_b {
                continue;
            }
            
            let node_a = &node_ids[idx_a];
            let node_b = &node_ids[idx_b];
            
            // Check if channel already exists
            let existing = nodes.values()
                .any(|n| n.channels.contains(node_a) && n.channels.contains(node_b));
            
            if existing {
                continue;
            }
            
            // Generate channel capacity
            let capacity: i128 = rng.gen_range(self.config.min_channel_capacity..self.config.max_channel_capacity);
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
        info!("Network initialized: {} nodes, {} channels", 
              network.num_nodes(), network.num_channels());
        
        Ok(())
    }
    
    /// Run the payment simulation
    pub async fn run_simulation(&self) -> Result<SimulationStats, SimulatorError> {
        info!("Starting simulation with {} payments", self.config.num_payments);
        
        let mut rng = self.rng.lock();
        let node_ids: Vec<String> = self.nodes.read().keys().cloned().collect();
        let mut payments = Vec::new();
        
        // Generate random payments
        for i in 0..self.config.num_payments {
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
        let network = self.network.read();
        let pathfinder = Pathfinder::new();
        
        let mut successful = 0;
        let mut failed = 0;
        let mut total_value = 0i128;
        let mut total_fees = 0i128;
        let mut path_lengths = Vec::new();
        
        for (source, dest, amount) in payments {
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
            
            match pathfinder.find_route_dijkstra(&network, &request) {
                Ok(route) => {
                    let elapsed = start.elapsed().as_millis() as u64;
                    
                    successful += 1;
                    total_value += amount;
                    total_fees += route.total_fees;
                    path_lengths.push(route.hops.len());
                    
                    debug!("Payment {} succeeded: {} -> {} ({} hops, {} fee) in {}ms",
                           successful, source, dest, route.hops.len(), route.total_fees, elapsed);
                }
                Err(e) => {
                    failed += 1;
                    debug!("Payment failed: {} -> {} - {:?}", source, dest, e);
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
        let success_rate = (successful as f64 / (successful + failed) as f64) * 100.0;
        
        let stats = SimulationStats {
            total_payments: successful + failed,
            successful_payments: successful,
            failed_payments: failed,
            total_value_routed: total_value,
            total_fees_collected: total_fees,
            avg_path_length: avg_path,
            max_path_length: max_path,
            success_rate,
            network_utilization: 0.0, // Would need more complex calculation
            latency_ms: Vec::new(),
        };
        
        *self.stats.write() = stats.clone();
        
        info!("Simulation complete: {} successful, {} failed, {:.2}% success rate",
              successful, failed, success_rate);
        info!("Average path length: {:.2}, Max: {}", avg_path, max_path);
        info!("Total value routed: {}, Total fees: {}", total_value, total_fees);
        
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
    
    /// Generate random bytes
    fn generate_random_bytes(len: usize, rng: &mut impl rand::Rng) -> Vec<u8> {
        (0..len).map(|_| rng.gen()).collect()
    }
    
    /// Run a stress test with parallel payments
    pub async fn run_stress_test(&self, concurrent: usize) -> Result<SimulationStats, SimulatorError> {
        info!("Running stress test with {} concurrent payments", concurrent);
        
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
            
            let _ = pathfinder.find_route_dijkstra(&network, &RouteRequest {
                source: source.clone(),
                destination: dest.clone(),
                amount: 1000,
                max_fee_budget: None,
                max_hops: None,
                find_any: false,
                payment_metadata: None,
            });
        }
        let dijkstra_time = start.elapsed().as_micros() as u64;
        results.insert("dijkstra_avg_us".to_string(), dijkstra_time / 100);
        
        // Benchmark A*
        let start = std::time::Instant::now();
        for i in 0..100 {
            let source = &node_ids[i % node_ids.len()];
            let dest = &node_ids[(i + 1) % node_ids.len()];
            
            let _ = pathfinder.find_route_astar(&network, &RouteRequest {
                source: source.clone(),
                destination: dest.clone(),
                amount: 1000,
                max_fee_budget: None,
                max_hops: None,
                find_any: false,
                payment_metadata: None,
            });
        }
        let astar_time = start.elapsed().as_micros() as u64;
        results.insert("astar_avg_us".to_string(), astar_time / 100);
        
        // Benchmark BFS
        let start = std::time::Instant::now();
        for i in 0..100 {
            let source = &node_ids[i % node_ids.len()];
            let dest = &node_ids[(i + 1) % node_ids.len()];
            
            let _ = pathfinder.find_route_bfs(&network, &RouteRequest {
                source: source.clone(),
                destination: dest.clone(),
                amount: 1000,
                max_fee_budget: None,
                max_hops: None,
                find_any: false,
                payment_metadata: None,
            });
        }
        let bfs_time = start.elapsed().as_micros() as u64;
        results.insert("bfs_avg_us".to_string(), bfs_time / 100);
        
        info!("Routing benchmarks: Dijkstra={}us, A*={}us, BFS={}us",
              dijkstra_time / 100, astar_time / 100, bfs_time / 100);
        
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
        
        assert_eq!(stats.total_payments, 50);
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
        assert_eq!(graph.num_channels() > 0, true);
    }
}

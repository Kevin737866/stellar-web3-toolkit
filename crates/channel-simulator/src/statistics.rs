//! # Statistics Module
//!
//! Statistical analysis utilities for the payment channel network simulator.

use crate::SimulationStats;
use channel_router::NetworkGraph;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Network statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    /// Number of nodes
    pub num_nodes: usize,
    /// Number of channels
    pub num_channels: usize,
    /// Network density
    pub density: f64,
    /// Average degree
    pub avg_degree: f64,
    /// Maximum degree
    pub max_degree: usize,
    /// Minimum degree
    pub min_degree: usize,
    /// Average path length
    pub avg_path_length: f64,
    /// Diameter (longest shortest path)
    pub diameter: usize,
    /// Clustering coefficient
    pub clustering_coefficient: f64,
    /// Number of connected components
    pub connected_components: usize,
    /// Node degree distribution
    pub degree_distribution: HashMap<usize, usize>,
}

/// Degree statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegreeStats {
    /// Mean degree
    pub mean: f64,
    /// Median degree
    pub median: f64,
    /// Standard deviation
    pub std_dev: f64,
    /// Mode degree
    pub mode: usize,
}

/// Path statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathStats {
    /// Average path length
    pub avg_length: f64,
    /// Median path length
    pub median_length: f64,
    /// Maximum path length
    pub max_length: usize,
    /// Standard deviation
    pub std_dev: f64,
    /// Path length histogram
    pub histogram: HashMap<usize, usize>,
}

/// Channel statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelStats {
    /// Total capacity
    pub total_capacity: i128,
    /// Average capacity
    pub avg_capacity: f64,
    /// Total balance
    pub total_balance: i128,
    /// Average balance
    pub avg_balance: f64,
    /// Utilization rate
    pub utilization_rate: f64,
    /// Capacity distribution
    pub capacity_distribution: HashMap<String, usize>,
}

/// Statistics calculator
pub struct StatisticsCalculator;

impl StatisticsCalculator {
    /// Calculate comprehensive network statistics
    pub fn calculate_network_stats(graph: &NetworkGraph) -> NetworkStats {
        let num_nodes = graph.num_nodes();
        let num_channels = graph.num_channels();

        // Calculate degree distribution
        let degrees: Vec<usize> = graph
            .adjacency
            .values()
            .map(|neighbors| neighbors.len())
            .collect();

        let avg_degree = if num_nodes > 0 {
            degrees.iter().sum::<usize>() as f64 / num_nodes as f64
        } else {
            0.0
        };

        let max_degree = degrees.iter().max().copied().unwrap_or(0);
        let min_degree = degrees.iter().min().copied().unwrap_or(0);

        // Calculate density
        let max_possible_edges = num_nodes * (num_nodes - 1) / 2;
        let density = if max_possible_edges > 0 {
            num_channels as f64 / max_possible_edges as f64
        } else {
            0.0
        };

        // Calculate degree distribution
        let mut degree_dist = HashMap::new();
        for d in &degrees {
            *degree_dist.entry(*d).or_insert(0) += 1;
        }

        NetworkStats {
            num_nodes,
            num_channels,
            density,
            avg_degree,
            max_degree,
            min_degree,
            avg_path_length: 0.0, // Would need BFS calculation
            diameter: 0,
            clustering_coefficient: 0.0, // Would need local calculation
            connected_components: 1,     // Would need component calculation
            degree_distribution: degree_dist,
        }
    }

    /// Calculate degree statistics
    pub fn calculate_degree_stats(graph: &NetworkGraph) -> DegreeStats {
        let degrees: Vec<usize> = graph
            .adjacency
            .values()
            .map(|neighbors| neighbors.len())
            .collect();

        if degrees.is_empty() {
            return DegreeStats {
                mean: 0.0,
                median: 0.0,
                std_dev: 0.0,
                mode: 0,
            };
        }

        let sum: usize = degrees.iter().sum();
        let mean = sum as f64 / degrees.len() as f64;

        let mut sorted = degrees.clone();
        sorted.sort();
        let median = if sorted.len().is_multiple_of(2) {
            (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) as f64 / 2.0
        } else {
            sorted[sorted.len() / 2] as f64
        };

        let variance: f64 = degrees
            .iter()
            .map(|d| (*d as f64 - mean).powi(2))
            .sum::<f64>()
            / degrees.len() as f64;
        let std_dev = variance.sqrt();

        // Find mode
        let mut counts = HashMap::new();
        for d in &degrees {
            *counts.entry(*d).or_insert(0) += 1;
        }
        let mode = counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(d, _)| d)
            .unwrap_or(0);

        DegreeStats {
            mean,
            median,
            std_dev,
            mode,
        }
    }

    /// Calculate path statistics using BFS
    pub fn calculate_path_stats(graph: &NetworkGraph, sample_size: usize) -> PathStats {
        let nodes: Vec<String> = graph.nodes.keys().cloned().collect();
        let mut all_paths = Vec::new();

        let sample = nodes
            .iter()
            .take(sample_size.min(nodes.len()))
            .cloned()
            .collect::<Vec<_>>();

        for source in &sample {
            for dest in &sample {
                if source != dest {
                    if let Some(path_len) = Self::bfs_shortest_path(graph, source, dest) {
                        all_paths.push(path_len);
                    }
                }
            }
        }

        if all_paths.is_empty() {
            return PathStats {
                avg_length: 0.0,
                median_length: 0.0,
                max_length: 0,
                std_dev: 0.0,
                histogram: HashMap::new(),
            };
        }

        let avg = all_paths.iter().sum::<usize>() as f64 / all_paths.len() as f64;

        let mut sorted = all_paths.clone();
        sorted.sort();
        let median = if sorted.len() % 2 == 0 {
            (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) as f64 / 2.0
        } else {
            sorted[sorted.len() / 2] as f64
        };

        let max = *sorted.iter().max().unwrap_or(&0);

        let variance = all_paths
            .iter()
            .map(|l| (*l as f64 - avg).powi(2))
            .sum::<f64>()
            / all_paths.len() as f64;
        let std_dev = variance.sqrt();

        let mut histogram = HashMap::new();
        for len in &all_paths {
            *histogram.entry(*len).or_insert(0) += 1;
        }

        PathStats {
            avg_length: avg,
            median_length: median,
            max_length: max,
            std_dev,
            histogram,
        }
    }

    /// BFS to find shortest path
    fn bfs_shortest_path(graph: &NetworkGraph, source: &str, dest: &str) -> Option<usize> {
        use std::collections::{HashSet, VecDeque};

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        visited.insert(source.to_string());
        queue.push_back((source.to_string(), 0));

        while let Some((node, dist)) = queue.pop_front() {
            if node == dest {
                return Some(dist);
            }

            if let Some(neighbors) = graph.adjacency.get(&node) {
                for neighbor in neighbors.keys() {
                    if !visited.contains(neighbor) {
                        visited.insert(neighbor.clone());
                        queue.push_back((neighbor.clone(), dist + 1));
                    }
                }
            }
        }

        None
    }

    /// Calculate channel statistics
    pub fn calculate_channel_stats(graph: &NetworkGraph) -> ChannelStats {
        let channels: Vec<_> = graph.channels.values().collect();

        if channels.is_empty() {
            return ChannelStats {
                total_capacity: 0,
                avg_capacity: 0.0,
                total_balance: 0,
                avg_balance: 0.0,
                utilization_rate: 0.0,
                capacity_distribution: HashMap::new(),
            };
        }

        let total_capacity: i128 = channels
            .iter()
            .map(|c| c.capacity_a_to_b + c.capacity_b_to_a)
            .sum();

        let avg_capacity = total_capacity as f64 / channels.len() as f64;

        let total_balance: i128 = channels
            .iter()
            .map(|c| c.capacity_a_to_b.min(c.capacity_b_to_a) * 2)
            .sum();

        let avg_balance = total_balance as f64 / channels.len() as f64;

        let utilization_rate = if total_capacity > 0 {
            total_balance as f64 / (total_capacity as f64 * 2.0)
        } else {
            0.0
        };

        // Capacity distribution
        let mut dist = HashMap::new();
        dist.insert(
            "very_low".to_string(),
            channels
                .iter()
                .filter(|c| {
                    let cap = c.capacity_a_to_b + c.capacity_b_to_a;
                    cap < 10_000_000
                })
                .count(),
        );
        dist.insert(
            "low".to_string(),
            channels
                .iter()
                .filter(|c| {
                    let cap = c.capacity_a_to_b + c.capacity_b_to_a;
                    (10_000_000..1_000_000_000).contains(&cap)
                })
                .count(),
        );
        dist.insert(
            "medium".to_string(),
            channels
                .iter()
                .filter(|c| {
                    let cap = c.capacity_a_to_b + c.capacity_b_to_a;
                    (1_000_000_000..10_000_000_000).contains(&cap)
                })
                .count(),
        );
        dist.insert(
            "high".to_string(),
            channels
                .iter()
                .filter(|c| {
                    let cap = c.capacity_a_to_b + c.capacity_b_to_a;
                    cap >= 10_000_000_000
                })
                .count(),
        );

        ChannelStats {
            total_capacity,
            avg_capacity,
            total_balance,
            avg_balance,
            utilization_rate,
            capacity_distribution: dist,
        }
    }

    /// Calculate success rate statistics
    pub fn calculate_success_stats(stats: &SimulationStats) -> HashMap<String, f64> {
        let mut result = HashMap::new();

        result.insert("success_rate".to_string(), stats.success_rate);
        result.insert("failure_rate".to_string(), 100.0 - stats.success_rate);
        result.insert("avg_path_length".to_string(), stats.avg_path_length);

        if stats.successful_payments > 0 {
            let avg_value = stats.total_value_routed as f64 / stats.successful_payments as f64;
            let avg_fee = stats.total_fees_collected as f64 / stats.successful_payments as f64;
            result.insert("avg_payment_value".to_string(), avg_value);
            result.insert("avg_fee".to_string(), avg_fee);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_degree_stats() {
        // Create a simple test graph
        let mut graph = NetworkGraph::new();

        for i in 0..5 {
            graph.add_node(channel_router::Node {
                id: format!("n{}", i),
                public_key: vec![],
                alias: None,
                online: true,
                last_seen: 0,
                features: channel_router::NodeFeatures::default(),
            });
        }

        // Add some edges
        graph.add_channel(channel_router::Channel {
            id: "c1".to_string(),
            node_a: "n0".to_string(),
            node_b: "n1".to_string(),
            capacity_a_to_b: 1000,
            capacity_b_to_a: 1000,
            base_fee: 1,
            fee_rate: 1000,
            cltv_delta: 40,
            min_htlc_size: 1,
            max_htlc_size: 2000,
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 0,
        });

        graph.add_channel(channel_router::Channel {
            id: "c2".to_string(),
            node_a: "n0".to_string(),
            node_b: "n2".to_string(),
            capacity_a_to_b: 1000,
            capacity_b_to_a: 1000,
            base_fee: 1,
            fee_rate: 1000,
            cltv_delta: 40,
            min_htlc_size: 1,
            max_htlc_size: 2000,
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 0,
        });

        let stats = StatisticsCalculator::calculate_degree_stats(&graph);
        assert_eq!(stats.mean, 0.8); // 4 total connections / 5 nodes
    }
}

// =========================================================================
// Enhancements for Issues #383, #386: Failure Summaries & Hop Length Metrics
// =========================================================================

/// Reason a simulated payment failed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FailureReason {
    /// No route exists connecting source and destination
    NoRouteFound,
    /// Insufficient channel balance / liquidity on candidate path
    InsufficientLiquidity,
    /// Route fees exceeded the sender's fee budget
    FeeExceededBudget,
    /// Route exceeded maximum permitted hop count
    MaxHopsExceeded,
    /// Channel liquidity completely depleted due to previous volume
    ChannelDepleted,
    /// Invalid payment parameters (e.g. non-positive amount)
    InvalidAmount,
    /// Source equals destination
    SourceEqualsDestination,
    /// Node was offline or unreachable
    NodeOffline,
    /// Unknown or generic error
    Other,
}

impl std::fmt::Display for FailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailureReason::NoRouteFound => write!(f, "NoRouteFound"),
            FailureReason::InsufficientLiquidity => write!(f, "InsufficientLiquidity"),
            FailureReason::FeeExceededBudget => write!(f, "FeeExceededBudget"),
            FailureReason::MaxHopsExceeded => write!(f, "MaxHopsExceeded"),
            FailureReason::ChannelDepleted => write!(f, "ChannelDepleted"),
            FailureReason::InvalidAmount => write!(f, "InvalidAmount"),
            FailureReason::SourceEqualsDestination => write!(f, "SourceEqualsDestination"),
            FailureReason::NodeOffline => write!(f, "NodeOffline"),
            FailureReason::Other => write!(f, "Other"),
        }
    }
}

/// Detailed diagnostic for a failed payment scenario (Issue #386)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedPaymentDetail {
    pub source: String,
    pub destination: String,
    pub amount: i128,
    pub reason: FailureReason,
    pub details: String,
}

/// Comprehensive summary of failed payment scenarios (Issue #386)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FailedPaymentSummary {
    pub total_failures: usize,
    pub by_reason: HashMap<FailureReason, usize>,
    pub samples: Vec<FailedPaymentDetail>,
}

impl FailedPaymentSummary {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_failure(
        &mut self,
        source: String,
        destination: String,
        amount: i128,
        reason: FailureReason,
        details: String,
    ) {
        self.total_failures += 1;
        *self.by_reason.entry(reason).or_insert(0) += 1;
        if self.samples.len() < 100 {
            self.samples.push(FailedPaymentDetail {
                source,
                destination,
                amount,
                reason,
                details,
            });
        }
    }

    pub fn format_report(&self) -> String {
        let mut report = format!("Failed Payment Summary: total={}\n", self.total_failures);
        for (reason, count) in &self.by_reason {
            let pct = if self.total_failures > 0 {
                (*count as f64 / self.total_failures as f64) * 100.0
            } else {
                0.0
            };
            report.push_str(&format!("  - {}: {} ({:.1}%)\n", reason, count, pct));
        }
        report
    }
}

/// Success and cost metrics broken down by route length / hops (Issue #383)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HopLengthMetrics {
    pub attempts: usize,
    pub successes: usize,
    pub failures: usize,
    pub success_rate: f64,
    pub total_fees: i128,
    pub avg_fee: f64,
}

impl HopLengthMetrics {
    pub fn record_attempt(&mut self) {
        self.attempts += 1;
        self.update_rate();
    }

    pub fn record_success(&mut self, fee: i128) {
        self.successes += 1;
        self.total_fees += fee;
        self.avg_fee = self.total_fees as f64 / self.successes as f64;
        self.update_rate();
    }

    pub fn record_failure(&mut self) {
        self.failures += 1;
        self.update_rate();
    }

    fn update_rate(&mut self) {
        if self.attempts > 0 {
            self.success_rate = (self.successes as f64 / self.attempts as f64) * 100.0;
        }
    }
}

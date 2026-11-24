//! # Node Disconnection and Recovery
//!
//! Models temporary node disconnections and subsequent recoveries during
//! payment-channel network simulations and topology fuzzing.
//!
//! When a node disconnects:
//! - Its `online` flag is set to `false` in both [`NetworkGraph`] and [`SimulatedNode`].
//! - Its active channels are temporarily suspended (removed from the routable graph
//!   and from both endpoints' [`SimulatedNode::channels`] sets) and stored in a
//!   [`DisconnectionTracker`].
//!
//! When a node recovers:
//! - Its `online` flag is restored to `true`.
//! - Each suspended channel touching the node is restored to [`NetworkGraph`] and
//!   [`SimulatedNode::channels`] **only if the peer endpoint is also online**.
//!   If the peer is still disconnected, the channel remains suspended until both
//!   endpoints have recovered.
//!
//! This preserves all [`NetworkGraph`] and [`SimulatedNode`] structural invariants
//! throughout partial outages and guarantees that no pathfinder can route through
//! an offline node.

use crate::{SimulatedNode, SimulatorError};
use channel_router::{Channel, NetworkGraph};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// Upper bound on `max_downtime_steps` to guarantee bounded execution.
pub const MAX_DOWNTIME_STEPS: usize = 1_000_000;

/// Configuration for temporary node disconnections and recovery during a simulation.
///
/// # Compatibility
///
/// [`SimulatorConfig::disconnection`](crate::SimulatorConfig::disconnection) defaults
/// to `None`, so callers that do not configure disconnection modeling observe the exact
/// same behavior and RNG sequence as before.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DisconnectionConfig {
    /// Per-step probability in `[0.0, 1.0]` that an online node disconnects.
    pub disconnect_probability: f64,
    /// Minimum number of simulation steps a disconnected node stays offline (`>= 1`).
    pub min_downtime_steps: usize,
    /// Maximum number of simulation steps a disconnected node stays offline
    /// (`>= min_downtime_steps`, `<= MAX_DOWNTIME_STEPS`).
    pub max_downtime_steps: usize,
    /// Optional cap on how many nodes may be disconnected simultaneously.
    /// `None` allows any number of nodes to be disconnected concurrently.
    pub max_concurrent_disconnections: Option<usize>,
    /// Whether to recover any remaining offline nodes at the end of the simulation.
    pub recover_at_end: bool,
}

impl Default for DisconnectionConfig {
    fn default() -> Self {
        Self {
            disconnect_probability: 0.05,
            min_downtime_steps: 2,
            max_downtime_steps: 10,
            max_concurrent_disconnections: None,
            recover_at_end: true,
        }
    }
}

impl DisconnectionConfig {
    /// Validate configuration parameters explicitly without substituting defaults.
    pub fn validate(&self) -> Result<(), SimulatorError> {
        if !self.disconnect_probability.is_finite()
            || !(0.0..=1.0).contains(&self.disconnect_probability)
        {
            return Err(SimulatorError::InvalidConfig(format!(
                "disconnect_probability must be finite and in [0.0, 1.0], got {}",
                self.disconnect_probability
            )));
        }

        if self.min_downtime_steps == 0 {
            return Err(SimulatorError::InvalidConfig(
                "min_downtime_steps must be at least 1".to_string(),
            ));
        }

        if self.max_downtime_steps < self.min_downtime_steps {
            return Err(SimulatorError::InvalidConfig(format!(
                "max_downtime_steps ({}) must be >= min_downtime_steps ({})",
                self.max_downtime_steps, self.min_downtime_steps
            )));
        }

        if self.max_downtime_steps > MAX_DOWNTIME_STEPS {
            return Err(SimulatorError::InvalidConfig(format!(
                "max_downtime_steps ({}) exceeds maximum bound ({MAX_DOWNTIME_STEPS})",
                self.max_downtime_steps
            )));
        }

        Ok(())
    }
}

/// Bookkeeping for a currently disconnected node.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OfflineNodeState {
    disconnected_at_step: usize,
    recover_at_step: Option<usize>,
}

/// Tracks disconnected nodes and their suspended channels so they can be
/// cleanly restored upon recovery without violating graph invariants.
#[derive(Debug, Clone, Default)]
pub struct DisconnectionTracker {
    /// Offline nodes keyed by node ID in deterministic order.
    offline_nodes: BTreeMap<String, OfflineNodeState>,
    /// Channels suspended while at least one endpoint is offline, keyed by channel ID.
    suspended_channels: BTreeMap<String, Channel>,
}

impl DisconnectionTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of nodes currently disconnected.
    pub fn offline_count(&self) -> usize {
        self.offline_nodes.len()
    }

    /// Number of channels currently suspended due to offline endpoints.
    pub fn suspended_channel_count(&self) -> usize {
        self.suspended_channels.len()
    }

    /// Sorted list of currently disconnected node IDs.
    pub fn offline_node_ids(&self) -> Vec<String> {
        self.offline_nodes.keys().cloned().collect()
    }

    /// Check whether a node is currently tracked as offline.
    pub fn is_offline(&self, node_id: &str) -> bool {
        self.offline_nodes.contains_key(node_id)
    }

    /// Disconnect `node_id` at `step`, optionally scheduling automatic recovery at
    /// `recover_at_step`.
    ///
    /// Returns the number of channels suspended. On error, no state is modified.
    pub fn disconnect_node<S: std::hash::BuildHasher>(
        &mut self,
        graph: &mut NetworkGraph,
        nodes: &mut HashMap<String, SimulatedNode, S>,
        node_id: &str,
        step: usize,
        recover_at_step: Option<usize>,
    ) -> Result<usize, SimulatorError> {
        if !graph.has_node(node_id) || !nodes.contains_key(node_id) {
            return Err(SimulatorError::UnknownNode(node_id.to_string()));
        }

        if self.offline_nodes.contains_key(node_id)
            || !nodes[node_id].node.online
            || !graph
                .get_node(node_id)
                .is_some_and(|node| node.online)
        {
            return Err(SimulatorError::InvalidNodeState(format!(
                "node '{node_id}' is already disconnected"
            )));
        }

        if let Some(target_step) = recover_at_step {
            if target_step <= step {
                return Err(SimulatorError::InvalidConfig(format!(
                    "recover_at_step ({target_step}) must be greater than current step ({step})"
                )));
            }
        }

        let mut channel_ids: Vec<String> = graph
            .node_channels
            .get(node_id)
            .map(|ids| ids.iter().cloned().collect())
            .unwrap_or_default();
        channel_ids.sort();

        let mut suspended_count = 0;
        for channel_id in channel_ids {
            if let Some(channel) = graph.get_channel(&channel_id).cloned() {
                graph.remove_channel(&channel_id);
                if let Some(node_a) = nodes.get_mut(&channel.node_a) {
                    node_a.channels.remove(&channel.node_b);
                }
                if let Some(node_b) = nodes.get_mut(&channel.node_b) {
                    node_b.channels.remove(&channel.node_a);
                }
                self.suspended_channels.insert(channel_id, channel);
                suspended_count += 1;
            }
        }

        if let Some(graph_node) = graph.nodes.get_mut(node_id) {
            graph_node.online = false;
            graph_node.last_seen = step as u64;
        }
        if let Some(sim_node) = nodes.get_mut(node_id) {
            sim_node.node.online = false;
            sim_node.node.last_seen = step as u64;
        }

        self.offline_nodes.insert(
            node_id.to_string(),
            OfflineNodeState {
                disconnected_at_step: step,
                recover_at_step,
            },
        );

        Ok(suspended_count)
    }

    /// Recover `node_id` at `step`, restoring all suspended channels whose other
    /// endpoint is also online.
    ///
    /// Returns the number of channels restored to the active graph. On error, no
    /// state is modified.
    pub fn recover_node<S: std::hash::BuildHasher>(
        &mut self,
        graph: &mut NetworkGraph,
        nodes: &mut HashMap<String, SimulatedNode, S>,
        node_id: &str,
        step: usize,
    ) -> Result<usize, SimulatorError> {
        if !graph.has_node(node_id) || !nodes.contains_key(node_id) {
            return Err(SimulatorError::UnknownNode(node_id.to_string()));
        }

        if !self.offline_nodes.contains_key(node_id) {
            return Err(SimulatorError::InvalidNodeState(format!(
                "node '{node_id}' is not disconnected"
            )));
        }

        self.offline_nodes.remove(node_id);

        if let Some(graph_node) = graph.nodes.get_mut(node_id) {
            graph_node.online = true;
            graph_node.last_seen = step as u64;
        }
        if let Some(sim_node) = nodes.get_mut(node_id) {
            sim_node.node.online = true;
            sim_node.node.last_seen = step as u64;
        }

        let restorable_ids: Vec<String> = self
            .suspended_channels
            .iter()
            .filter(|(_, ch)| {
                (ch.node_a == node_id || ch.node_b == node_id)
                    && !self.offline_nodes.contains_key(&ch.node_a)
                    && !self.offline_nodes.contains_key(&ch.node_b)
            })
            .map(|(id, _)| id.clone())
            .collect();

        let mut restored_count = 0;
        for channel_id in restorable_ids {
            if let Some(channel) = self.suspended_channels.remove(&channel_id) {
                if let Some(node_a) = nodes.get_mut(&channel.node_a) {
                    node_a.channels.insert(channel.node_b.clone());
                }
                if let Some(node_b) = nodes.get_mut(&channel.node_b) {
                    node_b.channels.insert(channel.node_a.clone());
                }
                graph.add_channel(channel);
                restored_count += 1;
            }
        }

        Ok(restored_count)
    }

    /// Recover all nodes whose scheduled `recover_at_step` is `<= step`.
    ///
    /// Returns the number of nodes recovered.
    pub fn recover_due_nodes<S: std::hash::BuildHasher>(
        &mut self,
        graph: &mut NetworkGraph,
        nodes: &mut HashMap<String, SimulatedNode, S>,
        step: usize,
    ) -> Result<usize, SimulatorError> {
        let due: Vec<String> = self
            .offline_nodes
            .iter()
            .filter(|(_, state)| {
                state
                    .recover_at_step
                    .is_some_and(|recover_at| recover_at <= step)
            })
            .map(|(id, _)| id.clone())
            .collect();

        let mut recovered = 0;
        for node_id in due {
            self.recover_node(graph, nodes, &node_id, step)?;
            recovered += 1;
        }
        Ok(recovered)
    }

    /// Recover all currently disconnected nodes at `step`.
    ///
    /// Returns the number of nodes recovered.
    pub fn recover_all<S: std::hash::BuildHasher>(
        &mut self,
        graph: &mut NetworkGraph,
        nodes: &mut HashMap<String, SimulatedNode, S>,
        step: usize,
    ) -> Result<usize, SimulatorError> {
        let offline = self.offline_node_ids();
        let mut recovered = 0;
        for node_id in offline {
            self.recover_node(graph, nodes, &node_id, step)?;
            recovered += 1;
        }
        Ok(recovered)
    }

    /// Apply one step of probabilistic disconnections according to `config`.
    ///
    /// Iterates node IDs in sorted order so results are fully deterministic for a
    /// given RNG seed. Returns the number of nodes disconnected in this step.
    pub fn step_random_disconnections<R: Rng, S: std::hash::BuildHasher>(
        &mut self,
        graph: &mut NetworkGraph,
        nodes: &mut HashMap<String, SimulatedNode, S>,
        step: usize,
        config: &DisconnectionConfig,
        rng: &mut R,
    ) -> Result<usize, SimulatorError> {
        config.validate()?;

        if config.disconnect_probability == 0.0
            || config.max_concurrent_disconnections == Some(0)
        {
            return Ok(0);
        }

        let mut online_ids: Vec<String> = nodes
            .iter()
            .filter(|(id, sim_node)| {
                sim_node.node.online && !self.offline_nodes.contains_key(id.as_str())
            })
            .map(|(id, _)| id.clone())
            .collect();
        online_ids.sort();

        let mut disconnected = 0;
        for node_id in online_ids {
            if let Some(limit) = config.max_concurrent_disconnections {
                if self.offline_nodes.len() >= limit {
                    break;
                }
            }

            if rng.gen::<f64>() < config.disconnect_probability {
                let downtime = rng.gen_range(config.min_downtime_steps..=config.max_downtime_steps);
                let recover_at = step.saturating_add(downtime);
                self.disconnect_node(graph, nodes, &node_id, step, Some(recover_at))?;
                disconnected += 1;
            }
        }

        Ok(disconnected)
    }

    /// Reset all tracking state (used when re-initializing a network).
    pub fn clear(&mut self) {
        self.offline_nodes.clear();
        self.suspended_channels.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzz::verify_topology;
    use channel_router::{Node, NodeFeatures};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::collections::HashSet;

    fn sample_network() -> (NetworkGraph, HashMap<String, SimulatedNode>) {
        let mut graph = NetworkGraph::new();
        let mut nodes = HashMap::new();

        for id in ["n0", "n1", "n2"] {
            let node = Node {
                id: id.to_string(),
                public_key: vec![1; 32],
                alias: Some(id.to_string()),
                online: true,
                last_seen: 0,
                features: NodeFeatures::default(),
            };
            graph.add_node(node.clone());
            nodes.insert(
                id.to_string(),
                SimulatedNode {
                    node,
                    balance: 0,
                    channels: HashSet::new(),
                },
            );
        }

        for (cid, a, b) in [("ch01", "n0", "n1"), ("ch12", "n1", "n2")] {
            graph.add_channel(Channel {
                id: cid.to_string(),
                node_a: a.to_string(),
                node_b: b.to_string(),
                capacity_a_to_b: 50_000,
                capacity_b_to_a: 50_000,
                base_fee: 1,
                fee_rate: 100,
                cltv_delta: 10,
                min_htlc_size: 1,
                max_htlc_size: 100_000,
                htlcs_in_flight: 0,
                enabled: true,
                age_seconds: 0,
            });
            nodes.get_mut(a).unwrap().channels.insert(b.to_string());
            nodes.get_mut(b).unwrap().channels.insert(a.to_string());
        }

        (graph, nodes)
    }

    #[test]
    fn config_validation_rejects_invalid_inputs() {
        let invalid_probs = [-0.1, 1.01, f64::NAN, f64::INFINITY, f64::NEG_INFINITY];
        for prob in invalid_probs {
            let cfg = DisconnectionConfig {
                disconnect_probability: prob,
                ..Default::default()
            };
            assert!(cfg.validate().is_err(), "expected error for prob {prob}");
        }

        let zero_min = DisconnectionConfig {
            min_downtime_steps: 0,
            ..Default::default()
        };
        assert!(zero_min.validate().is_err());

        let inverted_bounds = DisconnectionConfig {
            min_downtime_steps: 5,
            max_downtime_steps: 3,
            ..Default::default()
        };
        assert!(inverted_bounds.validate().is_err());

        let excessive_max = DisconnectionConfig {
            max_downtime_steps: MAX_DOWNTIME_STEPS + 1,
            ..Default::default()
        };
        assert!(excessive_max.validate().is_err());
    }

    #[test]
    fn config_validation_accepts_boundary_values() {
        let zero_prob = DisconnectionConfig {
            disconnect_probability: 0.0,
            min_downtime_steps: 1,
            max_downtime_steps: 1,
            max_concurrent_disconnections: Some(0),
            recover_at_end: false,
        };
        assert!(zero_prob.validate().is_ok());

        let max_prob = DisconnectionConfig {
            disconnect_probability: 1.0,
            min_downtime_steps: 1,
            max_downtime_steps: MAX_DOWNTIME_STEPS,
            max_concurrent_disconnections: Some(10),
            recover_at_end: true,
        };
        assert!(max_prob.validate().is_ok());
    }

    #[test]
    fn disconnect_and_recover_preserve_topology_invariants() {
        let (mut graph, mut nodes) = sample_network();
        let mut tracker = DisconnectionTracker::new();

        let suspended = tracker
            .disconnect_node(&mut graph, &mut nodes, "n1", 1, Some(4))
            .unwrap();
        assert_eq!(suspended, 2);
        assert_eq!(tracker.offline_count(), 1);
        assert_eq!(tracker.suspended_channel_count(), 2);
        assert!(!graph.get_node("n1").unwrap().online);
        assert!(!nodes["n1"].node.online);
        assert_eq!(graph.num_channels(), 0);
        verify_topology(&graph, &nodes).unwrap();

        // Not due yet at step 3
        assert_eq!(
            tracker
                .recover_due_nodes(&mut graph, &mut nodes, 3)
                .unwrap(),
            0
        );
        assert_eq!(tracker.offline_count(), 1);

        // Due at step 4
        assert_eq!(
            tracker
                .recover_due_nodes(&mut graph, &mut nodes, 4)
                .unwrap(),
            1
        );
        assert_eq!(tracker.offline_count(), 0);
        assert_eq!(tracker.suspended_channel_count(), 0);
        assert!(graph.get_node("n1").unwrap().online);
        assert!(nodes["n1"].node.online);
        assert_eq!(graph.num_channels(), 2);
        verify_topology(&graph, &nodes).unwrap();
    }

    #[test]
    fn overlapping_adjacent_disconnections_restore_shared_channel_only_when_both_online() {
        let (mut graph, mut nodes) = sample_network();
        let mut tracker = DisconnectionTracker::new();

        assert_eq!(
            tracker
                .disconnect_node(&mut graph, &mut nodes, "n0", 0, None)
                .unwrap(),
            1
        );
        assert_eq!(
            tracker
                .disconnect_node(&mut graph, &mut nodes, "n1", 0, None)
                .unwrap(),
            1
        );
        verify_topology(&graph, &nodes).unwrap();

        // Recovering n0 while n1 is still offline must NOT restore ch01 yet.
        assert_eq!(
            tracker
                .recover_node(&mut graph, &mut nodes, "n0", 1)
                .unwrap(),
            0
        );
        assert_eq!(graph.num_channels(), 0);
        verify_topology(&graph, &nodes).unwrap();

        // Recovering n1 restores both ch01 and ch12.
        assert_eq!(
            tracker
                .recover_node(&mut graph, &mut nodes, "n1", 2)
                .unwrap(),
            2
        );
        assert_eq!(graph.num_channels(), 2);
        verify_topology(&graph, &nodes).unwrap();
    }

    #[test]
    fn error_cases_do_not_mutate_state() {
        let (mut graph, mut nodes) = sample_network();
        let mut tracker = DisconnectionTracker::new();

        assert!(matches!(
            tracker.disconnect_node(&mut graph, &mut nodes, "unknown", 0, None),
            Err(SimulatorError::UnknownNode(_))
        ));
        assert!(matches!(
            tracker.recover_node(&mut graph, &mut nodes, "n0", 0),
            Err(SimulatorError::InvalidNodeState(_))
        ));
        assert!(matches!(
            tracker.disconnect_node(&mut graph, &mut nodes, "n0", 5, Some(5)),
            Err(SimulatorError::InvalidConfig(_))
        ));

        // State must remain completely untouched
        assert_eq!(graph.num_channels(), 2);
        assert_eq!(tracker.offline_count(), 0);
        assert!(nodes["n0"].node.online);

        tracker
            .disconnect_node(&mut graph, &mut nodes, "n0", 0, None)
            .unwrap();
        assert!(matches!(
            tracker.disconnect_node(&mut graph, &mut nodes, "n0", 1, None),
            Err(SimulatorError::InvalidNodeState(_))
        ));
        assert_eq!(tracker.offline_count(), 1);
    }

    #[test]
    fn step_random_disconnections_is_deterministic_and_bounded() {
        let cfg = DisconnectionConfig {
            disconnect_probability: 0.5,
            min_downtime_steps: 2,
            max_downtime_steps: 4,
            max_concurrent_disconnections: Some(2),
            recover_at_end: true,
        };

        let (mut g1, mut n1) = sample_network();
        let mut t1 = DisconnectionTracker::new();
        let mut rng1 = StdRng::seed_from_u64(12345);
        let d1 = t1
            .step_random_disconnections(&mut g1, &mut n1, 0, &cfg, &mut rng1)
            .unwrap();

        let (mut g2, mut n2) = sample_network();
        let mut t2 = DisconnectionTracker::new();
        let mut rng2 = StdRng::seed_from_u64(12345);
        let d2 = t2
            .step_random_disconnections(&mut g2, &mut n2, 0, &cfg, &mut rng2)
            .unwrap();

        assert_eq!(d1, d2);
        assert_eq!(t1.offline_node_ids(), t2.offline_node_ids());
        assert!(t1.offline_count() <= 2);
    }
}

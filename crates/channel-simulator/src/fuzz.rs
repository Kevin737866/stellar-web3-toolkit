//! # Topology Fuzzing
//!
//! Randomized generation of payment channel topologies, with every generated
//! network and every route found on it checked against a set of invariants.
//!
//! The topology generators are the part of the simulator that is hardest to
//! unit test: each of the seven shapes has its own edge cases around duplicate
//! edges, wrap-around connections and degenerate node counts, and a mistake
//! there does not fail loudly -- it quietly produces a graph whose adjacency
//! list disagrees with its channel set, after which every routing result is
//! meaningless. Fuzzing them together, over random sizes and parameters, is
//! what catches that class of bug.
//!
//! Invariants checked per topology:
//!
//! * every channel endpoint exists as a node
//! * channel ids are unique and no two channels join the same node pair
//! * adjacency is symmetric and agrees with `node_channels`
//! * every node's `SimulatedNode::channels` matches the graph's adjacency
//! * capacities are non-negative and consistent with the HTLC bounds
//! * generated fee schedules respect the router's protocol fee cap
//!
//! Invariants checked per route:
//!
//! * the hops form a walk from the request source to the request destination
//! * every hop's channel exists and connects the expected pair
//! * hop amounts grow by exactly the upstream fees and fit the channel
//!   capacity in the direction of travel
//! * `total_fees` matches the hops and satisfies the protocol fee cap

use crate::disconnection::{DisconnectionConfig, DisconnectionTracker};
use crate::network::{NetworkTopology, TopologyType};
use crate::{SimulatedNode, SimulatorConfig, SimulatorError};
use channel_router::fee_cap::FeeCap;
use channel_router::pathfinder::Pathfinder;
use channel_router::{NetworkGraph, Route, RouteRequest};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::time::{Duration, Instant};

/// Every topology shape the generator knows about.
pub const ALL_TOPOLOGIES: [TopologyType; 7] = [
    TopologyType::Random,
    TopologyType::ScaleFree,
    TopologyType::SmallWorld,
    TopologyType::Grid,
    TopologyType::Star,
    TopologyType::Line,
    TopologyType::Ring,
];

/// Upper bound on a configured wall-clock budget for one fuzz run, in
/// milliseconds (24 hours). A larger value is rejected rather than clamped, so
/// a run cannot be configured to hang for an unbounded amount of time.
pub const MAX_FUZZ_DURATION_MS: u64 = 86_400_000;

/// How to fuzz.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TopologyFuzzConfig {
    /// Number of topologies to generate.
    pub iterations: usize,
    /// Master seed. Each iteration derives its own deterministic seed from it,
    /// so a failure is reproducible from `(seed, iteration)` alone.
    pub seed: u64,
    /// Optional wall-clock budget for the whole run, in milliseconds.
    ///
    /// The budget is checked between iterations, so a run stops as soon as the
    /// budget is spent instead of after `iterations` topologies, and reports
    /// [`FuzzTermination::DurationBudgetExceeded`].
    ///
    /// # Compatibility
    ///
    /// `None` (the default) preserves the previous behavior: the run is bounded
    /// by `iterations` alone.
    #[serde(default)]
    pub max_duration_ms: Option<u64>,
    /// Smallest node count to generate. Values below 3 are the interesting
    /// degenerate cases, so they are in range rather than excluded.
    pub min_nodes: usize,
    /// Largest node count to generate.
    pub max_nodes: usize,
    /// Payment attempts to route per topology.
    pub payments_per_topology: usize,
    /// Optional temporary node disconnection and recovery modeling per payment step.
    /// When `None`, all nodes stay online for the entire iteration.
    #[serde(default)]
    pub disconnection: Option<DisconnectionConfig>,
}

impl Default for TopologyFuzzConfig {
    fn default() -> Self {
        TopologyFuzzConfig {
            iterations: 64,
            seed: 0x00C0_FFEE,
            min_nodes: 2,
            max_nodes: 40,
            payments_per_topology: 25,
            disconnection: None,
            max_duration_ms: None,
        }
    }
}

/// Why a fuzz run stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum FuzzTermination {
    /// Every configured iteration ran.
    #[default]
    Completed,
    /// The run stopped early because `max_duration_ms` was exhausted.
    DurationBudgetExceeded,
}

impl FuzzTermination {
    /// Stable name for reports and logs.
    pub fn name(self) -> &'static str {
        match self {
            FuzzTermination::Completed => "completed",
            FuzzTermination::DurationBudgetExceeded => "duration-budget-exceeded",
        }
    }
}

/// A single invariant violation found while fuzzing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzFailure {
    /// Iteration the failure happened on.
    pub iteration: usize,
    /// Seed for that iteration, so it can be replayed in isolation.
    pub seed: u64,
    /// Master seed of the run that produced the failure, so the whole run can
    /// be replayed as well as the single iteration.
    pub run_seed: u64,
    /// Topology being generated.
    pub topology: TopologyType,
    /// Which check failed.
    pub invariant: &'static str,
    /// Free-form detail about the failure.
    pub detail: String,
}

impl FuzzFailure {
    /// A one-line replay instruction naming both the run seed and the iteration
    /// seed, so a failure can be reproduced without guessing what to pass.
    pub fn replay_hint(&self) -> String {
        format!(
            "replay with seed={:#018x} iteration={} (run seed={:#018x}, topology={}, invariant={})",
            self.seed,
            self.iteration,
            self.run_seed,
            self.topology_name(),
            self.invariant
        )
    }
}

/// Summary of a fuzz run.
#[derive(Debug, Clone, Default)]
pub struct FuzzReport {
    /// Master seed the run was configured with. Always reported, so a clean run
    /// and a failing one are equally replayable.
    pub seed: u64,
    /// Wall-clock time the run took, in milliseconds.
    pub elapsed_ms: u64,
    /// Why the run stopped.
    pub termination: FuzzTermination,
    /// The wall-clock budget the run was configured with, for reports.
    pub max_duration_ms: Option<u64>,
    /// Topologies generated.
    pub iterations: usize,
    /// Routes whose invariants were checked.
    pub routes_checked: usize,
    /// Payment attempts made across all topologies.
    pub payments_attempted: usize,
    /// Search runs, i.e. payment attempts times the number of algorithms.
    pub route_attempts: usize,
    /// Searches that produced a route.
    pub routes_found: usize,
    /// Topologies that had at least one route.
    pub routable_topologies: usize,
    /// Node disconnections simulated across all iterations.
    pub disconnections_simulated: usize,
    /// Node recoveries simulated across all iterations.
    pub recoveries_simulated: usize,
    /// Invariant violations.
    pub failures: Vec<FuzzFailure>,
}

impl FuzzReport {
    /// Whether every invariant held.
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }

    /// Whether the run stopped at the duration budget instead of running every
    /// configured iteration.
    pub fn was_truncated(&self) -> bool {
        self.termination == FuzzTermination::DurationBudgetExceeded
    }

    /// Fraction of topologies that had at least one route, as a percentage.
    pub fn routable_percent(&self) -> f64 {
        if self.iterations == 0 {
            return 0.0;
        }
        self.routable_topologies as f64 / self.iterations as f64 * 100.0
    }

    /// Human-readable summary, including the seed and the first few failures.
    ///
    /// The seed is always in the first line, so pasting the summary into a bug
    /// report is enough to replay the run.
    pub fn summarize(&self) -> String {
        let mut summary = format!(
            "topology fuzz: seed={:#018x} {} topologies in {}ms, {} payments attempted, {} routes found over {} searches, {} routes checked, {:.1}% of topologies routable, {} failures",
            self.seed,
            self.iterations,
            self.elapsed_ms,
            self.payments_attempted,
            self.routes_found,
            self.route_attempts,
            self.routes_checked,
            self.routable_percent(),
            self.failures.len()
        );

        if self.was_truncated() {
            let _ = write!(
                summary,
                "\n  run stopped early: duration budget of {}ms exhausted; replay with a smaller `iterations` or a larger budget",
                self.max_duration_ms.unwrap_or_default()
            );
        }

        for failure in self.failures.iter().take(5) {
            let _ = write!(
                summary,
                "\n  [{} iteration={} seed={:#018x}] {}: {}",
                failure.topology_name(),
                failure.iteration,
                failure.seed,
                failure.invariant,
                failure.detail
            );
        }

        if self.failures.len() > 5 {
            let _ = write!(summary, "\n  ... and {} more", self.failures.len() - 5);
        }

        summary
    }
}

impl FuzzFailure {
    /// Name of the topology, for reporting.
    pub fn topology_name(&self) -> &'static str {
        match self.topology {
            TopologyType::Random => "random",
            TopologyType::ScaleFree => "scale-free",
            TopologyType::SmallWorld => "small-world",
            TopologyType::Grid => "grid",
            TopologyType::Star => "star",
            TopologyType::Line => "line",
            TopologyType::Ring => "ring",
        }
    }
}

/// Structural invariants a generated topology must satisfy.
///
/// Returns the number of channels that were verified, or a description of the
/// first violation found.
pub fn verify_topology<S: std::hash::BuildHasher>(
    graph: &NetworkGraph,
    nodes: &HashMap<String, SimulatedNode, S>,
) -> Result<usize, String> {
    if graph.num_nodes() != nodes.len() {
        return Err(format!(
            "graph has {} nodes but {} simulated nodes exist",
            graph.num_nodes(),
            nodes.len()
        ));
    }

    for id in nodes.keys() {
        if !graph.has_node(id) {
            return Err(format!("simulated node {id} is missing from the graph"));
        }
    }

    let cap = FeeCap::protocol();
    let mut pairs: HashSet<(String, String)> = HashSet::new();

    for channel in graph.channels.values() {
        if !graph.has_node(&channel.node_a) {
            return Err(format!(
                "channel {} references unknown node_a {}",
                channel.id, channel.node_a
            ));
        }
        if !graph.has_node(&channel.node_b) {
            return Err(format!(
                "channel {} references unknown node_b {}",
                channel.id, channel.node_b
            ));
        }
        if channel.node_a == channel.node_b {
            return Err(format!("channel {} is a self-loop", channel.id));
        }
        if channel.capacity_a_to_b < 0 || channel.capacity_b_to_a < 0 {
            return Err(format!("channel {} has negative capacity", channel.id));
        }
        if channel.max_htlc_size < channel.min_htlc_size {
            return Err(format!(
                "channel {} has max_htlc_size {} below min_htlc_size {}",
                channel.id, channel.max_htlc_size, channel.min_htlc_size
            ));
        }

        // A topology the simulator generates has to be routable by the router,
        // so it must not advertise fees the router would refuse.
        cap.check_channel(channel)
            .map_err(|e| format!("channel {} breaks the protocol fee cap: {e}", channel.id))?;

        let mut endpoints = [channel.node_a.clone(), channel.node_b.clone()];
        endpoints.sort();
        if !pairs.insert((endpoints[0].clone(), endpoints[1].clone())) {
            return Err(format!(
                "nodes {} and {} are joined by more than one channel",
                endpoints[0], endpoints[1]
            ));
        }

        // Adjacency must point back at this channel from both ends.
        for (from, to) in [
            (&channel.node_a, &channel.node_b),
            (&channel.node_b, &channel.node_a),
        ] {
            let adjacency = graph
                .adjacency
                .get(from)
                .ok_or_else(|| format!("node {from} has no adjacency entry"))?;

            match adjacency.get(to) {
                Some(id) if id == &channel.id => {}
                Some(other) => {
                    return Err(format!(
                        "adjacency {from}->{to} points at {other}, not {}",
                        channel.id
                    ))
                }
                None => {
                    return Err(format!(
                        "adjacency is missing the {from}->{to} direction of {}",
                        channel.id
                    ))
                }
            }

            let channels = graph
                .node_channels
                .get(from)
                .ok_or_else(|| format!("node {from} has no channel list"))?;
            if !channels.contains(&channel.id) {
                return Err(format!(
                    "node_channels for {from} is missing {}",
                    channel.id
                ));
            }
        }
    }

    for (node_id, adjacency) in &graph.adjacency {
        let expected: HashSet<&String> = adjacency.values().collect();
        let recorded: HashSet<&String> = graph
            .node_channels
            .get(node_id)
            .map(|ids| ids.iter().collect())
            .unwrap_or_default();

        if expected != recorded {
            return Err(format!(
                "node {node_id} adjacency holds {} channels but node_channels holds {}",
                expected.len(),
                recorded.len()
            ));
        }

        // The simulator's per-node view has to agree with the graph, or the
        // degree-based generators will draw from a different topology than the
        // one routing runs on.
        let simulated = nodes
            .get(node_id)
            .ok_or_else(|| format!("missing simulated node {node_id}"))?;
        let neighbours: HashSet<String> = adjacency.keys().cloned().collect();
        if simulated.channels != neighbours {
            return Err(format!(
                "simulated node {node_id} lists {} channels but the graph has {}",
                simulated.channels.len(),
                neighbours.len()
            ));
        }
    }

    // Any channel listed by a node's adjacency must exist in the channel map.
    for adjacency in graph.adjacency.values() {
        for channel_id in adjacency.values() {
            if !graph.has_channel(channel_id) {
                return Err(format!("adjacency references unknown channel {channel_id}"));
            }
        }
    }

    Ok(graph.num_channels())
}

/// Routing invariants a route returned by a search must satisfy.
pub fn verify_route(
    graph: &NetworkGraph,
    request: &RouteRequest,
    route: &Route,
) -> Result<(), String> {
    if route.hops.is_empty() {
        return Err("route has no hops".to_string());
    }

    if route.hops.len() > request.max_hops.unwrap_or(channel_router::MAX_ROUTE_HOPS) {
        return Err(format!(
            "route has {} hops, above the request's limit",
            route.hops.len()
        ));
    }

    if route.total_amount != request.amount {
        return Err(format!(
            "route total_amount {} does not match the requested {}",
            route.total_amount, request.amount
        ));
    }

    let hop_sum: i128 = route.hops.iter().map(|hop| hop.fee).sum();
    if route.total_fees != hop_sum {
        return Err(format!(
            "route declares {} in fees but its hops sum to {}",
            route.total_fees, hop_sum
        ));
    }

    let mut current = request.source.clone();
    let mut expected_amount = request.amount;

    for (index, hop) in route.hops.iter().enumerate() {
        if hop.amount != expected_amount {
            return Err(format!(
                "hop {index} forwards {} but {} should have arrived",
                hop.amount, expected_amount
            ));
        }

        let channel = graph
            .get_channel(&hop.channel_id)
            .ok_or_else(|| format!("hop {index} uses unknown channel {}", hop.channel_id))?;

        let next = if channel.node_a == current {
            &channel.node_b
        } else if channel.node_b == current {
            &channel.node_a
        } else {
            return Err(format!(
                "hop {index} uses channel {} which does not touch {current}",
                hop.channel_id
            ));
        };

        if &hop.node_id != next {
            return Err(format!(
                "hop {index} names {} but channel {} leads to {next}",
                hop.node_id, hop.channel_id
            ));
        }

        let capacity = if channel.node_a == current {
            channel.capacity_a_to_b
        } else {
            channel.capacity_b_to_a
        };
        if capacity < hop.amount {
            return Err(format!(
                "hop {index} forwards {} over channel {} with only {capacity} of capacity",
                hop.amount, hop.channel_id
            ));
        }

        expected_amount = hop.amount + hop.fee;
        current.clone_from(next);
    }

    if current != request.destination {
        return Err(format!(
            "route ends at {current} instead of {}",
            request.destination
        ));
    }

    FeeCap::protocol()
        .check_route(request.amount, route)
        .map_err(|e| format!("route breaks the protocol fee cap: {e}"))?;

    Ok(())
}

/// Validate the inputs that bound a fuzz run.
///
/// Rejects rather than clamps: a zero or absurdly large budget is a caller
/// mistake, and silently substituting a different one would make the run's
/// duration depend on something the caller never asked for.
pub fn validate_run_limits(config: &TopologyFuzzConfig) -> Result<(), SimulatorError> {
    if let Some(ref disconnection) = config.disconnection {
        disconnection.validate()?;
    }

    match config.max_duration_ms {
        Some(0) => Err(SimulatorError::InvalidConfig(
            "max_duration_ms must be >= 1 when set; omit it for a run bounded only by `iterations`"
                .to_string(),
        )),
        Some(ms) if ms > MAX_FUZZ_DURATION_MS => Err(SimulatorError::InvalidConfig(format!(
            "max_duration_ms ({ms}) exceeds the maximum bound ({MAX_FUZZ_DURATION_MS})"
        ))),
        _ => Ok(()),
    }
}

/// Randomized topology fuzzer.
pub struct TopologyFuzzer {
    config: TopologyFuzzConfig,
}

impl TopologyFuzzer {
    /// Create a fuzzer with the given configuration.
    pub fn new(config: TopologyFuzzConfig) -> Self {
        TopologyFuzzer { config }
    }

    /// Create a fuzzer after validating its configuration.
    pub fn try_new(config: TopologyFuzzConfig) -> Result<Self, SimulatorError> {
        validate_run_limits(&config)?;
        Ok(TopologyFuzzer { config })
    }

    /// The configuration being used.
    pub fn config(&self) -> &TopologyFuzzConfig {
        &self.config
    }

    /// Validate configuration and run the fuzzer.
    pub fn try_run(&self) -> Result<FuzzReport, SimulatorError> {
        validate_run_limits(&self.config)?;
        Ok(self.run())
    }

    /// Generate and check topologies until the iteration count or the optional
    /// wall-clock budget is exhausted.
    ///
    /// The budget is checked between iterations, so the run always stops on an
    /// iteration boundary and the report says why it stopped.
    pub fn run(&self) -> FuzzReport {
        let started = Instant::now();
        let budget = self.config.max_duration_ms.map(Duration::from_millis);
        let mut report = FuzzReport {
            seed: self.config.seed,
            max_duration_ms: self.config.max_duration_ms,
            ..FuzzReport::default()
        };

        for iteration in 0..self.config.iterations {
            if budget.is_some_and(|limit| started.elapsed() >= limit) {
                report.termination = FuzzTermination::DurationBudgetExceeded;
                break;
            }

            self.run_iteration(iteration, &mut report);
        }

        report.elapsed_ms = started.elapsed().as_millis() as u64;
        report
    }

    /// Replay a single iteration, for reproducing a reported failure.
    pub fn run_iteration(&self, iteration: usize, report: &mut FuzzReport) {
        let seed = self.iteration_seed(iteration);
        let mut rng = StdRng::seed_from_u64(seed);
        let topology = ALL_TOPOLOGIES[iteration % ALL_TOPOLOGIES.len()];

        if let Some(ref disconnection) = self.config.disconnection {
            if let Err(err) = disconnection.validate() {
                report.iterations += 1;
                report.failures.push(FuzzFailure {
                    iteration,
                    seed,
                    run_seed: self.config.seed,
                    topology,
                    invariant: "config",
                    detail: err.to_string(),
                });
                return;
            }
        }

        let sim_config = self.random_sim_config(&mut rng);
        let (mut graph, mut nodes) = NetworkTopology::new(sim_config, topology).generate(&mut rng);

        report.iterations += 1;

        if let Err(detail) = verify_topology(&graph, &nodes) {
            report.failures.push(FuzzFailure {
                iteration,
                seed,
                run_seed: self.config.seed,
                topology,
                invariant: "topology",
                detail,
            });
            // Routing on a malformed graph would only produce noise.
            return;
        }

        let mut routed_here = false;
        let mut tracker = self
            .config
            .disconnection
            .as_ref()
            .map(|_| DisconnectionTracker::new());

        for payment_index in 0..self.config.payments_per_topology {
            if let (Some(churn_cfg), Some(churn_tracker)) =
                (self.config.disconnection.as_ref(), tracker.as_mut())
            {
                match churn_tracker.recover_due_nodes(&mut graph, &mut nodes, payment_index) {
                    Ok(n) => report.recoveries_simulated += n,
                    Err(err) => {
                        report.failures.push(FuzzFailure {
                            iteration,
                            seed,
                            run_seed: self.config.seed,
                            topology,
                            invariant: "recovery",
                            detail: format!("payment {payment_index}: {err}"),
                        });
                        return;
                    }
                }
                match churn_tracker.step_random_disconnections(
                    &mut graph,
                    &mut nodes,
                    payment_index,
                    churn_cfg,
                    &mut rng,
                ) {
                    Ok(n) => report.disconnections_simulated += n,
                    Err(err) => {
                        report.failures.push(FuzzFailure {
                            iteration,
                            seed,
                            run_seed: self.config.seed,
                            topology,
                            invariant: "disconnection",
                            detail: format!("payment {payment_index}: {err}"),
                        });
                        return;
                    }
                }
                if let Err(detail) = verify_topology(&graph, &nodes) {
                    report.failures.push(FuzzFailure {
                        iteration,
                        seed,
                        run_seed: self.config.seed,
                        topology,
                        invariant: "topology_after_churn",
                        detail: format!("payment {payment_index}: {detail}"),
                    });
                    return;
                }
            }

            // Fewer than two nodes, or no channels at all: nothing to route.
            let Some(request) = self.random_payment(&graph, &mut rng) else {
                if self.config.disconnection.is_some() {
                    // With churn enabled, nodes may recover on later steps.
                    continue;
                }
                break;
            };
            let pathfinder = Pathfinder::new();

            report.payments_attempted += 1;
            report.route_attempts += 3;

            let attempts: [(&'static str, Result<Route, channel_router::RoutingError>); 3] = [
                ("dijkstra", pathfinder.find_route_dijkstra(&graph, &request)),
                ("bfs", pathfinder.find_route_bfs(&graph, &request)),
                ("astar", pathfinder.find_route_astar(&graph, &request)),
            ];

            for (algorithm, result) in attempts {
                // Failing to find a route is a legitimate outcome.
                let Ok(route) = result else { continue };

                report.routes_found += 1;
                routed_here = true;
                report.routes_checked += 1;

                if let Err(detail) = verify_route(&graph, &request, &route) {
                    report.failures.push(FuzzFailure {
                        iteration,
                        seed,
                        run_seed: self.config.seed,
                        topology,
                        invariant: "route",
                        detail: format!("payment {payment_index} via {algorithm}: {detail}"),
                    });
                }

                if self.config.disconnection.is_some() {
                    let source_online = nodes.get(&request.source).is_some_and(|n| n.node.online);
                    let offline_hop = route
                        .hops
                        .iter()
                        .find(|hop| !nodes.get(&hop.node_id).is_some_and(|n| n.node.online));
                    if !source_online || offline_hop.is_some() {
                        report.failures.push(FuzzFailure {
                            iteration,
                            seed,
                            run_seed: self.config.seed,
                            topology,
                            invariant: "route_offline_node",
                            detail: format!(
                                "payment {payment_index} via {algorithm} used an offline node"
                            ),
                        });
                    }
                }
            }
        }

        if let (Some(churn_cfg), Some(mut churn_tracker)) =
            (self.config.disconnection.as_ref(), tracker)
        {
            if churn_cfg.recover_at_end {
                match churn_tracker.recover_all(
                    &mut graph,
                    &mut nodes,
                    self.config.payments_per_topology,
                ) {
                    Ok(n) => report.recoveries_simulated += n,
                    Err(err) => {
                        report.failures.push(FuzzFailure {
                            iteration,
                            seed,
                            run_seed: self.config.seed,
                            topology,
                            invariant: "final_recovery",
                            detail: err.to_string(),
                        });
                        return;
                    }
                }
                if let Err(detail) = verify_topology(&graph, &nodes) {
                    report.failures.push(FuzzFailure {
                        iteration,
                        seed,
                        run_seed: self.config.seed,
                        topology,
                        invariant: "topology_after_recovery",
                        detail,
                    });
                }
            }
        }

        if routed_here {
            report.routable_topologies += 1;
        }
    }

    /// Deterministic per-iteration seed, so a failure names its own replay.
    fn iteration_seed(&self, iteration: usize) -> u64 {
        self.config
            .seed
            .wrapping_add((iteration as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15))
    }

    /// Random but bounded simulator parameters for one iteration.
    fn random_sim_config<R: Rng>(&self, rng: &mut R) -> SimulatorConfig {
        let min_nodes = self.config.min_nodes.max(1);
        let max_nodes = self.config.max_nodes.max(min_nodes);
        let num_nodes = rng.gen_range(min_nodes..=max_nodes);

        let min_capacity = rng.gen_range(1_000i128..10_000);
        let max_capacity = min_capacity * rng.gen_range(10i128..1_000);

        SimulatorConfig {
            num_nodes,
            avg_channels_per_node: rng.gen_range(1.0..6.0),
            min_channel_capacity: min_capacity,
            max_channel_capacity: max_capacity,
            avg_balance_percent: rng.gen_range(0.1..0.9),
            // Stay inside the router's protocol fee cap so the topology is
            // routable and the fee cap check exercises real routes.
            base_fee: rng.gen_range(0i128..1_000),
            fee_rate: rng.gen_range(0u32..fee_cap_rate()),
            cltv_delta: rng.gen_range(0u32..144),
            num_payments: self.config.payments_per_topology,
            max_payment_amount: min_capacity * rng.gen_range(1i128..8),
            seed: None,
            disconnection: None,
        }
    }

    /// A random payment between two distinct nodes that have channels.
    fn random_payment<R: Rng>(&self, graph: &NetworkGraph, rng: &mut R) -> Option<RouteRequest> {
        let candidates: Vec<&String> = graph
            .nodes
            .keys()
            .filter(|id| {
                graph
                    .adjacency
                    .get(*id)
                    .is_some_and(|neighbours| !neighbours.is_empty())
            })
            .collect();

        if candidates.len() < 2 {
            return None;
        }

        let source = candidates[rng.gen_range(0..candidates.len())];
        let destination = candidates[rng.gen_range(0..candidates.len())];

        if source == destination {
            return None;
        }

        // Keep the amount small enough that capacity, not the amount, is what
        // rejects a payment: the point is to exercise the routing paths.
        let amount = rng.gen_range(1i128..=10_000);

        Some(RouteRequest {
            source: source.clone(),
            destination: destination.clone(),
            amount,
            max_fee_budget: None,
            max_hops: None,
            find_any: false,
            payment_metadata: None,
        })
    }
}

impl Default for TopologyFuzzer {
    fn default() -> Self {
        Self::new(TopologyFuzzConfig::default())
    }
}

/// The router's per-channel fee-rate cap, kept in one place so the fuzzer and
/// the topology generator cannot drift apart.
pub fn fee_cap_rate() -> u32 {
    FeeCap::protocol().max_channel_fee_rate_ppm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::NetworkTopology;
    use channel_router::{Channel, Node, NodeFeatures};

    fn simple_graph() -> (NetworkGraph, HashMap<String, SimulatedNode>) {
        let mut graph = NetworkGraph::new();
        let mut nodes = HashMap::new();

        for id in ["a", "b", "c"] {
            let node = Node {
                id: id.to_string(),
                public_key: vec![1],
                alias: None,
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

        for (id, a, b) in [("ch1", "a", "b"), ("ch2", "b", "c")] {
            graph.add_channel(Channel {
                id: id.to_string(),
                node_a: a.to_string(),
                node_b: b.to_string(),
                capacity_a_to_b: 1_000_000,
                capacity_b_to_a: 1_000_000,
                base_fee: 1,
                fee_rate: 1_000,
                cltv_delta: 0,
                min_htlc_size: 1,
                max_htlc_size: 1_000_000,
                htlcs_in_flight: 0,
                enabled: true,
                age_seconds: 0,
            });
            // Keep the simulated view in step with the graph.
            nodes.get_mut(a).unwrap().channels.insert(b.to_string());
            nodes.get_mut(b).unwrap().channels.insert(a.to_string());
        }

        (graph, nodes)
    }

    #[test]
    fn verify_topology_accepts_a_consistent_graph() {
        let (graph, nodes) = simple_graph();
        assert_eq!(verify_topology(&graph, &nodes).unwrap(), 2);
    }

    #[test]
    fn verify_topology_catches_a_node_missing_from_the_graph() {
        let (graph, mut nodes) = simple_graph();
        let node = Node {
            id: "ghost".to_string(),
            public_key: vec![2],
            alias: None,
            online: true,
            last_seen: 0,
            features: NodeFeatures::default(),
        };
        nodes.insert(
            "ghost".to_string(),
            SimulatedNode {
                node,
                balance: 0,
                channels: HashSet::new(),
            },
        );

        // The simulated view has a node the graph does not know about.
        let err = verify_topology(&graph, &nodes).unwrap_err();
        assert!(err.contains("4 simulated nodes"), "{err}");
    }

    #[test]
    fn verify_topology_catches_a_disagreeing_simulated_node() {
        let (graph, mut nodes) = simple_graph();
        nodes.get_mut("a").unwrap().channels.remove("b");

        let err = verify_topology(&graph, &nodes).unwrap_err();
        assert!(err.contains("simulated node a"), "{err}");
    }

    #[test]
    fn verify_topology_catches_a_channel_with_a_missing_endpoint() {
        let (mut graph, mut nodes) = simple_graph();
        let node = Node {
            id: "d".to_string(),
            public_key: vec![2],
            alias: None,
            online: true,
            last_seen: 0,
            features: NodeFeatures::default(),
        };
        graph.add_node(node.clone());
        nodes.insert(
            "d".to_string(),
            SimulatedNode {
                node,
                balance: 0,
                channels: HashSet::new(),
            },
        );
        graph.add_channel(Channel {
            id: "ch3".to_string(),
            node_a: "a".to_string(),
            node_b: "d".to_string(),
            capacity_a_to_b: 10,
            capacity_b_to_a: 10,
            base_fee: 0,
            fee_rate: 0,
            cltv_delta: 0,
            min_htlc_size: 1,
            max_htlc_size: 10,
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 0,
        });

        // The graph is consistent, but the simulated edge view was not updated.
        assert!(verify_topology(&graph, &nodes).is_err());
    }

    #[test]
    fn verify_route_accepts_a_route_from_the_pathfinder() {
        let (graph, _) = simple_graph();
        let request = RouteRequest {
            source: "a".to_string(),
            destination: "c".to_string(),
            amount: 1_000,
            max_fee_budget: None,
            max_hops: None,
            find_any: false,
            payment_metadata: None,
        };

        let route = Pathfinder::new()
            .find_route_dijkstra(&graph, &request)
            .unwrap();
        assert!(verify_route(&graph, &request, &route).is_ok());
    }

    #[test]
    fn verify_route_rejects_a_route_to_the_wrong_destination() {
        let (graph, _) = simple_graph();
        let request = RouteRequest {
            source: "a".to_string(),
            destination: "b".to_string(),
            amount: 1_000,
            max_fee_budget: None,
            max_hops: None,
            find_any: false,
            payment_metadata: None,
        };

        let route = Pathfinder::new()
            .find_route_dijkstra(&graph, &request)
            .unwrap();
        assert!(verify_route(&graph, &request, &route).is_ok());

        // Same route, longer request: it no longer ends at the destination.
        let longer = RouteRequest {
            destination: "c".to_string(),
            ..request
        };
        assert!(verify_route(&graph, &longer, &route).is_err());
    }

    #[test]
    fn fuzzing_generates_every_topology_and_finds_no_violations() {
        let fuzzer = TopologyFuzzer::new(TopologyFuzzConfig {
            iterations: 70,
            seed: 0xDEAD_BEEF,
            min_nodes: 2,
            max_nodes: 30,
            payments_per_topology: 8,
            ..TopologyFuzzConfig::default()
        });

        let report = fuzzer.run();

        assert!(
            report.is_clean(),
            "invariant violations: {}",
            report.summarize()
        );
        assert_eq!(report.iterations, 70);
        // Every shape gets exercised at least once across 70 iterations.
        assert!(report.routable_topologies > 0);
        assert!(report.routes_checked > 0);
    }

    #[test]
    fn fuzzing_is_deterministic_for_a_given_seed() {
        let config = TopologyFuzzConfig {
            iterations: 21,
            seed: 7,
            min_nodes: 2,
            max_nodes: 20,
            payments_per_topology: 5,
            ..TopologyFuzzConfig::default()
        };

        let first = TopologyFuzzer::new(config.clone()).run();
        let second = TopologyFuzzer::new(config).run();

        assert_eq!(first.routes_checked, second.routes_checked);
        assert_eq!(first.routes_found, second.routes_found);
        assert_eq!(first.failures, second.failures);
    }

    #[test]
    fn degenerate_topologies_do_not_panic() {
        // One node and two nodes are the shapes most likely to divide by zero
        // or hang in a generator loop.
        for num_nodes in [1usize, 2, 3] {
            let fuzzer = TopologyFuzzer::new(TopologyFuzzConfig {
                iterations: 14,
                seed: num_nodes as u64,
                min_nodes: num_nodes,
                max_nodes: num_nodes,
                payments_per_topology: 3,
                ..TopologyFuzzConfig::default()
            });

            let report = fuzzer.run();
            assert!(
                report.is_clean(),
                "{num_nodes}-node topologies failed: {}",
                report.summarize()
            );
        }
    }

    #[test]
    fn every_topology_type_is_reachable_through_the_fuzzer() {
        let fuzzer = TopologyFuzzer::default();
        let mut seen = HashSet::new();

        for (iteration, topology) in ALL_TOPOLOGIES.iter().enumerate() {
            let mut rng = StdRng::seed_from_u64(fuzzer.iteration_seed(iteration));
            let (graph, nodes) =
                NetworkTopology::new(fuzzer.random_sim_config(&mut rng), *topology)
                    .generate(&mut rng);

            assert!(
                verify_topology(&graph, &nodes).is_ok(),
                "topology at iteration {iteration} is malformed"
            );
            seen.insert(*topology);
        }

        assert_eq!(seen.len(), ALL_TOPOLOGIES.len());
    }

    #[test]
    fn fuzzing_with_disconnection_and_recovery_preserves_invariants() {
        let fuzzer = TopologyFuzzer::try_new(TopologyFuzzConfig {
            iterations: 28,
            seed: 0xFACE_B00C,
            min_nodes: 3,
            max_nodes: 25,
            payments_per_topology: 10,
            disconnection: Some(DisconnectionConfig {
                disconnect_probability: 0.2,
                min_downtime_steps: 2,
                max_downtime_steps: 4,
                max_concurrent_disconnections: Some(4),
                recover_at_end: true,
            }),
            ..TopologyFuzzConfig::default()
        })
        .unwrap();

        let report = fuzzer.try_run().unwrap();
        assert!(
            report.is_clean(),
            "disconnection fuzzing violations: {}",
            report.summarize()
        );
        assert!(report.disconnections_simulated > 0);
        assert_eq!(report.disconnections_simulated, report.recoveries_simulated);
    }

    #[test]
    fn fuzzing_with_disconnection_is_deterministic() {
        let config = TopologyFuzzConfig {
            iterations: 14,
            seed: 999,
            min_nodes: 3,
            max_nodes: 18,
            payments_per_topology: 8,
            disconnection: Some(DisconnectionConfig {
                disconnect_probability: 0.15,
                min_downtime_steps: 1,
                max_downtime_steps: 3,
                max_concurrent_disconnections: Some(3),
                recover_at_end: true,
            }),
            ..TopologyFuzzConfig::default()
        };

        let first = TopologyFuzzer::new(config.clone()).run();
        let second = TopologyFuzzer::new(config).run();

        assert_eq!(first.routes_checked, second.routes_checked);
        assert_eq!(first.routes_found, second.routes_found);
        assert_eq!(
            first.disconnections_simulated,
            second.disconnections_simulated
        );
        assert_eq!(first.recoveries_simulated, second.recoveries_simulated);
        assert_eq!(first.failures, second.failures);
    }

    #[test]
    fn fuzzing_rejects_invalid_disconnection_config() {
        let bad_config = TopologyFuzzConfig {
            disconnection: Some(DisconnectionConfig {
                min_downtime_steps: 0,
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(matches!(
            TopologyFuzzer::try_new(bad_config.clone()),
            Err(SimulatorError::InvalidConfig(_))
        ));
        assert!(matches!(
            TopologyFuzzer::new(bad_config).try_run(),
            Err(SimulatorError::InvalidConfig(_))
        ));
    }

    #[test]
    fn zero_and_oversized_duration_budgets_are_rejected_explicitly() {
        let zero = TopologyFuzzConfig {
            max_duration_ms: Some(0),
            ..TopologyFuzzConfig::default()
        };
        let Err(err) = TopologyFuzzer::try_new(zero) else {
            panic!("a zero duration budget must be rejected");
        };
        assert!(matches!(err, SimulatorError::InvalidConfig(_)));
        assert!(err.to_string().contains("max_duration_ms"), "{err}");

        let oversized = TopologyFuzzConfig {
            max_duration_ms: Some(MAX_FUZZ_DURATION_MS + 1),
            ..TopologyFuzzConfig::default()
        };
        assert!(matches!(
            TopologyFuzzer::try_new(oversized),
            Err(SimulatorError::InvalidConfig(_))
        ));
    }

    #[test]
    fn duration_budget_stops_a_long_run_and_reports_the_seed() {
        let config = TopologyFuzzConfig {
            // Far more iterations than can finish inside the budget.
            iterations: 10_000_000,
            seed: 0x0BAD_F00D_1234_5678,
            min_nodes: 2,
            max_nodes: 12,
            payments_per_topology: 1,
            max_duration_ms: Some(5),
            ..TopologyFuzzConfig::default()
        };

        let fuzzer = TopologyFuzzer::try_new(config.clone()).unwrap();
        let report = fuzzer.run();

        assert!(report.was_truncated());
        assert_eq!(report.termination, FuzzTermination::DurationBudgetExceeded);
        assert_eq!(report.termination.name(), "duration-budget-exceeded");
        assert_eq!(report.seed, config.seed);
        assert!(report.iterations < config.iterations);
        assert_eq!(report.max_duration_ms, Some(5));

        let summary = report.summarize();
        assert!(summary.contains("seed=0x0badf00d12345678"), "{summary}");
        assert!(summary.contains("stopped early"), "{summary}");
    }

    #[test]
    fn a_run_without_a_budget_reports_completion() {
        let fuzzer = TopologyFuzzer::try_new(TopologyFuzzConfig {
            iterations: 7,
            seed: 5,
            min_nodes: 2,
            max_nodes: 10,
            payments_per_topology: 2,
            ..TopologyFuzzConfig::default()
        })
        .unwrap();

        let report = fuzzer.run();
        assert_eq!(report.termination, FuzzTermination::Completed);
        assert!(!report.was_truncated());
        assert_eq!(report.iterations, 7);
    }

    #[test]
    fn failures_name_the_seed_and_replay_iteration() {
        // An invalid churn config makes every iteration fail with a `config`
        // failure, which is the cheapest way to assert on the diagnostics.
        let config = TopologyFuzzConfig {
            iterations: 3,
            seed: 0xFEED_FACE,
            min_nodes: 2,
            max_nodes: 6,
            payments_per_topology: 1,
            disconnection: Some(DisconnectionConfig {
                min_downtime_steps: 0,
                ..Default::default()
            }),
            ..TopologyFuzzConfig::default()
        };

        let report = TopologyFuzzer::new(config.clone()).run();
        assert_eq!(report.failures.len(), 3);

        for (iteration, failure) in report.failures.iter().enumerate() {
            assert_eq!(failure.iteration, iteration);
            assert_eq!(failure.run_seed, config.seed);
            assert_eq!(
                failure.seed,
                0xFEED_FACE_u64
                    .wrapping_add((iteration as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15))
            );

            let hint = failure.replay_hint();
            assert!(hint.contains(&format!("iteration={iteration}")), "{hint}");
            assert!(hint.contains("seed=0x"), "{hint}");
        }

        let summary = report.summarize();
        assert!(summary.contains("seed=0x00000000feedface"), "{summary}");
        assert!(summary.contains("iteration=0"), "{summary}");
    }

    #[test]
    fn replaying_a_reported_failure_reproduces_it() {
        let config = TopologyFuzzConfig {
            iterations: 5,
            seed: 0x1234_ABCD,
            min_nodes: 2,
            max_nodes: 8,
            payments_per_topology: 2,
            disconnection: Some(DisconnectionConfig {
                max_downtime_steps: 0,
                ..Default::default()
            }),
            ..TopologyFuzzConfig::default()
        };

        let fuzzer = TopologyFuzzer::new(config);
        let report = fuzzer.run();
        let failure = report.failures.first().unwrap().clone();

        let mut replay = FuzzReport::default();
        fuzzer.run_iteration(failure.iteration, &mut replay);

        assert_eq!(replay.failures, vec![failure]);
    }
}

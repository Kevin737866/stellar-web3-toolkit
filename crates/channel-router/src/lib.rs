//! # Channel Router
//!
//! Multi-hop payment routing for Stellar payment channels.
//! Implements path-finding algorithms for routing payments through
//! the payment channel network.
//!
//! Policy rejections can be explained with [`find_best_route_with_policy`] and
//! [`evaluate_route_policy`], which report the candidate route and the exact
//! rule it broke (issue #365).

pub mod fee_cap;
pub mod graph;
pub mod pathfinder;
pub mod policy;
pub mod policy_report;

pub use fee_cap::FeeCap;
pub use policy_report::{
    CandidateRouteFailure, CandidateRouteSummary, PolicyFailureReason, RouteEvaluationReport,
    RoutePolicyError,
};

use fxhash::FxHashMap;
use priority_queue::PriorityQueue;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::HashSet;
use thiserror::Error;

/// Maximum number of hops allowed in a route
pub const MAX_ROUTE_HOPS: usize = 20;

/// Maximum amount we'll attempt to route (to prevent overflow)
pub const MAX_ROUTE_AMOUNT: i128 = i128::MAX / 2;

/// Minimum value accepted for `RouteSearchConfig::max_hop_count`.
///
/// A hop count of zero would mean "no path is acceptable", which is never a
/// useful configuration.  Setting this to 1 allows direct (single-hop) routes
/// while rejecting configurations that can never produce a result.
pub const MIN_HOP_COUNT: usize = 1;

/// Configuration for a route search, including an optional bounded hop limit.
///
/// `RouteSearchConfig` complements [`RouteRequest`] with search-time policy
/// that is validated before the pathfinder runs.  The main addition over
/// using `RouteRequest::max_hops` directly is that an invalid hop count is
/// rejected with an actionable error rather than silently clamped or ignored.
///
/// # Compatibility
///
/// Callers that do not need a custom hop limit should continue calling
/// [`find_best_route`] or [`find_best_route_with_cap`], which are unchanged.
/// `RouteSearchConfig` is only required when you want explicit validation of
/// the hop-count bound.
///
/// # Example
///
/// ```rust,ignore
/// let config = RouteSearchConfig::new(request)
///     .with_max_hop_count(5)?;
/// let route = find_best_route_with_config(&graph, &config, &FeeCap::protocol())?;
/// ```
#[derive(Debug, Clone)]
pub struct RouteSearchConfig {
    /// The underlying route request.
    pub request: RouteRequest,
    /// Maximum number of hops the search may traverse.
    ///
    /// When `Some`, it must satisfy `MIN_HOP_COUNT <= n <= MAX_ROUTE_HOPS`;
    /// the constructor enforces this.  When `None`, `MAX_ROUTE_HOPS` is used.
    pub max_hop_count: Option<usize>,
}

impl RouteSearchConfig {
    /// Wrap `request` in a `RouteSearchConfig` with no hop-count override.
    pub fn new(request: RouteRequest) -> Self {
        RouteSearchConfig {
            request,
            max_hop_count: None,
        }
    }

    /// Set an explicit maximum hop count, validating the bounds.
    ///
    /// Returns [`RoutingError::MaxHopCountTooLow`] when `count < MIN_HOP_COUNT`
    /// and [`RoutingError::MaxHopCountTooHigh`] when `count > MAX_ROUTE_HOPS`.
    pub fn with_max_hop_count(mut self, count: usize) -> Result<Self, RoutingError> {
        validate_max_hop_count(count)?;
        self.max_hop_count = Some(count);
        Ok(self)
    }

    /// The effective hop limit: the explicit override, or the value from the
    /// inner `RouteRequest`, or the protocol maximum.
    pub fn effective_max_hops(&self) -> usize {
        self.max_hop_count
            .or(self.request.max_hops)
            .unwrap_or(MAX_ROUTE_HOPS)
    }
}

/// Validate that `count` is a legal hop-count value.
///
/// Returns:
/// - [`RoutingError::MaxHopCountTooLow`] when `count < MIN_HOP_COUNT`
/// - [`RoutingError::MaxHopCountTooHigh`] when `count > MAX_ROUTE_HOPS`
/// - `Ok(())` otherwise
///
/// This function is the single enforcement point for hop-count bounds.  Both
/// [`RouteSearchConfig::with_max_hop_count`] and callers that set
/// `RouteRequest::max_hops` manually can call it to get the same error types.
pub fn validate_max_hop_count(count: usize) -> Result<(), RoutingError> {
    if count < MIN_HOP_COUNT {
        return Err(RoutingError::MaxHopCountTooLow {
            count,
            min: MIN_HOP_COUNT,
        });
    }
    if count > MAX_ROUTE_HOPS {
        return Err(RoutingError::MaxHopCountTooHigh {
            count,
            max: MAX_ROUTE_HOPS,
        });
    }
    Ok(())
}

/// Errors that can occur during routing
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RoutingError {
    #[error("No path found from {origin} to {destination}")]
    NoPathFound { origin: String, destination: String },

    #[error("Source node {node} has no channels")]
    NoChannelsForNode { node: String },

    #[error(
        "Insufficient capacity: needed {needed}, available {available} on channel {channel_id}"
    )]
    InsufficientCapacity {
        needed: i128,
        available: i128,
        channel_id: String,
    },

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

    #[error("Route failed policy checks: {0}")]
    PolicyCheckFailed(String),

    #[error(
        "Channel {channel_id} advertises a fee rate of {fee_rate} ppm, above the protocol cap of {cap} ppm"
    )]
    ChannelFeeRateCapExceeded {
        channel_id: String,
        fee_rate: u32,
        cap: u32,
    },

    #[error(
        "Channel {channel_id} advertises a base fee of {base_fee}, above the protocol cap of {cap}"
    )]
    ChannelBaseFeeCapExceeded {
        channel_id: String,
        base_fee: i128,
        cap: i128,
    },

    #[error("Hop fee {fee} for channel {channel_id} exceeds the cap of {cap}")]
    HopFeeCapExceeded {
        channel_id: String,
        fee: i128,
        cap: i128,
    },

    #[error("Route fee {fee} for amount {amount} exceeds the cap of {cap}")]
    RouteFeeCapExceeded { fee: i128, cap: i128, amount: i128 },

    #[error("Route declares {declared} in fees but its hops sum to {actual}")]
    InconsistentRouteFees { declared: i128, actual: i128 },

    #[error("Route requires total CLTV delta {required}, above budget of {max_allowed}")]
    TimeoutExceedsBudget { required: u32, max_allowed: u32 },

    #[error("Invalid timeout requirement on channel {channel_id}: {reason}")]
    InvalidHopTimeout { channel_id: String, reason: String },

    #[error("Cumulative CLTV timeout delta overflowed u32")]
    TimeoutOverflow,
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
#[allow(clippy::struct_excessive_bools)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

impl Route {
    /// Per-hop timeout requirements ordered from source to destination.
    pub fn hop_timeouts(&self) -> &[HopTimeout] {
        &self.metadata.hop_timeouts
    }

    /// Total cumulative CLTV delta required at the first hop of the route.
    pub fn total_cltv_delta(&self) -> u32 {
        self.metadata.total_cltv_delta
    }

    /// Resolve per-hop absolute expiry heights relative to `base_height`.
    ///
    /// Each hop's `expiry_height` is `base_height + incoming_cltv_delta`,
    /// preserving strictly decreasing timeouts from source to destination.
    pub fn hop_timeouts_from_height(
        &self,
        base_height: u32,
    ) -> Result<Vec<HopTimeout>, RoutingError> {
        self.metadata
            .hop_timeouts
            .iter()
            .map(|t| {
                let expiry_height = base_height
                    .checked_add(t.incoming_cltv_delta)
                    .ok_or(RoutingError::TimeoutOverflow)?;
                Ok(HopTimeout {
                    expiry_height,
                    ..t.clone()
                })
            })
            .collect()
    }
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

/// Per-hop timeout requirement derived from channel CLTV deltas and optional
/// payment metadata.
///
/// For a route `source -> h_0 -> h_1 -> ... -> h_{n-1} (destination)`,
/// `incoming_cltv_delta` is the cumulative time-lock delta required on the
/// HTLC entering this hop, and `outgoing_cltv_delta` is the delta forwarded
/// to the next hop (`incoming_cltv_delta - outgoing_cltv_delta == cltv_delta`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopTimeout {
    /// Channel ID for this hop.
    pub channel_id: String,
    /// Node ID reached by this hop.
    pub node_id: String,
    /// Time-lock delta required by this hop's channel.
    pub cltv_delta: u32,
    /// Cumulative CLTV delta from this hop through the destination.
    pub incoming_cltv_delta: u32,
    /// Cumulative CLTV delta forwarded to the next hop.
    pub outgoing_cltv_delta: u32,
    /// Expiry height (equals `incoming_cltv_delta` unless offset from a base height).
    pub expiry_height: u32,
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
    /// Total cumulative CLTV delta required across the route
    #[serde(default)]
    pub total_cltv_delta: u32,
    /// Per-hop timeout requirements ordered from source to destination
    #[serde(default)]
    pub hop_timeouts: Vec<HopTimeout>,
}

/// Compute per-hop timeout requirements backwards from destination to source,
/// populating `expiry_height` on each [`RouteHop`] and enforcing timeout safety
/// and optional CLTV budget bounds.
pub fn compute_hop_timeouts(
    hops: &mut [RouteHop],
    final_cltv_delta: u32,
    max_cltv_budget: Option<u32>,
) -> Result<(u32, Vec<HopTimeout>), RoutingError> {
    if hops.is_empty() {
        return Ok((final_cltv_delta, Vec::new()));
    }

    let mut outgoing_delta = final_cltv_delta;
    let mut timeouts = vec![
        HopTimeout {
            channel_id: String::new(),
            node_id: String::new(),
            cltv_delta: 0,
            incoming_cltv_delta: 0,
            outgoing_cltv_delta: 0,
            expiry_height: 0,
        };
        hops.len()
    ];

    let num_hops = hops.len();
    for (idx, hop) in hops.iter_mut().enumerate().rev() {
        if idx + 1 < num_hops && hop.cltv_delta == 0 {
            return Err(RoutingError::InvalidHopTimeout {
                channel_id: hop.channel_id.clone(),
                reason: "intermediate hop must have a positive cltv_delta for timeout safety"
                    .to_string(),
            });
        }
        let incoming_delta = outgoing_delta
            .checked_add(hop.cltv_delta)
            .ok_or(RoutingError::TimeoutOverflow)?;
        hop.expiry_height = incoming_delta;
        timeouts[idx] = HopTimeout {
            channel_id: hop.channel_id.clone(),
            node_id: hop.node_id.clone(),
            cltv_delta: hop.cltv_delta,
            incoming_cltv_delta: incoming_delta,
            outgoing_cltv_delta: outgoing_delta,
            expiry_height: incoming_delta,
        };
        outgoing_delta = incoming_delta;
    }

    let total_cltv_delta = outgoing_delta;
    if let Some(max_allowed) = max_cltv_budget {
        if total_cltv_delta > max_allowed {
            return Err(RoutingError::TimeoutExceedsBudget {
                required: total_cltv_delta,
                max_allowed,
            });
        }
    }

    Ok((total_cltv_delta, timeouts))
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
    /// Channels that are known to be temporarily unavailable and must not be
    /// used for this routing attempt.  Callers that have no exclusions leave
    /// this empty; existing call sites that construct `RouteRequest` without
    /// this field compile unchanged when they switch to struct-update syntax
    /// (`..RouteRequest { excluded_unavailable: vec![], .. }`).
    pub excluded_unavailable: Vec<UnavailableChannel>,
}

impl RouteRequest {
    /// Create a new route request (Issue #364)
    pub fn new(source: String, destination: String, amount: i128) -> Self {
        RouteRequest {
            source,
            destination,
            amount,
            max_fee_budget: None,
            max_hops: None,
            find_any: false,
            payment_metadata: None,
        }
    }

    /// Configure maximum allowed hops for this request (Issue #364)
    pub fn with_max_hops(mut self, max_hops: usize) -> Self {
        self.max_hops = Some(max_hops);
        self
    }

    /// Configure maximum fee budget for this request
    pub fn with_max_fee_budget(mut self, budget: i128) -> Self {
        self.max_fee_budget = Some(budget);
        self
    }
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
    pub nodes: FxHashMap<String, Node>,
    /// Map of channel ID to Channel
    pub channels: FxHashMap<String, Channel>,
    /// Map of node ID to set of channel IDs they're in
    pub node_channels: FxHashMap<String, HashSet<String>>,
    /// Adjacency list: node ID -> (neighbor ID -> channel ID)
    pub adjacency: FxHashMap<String, FxHashMap<String, String>>,
    /// Graph version for invalidation
    pub version: u64,
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
        let id = node.id.clone();
        self.nodes.insert(id.clone(), node);
        self.node_channels.entry(id.clone()).or_default();
        self.adjacency.entry(id).or_default();
    }

    /// Add a channel to the graph
    pub fn add_channel(&mut self, channel: Channel) {
        // Add to channels map
        self.channels.insert(channel.id.clone(), channel.clone());

        // Update node_channels
        self.node_channels
            .entry(channel.node_a.clone())
            .or_default()
            .insert(channel.id.clone());
        self.node_channels
            .entry(channel.node_b.clone())
            .or_default()
            .insert(channel.id.clone());

        // Update adjacency
        self.adjacency
            .entry(channel.node_a.clone())
            .or_default()
            .insert(channel.node_b.clone(), channel.id.clone());
        self.adjacency
            .entry(channel.node_b.clone())
            .or_default()
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

/// Find the best route using Dijkstra's algorithm with fees.
///
/// Channels and routes are held to the network-wide [`FeeCap::protocol`].
/// Use [`find_best_route_with_cap`] to apply a stricter budget.
pub fn find_best_route(
    graph: &NetworkGraph,
    request: &RouteRequest,
) -> Result<Route, RoutingError> {
    find_best_route_with_cap(graph, request, &FeeCap::protocol())
}

/// Find the best route using Dijkstra's algorithm with fees, rejecting any
/// channel or route that breaks `cap`.
///
/// Equal-cost routes are broken deterministically using [`TieBreaker::Canonical`].
/// Use [`find_best_route_with_tie_breaker`] to select a different tie-breaker.
pub fn find_best_route_with_cap(
    graph: &NetworkGraph,
    request: &RouteRequest,
    cap: &FeeCap,
) -> Result<Route, RoutingError> {
    find_best_route_with_tie_breaker(graph, request, cap, TieBreaker::Canonical)
}

/// Find the best route using Dijkstra's algorithm with fees, enforcing `cap`
/// and breaking equal-cost ties deterministically according to `tie_breaker`.
pub fn find_best_route_with_tie_breaker(
    graph: &NetworkGraph,
    request: &RouteRequest,
    cap: &FeeCap,
    tie_breaker: TieBreaker,
) -> Result<Route, RoutingError> {
    // Validate inputs explicitly
    if request.amount <= 0 {
        return Err(RoutingError::BelowDustLimit {
            amount: request.amount,
            dust_limit: 1,
        });
    }

    if request.amount > MAX_ROUTE_AMOUNT {
        return Err(RoutingError::AmountExceedsMaximum {
            amount: request.amount,
            max_amount: MAX_ROUTE_AMOUNT,
        });
    }

    if let Some(budget) = request.max_fee_budget {
        if budget < 0 {
            return Err(RoutingError::FeeExceedsBudget { fee: 0, budget });
        }
    }

    if !graph.has_node(&request.source) {
        return Err(RoutingError::NodeNotFound {
            node: request.source.clone(),
        });
    }

    if !graph.has_node(&request.destination) {
        return Err(RoutingError::NodeNotFound {
            node: request.destination.clone(),
        });
    }

    // Validate and compile the temporary-exclusion list before the search so
    // that invalid entries are caught atomically rather than mid-route.
    let excluded = build_exclusion_set(&request.excluded_unavailable)?;

    let max_hops = request.max_hops.unwrap_or(MAX_ROUTE_HOPS);

    // Dijkstra's algorithm with weighted edges (fees) and deterministic tie-breaking
    let mut best_keys: FxHashMap<String, policy::SearchKey> = FxHashMap::default();
    let mut prev: FxHashMap<String, (String, String, i128, i128)> = FxHashMap::default(); // node -> (prev_node, channel_id, amount, fee)
                                                                                          // The amount that actually arrives at each node. A hop's fee is charged on
                                                                                          // the amount forwarded through it, which is the payment plus every fee
                                                                                          // already paid upstream, so this has to be tracked per node rather than
                                                                                          // derived from the accumulated fee.
    let mut amount_at: FxHashMap<String, i128> = FxHashMap::default();
    let mut pq: PriorityQueue<String, Reverse<policy::SearchKey>> = PriorityQueue::new();

    let root_key = policy::SearchKey::root(0, tie_breaker);
    best_keys.insert(request.source.clone(), root_key.clone());
    amount_at.insert(request.source.clone(), request.amount);
    pq.push(request.source.clone(), Reverse(root_key));

    while let Some((node_id, Reverse(current_key))) = pq.pop() {
        // Found destination
        if node_id == request.destination {
            break;
        }

        // Skip if we've found a better path
        if let Some(best) = best_keys.get(&node_id) {
            if &current_key > best {
                continue;
            }
        }

        // Amount arriving at this node, which is what the next hop charges on.
        let current_amount = *amount_at.get(&node_id).unwrap_or(&request.amount);
        let dist_cost = current_key.primary_cost;

        // Check all neighbors in deterministic sorted order
        for (neighbor_id, channel_id) in policy::sorted_neighbors(graph, &node_id) {
            if let Some(channel) = graph.channels.get(channel_id) {
                // A hop that advertises an absurd fee schedule is never
                // admitted, no matter how cheap the rest of the route is.
                if cap.check_channel(channel).is_err() {
                    continue;
                }

        // Check all neighbors
        if let Some(neighbors) = graph.adjacency.get(&node_id) {
            for (neighbor_id, channel_id) in neighbors {
                if let Some(channel) = graph.channels.get(channel_id) {
                    // Skip channels that are temporarily unavailable.
                    if excluded.contains(channel_id.as_str()) {
                        continue;
                    }

                    // A hop that advertises an absurd fee schedule is never
                    // admitted, no matter how cheap the rest of the route is.
                    if cap.check_channel(channel).is_err() {
                        continue;
                    }

                    // Determine direction and available capacity.
                    //
                    // `neighbor_id` is where we are heading, so the capacity we
                    // need is the one leaving `node_id`: when the neighbour is
                    // `node_a`, we are `node_b` and travel along `b_to_a`.
                    // Reading the opposite direction lets a payment be routed
                    // through a hop that has no room for it.
                    let (available_capacity, _direction) = if &channel.node_a == neighbor_id {
                        (channel.capacity_b_to_a, Direction::BToA)
                    } else {
                        (channel.capacity_a_to_b, Direction::AToB)
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

                // Reject negative base fees to prevent negative-weight cycles
                if channel.base_fee < 0 {
                    continue;
                }

                // Calculate fee for this hop
                let fee = calculate_channel_fee(
                    amount_at_next_hop,
                    channel.base_fee,
                    channel.fee_rate,
                    channel.cltv_delta,
                );
                if fee < 0 {
                    continue;
                }

                let Some(next_dist) = dist_cost.checked_add(fee) else {
                    continue;
                };
                let Some(next_amount) = current_amount.checked_add(fee) else {
                    continue;
                };

                let next_key =
                    current_key.extend(next_dist, channel_id, neighbor_id, channel.cltv_delta);

                let is_better = match best_keys.get(neighbor_id) {
                    None => true,
                    Some(existing) => &next_key < existing,
                };

                if is_better {
                    best_keys.insert(neighbor_id.clone(), next_key.clone());
                    amount_at.insert(neighbor_id.clone(), next_amount);
                    prev.insert(
                        neighbor_id.clone(),
                        (node_id.clone(), channel_id.clone(), current_amount, fee),
                    );
                    pq.push(neighbor_id.clone(), Reverse(next_key));
                }
            }
        }
    }

    // Reconstruct route
    if !prev.contains_key(&request.destination) {
        return Err(RoutingError::NoPathFound {
            origin: request.source.clone(),
            destination: request.destination.clone(),
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
                *amount,
                *fee,
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

    let num_hops = hops.len();

    // Check path length
    if num_hops > max_hops {
        return Err(RoutingError::PathTooLong {
            length: num_hops,
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

    let (final_cltv_delta, max_cltv_budget) = match &request.payment_metadata {
        Some(meta) => (meta.required_cltv_delta.unwrap_or(0), meta.payment_expiry),
        None => (0, None),
    };
    let (total_cltv_delta, hop_timeouts) =
        compute_hop_timeouts(&mut hops, final_cltv_delta, max_cltv_budget)?;

    let route = Route {
        hops,
        total_fees,
        total_amount: request.amount,
        success_probability: 0.95, // Placeholder
        metadata: RouteMetadata {
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            num_nodes: num_hops,
            estimated_time_ms: 100,
            is_direct: num_hops == 1,
            total_cltv_delta,
            hop_timeouts,
        },
    };

    // Individually acceptable hops can still add up past the payment budget.
    cap.check_route(request.amount, &route)?;

    Ok(route)
}

/// Explain why candidate routes failed policy checks.
///
/// The returned report lists every simple candidate examined and the exact
/// rule that rejected it. A report with `accepted > 0` means a route exists;
/// it does not change any graph or request state.
pub fn evaluate_route_policy(
    graph: &NetworkGraph,
    request: &RouteRequest,
    policy: &policy::RoutingPolicy,
) -> Result<RouteEvaluationReport, RoutePolicyError> {
    Ok(policy_report::evaluate(graph, request, policy)?.report)
}

/// Find the best route under an explicit routing policy, reporting why every
/// rejected candidate failed (issue #365).
///
/// Selection is deterministic: candidates are sorted by total fee, hop count
/// and then channel ids, so equal-cost routes never depend on hash iteration.
/// Existing [`find_best_route`] callers are unaffected.
pub fn find_best_route_with_policy(
    graph: &NetworkGraph,
    request: &RouteRequest,
    policy: &policy::RoutingPolicy,
) -> Result<Route, RoutePolicyError> {
    let evaluation = policy_report::evaluate(graph, request, policy)?;
    let best = match evaluation.best() {
        Some(best) => best,
        None if evaluation.report.failures.is_empty() => {
            return Err(RoutePolicyError::NoCandidates {
                origin: request.source.clone(),
                destination: request.destination.clone(),
            })
        }
        None => return Err(RoutePolicyError::Rejected(evaluation.report.clone())),
    };

    let num_hops = best.hops.len();
    Ok(Route {
        hops: best.hops.clone(),
        total_fees: best.summary.total_fees,
        total_amount: request.amount,
        success_probability: 0.95,
        metadata: RouteMetadata {
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            num_nodes: num_hops,
            estimated_time_ms: 100 * num_hops as u64,
            is_direct: num_hops == 1,
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
            excluded_unavailable: vec![],
        };

        let route = find_best_route(&graph, &request).unwrap();
        assert_eq!(route.hops.len(), 2);
        assert_eq!(route.total_amount, 100);
    }

    fn add_node(graph: &mut NetworkGraph, id: &str) {
        graph.add_node(Node {
            id: id.to_string(),
            public_key: vec![1],
            alias: None,
            online: true,
            last_seen: 1000,
            features: NodeFeatures::default(),
        });
    }

    fn add_edge(graph: &mut NetworkGraph, id: &str, a: &str, b: &str, fee_rate: u32) {
        graph.add_channel(Channel {
            id: id.to_string(),
            node_a: a.to_string(),
            node_b: b.to_string(),
            // Capacity has to cover the payment plus the fees of the hops
            // that forward it, since each hop adds its fee to the amount.
            capacity_a_to_b: 5_000_000,
            capacity_b_to_a: 5_000_000,
            base_fee: 1,
            fee_rate,
            cltv_delta: 40,
            min_htlc_size: 1,
            max_htlc_size: 5_000_000,
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 3600,
        });
    }

    fn request(source: &str, destination: &str, amount: i128) -> RouteRequest {
        RouteRequest {
            source: source.to_string(),
            destination: destination.to_string(),
            amount,
            max_fee_budget: None,
            max_hops: None,
            find_any: false,
            payment_metadata: None,
            excluded_unavailable: vec![],
        }
    }

    #[test]
    fn route_through_channel_above_fee_rate_cap_is_not_found() {
        // alice - bob is honest, bob - carol is greedy. The only route to
        // carol runs through the greedy hop, so routing must fail rather than
        // forward the payment at an uncapped fee.
        let mut graph = NetworkGraph::new();
        for id in ["alice", "bob", "carol"] {
            add_node(&mut graph, id);
        }
        add_edge(&mut graph, "ch1", "alice", "bob", 1_000);
        add_edge(
            &mut graph,
            "ch2",
            "bob",
            "carol",
            fee_cap::MAX_CHANNEL_FEE_RATE_PPM + 1,
        );

        let err = find_best_route(&graph, &request("alice", "carol", 1_000)).unwrap_err();
        assert!(matches!(err, RoutingError::NoPathFound { .. }));
    }

    #[test]
    fn route_through_channel_above_base_fee_cap_is_not_found() {
        let mut graph = NetworkGraph::new();
        for id in ["alice", "bob"] {
            add_node(&mut graph, id);
        }
        add_edge(&mut graph, "ch1", "alice", "bob", 0);
        if let Some(channel) = graph.channels.get_mut("ch1") {
            channel.base_fee = fee_cap::MAX_CHANNEL_BASE_FEE + 1;
        }

        let err = find_best_route(&graph, &request("alice", "bob", 1_000)).unwrap_err();
        assert!(matches!(err, RoutingError::NoPathFound { .. }));
    }

    #[test]
    fn route_total_fee_is_capped() {
        let mut graph = NetworkGraph::new();
        for id in ["alice", "bob", "carol"] {
            add_node(&mut graph, id);
        }
        add_edge(
            &mut graph,
            "ch1",
            "alice",
            "bob",
            fee_cap::MAX_CHANNEL_FEE_RATE_PPM,
        );
        add_edge(
            &mut graph,
            "ch2",
            "bob",
            "carol",
            fee_cap::MAX_CHANNEL_FEE_RATE_PPM,
        );

        // With a 0 ppm, no-allowance route cap the two hops' flat base fees
        // alone already exceed the budget.
        let cap = FeeCap {
            max_route_fee_ppm: 0,
            max_route_fee_abs: 0,
            ..FeeCap::protocol()
        };
        let err = find_best_route_with_cap(&graph, &request("alice", "carol", 1_000_000), &cap)
            .unwrap_err();

        match err {
            RoutingError::HopFeeCapExceeded { .. } | RoutingError::RouteFeeCapExceeded { .. } => {}
            other => panic!("expected a fee cap violation, got {other}"),
        }

        // The protocol cap accepts the same route.
        assert!(find_best_route(&graph, &request("alice", "carol", 1_000_000)).is_ok());

        // The boundary is inclusive: a cap exactly equal to the route fee is
        // accepted, one stroop less is not.
        let exact = FeeCap::protocol();
        let route = find_best_route(&graph, &request("alice", "carol", 1_000_000)).unwrap();
        // 1_000_000 * 0.5% + 1 base fee = 5_001 on the first hop, then the
        // second hop charges on the 1_005_001 that arrives there.
        assert_eq!(route.total_fees, 5_001 + 5_026);
        assert!(exact
            .check_route_fee(route.total_amount, route.total_fees)
            .is_ok());

        let one_less = FeeCap {
            max_route_fee_abs: route.total_fees - 1,
            max_route_fee_ppm: 0,
            ..FeeCap::protocol()
        };
        assert!(
            find_best_route_with_cap(&graph, &request("alice", "carol", 1_000_000), &one_less)
                .is_err()
        );
    }

    #[test]
    fn route_and_hop_fees_agree_under_the_cap() {
        let mut graph = NetworkGraph::new();
        for id in ["alice", "bob", "carol"] {
            add_node(&mut graph, id);
        }
        add_edge(&mut graph, "ch1", "alice", "bob", 1_000);
        add_edge(&mut graph, "ch2", "bob", "carol", 1_000);

        let route = find_best_route(&graph, &request("alice", "carol", 1_000_000)).unwrap();
        let hop_sum: i128 = route.hops.iter().map(|h| h.fee).sum();
        assert_eq!(route.total_fees, hop_sum);
        assert!(FeeCap::protocol().check_route(1_000_000, &route).is_ok());
    }

    #[test]
    fn capacity_is_directional() {
        // A channel is only funded one way here: 1_000 stroops can leave alice
        // for bob, but nothing can leave bob for alice. Routing must use the
        // direction of travel, not whichever capacity field it finds first.
        let mut graph = NetworkGraph::new();
        for id in ["alice", "bob"] {
            add_node(&mut graph, id);
        }
        graph.add_channel(Channel {
            id: "ch1".to_string(),
            node_a: "alice".to_string(),
            node_b: "bob".to_string(),
            capacity_a_to_b: 1_000,
            capacity_b_to_a: 0,
            base_fee: 1,
            fee_rate: 1_000,
            cltv_delta: 40,
            min_htlc_size: 1,
            max_htlc_size: 1_000,
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 3600,
        });

        assert!(find_best_route(&graph, &request("alice", "bob", 500)).is_ok());
        assert!(matches!(
            find_best_route(&graph, &request("bob", "alice", 500)).unwrap_err(),
            RoutingError::NoPathFound { .. }
        ));

        // And the same through the pathfinder's search algorithms.
        let pathfinder = pathfinder::Pathfinder::new();
        assert!(pathfinder
            .find_route_dijkstra(&graph, &request("alice", "bob", 500))
            .is_ok());
        assert!(pathfinder
            .find_route_bfs(&graph, &request("alice", "bob", 500))
            .is_ok());
        assert!(pathfinder
            .find_route_astar(&graph, &request("alice", "bob", 500))
            .is_ok());
        assert!(pathfinder
            .find_route_dijkstra(&graph, &request("bob", "alice", 500))
            .is_err());
        assert!(pathfinder
            .find_route_bfs(&graph, &request("bob", "alice", 500))
            .is_err());
        assert!(pathfinder
            .find_route_astar(&graph, &request("bob", "alice", 500))
            .is_err());
    }

    #[test]
    fn k_routes_also_respect_the_fee_cap() {
        let mut graph = NetworkGraph::new();
        for id in ["alice", "bob", "carol"] {
            add_node(&mut graph, id);
        }
        add_edge(&mut graph, "ch1", "alice", "bob", 1_000);
        add_edge(
            &mut graph,
            "ch2",
            "bob",
            "carol",
            fee_cap::MAX_CHANNEL_FEE_RATE_PPM * 4,
        );

        let routes = find_k_routes(&graph, &request("alice", "carol", 1_000), 3).unwrap();
        assert!(routes.is_empty());
    }

    #[test]
    fn route_exposes_per_hop_timeout_requirements() {
        let mut graph = NetworkGraph::new();
        for id in ["alice", "bob", "carol"] {
            add_node(&mut graph, id);
        }
        add_edge(&mut graph, "ch1", "alice", "bob", 1_000);
        add_edge(&mut graph, "ch2", "bob", "carol", 1_000);

        let mut req = request("alice", "carol", 1_000);
        req.payment_metadata = Some(PaymentMetadata {
            payment_type: PaymentType::Regular,
            required_cltv_delta: Some(18),
            payment_expiry: Some(200),
        });

        let route = find_best_route(&graph, &req).unwrap();
        let timeouts = route.hop_timeouts();
        assert_eq!(timeouts.len(), 2);

        // Hop 1 (bob -> carol): outgoing = 18, incoming = 18 + 40 = 58
        assert_eq!(timeouts[1].channel_id, "ch2");
        assert_eq!(timeouts[1].cltv_delta, 40);
        assert_eq!(timeouts[1].outgoing_cltv_delta, 18);
        assert_eq!(timeouts[1].incoming_cltv_delta, 58);

        // Hop 0 (alice -> bob): outgoing = 58, incoming = 58 + 40 = 98
        assert_eq!(timeouts[0].channel_id, "ch1");
        assert_eq!(timeouts[0].cltv_delta, 40);
        assert_eq!(timeouts[0].outgoing_cltv_delta, 58);
        assert_eq!(timeouts[0].incoming_cltv_delta, 98);
        assert_eq!(route.total_cltv_delta(), 98);
        assert_eq!(route.hops[0].expiry_height, 98);
        assert_eq!(route.hops[1].expiry_height, 58);

        // Absolute heights from a base ledger height
        let abs = route.hop_timeouts_from_height(1_000).unwrap();
        assert_eq!(abs[0].expiry_height, 1_098);
        assert_eq!(abs[1].expiry_height, 1_058);
    }

    #[test]
    fn route_rejects_timeout_exceeding_budget() {
        let mut graph = NetworkGraph::new();
        for id in ["alice", "bob", "carol"] {
            add_node(&mut graph, id);
        }
        add_edge(&mut graph, "ch1", "alice", "bob", 1_000);
        add_edge(&mut graph, "ch2", "bob", "carol", 1_000);

        let mut req = request("alice", "carol", 1_000);
        req.payment_metadata = Some(PaymentMetadata {
            payment_type: PaymentType::Regular,
            required_cltv_delta: Some(20),
            payment_expiry: Some(99), // needs 40 + 40 + 20 = 100
        });

        let err = find_best_route(&graph, &req).unwrap_err();
        assert!(matches!(
            err,
            RoutingError::TimeoutExceedsBudget {
                required: 100,
                max_allowed: 99
            }
        ));
    }

    #[test]
    fn compute_hop_timeouts_rejects_zero_cltv_intermediate_hop_and_overflow() {
        let mut hops = vec![
            RouteHop::new("ch1".to_string(), "bob".to_string(), 100, 1, 0),
            RouteHop::new("ch2".to_string(), "carol".to_string(), 100, 1, 40),
        ];
        let err = compute_hop_timeouts(&mut hops, 0, None).unwrap_err();
        assert!(matches!(err, RoutingError::InvalidHopTimeout { .. }));

        let mut overflow_hops = vec![RouteHop::new(
            "ch1".to_string(),
            "bob".to_string(),
            100,
            1,
            u32::MAX,
        )];
        let err = compute_hop_timeouts(&mut overflow_hops, 1, None).unwrap_err();
        assert!(matches!(err, RoutingError::TimeoutOverflow));
    }
}

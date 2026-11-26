//! Explain why candidate routes failed policy checks (issue #365).
//!
//! The ordinary search functions return a single `RoutingError`, which loses
//! the identity of the rejected candidate and the rule it broke. This module
//! enumerates simple candidate paths deterministically, checks each one against
//! the same invariants the search enforces (liquidity, fee bounds, timeout
//! safety and hop limits), and reports every rejection with the channel and
//! value that caused it.
//!
//! Evaluation is pure: no graph, request or policy is mutated, so a failed
//! evaluation cannot leave partial state behind.

use crate::{
    calculate_channel_fee, Channel, FeeCap, NetworkGraph, RouteHop, RouteRequest, MAX_ROUTE_AMOUNT,
    MAX_ROUTE_HOPS,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

/// Upper bound on evaluated candidates, so a dense graph cannot turn an
/// explanation request into an unbounded search.
pub const MAX_EVALUATED_CANDIDATES: usize = 256;

/// Why a candidate route was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyFailureReason {
    /// The route uses a channel the policy excludes.
    ExcludedChannel { channel_id: String },
    /// The route touches a node the policy excludes.
    ExcludedNode { node_id: String },
    /// The channel is disabled in the graph snapshot.
    ChannelDisabled { channel_id: String },
    /// The advertised proportional fee is above the policy/protocol cap.
    FeeRateTooHigh {
        channel_id: String,
        fee_rate_ppm: u32,
        max_fee_rate_ppm: u32,
    },
    /// The advertised base fee is above the policy/protocol cap.
    BaseFeeTooHigh {
        channel_id: String,
        base_fee: i128,
        max_base_fee: i128,
    },
    /// One hop's computed fee is above the protocol cap for that amount.
    HopFeeTooHigh {
        channel_id: String,
        fee: i128,
        cap: i128,
    },
    /// The channel cannot forward the amount in the required direction.
    InsufficientLiquidity {
        channel_id: String,
        needed: i128,
        available: i128,
    },
    /// The forwarded amount is outside the channel's HTLC bounds.
    HtlcOutsideBounds {
        channel_id: String,
        amount: i128,
        min: i128,
        max: i128,
    },
    /// The route exceeds a hop limit.
    PathTooLong { hops: usize, max: usize },
    /// The total fee is above the payment budget.
    RouteFeeTooHigh { fee: i128, budget: i128 },
    /// The route's time locks do not satisfy the payment's CLTV requirement.
    UnsafeTimeout {
        channel_id: String,
        cltv_delta: u32,
        required: u32,
    },
    /// The accumulated time locks would exceed the payment expiry.
    TimeoutExceedsExpiry { total_cltv: u32, expiry: u32 },
}

impl PolicyFailureReason {
    /// Actionable description of this rejection.
    pub fn message(&self) -> String {
        match self {
            Self::ExcludedChannel { channel_id } => {
                format!("channel {channel_id} is excluded by policy")
            }
            Self::ExcludedNode { node_id } => {
                format!("node {node_id} is excluded by policy")
            }
            Self::ChannelDisabled { channel_id } => format!("channel {channel_id} is disabled"),
            Self::FeeRateTooHigh {
                channel_id,
                fee_rate_ppm,
                max_fee_rate_ppm,
            } => format!(
                "channel {channel_id} fee rate {fee_rate_ppm} ppm exceeds cap {max_fee_rate_ppm} ppm"
            ),
            Self::BaseFeeTooHigh {
                channel_id,
                base_fee,
                max_base_fee,
            } => format!(
                "channel {channel_id} base fee {base_fee} exceeds cap {max_base_fee}"
            ),
            Self::HopFeeTooHigh {
                channel_id,
                fee,
                cap,
            } => format!("hop {channel_id} charges fee {fee} above cap {cap}"),
            Self::InsufficientLiquidity {
                channel_id,
                needed,
                available,
            } => format!(
                "channel {channel_id} has {available} available but {needed} is required"
            ),
            Self::HtlcOutsideBounds {
                channel_id,
                amount,
                min,
                max,
            } => format!(
                "channel {channel_id} HTLC bounds are {min}..{max}, amount {amount} is outside"
            ),
            Self::PathTooLong { hops, max } => {
                format!("route has {hops} hops, limit is {max}")
            }
            Self::RouteFeeTooHigh { fee, budget } => {
                format!("route fee {fee} exceeds budget {budget}")
            }
            Self::UnsafeTimeout {
                channel_id,
                cltv_delta,
                required,
            } => format!(
                "channel {channel_id} CLTV delta {cltv_delta} does not meet required {required}"
            ),
            Self::TimeoutExceedsExpiry { total_cltv, expiry } => {
                format!("route time lock {total_cltv} exceeds payment expiry {expiry}")
            }
        }
    }
}

/// Identity of a rejected candidate, without floating-point fields so reports
/// can be compared and serialized deterministically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateRouteSummary {
    /// Channels used, in order.
    pub channel_ids: Vec<String>,
    /// Nodes visited after the source, in order.
    pub node_ids: Vec<String>,
    /// Amount the sender must provide, including accumulated fees.
    pub amount: i128,
    /// Total fees charged by the candidate.
    pub total_fees: i128,
    /// Sum of the candidate's CLTV deltas.
    pub total_cltv: u32,
}

/// One rejected candidate and the rule that rejected it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateRouteFailure {
    /// The candidate that was rejected.
    pub route: CandidateRouteSummary,
    /// Zero-based index of the offending hop, when the failure is hop-specific.
    pub hop_index: Option<usize>,
    /// Why the candidate was rejected.
    pub reason: PolicyFailureReason,
}

impl CandidateRouteFailure {
    /// Actionable one-line description.
    pub fn message(&self) -> String {
        match self.hop_index {
            Some(index) => format!(
                "candidate {} hop {index}: {}",
                self.route.channel_ids.join(" -> "),
                self.reason.message()
            ),
            None => format!(
                "candidate {}: {}",
                self.route.channel_ids.join(" -> "),
                self.reason.message()
            ),
        }
    }
}

/// Deterministic explanation of an evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteEvaluationReport {
    /// Source of the payment.
    pub origin: String,
    /// Destination of the payment.
    pub destination: String,
    /// Requested amount.
    pub amount: i128,
    /// Number of candidates examined.
    pub candidates_evaluated: usize,
    /// Number of candidates that passed every check.
    pub accepted: usize,
    /// Rejected candidates, in deterministic evaluation order.
    pub failures: Vec<CandidateRouteFailure>,
}

impl std::fmt::Display for RouteEvaluationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl RouteEvaluationReport {
    /// Whether at least one candidate passed all checks.
    pub fn has_route(&self) -> bool {
        self.accepted > 0
    }

    /// Actionable summary for operators and callers.
    pub fn message(&self) -> String {
        if self.failures.is_empty() {
            return format!(
                "No candidate route from {} to {} for amount {}",
                self.origin, self.destination, self.amount
            );
        }
        let mut lines: Vec<String> = self
            .failures
            .iter()
            .take(5)
            .map(CandidateRouteFailure::message)
            .collect();
        if self.failures.len() > 5 {
            lines.push(format!(
                "... and {} more rejection(s)",
                self.failures.len() - 5
            ));
        }
        format!(
            "{} candidate(s) rejected from {} to {} ({} accepted): {}",
            self.failures.len(),
            self.origin,
            self.destination,
            self.accepted,
            lines.join("; ")
        )
    }
}

/// Errors returned by the explanatory routing API.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RoutePolicyError {
    /// The request is malformed or unsafe.
    #[error("Invalid route request: {0}")]
    InvalidRequest(String),
    /// The policy is malformed or self-contradictory.
    #[error("Invalid routing policy: {0}")]
    InvalidPolicy(String),
    /// The graph contains too many simple paths to explain safely.
    #[error("Candidate limit of {limit} exceeded")]
    CandidateLimitExceeded { limit: usize },
    /// No simple candidate exists between the endpoints.
    #[error("No candidate route from {origin} to {destination}")]
    NoCandidates { origin: String, destination: String },
    /// Candidates existed but every one was rejected.
    #[error("{0}")]
    Rejected(RouteEvaluationReport),
}

/// Validate a route request without applying implicit defaults.
pub fn validate_request(request: &RouteRequest) -> Result<(), RoutePolicyError> {
    if request.source.trim().is_empty() {
        return Err(RoutePolicyError::InvalidRequest(
            "source must not be blank".to_string(),
        ));
    }
    if request.destination.trim().is_empty() {
        return Err(RoutePolicyError::InvalidRequest(
            "destination must not be blank".to_string(),
        ));
    }
    if request.source == request.destination {
        return Err(RoutePolicyError::InvalidRequest(format!(
            "source and destination must differ: {}",
            request.source
        )));
    }
    if request.amount <= 0 {
        return Err(RoutePolicyError::InvalidRequest(format!(
            "amount must be positive, got {}",
            request.amount
        )));
    }
    if request.amount > MAX_ROUTE_AMOUNT {
        return Err(RoutePolicyError::InvalidRequest(format!(
            "amount {} exceeds maximum {MAX_ROUTE_AMOUNT}",
            request.amount
        )));
    }
    if let Some(max_hops) = request.max_hops {
        if max_hops == 0 || max_hops > MAX_ROUTE_HOPS {
            return Err(RoutePolicyError::InvalidRequest(format!(
                "max_hops {max_hops} is outside 1..={MAX_ROUTE_HOPS}"
            )));
        }
    }
    if let Some(budget) = request.max_fee_budget {
        if budget < 0 {
            return Err(RoutePolicyError::InvalidRequest(format!(
                "fee budget must not be negative, got {budget}"
            )));
        }
    }
    if let Some(metadata) = &request.payment_metadata {
        if metadata.payment_expiry == Some(0) {
            return Err(RoutePolicyError::InvalidRequest(
                "payment expiry must be positive".to_string(),
            ));
        }
    }
    Ok(())
}

/// Validate a routing policy without clamping invalid values.
pub fn validate_policy(policy: &crate::policy::RoutingPolicy) -> Result<(), RoutePolicyError> {
    if policy.max_hops == 0 || policy.max_hops > MAX_ROUTE_HOPS {
        return Err(RoutePolicyError::InvalidPolicy(format!(
            "max_hops {} is outside 1..={MAX_ROUTE_HOPS}",
            policy.max_hops
        )));
    }
    if policy.max_fee_bps == 0 || policy.max_fee_bps > 10_000 {
        return Err(RoutePolicyError::InvalidPolicy(format!(
            "max_fee_bps {} is outside 1..=10000",
            policy.max_fee_bps
        )));
    }
    if policy.max_fee_rate == 0 {
        return Err(RoutePolicyError::InvalidPolicy(
            "max_fee_rate must be positive".to_string(),
        ));
    }
    if policy.max_base_fee < 0 {
        return Err(RoutePolicyError::InvalidPolicy(
            "max_base_fee must not be negative".to_string(),
        ));
    }
    if policy.min_amount <= 0 {
        return Err(RoutePolicyError::InvalidPolicy(
            "min_amount must be positive".to_string(),
        ));
    }
    if policy.max_amount < policy.min_amount {
        return Err(RoutePolicyError::InvalidPolicy(format!(
            "max_amount {} is below min_amount {}",
            policy.max_amount, policy.min_amount
        )));
    }
    Ok(())
}

/// A candidate that passed every policy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedCandidate {
    /// Deterministic summary of the candidate.
    pub summary: CandidateRouteSummary,
    /// Hops of the candidate, in order.
    pub hops: Vec<RouteHop>,
    /// Stable selection key: fee, hop count, then channel ids.
    pub selection_key: (i128, usize, Vec<String>),
}

/// Result of a pure policy evaluation.
#[derive(Debug, Clone)]
pub struct Evaluation {
    /// Candidates that passed every check, in deterministic selection order.
    pub accepted: Vec<AcceptedCandidate>,
    /// Explanatory report for all candidates.
    pub report: RouteEvaluationReport,
}

impl Evaluation {
    /// Best candidate under the deterministic selection key.
    pub fn best(&self) -> Option<&AcceptedCandidate> {
        self.accepted.first()
    }
}

/// Enumerate simple paths from `source` to `destination` up to `max_hops`,
/// in deterministic channel-id order.
fn enumerate_paths(
    graph: &NetworkGraph,
    source: &str,
    destination: &str,
    max_hops: usize,
) -> Result<Vec<Vec<(String, String)>>, RoutePolicyError> {
    let mut paths = Vec::new();
    let mut visited = HashSet::new();
    visited.insert(source.to_string());
    let mut path = Vec::new();
    collect_paths(
        graph,
        source,
        destination,
        max_hops,
        &mut visited,
        &mut path,
        &mut paths,
    )?;
    Ok(paths)
}

#[allow(clippy::too_many_arguments)]
fn collect_paths(
    graph: &NetworkGraph,
    current: &str,
    destination: &str,
    max_hops: usize,
    visited: &mut HashSet<String>,
    path: &mut Vec<(String, String)>,
    paths: &mut Vec<Vec<(String, String)>>,
) -> Result<(), RoutePolicyError> {
    if current == destination {
        paths.push(path.clone());
        return Ok(());
    }
    if path.len() >= max_hops {
        return Ok(());
    }

    let mut edges: Vec<(String, String)> = graph
        .adjacency
        .get(current)
        .map(|neighbors| {
            neighbors
                .iter()
                .map(|(neighbor, channel)| (channel.clone(), neighbor.clone()))
                .collect()
        })
        .unwrap_or_default();
    edges.sort(); // deterministic order, independent of FxHashMap iteration

    for (channel_id, neighbor) in edges {
        if visited.contains(&neighbor) || !graph.channels.contains_key(&channel_id) {
            continue;
        }
        if paths.len() >= MAX_EVALUATED_CANDIDATES {
            return Err(RoutePolicyError::CandidateLimitExceeded {
                limit: MAX_EVALUATED_CANDIDATES,
            });
        }
        visited.insert(neighbor.clone());
        path.push((channel_id, neighbor.clone()));
        collect_paths(
            graph,
            &neighbor,
            destination,
            max_hops,
            visited,
            path,
            paths,
        )?;
        path.pop();
        visited.remove(&neighbor);
    }
    Ok(())
}

fn reason_for_routing_error(channel: &Channel, error: crate::RoutingError) -> PolicyFailureReason {
    match error {
        crate::RoutingError::ChannelFeeRateCapExceeded { fee_rate, cap, .. } => {
            PolicyFailureReason::FeeRateTooHigh {
                channel_id: channel.id.clone(),
                fee_rate_ppm: fee_rate,
                max_fee_rate_ppm: cap,
            }
        }
        crate::RoutingError::ChannelBaseFeeCapExceeded { base_fee, cap, .. } => {
            PolicyFailureReason::BaseFeeTooHigh {
                channel_id: channel.id.clone(),
                base_fee,
                max_base_fee: cap,
            }
        }
        crate::RoutingError::HopFeeCapExceeded { fee, cap, .. } => {
            PolicyFailureReason::HopFeeTooHigh {
                channel_id: channel.id.clone(),
                fee,
                cap,
            }
        }
        _ => PolicyFailureReason::ChannelDisabled {
            channel_id: channel.id.clone(),
        },
    }
}

/// Evaluate every simple candidate and collect actionable rejections.
pub fn evaluate(
    graph: &NetworkGraph,
    request: &RouteRequest,
    policy: &crate::policy::RoutingPolicy,
) -> Result<Evaluation, RoutePolicyError> {
    validate_request(request)?;
    validate_policy(policy)?;

    let max_hops = request
        .max_hops
        .unwrap_or(policy.max_hops)
        .min(policy.max_hops);
    let cap = FeeCap::protocol();
    let paths = enumerate_paths(graph, &request.source, &request.destination, max_hops)?;

    let required_cltv = request
        .payment_metadata
        .as_ref()
        .and_then(|metadata| metadata.required_cltv_delta)
        .unwrap_or(0);
    let payment_expiry = request
        .payment_metadata
        .as_ref()
        .and_then(|metadata| metadata.payment_expiry);
    let fee_budget = request
        .max_fee_budget
        .unwrap_or(request.amount * i128::from(policy.max_fee_bps) / 10_000);

    let mut accepted = Vec::new();
    let mut failures = Vec::new();

    for path in paths {
        match evaluate_path(
            graph,
            request,
            policy,
            &cap,
            &path,
            fee_budget,
            required_cltv,
            payment_expiry,
        ) {
            Ok(candidate) => accepted.push(candidate),
            Err((route, hop_index, reason)) => failures.push(CandidateRouteFailure {
                route,
                hop_index,
                reason,
            }),
        }
    }

    accepted.sort_by(|a, b| a.selection_key.cmp(&b.selection_key));

    let report = RouteEvaluationReport {
        origin: request.source.clone(),
        destination: request.destination.clone(),
        amount: request.amount,
        candidates_evaluated: accepted.len() + failures.len(),
        accepted: accepted.len(),
        failures,
    };

    Ok(Evaluation { accepted, report })
}

#[allow(clippy::too_many_arguments)]
fn evaluate_path(
    graph: &NetworkGraph,
    request: &RouteRequest,
    policy: &crate::policy::RoutingPolicy,
    cap: &FeeCap,
    path: &[(String, String)],
    fee_budget: i128,
    required_cltv: u32,
    payment_expiry: Option<u32>,
) -> Result<AcceptedCandidate, (CandidateRouteSummary, Option<usize>, PolicyFailureReason)> {
    let channel_ids: Vec<String> = path.iter().map(|(channel, _)| channel.clone()).collect();
    let node_ids: Vec<String> = path.iter().map(|(_, node)| node.clone()).collect();
    let empty_summary = || CandidateRouteSummary {
        channel_ids: channel_ids.clone(),
        node_ids: node_ids.clone(),
        amount: request.amount,
        total_fees: 0,
        total_cltv: 0,
    };

    if path.len() > request.max_hops.unwrap_or(policy.max_hops) {
        return Err((
            empty_summary(),
            None,
            PolicyFailureReason::PathTooLong {
                hops: path.len(),
                max: request.max_hops.unwrap_or(policy.max_hops),
            },
        ));
    }
    if path.len() > policy.max_hops {
        return Err((
            empty_summary(),
            None,
            PolicyFailureReason::PathTooLong {
                hops: path.len(),
                max: policy.max_hops,
            },
        ));
    }

    let mut hops = Vec::with_capacity(path.len());
    let mut forwarded = request.amount;
    let mut total_fees = 0i128;
    let mut total_cltv = 0u32;
    let mut current = request.source.as_str();

    for (index, (channel_id, next_node)) in path.iter().enumerate() {
        let channel = match graph.channels.get(channel_id) {
            Some(channel) => channel,
            None => {
                return Err((
                    empty_summary(),
                    Some(index),
                    PolicyFailureReason::ChannelDisabled {
                        channel_id: channel_id.clone(),
                    },
                ))
            }
        };
        let summary_at = |fees: i128, cltv: u32| CandidateRouteSummary {
            channel_ids: channel_ids.clone(),
            node_ids: node_ids.clone(),
            amount: forwarded,
            total_fees: fees,
            total_cltv: cltv,
        };

        if policy.excluded_channels.contains(channel_id) {
            return Err((
                summary_at(total_fees, total_cltv),
                Some(index),
                PolicyFailureReason::ExcludedChannel {
                    channel_id: channel_id.clone(),
                },
            ));
        }
        if policy.excluded_nodes.contains(next_node) || policy.excluded_nodes.contains(current) {
            let node = if policy.excluded_nodes.contains(current) {
                current
            } else {
                next_node.as_str()
            };
            return Err((
                summary_at(total_fees, total_cltv),
                Some(index),
                PolicyFailureReason::ExcludedNode {
                    node_id: node.to_string(),
                },
            ));
        }
        if !channel.enabled {
            return Err((
                summary_at(total_fees, total_cltv),
                Some(index),
                PolicyFailureReason::ChannelDisabled {
                    channel_id: channel_id.clone(),
                },
            ));
        }

        let available = if channel.node_a == current {
            channel.capacity_a_to_b
        } else {
            channel.capacity_b_to_a
        };
        if available < forwarded {
            return Err((
                summary_at(total_fees, total_cltv),
                Some(index),
                PolicyFailureReason::InsufficientLiquidity {
                    channel_id: channel_id.clone(),
                    needed: forwarded,
                    available,
                },
            ));
        }
        if forwarded < channel.min_htlc_size || forwarded > channel.max_htlc_size {
            return Err((
                summary_at(total_fees, total_cltv),
                Some(index),
                PolicyFailureReason::HtlcOutsideBounds {
                    channel_id: channel_id.clone(),
                    amount: forwarded,
                    min: channel.min_htlc_size,
                    max: channel.max_htlc_size,
                },
            ));
        }

        if let Err(error) = cap.check_channel(channel) {
            return Err((
                summary_at(total_fees, total_cltv),
                Some(index),
                reason_for_routing_error(channel, error),
            ));
        }
        if channel.fee_rate > policy.max_fee_rate {
            return Err((
                summary_at(total_fees, total_cltv),
                Some(index),
                PolicyFailureReason::FeeRateTooHigh {
                    channel_id: channel_id.clone(),
                    fee_rate_ppm: channel.fee_rate,
                    max_fee_rate_ppm: policy.max_fee_rate,
                },
            ));
        }
        if channel.base_fee > policy.max_base_fee {
            return Err((
                summary_at(total_fees, total_cltv),
                Some(index),
                PolicyFailureReason::BaseFeeTooHigh {
                    channel_id: channel_id.clone(),
                    base_fee: channel.base_fee,
                    max_base_fee: policy.max_base_fee,
                },
            ));
        }

        let fee = calculate_channel_fee(
            forwarded,
            channel.base_fee,
            channel.fee_rate,
            channel.cltv_delta,
        );
        if let Err(error) = cap.check_hop_fee(channel_id, forwarded, channel.cltv_delta, fee) {
            return Err((
                summary_at(total_fees, total_cltv),
                Some(index),
                reason_for_routing_error(channel, error),
            ));
        }

        total_cltv = total_cltv.saturating_add(channel.cltv_delta);
        if total_cltv < required_cltv {
            return Err((
                summary_at(total_fees, total_cltv),
                Some(index),
                PolicyFailureReason::UnsafeTimeout {
                    channel_id: channel_id.clone(),
                    cltv_delta: channel.cltv_delta,
                    required: required_cltv,
                },
            ));
        }
        if payment_expiry.is_some_and(|expiry| total_cltv > expiry) {
            return Err((
                summary_at(total_fees, total_cltv),
                Some(index),
                PolicyFailureReason::TimeoutExceedsExpiry {
                    total_cltv,
                    expiry: payment_expiry.expect("checked above"),
                },
            ));
        }

        hops.push(RouteHop::new(
            channel_id.clone(),
            next_node.clone(),
            forwarded,
            fee,
            channel.cltv_delta,
        ));
        total_fees = total_fees.saturating_add(fee);
        forwarded = forwarded.saturating_add(fee);
        current = next_node.as_str();
    }

    let summary_at = |fees: i128, cltv: u32| CandidateRouteSummary {
        channel_ids: channel_ids.clone(),
        node_ids: node_ids.clone(),
        amount: request.amount,
        total_fees: fees,
        total_cltv: cltv,
    };

    if total_fees > fee_budget {
        return Err((
            summary_at(total_fees, total_cltv),
            None,
            PolicyFailureReason::RouteFeeTooHigh {
                fee: total_fees,
                budget: fee_budget,
            },
        ));
    }
    if let Err(error) = cap.check_route_fee(request.amount, total_fees) {
        return Err((
            summary_at(total_fees, total_cltv),
            None,
            match error {
                crate::RoutingError::RouteFeeCapExceeded { fee, cap, .. } => {
                    PolicyFailureReason::RouteFeeTooHigh { fee, budget: cap }
                }
                _ => PolicyFailureReason::RouteFeeTooHigh {
                    fee: total_fees,
                    budget: cap.max_route_fee(request.amount),
                },
            },
        ));
    }

    let summary = CandidateRouteSummary {
        channel_ids,
        node_ids,
        amount: request.amount,
        total_fees,
        total_cltv,
    };
    Ok(AcceptedCandidate {
        selection_key: (total_fees, hops.len(), summary.channel_ids.clone()),
        summary,
        hops,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::RoutingPolicy;
    use crate::{evaluate_route_policy, Node, NodeFeatures, PaymentMetadata};

    fn channel(
        id: &str,
        node_a: &str,
        node_b: &str,
        capacity: i128,
        fee_rate: u32,
        base_fee: i128,
        cltv_delta: u32,
    ) -> Channel {
        Channel {
            id: id.to_string(),
            node_a: node_a.to_string(),
            node_b: node_b.to_string(),
            capacity_a_to_b: capacity,
            capacity_b_to_a: capacity,
            base_fee,
            fee_rate,
            cltv_delta,
            min_htlc_size: 1,
            max_htlc_size: capacity,
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 3_600,
        }
    }

    fn graph_with(channels: Vec<Channel>) -> NetworkGraph {
        let mut graph = NetworkGraph::new();
        for (index, item) in ["alice", "bob", "carol"].iter().enumerate() {
            graph.add_node(Node {
                id: (*item).to_string(),
                public_key: vec![index as u8 + 1],
                alias: None,
                online: true,
                last_seen: 1_000,
                features: NodeFeatures::default(),
            });
        }
        for item in channels {
            graph.add_channel(item);
        }
        graph
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
        }
    }

    #[test]
    fn fee_rate_rejection_names_channel_and_cap() {
        let graph = graph_with(vec![channel("ch1", "alice", "bob", 10_000, 2_000, 0, 0)]);
        let mut policy = RoutingPolicy::default();
        policy.max_fee_rate = 1_000;

        let report = evaluate_route_policy(&graph, &request("alice", "bob", 1_000), &policy)
            .expect("evaluation should succeed");
        assert!(!report.has_route());
        assert_eq!(report.failures.len(), 1);
        assert_eq!(
            report.failures[0].reason,
            PolicyFailureReason::FeeRateTooHigh {
                channel_id: "ch1".to_string(),
                fee_rate_ppm: 2_000,
                max_fee_rate_ppm: 1_000,
            }
        );
        let message = report.message();
        assert!(message.contains("ch1"));
        assert!(message.contains("2000 ppm"));
    }

    #[test]
    fn liquidity_and_htlc_failures_are_actionable() {
        let graph = graph_with(vec![channel("ch1", "alice", "bob", 50, 0, 0, 0)]);
        let report = evaluate_route_policy(
            &graph,
            &request("alice", "bob", 100),
            &RoutingPolicy::default(),
        )
        .unwrap();
        assert_eq!(
            report.failures[0].reason,
            PolicyFailureReason::InsufficientLiquidity {
                channel_id: "ch1".to_string(),
                needed: 100,
                available: 50,
            }
        );
        assert!(report.failures[0].message().contains("50 available"));

        let graph = graph_with(vec![Channel {
            min_htlc_size: 200,
            ..channel("ch2", "alice", "bob", 10_000, 0, 0, 0)
        }]);
        let report = evaluate_route_policy(
            &graph,
            &request("alice", "bob", 100),
            &RoutingPolicy::default(),
        )
        .unwrap();
        assert!(matches!(
            report.failures[0].reason,
            PolicyFailureReason::HtlcOutsideBounds { .. }
        ));
    }

    #[test]
    fn timeout_safety_reports_missing_cltv_and_expiry() {
        let graph = graph_with(vec![
            channel("ch1", "alice", "bob", 10_000, 0, 0, 40),
            channel("ch2", "bob", "carol", 10_000, 0, 0, 40),
        ]);
        let mut req = request("alice", "carol", 1_000);
        req.payment_metadata = Some(PaymentMetadata {
            payment_type: crate::PaymentType::Regular,
            required_cltv_delta: Some(100),
            payment_expiry: None,
        });
        let report = evaluate_route_policy(&graph, &req, &RoutingPolicy::default()).unwrap();
        assert_eq!(
            report.failures[0].reason,
            PolicyFailureReason::UnsafeTimeout {
                channel_id: "ch1".to_string(),
                cltv_delta: 40,
                required: 100,
            }
        );

        let mut req = request("alice", "carol", 1_000);
        req.payment_metadata = Some(PaymentMetadata {
            payment_type: crate::PaymentType::Regular,
            required_cltv_delta: None,
            payment_expiry: Some(50),
        });
        let report = evaluate_route_policy(&graph, &req, &RoutingPolicy::default()).unwrap();
        assert_eq!(
            report.failures[0].reason,
            PolicyFailureReason::TimeoutExceedsExpiry {
                total_cltv: 80,
                expiry: 50,
            }
        );
    }

    #[test]
    fn boundary_values_are_accepted() {
        let graph = graph_with(vec![channel("ch1", "alice", "bob", 100, 1_000, 0, 0)]);
        let mut policy = RoutingPolicy::default();
        policy.max_fee_rate = 1_000;
        let mut request = request("alice", "bob", 100);
        request.max_fee_budget = Some(0);

        let report = evaluate_route_policy(&graph, &request, &policy).unwrap();
        assert_eq!(report.accepted, 1);
        assert!(report.failures.is_empty());
        assert!(report.has_route());

        request.max_fee_budget = Some(-1);
        assert!(matches!(
            evaluate_route_policy(&graph, &request, &policy),
            Err(RoutePolicyError::InvalidRequest(_))
        ));
    }

    #[test]
    fn excluded_channels_and_nodes_are_reported_separately() {
        let graph = graph_with(vec![
            channel("direct", "alice", "bob", 10_000, 0, 0, 0),
            channel("via_carol", "alice", "carol", 10_000, 0, 0, 0),
            channel("last", "carol", "bob", 10_000, 0, 0, 0),
        ]);
        let mut policy = RoutingPolicy::default();
        policy.excluded_channels.insert("direct".to_string());
        policy.excluded_nodes.insert("carol".to_string());

        let report =
            evaluate_route_policy(&graph, &request("alice", "bob", 1_000), &policy).unwrap();
        assert!(report.failures.iter().any(|failure| failure.reason
            == PolicyFailureReason::ExcludedChannel {
                channel_id: "direct".to_string()
            }));
        assert!(report
            .failures
            .iter()
            .any(|failure| matches!(failure.reason, PolicyFailureReason::ExcludedNode { .. })));
    }

    #[test]
    fn invalid_request_and_policy_are_rejected_explicitly() {
        let graph = graph_with(vec![channel("ch1", "alice", "bob", 10_000, 0, 0, 0)]);
        let policy = RoutingPolicy::default();

        let mut blank = request(" ", "bob", 10);
        assert!(matches!(
            evaluate_route_policy(&graph, &blank, &policy),
            Err(RoutePolicyError::InvalidRequest(_))
        ));
        blank.source = "alice".to_string();
        blank.destination = "alice".to_string();
        assert!(matches!(
            evaluate_route_policy(&graph, &blank, &policy),
            Err(RoutePolicyError::InvalidRequest(_))
        ));
        assert!(matches!(
            evaluate_route_policy(&graph, &request("alice", "bob", 0), &policy),
            Err(RoutePolicyError::InvalidRequest(_))
        ));

        let mut bad_policy = RoutingPolicy::default();
        bad_policy.max_hops = 0;
        assert!(matches!(
            evaluate_route_policy(&graph, &request("alice", "bob", 10), &bad_policy),
            Err(RoutePolicyError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn selection_breaks_equal_cost_ties_by_channel_id() {
        let mut graph = graph_with(vec![
            channel("zeta", "alice", "carol", 10_000, 0, 0, 0),
            channel("carol_bob", "carol", "bob", 10_000, 0, 0, 0),
            channel("alpha", "alice", "dave", 10_000, 0, 0, 0),
            channel("dave_bob", "dave", "bob", 10_000, 0, 0, 0),
        ]);
        graph.add_node(Node {
            id: "dave".to_string(),
            public_key: vec![4],
            alias: None,
            online: true,
            last_seen: 1_000,
            features: NodeFeatures::default(),
        });
        let evaluation = evaluate(
            &graph,
            &request("alice", "bob", 1_000),
            &RoutingPolicy::default(),
        )
        .unwrap();
        assert_eq!(evaluation.accepted.len(), 2);
        assert_eq!(evaluation.best().unwrap().summary.channel_ids[0], "alpha");
        assert_eq!(evaluation.report, evaluation.report.clone());
    }

    #[test]
    fn no_candidates_reports_an_empty_failure_list() {
        let graph = graph_with(vec![]);
        let report = evaluate_route_policy(
            &graph,
            &request("alice", "bob", 1_000),
            &RoutingPolicy::default(),
        )
        .unwrap();
        assert!(!report.has_route());
        assert_eq!(report.candidates_evaluated, 0);
        assert!(report.failures.is_empty());
        assert!(report.message().contains("No candidate route"));
    }
}

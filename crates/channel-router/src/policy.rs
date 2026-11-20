//! # Routing Policy Module
//!
//! Routing policies and constraints for the payment channel router.

use crate::{
    Channel, NetworkGraph, Route, RouteHop, RouteMetadata, RouteRequest, RoutingError,
    MAX_ROUTE_HOPS,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Detailed reasons why a route or channel violates a routing policy (Issue #365)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyViolation {
    MaxHopsExceeded {
        actual_hops: usize,
        limit: usize,
    },
    FeeBpsExceeded {
        actual_bps: u32,
        max_bps: u32,
    },
    BaseFeeExceeded {
        base_fee: i128,
        max_base_fee: i128,
        channel_id: String,
    },
    FeeRateExceeded {
        fee_rate: u32,
        max_fee_rate: u32,
        channel_id: String,
    },
    ExcludedNode {
        node: String,
    },
    ExcludedChannel {
        channel_id: String,
    },
    AmountBelowMinimum {
        amount: i128,
        min_amount: i128,
    },
    AmountAboveMaximum {
        amount: i128,
        max_amount: i128,
    },
}

/// Report detailing the outcome of routing policy evaluation (Issue #365)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCheckReport {
    pub passed: bool,
    pub violations: Vec<PolicyViolation>,
}

impl PolicyCheckReport {
    pub fn ok() -> Self {
        Self {
            passed: true,
            violations: Vec::new(),
        }
    }

    pub fn failed(violations: Vec<PolicyViolation>) -> Self {
        Self {
            passed: false,
            violations,
        }
    }

    /// Provide human-readable summary of policy failure reasons
    pub fn diagnostic(&self) -> String {
        if self.passed {
            "Policy check passed".to_string()
        } else {
            let details: Vec<String> = self
                .violations
                .iter()
                .map(|v| match v {
                    PolicyViolation::MaxHopsExceeded { actual_hops, limit } => {
                        format!("hop count {} exceeds limit {}", actual_hops, limit)
                    }
                    PolicyViolation::FeeBpsExceeded {
                        actual_bps,
                        max_bps,
                    } => {
                        format!("fee {} bps exceeds maximum {} bps", actual_bps, max_bps)
                    }
                    PolicyViolation::BaseFeeExceeded {
                        base_fee,
                        max_base_fee,
                        channel_id,
                    } => {
                        format!(
                            "channel {} base fee {} exceeds maximum {}",
                            channel_id, base_fee, max_base_fee
                        )
                    }
                    PolicyViolation::FeeRateExceeded {
                        fee_rate,
                        max_fee_rate,
                        channel_id,
                    } => {
                        format!(
                            "channel {} fee rate {} ppm exceeds maximum {} ppm",
                            channel_id, fee_rate, max_fee_rate
                        )
                    }
                    PolicyViolation::ExcludedNode { node } => {
                        format!("node {} is in policy excluded_nodes", node)
                    }
                    PolicyViolation::ExcludedChannel { channel_id } => {
                        format!("channel {} is in policy excluded_channels", channel_id)
                    }
                    PolicyViolation::AmountBelowMinimum { amount, min_amount } => {
                        format!("amount {} below minimum {}", amount, min_amount)
                    }
                    PolicyViolation::AmountAboveMaximum { amount, max_amount } => {
                        format!("amount {} above maximum {}", amount, max_amount)
                    }
                })
                .collect();
            format!("Policy check failed: {}", details.join("; "))
        }
    }
}

/// Routing preferences and constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingPolicy {
    /// Maximum number of hops
    pub max_hops: usize,
    /// Maximum fee as percentage of amount (basis points)
    pub max_fee_bps: u32,
    /// Maximum base fee
    pub max_base_fee: i128,
    /// Maximum fee rate (ppm)
    pub max_fee_rate: u32,
    /// Excluded node IDs
    pub excluded_nodes: HashSet<String>,
    /// Excluded channel IDs
    pub excluded_channels: HashSet<String>,
    /// Preferred nodes (favor these in routing)
    pub preferred_nodes: HashSet<String>,
    /// Whether to allow MPP (multi-path payments)
    pub allow_mpp: bool,
    /// Whether to allow trampoline routing
    pub allow_trampoline: bool,
    /// Cltv delta preference
    pub prefer_low_cltv: bool,
    /// Minimum amount (dust threshold)
    pub min_amount: i128,
    /// Maximum amount
    pub max_amount: i128,
}

impl Default for RoutingPolicy {
    fn default() -> Self {
        RoutingPolicy {
            max_hops: MAX_ROUTE_HOPS,
            max_fee_bps: 1000, // 10%
            max_base_fee: 1000,
            max_fee_rate: 10000, // 1%
            excluded_nodes: HashSet::new(),
            excluded_channels: HashSet::new(),
            preferred_nodes: HashSet::new(),
            allow_mpp: true,
            allow_trampoline: false,
            prefer_low_cltv: true,
            min_amount: 1,
            max_amount: i128::MAX / 2,
        }
    }
}

impl RoutingPolicy {
    /// Create a policy for high-value payments
    pub fn high_value() -> Self {
        RoutingPolicy {
            max_hops: 10,
            max_fee_bps: 500,       // 5% max
            prefer_low_cltv: false, // Prefer security over speed
            ..Default::default()
        }
    }

    /// Create a policy for micropayments
    pub fn micropayment() -> Self {
        RoutingPolicy {
            max_hops: 5,
            max_fee_bps: 5000, // 50% max (micropayments can have high fees)
            max_base_fee: 100,
            ..Default::default()
        }
    }

    /// Create a policy for privacy-focused routing
    pub fn privacy_focused() -> Self {
        RoutingPolicy {
            max_hops: MAX_ROUTE_HOPS,
            preferred_nodes: HashSet::new(), // Avoid specific nodes
            prefer_low_cltv: false,
            ..Default::default()
        }
    }

    /// Check if a channel meets the policy requirements
    pub fn channel_meets_requirements(&self, channel: &Channel) -> Result<(), RoutingError> {
        // Check excluded channels
        if self.excluded_channels.contains(&channel.id) {
            return Err(RoutingError::ChannelNotFound {
                channel_id: channel.id.clone(),
            });
        }

        // Check excluded nodes
        if self.excluded_nodes.contains(&channel.node_a)
            || self.excluded_nodes.contains(&channel.node_b)
        {
            return Err(RoutingError::NodeNotFound {
                node: "excluded".to_string(),
            });
        }

        // Check fee rate
        if channel.fee_rate > self.max_fee_rate {
            return Err(RoutingError::FeeExceedsBudget {
                fee: channel.fee_rate as i128,
                budget: self.max_fee_rate as i128,
            });
        }

        // Check base fee
        if channel.base_fee > self.max_base_fee {
            return Err(RoutingError::FeeExceedsBudget {
                fee: channel.base_fee,
                budget: self.max_base_fee,
            });
        }

        Ok(())
    }

    /// Check if a route meets the policy requirements
    /// Evaluate all policy constraints on a candidate route, reporting specific violations (Issue #365)
    pub fn evaluate_route(&self, route: &Route, request: &RouteRequest) -> PolicyCheckReport {
        let mut violations = Vec::new();

        if request.amount < self.min_amount {
            violations.push(PolicyViolation::AmountBelowMinimum {
                amount: request.amount,
                min_amount: self.min_amount,
            });
        }

        if request.amount > self.max_amount {
            violations.push(PolicyViolation::AmountAboveMaximum {
                amount: request.amount,
                max_amount: self.max_amount,
            });
        }

        if route.hops.len() > self.max_hops {
            violations.push(PolicyViolation::MaxHopsExceeded {
                actual_hops: route.hops.len(),
                limit: self.max_hops,
            });
        }

        if request.amount > 0 {
            let fee_percent = (route.total_fees as f64 / request.amount as f64 * 10000.0) as u32;
            if fee_percent > self.max_fee_bps {
                violations.push(PolicyViolation::FeeBpsExceeded {
                    actual_bps: fee_percent,
                    max_bps: self.max_fee_bps,
                });
            }
        }

        for hop in &route.hops {
            if self.excluded_channels.contains(&hop.channel_id) {
                violations.push(PolicyViolation::ExcludedChannel {
                    channel_id: hop.channel_id.clone(),
                });
            }

            if self.excluded_nodes.contains(&hop.node_id) {
                violations.push(PolicyViolation::ExcludedNode {
                    node: hop.node_id.clone(),
                });
            }
        }

        if violations.is_empty() {
            PolicyCheckReport::ok()
        } else {
            PolicyCheckReport::failed(violations)
        }
    }

    /// Check if a route meets the policy requirements, returning an actionable error on failure (Issue #365)
    pub fn route_meets_requirements(
        &self,
        route: &Route,
        request: &RouteRequest,
    ) -> Result<(), RoutingError> {
        let report = self.evaluate_route(route, request);
        if !report.passed {
            return Err(RoutingError::PolicyCheckFailed(report.diagnostic()));
        }

        if let Some(budget) = request.max_fee_budget {
            if route.total_fees > budget {
                return Err(RoutingError::FeeExceedsBudget {
                    fee: route.total_fees,
                    budget,
                });
            }
        }

        Ok(())
    }

    /// Apply policy to a route request
    pub fn apply_to_request(&self, mut request: RouteRequest) -> RouteRequest {
        // Apply hop limit
        if request.max_hops.is_none() || request.max_hops > Some(self.max_hops) {
            request.max_hops = Some(self.max_hops);
        }

        // Apply fee budget if not set
        if request.max_fee_budget.is_none() {
            let max_fee = (request.amount as f64 * self.max_fee_bps as f64 / 10000.0) as i128;
            request.max_fee_budget = Some(max_fee);
        }

        request
    }

    /// Calculate a score for a route (lower is better)
    pub fn score_route(&self, route: &Route) -> f64 {
        let mut score = 0.0;

        // Fee score (normalized)
        let fee_score = route.total_fees as f64;
        score += fee_score * 1.0;

        // Hop count score
        let hop_score = route.hops.len() as f64 * 10.0;
        score += hop_score;

        // CLTV delta score (if preferred)
        if self.prefer_low_cltv {
            let cltv_score: i128 = route.hops.iter().map(|h| h.cltv_delta as i128).sum();
            score += cltv_score as f64 * 0.5;
        }

        // Preferred nodes bonus
        for hop in &route.hops {
            if self.preferred_nodes.contains(&hop.node_id) {
                score -= 5.0;
            }
        }

        score
    }
}

/// Fee estimation for routing
pub struct FeeEstimator;

impl FeeEstimator {
    /// Estimate the fee for a route
    pub fn estimate_route_fee(
        graph: &NetworkGraph,
        hops: &[RouteHop],
        amount: i128,
    ) -> Result<i128, RoutingError> {
        let mut total_fee = 0i128;
        let mut remaining = amount;

        for hop in hops {
            let channel =
                graph
                    .get_channel(&hop.channel_id)
                    .ok_or(RoutingError::ChannelNotFound {
                        channel_id: hop.channel_id.clone(),
                    })?;

            let fee = Self::calculate_channel_fee(
                remaining,
                channel.base_fee,
                channel.fee_rate,
                channel.cltv_delta,
            );

            total_fee += fee;
            remaining += fee;
        }

        Ok(total_fee)
    }

    /// Calculate the fee for a single channel
    pub fn calculate_channel_fee(
        amount: i128,
        base_fee: i128,
        fee_rate_ppm: u32,
        cltv_delta: u32,
    ) -> i128 {
        // Fee = base_fee + (amount * fee_rate / 1,000,000) + time_lock_fee
        let proportional = (amount as u128 * fee_rate_ppm as u128 / 1_000_000) as i128;
        let time_lock = (cltv_delta as i128 * 10) / 1440; // ~1 XLM per day

        base_fee + proportional + time_lock
    }

    /// Estimate the fee for routing to a destination
    pub fn estimate_destination_fee(
        _graph: &NetworkGraph,
        _destination: &str,
        amount: i128,
    ) -> Option<i128> {
        // This is a rough estimate based on typical fees
        // In production, you'd use actual pathfinding
        let avg_hops = 3;
        let avg_fee_per_hop = Self::calculate_channel_fee(amount, 1, 1000, 40);

        Some(avg_fee_per_hop * avg_hops as i128)
    }
}

/// Channel selection strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionStrategy {
    /// Select the cheapest route
    Cheapest,
    /// Select the fastest route (fewest hops)
    Fastest,
    /// Select the most reliable route
    MostReliable,
    /// Random selection
    Random,
    /// Privacy-focused selection
    PrivacyFocused,
}

impl SelectionStrategy {
    /// Select the best route according to this strategy
    pub fn select<'a>(&self, routes: &'a [Route], _policy: &RoutingPolicy) -> Option<&'a Route> {
        match self {
            SelectionStrategy::Cheapest => routes.iter().min_by_key(|r| r.total_fees),
            SelectionStrategy::Fastest => routes.iter().min_by_key(|r| r.hops.len()),
            SelectionStrategy::MostReliable => routes
                .iter()
                .max_by_key(|r| (r.success_probability * 1000.0) as i32),
            SelectionStrategy::Random => {
                use rand::seq::SliceRandom;
                routes.choose(&mut rand::thread_rng())
            }
            SelectionStrategy::PrivacyFocused => {
                // Prefer routes with more hops
                routes.iter().max_by_key(|r| r.hops.len())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_defaults() {
        let policy = RoutingPolicy::default();
        assert_eq!(policy.max_hops, MAX_ROUTE_HOPS);
        assert!(policy.allow_mpp);
    }

    #[test]
    fn test_high_value_policy() {
        let policy = RoutingPolicy::high_value();
        assert!(policy.max_fee_bps < 1000);
        assert!(!policy.prefer_low_cltv);
    }

    #[test]
    fn test_policy_violation_reporting() {
        let mut policy = RoutingPolicy::default();
        policy.max_hops = 1;
        policy.excluded_nodes.insert("forbidden_node".to_string());

        let route = Route {
            hops: vec![
                RouteHop::new("c1".to_string(), "forbidden_node".to_string(), 1000, 10, 40),
                RouteHop::new("c2".to_string(), "n2".to_string(), 1000, 10, 40),
            ],
            total_amount: 1000,
            total_fees: 20,
            success_probability: 1.0,
            metadata: RouteMetadata {
                created_at: 0,
                num_nodes: 3,
                estimated_time_ms: 0,
                is_direct: false,
            },
        };

        let request = RouteRequest::new("n0".to_string(), "n2".to_string(), 1000);

        let report = policy.evaluate_route(&route, &request);
        assert!(!report.passed);
        assert!(report
            .violations
            .iter()
            .any(|v| matches!(v, PolicyViolation::MaxHopsExceeded { .. })));
        assert!(report
            .violations
            .iter()
            .any(|v| matches!(v, PolicyViolation::ExcludedNode { .. })));

        let diagnostic = report.diagnostic();
        assert!(diagnostic.contains("hop count 2 exceeds limit 1"));
        assert!(diagnostic.contains("forbidden_node"));
    }
}

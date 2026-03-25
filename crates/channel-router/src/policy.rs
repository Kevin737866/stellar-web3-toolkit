//! # Routing Policy Module
//! 
//! Routing policies and constraints for the payment channel router.

use crate::{NetworkGraph, Channel, Route, RouteRequest, RouteHop, RoutingError, MAX_ROUTE_HOPS};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

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
            max_fee_bps: 500, // 5% max
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
                channel_id: channel.id.clone()
            });
        }
        
        // Check excluded nodes
        if self.excluded_nodes.contains(&channel.node_a) || self.excluded_nodes.contains(&channel.node_b) {
            return Err(RoutingError::NodeNotFound {
                node: "excluded".to_string()
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
    pub fn route_meets_requirements(&self, route: &Route, request: &RouteRequest) -> Result<(), RoutingError> {
        // Check hop limit
        if route.hops.len() > self.max_hops {
            return Err(RoutingError::PathTooLong {
                length: route.hops.len(),
                max: self.max_hops,
            });
        }
        
        // Check fee percentage
        let fee_percent = (route.total_fees as f64 / request.amount as f64 * 10000.0) as u32;
        if fee_percent > self.max_fee_bps {
            return Err(RoutingError::FeeExceedsBudget {
                fee: route.total_fees,
                budget: (request.amount as f64 * self.max_fee_bps as f64 / 10000.0) as i128,
            });
        }
        
        // Check amount limits
        if request.amount < self.min_amount {
            return Err(RoutingError::BelowDustLimit {
                amount: request.amount,
                dust_limit: self.min_amount,
            });
        }
        
        if request.amount > self.max_amount {
            return Err(RoutingError::AmountExceedsMaximum {
                amount: request.amount,
                max_amount: self.max_amount,
            });
        }
        
        // Check excluded nodes
        for hop in &route.hops {
            if self.excluded_nodes.contains(&hop.node_id) {
                return Err(RoutingError::NodeNotFound {
                    node: hop.node_id.clone()
                });
            }
        }
        
        // Check excluded channels
        for hop in &route.hops {
            if self.excluded_channels.contains(&hop.channel_id) {
                return Err(RoutingError::ChannelNotFound {
                    channel_id: hop.channel_id.clone()
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
            let channel = graph.get_channel(&hop.channel_id)
                .ok_or(RoutingError::ChannelNotFound {
                    channel_id: hop.channel_id.clone()
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
        graph: &NetworkGraph,
        destination: &str,
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
    pub fn select<'a>(
        &self,
        routes: &'a [Route],
        _policy: &RoutingPolicy,
    ) -> Option<&'a Route> {
        match self {
            SelectionStrategy::Cheapest => {
                routes.iter().min_by_key(|r| r.total_fees)
            }
            SelectionStrategy::Fastest => {
                routes.iter().min_by_key(|r| r.hops.len())
            }
            SelectionStrategy::MostReliable => {
                routes.iter().max_by_key(|r| (r.success_probability * 1000.0) as i32)
            }
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
}

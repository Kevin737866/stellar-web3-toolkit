//! # Failed Payment Summaries
//!
//! When a simulated payment fails, the router's error says *why* for that one
//! payment but the simulator used to discard it after a `debug!` line. A run of
//! ten thousand payments then reported a success rate and nothing else, leaving
//! the operator unable to tell an exhausted channel from an unreachable
//! destination.
//!
//! [`FailureSummary`] aggregates those errors by [`FailureCategory`], keeps the
//! full error message for a bounded number of examples, and is exposed through
//! [`crate::Simulator::failure_summary`] after a run.

use channel_router::RoutingError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Maximum number of individual failures retained as examples in a summary.
///
/// Counts are always exact; only the examples are capped, so a run that fails
/// every payment does not grow the summary without bound.
pub const MAX_FAILURE_SAMPLES: usize = 20;

/// Coarse reason a simulated payment could not be routed.
///
/// The categories mirror [`RoutingError`] but are deliberately coarser: the
/// simulator groups failures for a report, and the exact channel or node
/// involved is preserved in each [`FailedPayment::reason`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCategory {
    /// No path exists between source and destination.
    NoPathFound,
    /// The source node has no channels at all.
    NoChannelsForNode,
    /// A hop did not have enough capacity in the direction needed.
    InsufficientCapacity,
    /// The amount was below a channel's dust limit.
    BelowDustLimit,
    /// The amount exceeded the router's maximum.
    AmountExceedsMaximum,
    /// The route needed more hops than allowed.
    PathTooLong,
    /// The route fee exceeded the request's budget.
    FeeExceedsBudget,
    /// A referenced node is not in the graph.
    NodeNotFound,
    /// A referenced channel is not in the graph.
    ChannelNotFound,
    /// A node address was malformed.
    InvalidNodeAddress,
    /// A hop or route advertised fees above the protocol cap.
    FeeCapRejected,
    /// A reason this summary does not categorise (kept so nothing is dropped).
    Other,
}

impl FailureCategory {
    /// Stable identifier used as the key in
    /// [`FailureSummary::by_category`] and in logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            FailureCategory::NoPathFound => "no_path_found",
            FailureCategory::NoChannelsForNode => "no_channels_for_node",
            FailureCategory::InsufficientCapacity => "insufficient_capacity",
            FailureCategory::BelowDustLimit => "below_dust_limit",
            FailureCategory::AmountExceedsMaximum => "amount_exceeds_maximum",
            FailureCategory::PathTooLong => "path_too_long",
            FailureCategory::FeeExceedsBudget => "fee_exceeds_budget",
            FailureCategory::NodeNotFound => "node_not_found",
            FailureCategory::ChannelNotFound => "channel_not_found",
            FailureCategory::InvalidNodeAddress => "invalid_node_address",
            FailureCategory::FeeCapRejected => "fee_cap_rejected",
            FailureCategory::Other => "other",
        }
    }

    /// Classify a router error.
    ///
    /// Every [`RoutingError`] variant is mapped explicitly rather than through a
    /// catch-all match, so adding a variant to the router is a compile error
    /// here instead of silently landing in [`FailureCategory::Other`].
    pub fn from_routing_error(error: &RoutingError) -> Self {
        match error {
            RoutingError::NoPathFound { .. } => FailureCategory::NoPathFound,
            RoutingError::NoChannelsForNode { .. } => FailureCategory::NoChannelsForNode,
            RoutingError::InsufficientCapacity { .. } => FailureCategory::InsufficientCapacity,
            RoutingError::BelowDustLimit { .. } => FailureCategory::BelowDustLimit,
            RoutingError::AmountExceedsMaximum { .. } => FailureCategory::AmountExceedsMaximum,
            RoutingError::PathTooLong { .. } => FailureCategory::PathTooLong,
            RoutingError::FeeExceedsBudget { .. } => FailureCategory::FeeExceedsBudget,
            RoutingError::NodeNotFound { .. } => FailureCategory::NodeNotFound,
            RoutingError::ChannelNotFound { .. } => FailureCategory::ChannelNotFound,
            RoutingError::InvalidNodeAddress => FailureCategory::InvalidNodeAddress,
            RoutingError::ChannelFeeRateCapExceeded { .. }
            | RoutingError::ChannelBaseFeeCapExceeded { .. }
            | RoutingError::HopFeeCapExceeded { .. }
            | RoutingError::RouteFeeCapExceeded { .. } => FailureCategory::FeeCapRejected,
            RoutingError::InconsistentRouteFees { .. }
            | RoutingError::PolicyCheckFailed(_)
            | RoutingError::TimeoutExceedsBudget { .. }
            | RoutingError::InvalidHopTimeout { .. }
            | RoutingError::TimeoutOverflow
            | RoutingError::ChannelTemporarilyUnavailable { .. } => FailureCategory::Other,
        }
    }
}

impl std::fmt::Display for FailureCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One failed payment, with the router's original error message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailedPayment {
    /// Source node of the payment.
    pub source: String,
    /// Destination node of the payment.
    pub destination: String,
    /// Amount the payment tried to move.
    pub amount: i128,
    /// Coarse category for reporting.
    pub category: FailureCategory,
    /// The router's message, verbatim, so a sample is actionable on its own.
    pub reason: String,
}

/// Aggregate view of every payment that failed during a simulation.
///
/// Counts are exact; `samples` holds at most [`MAX_FAILURE_SAMPLES`] failures in
/// the order they occurred. The map is a [`BTreeMap`] so reports order
/// categories deterministically across platforms.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureSummary {
    /// Total number of failed payments.
    pub total_failed: usize,
    /// Failed payments per [`FailureCategory::as_str`] key.
    pub by_category: BTreeMap<String, usize>,
    /// A bounded set of example failures, in occurrence order.
    pub samples: Vec<FailedPayment>,
}

impl FailureSummary {
    /// An empty summary.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one failure, incrementing its category count.
    ///
    /// The first [`MAX_FAILURE_SAMPLES`] failures are retained as examples;
    /// later ones still count.
    pub fn record(&mut self, failure: FailedPayment) {
        self.total_failed += 1;
        *self
            .by_category
            .entry(failure.category.as_str().to_string())
            .or_insert(0) += 1;
        if self.samples.len() < MAX_FAILURE_SAMPLES {
            self.samples.push(failure);
        }
    }

    /// True when no payment failed.
    pub fn is_empty(&self) -> bool {
        self.total_failed == 0
    }

    /// Number of failures recorded for `category`.
    pub fn category_count(&self, category: FailureCategory) -> usize {
        self.by_category
            .get(category.as_str())
            .copied()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure(source: &str, category: FailureCategory) -> FailedPayment {
        FailedPayment {
            source: source.to_string(),
            destination: "dest".to_string(),
            amount: 1_000,
            category,
            reason: format!("{category} for {source}"),
        }
    }

    #[test]
    fn every_router_error_maps_to_its_own_category() {
        let cases: Vec<(RoutingError, FailureCategory)> = vec![
            (
                RoutingError::NoPathFound {
                    origin: "a".to_string(),
                    destination: "b".to_string(),
                },
                FailureCategory::NoPathFound,
            ),
            (
                RoutingError::NoChannelsForNode {
                    node: "a".to_string(),
                },
                FailureCategory::NoChannelsForNode,
            ),
            (
                RoutingError::InsufficientCapacity {
                    needed: 2,
                    available: 1,
                    channel_id: "ch".to_string(),
                },
                FailureCategory::InsufficientCapacity,
            ),
            (
                RoutingError::BelowDustLimit {
                    amount: 1,
                    dust_limit: 2,
                },
                FailureCategory::BelowDustLimit,
            ),
            (
                RoutingError::AmountExceedsMaximum {
                    amount: 9,
                    max_amount: 1,
                },
                FailureCategory::AmountExceedsMaximum,
            ),
            (
                RoutingError::PathTooLong {
                    length: 30,
                    max: 20,
                },
                FailureCategory::PathTooLong,
            ),
            (
                RoutingError::FeeExceedsBudget { fee: 9, budget: 1 },
                FailureCategory::FeeExceedsBudget,
            ),
            (
                RoutingError::NodeNotFound {
                    node: "a".to_string(),
                },
                FailureCategory::NodeNotFound,
            ),
            (
                RoutingError::ChannelNotFound {
                    channel_id: "ch".to_string(),
                },
                FailureCategory::ChannelNotFound,
            ),
            (
                RoutingError::InvalidNodeAddress,
                FailureCategory::InvalidNodeAddress,
            ),
            (
                RoutingError::ChannelFeeRateCapExceeded {
                    channel_id: "ch".to_string(),
                    fee_rate: 9,
                    cap: 1,
                },
                FailureCategory::FeeCapRejected,
            ),
            (
                RoutingError::ChannelBaseFeeCapExceeded {
                    channel_id: "ch".to_string(),
                    base_fee: 9,
                    cap: 1,
                },
                FailureCategory::FeeCapRejected,
            ),
            (
                RoutingError::HopFeeCapExceeded {
                    fee: 9,
                    channel_id: "ch".to_string(),
                    cap: 1,
                },
                FailureCategory::FeeCapRejected,
            ),
            (
                RoutingError::RouteFeeCapExceeded {
                    fee: 9,
                    cap: 1,
                    amount: 1,
                },
                FailureCategory::FeeCapRejected,
            ),
            (
                RoutingError::InconsistentRouteFees {
                    declared: 1,
                    actual: 2,
                },
                FailureCategory::Other,
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(
                FailureCategory::from_routing_error(&error),
                expected,
                "wrong category for {error:?}"
            );
        }
    }

    #[test]
    fn counts_are_exact_while_samples_are_bounded() {
        let mut summary = FailureSummary::new();
        assert!(summary.is_empty());

        let overflow = MAX_FAILURE_SAMPLES + 5;
        for i in 0..overflow {
            summary.record(failure(&format!("node_{i}"), FailureCategory::NoPathFound));
        }
        summary.record(failure("last", FailureCategory::InsufficientCapacity));

        assert_eq!(summary.total_failed, overflow + 1);
        assert_eq!(summary.samples.len(), MAX_FAILURE_SAMPLES);
        assert_eq!(
            summary.category_count(FailureCategory::NoPathFound),
            overflow
        );
        assert_eq!(
            summary.category_count(FailureCategory::InsufficientCapacity),
            1
        );
        assert_eq!(summary.category_count(FailureCategory::PathTooLong), 0);
        assert!(!summary.is_empty());

        // Categories are keyed by their stable identifier and sorted by it.
        let keys: Vec<&String> = summary.by_category.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn each_category_has_a_distinct_stable_key() {
        let categories = [
            FailureCategory::NoPathFound,
            FailureCategory::NoChannelsForNode,
            FailureCategory::InsufficientCapacity,
            FailureCategory::BelowDustLimit,
            FailureCategory::AmountExceedsMaximum,
            FailureCategory::PathTooLong,
            FailureCategory::FeeExceedsBudget,
            FailureCategory::NodeNotFound,
            FailureCategory::ChannelNotFound,
            FailureCategory::InvalidNodeAddress,
            FailureCategory::FeeCapRejected,
            FailureCategory::Other,
        ];

        let mut keys: Vec<&str> = categories.iter().map(|c| c.as_str()).collect();
        assert!(keys.iter().all(|key| !key.is_empty()));
        keys.sort_unstable();
        let count = keys.len();
        keys.dedup();
        assert_eq!(keys.len(), count, "categories must not share a key");
    }
}

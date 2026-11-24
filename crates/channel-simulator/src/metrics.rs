//! # Payment Success Metrics by Route Length
//!
//! Breaks payment success down by the number of hops a payment has to take, so
//! a simulation reports *where* it fails instead of only how often.
//!
//! A single aggregate success rate hides the shape of the problem: a network can
//! look healthy at 85% overall while failing almost every payment that needs
//! four or more hops, which is exactly the regime a routing or fee change is
//! supposed to fix. Bucketing by route length makes that visible.
//!
//! ## Which length a payment is bucketed under
//!
//! * **Successful payment** — the number of hops in the route the router
//!   returned, i.e. the length actually used.
//! * **Failed payment that had a path** — the shortest hop distance between
//!   source and destination in the topology, ignoring capacity and fees. The
//!   payment would have needed at least that many hops, so it is counted
//!   against the bucket it was trying to reach.
//! * **Failed payment with no path at all** — counted in
//!   [`PaymentSuccessMetrics::unroutable`]. It belongs to no length bucket,
//!   because no route of any length exists in the topology.
//!
//! Counting failures by topological distance rather than by the hops a route
//! *would* have had keeps the denominator honest: a payment that fails because
//! a four-hop route is over capacity is a failure of four-hop routing, and
//! leaving it out of that bucket would inflate the reported success rate for
//! long routes.

use crate::SimulatorError;
use channel_router::NetworkGraph;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet, VecDeque};

/// Success statistics for one route length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RouteLengthBucket {
    /// Route length this bucket counts, in hops. `1` is a direct channel.
    pub route_length: usize,
    /// Payments attempted that would take this many hops.
    pub attempted: usize,
    /// Of those, the ones that routed.
    pub successful: usize,
    /// Of those, the ones that did not.
    pub failed: usize,
    /// Value successfully routed at this length.
    pub value_routed: i128,
}

impl RouteLengthBucket {
    /// A bucket for `route_length`, with no attempts recorded yet.
    pub fn new(route_length: usize) -> Self {
        Self {
            route_length,
            ..Self::default()
        }
    }

    /// Success rate as a percentage in `[0, 100]`.
    ///
    /// An empty bucket reports `0.0` rather than dividing by zero; check
    /// [`Self::attempted`] before treating the rate as meaningful.
    pub fn success_rate(&self) -> f64 {
        if self.attempted == 0 {
            return 0.0;
        }
        self.successful as f64 / self.attempted as f64 * 100.0
    }

    /// Whether any payment was bucketed here.
    pub fn is_empty(&self) -> bool {
        self.attempted == 0
    }
}

/// Payment outcomes grouped by route length.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentSuccessMetrics {
    /// One bucket per route length that was attempted, in ascending length
    /// order so reports and serialized forms are deterministic.
    pub by_route_length: BTreeMap<usize, RouteLengthBucket>,
    /// Payments attempted between nodes with no path at all in the topology.
    pub unroutable: usize,
}

impl PaymentSuccessMetrics {
    /// An empty metric set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one payment outcome.
    ///
    /// `route_length` is the number of hops the payment used, or the shortest
    /// hop distance it would have needed. `None` means no route of any length
    /// exists, and is recorded in [`Self::unroutable`].
    ///
    /// # Errors
    ///
    /// Rejects a zero route length (no route can have zero hops), a non-positive
    /// amount and a negative value rather than folding them into a bucket: a
    /// silently accepted zero would make the shortest bucket cover payments it
    /// does not describe.
    pub fn record(
        &mut self,
        route_length: Option<usize>,
        success: bool,
        amount: i128,
    ) -> Result<(), SimulatorError> {
        if amount <= 0 {
            return Err(SimulatorError::InvalidConfig(format!(
                "payment amount must be positive, got {amount}"
            )));
        }

        let Some(route_length) = route_length else {
            self.unroutable += 1;
            return Ok(());
        };

        if route_length == 0 {
            return Err(SimulatorError::InvalidRouteLength(route_length));
        }

        let bucket = self
            .by_route_length
            .entry(route_length)
            .or_insert_with(|| RouteLengthBucket::new(route_length));

        bucket.attempted += 1;
        if success {
            bucket.successful += 1;
            bucket.value_routed = bucket.value_routed.saturating_add(amount);
        } else {
            bucket.failed += 1;
        }

        Ok(())
    }

    /// The bucket for `route_length`, if any payment was attempted at it.
    pub fn bucket(&self, route_length: usize) -> Option<&RouteLengthBucket> {
        self.by_route_length.get(&route_length)
    }

    /// Success rate as a percentage for `route_length`, if it was attempted.
    pub fn success_rate_for(&self, route_length: usize) -> Option<f64> {
        self.bucket(route_length)
            .map(RouteLengthBucket::success_rate)
    }

    /// Route lengths that were attempted, in ascending order.
    pub fn route_lengths(&self) -> impl Iterator<Item = usize> + '_ {
        self.by_route_length.keys().copied()
    }

    /// Shortest attempted route length.
    pub fn min_route_length(&self) -> Option<usize> {
        self.by_route_length.keys().next().copied()
    }

    /// Longest attempted route length.
    pub fn max_route_length(&self) -> Option<usize> {
        self.by_route_length.keys().next_back().copied()
    }

    /// Total payments counted, including unroutable ones.
    pub fn total_attempted(&self) -> usize {
        self.by_route_length
            .values()
            .map(|bucket| bucket.attempted)
            .sum::<usize>()
            + self.unroutable
    }

    /// Total payments that routed, across every bucket.
    pub fn total_successful(&self) -> usize {
        self.by_route_length
            .values()
            .map(|bucket| bucket.successful)
            .sum()
    }

    /// Overall success rate as a percentage, over routed and unroutable
    /// attempts alike.
    pub fn overall_success_rate(&self) -> f64 {
        let attempted = self.total_attempted();
        if attempted == 0 {
            return 0.0;
        }
        self.total_successful() as f64 / attempted as f64 * 100.0
    }

    /// The attempted route length with the highest success rate.
    ///
    /// Ties are broken by the shorter route length, so the answer does not
    /// depend on map iteration order.
    pub fn best_route_length(&self) -> Option<(usize, f64)> {
        self.by_route_length
            .values()
            .filter(|bucket| !bucket.is_empty())
            .map(|bucket| (bucket.route_length, bucket.success_rate()))
            .reduce(|best, candidate| {
                if candidate.1 > best.1 {
                    candidate
                } else {
                    best
                }
            })
    }
}

/// Shortest hop distance from `source` to `destination`, ignoring capacity, fees
/// and channel state.
///
/// Returns `None` when either node is unknown to the graph or when no path
/// connects them. A node is at distance `0` from itself.
pub fn hop_distance(graph: &NetworkGraph, source: &str, destination: &str) -> Option<usize> {
    if !graph.has_node(source) || !graph.has_node(destination) {
        return None;
    }
    if source == destination {
        return Some(0);
    }

    let mut visited: HashSet<&str> = HashSet::new();
    let mut queue: VecDeque<(&str, usize)> = VecDeque::new();

    visited.insert(source);
    queue.push_back((source, 0));

    while let Some((node, distance)) = queue.pop_front() {
        let Some(neighbours) = graph.adjacency.get(node) else {
            continue;
        };

        for neighbour in neighbours.keys() {
            if neighbour == destination {
                return Some(distance + 1);
            }
            if visited.insert(neighbour) {
                queue.push_back((neighbour, distance + 1));
            }
        }
    }

    None
}

#[cfg(test)]
#[allow(clippy::float_cmp)] // the fixtures assert exact values they construct
mod tests {
    use super::*;
    use channel_router::{Channel, Node, NodeFeatures};

    fn graph_with_line(length: usize) -> NetworkGraph {
        let mut graph = NetworkGraph::new();
        for i in 0..length {
            graph.add_node(Node {
                id: format!("n{i}"),
                public_key: vec![],
                alias: None,
                online: true,
                last_seen: 0,
                features: NodeFeatures::default(),
            });
        }
        for i in 0..length.saturating_sub(1) {
            graph.add_channel(Channel {
                id: format!("ch{i}"),
                node_a: format!("n{i}"),
                node_b: format!("n{}", i + 1),
                capacity_a_to_b: 1_000,
                capacity_b_to_a: 1_000,
                base_fee: 0,
                fee_rate: 0,
                cltv_delta: 0,
                min_htlc_size: 1,
                max_htlc_size: 1_000,
                htlcs_in_flight: 0,
                enabled: true,
                age_seconds: 0,
            });
        }
        graph
    }

    #[test]
    fn an_empty_metric_set_reports_nothing() {
        let metrics = PaymentSuccessMetrics::new();
        assert_eq!(metrics.total_attempted(), 0);
        assert_eq!(metrics.overall_success_rate(), 0.0);
        assert_eq!(metrics.min_route_length(), None);
        assert_eq!(metrics.max_route_length(), None);
        assert_eq!(metrics.best_route_length(), None);
        assert_eq!(metrics.route_lengths().count(), 0);
        assert_eq!(metrics.success_rate_for(1), None);
    }

    #[test]
    fn a_single_hop_payment_is_bucketed_at_length_one() {
        let mut metrics = PaymentSuccessMetrics::new();
        metrics.record(Some(1), true, 500).unwrap();

        let bucket = metrics.bucket(1).expect("bucket 1");
        assert_eq!(bucket.route_length, 1);
        assert_eq!(bucket.attempted, 1);
        assert_eq!(bucket.successful, 1);
        assert_eq!(bucket.failed, 0);
        assert_eq!(bucket.value_routed, 500);
        assert!((bucket.success_rate() - 100.0).abs() < f64::EPSILON);
        assert_eq!(metrics.success_rate_for(1), Some(100.0));
        assert_eq!(metrics.overall_success_rate(), 100.0);
    }

    #[test]
    fn each_route_length_gets_its_own_success_rate() {
        let mut metrics = PaymentSuccessMetrics::new();
        // Direct payments all succeed.
        metrics.record(Some(1), true, 100).unwrap();
        metrics.record(Some(1), true, 100).unwrap();
        // Two-hop payments mostly fail.
        metrics.record(Some(2), true, 200).unwrap();
        metrics.record(Some(2), false, 200).unwrap();
        metrics.record(Some(2), false, 200).unwrap();

        assert_eq!(metrics.success_rate_for(1), Some(100.0));
        let two_hop_rate = metrics.success_rate_for(2).expect("bucket 2");
        assert!((two_hop_rate - 100.0 / 3.0).abs() < 1e-9, "{two_hop_rate}");
        // The aggregate hides the long-route problem; the buckets show it.
        assert!((metrics.overall_success_rate() - 60.0).abs() < 1e-9);
        assert_eq!(metrics.total_attempted(), 5);
        assert_eq!(metrics.total_successful(), 3);
        assert_eq!(metrics.bucket(2).unwrap().value_routed, 200);
    }

    #[test]
    fn unroutable_attempts_are_counted_outside_the_buckets() {
        let mut metrics = PaymentSuccessMetrics::new();
        metrics.record(Some(2), false, 10).unwrap();
        metrics.record(None, false, 10).unwrap();
        metrics.record(None, false, 10).unwrap();

        assert_eq!(metrics.unroutable, 2);
        assert_eq!(metrics.total_attempted(), 3);
        assert_eq!(metrics.total_successful(), 0);
        assert_eq!(metrics.overall_success_rate(), 0.0);
        // No path at all must not invent a length bucket.
        assert_eq!(metrics.by_route_length.len(), 1);
        assert_eq!(metrics.route_lengths().collect::<Vec<_>>(), vec![2]);
    }

    #[test]
    fn buckets_are_ordered_and_bounded_deterministically() {
        let mut metrics = PaymentSuccessMetrics::new();
        for length in [5usize, 2, 4, 1, 3] {
            metrics.record(Some(length), true, 1).unwrap();
        }

        assert_eq!(
            metrics.route_lengths().collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
        assert_eq!(metrics.min_route_length(), Some(1));
        assert_eq!(metrics.max_route_length(), Some(5));
    }

    #[test]
    fn a_zero_hop_route_length_is_rejected_without_touching_state() {
        let mut metrics = PaymentSuccessMetrics::new();
        let err = metrics.record(Some(0), true, 10).unwrap_err();

        assert!(matches!(err, SimulatorError::InvalidRouteLength(0)));
        assert!(err.to_string().contains("route length"));
        assert_eq!(metrics.total_attempted(), 0);
        assert!(metrics.by_route_length.is_empty());
    }

    #[test]
    fn non_positive_amounts_are_rejected_without_touching_state() {
        let mut metrics = PaymentSuccessMetrics::new();

        for amount in [0i128, -1] {
            let err = metrics.record(Some(2), true, amount).unwrap_err();
            assert!(matches!(err, SimulatorError::InvalidConfig(_)));
        }

        assert_eq!(metrics.total_attempted(), 0);
        assert_eq!(metrics.unroutable, 0);
    }

    #[test]
    fn a_tie_for_best_rate_prefers_the_shorter_route() {
        let mut metrics = PaymentSuccessMetrics::new();
        metrics.record(Some(3), true, 1).unwrap();
        metrics.record(Some(1), true, 1).unwrap();

        assert_eq!(metrics.best_route_length(), Some((1, 100.0)));
    }

    #[test]
    fn value_routed_saturates_instead_of_overflowing() {
        let mut metrics = PaymentSuccessMetrics::new();
        metrics.record(Some(1), true, i128::MAX).unwrap();
        metrics.record(Some(1), true, i128::MAX).unwrap();

        assert_eq!(metrics.bucket(1).unwrap().value_routed, i128::MAX);
    }

    #[test]
    fn hop_distance_walks_a_line_and_reports_unreachable_pairs() {
        let graph = graph_with_line(4);

        assert_eq!(hop_distance(&graph, "n0", "n0"), Some(0));
        assert_eq!(hop_distance(&graph, "n0", "n1"), Some(1));
        assert_eq!(hop_distance(&graph, "n0", "n3"), Some(3));
        assert_eq!(hop_distance(&graph, "n3", "n0"), Some(3));
        assert_eq!(hop_distance(&graph, "n0", "missing"), None);

        let mut disconnected = graph_with_line(2);
        disconnected.add_node(Node {
            id: "island".to_string(),
            public_key: vec![],
            alias: None,
            online: true,
            last_seen: 0,
            features: NodeFeatures::default(),
        });
        assert_eq!(hop_distance(&disconnected, "n0", "island"), None);
    }
}

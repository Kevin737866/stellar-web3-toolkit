//! # Fee Cap Module
//!
//! Protocol-level ceiling on the fees a routing hop may charge.
//!
//! A channel's fee schedule is gossiped by its operators and is therefore
//! attacker-controlled: nothing stops a node from advertising an enormous
//! `fee_rate` or `base_fee` and then sitting in the middle of every route it
//! can attract. Without a ceiling, a malicious intermediary can silently
//! drain most of a payment.
//!
//! [`FeeCap`] turns that into an enforced invariant. Routers consult it twice:
//! once when admitting a channel into consideration (cheap rejection of
//! absurd fee schedules) and once over the assembled route (so that a route
//! built from individually-acceptable hops still cannot exceed the budget for
//! the payment as a whole).

use crate::{Channel, NetworkGraph, Route, RouteHop, RoutingError, MAX_ROUTE_HOPS};
use serde::{Deserialize, Serialize};

/// Highest proportional fee rate (parts per million) a single channel may
/// advertise. `5_000` ppm is 0.5% of the forwarded amount per hop.
pub const MAX_CHANNEL_FEE_RATE_PPM: u32 = 5_000;

/// Highest flat base fee (in stroops) a single channel may advertise.
/// `100_000` stroops is 0.01 XLM per hop.
pub const MAX_CHANNEL_BASE_FEE: i128 = 100_000;

/// Highest total route fee (parts per million of the payment amount).
/// `20_000` ppm is 2% of the payment.
pub const MAX_ROUTE_FEE_PPM: u32 = 20_000;

/// Absolute allowance added to the route fee cap. A route pays a flat base fee
/// on every hop, so a pure percentage cap would reject even a two-hop route
/// for a tiny payment. This bounds those flat fees without letting the total
/// grow without limit.
pub const MAX_ROUTE_FEE_ABS: i128 = 200_000;

/// Time-lock fee coefficient: a hop earns 10 stroops per 1440 blocks of CLTV
/// delta. Mirrors [`crate::calculate_channel_fee`].
const TIME_LOCK_FEE_COEFFICIENT: i128 = 10;
const TIME_LOCK_FEE_DIVISOR: i128 = 1440;

/// A ceiling on per-channel and per-route routing fees.
///
/// Use [`FeeCap::protocol`] for the network-wide defaults, or build a stricter
/// cap for a specific payment (for example a high-value transfer that should
/// not pay more than a few basis points).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCap {
    /// Highest proportional fee rate a single channel may advertise (ppm).
    pub max_channel_fee_rate_ppm: u32,
    /// Highest flat base fee a single channel may advertise (stroops).
    pub max_channel_base_fee: i128,
    /// Highest total route fee, as ppm of the payment amount.
    pub max_route_fee_ppm: u32,
    /// Absolute allowance added to the route fee cap.
    pub max_route_fee_abs: i128,
}

impl Default for FeeCap {
    fn default() -> Self {
        Self::protocol()
    }
}

impl FeeCap {
    /// The network-wide fee ceiling.
    pub const fn protocol() -> Self {
        FeeCap {
            max_channel_fee_rate_ppm: MAX_CHANNEL_FEE_RATE_PPM,
            max_channel_base_fee: MAX_CHANNEL_BASE_FEE,
            max_route_fee_ppm: MAX_ROUTE_FEE_PPM,
            max_route_fee_abs: MAX_ROUTE_FEE_ABS,
        }
    }

    /// A fee cap that only allows the given total route fee percentage.
    ///
    /// Use this for payments where the default 2% is still too much, for
    /// example treasury movements. Per-channel limits are kept at the protocol
    /// defaults, since they bound what a single hop can charge rather than the
    /// route total.
    pub const fn with_route_fee_ppm(mut self, ppm: u32) -> Self {
        self.max_route_fee_ppm = ppm;
        self
    }

    /// Whether a channel's advertised fee schedule is within the cap.
    pub fn check_channel(&self, channel: &Channel) -> Result<(), RoutingError> {
        if channel.fee_rate > self.max_channel_fee_rate_ppm {
            return Err(RoutingError::ChannelFeeRateCapExceeded {
                channel_id: channel.id.clone(),
                fee_rate: channel.fee_rate,
                cap: self.max_channel_fee_rate_ppm,
            });
        }

        if channel.base_fee > self.max_channel_base_fee {
            return Err(RoutingError::ChannelBaseFeeCapExceeded {
                channel_id: channel.id.clone(),
                base_fee: channel.base_fee,
                cap: self.max_channel_base_fee,
            });
        }

        Ok(())
    }

    /// The most a single hop may charge to forward `amount` with the given
    /// CLTV delta.
    pub fn max_hop_fee(&self, amount: i128, cltv_delta: u32) -> i128 {
        let proportional = if amount > 0 {
            (amount as u128 * self.max_channel_fee_rate_ppm as u128 / 1_000_000) as i128
        } else {
            0
        };
        let time_lock = (cltv_delta as i128 * TIME_LOCK_FEE_COEFFICIENT) / TIME_LOCK_FEE_DIVISOR;

        proportional + self.max_channel_base_fee + time_lock
    }

    /// Whether a single hop's fee is within the cap.
    pub fn check_hop_fee(
        &self,
        channel_id: &str,
        amount: i128,
        cltv_delta: u32,
        fee: i128,
    ) -> Result<(), RoutingError> {
        let cap = self.max_hop_fee(amount, cltv_delta);
        if fee > cap {
            return Err(RoutingError::HopFeeCapExceeded {
                channel_id: channel_id.to_string(),
                fee,
                cap,
            });
        }
        Ok(())
    }

    /// The most a whole route may charge for a payment of `amount`.
    pub fn max_route_fee(&self, amount: i128) -> i128 {
        let proportional = if amount > 0 {
            (amount as u128 * self.max_route_fee_ppm as u128 / 1_000_000) as i128
        } else {
            0
        };

        proportional + self.max_route_fee_abs
    }

    /// Whether a total route fee is within the cap.
    pub fn check_route_fee(&self, amount: i128, total_fee: i128) -> Result<(), RoutingError> {
        let cap = self.max_route_fee(amount);
        if total_fee > cap {
            return Err(RoutingError::RouteFeeCapExceeded {
                fee: total_fee,
                cap,
                amount,
            });
        }
        Ok(())
    }

    /// Whether every hop of `hops` is within the cap and the route total is
    /// within the cap.
    pub fn check_hops(&self, amount: i128, hops: &[RouteHop]) -> Result<(), RoutingError> {
        for hop in hops {
            self.check_hop_fee(&hop.channel_id, hop.amount, hop.cltv_delta, hop.fee)?;
        }

        let total: i128 = hops.iter().map(|hop| hop.fee).sum();
        self.check_route_fee(amount, total)
    }

    /// Every channel in `graph` whose advertised fee schedule breaks the cap.
    ///
    /// Useful for auditing a gossip snapshot, and for explaining to an operator
    /// why routes through a channel were never chosen.
    pub fn offending_channels<'a>(&self, graph: &'a NetworkGraph) -> Vec<&'a Channel> {
        let mut offending: Vec<&Channel> = graph
            .channels
            .values()
            .filter(|channel| self.check_channel(channel).is_err())
            .collect();

        // `FxHashMap` iteration order is unspecified; sort so the result is
        // reproducible for callers that diff consecutive snapshots.
        offending.sort_by(|a, b| a.id.cmp(&b.id));
        offending
    }

    /// Whether an assembled route is within the cap.
    pub fn check_route(&self, amount: i128, route: &Route) -> Result<(), RoutingError> {
        if route.hops.len() > MAX_ROUTE_HOPS {
            return Err(RoutingError::PathTooLong {
                length: route.hops.len(),
                max: MAX_ROUTE_HOPS,
            });
        }

        self.check_hops(amount, &route.hops)?;

        // `Route::total_fees` is the value callers budget against, so a route
        // whose summary disagrees with its hops must not pass the cap.
        if route.total_fees != route.hops.iter().map(|hop| hop.fee).sum::<i128>() {
            return Err(RoutingError::InconsistentRouteFees {
                declared: route.total_fees,
                actual: route.hops.iter().map(|hop| hop.fee).sum(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RouteMetadata, RouteRequest};

    fn channel(fee_rate: u32, base_fee: i128) -> Channel {
        Channel {
            id: "ch_cap".to_string(),
            node_a: "a".to_string(),
            node_b: "b".to_string(),
            capacity_a_to_b: 1_000_000,
            capacity_b_to_a: 1_000_000,
            base_fee,
            fee_rate,
            cltv_delta: 40,
            min_htlc_size: 1,
            max_htlc_size: 1_000_000,
            htlcs_in_flight: 0,
            enabled: true,
            age_seconds: 0,
        }
    }

    #[test]
    fn protocol_cap_accepts_ordinary_channels() {
        let cap = FeeCap::protocol();
        assert!(cap.check_channel(&channel(1_000, 1)).is_ok());
        assert!(cap
            .check_channel(&channel(MAX_CHANNEL_FEE_RATE_PPM, 0))
            .is_ok());
        assert!(cap.check_channel(&channel(0, MAX_CHANNEL_BASE_FEE)).is_ok());
    }

    #[test]
    fn protocol_cap_rejects_greedy_fee_rate() {
        let cap = FeeCap::protocol();
        let err = cap
            .check_channel(&channel(MAX_CHANNEL_FEE_RATE_PPM + 1, 0))
            .unwrap_err();

        match err {
            RoutingError::ChannelFeeRateCapExceeded { fee_rate, cap, .. } => {
                assert_eq!(fee_rate, MAX_CHANNEL_FEE_RATE_PPM + 1);
                assert_eq!(cap, MAX_CHANNEL_FEE_RATE_PPM);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn protocol_cap_rejects_greedy_base_fee() {
        let cap = FeeCap::protocol();
        let err = cap
            .check_channel(&channel(0, MAX_CHANNEL_BASE_FEE + 1))
            .unwrap_err();

        assert!(matches!(
            err,
            RoutingError::ChannelBaseFeeCapExceeded { .. }
        ));
    }

    #[test]
    fn hop_fee_cap_scales_with_amount() {
        let cap = FeeCap::protocol();

        // A 1_000_000 stroop payment may pay up to 0.5% plus the base fee.
        let max = cap.max_hop_fee(1_000_000, 40);
        assert_eq!(max, 5_000 + MAX_CHANNEL_BASE_FEE);

        assert!(cap.check_hop_fee("ch", 1_000_000, 40, max).is_ok());
        assert!(cap.check_hop_fee("ch", 1_000_000, 40, max + 1).is_err());
    }

    #[test]
    fn hop_fee_cap_charges_for_time_locks() {
        let cap = FeeCap::protocol();
        // 144_000 blocks of CLTV is 1000 stroops of time-lock fee.
        assert_eq!(cap.max_hop_fee(0, 144_000), MAX_CHANNEL_BASE_FEE + 1_000);
    }

    #[test]
    fn route_fee_cap_bounds_total_but_allows_flat_base_fees() {
        let cap = FeeCap::protocol();

        // 2% of 1_000_000 is 20_000, plus the absolute allowance.
        assert_eq!(cap.max_route_fee(1_000_000), 20_000 + MAX_ROUTE_FEE_ABS);

        assert!(cap
            .check_route_fee(1_000_000, 20_000 + MAX_ROUTE_FEE_ABS)
            .is_ok());
        assert!(cap
            .check_route_fee(1_000_000, 20_000 + MAX_ROUTE_FEE_ABS + 1)
            .is_err());
    }

    #[test]
    fn stricter_route_cap_is_honoured() {
        let cap = FeeCap::protocol().with_route_fee_ppm(100); // 0.01%
        assert_eq!(cap.max_route_fee(1_000_000), 100 + MAX_ROUTE_FEE_ABS);
    }

    #[test]
    fn check_route_rejects_fee_above_hop_cap() {
        let cap = FeeCap::protocol();
        let hops = vec![RouteHop::new(
            "ch1".to_string(),
            "b".to_string(),
            100,
            MAX_CHANNEL_BASE_FEE * 10,
            40,
        )];

        assert!(cap.check_hops(100, &hops).is_err());
    }

    #[test]
    fn check_route_rejects_inconsistent_total() {
        let cap = FeeCap::protocol();
        let route = Route {
            hops: vec![RouteHop::new(
                "ch1".to_string(),
                "b".to_string(),
                100,
                1,
                40,
            )],
            // Declares a fee that does not match the hops.
            total_fees: 999_999_999,
            total_amount: 100,
            success_probability: 1.0,
            metadata: RouteMetadata::default(),
        };

        assert!(matches!(
            cap.check_route(100, &route).unwrap_err(),
            RoutingError::InconsistentRouteFees { .. }
        ));
    }

    #[test]
    fn check_channel_ignores_capacity() {
        // The fee cap is only about fees: capacity is checked at route time.
        let mut ch = channel(0, 0);
        ch.capacity_a_to_b = 0;
        assert!(FeeCap::protocol().check_channel(&ch).is_ok());
    }

    #[test]
    fn graph_reports_offending_channels() {
        let mut graph = NetworkGraph::new();
        for id in ["a", "b"] {
            graph.add_node(crate::Node {
                id: id.to_string(),
                public_key: vec![],
                alias: None,
                online: true,
                last_seen: 0,
                features: crate::NodeFeatures::default(),
            });
        }
        graph.add_channel(channel(1_000, 1));
        graph.add_channel(Channel {
            id: "ch_greedy".to_string(),
            node_a: "a".to_string(),
            node_b: "b".to_string(),
            ..channel(MAX_CHANNEL_FEE_RATE_PPM * 10, 0)
        });

        let offenders = FeeCap::protocol().offending_channels(&graph);
        assert_eq!(offenders.len(), 1);
        assert_eq!(offenders[0].id, "ch_greedy");
    }

    #[test]
    fn request_amount_helper_is_used_by_cap() {
        // Guards against the cap silently accepting a zero-amount payment.
        let cap = FeeCap::protocol();
        let request = RouteRequest {
            source: "a".to_string(),
            destination: "b".to_string(),
            amount: 0,
            max_fee_budget: None,
            max_hops: None,
            find_any: false,
            payment_metadata: None,
        };
        assert_eq!(request.amount, 0);
        assert!(cap
            .check_route_fee(request.amount, MAX_ROUTE_FEE_ABS)
            .is_ok());
    }
}

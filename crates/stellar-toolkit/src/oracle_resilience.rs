//! Bridge oracle quorum resilience (issue #211).
//!
//! Quorum batch evaluation (issue #210) answers *"do these confirmations release
//! this transfer?"*. This module answers the question an operator asks before a
//! batch arrives: **"with the oracles reachable right now, can the bridge settle
//! at all — and how many more failures would stop it?"**
//!
//! Those are different inputs and different failure modes. Batch evaluation
//! consumes verified amounts, ages and signer identities; liveness takes a
//! configuration (`n`, `m`) and the set of currently reachable oracle positions.
//! A bridge can be fully quorate for a fresh transfer and one operator restart
//! away from being unable to settle anything, and that is what this analysis
//! makes visible.
//!
//! The two numbers that matter:
//!
//! * **`missing`** — how many more reachable oracles are needed before quorum is
//!   possible at all. Non-zero means settlement is currently *blocked*; raising
//!   relayer retries will not help.
//! * **`online_failure_tolerance`** — how many of the currently reachable oracles
//!   can fail before settlement becomes blocked. Zero while `reachable` is the
//!   alerting condition: the bridge is exactly at quorum and every online key is
//!   already critical.
//!
//! [`QuorumLiveness::total_failure_tolerance`] is the static figure (`n - m`,
//! failures that can be absorbed from the whole set); the online figure is the
//! one that reflects today's incident.
//!
//! The analysis is pure and holds no state. It deliberately does not re-validate
//! oracle identities — that belongs to whatever builds the set — and the indices
//! here are positions in that set.

use std::collections::{BTreeMap, BTreeSet};

/// A quorum configuration that cannot describe any bridge.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LivenessError {
    #[error("a bridge needs at least one oracle")]
    EmptyOracleSet,
    #[error("threshold {threshold} is not in 1..={oracles}")]
    ThresholdOutOfRange { threshold: u32, oracles: u32 },
}

/// The result of assessing one configuration against the oracles reachable now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumLiveness {
    /// Configured oracle count (`n`).
    pub oracle_count: u32,
    /// Confirmations required (`m`).
    pub threshold: u32,
    /// Distinct, in-range oracles reported reachable.
    pub online: u32,
    /// Whether `online >= threshold`, i.e. some transfer can reach quorum.
    pub reachable: bool,
    /// Further reachable oracles needed to make quorum possible (`0` when
    /// reachable).
    pub missing: u32,
    /// Reachable oracles that can still fail while quorum stays possible. `0`
    /// while `reachable` means every reachable oracle is already critical.
    pub online_failure_tolerance: u32,
    /// Oracles anywhere in the set that can be offline while quorum stays
    /// possible (`n - m`). Includes the oracles that are already offline.
    pub total_failure_tolerance: u32,
    /// Reported indices that are not members of the set.
    pub ignored_out_of_range: u32,
    /// Repeated indices in the reachability report.
    pub ignored_duplicates: u32,
}

impl QuorumLiveness {
    /// Whether settlement is currently possible.
    pub fn is_reachable(&self) -> bool {
        self.reachable
    }

    /// Whether every reachable oracle is required for quorum.
    ///
    /// Only meaningful while reachable; an unreachable bridge has no oracle to
    /// call critical, and this returns `false` there rather than overstating the
    /// problem.
    pub fn every_online_oracle_is_critical(&self) -> bool {
        self.reachable && self.online_failure_tolerance == 0
    }
}

/// Assess `oracle_count`/`threshold` against `online` oracle indices.
///
/// `n >= 1` and `m` in `1..=n` are required; a threshold of zero would make an
/// empty reachability report quorate, and a threshold above `n` is unsatisfiable.
/// For consistency with the oracle-set type the integration uses, a set with
/// more than 64 members would already have been rejected there; this analysis
/// does not impose that ceiling, because liveness monitoring must still be able
/// to describe a misconfigured set rather than refuse to report on it.
///
/// Out-of-range indices (typically left over from a previous set rotation) and
/// duplicates are ignored and counted rather than refused: a monitoring feed
/// should still report the reachable truth when its inventory is stale, and the
/// counters make the difference visible.
pub fn assess_quorum_liveness(
    oracle_count: u32,
    threshold: u32,
    online: &[u32],
) -> Result<QuorumLiveness, LivenessError> {
    if oracle_count == 0 {
        return Err(LivenessError::EmptyOracleSet);
    }
    if threshold == 0 || threshold > oracle_count {
        return Err(LivenessError::ThresholdOutOfRange {
            threshold,
            oracles: oracle_count,
        });
    }

    let mut distinct: BTreeSet<u32> = BTreeSet::new();
    let mut ignored_out_of_range = 0u32;
    let mut ignored_duplicates = 0u32;
    for index in online {
        if *index >= oracle_count {
            ignored_out_of_range += 1;
        } else if !distinct.insert(*index) {
            ignored_duplicates += 1;
        }
    }

    let online = distinct.len() as u32;
    let reachable = online >= threshold;
    let missing = threshold.saturating_sub(online);
    let online_failure_tolerance = if reachable {
        online.saturating_sub(threshold)
    } else {
        0
    };

    Ok(QuorumLiveness {
        oracle_count,
        threshold,
        online,
        reachable,
        missing,
        online_failure_tolerance,
        total_failure_tolerance: oracle_count - threshold,
        ignored_out_of_range,
        ignored_duplicates,
    })
}


/// Units and decimal scale definition for oracle price values (#446).
///
/// Stellar asset native prices are represented with 7 decimals (1 stroop = 10^-7 XLM),
/// while external EVM or USD pegged feeds often use 8 or 18 decimals.
/// `PriceFeedScale` documents and enforces explicit decimal units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriceFeedScale {
    /// Number of fractional decimal digits (e.g., 7 for Stellar Stroops, 8 for Chainlink USD, 18 for Wei).
    pub decimals: u8,
    /// Base unit multiplier: 10^decimals.
    pub unit_scale: u128,
}

impl PriceFeedScale {
    pub const fn new(decimals: u8) -> Self {
        let mut scale = 1u128;
        let mut i = 0u8;
        while i < decimals {
            scale = scale.saturating_mul(10);
            i += 1;
        }
        Self {
            decimals,
            unit_scale: scale,
        }
    }

    /// Standard Stellar stroop unit scale (7 decimals).
    pub const STROOP: Self = Self::new(7);
    /// Standard 8-decimal asset feed scale (e.g. BTC/USD, ETH/USD).
    pub const EIGHT_DECIMALS: Self = Self::new(8);
    /// Standard 18-decimal token feed scale.
    pub const EIGHTEEN_DECIMALS: Self = Self::new(18);

    /// Formats an integer amount according to this scale into a human-readable decimal string.
    pub fn format_amount(&self, raw: i128) -> String {
        let is_negative = raw < 0;
        let abs_val = raw.unsigned_abs();
        let scale = self.unit_scale;
        let whole = abs_val / scale;
        let fraction = abs_val % scale;
        let sign = if is_negative { "-" } else { "" };
        if self.decimals == 0 {
            format!("{}{}", sign, whole)
        } else {
            let frac_str = format!("{:0width$}", fraction, width = self.decimals as usize);
            let trimmed = frac_str.trim_end_matches('0');
            if trimmed.is_empty() {
                format!("{}{}.0", sign, whole)
            } else {
                format!("{}{}.{}", sign, whole, trimmed)
            }
        }
    }
}

/// A price observation from an oracle source with timestamp and units (#443, #444, #446).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceObservation {
    pub source: String,
    pub price: i128,
    pub timestamp: u64,
    pub scale: PriceFeedScale,
}

/// Errors occurring during price observation ingestion and validation (#443, #444).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PriceValidationError {
    #[error("non-positive price {price} reported by source `{source}`")]
    NonPositivePrice { source: String, price: i128 },
    #[error("timestamp regression: observed {observed_ts} <= latest valid {latest_ts} for source `{source}`")]
    TimestampRegression {
        source: String,
        observed_ts: u64,
        latest_ts: u64,
    },
    #[error("scale mismatch: expected {expected} decimals, got {actual} for source `{source}`")]
    ScaleMismatch {
        source: String,
        expected: u8,
        actual: u8,
    },
}

/// Resilient price feed tracker that enforces timestamp monotonicity (#444)
/// and preserves the previous valid price when invalid data is reported (#443).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResilientPriceTracker {
    pub expected_scale: PriceFeedScale,
    sources: BTreeMap<String, PriceObservation>,
    rejected_invalid: u32,
    rejected_regressive: u32,
}

impl ResilientPriceTracker {
    pub fn new(scale: PriceFeedScale) -> Self {
        Self {
            expected_scale: scale,
            sources: BTreeMap::new(),
            rejected_invalid: 0,
            rejected_regressive: 0,
        }
    }

    /// Record a price observation from `source`.
    ///
    /// Invariants:
    /// 1. Price must be strictly positive (`price > 0`).
    /// 2. Timestamp ordering must be strictly ascending (`timestamp > previous.timestamp`).
    /// 3. Decimal scale must match the tracker's expected scale.
    ///
    /// On validation failure, the tracker preserves the previous valid observation intact (#443)
    /// and returns the specific [`PriceValidationError`].
    pub fn record_observation(
        &mut self,
        source: &str,
        price: i128,
        timestamp: u64,
        scale: PriceFeedScale,
    ) -> Result<&PriceObservation, PriceValidationError> {
        if scale.decimals != self.expected_scale.decimals {
            self.rejected_invalid += 1;
            return Err(PriceValidationError::ScaleMismatch {
                source: source.to_string(),
                expected: self.expected_scale.decimals,
                actual: scale.decimals,
            });
        }

        if price <= 0 {
            self.rejected_invalid += 1;
            return Err(PriceValidationError::NonPositivePrice {
                source: source.to_string(),
                price,
            });
        }

        if let Some(prev) = self.sources.get(source) {
            if timestamp <= prev.timestamp {
                self.rejected_regressive += 1;
                return Err(PriceValidationError::TimestampRegression {
                    source: source.to_string(),
                    observed_ts: timestamp,
                    latest_ts: prev.timestamp,
                });
            }
        }

        let obs = PriceObservation {
            source: source.to_string(),
            price,
            timestamp,
            scale,
        };
        self.sources.insert(source.to_string(), obs);
        Ok(self.sources.get(source).unwrap())
    }

    /// Retrieve the latest valid observation for `source` if present.
    pub fn get_latest_valid(&self, source: &str) -> Option<&PriceObservation> {
        self.sources.get(source)
    }

    /// Total count of invalid/non-positive price attempts rejected while preserving previous valid price.
    pub fn rejected_invalid_count(&self) -> u32 {
        self.rejected_invalid
    }

    /// Total count of out-of-order or regressive timestamps rejected.
    pub fn rejected_regressive_count(&self) -> u32 {
        self.rejected_regressive
    }

    /// Calculate the median price across all currently valid sources.
    pub fn calculate_median_price(&self) -> Option<i128> {
        if self.sources.is_empty() {
            return None;
        }
        let mut prices: Vec<i128> = self.sources.values().map(|o| o.price).collect();
        prices.sort_unstable();
        let mid = prices.len() / 2;
        if prices.len() % 2 == 1 {
            Some(prices[mid])
        } else {
            Some((prices[mid - 1] + prices[mid]) / 2)
        }
    }
}

/// Jittered retry policy for resilient oracle polling (#445).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JitteredRetryPolicy {
    pub base_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub max_retries: u32,
}

impl JitteredRetryPolicy {
    pub const fn new(base_backoff_ms: u64, max_backoff_ms: u64, max_retries: u32) -> Self {
        Self {
            base_backoff_ms,
            max_backoff_ms,
            max_retries,
        }
    }

    /// Default policy: 200ms base, 5000ms max, 5 retries.
    pub const DEFAULT: Self = Self::new(200, 5_000, 5);

    /// Calculate bounded exponential backoff with pseudo-random jitter.
    pub fn calculate_backoff_ms(&self, attempt: u32, jitter_seed: u64) -> u64 {
        let exp = self.base_backoff_ms.saturating_mul(1u64 << attempt.min(10));
        let capped = exp.min(self.max_backoff_ms);
        let jitter_range = capped / 4;
        if jitter_range == 0 {
            capped
        } else {
            (capped - jitter_range) + (jitter_seed % (jitter_range + 1))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_at_quorum_has_no_remaining_tolerance() {
        let liveness = assess_quorum_liveness(5, 3, &[0, 1, 2]).expect("valid configuration");
        assert!(liveness.is_reachable());
        assert_eq!(liveness.online, 3);
        assert_eq!(liveness.missing, 0);
        assert_eq!(liveness.online_failure_tolerance, 0);
        assert_eq!(liveness.total_failure_tolerance, 2);
        assert!(liveness.every_online_oracle_is_critical());
    }

    #[test]
    fn one_short_is_blocked_and_reports_what_is_missing() {
        let liveness = assess_quorum_liveness(5, 3, &[0, 1]).expect("valid configuration");
        assert!(!liveness.is_reachable());
        assert_eq!(liveness.online, 2);
        assert_eq!(liveness.missing, 1);
        assert_eq!(liveness.online_failure_tolerance, 0);
        assert!(!liveness.every_online_oracle_is_critical());
    }

    #[test]
    fn a_full_set_reports_the_static_failure_tolerance() {
        let liveness = assess_quorum_liveness(5, 3, &[0, 1, 2, 3, 4]).expect("valid configuration");
        assert!(liveness.is_reachable());
        assert_eq!(liveness.online_failure_tolerance, 2);
        assert_eq!(liveness.total_failure_tolerance, 2);
        assert!(!liveness.every_online_oracle_is_critical());
    }

    #[test]
    fn an_empty_reachability_report_is_blocked_by_the_whole_threshold() {
        let liveness = assess_quorum_liveness(4, 3, &[]).expect("valid configuration");
        assert!(!liveness.is_reachable());
        assert_eq!(liveness.online, 0);
        assert_eq!(liveness.missing, 3);
        assert_eq!(liveness.total_failure_tolerance, 1);
    }

    #[test]
    fn out_of_range_indices_are_ignored_and_counted() {
        // Index 7 is not in a 5-oracle set: a stale inventory must not be able
        // to report a bridge as reachable when it is not.
        let liveness = assess_quorum_liveness(5, 3, &[0, 1, 7, 99]).expect("valid configuration");
        assert_eq!(liveness.online, 2);
        assert_eq!(liveness.ignored_out_of_range, 2);
        assert!(!liveness.is_reachable());
        assert_eq!(liveness.missing, 1);
    }

    #[test]
    fn duplicate_indices_count_once() {
        let liveness =
            assess_quorum_liveness(5, 3, &[0, 0, 1, 1, 2, 2, 2]).expect("valid configuration");
        assert_eq!(liveness.online, 3);
        assert_eq!(liveness.ignored_duplicates, 4);
        assert_eq!(liveness.online_failure_tolerance, 0);
    }

    #[test]
    fn a_single_oracle_bridge_is_its_own_quorum() {
        let online = assess_quorum_liveness(1, 1, &[0]).expect("valid configuration");
        assert!(online.is_reachable());
        assert_eq!(online.total_failure_tolerance, 0);
        assert!(online.every_online_oracle_is_critical());

        let offline = assess_quorum_liveness(1, 1, &[]).expect("valid configuration");
        assert!(!offline.is_reachable());
        assert_eq!(offline.missing, 1);
    }

    #[test]
    fn a_wide_set_is_analysed_without_an_artificial_cap() {
        // The analysis describes whatever set it is given; a monitoring tool
        // should not refuse to report on a misconfigured 100-oracle bridge.
        let all: Vec<u32> = (0..100).collect();
        let liveness = assess_quorum_liveness(100, 60, &all).expect("valid configuration");
        assert_eq!(liveness.online, 100);
        assert_eq!(liveness.online_failure_tolerance, 40);
        assert_eq!(liveness.total_failure_tolerance, 40);

        let one_missing = assess_quorum_liveness(100, 60, &all[1..]).expect("valid configuration");
        assert_eq!(one_missing.online, 99);
        assert_eq!(one_missing.online_failure_tolerance, 39);
    }

    #[test]
    fn wide_sets_do_not_double_count_or_accept_stale_positions() {
        // One duplicate, one index outside the set: only 60 distinct positions
        // are reachable, which is exactly the threshold.
        let mut report: Vec<u32> = (0..60).collect();
        report.push(0);
        report.push(100);
        let liveness = assess_quorum_liveness(100, 60, &report).expect("valid configuration");
        assert_eq!(liveness.online, 60);
        assert!(liveness.is_reachable());
        assert!(liveness.every_online_oracle_is_critical());
        assert_eq!(liveness.ignored_duplicates, 1);
        assert_eq!(liveness.ignored_out_of_range, 1);
    }

    #[test]
    fn rejects_configurations_with_no_valid_quorum() {
        assert_eq!(
            assess_quorum_liveness(0, 1, &[]),
            Err(LivenessError::EmptyOracleSet)
        );
        assert_eq!(
            assess_quorum_liveness(3, 0, &[0]),
            Err(LivenessError::ThresholdOutOfRange {
                threshold: 0,
                oracles: 3
            })
        );
        assert_eq!(
            assess_quorum_liveness(3, 4, &[0, 1, 2]),
            Err(LivenessError::ThresholdOutOfRange {
                threshold: 4,
                oracles: 3
            })
        );
    }

    #[test]
    fn price_feed_scale_formatting_and_units() {
        let stroop = PriceFeedScale::STROOP;
        assert_eq!(stroop.decimals, 7);
        assert_eq!(stroop.unit_scale, 10_000_000);
        assert_eq!(stroop.format_amount(15_000_000), "1.5");
        assert_eq!(stroop.format_amount(10_000_000), "1.0");
        assert_eq!(stroop.format_amount(700), "0.00007");

        let eight = PriceFeedScale::EIGHT_DECIMALS;
        assert_eq!(eight.format_amount(65_432_100_000), "654.321");
    }

    #[test]
    fn preserves_previous_valid_price_on_invalid_reported_data() {
        let mut tracker = ResilientPriceTracker::new(PriceFeedScale::STROOP);
        // Valid initial observation
        tracker.record_observation("feed_a", 15_000_000, 1000, PriceFeedScale::STROOP).expect("valid");
        assert_eq!(tracker.get_latest_valid("feed_a").unwrap().price, 15_000_000);

        // Invalid non-positive price attempt
        let err = tracker.record_observation("feed_a", -500, 1010, PriceFeedScale::STROOP);
        assert_eq!(
            err,
            Err(PriceValidationError::NonPositivePrice {
                source: "feed_a".to_string(),
                price: -500,
            })
        );
        // Invariant #443: previous valid price remains intact!
        assert_eq!(tracker.get_latest_valid("feed_a").unwrap().price, 15_000_000);
        assert_eq!(tracker.rejected_invalid_count(), 1);
    }

    #[test]
    fn validates_timestamp_ordering_strictly_ascending() {
        let mut tracker = ResilientPriceTracker::new(PriceFeedScale::STROOP);
        tracker.record_observation("feed_b", 20_000_000, 1000, PriceFeedScale::STROOP).expect("valid");

        // Regressive timestamp (990 <= 1000)
        let reg_err = tracker.record_observation("feed_b", 21_000_000, 990, PriceFeedScale::STROOP);
        assert_eq!(
            reg_err,
            Err(PriceValidationError::TimestampRegression {
                source: "feed_b".to_string(),
                observed_ts: 990,
                latest_ts: 1000,
            })
        );
        assert_eq!(tracker.get_latest_valid("feed_b").unwrap().price, 20_000_000);
        assert_eq!(tracker.rejected_regressive_count(), 1);

        // Equal timestamp (1000 <= 1000)
        let eq_err = tracker.record_observation("feed_b", 21_000_000, 1000, PriceFeedScale::STROOP);
        assert!(matches!(eq_err, Err(PriceValidationError::TimestampRegression { .. })));

        // Strictly newer succeeds
        tracker.record_observation("feed_b", 22_000_000, 1001, PriceFeedScale::STROOP).expect("newer timestamp");
        assert_eq!(tracker.get_latest_valid("feed_b").unwrap().price, 22_000_000);
    }

    #[test]
    fn jittered_retry_policy_bounds_and_backoff() {
        let policy = JitteredRetryPolicy::new(100, 1000, 5);
        // Attempt 0: base 100ms, jitter in [75, 100]
        let b0 = policy.calculate_backoff_ms(0, 15);
        assert!(b0 >= 75 && b0 <= 100);

        // High attempt capped at max_backoff 1000ms, jitter in [750, 1000]
        let b_high = policy.calculate_backoff_ms(10, 42);
        assert!(b_high >= 750 && b_high <= 1000);
    }

}

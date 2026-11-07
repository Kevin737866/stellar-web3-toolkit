//! Bridge oracle quorum resilience and price feed validation.
//!
//! Provides two complementary capabilities for oracle operations:
//! 1. Quorum liveness and failure tolerance analysis (issue #211).
//! 2. Resilient price feed tracking, freshness windows (#438), deterministic median
//!    tie handling (#439), bounded deviation enforcement (#440), source health
//!    reporting (#441), quorum-enforced aggregation (#442), decimal scaling (#443),
//!    and exponential jittered retries (#445).

use std::collections::{BTreeMap, BTreeSet};

/// A quorum configuration that cannot describe any bridge.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LivenessError {
    #[error("a bridge needs at least one oracle")]
    EmptyOracleSet,
    #[error("threshold {threshold} is not in 1..={oracles}")]
    InvalidThreshold { oracles: u32, threshold: u32 },
}

/// The state of a bridge's oracle quorum right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumLiveness {
    pub oracles: u32,
    pub threshold: u32,
    pub online: u32,
    pub reachable: bool,
    pub missing: u32,
    pub online_failure_tolerance: u32,
    pub total_failure_tolerance: u32,
    pub ignored_out_of_range: u32,
    pub ignored_duplicates: u32,
}

impl QuorumLiveness {
    pub fn is_reachable(&self) -> bool {
        self.reachable
    }

    pub fn every_online_oracle_is_critical(&self) -> bool {
        self.reachable && self.online_failure_tolerance == 0
    }
}

pub fn assess_quorum_liveness(
    oracles: u32,
    threshold: u32,
    online_positions: &[u32],
) -> Result<QuorumLiveness, LivenessError> {
    if oracles == 0 {
        return Err(LivenessError::EmptyOracleSet);
    }
    if threshold == 0 || threshold > oracles {
        return Err(LivenessError::InvalidThreshold { oracles, threshold });
    }

    let mut distinct_valid = BTreeSet::new();
    let mut ignored_out_of_range = 0u32;
    let mut ignored_duplicates = 0u32;

    for &pos in online_positions {
        if pos >= oracles {
            ignored_out_of_range += 1;
        } else if !distinct_valid.insert(pos) {
            ignored_duplicates += 1;
        }
    }

    let online = distinct_valid.len() as u32;
    let reachable = online >= threshold;
    let missing = threshold.saturating_sub(online);
    let online_failure_tolerance = online.saturating_sub(threshold);
    let total_failure_tolerance = oracles.saturating_sub(threshold);

    Ok(QuorumLiveness {
        oracles,
        threshold,
        online,
        reachable,
        missing,
        online_failure_tolerance,
        total_failure_tolerance,
        ignored_out_of_range,
        ignored_duplicates,
    })
}

// ============================================================================
// Resilient Price Tracker, Freshness & Deviation Bounds (#438, #439, #440, #441, #442)
// ============================================================================

/// Formatting and decimal scaling for price feed observations (#443, #446).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceFeedScale {
    pub decimals: u8,
    pub unit_label: String,
}

impl PriceFeedScale {
    pub fn new(decimals: u8, unit_label: impl Into<String>) -> Self {
        Self {
            decimals,
            unit_label: unit_label.into(),
        }
    }

    pub fn format_amount(&self, raw: i128) -> String {
        if self.decimals == 0 {
            return format!("{} {}", raw, self.unit_label);
        }
        let factor = 10_i128.pow(self.decimals as u32);
        let whole = raw / factor;
        let frac = (raw % factor).abs();
        format!("{}.{:0width$} {}", whole, frac, self.unit_label, width = self.decimals as usize)
    }
}

/// An observation reported by an individual oracle source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceObservation {
    pub source: String,
    pub price: i128,
    pub timestamp: u64,
    pub round_id: u64,
}

/// Validation errors for incoming price observations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PriceValidationError {
    #[error("price observation must be strictly positive, got {0}")]
    ZeroOrNegativePrice(i128),
    #[error("observation is stale: age {age_seconds}s exceeds freshness window {max_freshness_seconds}s")]
    StaleObservation {
        age_seconds: u64,
        max_freshness_seconds: u64,
    },
    #[error("observation timestamp {timestamp} is in the future relative to ledger {current_timestamp}")]
    FutureTimestamp {
        timestamp: u64,
        current_timestamp: u64,
    },
    #[error("regressive timestamp for source {source}: previous {previous}, received {incoming}")]
    RegressiveTimestamp {
        source: String,
        previous: u64,
        incoming: u64,
    },
    #[error("price deviation {deviation_bps} bps from reference {reference_price} exceeds limit {max_deviation_bps} bps")]
    ExcessiveDeviation {
        source: String,
        candidate_price: i128,
        reference_price: i128,
        deviation_bps: u32,
        max_deviation_bps: u32,
    },
}

/// Deterministic tie-handling mode for median price aggregation with an even number of observations (#439).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MedianTieBreaker {
    /// Arithmetic mean of the two middle elements `(p_mid1 + p_mid2) / 2`.
    #[default]
    ArithmeticMean,
    /// The lower middle observation in sorted ascending order.
    LowerMedian,
    /// The upper middle observation in sorted ascending order.
    UpperMedian,
}

/// Aggregation and quorum errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PriceAggregationError {
    #[error("insufficient oracle quorum: {active_sources} active sources, required {required_quorum}")]
    InsufficientQuorum {
        active_sources: usize,
        required_quorum: usize,
    },
    #[error("no observations available to aggregate")]
    EmptyObservations,
    #[error("arithmetic overflow during aggregation")]
    Overflow,
}

/// Detailed health status for an individual oracle source (#441).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleSourceHealth {
    pub source: String,
    pub last_updated_timestamp: u64,
    pub is_healthy: bool,
    pub accepted_observations_count: u64,
    pub rejected_observations_count: u64,
    pub latest_price: Option<i128>,
}

/// Resilient price tracker enforcing freshness windows, bounded deviation,
/// deterministic median calculation, and quorum requirements.
#[derive(Debug, Clone)]
pub struct ResilientPriceTracker {
    pub scale: PriceFeedScale,
    pub max_freshness_seconds: Option<u64>,
    pub max_deviation_bps: Option<u32>,
    pub tie_breaker: MedianTieBreaker,
    latest_valid: BTreeMap<String, PriceObservation>,
    source_stats: BTreeMap<String, (u64, u64)>, // (accepted, rejected)
    rejected_invalid: u32,
    rejected_regressive: u32,
    rejected_stale: u32,
    rejected_deviation: u32,
    last_accepted_median: Option<i128>,
}

impl ResilientPriceTracker {
    pub fn new(scale: PriceFeedScale) -> Self {
        Self {
            scale,
            max_freshness_seconds: None,
            max_deviation_bps: None,
            tie_breaker: MedianTieBreaker::default(),
            latest_valid: BTreeMap::new(),
            source_stats: BTreeMap::new(),
            rejected_invalid: 0,
            rejected_regressive: 0,
            rejected_stale: 0,
            rejected_deviation: 0,
            last_accepted_median: None,
        }
    }

    /// Configure a maximum freshness window in seconds (#438).
    pub fn with_freshness_window(mut self, max_freshness_seconds: u64) -> Self {
        self.max_freshness_seconds = Some(max_freshness_seconds);
        self
    }

    /// Configure a maximum allowed price deviation in basis points (#440).
    pub fn with_max_deviation_bps(mut self, max_deviation_bps: u32) -> Self {
        self.max_deviation_bps = Some(max_deviation_bps);
        self
    }

    /// Configure deterministic tie breaker for even median counts (#439).
    pub fn with_tie_breaker(mut self, tie_breaker: MedianTieBreaker) -> Self {
        self.tie_breaker = tie_breaker;
        self
    }

    /// Record and validate an incoming observation against freshness, regression, and deviation invariants.
    pub fn record_observation(
        &mut self,
        obs: PriceObservation,
        current_timestamp: u64,
    ) -> Result<(), PriceValidationError> {
        if obs.price <= 0 {
            self.rejected_invalid += 1;
            self.increment_rejected(&obs.source);
            return Err(PriceValidationError::ZeroOrNegativePrice(obs.price));
        }

        // Freshness check (#438)
        if let Some(max_freshness) = self.max_freshness_seconds {
            if current_timestamp > obs.timestamp {
                let age = current_timestamp - obs.timestamp;
                if age > max_freshness {
                    self.rejected_stale += 1;
                    self.increment_rejected(&obs.source);
                    return Err(PriceValidationError::StaleObservation {
                        age_seconds: age,
                        max_freshness_seconds: max_freshness,
                    });
                }
            }
        }

        // Future timestamp check (allowing max 60s skew)
        if obs.timestamp > current_timestamp + 60 {
            self.rejected_invalid += 1;
            self.increment_rejected(&obs.source);
            return Err(PriceValidationError::FutureTimestamp {
                timestamp: obs.timestamp,
                current_timestamp,
            });
        }

        // Monotonic timestamp check per source
        if let Some(prev) = self.latest_valid.get(&obs.source) {
            if obs.timestamp <= prev.timestamp {
                self.rejected_regressive += 1;
                self.increment_rejected(&obs.source);
                return Err(PriceValidationError::RegressiveTimestamp {
                    source: obs.source.clone(),
                    previous: prev.timestamp,
                    incoming: obs.timestamp,
                });
            }
        }

        // Bounded deviation check (#440)
        if let Some(max_bps) = self.max_deviation_bps {
            let ref_price = self
                .latest_valid
                .get(&obs.source)
                .map(|p| p.price)
                .or(self.last_accepted_median);

            if let Some(ref_price) = ref_price {
                if ref_price > 0 {
                    let diff = (obs.price - ref_price).abs();
                    let deviation_bps = (diff * 10_000 / ref_price) as u32;
                    if deviation_bps > max_bps {
                        self.rejected_deviation += 1;
                        self.increment_rejected(&obs.source);
                        return Err(PriceValidationError::ExcessiveDeviation {
                            source: obs.source.clone(),
                            candidate_price: obs.price,
                            reference_price: ref_price,
                            deviation_bps,
                            max_deviation_bps: max_bps,
                        });
                    }
                }
            }
        }

        // Accepted observation
        let stats = self.source_stats.entry(obs.source.clone()).or_insert((0, 0));
        stats.0 += 1;
        self.latest_valid.insert(obs.source.clone(), obs);
        Ok(())
    }

    fn increment_rejected(&mut self, source: &str) {
        let stats = self.source_stats.entry(source.to_string()).or_insert((0, 0));
        stats.1 += 1;
    }

    pub fn get_latest_valid(&self, source: &str) -> Option<&PriceObservation> {
        self.latest_valid.get(source)
    }

    pub fn active_source_count(&self) -> usize {
        self.latest_valid.len()
    }

    pub fn rejected_invalid_count(&self) -> u32 {
        self.rejected_invalid
    }

    pub fn rejected_regressive_count(&self) -> u32 {
        self.rejected_regressive
    }

    pub fn rejected_stale_count(&self) -> u32 {
        self.rejected_stale
    }

    pub fn rejected_deviation_count(&self) -> u32 {
        self.rejected_deviation
    }

    /// Expose health and last-update times for all known sources (#441).
    pub fn get_sources_health(&self, current_timestamp: u64) -> Vec<OracleSourceHealth> {
        let freshness_limit = self.max_freshness_seconds.unwrap_or(300);
        let mut result = Vec::new();

        for (source, stats) in &self.source_stats {
            let latest = self.latest_valid.get(source);
            let last_ts = latest.map(|o| o.timestamp).unwrap_or(0);
            let is_healthy = latest.map_or(false, |o| {
                current_timestamp >= o.timestamp && (current_timestamp - o.timestamp) <= freshness_limit
            });

            result.push(OracleSourceHealth {
                source: source.clone(),
                last_updated_timestamp: last_ts,
                is_healthy,
                accepted_observations_count: stats.0,
                rejected_observations_count: stats.1,
                latest_price: latest.map(|o| o.price),
            });
        }
        result
    }

    /// Compute median price across valid sources with quorum verification (#439, #442).
    pub fn calculate_median_price_with_quorum(
        &mut self,
        min_quorum: usize,
    ) -> Result<i128, PriceAggregationError> {
        let count = self.latest_valid.len();
        if count < min_quorum {
            return Err(PriceAggregationError::InsufficientQuorum {
                active_sources: count,
                required_quorum: min_quorum,
            });
        }
        if count == 0 {
            return Err(PriceAggregationError::EmptyObservations);
        }

        let mut prices: Vec<i128> = self.latest_valid.values().map(|o| o.price).collect();
        prices.sort_unstable();

        let median = if count % 2 == 1 {
            prices[count / 2]
        } else {
            let mid1 = prices[(count / 2) - 1];
            let mid2 = prices[count / 2];
            match self.tie_breaker {
                MedianTieBreaker::ArithmeticMean => mid1
                    .checked_add(mid2)
                    .map(|sum| sum / 2)
                    .ok_or(PriceAggregationError::Overflow)?,
                MedianTieBreaker::LowerMedian => mid1,
                MedianTieBreaker::UpperMedian => mid2,
            }
        };

        self.last_accepted_median = Some(median);
        Ok(median)
    }

    /// Calculate median price without explicit quorum limit.
    pub fn calculate_median_price(&mut self) -> Option<i128> {
        self.calculate_median_price_with_quorum(1).ok()
    }
}

// ============================================================================
// Exponential Jittered Retries (#445)
// ============================================================================

/// Exponential backoff policy with bounded random jitter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JitteredRetryPolicy {
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub max_retries: u32,
}

impl JitteredRetryPolicy {
    pub fn new(base_delay_ms: u64, max_delay_ms: u64, max_retries: u32) -> Self {
        Self {
            base_delay_ms,
            max_delay_ms,
            max_retries,
        }
    }

    pub fn calculate_backoff_ms(&self, attempt: u32, jitter_seed: u64) -> u64 {
        if attempt == 0 {
            return 0;
        }
        let exp_factor = 2u64.saturating_pow(attempt.saturating_sub(1));
        let nominal = self.base_delay_ms.saturating_mul(exp_factor).min(self.max_delay_ms);
        let jitter = (jitter_seed % 250).min(nominal / 4);
        nominal.saturating_add(jitter).min(self.max_delay_ms)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quorum_liveness_basic() {
        let liveness = assess_quorum_liveness(5, 3, &[0, 1, 2, 3, 4]).unwrap();
        assert!(liveness.is_reachable());
        assert_eq!(liveness.online_failure_tolerance, 2);

        let liveness = assess_quorum_liveness(5, 3, &[0, 1, 2]).unwrap();
        assert!(liveness.every_online_oracle_is_critical());

        let liveness = assess_quorum_liveness(5, 3, &[0, 1]).unwrap();
        assert!(!liveness.is_reachable());
        assert_eq!(liveness.missing, 1);
    }

    #[test]
    fn test_freshness_window_rejection_issue_438() {
        let scale = PriceFeedScale::new(7, "USDC");
        let mut tracker = ResilientPriceTracker::new(scale).with_freshness_window(120);

        // Fresh observation within 120s window: accepted
        let obs_fresh = PriceObservation {
            source: "oracle_alpha".into(),
            price: 10_000_000,
            timestamp: 1_000,
            round_id: 1,
        };
        assert!(tracker.record_observation(obs_fresh, 1_050).is_ok());

        // Stale observation (150s old > 120s): rejected with StaleObservation
        let obs_stale = PriceObservation {
            source: "oracle_beta".into(),
            price: 10_050_000,
            timestamp: 800,
            round_id: 1,
        };
        let err = tracker.record_observation(obs_stale, 1_050);
        assert!(matches!(
            err,
            Err(PriceValidationError::StaleObservation { age_seconds: 250, max_freshness_seconds: 120 })
        ));
        assert_eq!(tracker.rejected_stale_count(), 1);

        // Boundary test: exactly 120s age is accepted
        let obs_boundary = PriceObservation {
            source: "oracle_gamma".into(),
            price: 10_020_000,
            timestamp: 930,
            round_id: 1,
        };
        assert!(tracker.record_observation(obs_boundary, 1_050).is_ok());
    }

    #[test]
    fn test_deterministic_tie_breaker_issue_439() {
        let scale = PriceFeedScale::new(7, "USDC");

        // Even number of observations (10 and 20)
        let setup_even = |tie_breaker| {
            let mut tracker = ResilientPriceTracker::new(scale.clone()).with_tie_breaker(tie_breaker);
            tracker
                .record_observation(
                    PriceObservation {
                        source: "s1".into(),
                        price: 10_000_000,
                        timestamp: 100,
                        round_id: 1,
                    },
                    100,
                )
                .unwrap();
            tracker
                .record_observation(
                    PriceObservation {
                        source: "s2".into(),
                        price: 20_000_000,
                        timestamp: 100,
                        round_id: 1,
                    },
                    100,
                )
                .unwrap();
            tracker
        };

        // ArithmeticMean: (10 + 20) / 2 = 15
        let mut t_mean = setup_even(MedianTieBreaker::ArithmeticMean);
        assert_eq!(t_mean.calculate_median_price(), Some(15_000_000));

        // LowerMedian: 10
        let mut t_lower = setup_even(MedianTieBreaker::LowerMedian);
        assert_eq!(t_lower.calculate_median_price(), Some(10_000_000));

        // UpperMedian: 20
        let mut t_upper = setup_even(MedianTieBreaker::UpperMedian);
        assert_eq!(t_upper.calculate_median_price(), Some(20_000_000));
    }

    #[test]
    fn test_bounded_deviation_issue_440() {
        let scale = PriceFeedScale::new(7, "USDC");
        // Max 500 bps = 5.00% deviation allowed
        let mut tracker = ResilientPriceTracker::new(scale).with_max_deviation_bps(500);

        // Baseline: 10_000_000
        tracker
            .record_observation(
                PriceObservation {
                    source: "feed_1".into(),
                    price: 10_000_000,
                    timestamp: 100,
                    round_id: 1,
                },
                100,
            )
            .unwrap();

        // 3% increase: 10_300_000 (within 5% threshold): accepted
        assert!(tracker
            .record_observation(
                PriceObservation {
                    source: "feed_1".into(),
                    price: 10_300_000,
                    timestamp: 110,
                    round_id: 2,
                },
                110,
            )
            .is_ok());

        // 10% jump: 11_330_000 (deviation > 500 bps from 10_300_000): rejected
        let err = tracker.record_observation(
            PriceObservation {
                source: "feed_1".into(),
                price: 11_500_000,
                timestamp: 120,
                round_id: 3,
            },
            120,
        );
        assert!(matches!(
            err,
            Err(PriceValidationError::ExcessiveDeviation {
                source: _,
                candidate_price: 11_500_000,
                reference_price: 10_300_000,
                deviation_bps: _,
                max_deviation_bps: 500,
            })
        ));
        assert_eq!(tracker.rejected_deviation_count(), 1);
    }

    #[test]
    fn test_oracle_source_health_reporting_issue_441() {
        let scale = PriceFeedScale::new(7, "USDC");
        let mut tracker = ResilientPriceTracker::new(scale).with_freshness_window(60);

        // Record 1 valid and 1 invalid for source A
        tracker
            .record_observation(
                PriceObservation {
                    source: "source_A".into(),
                    price: 100,
                    timestamp: 1_000,
                    round_id: 1,
                },
                1_000,
            )
            .unwrap();
        let _ = tracker.record_observation(
            PriceObservation {
                source: "source_A".into(),
                price: -50,
                timestamp: 1_010,
                round_id: 2,
            },
            1_010,
        );

        let health = tracker.get_sources_health(1_020);
        assert_eq!(health.len(), 1);
        let s_a = &health[0];
        assert_eq!(s_a.source, "source_A");
        assert!(s_a.is_healthy);
        assert_eq!(s_a.accepted_observations_count, 1);
        assert_eq!(s_a.rejected_observations_count, 1);
        assert_eq!(s_a.latest_price, Some(100));

        // Evaluate at timestamp 1_100 (> 60s age): reported as unhealthy
        let stale_health = tracker.get_sources_health(1_100);
        assert!(!stale_health[0].is_healthy);
    }

    #[test]
    fn test_insufficient_quorum_aggregation_issue_442() {
        let scale = PriceFeedScale::new(7, "USDC");
        let mut tracker = ResilientPriceTracker::new(scale);

        // Empty tracker with quorum 1: InsufficientQuorum
        let res_empty = tracker.calculate_median_price_with_quorum(1);
        assert!(matches!(
            res_empty,
            Err(PriceAggregationError::InsufficientQuorum { active_sources: 0, required_quorum: 1 })
        ));

        // Insert 1 observation
        tracker
            .record_observation(
                PriceObservation {
                    source: "node_1".into(),
                    price: 50_000_000,
                    timestamp: 10,
                    round_id: 1,
                },
                10,
            )
            .unwrap();

        // Quorum 2 requires at least 2 sources
        let res_fail = tracker.calculate_median_price_with_quorum(2);
        assert!(matches!(
            res_fail,
            Err(PriceAggregationError::InsufficientQuorum { active_sources: 1, required_quorum: 2 })
        ));

        // Insert second observation: Quorum 2 succeeds
        tracker
            .record_observation(
                PriceObservation {
                    source: "node_2".into(),
                    price: 60_000_000,
                    timestamp: 10,
                    round_id: 1,
                },
                10,
            )
            .unwrap();
        let res_ok = tracker.calculate_median_price_with_quorum(2);
        assert_eq!(res_ok, Ok(55_000_000));
    }

    #[test]
    fn test_jittered_retry_policy_issue_445() {
        let policy = JitteredRetryPolicy::new(100, 1000, 5);
        assert_eq!(policy.calculate_backoff_ms(0, 42), 0);
        let b1 = policy.calculate_backoff_ms(1, 10);
        assert!((100..=125).contains(&b1));
        let b_high = policy.calculate_backoff_ms(10, 99);
        assert_eq!(b_high, 1000);
    }
}

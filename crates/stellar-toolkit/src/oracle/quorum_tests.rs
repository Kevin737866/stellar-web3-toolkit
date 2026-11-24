#![cfg(test)]

use std::vec;
use std::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleObservation {
    pub source_id: &'static str,
    pub price: i128,
    pub timestamp: u64,
    pub decimals: u32,
    pub healthy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleError {
    InsufficientQuorum { required: usize, valid: usize },
    InvalidQuorumConfig,
    StaleObservation,
    DecimalsMismatch,
    ExcessiveDeviation,
}

#[derive(Debug, Clone)]
pub struct QuorumConfig {
    pub min_quorum: usize,
    pub max_age_secs: u64,
    pub expected_decimals: u32,
    pub max_deviation_bps: u32,
}

/// Aggregates valid, fresh, healthy oracle observations and rejects insufficient quorum explicitly.
pub fn aggregate_with_quorum(
    observations: &[OracleObservation],
    now: u64,
    config: &QuorumConfig,
) -> Result<i128, OracleError> {
    if config.min_quorum == 0 {
        return Err(OracleError::InvalidQuorumConfig);
    }

    let mut valid_prices: Vec<i128> = Vec::new();

    for obs in observations {
        if !obs.healthy || obs.price <= 0 {
            continue;
        }
        if obs.decimals != config.expected_decimals {
            return Err(OracleError::DecimalsMismatch);
        }
        if now.saturating_sub(obs.timestamp) > config.max_age_secs {
            continue;
        }
        valid_prices.push(obs.price);
    }

    if valid_prices.len() < config.min_quorum {
        return Err(OracleError::InsufficientQuorum {
            required: config.min_quorum,
            valid: valid_prices.len(),
        });
    }

    valid_prices.sort_unstable();
    let median = valid_prices[valid_prices.len() / 2];

    for price in &valid_prices {
        let diff = (*price - median).abs();
        let max_allowed = (median.saturating_mul(config.max_deviation_bps as i128)) / 10_000;
        if diff > max_allowed {
            return Err(OracleError::ExcessiveDeviation);
        }
    }

    Ok(median)
}

#[test]
fn test_quorum_succeeds_at_exact_boundary() {
    let config = QuorumConfig {
        min_quorum: 3,
        max_age_secs: 60,
        expected_decimals: 7,
        max_deviation_bps: 500,
    };

    let observations = vec![
        OracleObservation {
            source_id: "src_a",
            price: 100_000_000,
            timestamp: 990,
            decimals: 7,
            healthy: true,
        },
        OracleObservation {
            source_id: "src_b",
            price: 101_000_000,
            timestamp: 995,
            decimals: 7,
            healthy: true,
        },
        OracleObservation {
            source_id: "src_c",
            price: 102_000_000,
            timestamp: 1000,
            decimals: 7,
            healthy: true,
        },
    ];

    let result = aggregate_with_quorum(&observations, 1000, &config);
    assert_eq!(result, Ok(101_000_000));
}

#[test]
fn test_insufficient_quorum_with_fewer_sources_than_required() {
    let config = QuorumConfig {
        min_quorum: 3,
        max_age_secs: 60,
        expected_decimals: 7,
        max_deviation_bps: 500,
    };

    let observations = vec![
        OracleObservation {
            source_id: "src_a",
            price: 100_000_000,
            timestamp: 995,
            decimals: 7,
            healthy: true,
        },
        OracleObservation {
            source_id: "src_b",
            price: 101_000_000,
            timestamp: 1000,
            decimals: 7,
            healthy: true,
        },
    ];

    let result = aggregate_with_quorum(&observations, 1000, &config);
    assert_eq!(
        result,
        Err(OracleError::InsufficientQuorum {
            required: 3,
            valid: 2,
        })
    );
}

#[test]
fn test_insufficient_quorum_when_stale_and_unhealthy_sources_drop_count() {
    let config = QuorumConfig {
        min_quorum: 3,
        max_age_secs: 60,
        expected_decimals: 7,
        max_deviation_bps: 500,
    };

    let observations = vec![
        OracleObservation {
            source_id: "src_a",
            price: 100_000_000,
            timestamp: 995,
            decimals: 7,
            healthy: true,
        },
        OracleObservation {
            source_id: "src_b",
            price: 101_000_000,
            timestamp: 900, // Stale (> 60s old)
            decimals: 7,
            healthy: true,
        },
        OracleObservation {
            source_id: "src_c",
            price: 102_000_000,
            timestamp: 998,
            decimals: 7,
            healthy: false, // Unhealthy
        },
        OracleObservation {
            source_id: "src_d",
            price: 0, // Invalid non-positive price
            timestamp: 999,
            decimals: 7,
            healthy: true,
        },
    ];

    let result = aggregate_with_quorum(&observations, 1000, &config);
    assert_eq!(
        result,
        Err(OracleError::InsufficientQuorum {
            required: 3,
            valid: 1,
        })
    );
}

#[test]
fn test_empty_observations_returns_insufficient_quorum() {
    let config = QuorumConfig {
        min_quorum: 2,
        max_age_secs: 60,
        expected_decimals: 7,
        max_deviation_bps: 500,
    };

    let result = aggregate_with_quorum(&[], 1000, &config);
    assert_eq!(
        result,
        Err(OracleError::InsufficientQuorum {
            required: 2,
            valid: 0,
        })
    );
}
//! Deterministic PRNG seeding and reproducible scenario runner for `crates/channel-simulator`.
//!
//! Ensures identical simulation seeds produce identical event traces, message latencies,
//! fault schedules, and final ledger balances while exposing the active seed in failure
//! diagnostics for exact replay.

use std::fmt;
use std::vec::Vec;

pub const DEFAULT_MAX_STEPS: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimulationSeedError {
    ZeroSeedNotAllowed,
    ZeroMaxSteps,
    StepBudgetExceeded { max_steps: usize, seed: u64 },
    InvalidChannelCount,
    InvariantViolation {
        step: usize,
        seed: u64,
        detail: &'static str,
    },
}

impl fmt::Display for SimulationSeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSeedNotAllowed => {
                write!(f, "simulation seed must be non-zero for deterministic replay")
            }
            Self::ZeroMaxSteps => write!(f, "max_steps must be greater than zero"),
            Self::StepBudgetExceeded { max_steps, seed } => write!(
                f,
                "simulation exceeded bounded step limit ({max_steps}) [reproduce with seed={seed:#018x}]"
            ),
            Self::InvalidChannelCount => write!(f, "channel_count must be greater than zero"),
            Self::InvariantViolation { step, seed, detail } => write!(
                f,
                "invariant violation at step {step}: {detail} [reproduce with seed={seed:#018x}]"
            ),
        }
    }
}

impl std::error::Error for SimulationSeedError {}

/// Deterministic SplitMix64 PRNG so scenario runs are reproducible across platforms
/// without relying on ambient OS entropy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeterministicRng {
    seed: u64,
    state: u64,
}

impl DeterministicRng {
    pub fn new(seed: u64) -> Result<Self, SimulationSeedError> {
        if seed == 0 {
            return Err(SimulationSeedError::ZeroSeedNotAllowed);
        }
        Ok(Self { seed, state: seed })
    }

    pub fn seed(&self) -> u64 {
        self.seed
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn next_range(&mut self, upper_exclusive: u64) -> u64 {
        if upper_exclusive <= 1 {
            return 0;
        }
        self.next_u64() % upper_exclusive
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioConfig {
    pub seed: u64,
    pub channel_count: usize,
    pub initial_balance_per_side: i128,
    pub max_steps: usize,
    pub target_steps: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulationStepRecord {
    pub step: usize,
    pub channel_idx: usize,
    pub delta: i128,
    pub latency_ms: u64,
    pub dropped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioReport {
    pub seed: u64,
    pub executed_steps: usize,
    pub trace: Vec<SimulationStepRecord>,
    pub final_balances: Vec<(i128, i128)>,
}

/// Runs a bounded, deterministic payment-channel network simulation from an explicit seed.
pub fn run_seeded_scenario(config: &ScenarioConfig) -> Result<ScenarioReport, SimulationSeedError> {
    if config.channel_count == 0 {
        return Err(SimulationSeedError::InvalidChannelCount);
    }
    if config.max_steps == 0 {
        return Err(SimulationSeedError::ZeroMaxSteps);
    }
    if config.target_steps > config.max_steps {
        return Err(SimulationSeedError::StepBudgetExceeded {
            max_steps: config.max_steps,
            seed: config.seed,
        });
    }

    let mut rng = DeterministicRng::new(config.seed)?;
    let mut balances: Vec<(i128, i128)> = (0..config.channel_count)
        .map(|_| {
            (
                config.initial_balance_per_side,
                config.initial_balance_per_side,
            )
        })
        .collect();
    let total_capacity = config
        .initial_balance_per_side
        .saturating_mul(2);

    let mut trace = Vec::with_capacity(config.target_steps);

    for step in 0..config.target_steps {
        let channel_idx = (rng.next_range(config.channel_count as u64)) as usize;
        let latency_ms = 5 + rng.next_range(95);
        let dropped = rng.next_range(10) == 0;
        let direction_a_to_b = rng.next_range(2) == 0;
        let raw_amount = (1 + rng.next_range(50)) as i128;

        let (left, right) = balances[channel_idx];
        let delta = if dropped {
            0
        } else if direction_a_to_b {
            let transferable = raw_amount.min(left);
            balances[channel_idx] = (left - transferable, right + transferable);
            transferable
        } else {
            let transferable = raw_amount.min(right);
            balances[channel_idx] = (left + transferable, right - transferable);
            -transferable
        };

        let (updated_left, updated_right) = balances[channel_idx];
        if updated_left < 0
            || updated_right < 0
            || updated_left.saturating_add(updated_right) != total_capacity
        {
            return Err(SimulationSeedError::InvariantViolation {
                step,
                seed: config.seed,
                detail: "channel capacity conservation violated",
            });
        }

        trace.push(SimulationStepRecord {
            step,
            channel_idx,
            delta,
            latency_ms,
            dropped,
        });
    }

    Ok(ScenarioReport {
        seed: config.seed,
        executed_steps: trace.len(),
        trace,
        final_balances: balances,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_seeds_produce_identical_traces_and_balances() {
        let config = ScenarioConfig {
            seed: 0x5EED_CAFE_1234_5678,
            channel_count: 4,
            initial_balance_per_side: 1_000,
            max_steps: DEFAULT_MAX_STEPS,
            target_steps: 250,
        };

        let run_a = run_seeded_scenario(&config).expect("first seeded run succeeds");
        let run_b = run_seeded_scenario(&config).expect("second seeded run succeeds");

        assert_eq!(run_a.seed, config.seed);
        assert_eq!(run_a, run_b);
    }

    #[test]
    fn test_distinct_seeds_diverge_deterministically() {
        let base = ScenarioConfig {
            seed: 101,
            channel_count: 3,
            initial_balance_per_side: 500,
            max_steps: 500,
            target_steps: 100,
        };
        let mut other = base.clone();
        other.seed = 202;

        let report_1 = run_seeded_scenario(&base).unwrap();
        let report_2 = run_seeded_scenario(&other).unwrap();

        assert_ne!(report_1.trace, report_2.trace);
    }

    #[test]
    fn test_rejects_zero_seed_and_unbounded_steps_with_seed_diagnostics() {
        let zero_seed = ScenarioConfig {
            seed: 0,
            channel_count: 2,
            initial_balance_per_side: 100,
            max_steps: 100,
            target_steps: 10,
        };
        assert_eq!(
            run_seeded_scenario(&zero_seed),
            Err(SimulationSeedError::ZeroSeedNotAllowed)
        );

        let over_budget = ScenarioConfig {
            seed: 0xDEAD_BEEF,
            channel_count: 2,
            initial_balance_per_side: 100,
            max_steps: 50,
            target_steps: 51,
        };
        let err = run_seeded_scenario(&over_budget).unwrap_err();
        assert_eq!(
            err,
            SimulationSeedError::StepBudgetExceeded {
                max_steps: 50,
                seed: 0xDEAD_BEEF,
            }
        );
        assert!(err.to_string().contains("0x00000000deadbeef"));
    }
}
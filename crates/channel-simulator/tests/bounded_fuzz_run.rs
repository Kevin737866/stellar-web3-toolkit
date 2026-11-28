//! Integration tests for bounded fuzz runs and seed-reporting failure
//! diagnostics in `channel-simulator` (issue #382).
//!
//! These exercise the public fuzzer API the way an operator would: configure a
//! run, let it stop at its budget, and replay a reported failure from the seed
//! the report names.

use channel_simulator::fuzz::{
    FuzzTermination, TopologyFuzzConfig, TopologyFuzzer, MAX_FUZZ_DURATION_MS,
};
use channel_simulator::{DisconnectionConfig, SimulatorError};

fn bounded_config(iterations: usize, max_duration_ms: Option<u64>) -> TopologyFuzzConfig {
    TopologyFuzzConfig {
        iterations,
        seed: 0x5EED_1234_ABCD_0001,
        min_nodes: 2,
        max_nodes: 16,
        payments_per_topology: 2,
        max_duration_ms,
        ..TopologyFuzzConfig::default()
    }
}

#[test]
fn a_long_run_stops_at_its_duration_budget_and_stays_replayable() {
    let fuzzer = TopologyFuzzer::try_new(bounded_config(5_000_000, Some(10))).unwrap();
    let report = fuzzer.run();

    assert_eq!(report.termination, FuzzTermination::DurationBudgetExceeded);
    assert!(report.was_truncated());
    assert_eq!(report.seed, 0x5EED_1234_ABCD_0001);
    assert!(
        report.iterations < 5_000_000,
        "budget did not bound the run: {} iterations",
        report.iterations
    );
    // The report is what a bug report quotes, so it must carry the seed.
    assert!(report.summarize().contains("seed=0x5eed1234abcd0001"));
}

#[test]
fn a_clean_bounded_run_reports_completion_and_the_seed() {
    let fuzzer = TopologyFuzzer::try_new(bounded_config(9, Some(MAX_FUZZ_DURATION_MS))).unwrap();
    let report = fuzzer.run();

    assert_eq!(report.termination, FuzzTermination::Completed);
    assert!(report.is_clean(), "{}", report.summarize());
    assert_eq!(report.iterations, 9);
    assert_eq!(report.max_duration_ms, Some(MAX_FUZZ_DURATION_MS));
}

#[test]
fn a_reported_failure_replays_from_its_recorded_seed() {
    // Invalid churn parameters turn every iteration into a reported failure.
    let config = TopologyFuzzConfig {
        iterations: 4,
        seed: 0xC0FF_EE00_1234_5678,
        min_nodes: 3,
        max_nodes: 10,
        payments_per_topology: 2,
        disconnection: Some(DisconnectionConfig {
            disconnect_probability: 2.0,
            ..DisconnectionConfig::default()
        }),
        max_duration_ms: None,
    };

    let fuzzer = TopologyFuzzer::new(config);
    let report = fuzzer.run();
    let failure = report.failures.first().cloned().expect("a failure");

    assert_eq!(report.failures.len(), 4);
    assert_eq!(failure.run_seed, 0xC0FF_EE00_1234_5678);
    assert!(failure
        .replay_hint()
        .contains(&format!("iteration={}", failure.iteration)));

    // Replaying just the named iteration reproduces exactly that failure.
    let mut replayed = channel_simulator::fuzz::FuzzReport::default();
    fuzzer.run_iteration(failure.iteration, &mut replayed);
    assert_eq!(replayed.failures, vec![failure]);
}

#[test]
fn the_duration_budget_is_validated_instead_of_clamped() {
    let zero = TopologyFuzzer::try_new(bounded_config(10, Some(0)));
    assert!(matches!(zero, Err(SimulatorError::InvalidConfig(_))));

    let oversized = TopologyFuzzer::try_new(bounded_config(10, Some(MAX_FUZZ_DURATION_MS + 1)));
    assert!(matches!(oversized, Err(SimulatorError::InvalidConfig(_))));
}

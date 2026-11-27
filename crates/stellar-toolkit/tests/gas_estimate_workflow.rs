//! Integration tests for `gas estimate` fee breakdown (issue #314).
//!
//! These tests exercise the public library API end-to-end using
//! [`stellar_toolkit::FeeEstimateReport`], mirroring the conventions in
//! `env_validate_workflow.rs`.

use stellar_toolkit::{
    FeeBreakdown, FeeEstimateReport, FeeSchedule, GasSimulator, TransactionProfile,
};

// ── Helper ────────────────────────────────────────────────────────────────────

fn testnet_simulator() -> GasSimulator {
    GasSimulator::new(FeeSchedule::testnet_default())
}

// ── Normal path: breakdown values and percentages ────────────────────────────

#[test]
fn report_breakdown_stroops_match_direct_estimate() {
    let sim = testnet_simulator();
    let profile = TransactionProfile::default();
    let report = FeeEstimateReport::build(&sim, profile);
    let direct = sim.estimate(&profile);

    assert_eq!(report.estimate.total_stroops, direct.total_stroops);
    assert_eq!(
        report.estimate.breakdown.resource_fee,
        direct.breakdown.resource_fee
    );
    assert_eq!(
        report.estimate.breakdown.inclusion_bid,
        direct.breakdown.inclusion_bid
    );
    assert_eq!(
        report.estimate.breakdown.base_fee,
        direct.breakdown.base_fee
    );
    assert_eq!(
        report.estimate.breakdown.per_operation,
        direct.breakdown.per_operation
    );
}

#[test]
fn report_breakdown_percents_sum_to_100_for_default_profile() {
    let sim = testnet_simulator();
    let report = FeeEstimateReport::build(&sim, TransactionProfile::default());
    let pct = &report.percents;
    let sum =
        pct.base_fee_pct + pct.resource_fee_pct + pct.inclusion_bid_pct + pct.per_operation_pct;
    // Four components, each rounded to 1 d.p., so at most ±0.4 rounding error.
    assert!(
        (sum - 100.0).abs() < 0.4,
        "percent components must sum to ~100, got {sum}"
    );
}

#[test]
fn report_dominant_component_is_resource_fee_for_default_profile() {
    let sim = testnet_simulator();
    let report = FeeEstimateReport::build(&sim, TransactionProfile::default());
    let pct = &report.percents;
    // resource_fee is 1_008_000 out of 1_008_300 — well above 99%.
    assert!(
        pct.resource_fee_pct > 99.0,
        "resource fee must dominate for default profile, got {}%",
        pct.resource_fee_pct
    );
    assert!(
        pct.base_fee_pct < 1.0,
        "base fee must be <1% for default profile, got {}%",
        pct.base_fee_pct
    );
}

// ── Normal path: JSON output ──────────────────────────────────────────────────

#[test]
fn to_json_emits_valid_json() {
    let sim = testnet_simulator();
    let report = FeeEstimateReport::build(&sim, TransactionProfile::default());
    let json = report.to_json().expect("to_json must not fail");
    let _: serde_json::Value =
        serde_json::from_str(&json).expect("to_json must produce valid JSON");
}

#[test]
fn to_json_contains_all_required_top_level_keys() {
    let sim = testnet_simulator();
    let report = FeeEstimateReport::build(&sim, TransactionProfile::default());
    let json = report.to_json().expect("to_json must not fail");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert!(v["profile"].is_object(), "profile must be an object");
    assert!(v["estimate"].is_object(), "estimate must be an object");
    assert!(v["bump_ladder"].is_array(), "bump_ladder must be an array");
}

#[test]
fn to_json_breakdown_has_stroops_xlm_and_pct_for_every_component() {
    let sim = testnet_simulator();
    let report = FeeEstimateReport::build(&sim, TransactionProfile::default());
    let json = report.to_json().expect("to_json must not fail");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let bd = &v["estimate"]["breakdown"];

    for key in ["base_fee", "resource_fee", "inclusion_bid", "per_operation"] {
        assert!(
            bd[key]["stroops"].is_number(),
            "{key}.stroops must be a number"
        );
        assert!(bd[key]["xlm"].is_string(), "{key}.xlm must be a string");
        assert!(bd[key]["pct"].is_number(), "{key}.pct must be a number");
    }
    // `inclusion_bid` additionally carries bid_ledgers.
    assert!(
        v["estimate"]["breakdown"]["inclusion_bid"]["bid_ledgers"].is_number(),
        "inclusion_bid.bid_ledgers must be a number"
    );
}

#[test]
fn to_json_stroops_match_human_readable_breakdown() {
    let sim = testnet_simulator();
    let profile = TransactionProfile::default();
    let report = FeeEstimateReport::build(&sim, profile);
    let json = report.to_json().expect("to_json must not fail");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();

    let bd = &report.estimate.breakdown;
    assert_eq!(
        v["estimate"]["breakdown"]["resource_fee"]["stroops"]
            .as_u64()
            .unwrap(),
        u64::from(bd.resource_fee)
    );
    assert_eq!(
        v["estimate"]["total_stroops"].as_u64().unwrap(),
        u64::from(report.estimate.total_stroops)
    );
}

#[test]
fn to_json_total_xlm_string_ends_with_xlm_suffix() {
    let sim = testnet_simulator();
    let report = FeeEstimateReport::build(&sim, TransactionProfile::default());
    let json = report.to_json().expect("to_json must not fail");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let xlm = v["estimate"]["total_xlm"].as_str().unwrap_or("");
    assert!(
        xlm.ends_with(" XLM"),
        "total_xlm must end with ' XLM', got '{xlm}'"
    );
}

// ── Normal path: bump ladder in report ───────────────────────────────────────

#[test]
fn report_bump_ladder_entries_are_strictly_increasing() {
    let sim = testnet_simulator();
    let report = FeeEstimateReport::build(&sim, TransactionProfile::default());
    let mut prev = report.estimate.total_stroops;
    for bump in &report.bump_ladder {
        assert!(
            bump.outer_fee_stroops > prev,
            "ladder must be strictly increasing: {} -> {}",
            prev,
            bump.outer_fee_stroops
        );
        prev = bump.outer_fee_stroops;
    }
}

#[test]
fn to_json_bump_ladder_attempt_numbers_are_one_indexed() {
    let sim = testnet_simulator();
    let report = FeeEstimateReport::build(&sim, TransactionProfile::default());
    let json = report.to_json().expect("to_json must not fail");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let ladder = v["bump_ladder"].as_array().unwrap();
    for (i, entry) in ladder.iter().enumerate() {
        assert_eq!(
            entry["attempt"].as_u64(),
            Some(i as u64 + 1),
            "attempt must be 1-indexed"
        );
    }
}

// ── Boundary: zero-instructions profile ──────────────────────────────────────

#[test]
fn zero_instruction_profile_has_zero_resource_fee_pct_from_instructions() {
    let sim = testnet_simulator();
    let profile = TransactionProfile {
        operations: 1,
        instructions: 0,
        ledger_reads: 0,
        ledger_writes: 0,
        bid_ledgers: 0,
    };
    let report = FeeEstimateReport::build(&sim, profile);
    // With no resources and no bid, all cost is base + per_op.
    assert_eq!(report.estimate.breakdown.resource_fee, 0);
    assert_eq!(report.estimate.breakdown.inclusion_bid, 0);
    assert!(
        report.percents.base_fee_pct + report.percents.per_operation_pct > 99.0,
        "base + per_op must account for the full cost when resources are zero"
    );
}

#[test]
fn zero_instruction_profile_to_json_is_valid() {
    let sim = testnet_simulator();
    let profile = TransactionProfile {
        operations: 1,
        instructions: 0,
        ledger_reads: 0,
        ledger_writes: 0,
        bid_ledgers: 0,
    };
    let report = FeeEstimateReport::build(&sim, profile);
    let json = report.to_json().expect("to_json must not fail");
    let _: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
}

// ── Boundary: single-component dominance ─────────────────────────────────────

#[test]
fn huge_instruction_count_makes_resource_fee_near_100_pct() {
    let sim = testnet_simulator();
    let profile = TransactionProfile {
        operations: 1,
        instructions: u32::MAX / 100, // very large but no overflow
        ledger_reads: 0,
        ledger_writes: 0,
        bid_ledgers: 0,
    };
    let report = FeeEstimateReport::build(&sim, profile);
    assert!(
        report.percents.resource_fee_pct > 95.0,
        "huge instruction count must make resource_fee dominate, got {}%",
        report.percents.resource_fee_pct
    );
}

// ── Boundary: saturation ─────────────────────────────────────────────────────

#[test]
fn saturating_profile_produces_valid_report_without_panic() {
    let sim = testnet_simulator();
    let profile = TransactionProfile {
        operations: u32::MAX,
        instructions: u32::MAX,
        ledger_reads: u32::MAX,
        ledger_writes: u32::MAX,
        bid_ledgers: u32::MAX,
    };
    let report = FeeEstimateReport::build(&sim, profile);
    assert_eq!(report.estimate.total_stroops, u32::MAX);
    // JSON serialisation must not panic on the saturated value.
    let json = report
        .to_json()
        .expect("to_json must not fail on saturated profile");
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(
        v["estimate"]["total_stroops"].as_u64().unwrap(),
        u64::from(u32::MAX)
    );
}

// ── Boundary: zero-operations edge case ──────────────────────────────────────

#[test]
fn zero_total_stroops_produces_zero_percents() {
    // A FeeBreakdown whose components are all zero has total=0 and all percents=0.
    let bd = FeeBreakdown {
        base_fee: 0,
        resource_fee: 0,
        inclusion_bid: 0,
        per_operation: 0,
    };
    let pct = bd.percent_of(0);
    assert!((pct.base_fee_pct - 0.0).abs() < f64::EPSILON);
    assert!((pct.resource_fee_pct - 0.0).abs() < f64::EPSILON);
    assert!((pct.inclusion_bid_pct - 0.0).abs() < f64::EPSILON);
    assert!((pct.per_operation_pct - 0.0).abs() < f64::EPSILON);
}

// ── Failure path: invalid base_fee is caught by the simulator ────────────────

#[test]
fn fee_bump_rejects_zero_base_fee() {
    let sim = testnet_simulator();
    // fee_bump is the entry point that checks base_fee == 0.
    assert!(
        sim.fee_bump(1_000, 1_000, 0).is_err(),
        "zero base_fee must be rejected"
    );
}

// ── Compatibility: existing FeeEstimate fields remain unchanged ───────────────

#[test]
fn fee_estimate_total_xlm_matches_expected_value_for_default_profile() {
    let sim = testnet_simulator();
    let estimate = sim.estimate(&TransactionProfile::default());
    // 1_008_300 stroops / 10_000_000 = 0.10083 XLM
    let xlm = estimate.total_xlm();
    assert!(
        (xlm - 0.100_830_0_f64).abs() < 1e-7,
        "total_xlm must be ~0.1008300, got {xlm}"
    );
}

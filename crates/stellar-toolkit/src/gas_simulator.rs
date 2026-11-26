//! Local gas simulator with fee bump planning (issue #243).
//!
//! Estimates the fee of a Soroban transaction from its resource profile and
//! plans the fee bump transactions used to resubmit a transaction that was not
//! included in a ledger because the network base fee moved. Fees are expressed in
//! stroops (1 XLM = `10_000_000` stroops) to match the Stellar protocol.
//!
//! # Fee breakdown
//!
//! [`GasSimulator::estimate`] returns a [`FeeEstimate`] that includes a
//! [`FeeBreakdown`] with four named components:
//!
//! | Component | What it covers |
//! |-----------|----------------|
//! | `base_fee` | Protocol minimum, one unit per operation |
//! | `resource_fee` | Soroban instructions + read/write footprint |
//! | `inclusion_bid` | Per-ledger inclusion incentive |
//! | `per_operation` | Fixed per-op overhead (signature, envelope) |
//!
//! [`FeeEstimateReport`] wraps the estimate together with the transaction
//! profile and per-component percentage labels for display and machine
//! consumption. Use [`FeeEstimateReport::to_json`] to get a stable JSON
//! representation suitable for scripting and CI pipelines.

use crate::error::{Result, ToolkitError};
use serde::{Deserialize, Serialize};

/// Stroops in one XLM.
pub const STROOPS_PER_XLM: u64 = 10_000_000;

/// Network fee parameters, all values in stroops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeSchedule {
    /// Minimum fee accepted per operation (the network base fee).
    pub base_fee_stroops: u32,
    /// Soroban resource fee charged per executed instruction.
    pub per_instruction_stroops: u32,
    /// Footprint fee for reading a ledger entry.
    pub read_entry_stroops: u32,
    /// Footprint fee for writing a ledger entry.
    pub write_entry_stroops: u32,
    /// Fixed per operation overhead (signature envelope, inclusion).
    pub per_operation_stroops: u32,
    /// Bid paid per ledger of expected inclusion delay.
    pub bid_per_ledger_stroops: u32,
    /// Ceiling for fee bumps so a retry loop cannot bid away the account.
    pub max_fee_stroops: u32,
    /// Percentage added to the fee on every bump (`50` => x1.5).
    pub bump_percent: u32,
    /// Maximum number of automated bumps.
    pub max_bumps: u32,
}

impl FeeSchedule {
    /// Conservative defaults for the public testnet fee model.
    #[must_use]
    pub fn testnet_default() -> Self {
        Self {
            base_fee_stroops: 100,
            per_instruction_stroops: 10,
            read_entry_stroops: 1_000,
            write_entry_stroops: 5_000,
            per_operation_stroops: 100,
            bid_per_ledger_stroops: 100,
            max_fee_stroops: 10_000_000,
            bump_percent: 50,
            max_bumps: 3,
        }
    }
}

/// Resource profile of the transaction being submitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionProfile {
    /// Number of transaction operations, each paying its own base fee.
    pub operations: u32,
    /// Soroban instructions executed by the transaction.
    pub instructions: u32,
    /// Ledger entries read by the read footprint.
    pub ledger_reads: u32,
    /// Ledger entries written by the write footprint.
    pub ledger_writes: u32,
    /// Expected number of ledgers to wait for inclusion.
    pub bid_ledgers: u32,
}

impl Default for TransactionProfile {
    fn default() -> Self {
        Self {
            operations: 1,
            instructions: 100_000,
            ledger_reads: 3,
            ledger_writes: 1,
            bid_ledgers: 1,
        }
    }
}

/// Per component fee breakdown, all values in stroops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeBreakdown {
    pub base_fee: u32,
    pub resource_fee: u32,
    pub inclusion_bid: u32,
    pub per_operation: u32,
}

impl FeeBreakdown {
    /// Percentage of `total` that each component accounts for, rounded to one
    /// decimal place. Returns `0.0` when `total` is zero.
    #[must_use]
    pub fn percent_of(&self, total: u32) -> FeeBreakdownPercents {
        let pct = |part: u32| -> f64 {
            if total == 0 {
                0.0
            } else {
                (f64::from(part) / f64::from(total) * 1000.0).round() / 10.0
            }
        };
        FeeBreakdownPercents {
            base_fee_pct: pct(self.base_fee),
            resource_fee_pct: pct(self.resource_fee),
            inclusion_bid_pct: pct(self.inclusion_bid),
            per_operation_pct: pct(self.per_operation),
        }
    }
}

/// Per-component percentage share of the total fee (one decimal place).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct FeeBreakdownPercents {
    pub base_fee_pct: f64,
    pub resource_fee_pct: f64,
    pub inclusion_bid_pct: f64,
    pub per_operation_pct: f64,
}

/// Total fee required to submit a transaction with the current base fee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeEstimate {
    pub total_stroops: u32,
    pub breakdown: FeeBreakdown,
    pub bid_ledgers: u32,
}

impl FeeEstimate {
    #[must_use]
    pub fn total_xlm(&self) -> f64 {
        f64::from(self.total_stroops) / STROOPS_PER_XLM as f64
    }
}

/// Full structured report combining the estimate, the profile that produced it,
/// the fee-bump ladder, and per-component percentage labels.
///
/// Use [`FeeEstimateReport::to_json`] for a stable machine-readable
/// representation. The JSON schema is documented below.
///
/// # JSON schema
///
/// ```json
/// {
///   "profile": {
///     "operations": 1,
///     "instructions": 100000,
///     "ledger_reads": 3,
///     "ledger_writes": 1,
///     "bid_ledgers": 1
///   },
///   "estimate": {
///     "total_stroops": 1008300,
///     "total_xlm": "0.1008300 XLM",
///     "breakdown": {
///       "base_fee":      { "stroops": 100,     "xlm": "0.0000100 XLM", "pct": 0.0 },
///       "resource_fee":  { "stroops": 1008000, "xlm": "0.1008000 XLM", "pct": 99.9 },
///       "inclusion_bid": { "stroops": 100,     "xlm": "0.0000100 XLM", "pct": 0.0, "bid_ledgers": 1 },
///       "per_operation": { "stroops": 100,     "xlm": "0.0000100 XLM", "pct": 0.0 }
///     }
///   },
///   "bump_ladder": [
///     { "attempt": 1, "inner_stroops": 1008300, "outer_stroops": 1512450, "outer_xlm": "0.1512450 XLM", "pct_over_signed": 150 }
///   ]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimateReport {
    /// Transaction profile used to compute the estimate.
    pub profile: TransactionProfile,
    /// Fee estimate including the per-component breakdown.
    pub estimate: FeeEstimate,
    /// Percentage share of each component in the total fee.
    pub percents: FeeBreakdownPercents,
    /// Fee bump ladder for automated retries.
    pub bump_ladder: Vec<FeeBump>,
}

impl FeeEstimateReport {
    /// Build a report for `profile` using `simulator`.
    #[must_use]
    pub fn build(simulator: &GasSimulator, profile: TransactionProfile) -> Self {
        let estimate = simulator.estimate(&profile);
        let percents = estimate.breakdown.percent_of(estimate.total_stroops);
        let bump_ladder = simulator.bump_ladder(estimate.total_stroops);
        Self {
            profile,
            estimate,
            percents,
            bump_ladder,
        }
    }

    /// Serialise the report to compact, pretty-printed JSON.
    ///
    /// The output is stable across patch versions of this crate: existing keys
    /// are never removed and new keys are always added at the end of their
    /// object.
    ///
    /// # Errors
    ///
    /// Returns a [`ToolkitError::ExecutionError`] if `serde_json` fails to
    /// serialise the report (this cannot happen with the types used here, but
    /// the method signature is `Result` to match other `to_json` methods in this
    /// crate).
    pub fn to_json(&self) -> Result<String> {
        // Build a richer JSON value that includes the XLM string alongside the
        // raw stroops so callers do not have to implement the conversion.
        let bd = &self.estimate.breakdown;
        let pct = &self.percents;
        let total = self.estimate.total_stroops;

        let breakdown = serde_json::json!({
            "base_fee": {
                "stroops": bd.base_fee,
                "xlm": format_stroops(bd.base_fee),
                "pct": pct.base_fee_pct
            },
            "resource_fee": {
                "stroops": bd.resource_fee,
                "xlm": format_stroops(bd.resource_fee),
                "pct": pct.resource_fee_pct
            },
            "inclusion_bid": {
                "stroops": bd.inclusion_bid,
                "xlm": format_stroops(bd.inclusion_bid),
                "pct": pct.inclusion_bid_pct,
                "bid_ledgers": self.estimate.bid_ledgers
            },
            "per_operation": {
                "stroops": bd.per_operation,
                "xlm": format_stroops(bd.per_operation),
                "pct": pct.per_operation_pct
            }
        });

        let ladder: Vec<serde_json::Value> = self
            .bump_ladder
            .iter()
            .enumerate()
            .map(|(i, bump)| {
                serde_json::json!({
                    "attempt": i + 1,
                    "inner_stroops": bump.inner_fee_stroops,
                    "outer_stroops": bump.outer_fee_stroops,
                    "outer_xlm": format_stroops(bump.outer_fee_stroops),
                    "pct_over_signed": bump.percent_over_signed_fee()
                })
            })
            .collect();

        let doc = serde_json::json!({
            "profile": self.profile,
            "estimate": {
                "total_stroops": total,
                "total_xlm": format_stroops(total),
                "breakdown": breakdown
            },
            "bump_ladder": ladder
        });

        serde_json::to_string_pretty(&doc)
            .map_err(|e| ToolkitError::ExecutionError(format!("json serialise: {e}")))
    }
}

/// A fee bump transaction wrapping an already signed inner transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeBump {
    /// Fee of the inner transaction being resubmitted.
    pub inner_fee_stroops: u32,
    /// Fee the inner transaction carried when it was originally signed.
    pub inner_fee_at_signing_stroops: u32,
    /// Fee paid by the outer transaction; this is what the fee source pays.
    pub outer_fee_stroops: u32,
    /// Network base fee the bump was computed against.
    pub base_fee_stroops: u32,
}

impl FeeBump {
    /// Total amount the fee source has to hold for this attempt.
    #[must_use]
    pub fn fee_source_pays(&self) -> u32 {
        self.outer_fee_stroops
    }

    /// Percentage the outer fee raises the fee the inner transaction was signed with.
    #[must_use]
    pub fn percent_over_signed_fee(&self) -> u32 {
        if self.inner_fee_at_signing_stroops == 0 {
            return 0;
        }
        // Computed in `u64` so the multiply cannot overflow at the top of the
        // fee range, then narrowed: the result is a percentage, so it always
        // fits back into `u32`.
        ((u64::from(self.outer_fee_stroops) * 100) / u64::from(self.inner_fee_at_signing_stroops))
            as u32
    }
}

/// Estimates Soroban fees and plans fee bumps.
pub struct GasSimulator {
    schedule: FeeSchedule,
}

impl GasSimulator {
    #[must_use]
    pub fn new(schedule: FeeSchedule) -> Self {
        Self { schedule }
    }

    /// Fee required to submit `profile` right now.
    #[must_use]
    pub fn estimate(&self, profile: &TransactionProfile) -> FeeEstimate {
        let schedule = &self.schedule;
        let resource_fee = profile
            .instructions
            .saturating_mul(schedule.per_instruction_stroops)
            .saturating_add(
                profile
                    .ledger_reads
                    .saturating_mul(schedule.read_entry_stroops),
            )
            .saturating_add(
                profile
                    .ledger_writes
                    .saturating_mul(schedule.write_entry_stroops),
            );
        let inclusion_bid = profile
            .bid_ledgers
            .saturating_mul(schedule.bid_per_ledger_stroops);
        let per_operation = schedule
            .per_operation_stroops
            .saturating_mul(profile.operations);
        let base_fee = schedule.base_fee_stroops.saturating_mul(profile.operations);

        let total_stroops = base_fee
            .saturating_add(resource_fee)
            .saturating_add(inclusion_bid)
            .saturating_add(per_operation)
            .max(schedule.base_fee_stroops);

        FeeEstimate {
            total_stroops,
            breakdown: FeeBreakdown {
                base_fee,
                resource_fee,
                inclusion_bid,
                per_operation,
            },
            bid_ledgers: profile.bid_ledgers,
        }
    }

    /// Builds the fee bump required by the network rule
    /// `outer_fee = ceil(inner_fee * base_fee / inner_fee_at_signing)`, floored at
    /// the current base fee and capped by `max_fee_stroops`.
    pub fn fee_bump(
        &self,
        inner_fee_stroops: u32,
        inner_fee_at_signing_stroops: u32,
        base_fee_stroops: u32,
    ) -> Result<FeeBump> {
        if inner_fee_stroops == 0 {
            return Err(ToolkitError::ExecutionError(
                "fee bump requires a non-zero inner fee".to_string(),
            ));
        }
        if inner_fee_at_signing_stroops == 0 {
            return Err(ToolkitError::ExecutionError(
                "fee bump requires the fee the inner transaction was signed with".to_string(),
            ));
        }
        if base_fee_stroops == 0 {
            return Err(ToolkitError::ExecutionError(
                "fee bump requires a non-zero base fee".to_string(),
            ));
        }

        let scaled = (u64::from(inner_fee_stroops) * u64::from(base_fee_stroops))
            .div_ceil(u64::from(inner_fee_at_signing_stroops));
        let outer_fee_stroops = scaled
            .max(u64::from(base_fee_stroops))
            .min(u64::from(self.schedule.max_fee_stroops)) as u32;

        Ok(FeeBump {
            inner_fee_stroops,
            inner_fee_at_signing_stroops,
            outer_fee_stroops,
            base_fee_stroops,
        })
    }

    /// True while another bump stays within `max_fee_stroops`.
    #[must_use]
    pub fn is_bumpable(&self, fee_stroops: u32) -> bool {
        fee_stroops < self.schedule.max_fee_stroops
    }

    /// Escalating outer fees for automated retries. The ladder stops at
    /// `max_bumps` attempts, at `max_fee_stroops`, or as soon as a bump would no
    /// longer raise the fee.
    #[must_use]
    pub fn bump_ladder(&self, start_fee_stroops: u32) -> Vec<FeeBump> {
        let schedule = &self.schedule;
        let signed_fee = start_fee_stroops.max(schedule.base_fee_stroops);
        let mut current = signed_fee;
        let mut ladder = Vec::new();

        for _ in 0..schedule.max_bumps {
            let raised = current.saturating_mul(100u32.saturating_add(schedule.bump_percent)) / 100;
            let next = raised.min(schedule.max_fee_stroops);
            if next <= current {
                break;
            }
            ladder.push(FeeBump {
                inner_fee_stroops: current,
                inner_fee_at_signing_stroops: signed_fee,
                outer_fee_stroops: next,
                base_fee_stroops: schedule.base_fee_stroops,
            });
            current = next;
        }
        ladder
    }
}

/// Formats stroops as a human readable XLM amount (7 decimal places).
#[must_use]
pub fn format_stroops(stroops: u32) -> String {
    let value = u64::from(stroops);
    let whole = value / STROOPS_PER_XLM;
    let fraction = value % STROOPS_PER_XLM;
    format!("{whole}.{fraction:07} XLM")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn testnet() -> GasSimulator {
        GasSimulator::new(FeeSchedule::testnet_default())
    }

    #[test]
    fn test_estimate_matches_manual_breakdown() {
        let simulator = testnet();
        let estimate = simulator.estimate(&TransactionProfile::default());
        // 100_000 * 10 + 3 * 1_000 + 1 * 5_000 resource fee
        assert_eq!(estimate.breakdown.resource_fee, 1_008_000);
        assert_eq!(estimate.breakdown.inclusion_bid, 100);
        assert_eq!(estimate.breakdown.per_operation, 100);
        assert_eq!(estimate.breakdown.base_fee, 100);
        assert_eq!(estimate.total_stroops, 1_008_300);
    }

    // ── FeeBreakdown percentage helpers ──────────────────────────────────────

    #[test]
    fn breakdown_percents_sum_to_one_hundred_for_default_profile() {
        let simulator = testnet();
        let estimate = simulator.estimate(&TransactionProfile::default());
        let pct = estimate.breakdown.percent_of(estimate.total_stroops);
        let sum = pct.base_fee_pct + pct.resource_fee_pct + pct.inclusion_bid_pct + pct.per_operation_pct;
        // Allow ±0.4 for rounding across four components rounded to 1 decimal place.
        assert!((sum - 100.0).abs() < 0.4, "percents sum to ~100, got {sum}");
    }

    #[test]
    fn breakdown_percents_zero_total_returns_all_zeros() {
        let bd = FeeBreakdown {
            base_fee: 0,
            resource_fee: 0,
            inclusion_bid: 0,
            per_operation: 0,
        };
        let pct = bd.percent_of(0);
        assert_eq!(pct.base_fee_pct, 0.0);
        assert_eq!(pct.resource_fee_pct, 0.0);
        assert_eq!(pct.inclusion_bid_pct, 0.0);
        assert_eq!(pct.per_operation_pct, 0.0);
    }

    #[test]
    fn breakdown_percents_single_component_is_100() {
        let bd = FeeBreakdown {
            base_fee: 500,
            resource_fee: 0,
            inclusion_bid: 0,
            per_operation: 0,
        };
        let pct = bd.percent_of(500);
        assert_eq!(pct.base_fee_pct, 100.0);
        assert_eq!(pct.resource_fee_pct, 0.0);
    }

    // ── FeeEstimateReport ─────────────────────────────────────────────────────

    #[test]
    fn fee_estimate_report_build_round_trips_estimate() {
        let simulator = testnet();
        let profile = TransactionProfile::default();
        let report = FeeEstimateReport::build(&simulator, profile);
        // The report's estimate must equal a direct call.
        let direct = simulator.estimate(&profile);
        assert_eq!(report.estimate.total_stroops, direct.total_stroops);
        assert_eq!(report.estimate.breakdown.resource_fee, direct.breakdown.resource_fee);
    }

    #[test]
    fn fee_estimate_report_to_json_emits_valid_json_with_required_keys() {
        let simulator = testnet();
        let report = FeeEstimateReport::build(&simulator, TransactionProfile::default());
        let json = report.to_json().expect("to_json must not fail");
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

        // Top-level keys.
        assert!(v["profile"].is_object(), "profile key must be an object");
        assert!(v["estimate"].is_object(), "estimate key must be an object");
        assert!(v["bump_ladder"].is_array(), "bump_ladder key must be an array");

        // Breakdown sub-keys.
        let bd = &v["estimate"]["breakdown"];
        for key in ["base_fee", "resource_fee", "inclusion_bid", "per_operation"] {
            assert!(bd[key]["stroops"].is_number(), "{key}.stroops must be a number");
            assert!(bd[key]["xlm"].is_string(), "{key}.xlm must be a string");
            assert!(bd[key]["pct"].is_number(), "{key}.pct must be a number");
        }
        assert!(bd["inclusion_bid"]["bid_ledgers"].is_number(), "bid_ledgers must be present");

        // total_xlm must look like an XLM string.
        let xlm = v["estimate"]["total_xlm"].as_str().unwrap_or("");
        assert!(xlm.ends_with(" XLM"), "total_xlm must end with ' XLM', got '{xlm}'");
    }

    #[test]
    fn fee_estimate_report_to_json_bump_ladder_entries_are_well_formed() {
        let simulator = testnet();
        let report = FeeEstimateReport::build(&simulator, TransactionProfile::default());
        let json = report.to_json().expect("to_json must not fail");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let ladder = v["bump_ladder"].as_array().unwrap();

        for (i, entry) in ladder.iter().enumerate() {
            assert_eq!(entry["attempt"].as_u64(), Some(i as u64 + 1), "attempt numbers are 1-indexed");
            assert!(entry["inner_stroops"].is_number(), "inner_stroops must be a number");
            assert!(entry["outer_stroops"].is_number(), "outer_stroops must be a number");
            assert!(entry["outer_xlm"].is_string(), "outer_xlm must be a string");
            assert!(entry["pct_over_signed"].is_number(), "pct_over_signed must be a number");
        }
    }

    #[test]
    fn fee_estimate_report_to_json_empty_ladder_when_at_cap() {
        let mut schedule = FeeSchedule::testnet_default();
        schedule.max_fee_stroops = 100; // below any realistic fee
        let simulator = GasSimulator::new(schedule);
        let report = FeeEstimateReport::build(&simulator, TransactionProfile::default());
        let json = report.to_json().expect("to_json must not fail");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Ladder may be empty when capped.
        assert!(v["bump_ladder"].is_array());
    }

    #[test]
    fn test_estimate_charges_base_fee_per_operation() {
        let simulator = testnet();
        let profile = TransactionProfile {
            operations: 2,
            instructions: 0,
            ledger_reads: 0,
            ledger_writes: 0,
            bid_ledgers: 0,
        };
        let estimate = simulator.estimate(&profile);
        assert_eq!(estimate.breakdown.base_fee, 200);
        assert_eq!(estimate.breakdown.per_operation, 200);
        assert_eq!(estimate.total_stroops, 400);
    }

    #[test]
    fn hostile_resource_profiles_saturate_instead_of_wrapping() {
        let estimate = testnet().estimate(&TransactionProfile {
            operations: u32::MAX,
            instructions: u32::MAX,
            ledger_reads: u32::MAX,
            ledger_writes: u32::MAX,
            bid_ledgers: u32::MAX,
        });
        assert_eq!(estimate.total_stroops, u32::MAX);
        assert_eq!(estimate.breakdown.resource_fee, u32::MAX);
    }

    #[test]
    fn test_fee_bump_scales_with_base_fee() {
        let simulator = testnet();
        let bump = simulator.fee_bump(1_000, 500, 200).unwrap();
        // ceil(1000 * 200 / 500) = 400
        assert_eq!(bump.outer_fee_stroops, 400);
        assert_eq!(bump.base_fee_stroops, 200);
        assert_eq!(bump.inner_fee_stroops, 1_000);
        assert_eq!(bump.fee_source_pays(), 400);
    }

    #[test]
    fn test_fee_bump_is_floored_at_base_fee() {
        let simulator = testnet();
        let bump = simulator.fee_bump(100, 1_000, 300).unwrap();
        assert_eq!(bump.outer_fee_stroops, 300);
    }

    #[test]
    fn test_fee_bump_respects_max_fee() {
        let mut schedule = FeeSchedule::testnet_default();
        schedule.max_fee_stroops = 1_000;
        let simulator = GasSimulator::new(schedule);
        let bump = simulator.fee_bump(10_000, 1_000, 900).unwrap();
        assert_eq!(bump.outer_fee_stroops, 1_000);
        assert!(!simulator.is_bumpable(1_000));
    }

    #[test]
    fn test_fee_bump_rejects_degenerate_input() {
        let simulator = testnet();
        assert!(simulator.fee_bump(0, 100, 100).is_err());
        assert!(simulator.fee_bump(100, 0, 100).is_err());
        assert!(simulator.fee_bump(100, 100, 0).is_err());
    }

    #[test]
    fn test_bump_ladder_escalates_by_percent() {
        let simulator = testnet();
        let ladder = simulator.bump_ladder(1_000);
        let fees: Vec<u32> = ladder.iter().map(|b| b.outer_fee_stroops).collect();
        assert_eq!(fees, vec![1_500, 2_250, 3_375]);
        assert!(ladder
            .iter()
            .all(|b| b.inner_fee_at_signing_stroops == 1_000));
        assert_eq!(ladder[0].percent_over_signed_fee(), 150);
        assert_eq!(ladder[2].percent_over_signed_fee(), 337);
    }

    #[test]
    fn test_bump_ladder_stops_at_max_fee() {
        let mut schedule = FeeSchedule::testnet_default();
        schedule.max_fee_stroops = 2_000;
        let simulator = GasSimulator::new(schedule);
        let fees: Vec<u32> = simulator
            .bump_ladder(1_000)
            .iter()
            .map(|b| b.outer_fee_stroops)
            .collect();
        assert_eq!(fees, vec![1_500, 2_000]);
    }

    #[test]
    fn bump_ladders_remain_bounded_for_extreme_fee_inputs() {
        for max_fee in [1, 100, 10_000, u32::MAX] {
            for start_fee in [0, 1, 100, u32::MAX] {
                for bump_percent in [0, 1, 50, u32::MAX] {
                    for max_bumps in [0, 1, 3, 32] {
                        let mut schedule = FeeSchedule::testnet_default();
                        schedule.max_fee_stroops = max_fee;
                        schedule.bump_percent = bump_percent;
                        schedule.max_bumps = max_bumps;
                        let ladder = GasSimulator::new(schedule).bump_ladder(start_fee);
                        let mut previous = start_fee.max(schedule.base_fee_stroops);

                        assert!(ladder.len() <= max_bumps as usize);
                        for bump in ladder {
                            assert!(bump.outer_fee_stroops <= max_fee);
                            assert!(bump.outer_fee_stroops > previous);
                            previous = bump.outer_fee_stroops;
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_bump_ladder_respects_max_bumps() {
        let mut schedule = FeeSchedule::testnet_default();
        schedule.max_bumps = 1;
        let simulator = GasSimulator::new(schedule);
        assert_eq!(simulator.bump_ladder(1_000).len(), 1);
    }

    #[test]
    fn test_bump_ladder_never_lowers_the_base_fee() {
        let mut schedule = FeeSchedule::testnet_default();
        schedule.bump_percent = 0;
        let simulator = GasSimulator::new(schedule);
        assert!(simulator.bump_ladder(10).is_empty());
    }

    #[test]
    fn test_format_stroops() {
        assert_eq!(format_stroops(1_008_300), "0.1008300 XLM");
        assert_eq!(format_stroops(10_000_000), "1.0000000 XLM");
        assert_eq!(format_stroops(0), "0.0000000 XLM");
    }
}

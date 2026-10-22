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

use std::collections::BTreeSet;

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
}

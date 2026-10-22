//! Bridge oracle confirmation quorum (issue #210).
//!
//! A bridge releases a transfer only once an m-of-n oracle set agrees on it.
//! Deciding that from a batch of confirmations looks like counting, but four
//! separate things can go wrong, and each one turns a quorum count into a bridge
//! drain:
//!
//! * **Duplicate signers.** One oracle that signs twice must not count twice,
//!   otherwise a single key can manufacture quorum alone.
//! * **Unknown signers.** A confirmation from an address outside the configured
//!   set is not a vote. It is ignored and reported, never counted and never a
//!   hard error: the batch usually comes from a relayer that has its own view of
//!   the set.
//! * **Stale or future-dated signatures.** A confirmation from a previous
//!   transfer attempt (or one dated after the ledger being evaluated) must not be
//!   reusable. Only confirmations inside `max_age_ledgers` of `current_ledger`
//!   count.
//! * **Equivocation.** If two different amounts each reach the threshold, the
//!   oracle set has contradicted itself. Releasing either one is arbitrary, so
//!   the verdict is [`QuorumVerdict::Equivocal`] and the transfer must not be
//!   released. This is also what a single oracle voting for two different
//!   amounts is treated as: that oracle's vote is discarded entirely rather than
//!   letting it push one side over the line.
//!
//! The result is a [`QuorumReport`] rather than a bare `bool`: an operator or a
//! relayer needs to know *how far* from quorum a batch is, what the largest
//! agreeing group is, and why confirmations were discarded.
//!
//! This module is pure and host-side: it evaluates a batch that a caller has
//! already fetched (from Horizon, an RPC indexer or the bridge contract's events).
//! It does not sign, verify signatures or submit anything, and it holds no state.

use std::collections::{BTreeMap, BTreeSet};

/// Largest oracle set this module will validate.
///
/// A bridge's set has to stay small enough to name and rotate by hand; 64 is the
/// same ceiling used by the contract-side quorum helpers and keeps every
/// confirmation in a single batch a human can audit.
pub const MAX_ORACLES: usize = 64;

/// An oracle set and the number of its members that must agree.
///
/// Construction is validation: a value of this type always has at least one
/// unique oracle and a threshold in `1..=n`, so [`OracleSet::evaluate`] never
/// has to reject its own configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleSet {
    oracles: Vec<String>,
    threshold: u32,
}

/// Why an [`OracleSet`] or a quorum configuration is unusable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OracleQuorumError {
    #[error("an oracle set needs at least one oracle")]
    EmptyOracleSet,
    #[error("oracle `{0}` appears more than once in the set")]
    DuplicateOracle(String),
    #[error("oracle set has {count} members, the maximum is {max}")]
    OracleSetTooLarge { count: usize, max: usize },
    #[error("threshold {threshold} is not in 1..={oracles}")]
    ThresholdOutOfRange { threshold: u32, oracles: u32 },
}

impl OracleSet {
    /// Validate `oracles` and `threshold`.
    ///
    /// Rejects an empty set, duplicates, more than [`MAX_ORACLES`] members, and a
    /// threshold outside `1..=n`. A threshold of zero would make an empty batch
    /// quorate; a threshold above `n` is unsatisfiable, which is a configuration
    /// bug worth failing at construction rather than at settlement time.
    pub fn new(
        oracles: impl IntoIterator<Item = String>,
        threshold: u32,
    ) -> Result<Self, OracleQuorumError> {
        let oracles: Vec<String> = oracles.into_iter().collect();
        if oracles.is_empty() {
            return Err(OracleQuorumError::EmptyOracleSet);
        }
        if oracles.len() > MAX_ORACLES {
            return Err(OracleQuorumError::OracleSetTooLarge {
                count: oracles.len(),
                max: MAX_ORACLES,
            });
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for oracle in &oracles {
            if !seen.insert(oracle.as_str()) {
                return Err(OracleQuorumError::DuplicateOracle(oracle.clone()));
            }
        }
        if threshold == 0 || threshold as usize > oracles.len() {
            return Err(OracleQuorumError::ThresholdOutOfRange {
                threshold,
                oracles: oracles.len() as u32,
            });
        }
        Ok(Self { oracles, threshold })
    }

    /// The oracle identifiers, in configuration order.
    pub fn oracles(&self) -> &[String] {
        &self.oracles
    }

    /// Confirmations required to release a transfer.
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Number of oracles in the set.
    pub fn len(&self) -> usize {
        self.oracles.len()
    }

    /// Whether the set is empty. Always `false` for a validated set; present for
    /// the `len`/`is_empty` convention.
    pub fn is_empty(&self) -> bool {
        self.oracles.is_empty()
    }

    /// Whether `oracle` is a member of this set.
    pub fn contains(&self, oracle: &str) -> bool {
        self.oracles.iter().any(|member| member == oracle)
    }

    /// Evaluate `confirmations` for `transfer_id` at `current_ledger`.
    ///
    /// Only confirmations whose `transfer_id` matches are considered. A
    /// confirmation counts when its oracle is in the set, its amount agrees with
    /// that oracle's other confirmation (if any), and its ledger is not in the
    /// future and no more than `max_age_ledgers` behind `current_ledger`.
    ///
    /// The verdict is:
    ///
    /// * [`QuorumVerdict::Confirmed`] when exactly one amount reaches the
    ///   threshold;
    /// * [`QuorumVerdict::Equivocal`] when two or more amounts do — including the
    ///   case where one oracle voted for two different amounts, whose votes are
    ///   discarded;
    /// * [`QuorumVerdict::Pending`] otherwise, carrying the largest agreeing
    ///   group and how many more confirmations it needs.
    ///
    /// `max_age_ledgers` is a window, not a policy: the caller decides how much
    /// reordering and relayer lag to accept. `0` means only confirmations from
    /// `current_ledger` itself count.
    pub fn evaluate(
        &self,
        transfer_id: &str,
        confirmations: &[OracleConfirmation],
        current_ledger: u32,
        max_age_ledgers: u32,
    ) -> QuorumReport {
        let mut report = QuorumReport::default();
        let mut votes: BTreeMap<&str, i128> = BTreeMap::new();
        let mut conflicted: BTreeSet<&str> = BTreeSet::new();

        for confirmation in confirmations {
            if confirmation.transfer_id != transfer_id {
                continue;
            }
            let oracle = confirmation.oracle.as_str();
            if !self.contains(oracle) {
                report.ignored_unknown += 1;
                continue;
            }
            let stale = confirmation.ledger > current_ledger
                || current_ledger - confirmation.ledger > max_age_ledgers;
            if stale {
                report.ignored_stale += 1;
                continue;
            }
            if conflicted.contains(oracle) {
                report.ignored_conflicting += 1;
                continue;
            }
            match votes.get(oracle) {
                None => {
                    votes.insert(oracle, confirmation.amount);
                }
                Some(previous) if *previous == confirmation.amount => {
                    report.ignored_duplicate += 1;
                }
                Some(_) => {
                    // One oracle, two amounts: drop its vote entirely. Counting
                    // either one would let a single misbehaving key decide which
                    // amount the bridge releases.
                    votes.remove(oracle);
                    conflicted.insert(oracle);
                    report.ignored_conflicting += 1;
                }
            }
        }

        report.accepted = votes.len() as u32;
        let mut groups: BTreeMap<i128, u32> = BTreeMap::new();
        for amount in votes.values() {
            *groups.entry(*amount).or_insert(0) += 1;
        }
        let mut groups: Vec<(i128, u32)> = groups.into_iter().collect();
        // Largest group first; equal sizes break by amount so the report is
        // deterministic across runs and machines.
        groups.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));

        let quorate: Vec<&(i128, u32)> = groups
            .iter()
            .filter(|(_, signers)| *signers >= self.threshold)
            .collect();

        report.verdict = if quorate.len() >= 2 {
            QuorumVerdict::Equivocal {
                first_amount: quorate[0].0,
                first_signers: quorate[0].1,
                second_amount: quorate[1].0,
                second_signers: quorate[1].1,
            }
        } else if let Some((amount, signers)) = quorate.first() {
            QuorumVerdict::Confirmed {
                amount: *amount,
                signers: *signers,
            }
        } else {
            let (best_amount, signers) = match groups.first() {
                Some((amount, signers)) => (Some(*amount), *signers),
                None => (None, 0),
            };
            QuorumVerdict::Pending {
                best_amount,
                signers,
                required: self.threshold,
                missing: self.threshold.saturating_sub(signers),
            }
        };

        report
    }
}

/// One oracle's statement that `transfer_id` moved `amount` at `ledger`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleConfirmation {
    pub oracle: String,
    pub transfer_id: String,
    pub amount: i128,
    pub ledger: u32,
}

/// What the confirmations for one transfer amount to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumVerdict {
    /// Exactly one amount reached the threshold.
    Confirmed { amount: i128, signers: u32 },
    /// No amount reached the threshold; the largest group is reported.
    Pending {
        best_amount: Option<i128>,
        signers: u32,
        required: u32,
        missing: u32,
    },
    /// Two or more different amounts each reached the threshold. Releasing
    /// either would be arbitrary, so neither may be released.
    Equivocal {
        first_amount: i128,
        first_signers: u32,
        second_amount: i128,
        second_signers: u32,
    },
}

impl QuorumVerdict {
    /// The amount to release, if exactly one amount reached quorum.
    pub fn confirmed_amount(&self) -> Option<i128> {
        match self {
            Self::Confirmed { amount, .. } => Some(*amount),
            _ => None,
        }
    }

    /// Whether the transfer may be released.
    pub fn is_confirmed(&self) -> bool {
        matches!(self, Self::Confirmed { .. })
    }
}

/// A [`QuorumVerdict`] plus the accounting behind it.
///
/// The discarded counts are deliberate: a batch that loses confirmations to
/// unknown or stale entries looks identical to a batch that simply received too
/// few, and an operator needs to tell those apart.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuorumReport {
    pub verdict: QuorumVerdict,
    /// Distinct, in-set oracles that contributed a vote to the tally.
    pub accepted: u32,
    /// Confirmations from addresses outside the set.
    pub ignored_unknown: u32,
    /// Confirmations from the future or older than the age window.
    pub ignored_stale: u32,
    /// Repeated confirmations from the same oracle for the same amount.
    pub ignored_duplicate: u32,
    /// Votes discarded because the same oracle gave two different amounts.
    pub ignored_conflicting: u32,
}

impl Default for QuorumVerdict {
    fn default() -> Self {
        Self::Pending {
            best_amount: None,
            signers: 0,
            required: 0,
            missing: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oracle_set(threshold: u32) -> OracleSet {
        OracleSet::new(
            vec![
                "GORACLEA".to_string(),
                "GORACLEB".to_string(),
                "GORACLEC".to_string(),
                "GORACLED".to_string(),
                "GORACLEE".to_string(),
            ],
            threshold,
        )
        .expect("valid test set")
    }

    fn confirmation(oracle: &str, amount: i128) -> OracleConfirmation {
        OracleConfirmation {
            oracle: oracle.to_string(),
            transfer_id: "transfer-1".to_string(),
            amount,
            ledger: 100,
        }
    }

    #[test]
    fn rejects_an_empty_set() {
        assert_eq!(
            OracleSet::new(Vec::new(), 1),
            Err(OracleQuorumError::EmptyOracleSet)
        );
    }

    #[test]
    fn rejects_duplicate_oracles() {
        let result = OracleSet::new(vec!["GORACLEA".to_string(), "GORACLEA".to_string()], 1);
        assert_eq!(
            result,
            Err(OracleQuorumError::DuplicateOracle("GORACLEA".to_string()))
        );
    }

    #[test]
    fn rejects_a_threshold_outside_the_set() {
        assert_eq!(
            OracleSet::new(vec!["GORACLEA".to_string()], 0),
            Err(OracleQuorumError::ThresholdOutOfRange {
                threshold: 0,
                oracles: 1
            })
        );
        assert_eq!(
            OracleSet::new(vec!["GORACLEA".to_string()], 2),
            Err(OracleQuorumError::ThresholdOutOfRange {
                threshold: 2,
                oracles: 1
            })
        );
    }

    #[test]
    fn rejects_an_oversized_set() {
        let oracles = (0..=MAX_ORACLES)
            .map(|index| format!("GORACLE{index}"))
            .collect::<Vec<_>>();
        assert_eq!(
            OracleSet::new(oracles, 1),
            Err(OracleQuorumError::OracleSetTooLarge {
                count: MAX_ORACLES + 1,
                max: MAX_ORACLES,
            })
        );
    }

    #[test]
    fn confirms_at_exactly_the_threshold() {
        let set = oracle_set(3);
        let batch = [
            confirmation("GORACLEA", 500),
            confirmation("GORACLEB", 500),
            confirmation("GORACLEC", 500),
        ];

        let report = set.evaluate("transfer-1", &batch, 100, 10);
        assert_eq!(
            report.verdict,
            QuorumVerdict::Confirmed {
                amount: 500,
                signers: 3
            }
        );
        assert_eq!(report.accepted, 3);
        assert!(report.verdict.is_confirmed());
        assert_eq!(report.verdict.confirmed_amount(), Some(500));
    }

    #[test]
    fn one_below_the_threshold_is_pending_with_a_missing_count() {
        let set = oracle_set(3);
        let batch = [confirmation("GORACLEA", 500), confirmation("GORACLEB", 500)];

        let report = set.evaluate("transfer-1", &batch, 100, 10);
        assert_eq!(
            report.verdict,
            QuorumVerdict::Pending {
                best_amount: Some(500),
                signers: 2,
                required: 3,
                missing: 1,
            }
        );
        assert!(!report.verdict.is_confirmed());
    }

    #[test]
    fn an_empty_batch_reports_no_best_amount() {
        let report = oracle_set(2).evaluate("transfer-1", &[], 100, 10);
        assert_eq!(
            report.verdict,
            QuorumVerdict::Pending {
                best_amount: None,
                signers: 0,
                required: 2,
                missing: 2,
            }
        );
        assert_eq!(report.accepted, 0);
    }

    #[test]
    fn a_single_oracle_cannot_make_quorum_by_signing_twice() {
        let set = oracle_set(2);
        let batch = [
            confirmation("GORACLEA", 500),
            confirmation("GORACLEA", 500),
            confirmation("GORACLEA", 500),
        ];

        let report = set.evaluate("transfer-1", &batch, 100, 10);
        assert_eq!(report.accepted, 1);
        assert_eq!(report.ignored_duplicate, 2);
        assert_eq!(
            report.verdict,
            QuorumVerdict::Pending {
                best_amount: Some(500),
                signers: 1,
                required: 2,
                missing: 1,
            }
        );
    }

    #[test]
    fn unknown_oracles_are_ignored_and_counted() {
        let set = oracle_set(2);
        let batch = [
            confirmation("GORACLEA", 500),
            confirmation("GSTRANGER", 500),
            confirmation("GSTRANGER2", 500),
        ];

        let report = set.evaluate("transfer-1", &batch, 100, 10);
        assert_eq!(report.accepted, 1);
        assert_eq!(report.ignored_unknown, 2);
        assert!(!report.verdict.is_confirmed());
    }

    #[test]
    fn stale_and_future_confirmations_do_not_count() {
        let set = oracle_set(2);
        let batch = [
            OracleConfirmation {
                oracle: "GORACLEA".to_string(),
                transfer_id: "transfer-1".to_string(),
                amount: 500,
                ledger: 100,
            },
            OracleConfirmation {
                oracle: "GORACLEB".to_string(),
                transfer_id: "transfer-1".to_string(),
                amount: 500,
                ledger: 89, // 11 ledgers old, window is 10
            },
            OracleConfirmation {
                oracle: "GORACLEC".to_string(),
                transfer_id: "transfer-1".to_string(),
                amount: 500,
                ledger: 101, // dated after the ledger being evaluated
            },
            OracleConfirmation {
                oracle: "GORACLED".to_string(),
                transfer_id: "transfer-1".to_string(),
                amount: 500,
                ledger: 90, // exactly at the window edge
            },
        ];

        let report = set.evaluate("transfer-1", &batch, 100, 10);
        assert_eq!(report.accepted, 2, "the edge confirmation still counts");
        assert_eq!(report.ignored_stale, 2);
        assert_eq!(
            report.verdict,
            QuorumVerdict::Confirmed {
                amount: 500,
                signers: 2
            }
        );
    }

    #[test]
    fn confirmations_for_another_transfer_are_skipped() {
        let set = oracle_set(1);
        let batch = [OracleConfirmation {
            oracle: "GORACLEA".to_string(),
            transfer_id: "transfer-2".to_string(),
            amount: 500,
            ledger: 100,
        }];

        let report = set.evaluate("transfer-1", &batch, 100, 10);
        assert_eq!(report.accepted, 0);
        assert_eq!(report.ignored_unknown, 0);
        assert_eq!(
            report.verdict,
            QuorumVerdict::Pending {
                best_amount: None,
                signers: 0,
                required: 1,
                missing: 1,
            }
        );
    }

    #[test]
    fn two_quorate_amounts_are_equivocal() {
        let set = oracle_set(2);
        let batch = [
            confirmation("GORACLEA", 500),
            confirmation("GORACLEB", 500),
            confirmation("GORACLEC", 700),
            confirmation("GORACLED", 700),
        ];

        let report = set.evaluate("transfer-1", &batch, 100, 10);
        assert_eq!(
            report.verdict,
            QuorumVerdict::Equivocal {
                first_amount: 500,
                first_signers: 2,
                second_amount: 700,
                second_signers: 2,
            }
        );
        assert!(!report.verdict.is_confirmed());
    }

    #[test]
    fn one_oracle_answering_two_amounts_has_both_votes_discarded() {
        let set = oracle_set(2);
        let batch = [
            confirmation("GORACLEA", 500),
            confirmation("GORACLEB", 500),
            confirmation("GORACLEA", 700),
        ];

        let report = set.evaluate("transfer-1", &batch, 100, 10);
        assert_eq!(report.accepted, 1, "only GORACLEB's vote survives");
        assert_eq!(report.ignored_conflicting, 1);
        assert_eq!(
            report.verdict,
            QuorumVerdict::Pending {
                best_amount: Some(500),
                signers: 1,
                required: 2,
                missing: 1,
            }
        );

        // A later confirmation from the conflicted oracle is still discarded.
        let mut extended = batch.to_vec();
        extended.push(confirmation("GORACLEA", 500));
        let report = set.evaluate("transfer-1", &extended, 100, 10);
        assert_eq!(report.accepted, 1);
        assert_eq!(report.ignored_conflicting, 2);
        assert!(!report.verdict.is_confirmed());
    }

    #[test]
    fn a_larger_set_counts_only_distinct_fresh_members() {
        let set = oracle_set(3);
        let batch = [
            confirmation("GORACLEA", 500),
            confirmation("GORACLEB", 500),
            confirmation("GORACLEC", 500),
            confirmation("GORACLED", 700),
            confirmation("GORACLEE", 500),
            confirmation("GSTRANGER", 500),
            OracleConfirmation {
                oracle: "GORACLEA".to_string(),
                transfer_id: "transfer-1".to_string(),
                amount: 500,
                ledger: 1,
            },
        ];

        let report = set.evaluate("transfer-1", &batch, 100, 10);
        assert_eq!(report.accepted, 5);
        assert_eq!(report.ignored_unknown, 1);
        assert_eq!(report.ignored_stale, 1);
        assert_eq!(
            report.verdict,
            QuorumVerdict::Confirmed {
                amount: 500,
                signers: 4
            }
        );
    }
}

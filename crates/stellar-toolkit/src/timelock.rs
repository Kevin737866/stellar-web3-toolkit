//! Timelock delay minimums (issue #208) and proposal execution gate (issue #451).
//!
//! The bridge pause guard (`contracts/bridge-pause-guard`) enforces its delays in
//! `initialize`, so a deployed guard can never be configured with a pause that
//! lands instantly. The gap this module closes is the one before that: the
//! deployer, the release config and the incident runbook all have to agree with
//! the contract, and a mismatch is discovered today only when `initialize`
//! traps on-chain.
//!
//! [`TimelockPolicy`] is that agreement as a type. It mirrors the contract's
//! bounds exactly ([`MIN_PAUSE_DELAY`], [`MAX_PAUSE_DELAY`], and the rule that a
//! resume may never be faster than the pause), and its [`DelayKind`] arithmetic
//! mirrors the contract's `requested_ledger + delay` clock. `verify invariants`
//! runs it as an automated check on every push, so a policy that would produce a
//! pause in its own request ledger fails in CI rather than on mainnet.
//!
//! Keeping two copies of the numbers is the cost of not linking a `no_std`
//! contract into the tooling crate. The constants are therefore asserted in both
//! places and any change has to be made in both — see `docs/BRIDGE_PAUSE_TIMELOCK.md`.

/// Shortest pause delay the bridge accepts. `0` would let a pause land in the
/// ledger it was requested in, which is the silent freeze the timelock prevents.
pub const MIN_PAUSE_DELAY: u32 = 1;

/// Longest accepted delay: 17 280 ledgers, about one day at 5 seconds each.
/// Past this a pause stops being incident response and becomes a hostage.
pub const MAX_PAUSE_DELAY: u32 = 17_280;

/// Which direction of the pause state machine a delay applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelayKind {
    /// Guardian-requested pause; the fast direction.
    Pause,
    /// Admin-requested resume; must be at least as slow as the pause.
    Resume,
}

impl DelayKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pause => "pause",
            Self::Resume => "resume",
        }
    }
}

/// A pause/resume delay pair that a bridge can be initialised with.
///
/// Construction is validation: a value of this type always satisfies every
/// bound the contract enforces, so callers cannot forget the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimelockPolicy {
    pause_delay: u32,
    unpause_delay: u32,
}

/// A delay configuration or execution attempt the bridge or governance timelock rejects.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TimelockError {
    #[error("pause delay {configured} is outside [{MIN_PAUSE_DELAY}, {MAX_PAUSE_DELAY}] ledgers")]
    PauseDelayOutOfRange { configured: u32 },
    #[error("resume delay {configured} is outside [{MIN_PAUSE_DELAY}, {MAX_PAUSE_DELAY}] ledgers")]
    ResumeDelayOutOfRange { configured: u32 },
    #[error(
        "resume delay {unpause} is faster than the pause delay {pause}; a pause that resumes \
         faster than it engages is decoration"
    )]
    ResumeFasterThanPause { pause: u32, unpause: u32 },
    #[error(
        "proposal timelock has not expired at ledger {current_ledger} (effective at ledger {effective_ledger})"
    )]
    TimelockNotExpired {
        current_ledger: u32,
        effective_ledger: u32,
    },
    #[error("required quorum must be strictly positive")]
    ZeroQuorumRequirement,
    #[error("role {role:?} is not authorized to execute governance action {action:?}")]
    UnauthorizedGovernanceAction {
        role: GovernanceRole,
        action: GovernanceAction,
    },
    #[error("cannot propose bridge resume while pause timelock is active")]
    ResumeWhilePauseTimelockActive,
    #[error("bridge is already unpaused; cannot propose resume")]
    BridgeAlreadyUnpaused,
    #[error("guardian quorum not reached: received {votes} votes, required {required}")]
    InsufficientGuardianQuorum { votes: u32, required: u32 },
    #[error("guardian threshold {threshold} exceeds active guardian count {count}")]
    ThresholdExceedsGuardianCount { threshold: u32, count: u32 },
}

impl TimelockPolicy {
    /// Validate a `(pause_delay, unpause_delay)` pair against the contract's
    /// install rules.
    pub fn new(pause_delay: u32, unpause_delay: u32) -> Result<Self, TimelockError> {
        if !(MIN_PAUSE_DELAY..=MAX_PAUSE_DELAY).contains(&pause_delay) {
            return Err(TimelockError::PauseDelayOutOfRange {
                configured: pause_delay,
            });
        }
        if !(MIN_PAUSE_DELAY..=MAX_PAUSE_DELAY).contains(&unpause_delay) {
            return Err(TimelockError::ResumeDelayOutOfRange {
                configured: unpause_delay,
            });
        }
        if unpause_delay < pause_delay {
            return Err(TimelockError::ResumeFasterThanPause {
                pause: pause_delay,
                unpause: unpause_delay,
            });
        }
        Ok(Self {
            pause_delay,
            unpause_delay,
        })
    }

    pub fn pause_delay(self) -> u32 {
        self.pause_delay
    }

    pub fn unpause_delay(self) -> u32 {
        self.unpause_delay
    }

    pub fn delay(self, kind: DelayKind) -> u32 {
        match kind {
            DelayKind::Pause => self.pause_delay,
            DelayKind::Resume => self.unpause_delay,
        }
    }

    /// Ledger a request made in `requested_ledger` becomes actionable on.
    ///
    /// Saturating rather than wrapping: near the end of the ledger range a
    /// request must become *never* actionable, not actionable immediately.
    pub fn effective_ledger(self, requested_ledger: u32, kind: DelayKind) -> u32 {
        requested_ledger.saturating_add(self.delay(kind))
    }

    /// Whether a request made in `requested_ledger` may be activated at
    /// `current_ledger`.
    pub fn is_effective(self, requested_ledger: u32, kind: DelayKind, current_ledger: u32) -> bool {
        current_ledger >= self.effective_ledger(requested_ledger, kind)
    }

    /// Enforce that a proposal or scheduled action is not executed before its
    /// timelock expires (issue #451).
    ///
    /// Returns the `effective_ledger` when `current_ledger >= effective_ledger`,
    /// or [`TimelockError::TimelockNotExpired`] if invoked early.
    pub fn verify_execution(
        self,
        requested_ledger: u32,
        kind: DelayKind,
        current_ledger: u32,
    ) -> Result<u32, TimelockError> {
        let effective = self.effective_ledger(requested_ledger, kind);
        if current_ledger < effective {
            return Err(TimelockError::TimelockNotExpired {
                current_ledger,
                effective_ledger: effective,
            });
        }
        Ok(effective)
    }
}


/// Snapshot of vote totals and quorum progress returned by proposal queries (issue #456).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposalQuorumProgress {
    pub votes_for: u128,
    pub votes_against: u128,
    pub votes_abstain: u128,
    pub total_cast: u128,
    pub required_quorum: u128,
    pub quorum_progress_bps: u32,
    pub quorum_reached: bool,
}

impl ProposalQuorumProgress {
    /// Compute vote totals and quorum progress for a proposal query (issue #456).
    pub fn compute(
        votes_for: u128,
        votes_against: u128,
        votes_abstain: u128,
        required_quorum: u128,
    ) -> Result<Self, TimelockError> {
        if required_quorum == 0 {
            return Err(TimelockError::ZeroQuorumRequirement);
        }
        let total_cast = votes_for
            .saturating_add(votes_against)
            .saturating_add(votes_abstain);
        let raw_bps = total_cast.saturating_mul(10_000) / required_quorum;
        let quorum_progress_bps = raw_bps.min(10_000) as u32;
        Ok(Self {
            votes_for,
            votes_against,
            votes_abstain,
            total_cast,
            required_quorum,
            quorum_progress_bps,
            quorum_reached: total_cast >= required_quorum,
        })
    }
}

/// Roles recognized by the governance upgrade and emergency veto model (issue #457).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceRole {
    Voter,
    EmergencyGuardian,
    TimelockAdmin,
}

/// Privileged governance operations subject to permission checks (issue #457).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceAction {
    EmergencyVeto,
    ExecuteUpgrade,
}

/// Verify whether `role` is permitted to invoke `action` (issue #457).
pub fn authorize_governance_action(
    role: GovernanceRole,
    action: GovernanceAction,
) -> Result<(), TimelockError> {
    match (role, action) {
        (GovernanceRole::EmergencyGuardian | GovernanceRole::TimelockAdmin, GovernanceAction::EmergencyVeto) => Ok(()),
        (GovernanceRole::TimelockAdmin, GovernanceAction::ExecuteUpgrade) => Ok(()),
        _ => Err(TimelockError::UnauthorizedGovernanceAction { role, action }),
    }
}



// ============================================================================
// Bridge Pause Governance, Quorum, and Audit Types (Issues #430-#436)
// ============================================================================

/// Snapshot of the bridge pause status including active proposal ID and deadlines (issues #431, #436).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgePauseStatus {
    pub is_paused: bool,
    /// Active proposal ID under evaluation (#436).
    pub active_proposal_id: Option<u64>,
    pub current_ledger: u32,
    /// Ledger at which the pending change becomes effective (#431).
    pub effective_deadline_ledger: Option<u32>,
    /// Remaining ledgers until effective execution (#431).
    pub remaining_ledgers: Option<u32>,
    pub change_direction: Option<DelayKind>,
    pub guardian_quorum_reached: bool,
}

/// Guardian quorum configuration and threshold management (#430, #435).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardianQuorum {
    pub active_guardians: u32,
    pub required_threshold: u32,
}

impl GuardianQuorum {
    /// Create and validate a guardian quorum threshold (#430, #435).
    pub fn new(active_guardians: u32, required_threshold: u32) -> Result<Self, TimelockError> {
        if required_threshold == 0 {
            return Err(TimelockError::ZeroQuorumRequirement);
        }
        if required_threshold > active_guardians {
            return Err(TimelockError::ThresholdExceedsGuardianCount {
                threshold: required_threshold,
                count: active_guardians,
            });
        }
        Ok(Self {
            active_guardians,
            required_threshold,
        })
    }

    /// Check whether a given vote count reaches quorum.
    pub fn is_quorum_reached(&self, votes: u32) -> bool {
        votes >= self.required_threshold
    }

    /// Validate guardian quorum before accepting pause actions (#430).
    pub fn validate_quorum(&self, votes: u32) -> Result<(), TimelockError> {
        if !self.is_quorum_reached(votes) {
            return Err(TimelockError::InsufficientGuardianQuorum {
                votes,
                required: self.required_threshold,
            });
        }
        Ok(())
    }
}

/// Audit event stream entries for bridge pause and resume lifecycle actions (#432).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgePauseAuditEvent {
    PauseProposed {
        proposal_id: u64,
        proposer: String,
        effective_ledger: u32,
        reason: String,
    },
    PauseActivated {
        proposal_id: u64,
        activated_ledger: u32,
    },
    ResumeProposed {
        proposal_id: u64,
        proposer: String,
        effective_ledger: u32,
    },
    ResumeActivated {
        proposal_id: u64,
        activated_ledger: u32,
    },
    ProposalCancelled {
        proposal_id: u64,
        cancelled_ledger: u32,
        cancelled_by: String,
    },
}

/// Compute observable bridge pause status reporting active proposal ID, timelock deadlines, and remaining ledgers (#431, #436).
pub fn compute_bridge_pause_status(
    is_paused: bool,
    pending: Option<(u64, DelayKind, u32)>, // (proposal_id, kind, requested_ledger)
    current_ledger: u32,
    policy: TimelockPolicy,
    quorum: Option<GuardianQuorum>,
    guardian_votes: u32,
) -> BridgePauseStatus {
    let (active_proposal_id, change_direction, effective_deadline_ledger, remaining_ledgers) =
        match pending {
            Some((id, kind, req_ledger)) => {
                let deadline = policy.effective_ledger(req_ledger, kind);
                let remaining = deadline.saturating_sub(current_ledger);
                (Some(id), Some(kind), Some(deadline), Some(remaining))
            }
            None => (None, None, None, None),
        };

    let guardian_quorum_reached = match quorum {
        Some(q) => q.is_quorum_reached(guardian_votes),
        None => true,
    };

    BridgePauseStatus {
        is_paused,
        active_proposal_id,
        current_ledger,
        effective_deadline_ledger,
        remaining_ledgers,
        change_direction,
        guardian_quorum_reached,
    }
}

/// Validate that a bridge resume proposal is allowed (#434).
///
/// Rejects resume proposals while a pause proposal timelock is actively pending.
pub fn validate_bridge_resume_proposal(
    is_paused: bool,
    pause_pending: bool,
) -> Result<(), TimelockError> {
    if pause_pending {
        return Err(TimelockError::ResumeWhilePauseTimelockActive);
    }
    if !is_paused {
        return Err(TimelockError::BridgeAlreadyUnpaused);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_constants_match_the_bridge_contract() {
        // `contracts/bridge-pause-guard/src/lib.rs` carries the same two numbers.
        // If one side moves, this test is the reminder to move the other.
        assert_eq!(MIN_PAUSE_DELAY, 1);
        assert_eq!(MAX_PAUSE_DELAY, 17_280);
    }

    #[test]
    fn in_range_delays_are_accepted() {
        for (pause, unpause) in [
            (MIN_PAUSE_DELAY, MIN_PAUSE_DELAY),
            (MIN_PAUSE_DELAY, MAX_PAUSE_DELAY),
            (10, 10),
            (10, 20),
            (MAX_PAUSE_DELAY, MAX_PAUSE_DELAY),
        ] {
            let policy = TimelockPolicy::new(pause, unpause).expect("valid pair");
            assert_eq!(policy.pause_delay(), pause);
            assert_eq!(policy.unpause_delay(), unpause);
        }
    }

    #[test]
    fn a_zero_pause_delay_is_refused() {
        assert_eq!(
            TimelockPolicy::new(0, 1),
            Err(TimelockError::PauseDelayOutOfRange { configured: 0 })
        );
    }

    #[test]
    fn delays_past_the_ceiling_are_refused() {
        assert_eq!(
            TimelockPolicy::new(MAX_PAUSE_DELAY + 1, MAX_PAUSE_DELAY + 1),
            Err(TimelockError::PauseDelayOutOfRange {
                configured: MAX_PAUSE_DELAY + 1
            })
        );
        assert_eq!(
            TimelockPolicy::new(1, MAX_PAUSE_DELAY + 1),
            Err(TimelockError::ResumeDelayOutOfRange {
                configured: MAX_PAUSE_DELAY + 1
            })
        );
        assert_eq!(
            TimelockPolicy::new(1, 0),
            Err(TimelockError::ResumeDelayOutOfRange { configured: 0 })
        );
    }

    #[test]
    fn a_fast_resume_is_refused() {
        assert_eq!(
            TimelockPolicy::new(100, 99),
            Err(TimelockError::ResumeFasterThanPause {
                pause: 100,
                unpause: 99
            })
        );
    }

    #[test]
    fn a_pause_never_lands_in_its_request_ledger() {
        for pause in [MIN_PAUSE_DELAY, 2, 100, MAX_PAUSE_DELAY] {
            let policy = TimelockPolicy::new(pause, pause).unwrap();
            for requested in [0u32, 1, 1_000, u32::MAX / 2] {
                for kind in [DelayKind::Pause, DelayKind::Resume] {
                    let effective = policy.effective_ledger(requested, kind);
                    assert!(effective > requested, "{kind:?} landed at {effective}");
                    assert!(!policy.is_effective(requested, kind, requested));
                    assert!(!policy.is_effective(requested, kind, effective - 1));
                    assert!(policy.is_effective(requested, kind, effective));
                }
            }
        }
    }

    #[test]
    fn the_effective_ledger_saturates_instead_of_wrapping() {
        let policy = TimelockPolicy::new(MAX_PAUSE_DELAY, MAX_PAUSE_DELAY).unwrap();
        assert_eq!(
            policy.effective_ledger(u32::MAX - 1, DelayKind::Pause),
            u32::MAX
        );
        assert_eq!(
            policy.effective_ledger(u32::MAX, DelayKind::Pause),
            u32::MAX
        );
    }

    #[test]
    fn accepted_policies_always_resume_at_least_as_slowly_as_they_pause() {
        for pause in 0..=MAX_PAUSE_DELAY + 2 {
            for unpause in [pause, pause + 1, pause.saturating_sub(1)] {
                if let Ok(policy) = TimelockPolicy::new(pause, unpause) {
                    assert!(policy.unpause_delay() >= policy.pause_delay());
                }
            }
        }
    }

    #[test]
    fn execution_before_timelock_expiry_is_rejected() {
        let policy = TimelockPolicy::new(25, 50).unwrap();
        let requested = 1_000u32;

        assert_eq!(
            policy.verify_execution(requested, DelayKind::Pause, 1_000),
            Err(TimelockError::TimelockNotExpired {
                current_ledger: 1_000,
                effective_ledger: 1_025,
            })
        );
        assert_eq!(
            policy.verify_execution(requested, DelayKind::Pause, 1_024),
            Err(TimelockError::TimelockNotExpired {
                current_ledger: 1_024,
                effective_ledger: 1_025,
            })
        );
        assert_eq!(
            policy.verify_execution(requested, DelayKind::Pause, 1_025),
            Ok(1_025)
        );
        assert_eq!(
            policy.verify_execution(requested, DelayKind::Resume, 1_049),
            Err(TimelockError::TimelockNotExpired {
                current_ledger: 1_049,
                effective_ledger: 1_050,
            })
        );
        assert_eq!(
            policy.verify_execution(requested, DelayKind::Resume, 1_050),
            Ok(1_050)
        );
    }

    #[test]
    fn bridge_pause_status_reports_proposal_id_and_deadlines() {
        let policy = TimelockPolicy::new(10, 20).unwrap();
        let status = compute_bridge_pause_status(
            false,
            Some((42, DelayKind::Pause, 1_000)),
            1_004,
            policy,
            Some(GuardianQuorum::new(5, 3).unwrap()),
            3,
        );

        assert_eq!(status.active_proposal_id, Some(42));
        assert_eq!(status.effective_deadline_ledger, Some(1_010));
        assert_eq!(status.remaining_ledgers, Some(6));
        assert_eq!(status.change_direction, Some(DelayKind::Pause));
        assert!(status.guardian_quorum_reached);
    }

    #[test]
    fn bridge_pause_status_when_no_pending_proposal() {
        let policy = TimelockPolicy::new(10, 20).unwrap();
        let status = compute_bridge_pause_status(true, None, 1_050, policy, None, 0);

        assert_eq!(status.active_proposal_id, None);
        assert_eq!(status.effective_deadline_ledger, None);
        assert_eq!(status.remaining_ledgers, None);
        assert_eq!(status.change_direction, None);
        assert!(status.is_paused);
        assert!(status.guardian_quorum_reached);
    }

    #[test]
    fn guardian_quorum_validation_and_threshold_boundaries() {
        // Valid quorum threshold
        let quorum = GuardianQuorum::new(5, 3).unwrap();
        assert!(quorum.is_quorum_reached(3));
        assert!(quorum.is_quorum_reached(4));
        assert!(!quorum.is_quorum_reached(2));
        assert!(quorum.validate_quorum(3).is_ok());
        assert_eq!(
            quorum.validate_quorum(2),
            Err(TimelockError::InsufficientGuardianQuorum { votes: 2, required: 3 })
        );

        // Boundary: 0 threshold is refused
        assert_eq!(
            GuardianQuorum::new(5, 0),
            Err(TimelockError::ZeroQuorumRequirement)
        );

        // Boundary: threshold > guardian count is refused
        assert_eq!(
            GuardianQuorum::new(5, 6),
            Err(TimelockError::ThresholdExceedsGuardianCount { threshold: 6, count: 5 })
        );

        // Boundary: unanimous threshold (threshold == count) is accepted
        assert!(GuardianQuorum::new(5, 5).is_ok());
    }

    #[test]
    fn resume_proposal_rejected_when_pause_timelock_is_active() {
        // Pause is pending -> resume must be rejected
        assert_eq!(
            validate_bridge_resume_proposal(false, true),
            Err(TimelockError::ResumeWhilePauseTimelockActive)
        );

        // Bridge not paused and no pause pending -> rejected
        assert_eq!(
            validate_bridge_resume_proposal(false, false),
            Err(TimelockError::BridgeAlreadyUnpaused)
        );

        // Bridge paused and no pause pending -> allowed
        assert!(validate_bridge_resume_proposal(true, false).is_ok());
    }

    #[test]
    fn bridge_pause_audit_event_stream_variants() {
        let proposed = BridgePauseAuditEvent::PauseProposed {
            proposal_id: 101,
            proposer: "guardian_alpha".into(),
            effective_ledger: 500,
            reason: "Detected suspicious outflow anomaly".into(),
        };
        let activated = BridgePauseAuditEvent::PauseActivated {
            proposal_id: 101,
            activated_ledger: 500,
        };
        let resume_proposed = BridgePauseAuditEvent::ResumeProposed {
            proposal_id: 102,
            proposer: "admin_beta".into(),
            effective_ledger: 550,
        };
        let cancelled = BridgePauseAuditEvent::ProposalCancelled {
            proposal_id: 101,
            cancelled_ledger: 490,
            cancelled_by: "timelock_admin".into(),
        };

        assert!(matches!(proposed, BridgePauseAuditEvent::PauseProposed { proposal_id: 101, .. }));
        assert!(matches!(activated, BridgePauseAuditEvent::PauseActivated { proposal_id: 101, .. }));
        assert!(matches!(resume_proposed, BridgePauseAuditEvent::ResumeProposed { proposal_id: 102, .. }));
        assert!(matches!(cancelled, BridgePauseAuditEvent::ProposalCancelled { proposal_id: 101, .. }));
    }
}


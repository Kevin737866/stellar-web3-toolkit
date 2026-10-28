# Governance Voting Guards (Issues #448, #449, #450)

`stellar_toolkit::conviction` enforces three pre-execution invariants on governance proposals and ballots:

1. **Bounded Vote Windows (`#448`):** `VoteWindow::new(start_ledger, end_ledger, current_ledger)` rejects start ledgers in the past, inverted bounds (`end <= start`), and windows exceeding `MAX_VOTE_WINDOW_LEDGERS` (`120_960` ledgers).
2. **Duplicate Vote Prevention (`#449`):** `ProposalBallotBox::record_vote(proposal_id, voter, weight)` guarantees each `(proposal_id, voter)` pair is counted at most once.
3. **Zero-Power Quorum Guard (`#450`):** `evaluate_quorum(participating_votes, eligible_voting_power, quorum_bps)` explicitly returns `Err(GovernanceVoteError::ZeroEligibleVotingPower)` when `eligible_voting_power == 0` instead of dividing by zero or vacuously passing proposals.

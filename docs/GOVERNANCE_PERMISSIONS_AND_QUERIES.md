# Governance Upgrade Permissions, Emergency Veto, and Quorum Progress Queries (Issues #456, #457)

## Proposal Vote Totals and Quorum Progress (`#456`)

`ProposalQuorumProgress::compute(votes_for, votes_against, votes_abstain, required_quorum)` exposes:
- `votes_for`, `votes_against`, `votes_abstain`, and `total_cast`
- `required_quorum` (rejecting `0` with `TimelockError::ZeroQuorumRequirement`)
- `quorum_progress_bps` capped at `10_000` (`100.00%`) and `quorum_reached`

## Upgrade and Emergency Veto Permission Matrix (`#457`)

| Role | `EmergencyVeto` | `ExecuteUpgrade` |
| --- | --- | --- |
| `Voter` | Denied | Denied |
| `EmergencyGuardian` | Allowed (pre-execution safety brake) | Denied (cannot unilaterally upgrade) |
| `TimelockAdmin` | Allowed | Allowed (after timelock expiry) |

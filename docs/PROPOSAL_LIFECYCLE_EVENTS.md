# Proposal Lifecycle Events, Cancellation Reasons, and Delegation (Issues #452, #453, #454)

- **Stable State Change Events (`#452`):** `ProposalStateEvent::to_canonical_string()` emits a deterministic key-value event format (`proposal_state_change:id=<id>:from=<state>:to=<state>:ledger=<ledger>`).
- **Explicit Cancellation Reasons (`#453`):** `ProposalCancellationRecord::new` rejects empty or overlong reasons (`> 512` bytes) and pairs every cancellation with a `ProposalStateEvent`.
- **Delegated Voting Power Tracking (`#454`):** `DelegationTracker` tracks balances across delegation, re-delegation, and revocation without double-counting or allowing self-delegation.

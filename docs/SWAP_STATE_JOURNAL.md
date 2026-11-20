# Durable Swap State Transitions

**Issue:** [#390](https://github.com/Kevin737866/stellar-web3-toolkit/issues/390) — *Persist swap state transitions before submitting chain actions*

A coordinator that keeps swap state only in memory loses it when the process
restarts. Worse, a crash *between* building a chain action and applying its
result leaves nothing behind: on restart the swap still looks `Pending`, so the
next attempt re-submits an action the chain may already have accepted. That is
how a swap gets funded twice.

The journal removes the ambiguity. Every transition is written down *before* it
is applied in memory and *before* the corresponding chain action is submitted.
After a restart the coordinator can rebuild the swap from the journal alone, and
the actions that were in flight are reported explicitly instead of being
silently forgotten.

## The journal

```rust
pub trait TransitionJournal: Send + Sync {
    fn append(&self, record: TransitionRecord) -> Result<TransitionRecord>;
    fn transitions(&self, swap_id: &str) -> Result<Vec<TransitionRecord>>;
    fn swap_ids(&self) -> Result<Vec<String>>;
    fn unresolved_actions(&self) -> Result<Vec<UnresolvedAction>>;
}
```

Two implementations ship:

| Type | Backing | Use |
| --- | --- | --- |
| `InMemoryJournal` | `Vec` per swap | Tests, and the default for `AtomicSwapCoordinator::new` |
| `FileJournal` | Append-only JSONL | Anything that must survive a restart |

`FileJournal` writes one JSON object per line and flushes after every append.
Reopening the same path replays the file into memory, so a coordinator started
against it sees the swaps that had been initiated before the restart.

## One record per transition

```rust
pub struct TransitionRecord {
    pub swap_id: String,
    pub seq: u64,              // 1-based, dense, per swap
    pub idempotency_key: String,
    pub recorded_at: u64,      // unix seconds
    pub ledger: u32,
    pub kind: TransitionKind,
    pub snapshot: AtomicSwap,  // state after the transition
}

pub enum TransitionKind {
    Initiated,
    ChainActionPending  { operation: String },
    ChainActionConfirmed { operation: String },
    ChainActionFailed   { operation: String, detail: String },
    Settled,
    Refunded,
    Expired,
    Failed              { code: String },
}
```

`idempotency_key` is derived from the transition, not from wall-clock time, so
appending the same transition twice returns the first record unchanged instead
of duplicating it. Reusing a key for a *different* transition is refused with
`JournalError::Conflict` — that is a bug in the caller, not something
to paper over.

## Bracket every chain action

The point of the journal is the gap between "we decided to submit" and "the
chain answered". Close it from both sides:

```rust
// 1. Record the intent before submitting anything.
coordinator
    .record_chain_action_pending(&swap_id, "lock", current_ledger)
    .await?;

// 2. Submit.
let result = submit_lock(...).await;

// 3. Record the outcome.
match result {
    Ok(_) => coordinator
        .record_chain_action_confirmed(&swap_id, "lock", current_ledger)
        .await?,
    Err(e) => coordinator
        .record_chain_action_failed(&swap_id, "lock", &e.to_string(), current_ledger)
        .await?,
}
```

A `ChainActionPending` with no matching confirmed/failed record is exactly the
case that used to be invisible. `unresolved_chain_actions()` returns those, and
a restart reports them before doing any new work:

```rust
let restarted = AtomicSwapCoordinator::with_journal(config, 3, Arc::new(FileJournal::open(path)?));
let restored = restarted.recover_from_journal().await?;

for action in restarted.unresolved_chain_actions()? {
    // Ask the chain what happened to `action.operation` on `action.swap_id`
    // before retrying it.
}
```

## Lifecycle transitions are journalled automatically

`initiate_swap`, `complete_swap`, `refund_swap` and `fail_swap` append their
record before they mutate the in-memory swap:

* `initiate_swap` appends `Initiated` before the swap becomes visible, so a swap
  can never exist in memory without a matching journal entry.
* `complete_swap` appends `Settled` *after* the preimage is verified but *before*
  the swap is marked complete. If the process dies mid-settlement, the revealed
  preimage is already durable.
* `refund_swap` appends `Refunded` before marking the swap refunded.
* `expire_swap` appends `Expired` once the timeout ledger has passed, so an
  expired swap does not come back as `Pending` (and therefore refundable) after
  a restart.
* `fail_swap` appends `Failed` only for the first reason. A second `fail_swap`
  call returns `Ok(false)` and appends nothing, matching the "first reason wins"
  rule from [#391](SWAP_FAILURE_REASONS.md).

## Recovery semantics

`recover_from_journal` restores each swap to the state its **last** record
describes and returns how many swaps it restored. It never overwrites a swap
that is already in memory: recovery fills gaps, it does not roll back live
state.

## Operational notes

* The journal grows with the number of transitions, not with uptime, but a
  long-lived deployment should still rotate it. `FileJournal` replays the whole
  file on open, so keep the active file bounded and archive closed ones.
* A corrupt line is reported as `JournalError::Corrupt { line, detail }` with
  the 1-based line number, rather than being skipped. Skipping a bad line would
  silently drop a transition, which is the failure mode this module exists to
  prevent.
* `AtomicSwapError::Journal` wraps every journal failure, so a full disk or a
  read-only mount surfaces as a failed transition instead of an unlogged one.

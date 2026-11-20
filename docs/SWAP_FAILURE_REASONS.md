# Terminal Failure Reasons for Atomic Swaps

**Issue:** [#391](https://github.com/Kevin737866/stellar-web3-toolkit/issues/391) — *Expose the terminal reason for each failed atomic swap*

`SwapStatus::Failed` used to be a dead end. A swap that neither settled nor timed
out reported the same thing whether the on-chain funding had failed, the
coordination retry budget had run out, or an operator had abandoned it. An
operator seeing `failed` had to reconstruct the cause from logs, and any retry
loop could rewrite the status without leaving a trace of why it first stopped.

Every failed swap now carries a `SwapFailure`, recorded once and never rewritten.

## What gets recorded

```rust
pub struct SwapFailure {
    pub reason: SwapFailureReason,
    pub ledger: u32, // ledger the failure was observed at
}

pub enum SwapFailureReason {
    ChainActionFailed { operation: String, detail: String },
    RetryBudgetExhausted { operation: String, attempts: u32 },
    CounterpartyTimeout,
    Abandoned { detail: String },
}
```

`reason.code()` returns a stable, coarse identifier for grouping
(`chain_action_failed`, `retry_budget_exhausted`, `counterparty_timeout`,
`abandoned`). The `detail` fields are free text for humans; the code is what a
dashboard groups by, so it does not change between releases.

## Recording a failure

```rust
let recorded = coordinator
    .fail_swap(
        &swap_id,
        SwapFailureReason::RetryBudgetExhausted {
            operation: "submit_htlc".to_string(),
            attempts: 3,
        },
        current_ledger,
    )
    .await?;
```

* `Ok(true)` — the reason was recorded. The swap is now `Failed`, a single
  `SwapEvent::Failed { reason_code, .. }` is emitted, and the monitor's copy of
  the swap carries the same reason.
* `Ok(false)` — the swap already had a reason. Nothing is overwritten and no
  second event is emitted.
* `Err(SwapNotFound)` — unknown swap id.
* `Err(SwapAlreadyCompleted)` — the swap already settled (`Completed`),
  refunded, or expired. A late error report cannot relabel a settled swap.

Reading it back:

```rust
let reason: Option<String> = coordinator.terminal_reason(&swap_id).await?;
// Some("retry budget exhausted for `submit_htlc` after 3 attempt(s)")
```

`terminal_reason` is `None` while the swap can still settle, so a caller can use
it directly as "is this swap finished and, if so, why".

## Design rules

* **First reason wins.** `AtomicSwap::mark_failed` returns `false` when a reason
  is already present. The first, most specific observation is the one an operator
  acts on; a later, vaguer report must not replace it.
* **Settled swaps are not failures.** `Completed`, `Refunded` and `Expired` are
  terminal outcomes of their own; `fail_swap` refuses to touch them.
* **A `Failed` swap without a reason is still explainable.** Records written
  before this change (or set directly) report
  `"failed without a recorded reason"` rather than inventing a cause.
* **The monitor and the coordinator agree.** The coordinator propagates the
  reason to the monitor so `get_statistics`, `get_swap` and the emitted event all
  describe the same failure.

# Timeout Boundary for the Preimage and Refund Paths

**Issue:** [#396](https://github.com/Kevin737866/stellar-web3-toolkit/issues/396) — *Add timeout-boundary tests for preimage and refund paths*

An atomic swap has one timeout ledger. The question this change pins down is
exactly which side of that ledger each path is allowed on. Before #396 the
boundary was implemented correctly but never tested at the off-by-one point, and
the refund path reported a refund *before* the timeout with `SwapExpired` — an
error that claims a timeout which has not happened.

The boundary is **exclusive on the timeout side**: a swap whose timeout is `T`
is expired at `T + 1` but not at `T`. The timeout ledger is therefore the *last*
ledger at which the swap can still settle.

## The boundary

```rust
pub fn is_expired(&self, current_ledger: u32) -> bool {
    current_ledger > self.timeout_ledger
}

pub fn can_complete(&self, current_ledger: u32) -> bool {
    self.is_pending() && !self.is_expired(current_ledger)
}

pub fn can_refund(&self, current_ledger: u32) -> bool {
    self.is_pending() && self.is_expired(current_ledger)
}
```

| `current_ledger` | `is_expired` | preimage path (`can_complete`) | refund path (`can_refund`) |
| --- | --- | --- | --- |
| `T - 1` | no | open | closed |
| `T`     | no | **open** (last settleable ledger) | closed |
| `T + 1` | yes | closed | **open** |

The two paths are mirrors: at the timeout ledger the preimage path is still open
and the refund path is not, and one ledger later they swap. A participant cannot
claw back funds via a refund while the counterparty could still reveal the
preimage and settle.

## The preimage path

`AtomicSwapCoordinator::complete_swap` reveals the preimage. It succeeds at
exactly `timeout_ledger` and is refused one ledger later:

- `current_ledger <= timeout_ledger`, swap pending → completes; the preimage is
  stored and a `Settled` transition is journalled.
- `current_ledger > timeout_ledger` → [`AtomicSwapError::SwapExpired`].
- A preimage that does not hash to the swap's lock →
  [`AtomicSwapError::InvalidPreimage`]; the swap is left untouched and nothing
  is journalled.
- A swap that already settled → [`AtomicSwapError::SwapAlreadyCompleted`].

## The refund path

`AtomicSwapCoordinator::refund_swap` is the timeout escape hatch. It opens only
*after* the timeout ledger:

- `current_ledger > timeout_ledger`, swap pending → refunds; a `Refunded`
  transition is journalled.
- `current_ledger <= timeout_ledger`, swap pending →
  [`AtomicSwapError::RefundBeforeTimeout`] (new in #396). The error carries the
  `timeout_ledger` and `current_ledger` so an operator knows exactly how long to
  wait.
- A swap that already reached a terminal state → [`AtomicSwapError::SwapExpired`].

A refused refund leaves no partial state: the swap stays pending, the preimage
path stays open at that ledger, and no `Refunded` record is written. The journal
is written *before* the in-memory state moves (see [SWAP_STATE_JOURNAL.md](SWAP_STATE_JOURNAL.md)),
so a refusal never leaves memory and disk disagreeing.

## Restart recovery

A swap restored from a durable journal keeps its original `timeout_ledger`, so
the boundary survives a restart unchanged. After `recover_from_journal` the
preimage path is still open at `T` and the refund path still closed, exactly as
before the crash, and the recovered swap can still be settled at `T`.

## Compatibility

`RefundBeforeTimeout` is a new, additive error variant. Before #396 the refund
path returned `SwapExpired` for a refund requested before the timeout, which
described a timeout that had not happened. Callers that matched only on
`SwapExpired` for that case will now see `RefundBeforeTimeout` instead; callers
that propagate the error as `AtomicSwapError` are unaffected. The terminal-state
case still returns `SwapExpired`, unchanged.

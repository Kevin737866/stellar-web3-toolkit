# Validating Breach Evidence Before a Justice Response

**Issue:** [#371](https://github.com/Kevin737866/stellar-web3-toolkit/issues/371) — *Validate breach evidence before generating a justice response*

A justice transaction is a claim against the counterparty: it publishes the
breach transaction and takes the channel's balance. Submitting one on bad
evidence is not a harmless mistake — it is an on-chain accusation that costs a
fee, may be contested, and, if the "breach" was actually the honest state, can
itself be punished.

So the watchtower now checks the evidence *before* it builds or submits
anything. `JusticeService::validate_breach` returns a `BreachEvidence` on
success; `submit_justice` calls it first and records no pending transaction when
it fails.

## What is checked

`BreachAttempt` carries the two channel states it is comparing. Each invariant
below is refused with `JusticeError::InvalidBreach(reason)`, where `reason` names
the field that was rejected, so an operator can tell malformed input from a real
breach.

| Invariant | Why |
| --- | --- |
| `channel_id` is not blank | The response cannot be attributed to a channel without it. |
| `breach_tx_hash` is not blank | There is nothing to publish, so nothing to respond to. |
| `detected_at != 0` | A zero timestamp means the detector never stamped the evidence. |
| `new_sequence > old_sequence` | A breach is a *newer* state superseding the honest one. An equal or lower sequence is not evidence of anything. |
| every balance `>= 0` | A negative balance cannot exist on a channel. |
| `old_a + old_b == new_a + new_b` | Both states describe the same channel. A justice claim cannot create or destroy funds, so unequal totals mean the states do not belong together. |

Sums are computed with `checked_add`, so a balance pair that overflows `i128`
is refused rather than wrapping to a total that happens to match.

## The validated type

```rust
pub struct BreachEvidence {
    pub channel_id: String,
    pub breach_tx_hash: String,
    pub detected_at: u64,
    pub old_sequence: u32,
    pub new_sequence: u32,
    pub total_balance: i128, // old_a + old_b, which the new state must match
}
```

Holding a `BreachEvidence` is the proof that the invariants held. Code that
needs to build a claim should take the validated type rather than re-reading a
raw `BreachAttempt`, so a new call path cannot skip the check.

## Usage

```rust
let service = JusticeService::new(rpc_url, watchtower_key, fee);

// Validates first, then builds and queues the transaction.
let tx = service.submit_justice(&breach).await?;

// Or validate on its own, e.g. to log evidence before acting.
let evidence = service.validate_breach(&breach)?;
info!(channel = %evidence.channel_id, total = evidence.total_balance, "breach confirmed");
```

A rejected breach leaves no trace in `pending_txs`; the next scan re-evaluates
it from scratch. That matters because the monitor re-detects a breach on every
scan, so a validation failure does not need any cleanup.

## Retrying transient storage failures

Reading the channel's stored state goes through `StorageBackend`, which can fail
transiently (timeouts, dropped connections, lock contention). Such failures are
retried so that a momentary storage hiccup does not delay a justice response.

- Only errors classified as transient are retried. Validation errors
  (`JusticeError::InvalidBreach`) are never retried, since re-running the same
  check on the same input yields the same result.
- Retries use bounded exponential backoff. Exhausting the retry budget returns
  the last storage error to the caller; no partial state is written.
- **No duplicate actions.** A justice transaction is recorded in `pending_txs`
  under its breach identity (`channel_id` plus `new_sequence`) before submission.
  A retry that finds the identity already recorded returns the existing
  transaction instead of building and submitting a second one. Operators can
  inspect `pending_txs` to recover a claim whose submission outcome is unknown.

## What this does *not* cover

Validation is an internal-consistency check, not a proof of fraud. It cannot
tell whether the sequence numbers belong to the channel or whether the state was
signed by the counterparty — that requires the channel's stored state and the
signatures, which live behind `StorageBackend` and the on-chain verifier.
This check exists to stop the watchtower from acting on malformed or
self-contradictory evidence; the chain remains the authority on whether the
breach is real.

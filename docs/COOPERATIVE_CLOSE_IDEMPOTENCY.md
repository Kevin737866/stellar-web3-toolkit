# Idempotent Cooperative Channel Close

**Issue:** [#351](https://github.com/Kevin737866/stellar-web3-toolkit/issues/351) — *Make cooperative channel close retries idempotent*

A cooperative close is the last state transition a channel makes. It settles both
balances and, on chain, it is the point after which nothing else can happen. That
makes it the worst possible place for a retry to be unsafe — and it is exactly
where retries happen, because a close submitted over a flaky connection looks
identical to one that never landed.

## The problem

Before this change both layers treated a second close as an error, in different
ways:

| Layer | Old behaviour on a retry |
| --- | --- |
| `ChannelManager::cooperative_close` | `InvalidState("Cannot close channel in state Closing")` |
| `PaymentChannel::cooperative_close` (contract) | Succeeded again: balances rewritten, `sequence_number` advanced, a second `channel_close` event published |

Neither is safe. The first turns a successful close into a client-visible failure,
so a client cannot tell "the close worked and the response was lost" from "the
close was rejected". The second is worse: a retry could rewrite the settlement,
and a late retry with a stale split could move funds after both parties had
already observed the close.

## The rule

A close is identified by its outcome, not by a request id: **the same final
balance split presented again is the same close.**

### Off-chain (`crates/payment-channel`)

```rust
manager.cooperative_close(&channel_id)?;        // Open      → Closing
manager.cooperative_close(&channel_id)?;        // Closing   → Closing (no-op)
manager.cooperative_close_at(&channel_id, 42)?; // retry at a known height (no-op)
```

* `Open` → applies the close, records one snapshot, returns `Closing`.
* `Closing` / `Closed` → returns the current state unchanged. No snapshot, no
  sequence bump, no ledger height consumed.
* `ForceClosed` / `Dispute` → `InvalidState`: a cooperative close cannot override
  a unilateral one, and the state is left untouched.
* Unknown channel → `ChannelNotFound`.

`cooperative_close_at` is the height-aware twin for callers that observed the
close on chain. A retry ignores the supplied height, because there is nothing
left to record.

### On chain (`contracts/payment-channel-contract`)

The contract records which sequence number settled the channel
(`ChannelState::close_sequence`), and treats a second call as follows:

| Call | Result |
| --- | --- |
| First close | Balances written, `is_cooperative_close = true`, `close_sequence` stamped, one event |
| Same balances again | `Ok(())`, no state change, no second event |
| Different balances | `ChannelAlreadyClosed` — the channel already settled on a different split |
| Total does not match | `BalanceMismatch` (or `InvalidBalance` for a negative side) |
| Active HTLCs | `ActiveHtlcsExist` — their amounts sit outside the two balances |
| Unknown channel | `ChannelNotFound` |

A settled channel also rejects `update_state`, `create_htlc`, `claim_htlc`,
`refund_htlc`, `top_up` and `initiate_unilateral_close` with
`ChannelAlreadyClosed`. Without that guard, "settled" would not be terminal: a
retry sequence could reopen a channel that both parties already consider closed.

## Compatibility

* The contract entry point keeps its signature; only its behaviour on a repeated
  call changed, from "succeeds and rewrites" to "succeeds and does nothing".
* `ChannelState` gained `close_sequence`. It is `0` while the channel is open, so
  a state read from an older deployment still deserialises into the same shape.
* `ChannelManager::cooperative_close` keeps its signature; `cooperative_close_at`
  is additive.

## Tests

* `crates/payment-channel/src/lib.rs` — retry is a no-op, retry at a known height
  is a no-op, a `Closed` channel accepts a retry, a force-closed channel is
  refused, an unknown channel reports `ChannelNotFound`, and a retried close still
  rolls back correctly on a reorg.
* `contracts/payment-channel-contract/tests/cooperative_close.rs` — the first
  close settles the split, a retry publishes no second event, a conflicting split
  is refused, the total must be conserved, an outstanding HTLC blocks the close,
  and a settled channel rejects every mutating entry point.

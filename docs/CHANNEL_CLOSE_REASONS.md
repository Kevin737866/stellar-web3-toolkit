# Channel Close Reasons

**Issue:** [#350](https://github.com/Kevin737866/stellar-web3-toolkit/issues/350) — *Expose channel close reasons through the payment-channel API*

A channel can end in more than one way: the two participants can agree on a
split, the channel can settle on a state both of them signed, or one participant
can force it closed. Before this change that distinction lived only in the
operation that was called and in the resulting `ChannelStatus`. Once the call
returned, a client had no way to ask *how* a channel had closed.

## The interface

### On chain (`contracts/payment-channel-contract`)

```rust
pub enum CloseReason {
    NotClosed,        // still open
    Cooperative,      // closed by cooperative_close
    SignedSettlement, // closed by settle_signed_state
    Unilateral,       // closed by initiate_unilateral_close
}

// New entry point:
PaymentChannel::get_close_reason(env, channel_id) -> Result<CloseReason, PaymentChannelError>
```

The reason is also reported as `ChannelState::close_reason`, so a caller that
already reads `get_channel_state` needs no extra round trip.

`get_close_reason` returns [`PaymentChannelError::ChannelNotFound`] for an
unknown channel rather than a default, so "still open" (`NotClosed`) and "no such
channel" can never be confused.

### Off chain (`crates/payment-channel`)

```rust
pub enum CloseReason { NotClosed, Cooperative, SignedSettlement, Unilateral }

manager.close_reason(&channel_id)?; // Result<CloseReason, PaymentChannelError>
```

`LocalChannelState::close_reason` carries the same value inside the full channel
state. An unknown channel returns `PaymentChannelError::ChannelNotFound`.

## The rules

| Operation | Reason recorded |
| --- | --- |
| `initialize` / `create_channel` | `NotClosed` |
| `cooperative_close` | `Cooperative` |
| `settle_signed_state` | `SignedSettlement` |
| `initiate_unilateral_close` | `Unilateral` |
| `update_state`, `top_up`, `create_htlc`, `claim_htlc`, `refund_htlc`, `contest_close` | unchanged |

Invariants the implementation enforces:

* **Authorization** — a unilateral close still requires the caller to be a
  participant (`UnauthorizedParticipant`), and the reason is only written after
  that check passes.
* **Recoverable lifecycle transitions** — the reason is written by the same
  entry point that performs the close, in the same storage write, so there is no
  window in which a channel is closed with a stale reason. A retry of an
  already-applied cooperative close returns the recorded reason untouched; a
  close that is refused (balance mismatch, active HTLCs, already settled on a
  different split) leaves the reason exactly as it was.
* **No partial updates** — every failure path returns before the state is
  mutated, so a rejected close cannot record a reason.

`contest_close` deliberately does not change the reason: it records that a newer
state exists, not that the channel has closed. A unilateral close that is later
contested still reports `Unilateral`.

## Configuration

No new configuration. The only ABI-visible additions are the `CloseReason` type,
`ChannelState::close_reason` and the `get_close_reason` entry point.

## Compatibility

* `get_channel_state` keeps its signature; it now includes the additional
  `close_reason` field.
* `ChannelState` gained `close_reason`. Soroban decodes a `#[contracttype]`
  struct by field name, so a channel state written by a contract version that
  predates this field will **not** deserialize after an in-place upgrade. Channels
  that must survive an upgrade have to be re-opened, or migrated by a dedicated
  migration entry point. Fresh deployments and channels created after the upgrade
  are unaffected.
* `LocalChannelState` gained `close_reason` as well. Serde-based consumers of
  the JSON/state encoding must accept the new field; it defaults to
  `NotClosed` when absent only if they treat it as `Option`/`Default`, so
  consumers that pin the exact shape should be updated.
* The `ChannelManager` methods that close a channel keep their signatures;
  `close_reason` is additive.

## Tests

* `crates/payment-channel/src/lib.rs` — open channel reports `NotClosed`, unknown
  channel reports `ChannelNotFound`, each close path records its reason, a
  rejected close does not overwrite the reason, and a reorg rollback below a
  close restores `NotClosed`.
* `contracts/payment-channel-contract/src/lib.rs` — the same cases as unit tests
  over the generated client, including the idempotent cooperative-close retry and
  an unknown channel id.
* `contracts/payment-channel-contract/tests/close_reasons.rs` — integration
  coverage of the full workflow: open → update → signed settlement, cooperative
  close with retry, unilateral close, a rejected close that leaves the channel
  usable, an unauthorized close, and an unknown channel.

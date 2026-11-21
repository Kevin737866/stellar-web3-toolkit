# Stale Signed Channel States

**Issue:** [#352](https://github.com/Kevin737866/stellar-web3-toolkit/issues/352) — *Reject stale signed channel states during settlement*

A payment channel works because "the newest signed state wins". Each off-chain
update replaces the balance split and bumps a sequence number, and both parties
keep the copy they signed. Settlement is where that rule has to be enforced
against the counterparty rather than only locally.

## The problem

Settlement used to accept any well-formed split:

| Layer | Old behaviour |
| --- | --- |
| `ChannelManager` | No settlement entry point at all; the split came from whatever the caller passed |
| `PaymentChannel::cooperative_close` | Accepted any split that summed to the total, and only rejected a *second* close |

Nothing compared the presented state against the channel's sequence number. A
party that kept an older, more favourable split could settle on it after the
channel had moved on, moving funds backwards. The stored sequence number was not
enough on its own either, because the presented copy had no sequence attached to
compare against.

## The rule

A settlement is only accepted when the state it presents is **strictly newer**
than the one the channel has recorded.

### The signed payload

`payment_channel::signed::SignedChannelState` is the message both participants
sign:

```rust
pub struct SignedChannelState {
    pub channel_id: String,
    pub sequence_number: u32,
    pub balance_a: i128,
    pub balance_b: i128,
}
```

`digest()` produces the canonical SHA-256 preimage, with every field
length-prefixed or fixed-width and big-endian:

```text
"stellar-payment-channel/signed-state/v1"
|| len(channel_id) as u64 BE || channel_id bytes
|| sequence_number as u32 BE
|| balance_a as i128 BE
|| balance_b as i128 BE
```

The length prefix is what keeps the encoding unambiguous: `"ab" + "c"` and
`"a" + "bc"` cannot collide, and neither can a reordered or truncated payload.
The contract uses the same layout, so a signature made off chain verifies on
chain.

### Off chain (`crates/payment-channel`)

```rust
manager.set_remote_public_key(&channel_id, counterparty_key)?;

let signed = SignedChannelState::new(&channel_id, 7, 1_200, 800);
manager.settle_signed_state(&signed, &signature, ledger_height)?;
```

`settle_signed_state` refuses, leaving the channel untouched, when:

| Condition | Error |
| --- | --- |
| Channel unknown | `ChannelNotFound` |
| Channel not `Open` | `ChannelClosed` |
| No counterparty key registered | `InvalidState` |
| Signature does not verify | `SignatureError` |
| A balance is negative or the total overflows | `InvalidState` |
| Balances do not sum to the channel total | `InvalidState` |
| `sequence_number` is equal to or lower than the recorded one | `StaleState` |
| `ledger_height` is not newer than the last recorded height | `ReorgDetected` |

On success the balances are applied, the sequence number advances to the signed
one (gaps are allowed, because a participant may have missed intermediate
updates) and the channel moves to `Closing`.

Signature verification runs before the staleness check, so an unsigned caller
cannot probe the recorded sequence number from the error it gets back.

### On chain (`contracts/payment-channel-contract`)

```rust
client.settle_signed_state(&channel_id, &1_200, &800, &7, &sig_a, &sig_b);
```

The contract entry point takes the signed fields explicitly, applies the same
conservation and HTLC checks as `cooperative_close`, and rejects
`sequence_number <= ChannelState::sequence_number` with
`PaymentChannelError::StaleState`. `signature_a`/`signature_b` are part of the
ABI but are not verified yet, matching `update_state` and `cooperative_close`.
The staleness check does not depend on that verification landing: it is enforced
against the stored sequence number.

## Compatibility

* `ChannelState` already carried `sequence_number` and `close_sequence`, so no
  storage migration is needed.
* `settle_signed_state` is additive at both layers; `cooperative_close` and
  `update_state` keep their signatures and behaviour.
* `PaymentChannelError::StaleState` is a new contract error discriminant (30).
  Older clients that only match known discriminants will surface it as an
  unknown contract error rather than a panic.

## Tests

* `crates/payment-channel/src/signed.rs` — the digest is deterministic, every
  field changes it, the length prefix removes boundary ambiguity, and totals
  reject negatives and overflow.
* `crates/payment-channel/src/lib.rs` — a newer state settles; a stale state is
  refused and changes nothing; an equal sequence is stale; a gap is accepted; an
  unsigned state, a missing key, a wrong total, a foreign channel, a stale
  height, and a second settlement are each refused.
* `contracts/payment-channel-contract/tests/signed_settlement.rs` — the same
  matrix against the deployed contract, including the event count and the
  terminal-settlement rule.

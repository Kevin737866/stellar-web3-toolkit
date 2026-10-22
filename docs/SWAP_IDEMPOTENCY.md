# Idempotent Swap Initiation

**Issue:** [#212](https://github.com/Kevin737866/stellar-web3-toolkit/issues/212) — *Swap coordinator idempotency*

A swap is a two-sided commitment: the initiator locks the hash lock and the
participant funds the other leg. Initiation is the step that creates the hash
lock, the preimage and the swap record, and it is the one step a client is most
likely to retry — a request that timed out looks exactly like a request that was
never processed.

Before this change, retrying it was not safe:

```text
client → initiate_swap ──▶ swap A (hash lock HA, preimage PA)   [response lost]
client → initiate_swap ──▶ swap B (hash lock HB, preimage PB)
```

Both calls succeed, both swaps are funded against the same intent, and the client
cannot even tell which response belongs to the transfer it actually made. Two
settlement flows now compete for one payment.

`atomic_swap::idempotency` gives initiation a caller-chosen key and binds it to
the initiation it first produced.

## The mechanism

```rust
let key = IdempotencyKey::new("order-4711")?;

// First attempt: creates the swap and records the response under the key.
let response = coordinator
    .initiate_swap_idempotent(initiator.clone(), request.clone(), key.clone())
    .await?;

// Retry after a timeout: same key, same initiator, same request.
let again = coordinator
    .initiate_swap_idempotent(initiator, request, key)
    .await?;

assert_eq!(response, again); // same swap id, hash lock, timeout and preimage
```

What each outcome means:

| Call | Result |
| --- | --- |
| Unused key, valid request | Initiates normally and records the response |
| Used key, same initiator, same request | Replays the recorded response; **no** second swap |
| Used key, different initiator | `IdempotencyConflict` |
| Used key, different request | `IdempotencyConflict` |
| Unused key, invalid request | The original error; the key is **not** bound, so a corrected retry may reuse it |

The response is replayed in full, including the preimage. That is safe because
the binding records the initiator: another caller cannot use a guessed or
observed key to read it (`IdempotencyConflict`), and the request must match
byte-for-byte after deserialisation.

## Key rules

* Keys are **not** normalised. `swap-1` and `Swap-1` are different keys; silently
  folding case or whitespace would make accidental replay possible.
* Keys are **bounded**: empty keys are rejected (every anonymous retry would
  collide), keys over `MAX_IDEMPOTENCY_KEY_LEN` (128) bytes are rejected, and
  control characters are rejected because they do not survive logging or an HTTP
  header round trip cleanly.
* The store is **process-scoped**. It is exactly-once initiation inside one
  coordinator, which is where the duplicate-swap bug lives, not a distributed
  lock. Two coordinator instances do not share bindings.
* Bindings are **retained** for the coordinator's lifetime; the length bound is
  what keeps that bounded. `forget_idempotency_key` exists for the rare case
  where an operator has independently established that the original swap will
  never be used — after it, the same key can initiate a new swap.

## Concurrency

`initiate_swap_idempotent` holds the store lock across initiation. Two retries of
the same key that arrive at the same time therefore cannot both miss the store:
the first creates the swap and records it, the second observes the record and
replays it. The critical section only covers in-memory work and the monitor
fan-out, and plain `initiate_swap` is unaffected — it does not take the lock.

## What this does not do

* It does not make **settlement** idempotent. `complete_swap` already refuses a
  second completion with the same swap id, and the hash lock binds the preimage.
* It does not deduplicate across coordinator instances. If initiation ever moves
  behind a shared database, the store is the seam that would be replaced; the
  key validation and the "same key, same request" contract stay the same.
* It does not reconcile two *different* keys that describe the same intent. Only
  the caller knows that two attempts are the same attempt, so only the caller can
  choose the key.

## Tests

`cargo test -p atomic-swap` covers:

* **Store:** key validation (empty, over-long, control characters, the exact
  length boundary), first-binding-wins, conflict on a different request or
  initiator, and `forget`.
* **Coordinator:** a retry replays the original response and creates no second
  swap; a conflicting request creates nothing and leaves the original reachable;
  a failed initiation leaves the key unbound; two concurrent retries produce one
  swap; a forgotten key may initiate again.

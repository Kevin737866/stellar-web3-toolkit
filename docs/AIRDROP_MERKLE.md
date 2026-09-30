# Airdrop Contract with Merkle Proofs

Implements issue [#256](https://github.com/Kevin737866/stellar-web3-toolkit/issues/256)
(retry of #69) in `contracts/airdrop-merkle`.

## Overview.

Storing one on-chain entry per recipient makes a large airdrop prohibitively
expensive. Instead the admin commits to a **Merkle root** off-chain and stores
only that root. Recipients prove membership with a sibling path, and the
contract releases their allocation. One claim costs a constant number of
hashes regardless of how many people the campaign targets.

## Interface

| Function | Notes |
| --- | --- |
| `initialize(admin, token, expiry_ledger)` | One-time. `token` is the SEP-41 token paid out. `expiry_ledger` of `0` means the campaign never expires. |
| `set_merkle_root(root, total_amount)` | Admin, once. Immutable after the first successful claim. |
| `fund(funder, amount)` | Tops the escrow up. Any holder of `token` may fund. |
| `claim(claimer, amount, proof) -> i128` | Verifies the proof against the root, marks the claim spent and transfers `amount`. |
| `is_claimed(account, amount)` | Whether that exact `(account, amount)` leaf has been spent. |
| `sweep_unclaimed(to) -> i128` | After expiry, returns the remainder to `to`. |
| `set_paused(paused)` | Admin. Pauses claims; `fund` and `sweep_unclaimed` stay open. |
| `set_admin(new_admin)` | Current admin authorises the handover. |

Views: `admin`, `token`, `merkle_root`, `total_amount`, `claimed_amount`,
`claim_count`, `expiry_ledger`, `expired`, `paused`.

## Leaf and node encoding

Everything is hashed with SHA-256 through `Env::crypto`, so the tree can be
rebuilt in any language.

| Node | Pre-image |
| --- | --- |
| leaf | `SHA256(LEAF_DOMAIN ‖ account_sc_address_xdr ‖ amount_i128_xdr)` |
| internal | `SHA256(0x01 ‖ min(left, right) ‖ max(left, right))` |

- `LEAF_DOMAIN` is `soroban-merkle-claim-v1` (exported as
  `airdrop_merkle::LEAF_DOMAIN`).
- Halves are ordered **lexicographically as raw 32-byte payloads**. `BytesN`'s
  own `Ord` is defined over the underlying host object and does *not* match, so
  `hash_node` compares `to_array()` directly. Getting this wrong silently
  produces proofs that never verify.
- The `0x01` prefix keeps internal nodes in a different domain than leaves, so a
  leaf can never be replayed as a subtree.
- The contract's Stellar Asset Contract (id `1`) and amount `1000` hash to
  `a5429068f242de7668e5b645ddeb99499adda821ee2b368151d21b2a069b9e01`, asserted
  by `leaf_digest_matches_the_documented_preimage` so the encoding cannot drift.

## Tree shape

1. Hash every `(account, amount)` leaf.
2. Sort the leaves lexicographically.
3. Pair adjacent nodes; an **unpaired node is promoted unchanged** to the next
   level, which is why odd-sized campaigns work.
4. A recipient's proof is the list of siblings along their branch, ordered
   leaf-to-root.

`verify_proof` applies the same sorted-halves rule, so it does not need to know
whether a sibling sits on the left or the right.

## Usage

```rust
let client = AirdropMerkleClient::new(&env, &id);
client.initialize(&admin, &token, &0);          // never expires
client.set_merkle_root(&root, &total);
client.fund(&funder, &total);                   // from a single address

// Recipient presents their own branch. The path is leaf-to-root.
client.claim(&alice, &allocation, &to_proof(&alice));
assert!(client.is_claimed(&alice, &allocation));
```

The test module contains a reference `build_tree` that produces a root and a
path per leaf; it is the executable specification of the shape above.

## Funding invariant

Before paying, the contract asserts

```text
escrow_balance + claimed_amount >= total_amount
```

That is the *remaining liability* check. It guarantees an early claimant can
never consume funds earmarked for a later one, and it surfaces a campaign that
was never funded in full — every claim fails loudly with
`campaign is underfunded` until the escrow is topped up, rather than the first
few recipients draining it and the rest losing their allocation.

## Storage

- **Instance**: `Config`, `ClaimCount`.
- **Persistent**: `Claimed(account, amount)`, with a TTL bump on read and write
  following `docs/SOROBAN_STORAGE_BEST_PRACTICES.md`.

## Security notes

- Replay protection is per `(account, amount)` leaf, so the same recipient
  cannot claim twice and a proof for one amount cannot be reused for another.
- The root is immutable after the first successful claim, so the admin cannot
  rewrite the campaign under claimants who already proved membership.
- `sweep_unclaimed` only works after expiry, and expiry is disabled entirely
  when `expiry_ledger` is `0`.
- `set_paused` stops claims but leaves `fund` and `sweep_unclaimed` available,
  so a pause cannot strand the escrow.
- `claim` is idempotent-safe by panicking rather than returning an error code,
  which is the convention for SEP-41-style interfaces.

## Tests

`cargo test -p airdrop-merkle` — 16 tests including the documented hash
preimages, order-independent node hashing, odd-sized tree promotion, the
single-recipient empty proof, multi-recipient payouts, replay rejection,
cross-account proof rejection, root immutability, expiry and sweep, the
never-expiring campaign, pause/resume, underfunded campaigns, and events.

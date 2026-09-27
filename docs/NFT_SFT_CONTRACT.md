# NFT / SFT Asset Contract

Implements issue [#254](https://github.com/Kevin737866/stellar-web3-toolkit/issues/254)
(retry of #67) in `contracts/nft-sft-contract`.

## Overview

One deployed contract holds a collection of **base tokens**. A base token is
identified by a `token_id` and carries a supply:

| Supply | Type | Ownership |
| --- | --- | --- |
| `1` | NFT | `owner_of` returns the single holder |
| `> 1` | SFT | divisible; `owner_of` returns `None` once divided |

The fungible-shaped surface (`balance`, `allowance`, `approve`, `transfer`,
`transfer_from`, `burn`, `burn_from`, `decimals`, `name`, `symbol`) follows
[SEP-41](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0041.md)
generalised over `token_id`. The metadata surface (`owner_of`, `uri`,
`metadata`, `set_metadata`, `base_supply`, `total_supply`, `is_nft`) follows the
SEP-41 non-fungible conventions and
[SEP-50](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0050.md)
in shape: an NFT is a fungible token with one unit per instance.

## Interface

### Admin

| Function | Notes |
| --- | --- |
| `initialize(admin, name, symbol, decimals, base_uri, max_supply)` | One-time. `max_supply` of `0` means an unbounded collection. |
| `set_admin(new_admin)` | Two-step-free handover; the current admin must authorise. |
| `set_base_uri(base_uri)` | Template used when a token has no explicit URI. |
| `max_supply()` | Collection cap, `0` for unbounded. |
| `freeze()` / `unfreeze()` / `frozen()` | Halts transfers. Burns stay open so holders can always exit. |

### Token surface

| Function | Notes |
| --- | --- |
| `mint(to, token_id, quantity, asset_name, uri)` | Admin only. A `token_id` cannot be minted twice until it is fully burned. |
| `balance(holder, token_id)` | Units held. |
| `owner_of(token_id)` | `Some(holder)` exactly when one address holds every unit. |
| `is_nft(token_id)` | `base_supply == 1`. |
| `base_supply(token_id)` / `total_supply()` | Units in existence for one base token / across the collection. |
| `metadata(token_id)` / `uri(token_id)` | Explicit metadata, falling back to the `base_uri` template. |
| `set_metadata(token_id, asset_name, uri)` | The sole holder may do this for an NFT; otherwise the admin must, because a divided SFT has no single owner. |
| `approve` / `allowance` / `transfer` / `transfer_from` / `burn` / `burn_from` | SEP-41 semantics, per `token_id`. |

## Usage

```rust
let client = NftSftContractClient::new(&env, &id);
client.initialize(&admin, &name, &symbol, &0, &base_uri, &0);

// One-of-a-kind token; `owner_of` reports the holder.
client.mint(&alice, &1, &1, &String::from_str(&env, "Genesis"), &uri);

// Divisible token; no owner until it is fully moved to one address.
client.mint(&alice, &2, &10, &String::from_str(&env, "Tickets"), &uri);
client.transfer(&alice, &bob, &2, &4);   // divided: owner_of -> None
client.transfer(&bob, &alice, &2, &6);   // whole supply: owner_of -> Some(alice)
```

Burning the final unit retires the base token and frees its `token_id` for
re-minting:

```rust
client.burn(&alice, &2, &7);   // alice keeps 3, still no owner
client.burn(&alice, &2, &3);   // supply 0: every trace of the token is removed
client.mint(&alice, &2, &5, &name, &uri);   // id is reusable
```

## How sole ownership is tracked

A base token has a sole owner exactly when one address holds every unit of it.
Persistent storage is not iterable, so the contract keeps a holder list per
base token (`DataKey::Holders`) in step with the balances. `refresh_base_holder`
then reduces that list to a single address or clears it, which is what
`owner_of` and the `set_metadata` authorisation branch read.

Any other outcome — a partial transfer, a burn that leaves a third party with
some units, a divided SFT — leaves the token without an owner, which is the
honest answer rather than a guess.

## Storage

- **Instance**: `Config`, `TotalSupply`, `BaseSupply(token_id)`,
  `BaseMeta(token_id)`, `BaseHolder(token_id)`.
- **Persistent**: `Balance(address, token_id)`, `Holders(token_id)`,
  `Allowance({from, spender, token_id})`, each with a TTL bump on read and
  write following `docs/SOROBAN_STORAGE_BEST_PRACTICES.md`.

Per-holder balances live in persistent storage so that a large collection does
not have to fit in a single instance entry.

## Security notes

- Transfers and burns are holder-authorised; `transfer_from` and `burn_from`
  are spender-authorised and draw down the SEP-41 allowance.
- `mint` is admin-only and refuses to exceed `max_supply` when one is set.
- Freezing blocks transfers but not burns, so a freeze cannot strand an NFT.
- A fully burned base token deletes its supply, metadata and holder entries, so
  a burned `token_id` cannot be resurrected with stale state.

## Tests

`cargo test -p nft-sft-contract` — 16 tests covering initialisation, NFT
ownership handover, SFT division and re-consolidation, burn-driven ownership
restoration, allowance gating and expiry, freezing, the collection cap, id
reuse, and event emission.

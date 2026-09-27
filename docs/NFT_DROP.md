# Blind-Mint NFT Drop

`NftDropContract` (issue **#149**) runs a phased mint drop for a collection.
Buyers **blind mint** — the asset is assigned to them immediately but its
metadata stays hidden until the admin *reveals* it, so a minter cannot
cherry-pick which asset they receive. Minting is gated by sale phases, supply
caps, a per-address limit and an optional time window.

| Contract | Package | Purpose |
|---|---|---|
| `NftDropContract` | `contracts/nft-drop` | Phased blind-mint drop with allowlist, reveal and payment collection. |

## Sale phases

| Phase | Meaning |
|---|---|
| `Pending` | Not on sale yet (initial state) |
| `Allowlist` | Only allowlisted accounts may mint, at `allowlist_price` |
| `Public` | Anyone may mint, at `public_price` |
| `Ended` | Sale closed |

## Lifecycle

1. **`configure`** — one-time setup: admin, SEP-41 payment token, allowlist and
   public prices, `max_supply`, per-address limit, sale window
   (`start_time`/`end_time`; `0` disables a bound), reveal time and an optional
   access-control contract.
2. **`set_phase`** — the admin opens the allowlist or public phase.
3. **`add_to_allowlist` / `remove_from_allowlist`** — manage who may mint during
   the allowlist phase.
4. **`blind_mint`** — a buyer pays the phase price and is assigned the next
   token id. Metadata is still hidden.
5. **`reveal`** — at/after `reveal_time` the admin publishes each asset's
   metadata URI.
6. **`withdraw`** — the admin withdraws the collected proceeds.

## API

```rust
use nft_drop::{NftDropContract, SalePhase};

let drop_id = env.register_contract(None, NftDropContract);
let drop = NftDropContractClient::new(&env, &drop_id);

// allowlist price 40, public price 200, 1,000 max supply, 2 per address.
drop.configure(
    &admin,
    &payment_token,
    &40_i128,
    &200_i128,
    &1_000_u32,
    &2_u32,
    &0_u64,       // start_time: no lower bound
    &0_u64,       // end_time: no upper bound
    &1_800_000_000_u64, // reveal_time
    &None,        // optional collection access-control contract
);

// Open the allowlist phase, seed it, then take public.
drop.set_phase(&admin, &SalePhase::Allowlist);
let mut batch = Vec::new(&env);
batch.push_back(member.clone());
drop.add_to_allowlist(&admin, &batch);

drop.set_phase(&admin, &SalePhase::Public);

// A buyer blind mints; the asset owner is recorded, metadata stays hidden.
let token_id = drop.blind_mint(&buyer);
assert_eq!(drop.owner_of(&token_id), buyer);
assert!(!drop.is_revealed(&token_id));

// Later, the admin (or a PERM_ADMIN holder) reveals the metadata.
drop.reveal(&admin, &token_id, &String::from_str(&env, "ipfs://nft-drop/0"));
assert_eq!(drop.token_uri(&token_id), String::from_str(&env, "ipfs://nft-drop/0"));

// The admin can transfer assets and withdraw proceeds.
drop.transfer(&buyer, &collector, &token_id);
drop.withdraw(&admin, &200_i128);
```

Read helpers: `get_config()`, `phase()`, `total_supply()`, `owner_of(token_id)`,
`balance_of(account)`, `mints_of(account)`, `is_allowlisted(account)`,
`is_revealed(token_id)`, `token_uri(token_id)`.

### Delegated administration

When `access_control` is configured, any account holding `PERM_ADMIN` for the
drop's collection in the [collection access-control contract](COLLECTION_ACCESS_CONTROL.md)
(issue **#148**) may call the privileged methods (`set_phase`, `set_prices`,
`set_times`, `set_access_control`, allowlist management, `reveal`, `withdraw`).
This lets a collection's role registry drive a drop without sharing the drop
admin key.

### Notes

- Minting reverts with `sale not active`, `sale not started`, `sale ended`,
  `sold out`, `mint limit reached` or `not allowlisted` as appropriate.
- Prices of `0` are allowed, so a free drop needs no payment token funding.
- `reveal` reverts with `reveal not open` before `reveal_time`, and
  `unknown token` for an id that was never minted.
- Token ownership, balances and metadata are stored in **persistent storage**
  with TTL extension; the config and mint counter live in instance storage. See
  [SOROBAN_STORAGE_BEST_PRACTICES](SOROBAN_STORAGE_BEST_PRACTICES.md).

## Example Integration

`contracts/nft-drop/tests/integration.rs` deploys the drop alongside the
collection access-control registry, grants a curator `PERM_ADMIN`, and shows the
curator opening the sale and revealing metadata while a stranger is rejected.

```bash
cargo test -p nft-drop --test integration
```

## Testing

```bash
cargo test -p nft-drop
```

Coverage includes phase gating, allowlist enforcement and pricing, per-address
limits, max supply, hidden metadata until reveal, reveal timing, transfers,
withdrawal and unauthorized-access rejections.

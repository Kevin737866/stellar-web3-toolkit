# Marketplace Listings & Royalty Splitting

This document covers the two token-layer contracts added for issues **#146** and **#147**:

| Contract | Package | Purpose |
|---|---|---|
| `MarketplaceContract` | `contracts/marketplace-contract` | Escrows digital assets and settles primary/secondary listings in a SEP-41 payment token. |
| `RoyaltySplitter` | `contracts/royalty-splitter` | Splits secondary-sale proceeds across multiple royalty receivers. |

Both contracts build on the [SEP-41 token standard](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0041.md).
They never invent their own token interface: the listed asset and the payment
asset are both referenced by their SEP-41 contract address, so any Soroban token
(fungible or NFT-style) composes with them. Royalty semantics follow the
EIP-2981 model adapted to Soroban, with multi-receiver splits expressed in basis
points (1 bps = 0.01%).

## Marketplace Listing Contract (Issue #146)

### Lifecycle

1. **`create_listing`** — the seller authorizes an escrow transfer of the asset
   into the marketplace. The listing is stored with its price, payment token,
   and metadata.
2. **`buy`** — the buyer authorizes payment. The marketplace fee (in bps) goes to
   the configured recipient, the remainder goes to the seller, and the escrowed
   asset is released to the buyer.
3. **`cancel_listing`** — the seller reclaims the escrowed asset from an active
   listing.
4. **`update_price`** — the seller adjusts the asking price of an active listing.

### API

```rust
// Configure the marketplace (one-time). fee_bps = 250 → 2.5%.
market.initialize(&admin, &250_u32, &fee_recipient);

// Seller escrows an NFT-style asset (token_id = 1, one unit) for 1,000 units.
let listing_id = market.create_listing(
    &seller,
    &asset,          // SEP-41 asset contract
    &1_u128,         // token_id (0 for fungible listings)
    &1_i128,         // amount held in escrow
    &1_000_i128,     // price in payment_token base units
    &payment_token,  // SEP-41 token used to settle
);

// Buyer settles. Returns the seller proceeds after fees (975).
let proceeds = market.buy(&buyer, &listing_id);

// Seller can cancel an active listing and recover the escrow.
market.cancel_listing(&seller, &listing_id);

// Admin-only configuration.
market.set_fee_bps(&500_u32);
market.set_fee_recipient(&new_recipient);
```

Read helpers: `get_listing(listing_id)`, `listing_count()`, `get_fee_bps()`,
`get_fee_recipient()`.

### Notes

- Listings are stored in **persistent storage** keyed by listing id, with TTL
  extension on read/write, following [SOROBAN_STORAGE_BEST_PRACTICES](SOROBAN_STORAGE_BEST_PRACTICES.md).
  Contract-wide configuration lives in instance storage.
- Fees are capped at 10,000 bps (100%). `initialize` and `set_fee_bps` reject
  anything larger.
- A seller cannot buy their own listing, and inactive listings cannot be
  purchased or re-cancelled.

## Royalty Splitter (Issue #147)

### Model

Each asset (`collection` + `token_id`) can map to a `RoyaltyInfo` containing an
ordered list of `Receiver { recipient, bps }`. The total share is capped by the
contract's `max_royalty_bps` (and can never exceed 10,000 bps). When an asset has
no explicit entry, an optional default royalty applies.

Either the contract **admin** or the **collection contract itself** may register
or clear an asset's royalty, so a collection can enforce its own secondary-sale
terms.

### API

```rust
splitter.initialize(&admin, &1_000_u32); // cap royalties at 10%

// Creator 5%, charity 2.5%, platform 2.5% = 10%.
let mut royalty = Vec::new(&env);
royalty.push_back(Receiver { recipient: creator.clone(),  bps: 500 });
royalty.push_back(Receiver { recipient: charity.clone(),  bps: 250 });
royalty.push_back(Receiver { recipient: platform.clone(), bps: 250 });
splitter.set_royalty(&admin, &collection, &token_id, &royalty);

// Inspect the split for a 1,000-unit sale (no transfers):
let payouts = splitter.preview(&collection, &token_id, &1_000_i128);
let total   = splitter.total_royalty(&collection, &token_id, &1_000_i128);

// Pay royalties from a payer in a SEP-41 token:
splitter.distribute(&buyer, &collection, &token_id, &1_000_i128, &payment_token);

// Fallback for assets without an explicit entry, and cleanup:
splitter.set_default_royalty(&admin, &default_receivers);
splitter.clear_royalty(&collection, &collection, &token_id);
```

Read helpers: `royalty_info(collection, token_id)`, `get_max_royalty_bps()`.

### Notes

- Receiver shares are validated: at least one receiver, positive bps, no
  duplicate beneficiaries, and a total within the configured cap.
- Payouts are floored to whole base units. Summed payouts can therefore be
  slightly below `total_royalty`; the rounding dust stays with the seller.
- Royalty entries are stored in persistent storage with TTL extension.

## Example Integration

`contracts/marketplace-contract/tests/integration.rs` demonstrates a complete
secondary sale across both contracts: a creator registers a royalty split, the
owner lists the asset, a buyer settles the listing (2.5% marketplace fee), and
the royalty splitter pays the creator and platform their shares.

```bash
cargo test -p marketplace-contract --test integration
```

## Testing

```bash
# Marketplace unit tests
cargo test -p marketplace-contract

# Royalty splitter unit tests
cargo test -p royalty-splitter

# Both crates together
cargo test -p marketplace-contract -p royalty-splitter
```

Coverage includes escrow/release accounting, fee math, cancellation,
authorization failures, duplicate receivers, cap enforcement, fallback royalties,
and rounding behaviour.

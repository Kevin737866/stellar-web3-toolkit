# Stellar Web3 Toolkit API Reference

**Version**: v0.1.0

Complete API documentation reference for Soroban contracts and SDK crates in `stellar-web3-toolkit`.

## Table of Contents

- [P2PQRPaymentFlow::parse_qr_uri](#p2pqrpaymentflowparse_qr_uri)
- [P2PQRPaymentFlow::encode_qr_uri](#p2pqrpaymentflowencode_qr_uri)
- [OneClickAirdropClaimer::execute_one_click_claim](#oneclickairdropclaimerexecute_one_click_claim)
- [OneClickAirdropClaimer::check_eligibility](#oneclickairdropclaimercheck_eligibility)
- [ExampleGalleryRegistry::list_examples](#examplegalleryregistrylist_examples)
- [AmmPool::swap](#ammpoolswap)
- [MarketplaceContract::create_listing](#marketplacecontractcreate_listing)
- [MarketplaceContract::buy](#marketplacecontractbuy)
- [RoyaltySplitter::set_royalty](#royaltysplitterset_royalty)
- [RoyaltySplitter::distribute](#royaltysplitterdistribute)

---

### P2PQRPaymentFlow::parse_qr_uri

*Module/Contract*: `crates/stellar-toolkit (p2p_qr_payment)`

Parses a standard SEP-0007 / web+stellar QR code URI into a structured payment request.

**Parameters:**
- `uri_str`: `&str`

**Return Type:** `Result<QRPaymentRequest>`

```rust
let request = P2PQRPaymentFlow::parse_qr_uri("web+stellar:pay?destination=GABC...&amount=100.50&asset_code=USDC")?;
```

---

### P2PQRPaymentFlow::encode_qr_uri

*Module/Contract*: `crates/stellar-toolkit (p2p_qr_payment)`

Encodes a `QRPaymentRequest` into a standard QR URI format.

**Parameters:**
- `request`: `&QRPaymentRequest`

**Return Type:** `String`

```rust
let uri = P2PQRPaymentFlow::encode_qr_uri(&request);
```

---

### OneClickAirdropClaimer::execute_one_click_claim

*Module/Contract*: `crates/stellar-toolkit (one_click_airdrop)`

Builds, signs, and executes an automated single-click token airdrop claim.

**Parameters:**
- `request`: `&AirdropClaimRequest`

**Return Type:** `Result<ClaimStatus>`

```rust
let status = OneClickAirdropClaimer::execute_one_click_claim(&request)?;
```

---

### OneClickAirdropClaimer::check_eligibility

*Module/Contract*: `crates/stellar-toolkit (one_click_airdrop)`

Checks eligibility and claim status of an account address.

**Parameters:**
- `claimant_address`: `&str`
- `airdrop_id`: `&str`

**Return Type:** `Result<ClaimStatus>`

```rust
let status = OneClickAirdropClaimer::check_eligibility("GCLAIMANT...", "winter-2026")?;
```

---

### ExampleGalleryRegistry::list_examples

*Module/Contract*: `crates/stellar-toolkit (example_gallery)`

Returns a list of all available runnable smart contract examples in the gallery.

**Parameters:**
None

**Return Type:** `Vec<&ContractExample>`

```rust
let registry = ExampleGalleryRegistry::default();
let list = registry.list_examples();
```

---

### AmmPool::swap

*Module/Contract*: `contracts/amm-pool`

Executes a constant-product AMM token swap with slippage protection.

**Parameters:**
- `to`: `Address`
- `out_a`: `i128`
- `out_b`: `i128`

**Return Type:** `()`

```rust
amm_pool_client.swap(&user, &100_i128, &0_i128);
```

---

### MarketplaceContract::create_listing

*Module/Contract*: `contracts/marketplace-contract`

Escrows a SEP-41 digital asset and creates a marketplace listing priced in a SEP-41 payment token.

**Parameters:**
- `seller`: `Address`
- `asset`: `Address` (SEP-41 asset contract)
- `token_id`: `u128` (`0` for fungible listings)
- `amount`: `i128`
- `price`: `i128`
- `payment_token`: `Address`

**Return Type:** `u64` (listing id)

```rust
let listing_id = marketplace.create_listing(&seller, &asset, &1_u128, &1_i128, &1_000_i128, &payment_token);
```

---

### MarketplaceContract::buy

*Module/Contract*: `contracts/marketplace-contract`

Settles an active listing: charges the buyer, pays the seller net of the marketplace fee, and releases the escrowed asset.

**Parameters:**
- `buyer`: `Address`
- `listing_id`: `u64`

**Return Type:** `i128` (seller proceeds after fees)

```rust
let proceeds = marketplace.buy(&buyer, &listing_id);
```

---

### RoyaltySplitter::set_royalty

*Module/Contract*: `contracts/royalty-splitter`

Registers a multi-receiver royalty split for an asset, called by the admin or the collection contract.

**Parameters:**
- `caller`: `Address`
- `collection`: `Address`
- `token_id`: `u128`
- `receivers`: `Vec<Receiver>`

**Return Type:** `()`

```rust
splitter.set_royalty(&admin, &collection, &token_id, &receivers);
```

---

### RoyaltySplitter::distribute

*Module/Contract*: `contracts/royalty-splitter`

Computes royalty shares for a sale price and transfers each share in a SEP-41 payment token from the payer to its receiver.

**Parameters:**
- `payer`: `Address`
- `collection`: `Address`
- `token_id`: `u128`
- `sale_price`: `i128`
- `payment_token`: `Address`

**Return Type:** `Vec<Payout>`

```rust
let payouts = splitter.distribute(&buyer, &collection, &token_id, &1_000_i128, &payment_token);
```

---

### CollectionAccessControl::initialize

*Module/Contract*: `contracts/collection-access-control`

One-time configuration of the collection permission registry with a contract-wide admin.

**Parameters:**
- `admin`: `Address`

**Return Type:** `()`

```rust
acl.initialize(&admin);
```

---

### CollectionAccessControl::register_collection

*Module/Contract*: `contracts/collection-access-control`

Registers a collection contract and names its owner. Admin only, once per collection.

**Parameters:**
- `caller`: `Address`
- `collection`: `Address`
- `owner`: `Address`

**Return Type:** `()`

```rust
acl.register_collection(&admin, &collection, &owner);
```

---

### CollectionAccessControl::grant_permissions

*Module/Contract*: `contracts/collection-access-control`

Adds permission bits to an account without disturbing existing grants. Caller must hold `PERM_ADMIN` for the collection.

**Parameters:**
- `caller`: `Address`
- `collection`: `Address`
- `account`: `Address`
- `permissions`: `u32`

**Return Type:** `()`

```rust
acl.grant_permissions(&owner, &collection, &artist, &(PERM_MINTER | PERM_METADATA));
```

---

### CollectionAccessControl::has_permission

*Module/Contract*: `contracts/collection-access-control`

Returns `true` when the account holds every bit in `permission`, including default permissions and the owner's implicit `PERM_ALL`.

**Parameters:**
- `collection`: `Address`
- `account`: `Address`
- `permission`: `u32`

**Return Type:** `bool`

```rust
if acl.has_permission(&collection, &artist, &PERM_MINTER) { /* mint */ }
```

---

### NftDropContract::configure

*Module/Contract*: `contracts/nft-drop`

One-time configuration of a blind-mint NFT drop: admin, payment token, phase prices, supply caps, sale window, reveal time and optional access-control contract.

**Parameters:**
- `admin`: `Address`
- `payment_token`: `Address`
- `allowlist_price`: `i128`
- `public_price`: `i128`
- `max_supply`: `u32`
- `per_address_limit`: `u32`
- `start_time`: `u64`
- `end_time`: `u64`
- `reveal_time`: `u64`
- `access_control`: `Option<Address>`

**Return Type:** `()`

```rust
drop.configure(&admin, &payment, &40, &200, &1_000, &2, &0, &0, &1_800_000_000, &None);
```

---

### NftDropContract::blind_mint

*Module/Contract*: `contracts/nft-drop`

Mints the next asset to the buyer at the current phase's price while keeping its metadata hidden until revealed. Returns the new token id.

**Parameters:**
- `buyer`: `Address`

**Return Type:** `u64`

```rust
let token_id = drop.blind_mint(&buyer);
```

---

### NftDropContract::reveal

*Module/Contract*: `contracts/nft-drop`

Publishes the metadata URI for a blind-minted asset at/after `reveal_time`. Admin (or a `PERM_ADMIN` holder when access control is configured) only.

**Parameters:**
- `caller`: `Address`
- `token_id`: `u64`
- `uri`: `String`

**Return Type:** `()`

```rust
drop.reveal(&admin, &token_id, &String::from_str(&env, "ipfs://nft-drop/0"));
```

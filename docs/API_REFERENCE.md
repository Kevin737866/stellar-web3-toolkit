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

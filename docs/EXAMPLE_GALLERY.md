# Soroban Smart Contract Example Gallery

Welcome to the **Stellar Web3 Toolkit Example Gallery**. This gallery provides curated, runnable smart contract interaction examples for developers building on Stellar & Soroban.

---

## 1. Automated Market Maker (AMM) Liquidity & Swap

Demonstrates initializing liquidity pools, depositing reserves, and executing exact-in swaps on Soroban.

- **Category**: DeFi / AMM
- **Contract WASM Hash**: `a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef`
- **CLI Run Command**: `stellar-toolkit example run --id amm-pool-swap --network testnet`

```rust
use soroban_sdk::{Env, Address};
use amm_pool::AmmPoolClient;

let env = Env::default();
let client = AmmPoolClient::new(&env, &contract_id);
client.deposit(&user, &1000_i128, &2000_i128);
let out = client.swap(&user, &token_a, &100_i128, &180_i128);
```

---

## 2. Stateful Payment Channel Settlement

Showcases opening payment channels, off-chain state updates with HMAC signatures, and channel closing with on-chain dispute resolution.

- **Category**: Layer 2 / Payments
- **Contract WASM Hash**: `b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef12`
- **CLI Run Command**: `stellar-toolkit example run --id payment-channel-offchain --network testnet`

```rust
let channel = PaymentChannel::open(&env, &alice, &bob, 5000_i128, 86400);
let signature = channel.sign_state_update(nonce, alice_bal, bob_bal);
channel.close(&env, &signature);
```

---

## 3. One-Click Airdrop Claim UX

Allows eligible accounts to claim token airdrops with cryptographic proof verification and single-click execution.

- **Category**: Token Distribution
- **Contract WASM Hash**: `c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef1234`
- **CLI Run Command**: `stellar-toolkit example run --id one-click-airdrop --network testnet`

```rust
use stellar_toolkit::OneClickAirdropClaimer;

let claimer = OneClickAirdropClaimer::new();
let tx = claimer.claim_airdrop("GCLAIMANT...", "airdrop-event-2026", &proof)?;
```

---

## 4. Digital Asset Marketplace & Royalty Splitting

Demonstrates escrowing a SEP-41 digital asset for sale, settling a purchase with a marketplace fee, and paying creator royalties to multiple receivers on the secondary sale.

- **Category**: NFTs / Tokens
- **Contract WASM Hash**: `d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef123456`
- **CLI Run Command**: `stellar-toolkit example run --id marketplace-royalty --network testnet`

```rust
use marketplace_contract::MarketplaceContractClient;
use royalty_splitter::RoyaltySplitterClient;

let listing_id = market.create_listing(&seller, &asset, &1_u128, &1_i128, &1_000_i128, &payment_token);
let proceeds = market.buy(&buyer, &listing_id);
let payouts = splitter.distribute(&buyer, &asset, &1_u128, &1_000_i128, &payment_token);
```

---

## 5. Phased Blind-Mint NFT Drop with Collection Roles

Runs a phased NFT drop where buyers blind mint before metadata is revealed, with privileged drop operations delegated to a collection role registry.

- **Category**: NFTs / Tokens
- **Contract WASM Hash**: `e5f678901234567890abcdef1234567890abcdef1234567890abcdef1234567890`
- **CLI Run Command**: `stellar-toolkit example run --id nft-drop --network testnet`

```rust
use collection_access_control::{CollectionAccessControlClient, PERM_ADMIN};
use nft_drop::{NftDropContractClient, SalePhase};

// Grant a curator admin rights over the drop's collection...
acl.register_collection(&admin, &drop_id, &admin);
acl.grant_permissions(&admin, &drop_id, &curator, &PERM_ADMIN);

// ...so the curator can open the sale and reveal metadata.
drop.set_phase(&curator, &SalePhase::Public);
let token_id = drop.blind_mint(&collector);
drop.reveal(&curator, &token_id, &uri);
```

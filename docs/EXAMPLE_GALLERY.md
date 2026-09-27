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

## 4. NFT / SFT Asset Contract

Mints non-fungible and semi-fungible tokens under one collection, tracks sole
ownership, and gates metadata updates on the holder's own signature.

- **Category**: Assets / NFTs
- **Docs**: [`docs/NFT_SFT_CONTRACT.md`](./NFT_SFT_CONTRACT.md)
- **CLI Run Command**: `stellar-toolkit example run --id nft-sft-metadata --network testnet`

```rust
use soroban_sdk::{Env, String};
use nft_sft_contract::NftSftContractClient;

let client = NftSftContractClient::new(&env, &contract_id);
client.initialize(&admin, &name, &symbol, &0, &base_uri, &0);

// One-of-a-kind: owner_of reports the holder.
client.mint(&alice, &1, &1, &String::from_str(&env, "Genesis"), &uri);

// Divisible: no owner until the whole supply sits with one address.
client.mint(&alice, &2, &10, &String::from_str(&env, "Tickets"), &uri);
client.transfer(&alice, &bob, &2, &4);   // divided  -> owner_of is None
client.transfer(&bob, &alice, &2, &6);   // whole    -> owner_of is Some(alice)
```

---

## 5. Real-World Asset Fractionalization

Escrows a whole asset and issues a SEP-41 share token for it, with full-supply
redemption.

- **Category**: Assets / RWA
- **Docs**: [`docs/RWA_FRACTIONALIZATION.md`](./RWA_FRACTIONALIZATION.md)
- **CLI Run Command**: `stellar-toolkit example run --id rwa-fractionalize --network testnet`

```rust
use rwa_fractionalizer::RwaFractionalizerClient;

let client = RwaFractionalizerClient::new(&env, &contract_id);
client.initialize(&admin, &underlying_token);

// Escrow the issuer's asset, mint shares.
client.fractionalize(&issuer, &10_000, &2, &String::from_str(&env, "ipfs://rwa/1"));
client.transfer(&issuer, &alice, &5_000);

// Redemption needs the whole outstanding supply in one hand.
client.transfer(&alice, &issuer, &5_000);
client.redeem(&issuer, &issuer);
```

---

## 6. Merkle-Proof Airdrop

Runs an airdrop for thousands of recipients at constant cost per claim, using an
off-chain Merkle root and on-chain sibling proofs.

- **Category**: Token Distribution
- **Docs**: [`docs/AIRDROP_MERKLE.md`](./AIRDROP_MERKLE.md)
- **CLI Run Command**: `stellar-toolkit example run --id merkle-airdrop-claim --network testnet`

```rust
use airdrop_merkle::AirdropMerkleClient;

let client = AirdropMerkleClient::new(&env, &contract_id);
client.initialize(&admin, &airdrop_token, &0);
client.set_merkle_root(&root, &total);
client.fund(&funder, &total);

// The recipient supplies only the siblings on their own branch.
client.claim(&alice, &allocation, &to_proof(&alice));
assert!(client.is_claimed(&alice, &allocation));
```

---

## 7. Token Locker with Delegates

Custodies SEP-41 tokens so they can be vested to a recipient or spent by a
capped, expiring delegate.

- **Category**: Assets / Custody
- **Docs**: [`docs/TOKEN_LOCKERS.md`](./TOKEN_LOCKERS.md)
- **CLI Run Command**: `stellar-toolkit example run --id token-locker-vest --network testnet`

```rust
use token_locker::TokenLockerClient;

let client = TokenLockerClient::new(&env, &contract_id);
client.initialize(&admin, &name, &symbol);
client.deposit(&holder, &token, &3_000);

// Irrevocable vest of 500 units, releasable from ledger 100.
let id = client.lock(&holder, &token, &recipient, &500, &100);
env.ledger().set_sequence_number(100);
client.release(&id);                                 // credited to the recipient

// Delegated spending, capped and expiring.
client.set_delegate(&holder, &delegate, &token, &800, &500);
client.move_from(&holder, &token, &delegate, &payee, &300);
```

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

# Soroban Smart Contract Development Getting-Started Guide

This tutorial walks contract developers through setup, architecture, testing, compilation, deployment, and client integration for Soroban smart contracts on the Stellar network using the `stellar-web3-toolkit`.

---

## 1. Environment & Toolchain Setup

### Prerequisites

Ensure you have Rust, Cargo, and the WebAssembly target installed:

```bash
# 1. Install Rust (toolchain 1.77+ recommended)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Add Wasm target for Soroban contract compilation
rustup target add wasm32-unknown-unknown

# 3. Install Stellar CLI
cargo install --locked stellar-cli --features opt
```

---

## 2. Contract Project Structure

A standard Soroban contract in this toolkit uses the following layout:

```text
contracts/amm-pool/
├── Cargo.toml
└── src/
    ├── lib.rs
    └── test.rs
```

### `Cargo.toml` Configuration

```toml
[package]
name = "amm-pool"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
soroban-sdk = { workspace = true }

[dev-dependencies]
soroban-sdk = { workspace = true, features = ["testutils"] }
```

---

## 3. Writing Your First Soroban Contract

Here is a clean implementation of a stateful counter and liquidity pool guard contract (`contracts/amm-pool/src/lib.rs`):

```rust
#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, Symbol};

const COUNTER_KEY: Symbol = symbol_short!("COUNTER");

#[contract]
pub struct LiquidityPool;

#[contractimpl]
impl LiquidityPool {
    /// Initialize pool state and counter.
    pub fn initialize(env: Env, admin: Address) -> u32 {
        admin.require_auth();
        env.storage().instance().set(&COUNTER_KEY, &1u32);
        1
    }

    /// Increment invocation counter and return new count.
    pub fn increment(env: Env) -> u32 {
        let count: u32 = env.storage().instance().get(&COUNTER_KEY).unwrap_or(0);
        let new_count = count.saturating_add(1);
        env.storage().instance().set(&COUNTER_KEY, &new_count);
        new_count
    }

    /// Read current counter state.
    pub fn get_count(env: Env) -> u32 {
        env.storage().instance().get(&COUNTER_KEY).unwrap_or(0)
    }
}
```

---

## 4. Testing Your Contract

Soroban provides built-in test utilities in Rust without requiring a running node (`contracts/amm-pool/src/test.rs`):

```rust
#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, Address, Env};

#[test]
fn test_pool_counter_lifecycle() {
    let env = Env::default();
    let contract_id = env.register_contract(None, LiquidityPool);
    let client = LiquidityPoolClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();

    let init_val = client.initialize(&admin);
    assert_eq!(init_val, 1);

    assert_eq!(client.increment(), 2);
    assert_eq!(client.increment(), 3);
    assert_eq!(client.get_count(), 3);
}
```

Run tests using cargo:

```bash
cargo test --workspace
```

---

## 5. Compiling to WebAssembly (Wasm)

Build release Wasm binaries for all contracts:

```bash
# Using cargo directly
cargo build --target wasm32-unknown-unknown --release

# Or using the stellar-toolkit CLI helper
cargo run -p stellar-toolkit -- compile
```

The compiled binaries will be output to `target/wasm32-unknown-unknown/release/`.

---

## 6. Deploying to Testnet & Invoking via CLI

### 6.1 Configuring Identity & Network

```bash
# Generate a testnet keypair
stellar keys generate Alice --global

# Fund account via Friendbot
stellar keys fund Alice --network testnet
```

### 6.2 Deploying Wasm & Initializing

```bash
# 1. Install contract Wasm code on-chain
WASMHASH=$(stellar contract install \
  --wasm target/wasm32-unknown-unknown/release/amm_pool.wasm \
  --source Alice \
  --network testnet)

# 2. Deploy contract instance
CONTRACT_ID=$(stellar contract deploy \
  --wasm-hash $WASMHASH \
  --source Alice \
  --network testnet)

# 3. Invoke contract method
stellar contract invoke \
  --id $CONTRACT_ID \
  --source Alice \
  --network testnet \
  -- \
  increment
```

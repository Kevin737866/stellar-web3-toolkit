# Stellar & Soroban SDK Version Migration Guide

This guide provides a comprehensive walkthrough for upgrading codebase dependencies across `stellar-sdk` and `soroban-sdk` versions, detailing breaking changes, API renames, type unification, and migration steps for both Rust smart contracts and JavaScript/TypeScript clients.

---

## 1. Overview of SDK Evolution

With recent releases of the Stellar ecosystem tooling:
- **`stellar-sdk` (JS/TS)** unified the standalone `@stellar/soroban-client` package into `stellar-sdk` (v12+).
- **`soroban-sdk` (Rust)** introduced storage TTL extensions, contract event enhancements, and streamlined symbol parsing.

| Legacy SDK / Pattern | Modern SDK / Pattern | Key Change Description |
|---|---|---|
| `@stellar/soroban-client` | `stellar-sdk` (`rpc.Server`) | Soroban RPC client moved directly into `stellar-sdk` under the `rpc` namespace. |
| `sorobanClient.Server(url)` | `new rpc.Server(url)` | Single unified SDK import for Stellar Horizon and Soroban RPC. |
| `xdr.ScVal` manual construction | `nativeToScVal` / `scValToNative` | High-level helpers convert JS types to XDR values automatically. |
| `env.storage().persistent().has()` | `env.storage().persistent().extend_ttl()` | Storage entries require explicit TTL bump management to avoid data archival. |
| `Symbol::from_str(&env, "name")` | `symbol_short!("name")` | Short symbols (up to 9 chars) use zero-allocation `symbol_short!` macro. |

---

## 2. JavaScript / TypeScript Client Migration

### 2.1 Updating Dependencies in `package.json`

Replace `@stellar/soroban-client` with `stellar-sdk`:

```diff
  "dependencies": {
-   "@stellar/soroban-client": "^1.0.0",
-   "stellar-sdk": "^10.4.0"
+   "stellar-sdk": "^12.3.0"
  }
```

### 2.2 Updating Client Imports & Contract Invocations

#### Legacy Import Pattern (`soroban-client`)

```typescript
// LEGACY (Pre-v12)
import { Server, Contract, xdr } from "@stellar/soroban-client";

const server = new Server("https://soroban-testnet.stellar.org");
const contract = new Contract("C123...");
```

#### Modern Import Pattern (`stellar-sdk` v12+)

```typescript
// MODERN (v12+)
import { rpc, Contract, nativeToScVal, scValToNative, TransactionBuilder, Networks } from "stellar-sdk";

const server = new rpc.Server("https://soroban-testnet.stellar.org");
const contract = new Contract("C123...");

// Invoking contract method with native JavaScript type conversion
const tx = new TransactionBuilder(account, { fee: "100", networkPassphrase: Networks.TESTNET })
  .addOperation(
    contract.call(
      "transfer",
      nativeToScVal(fromAddress, { type: "address" }),
      nativeToScVal(toAddress, { type: "address" }),
      nativeToScVal(10000000n, { type: "i128" })
    )
  )
  .setTimeout(30)
  .build();
```

---

## 3. Rust Smart Contract (`soroban-sdk`) Migration

### 3.1 `Cargo.toml` Workspace Configuration

Update workspace dependency definitions:

```toml
[workspace.dependencies]
soroban-sdk = "20.5.0"
```

### 3.2 Storage & TTL Bumping Migration

In `soroban-sdk` v20+, all persistent and instance storage entries should be periodically extended to prevent data archival on-chain.

#### Legacy Storage Access

```rust
// LEGACY
pub fn get_balance(env: Env, user: Address) -> i128 {
    env.storage().persistent().get(&DataKey::Balance(user)).unwrap_or(0)
}
```

#### Modern Storage Access with TTL Bumping

```rust
// MODERN (v20+)
pub fn get_balance(env: Env, user: Address) -> i128 {
    let key = DataKey::Balance(user);
    if let Some(balance) = env.storage().persistent().get(&key) {
        // Extend TTL by at least 10,000 ledgers (~14 days) if remaining TTL is under 1,000 ledgers
        env.storage().persistent().extend_ttl(&key, 1000, 10000);
        balance
    } else {
        0
    }
}
```

---

## 4. Migration Verification Checklist

- [x] Uninstall legacy `@stellar/soroban-client` package.
- [x] Update imports to use `stellar-sdk` namespace `rpc.Server`.
- [x] Replace manual XDR builder calls with `nativeToScVal` and `scValToNative`.
- [x] Ensure all persistent contract storage calls use `extend_ttl`.
- [x] Execute `cargo test --workspace` to verify contract compatibility.

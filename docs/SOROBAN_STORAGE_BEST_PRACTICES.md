# Soroban Smart Contract Storage Best Practices

This guide outlines architectural patterns, storage model selection, TTL (Time-To-Live) management, footprint minimization, and cost optimization strategies for storing state in Soroban contracts.

---

## 1. Soroban Storage Types Comparison

Soroban provides three primary storage types:

| Storage Type | Persistence / Lifetime | Rent Costs | Typical Use Cases |
|---|---|---|---|
| **Instance Storage** | Tied to contract instance; deleted if contract dies | Low overhead | Contract-wide admin keys, global flags, operational metrics. |
| **Persistent Storage** | Bound to user data keys; strictly persistent if extended | Rent paid per byte per ledger | User account balances, vault deposits, liquidity shares. |
| **Temporary Storage** | Short-lived; automatically expires without archive recovery | Lowest cost | Nonce validation, short-term flash loans, claimable balances. |

---

## 2. Best-Practice Patterns

### 2.1 Storage Key Structuring

Use strongly-typed `#[contracttype]` Enums as storage keys rather than raw strings to reduce serialization bytes and eliminate key collision risks:

```rust
use soroban_sdk::{contracttype, Address};

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataKey {
    Admin,
    FeeRate,
    Balance(Address),
    Allowance { from: Address, spender: Address },
    Nonce(Address),
}
```

### 2.2 Time-To-Live (TTL) Extension Strategy

In Soroban v20+, persistent and instance storage entries must be extended periodically (`extend_ttl`). Failure to extend TTL leads to state archival, requiring expensive restoration transactions.

```rust
use soroban_sdk::{Env, Address};

const BALANCE_TTL_THRESHOLD: u32 = 2_000; // ~3 days
const BALANCE_TTL_BUMP: u32 = 100_000;    // ~140 days

pub fn read_balance_with_ttl(env: &Env, key: &DataKey) -> i128 {
    if let Some(balance) = env.storage().persistent().get::<_, i128>(key) {
        // Extend TTL if remaining lifespan drops below threshold
        env.storage().persistent().extend_ttl(
            key,
            BALANCE_TTL_THRESHOLD,
            BALANCE_TTL_BUMP,
        );
        balance
    } else {
        0
    }
}
```

### 2.3 Minimizing Storage Footprint

- Store compact integer types (`u32`, `u64`, `i128`) instead of strings whenever possible.
- Avoid storing large arrays or unindexed lists directly inside a single key. Use mapping keys (`DataKey::Item(index)`) for linear scaling.

---

## 3. Account Abstraction & Session Key Storage Pattern

For account abstraction and session key UX:
- Store session key authorizations in **Temporary Storage** if the session expires within 24 hours.
- Store multi-guardian recovery thresholds in **Persistent Storage** with explicit TTL extension upon account configuration changes.

```rust
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionStorageKey {
    SessionKey(Address),
    GuardianRecoveryConfig(Address),
}
```

---

## 4. Summary Checklist

- [x] Use `#[contracttype]` enums for type-safe, minimal footprint storage keys.
- [x] Categorize state into Instance, Persistent, or Temporary storage.
- [x] Always invoke `extend_ttl()` when reading or writing critical persistent data.
- [x] Prefer Temporary storage for nonces, session authorizations, and temporary claims.
- [x] Audit storage rent costs prior to mainnet deployment.

# Session-Based UX & Account Abstraction Architecture

This guide details the session-based UX capability, session key lifecycle, transaction signing delegation, and social guardian recovery primitives implemented in `stellar-web3-toolkit`.

---

## 1. Architecture & Overview

Session-based account abstraction allows users to sign transactions via short-lived, constrained **Session Keys** without repeatedly prompting wallet popup approvals or exposing primary master private keys.

```text
+-----------------------+         +----------------------------+
|  Primary User Wallet  | ------> | AccountAbstractionManager  |
|   (Master Key / G...) |         |  - Registers Session Keys  |
+-----------------------+         |  - Enforces Policies       |
                                  +----------------------------+
                                                |
                                                v
                                  +----------------------------+
                                  |   Active Session Key       |
                                  |  - Expiration TTL          |
                                  |  - Contract Whitelist      |
                                  |  - Max Spend Limit         |
                                  +----------------------------+
```

---

## 2. Key Capabilities

### 2.1 Session Key Management (`crates/stellar-toolkit/src/session_keys.rs`)

- **Session Policy**: Binds expiration Unix timestamp, whitelisted contract IDs, allowed method names, and maximum spending limits (in stroops/tokens).
- **Policy Enforcement**: `validate_and_record_call()` checks expiration, revocation status, contract and method authorization, and spend limits before signing.
- **Transaction Signing Delegation**: `sign_with_session()` signs transaction payloads using active session keys.
- **Revocation**: Master keys can instantly revoke session keys via `revoke_session()`.

### 2.2 Social Recovery UX

- **Multi-Guardian Recovery**: Supports $M$-of-$N$ threshold recovery.
- **Recovery Request Flow**: Guardians confirm proposed key rotation asynchronously via `initiate_recovery()` and `confirm_recovery()`.

---

## 3. Rust Code Usage Example

```rust
use stellar_toolkit::session_keys::{
    AccountAbstractionManager, SessionKey, SessionPolicy,
};
use std::collections::{HashMap, HashSet};

fn main() {
    let mut manager = AccountAbstractionManager::new();

    // 1. Define a session policy valid for 1 hour with a 10,000 unit spend limit
    let policy = SessionPolicy {
        expires_at: 1750000000,
        allowed_contracts: HashSet::from(["contract_amm".to_string()]),
        allowed_methods: HashMap::from([(
            "contract_amm".to_string(),
            HashSet::from(["swap".to_string(), "deposit".to_string()]),
        )]),
        max_spend_limit: Some(10000),
    };

    // 2. Register ephemeral session key
    let session = SessionKey::new("sess_abc123", "G_USER_ADDRESS", "PUB_EPHEMERAL_KEY", policy);
    manager.register_session(session);

    // 3. Validate and record invocation
    let result = manager.validate_and_record_call(
        "sess_abc123",
        "contract_amm",
        "swap",
        500,
        1749999000,
    );

    assert!(result.is_ok());
}
```

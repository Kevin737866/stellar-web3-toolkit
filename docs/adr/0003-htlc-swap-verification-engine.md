# ADR-0003: HTLC Atomic Swap State Verification Engine

* **Status**: Accepted
* **Date**: 2026-08-29
* **Authors**: Stellar Web3 Toolkit Core Team

## Context

Hashed Timelock Contracts (HTLCs) facilitate trustless cross-chain and cross-asset atomic swaps. State transitions must strictly validate cryptographic preimage hashes and ledger expiration timestamps to prevent funds lockup or double-spending.

## Decision

We enforce explicit state verification in `crates/atomic-swap` and `contracts/htlc-contract`:
1. Use SHA-256 preimage verification (`sha256(preimage) == hash_lock`).
2. Enforce strict ledger sequence expiration (`ledger.timestamp() >= timelock`).
3. Support automatic refund routing if timelocks expire before preimage disclosure.

## Consequences

### Positive
* Prevents unauthorized funds withdrawal without secret preimages.
* Guarantees deterministic refund path for counterparty if swap times out.
* Verified compatibility with Soroban RPC and Horizon ledger state.

### Negative
* Reclaim transactions must be submitted prior to ledger TTL expiration.

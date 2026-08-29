# Stellar & Soroban Protocol Glossary

This document provides a comprehensive glossary of domain terms, protocol primitives, and technical concepts used throughout the **Stellar Web3 Toolkit**.

---

## Terms & Concepts

### **Account**
A public-key address on the Stellar ledger identified by an `Ed25519` public key (starting with `G`). Accounts store XLM balances, asset trustlines, signers, thresholds, and sequence numbers.

### **Atomic Swap**
A cryptographic trade mechanism allowing two parties to exchange assets across different blockchains or protocols atomically without relying on a trusted intermediary.

### **Footprint**
A list of ledger keys that a Soroban smart contract transaction will read or write. Footprints enable parallel transaction execution by declaring read/write storage access upfront.

### **Hashed Timelock Contract (HTLC)**
A class of smart contract that uses cryptographic hashlocks (requiring a secret preimage to claim funds) and timelocks (enforcing an expiration ledger sequence after which funds can be refunded).

### **Horizon**
The HTTP REST API server for the Stellar network. Horizon provides developer-friendly endpoints for querying ledger history, account balances, offers, and submitting transactions.

### **Ledger**
The state database of the Stellar network. A new ledger header and state block is generated approximately every 5 seconds via the Stellar Consensus Protocol (SCP).

### **Operation**
An individual command that mutates the Stellar ledger state (e.g. `Payment`, `CreateAccount`, `ChangeTrust`, `InvokeHostFunction`). Multiple operations can be bundled inside a single transaction.

### **Preimage**
A secret byte sequence `S` such that `SHA256(S) == H`. In HTLC atomic swaps, disclosing the preimage unlocks escrowed funds.

### **Soroban**
Stellar's smart contract platform built on WebAssembly (WASM). Soroban brings Rust-based smart contracts, state isolation, and scalable execution to Stellar.

### **Soroban RPC**
An JSON-RPC endpoint dedicated to interacting with Soroban smart contracts, enabling contract invocation simulations, event subscriptions, and state reads.

### **Trustline**
An explicit record created on a Stellar account authorizing it to hold and transfer a specific non-native asset (e.g., USDC, EURC) issued by a specific account address.

### **WASM (WebAssembly)**
A binary instruction format designed as a portable compilation target for programming languages like Rust. Soroban smart contracts are compiled to WASM binaries.

### **XDR (External Data Representation)**
An IETF standard serialization format (RFC 4506) used across Stellar protocol communication, transaction signing, and ledger storage.

---

## Additional Resources
- [Stellar Developer Documentation](https://developers.stellar.org/)
- [Soroban Smart Contract Documentation](https://soroban.stellar.org/)
- [Stellar Architecture Decision Records](adr/README.md)

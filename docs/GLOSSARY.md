# Stellar & Soroban Protocol Glossary

This document provides a comprehensive glossary of domain terms, protocol primitives, and technical concepts used throughout the **Stellar Web3 Toolkit**.

---

## Terms & Concepts

### **Account**
<a id="account"></a>
A public-key address on the Stellar ledger identified by an `Ed25519` public key (starting with `G`). Accounts store XLM balances, asset trustlines, signers, thresholds, and sequence numbers.

### **Atomic Swap**
<a id="atomic-swap"></a>
A cryptographic trade mechanism allowing two parties to exchange assets across different blockchains or protocols atomically without relying on a trusted intermediary.

### **Footprint**
<a id="footprint"></a>
A list of ledger keys that a Soroban smart contract transaction will read or write. Footprints enable parallel transaction execution by declaring read/write storage access upfront.

### **Hashed Timelock Contract (HTLC)**
<a id="hashed-timelock-contract-htlc"></a>
A class of smart contract that uses cryptographic hashlocks (requiring a secret preimage to claim funds) and timelocks (enforcing an expiration ledger sequence after which funds can be refunded).

### **Horizon**
<a id="horizon"></a>
The HTTP REST API server for the Stellar network. Horizon provides developer-friendly endpoints for querying ledger history, account balances, offers, and submitting transactions.

### **Ledger**
<a id="ledger"></a>
The state database of the Stellar network. A new ledger header and state block is generated approximately every 5 seconds via the Stellar Consensus Protocol (SCP).

### **Operation**
<a id="operation"></a>
An individual command that mutates the Stellar ledger state (e.g. `Payment`, `CreateAccount`, `ChangeTrust`, `InvokeHostFunction`). Multiple operations can be bundled inside a single transaction.

### **Preimage**
<a id="preimage"></a>
A secret byte sequence `S` such that `SHA256(S) == H`. In HTLC atomic swaps, disclosing the preimage unlocks escrowed funds.

### **Soroban**
<a id="soroban"></a>
Stellar's smart contract platform built on WebAssembly (WASM). Soroban brings Rust-based smart contracts, state isolation, and scalable execution to Stellar.

### **Soroban RPC**
<a id="soroban-rpc"></a>
An JSON-RPC endpoint dedicated to interacting with Soroban smart contracts, enabling contract invocation simulations, event subscriptions, and state reads.

### **Trustline**
<a id="trustline"></a>
An explicit record created on a Stellar account authorizing it to hold and transfer a specific non-native asset (e.g., USDC, EURC) issued by a specific account address.

### **WASM (WebAssembly)**
<a id="wasm-webassembly"></a>
A binary instruction format designed as a portable compilation target for programming languages like Rust. Soroban smart contracts are compiled to WASM binaries.

### **XDR (External Data Representation)**
<a id="xdr-external-data-representation"></a>
An IETF standard serialization format (RFC 4506) used across Stellar protocol communication, transaction signing, and ledger storage.

---

## Linking to a term

Every term above has an explicit HTML anchor immediately beneath its heading, so other
documents can link straight to a definition instead of saying "see the glossary, somewhere
under Terms & Concepts". Link with a relative path and the slug:

```markdown
See [Hashed Timelock Contract (HTLC)](GLOSSARY.md#hashed-timelock-contract-htlc) for how
claims and refunds are separated.
```

The slug rule is deliberately boring, and is what the `stellar-toolkit glossary`
command reproduces: **lowercase the term, drop bold markers, replace every
non-alphanumeric run with a single hyphen, and trim leading/trailing hyphens.**
So `Hashed Timelock Contract (HTLC)` is `#hashed-timelock-contract-htlc`, and
`XDR (External Data Representation)` is `#xdr-external-data-representation`.

Those anchors are written out explicitly rather than left to GitHub's automatic
heading slugs, and they are chosen to **match GitHub's algorithm exactly**. That
matters more than it might look: the parenthetical in `### **Hashed Timelock
Contract (HTLC)**` is kept by the automatic slug (`#hashed-timelock-contract-htlc`),
which is not what a reader would guess, and an automatic slug silently changes
if the heading is ever reworded. Pinning them means the link target is stated in
the file, a test can assert it, and stripping the `<a id>` lines would not break
a single incoming link.

You can also look a term up without leaving the terminal:

```console
$ stellar-toolkit glossary timelock
```

See [`crates/stellar-toolkit/src/glossary.rs`](../crates/stellar-toolkit/src/glossary.rs)
for the lookup rules and the parser.

---

## Additional Resources
- [Stellar Developer Documentation](https://developers.stellar.org/)
- [Soroban Smart Contract Documentation](https://soroban.stellar.org/)
- [Stellar Architecture Decision Records](adr/README.md)

# ADR-0002: Soroban WASM Compilation & Optimization Pipeline

* **Status**: Accepted
* **Date**: 2026-08-29
* **Authors**: Stellar Web3 Toolkit Core Team

## Context

Soroban smart contracts compiled to WebAssembly (WASM) must meet strict execution footprint limits and bytecode size constraints on the Stellar network. Unoptimized WASM binaries incur excessive ledger storage costs and execution fees.

## Decision

We establish an automated Rust-to-WASM compilation and optimization pipeline utilizing:
1. Target `wasm32-unknown-unknown` compilation via `cargo build --target wasm32-unknown-unknown --release`.
2. Size optimization flags (`opt-level = "z"`, `codegen-units = 1`, `lto = true`, `panic = "abort"`).
3. Post-build WASM bytecode stripping and `wasm-opt` optimization pass to minimize contract size.

## Consequences

### Positive
* Substantially reduces compiled WASM bytecode size (up to 65% size reduction).
* Lowers ledger storage fees for end users.
* Guarantees reproducible builds across developer environments.

### Negative
* Requires local installation of LLVM/WASM build targets.
* Increases compilation time during release builds.

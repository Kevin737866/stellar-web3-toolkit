# Contributor Onboarding & Development Guide

Welcome to the **Stellar Web3 Toolkit** contributor guide! This document outlines step-by-step instructions for setting up your development environment, navigating the codebase, running tests, and submitting high-quality contributions.

---

## 1. Prerequisites & Toolchain Setup

To build, test, and contribute to Stellar Web3 Toolkit, install the following:

- **Rust Toolchain** (1.75 or later):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **WASM Target**:
  ```bash
  rustup target add wasm32-unknown-unknown
  ```
- **Cargo Tools & Formatters**:
  ```bash
  rustup component add rustfmt clippy
  ```

---

## 2. Repository Architecture Overview

```
stellar-web3-toolkit/
├── crates/
│   ├── stellar-toolkit/     # Core CLI binary & command implementations
│   ├── atomic-swap/         # HTLC atomic swap state engine & helpers
│   ├── payment-channel/     # Off-chain payment channel manager
│   ├── watchtower/          # Dispute monitoring service
│   ├── channel-router/      # Payment routing algorithm
│   └── stellar-did/         # W3C DID method implementation for Stellar
├── contracts/
│   ├── htlc-contract/       # Soroban HTLC smart contract
│   ├── payment-channel-contract/ # On-chain channel settlement contract
│   └── amm-pool/            # Soroban AMM liquidity pool
└── docs/
    ├── adr/                 # Architecture Decision Records
    ├── GLOSSARY.md          # Protocol terms reference
    └── SECURITY_AUDIT.md    # Security guidelines
```

---

## 3. Development Workflow

### Step 1: Fork & Clone
```bash
git clone https://github.com/<your-username>/stellar-web3-toolkit.git
cd stellar-web3-toolkit
```

### Step 2: Create a Feature Branch
```bash
git checkout -b feat/my-new-feature
```

### Step 3: Build Workspace
```bash
cargo build --workspace
```

### Step 4: Run Tests & Quality Checks
```bash
# Run unit & integration tests
cargo test --workspace

# Check formatting
cargo fmt --check

# Run linter
cargo clippy --all-targets --all-features -- -D warnings
```

---

## 4. Code Standards & Pull Request Checklist

When preparing a Pull Request:
- Ensure all automated tests (`cargo test`) pass cleanly.
- Follow existing Rust idioms, error types (`thiserror`/`anyhow`), and module layout.
- Include unit tests for any new features or bug fixes.
- If introducing an architectural change, submit an [ADR](adr/template.md).
- Link relevant GitHub issues using closing keywords (e.g. `Closes #144`).

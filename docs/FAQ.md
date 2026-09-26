# Frequently Asked Questions

Answers to the questions that come up most often when working in the **Stellar Web3 Toolkit**: building it, testing it, extending it, and keeping its Soroban state alive.

If your question is not answered here, the [Glossary](GLOSSARY.md) explains the protocol terminology and the [Contributor Onboarding Guide](CONTRIBUTING_ONBOARDING.md) walks through the full development workflow.

## Table of Contents

- [Getting Started](#getting-started)
  - [What do I need installed?](#what-do-i-need-installed)
  - [How do I build the toolkit?](#how-do-i-build-the-toolkit)
  - [How do I run the tests?](#how-do-i-run-the-tests)
  - [How do I build the WASM contracts?](#how-do-i-build-the-wasm-contracts)
- [Contracts and Crates](#contracts-and-crates)
  - [What is the difference between `contracts/` and `crates/`?](#what-is-the-difference-between-contracts-and-crates)
  - [Which contracts are deployable?](#which-contracts-are-deployable)
  - [What is the factory/pool/router split?](#what-is-the-factorypoolrouter-split)
- [Soroban Storage](#soroban-storage)
  - [Why does my contract state expire?](#why-does-my-contract-state-expire)
  - [How do I auto-extend a storage TTL?](#how-do-i-auto-extend-a-storage-ttl)
  - [Which TTL policy should I use?](#which-ttl-policy-should-i-use)
  - [Does extending a TTL cost anything?](#does-extending-a-ttl-cost-anything)
- [Documentation](#documentation)
  - [How do I propose an architecture decision?](#how-do-i-propose-an-architecture-decision)
  - [How do I check that documentation links still work?](#how-do-i-check-that-documentation-links-still-work)
- [Contributing](#contributing)
  - [What does CI check?](#what-does-ci-check)
  - [How do I keep a doc link from breaking?](#how-do-i-keep-a-doc-link-from-breaking)

## Getting Started

### What do I need installed?

A Rust toolchain and the WebAssembly target. The pinned version lives in `rust-toolchain.toml`, so `rustup` will pick it up automatically:

```bash
rustup target add wasm32-unknown-unknown
```

Docker is optional, but `scripts/reproducible-build.sh` uses it to reproduce the CI build locally. See [Reproducible Builds](REPRODUCIBLE_BUILDS.md) for details.

### How do I build the toolkit?

```bash
cargo build --release
```

To build everything as WASM the way CI does — excluding the host-only crates that cannot target `wasm32-unknown-unknown`:

```bash
cargo build --workspace \
  --exclude stellar-toolkit --exclude stellar-did --exclude payment-channel \
  --exclude channel-router --exclude channel-simulator --exclude watchtower \
  --exclude atomic-swap --exclude soroban-ttl \
  --target wasm32-unknown-unknown --release
```

### How do I run the tests?

```bash
cargo test
```

Tests are colocated with the code they cover, in `#[cfg(test)] mod tests` blocks, so a failing test names the unit it belongs to. Contract tests use the Soroban test environment (`Env::default()` plus `register_contract`), which means they run natively and need no network or node.

The routing and topology tests live in dedicated crates and are also run on their own in CI:

```bash
cargo test --package channel-simulator
cargo test --package channel-router
```

### How do I build the WASM contracts?

Use the helper script so the build matches CI, including the `SOURCE_DATE_EPOCH` normalisation that makes the output byte-for-byte reproducible:

```bash
./scripts/reproducible-build.sh
```

To compare a local build against a reference set of checksums:

```bash
./scripts/verify-bytecode.sh --reference path/to/checksums.txt
```

## Contracts and Crates

### What is the difference between `contracts/` and `crates/`?

`contracts/` holds deployable Soroban contracts. They are `#![no_std]`, compile to `wasm32-unknown-unknown`, and their entrypoints are annotated with `#[contractimpl]`.

`crates/` holds host-side libraries and binaries: SDKs, routers, simulators and shared helpers. They build for the host and are excluded from the WASM build.

Shared building blocks that contracts depend on still live in `crates/` — `soroban-ttl` is the helper crate that every contract uses to keep its storage entries alive.

### Which contracts are deployable?

| Package | Purpose |
|:--|:--|
| `htlc-contract` | Hashed timelock contracts for atomic cross-asset swaps |
| `amm-pool` | Constant-product liquidity pool, also a SEP-41 LP token |
| `amm-factory` | Deploys pools for token pairs and resolves pair addresses |
| `amm-router` | Multi-hop swap routing across pools |
| `payment-channel-contract` | Off-chain payment channel state and HTLCs |

### What is the factory/pool/router split?

The factory owns the mapping from a token pair to its pool and deploys new pools permissionlessly. Each pool holds the reserves and the LP balances for exactly one pair. The router finds a path across several pools and performs the hops, so callers do not have to discover pools themselves.

`get_pair` on the factory is the canonical lookup: it sorts the two token addresses, so `get_pair(a, b)` and `get_pair(b, a)` return the same pool.

## Soroban Storage

### Why does my contract state expire?

Soroban entries are rented, not permanent. Persistent and temporary entries carry a remaining lifespan measured in ledgers, and once it runs out the entry is **archived** — it stops being readable until someone submits a paid restore transaction. Instance storage follows the lifetime of the contract instance and is archived along with it.

Archived state is the most common cause of "my balances vanished" bug reports on Soroban, and the fix is always the same: keep the entry alive while it is still in use.

### How do I auto-extend a storage TTL?

Use the `soroban-ttl` crate. Each helper takes an `Env` and a `TtlPolicy`:

```rust
use soroban_sdk::Env;
use soroban_ttl::{extend_instance, TtlPolicy};

fn record_deposit(env: &Env) {
    env.storage().instance().set(&DataKey::Total, &1_000i128);
    extend_instance(env, TtlPolicy::BALANCE);
}
```

There is one helper per storage tier — `extend_instance`, `extend_persistent` and `extend_temporary` — and they all follow the same rule: if the entry's remaining lifespan is already above the policy threshold, nothing happens; otherwise the lifespan is pushed out to the policy's target.

Call the helper wherever state is read or written. Writes are the obvious place, but reads matter too: an integrator polling `get_swap` or `get_reserves` is still depending on that entry, so those paths extend as well. `htlc-contract` and `amm-pool` both follow this pattern.

### Which TTL policy should I use?

`TtlPolicy` ships three presets, chosen by how long the state can safely go untouched:

| Preset | Threshold | Extend to | Use for |
|:--|--:|--:|:--|
| `TtlPolicy::TRANSIENT` | 6 hours | 24 hours | Scratch state: nonces, replay guards, in-flight routing |
| `TtlPolicy::BALANCE` | 2,000 ledgers | 100,000 ledgers | User balances, allowances, pool and factory registries |
| `TtlPolicy::LONG_LIVED` | 3 days | 180 days | State that must survive long inactivity, such as an atomic swap a counterparty may claim late |

`TtlPolicy::BALANCE` intentionally matches the constants in [Soroban Storage Best Practices](SOROBAN_STORAGE_BEST_PRACTICES.md), and a test asserts the two stay in agreement. For anything else, build a policy with `TtlPolicy::hours(threshold, extend_to)` or `TtlPolicy::days(threshold, extend_to)` rather than hand-counting ledgers.

### Does extending a TTL cost anything?

Yes — rent is proportional to the remaining lifespan, so a larger `extend_to` costs more. That is exactly why the threshold exists: an entry with plenty of life left is left alone, and the contract only pays when an entry is genuinely at risk. A fresh entry is therefore not bumped at all under `TtlPolicy::BALANCE`, because the network's default entry lifetime is already above its threshold.

## Documentation

### How do I propose an architecture decision?

1. Copy [template.md](adr/template.md).
2. Take the next sequential number, for example `0004-your-title.md`.
3. Fill in the **Context**, **Decision** and **Consequences** sections.
4. Add a row to the index in [the ADR README](adr/README.md) with its status and date.
5. Open a pull request.

`scripts/check-doc-links.py` validates step 4 for you: the index is a table of relative links, and a row pointing at a file that does not exist fails the check.

### How do I check that documentation links still work?

```bash
python3 scripts/check-doc-links.py
```

It walks every Markdown file in the repository and verifies that each relative link resolves to a real file, and that each `#anchor` fragment matches a heading or explicit `<a id="...">` in the target document. External links are skipped rather than fetched, so the check is hermetic and works offline.

It runs in CI, and it has its own test suite:

```bash
python3 scripts/test_check_doc_links.py
```

## Contributing

### What does CI check?

`cargo fmt`, `cargo clippy` with warnings denied, builds for `wasm32-unknown-unknown` and the host, the test suite, routing benchmarks, `cargo audit`, a reproducible double WASM build compared by checksum, generated documentation, and the documentation link check.

### How do I keep a doc link from breaking?

Prefer explicit anchors. A link to `doc.md#some-heading` breaks the moment someone rewords the heading, and nothing warns you until a reader clicks it. When a deep link is worth keeping, pin it with an HTML anchor that is not derived from prose:

```markdown
<a id="ttl-policy-table"></a>
### TTL policy table
```

`check-doc-links.py` validates explicit anchors alongside generated heading slugs, so a pinned link is just as protected as a generated one.

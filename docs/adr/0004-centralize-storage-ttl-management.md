# ADR-0004: Centralize Storage TTL Management in a Shared Crate

- **Status**: Accepted
- **Date**: 2026-09-26
- **Deciders**: Stellar Web3 Toolkit maintainers
- **Relates to**: [ADR-0001](0001-record-architecture-decisions.md), [Soroban Storage Best Practices](../SOROBAN_STORAGE_BEST_PRACTICES.md)

## Context

Soroban storage entries are rented rather than permanent. Every persistent and temporary entry, and the contract instance entry that backs instance storage, carries a remaining lifespan measured in ledgers. When that lifespan runs out the entry is **archived**: it stops being readable until a paid restore transaction is submitted.

[ADR-0001](0001-record-architecture-decisions.md) established the practice of recording architectural decisions, and [Soroban Storage Best Practices](../SOROBAN_STORAGE_BEST_PRACTICES.md) documents the threshold/bump pattern for keeping entries alive. The pattern was described but never implemented: no contract in the workspace called `extend_ttl`, so every entry in `htlc-contract`, `amm-pool` and `amm-factory` was on track to be archived regardless of use.

Left alone, the obvious fix is to sprinkle `extend_ttl` calls with hand-picked constants at each call site. That has three problems:

1. **Divergence.** Two contracts that hold the same kind of state (an LP balance, a swap record) end up with different policies, and the weaker one silently becomes the bug.
2. **Magic numbers.** `extend_ttl(2_000, 100_000)` at a call site carries no indication of what those figures mean or how long they last in wall-clock terms.
3. **Untestable semantics.** The threshold/extend-to interaction is subtle — the extension is a no-op while the entry lives longer than the threshold — and it is easy to believe the code works when it has never actually been observed to extend anything.

## Decision

We introduce `soroban-ttl`, a small `no_std` host-independent crate in `crates/soroban-ttl`, as the single place where TTL policy is defined and applied.

The crate exposes a `TtlPolicy` value holding a `threshold` and an `extend_to`, both in ledgers, with constructors from wall-clock units:

- `TtlPolicy::hours(threshold_hours, extend_to_hours)`
- `TtlPolicy::days(threshold_days, extend_to_days)`

It ships three presets, so most call sites need no arithmetic at all:

| Preset | Threshold | Extend to | Intended use |
|:--|--:|--:|:--|
| `TtlPolicy::TRANSIENT` | 6 hours | 24 hours | Nonces, replay guards, in-flight routing state |
| `TtlPolicy::BALANCE` | 2,000 ledgers | 100,000 ledgers | Balances, allowances, pool and factory registries |
| `TtlPolicy::LONG_LIVED` | 3 days | 180 days | State that must outlive long inactivity, such as a swap claimed by a late counterparty |

`TtlPolicy::BALANCE` deliberately uses the same constants as `BALANCE_TTL_THRESHOLD` and `BALANCE_TTL_BUMP` in the storage guide, and a unit test asserts the two remain equal so the code and the documentation cannot drift apart.

One helper is provided per storage tier — `extend_instance`, `extend_persistent` and `extend_temporary` — each taking an `Env` and a `TtlPolicy`, and each delegating to Soroban's `extend_ttl` unchanged. The crate deliberately adds no caching, no budget accounting and no opinion about *which* keys deserve a longer life: it is a named policy plus a thin, auditable wrapper.

Contracts call these helpers on both the paths that write state and the paths that read it. Extending on reads is the part that is easy to miss: an integrator polling `get_swap` or `get_reserves` is still relying on that entry, and treating a read as a reason to keep the entry alive is what stops state from being archived out from under an active user.

## Consequences

### Positive

- Storage lifetime is decided in one file, and a policy can be changed for every contract at once.
- Contracts read as intent (`extend_instance(env, TtlPolicy::BALANCE)`) rather than as unexplained ledger counts.
- The threshold behaviour is covered by tests that assert the no-op path, the boundary, and the actual observed TTL values, so a future change to the policy cannot silently stop extending anything.
- A regression test in each contract proves the wiring, not just the helper: pool and swap state is aged past the threshold in a test ledger and then shown to be revived.

### Negative & Trade-offs

- The host-only crate list in CI's WASM build grows by one, so `soroban-ttl` must be excluded from the `wasm32-unknown-unknown` build alongside the other `crates/` members.
- Every state-touching entrypoint now performs one additional host call. When the entry is above the threshold this is cheap, but it is not free, and the cheapest arrangement would be to extend only on writes.
- A policy is a point-in-time choice. If the network's `min_persistent_entry_ttl` or `max_entry_ttl` move, a preset that no longer reaches the intended window needs revisiting.
- Choosing not to extend on read paths would be cheaper still; we accept the cost because a state entry that is being read is a state entry that is still in use.

## Compliance & Verification

The following verify this decision remains implemented:

- `crates/soroban-ttl` — unit tests for the preset arithmetic, for the documented `BALANCE` constants, and for the extend/no-op/boundary behaviour of each storage tier.
- `contracts/htlc-contract/src/lib.rs` — `ttl_tests` assert that `create_swap` pushes the instance TTL out, that reading an aged swap revives it, and that a swap abandoned past its timeout is still refundable.
- `contracts/amm-pool/src/lib.rs` — tests assert that `add_liquidity` and the read-only `get_reserves` both revive an aged pool, and that a depositor's LP balance survives the full policy window.
- `docs/FAQ.md` — the storage section documents the presets so users can pick the right one.

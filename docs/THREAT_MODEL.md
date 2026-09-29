# Threat Model

Issue #116. This document is the security work item's written half: it names the
attack surface of this repository, the mitigation that addresses each entry, and
the *automated check* that would notice if a mitigation regressed. Everything
listed under "Checked by" runs in CI or in `cargo test --workspace`.

The sibling documents are [`docs/KEY_MANAGEMENT.md`](KEY_MANAGEMENT.md) (key
material and cold storage) and [`docs/SECURITY_AUDIT.md`](SECURITY_AUDIT.md)
(the HTLC audit). Where this document and a contract's own doc comment
disagree, the code and its tests win — this is a map, not a specification.

---

## 1. Attack surface

### 1.1 Soroban contracts

| Id | Attack | Impact | Mitigation | Checked by |
|----|--------|--------|-----------|-----------|
| C1 | Unauthorized state change — a caller mutates state without `require_auth` | Total loss of the asset the contract holds | `Address::require_auth()` on every mutating entry point | Per-contract `#[should_panic]` tests; `testutils::Address` authorization tests |
| C2 | HTLC claim with a forged or replayed preimage | Funds released to the wrong party | SHA-256 preimage comparison against the stored hash, single-use swap id, expiry check before refund | `contracts/htlc-contract` tests; `docs/HTLC_IMPLEMENTATION.md` |
| C3 | Merkle airdrop claim for an address that is not in the tree | Entire allocation drained by one claimant | Leaf = `H(domain ‖ address ‖ amount)`, proof folded at exactly the published depth; the amount is part of the leaf, so it cannot be chosen by the claimant | `merkle::*` invariants (below), `contracts/airdrop-merkle` tests |
| C4 | AMM price manipulation — swap that reduces `k` | Pool drained by repeated small trades | 0.3% fee applied before `x*y = k`; reserves updated after the transfer | `contracts/amm-pool` tests; `gas::*` (`x*y>=k` in the contract's own tests) |
| C5 | Integer overflow in amount math | Panic (with `overflow-checks = true`) or wrong amount | `checked_*` / `saturating_*` everywhere in the math layer; overflow-safe restoring square root | `contracts/amm-pool/src/math.rs` property sweeps incl. `u128::MAX` |
| C6 | Reentrancy through a token callback | Double spend of an escrowed asset | State is written before external calls; no callback re-entry path | `contracts/*` integration tests |
| C7 | Self-dealing via the fee path — a swap to the pool's own address | Fee rounded into the caller's pocket | Recipient is never the pool address | `contracts/amm-pool` tests |
| C8 | Flash-loan `k` check bypass | Pool drained without repaying | Post-repayment balances checked against adjusted reserves (`flash_k_ok`) | `math_tests::flash_repay_satisfies_k` |
| C9 | Quorum forged by one signer answering repeatedly | A single key controls a "multi-party" decision | Confirmations are counted **distinctly** (`count_distinct_voters`) and capped at the validator-set size | `math_tests::duplicate_confirmations_count_once`, `large_validator_set_uses_the_fallback_path` |

### 1.2 Host-side tooling (`crates/`)

| Id | Attack | Impact | Mitigation | Checked by |
|----|--------|--------|-----------|-----------|
| T1 | Secret material committed to the repository | Full account takeover | `security secrets` scanner in CI; masked findings so the scan cannot leak the key itself | `key_hygiene::*`, incl. a scan of this repository |
| T2 | Key material written to a log by a debug print | Same as T1, but via a build log or CI transcript | Redacting `Debug` on `WalletCommand` and `GeneratedWallet`; errors mask key input | `wallet::debug_never_prints_the_phrase_or_the_secret`, `wallet::rejected_secret_key_is_not_echoed_in_the_error` |
| T3 | A mainnet deploy from a testnet config (or vice versa) | Transactions signed for the wrong chain; silent misdeployment | `env validate` checks the passphrase/network/endpoint triple and refuses `auto_fund` on mainnet | `env_config::*` |
| T4 | A production deploy without multisig or cold storage | One stolen key is enough | `config/prod.toml` must assert `[security] require_multisig` + `cold_storage_signing`; validated in CI | `env_config::missing_security_block_fails_mainnet` |
| T5 | Deployed WASM differs from the reviewed WASM | Unreviewed code with full authority | Byte-reproducible builds + checksum diff; monitoring alert `WasmHashMismatch` | `.github/workflows/ci.yml` `wasm` job, `scripts/verify-bytecode.sh` |
| T6 | Malicious npm/soroban dependency in a published artifact | Supply-chain compromise | Lockfile is committed; `cargo audit` job; contracts pinned to `soroban-sdk 21.4.0` | CI `security` job |
| T7 | Fee-bump loop that drains the account | Availability/loss of funds | `max_fee_stroops` cap and `max_bumps` limit; the ladder stops when a bump no longer raises the fee | `gas::ladder_always_raises_the_fee` invariant |
| T8 | Pagination that silently skips or repeats entries | An operator audits the wrong state and misses a problem | `pages()` is total: every filtered entry appears exactly once, in order, and the last page has no cursor | `state::pagination_visits_each_entry_once` invariant + `state_inspector::*` tests |
| T9 | Help text overflowing a narrow terminal | Options and safety warnings scroll out of view | Wrapper bounds every line to the requested width | `help::wrapped_lines_fit_the_width` invariant |
| T10 | Generated TypeScript client widening a 64-bit integer to `number` | Silent precision loss on amounts (above 2^53) | 64-bit+ Soroban integers map to `bigint`; generics are recursed | `ts_codegen::*` incl. `wide_integers_map_to_bigint`, CI `codegen check` |

### 1.3 Process and CI

| Id | Attack | Impact | Mitigation | Checked by |
|----|--------|--------|-----------|-----------|
| P1 | An unreviewed commit reaching `main` | Any of the above | CI must be green: `fmt`, `clippy -D warnings`, build, test, wasm reproducibility, audit, codegen, env config, secret scan, invariants | `.github/workflows/ci.yml` |
| P2 | Deploying from a branch that is not the reviewed one | T5 | Release workflow builds from the tagged commit and records `sha` in the audit log | `.github/workflows/release.yml` |
| P3 | Workspace member dropped from `Cargo.toml` | A crate is silently exempt from fmt/clippy/test — which is exactly how five of them were previously unbuilt | The workspace lists all 20 members; CI builds the whole workspace | `cargo build --workspace` in CI |

---

## 2. Mitigations, by kind

The mitigations above fall into four groups; when adding a feature, pick one:

1. **Type-level.** Make the wrong state unrepresentable — `QuorumStatus` instead
   of `bool`, `Durability` instead of a string, `Option<Hash>` instead of a
   sentinel.
2. **Checked arithmetic.** No bare `+`, `*`, or `-` on amounts. The release
   profile sets `overflow-checks = true` and `panic = "abort"`, so an overflow
   is a failed transaction, not a corrupted balance.
3. **Validation at the boundary.** `env validate` for configuration,
   `require_auth()` for contract entry points, `decode_secret` for key input.
   Anything crossing a trust boundary is checked before use.
4. **Automated checks.** Every mitigation above has a test or a CI job. A
   mitigation with no check is a comment.

---

## 3. Automated checks

```bash
# 1. Unit, integration and doc tests
cargo test --workspace --all-features

# 2. Lints (CI runs these with -D warnings)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

# 3. Informal verification: search for counterexamples to the invariants
cargo run -p stellar-toolkit -- verify invariants

# 4. Environment config contract (passphrase/network/security flags)
cargo run -p stellar-toolkit -- env validate

# 5. No secret material in the tree
cargo run -p stellar-toolkit -- security secrets

# 6. Reproducible WASM + supply chain
./scripts/reproducible-build.sh
./scripts/verify-bytecode.sh --reference wasm-checksums.txt
cargo audit
```

All six run in the `automated-checks`, `test`, `wasm` and `security` jobs of
`.github/workflows/ci.yml`.

### Informal verification (`verify invariants`)

The property harness is documented in
[`docs/INFORMAL_VERIFICATION.md`](INFORMAL_VERIFICATION.md). In short: it samples
randomised inputs against a stated invariant, and a failure prints the seed that
reproduces it. The security-relevant invariants currently enforced are:

| Invariant | What a counterexample would mean |
|-----------|----------------------------------|
| `merkle::proof_verifies_for_every_leaf` | Honest claimants cannot claim |
| `merkle::proof_rejects_foreign_address` | Anyone can mint an allocation |
| `merkle::leaf_authenticates_the_amount` | A claimant can choose their own amount |
| `gas::ladder_always_raises_the_fee` | Retries stall or escalate past the cap |
| `key_hygiene::every_generated_secret_key_is_flagged` | The secret scanner has a blind spot |
| `key_hygiene::masking_never_reveals_the_value` | The scanner leaks what it finds |
| `state::pagination_visits_each_entry_once` | An audit walks the wrong state |
| `help::wrapped_lines_fit_the_width` | Safety text scrolls out of view |

These are *informal*: passing means "no counterexample was found in the sampled
space", not "the property holds". They find bugs; they do not prove absence.

---

## 4. Residual risk

Accepted, with the reasoning recorded:

* **Sampled verification.** The invariant suite explores a fixed number of
  iterations per run. A narrow enough bug can hide. Increase `--iterations` or
  `--seed` when working on the corresponding code path.
* **No fuzzing of the WASM host boundary.** Contract tests run in
  `soroban-sdk`'s testutils host, not against a real node. XDR and ledger
  semantics are assumed.
* **Economic attacks.** Impermanent loss, MEV and oracle manipulation are out of
  scope here; see the AMM notes in the contract's own documentation.
* **Front-running.** `docs/SECURITY_AUDIT.md` records front-running on swap
  creation as "consider for future"; on Stellar the practical mitigation is
  short ledger windows plus slippage bounds on the caller side.
* **Rate limiting / DoS.** Public endpoints are explicitly out of scope in
  `SECURITY.md`; the CLI is a local tool.
* **Secret scanning is text-based.** No git-history mode — a deleted key is
  still in the history. See `docs/KEY_MANAGEMENT.md` §7.

---

## 5. Audit guidance

For a review of this repository, the artefacts to request, in order:

1. `cargo test --workspace --all-features` output for the reviewed commit, plus
   the CI run for the same SHA.
2. `cargo run -p stellar-toolkit -- verify invariants --json` — the seed and
   iteration count are part of the evidence, because the result is only
   meaningful for the seed that produced it.
3. `cargo run -p stellar-toolkit -- env validate --json` and
   `config/{dev,test,prod}.toml`.
4. `cargo run -p stellar-toolkit -- security secrets` and
   `docs/KEY_MANAGEMENT.md` §7.
5. `wasm-checksums.txt` plus `scripts/verify-bytecode.sh --reference …` output.
6. For the HTLC and AMM specifically, `docs/SECURITY_AUDIT.md` and the
   `#[should_panic]` tests that pin the rejection paths.

### Adding a mitigation

A mitigation is not finished until:

- [ ] it is in a type, a `checked_*` call, or a boundary validation;
- [ ] there is a test that fails if it is removed (`#[should_panic]` for the
      rejected path, not just a happy-path assertion);
- [ ] it appears in the table above with the file or test that enforces it.

## See also

- [`docs/KEY_MANAGEMENT.md`](KEY_MANAGEMENT.md)
- [`docs/INFORMAL_VERIFICATION.md`](INFORMAL_VERIFICATION.md)
- [`docs/SECURITY_AUDIT.md`](SECURITY_AUDIT.md)
- [`SECURITY.md`](../SECURITY.md)

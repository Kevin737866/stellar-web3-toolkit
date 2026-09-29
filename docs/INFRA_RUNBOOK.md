# Infrastructure Runbook — CI, Reproducible Builds, Release & Monitoring

Covers the four infra issues assigned to @danieloche635-bit:

| Issue | Title |
|-------|-------|
| #117 | Build CI pipeline for automated contract builds |
| #119 | Create Dockerized build environment for reproducible WASM |
| #120 | Add GitHub Actions workflow for release of contracts |
| #121 | Build monitoring dashboard for testnet contracts |
| #246 | Automated check #57 — TypeScript codegen import dedup |
| #247 | Automated check #58 — TypeScript client bigint mapping |
| #248 | Automated check #59 — monitoring snapshot restore checksum |

It also documents the `stellar-toolkit` CLI tooling issues (#240, #242, #243,
#244) in §5, and the environment-config, key-hygiene and informal-verification
work in §6:

| Issue | Title |
|-------|-------|
| #115 | Implement key management and cold-storage guidance |
| #116 | Add informal-verification test framework |
| #118 | Add multi-environment deploy (dev/test/prod) configs |

---

## 1. CI Pipeline (Issue #117)

**File:** `.github/workflows/ci.yml` · `rust-toolchain.toml`

- **Pinned toolchain:** `rust-toolchain.toml` pins `channel = "1.98.1"` + `wasm32v1-none`. All CI jobs use `dtolnay/rust-toolchain@master` with `toolchain: 1.98.1` so local and CI produce identical WASM.
- **Caching:** `Swatinem/rust-cache@v2` keys on target (`build-wasm`, `build`, `wasm-contracts`) — 2-3× faster.
- **Jobs:** `fmt` → `clippy` → `build` (matrix `wasm32` + `x86_64`) → `test` → `simulation` → `security` → `wasm` → `wasm-verify` → `docs` → `automated-checks` → `merge-check`.
- **Reproducibility guard:** `wasm` builds contracts twice and diffs `wasm-checksums.txt`; artifacts uploaded as `wasm-contracts` (14-day retention) and `wasm-checksums` (30-day).
- **Concurrency:** `cancel-in-progress: true` per ref.

**Run locally:**

```bash
cargo fmt --check
cargo clippy --all --all-targets --all-features -- -D warnings
cargo test --all --all-features
cargo build --workspace --exclude stellar-toolkit --target wasm32v1-none --release
```

---

## 2. Dockerized Reproducible Build (Issue #119)

**Files:** `Dockerfile` · `docker-compose.yml` · `.dockerignore` · `scripts/reproducible-build.sh` · `scripts/verify-bytecode.sh`

- **Base:** `rust:1.98-bookworm` with `wasm32v1-none`, `binaryen`, `wabt`, `soroban-cli 21.5.0`, `wasm-pack`.
- **Determinism:** `SOURCE_DATE_EPOCH=0`, `RUSTFLAGS="-C target-feature=-crt-static"`, clean incremental caches, pinned `Cargo.lock`.
- **Quickstart:**

```bash
# Local (native) reproducible build + double-build hash check
./scripts/reproducible-build.sh
# → target/reproducible/wasm-checksums.txt + size report

# Docker-isolated build
./scripts/reproducible-build.sh --docker

# Verify local vs. release artifact
./scripts/verify-bytecode.sh --reference dist/wasm-checksums.txt

# Verify local vs. Docker
./scripts/verify-bytecode.sh --docker

# Compose (builder + optional local Stellar + monitoring stack)
docker compose build builder
docker compose run --rm builder
docker compose up prometheus grafana  # see §4
```

CI's `wasm` job mirrors `scripts/reproducible-build.sh` exactly, so a green CI means the WASM is byte-for-byte reproducible.

---

## 3. Release Workflow & Multi-Env Deploys (Issue #120)

**Files:** `.github/workflows/release.yml` · `config/{dev,test,prod}.toml` · `config/README.md`

### Trigger

- Push tag `v*.*.*` → builds, verifies, then creates GitHub Release via `softprops/action-gh-release@v2` with `dist/*.wasm` + `wasm-checksums.txt`.
- Manual `workflow_dispatch` with inputs `environment: {dev|test|prod}` and `dry_run: {true|false}`.

### Jobs

1. **build** — reproducible WASM build, runs both `cargo build …` and `scripts/reproducible-build.sh`, packages `dist/`.
2. **release** — only on tags, publishes Release + checksums + notes (how to verify).
3. **deploy-testnet** — `environment: test` (or `dev`/`prod`), `workflow_dispatch` only; dry-run by default; loads `config/<env>.toml`, prints checksums, appends `logs/deployment-audit.log`.
4. **deploy-prod-gate** — `environment: prod` with GitHub Environment protection (manual approval required).

### Environment configs

| Env | File | Network | Horizon | RPC |
|-----|------|---------|---------|-----|
| dev | `config/dev.toml` | local quickstart | `localhost:8000` | `localhost:8001` |
| test | `config/test.toml` | testnet | `horizon-testnet.stellar.org` | `soroban-testnet.stellar.org` |
| prod | `config/prod.toml` | mainnet | `horizon.stellar.org` | `soroban.stellar.org` |

Secrets (`STELLAR_SECRET_KEY_*`) are never committed — use GitHub `secrets` per environment.

### Validating the configs (Issue #118)

The configs are checked against an explicit contract rather than trusted:

```bash
cargo run -p stellar-toolkit -- env list                 # what each env resolves to
cargo run -p stellar-toolkit -- env validate              # all environments (CI gate)
cargo run -p stellar-toolkit -- env validate --env prod --json
cargo run -p stellar-toolkit -- env show test
```

`env validate` fails on any error finding: an unknown key, a passphrase that
does not belong to the declared network, a mainnet config pointing at a testnet
endpoint, `auto_fund = true` on mainnet, a missing `[security]` block, a
non-stroop fee, or a file whose `[env] name` does not match its filename.
Warnings (no alerting configured, zero confirmations, a manual-approval gate on
a non-production environment) are reported without failing. The full rule table
lives in [`config/README.md`](../config/README.md).

**Manual release:**

```bash
git tag v0.2.0 && git push origin v0.2.0
# or: gh workflow run release.yml -f environment=test -f dry_run=true
gh release view v0.2.0
```

---

## 4. Monitoring Dashboard (Issue #121)

**Files:** `crates/stellar-toolkit/src/monitoring_dashboard.rs` · `monitoring/prometheus.yml` · `monitoring/alert-rules.yml` · `monitoring/grafana-dashboard.json` · `monitoring/dashboard/index.html`

### CLI

```bash
# Snapshot (JSON + HTML + Prometheus metrics)
cargo run -p stellar-toolkit -- monitoring dashboard --output target/monitoring --print-metrics
# Auto-detects wasm-checksums.txt at wasm-checksums.txt, dist/wasm-checksums.txt, target/reproducible/wasm-checksums.txt
cargo run -p stellar-toolkit -- monitoring dashboard --checksums dist/wasm-checksums.txt --output target/monitoring

# CI-friendly check (fails on hash mismatch)
cargo run -p stellar-toolkit -- monitoring check
cargo run -p stellar-toolkit -- monitoring check --checksums wasm-checksums.txt

# With custom workspace root
cargo run -p stellar-toolkit -- monitoring dashboard --workspace /path/to/workspace --output /tmp/monitor
```

Outputs:

- `target/monitoring/dashboard.json` — full `DashboardReport` (health, hash_match, alerts, summary)
- `target/monitoring/report.html` — static snapshot
- `target/monitoring/metrics.txt` — Prometheus text format (`stellar_contract_up`, `stellar_contract_wasm_hash_mismatch`, `stellar_horizon_up`, `stellar_soroban_up`)
- `target/monitoring/checksums.sha256` — sha256 manifest of the three files above

### Static dashboard

Open `monitoring/dashboard/index.html` in a browser — it live-polls `https://horizon-testnet.stellar.org` and `https://soroban-testnet.stellar.org` every 30s and renders contract health. For server-side polling, use the CLI above.

### Prometheus + Grafana + Alerts

```bash
docker compose up prometheus grafana
# Prometheus: http://localhost:9090  (scrapes localhost:9091 /metrics from the CLI poller)
# Grafana:    http://localhost:3000  (admin/admin)
# Import: monitoring/grafana-dashboard.json
# Rules:  monitoring/alert-rules.yml (ContractNotFound, AnomalousTxVolume, HorizonDown, WasmHashMismatch, HighFailedTxRate)
```

Alert `WasmHashMismatch` bridges #119/#120 — it fires when `stellar_contract_wasm_hash_mismatch == 1`, i.e., deployed WASM != reproducible build hash from `scripts/verify-bytecode.sh`.

### Tests

```bash
cargo test -p stellar-toolkit monitoring_dashboard
# 4 tests: test_monitor_config_defaults, test_dashboard_generates_report, test_hash_mismatch_alert, test_prometheus_metrics_format
```

---

## 5. CLI Tooling (Issues #240, #242, #243, #244)

**Files:** `crates/stellar-toolkit/src/help_text.rs` · `scaffolder.rs` · `gas_simulator.rs` · `state_inspector.rs` · `cli.rs`

### Wrapped command overview (Issue #240)

`clap` is built without terminal-size detection, so long descriptions used to
overflow narrow terminals. `stellar-toolkit help` renders the *real* command
tree (via `clap::CommandFactory`) and wraps every line, including tokens longer
than the wrap width (paths, URLs).

```bash
cargo run -p stellar-toolkit -- help             # width from $COLUMNS, otherwise 100
COLUMNS=72 cargo run -p stellar-toolkit -- help   # narrower layout
cargo run -p stellar-toolkit -- help --width 100
```

### Scaffolder + template lint (Issue #242)

```bash
# Render the built-in contract template, lint it, then write it out
cargo run -p stellar-toolkit -- scaffold new amm-pool --out target/scaffold/amm-pool
cargo run -p stellar-toolkit -- scaffold new amm-pool --out target/scaffold/amm-pool --dry-run

# Lint an existing project directory (CI gate: exits non-zero on error findings)
cargo run -p stellar-toolkit -- scaffold lint --dir contracts/amm-pool
```

Lint rules: required files (`Cargo.toml`, `src/lib.rs`, `README.md`), kebab-case
crate name, edition 2021 (or `edition.workspace = true`), `cdylib` crate type,
`soroban-sdk` dependency, `#![no_std]`, a test module, README heading/build
command, plus trailing-whitespace and final-newline hygiene. Errors fail the
command; warnings are reported without failing it.

### Gas / fee simulation (Issue #243)

```bash
cargo run -p stellar-toolkit -- gas estimate
cargo run -p stellar-toolkit -- gas estimate --instructions 250000 --writes 3 --bid-ledgers 2
cargo run -p stellar-toolkit -- gas estimate --base-fee 5000 --bump-percent 100 --max-bumps 5
```

Prints the fee breakdown (base fee, resource fee, inclusion bid, per-operation)
in stroops and XLM, the single fee bump required by the protocol rule
`outer_fee = ceil(inner_fee * base_fee / fee_at_signing)`, and an escalating
fee-bump ladder that stops at `--max-bumps` or the `max_fee_stroops` cap.

### Contract state inspection (Issue #244)

```bash
# First page of the built-in sample export
cargo run -p stellar-toolkit -- inspect state

# Filter, page and serialize
cargo run -p stellar-toolkit -- inspect state --contract CDEMO7POOLCONTRACTID --key-prefix Reserves/
cargo run -p stellar-toolkit -- inspect state --page-size 2 --cursor 2
cargo run -p stellar-toolkit -- inspect state --all-pages --include-temporary
cargo run -p stellar-toolkit -- inspect state --input state-export.json --json
```

Entries are ordered by (durability, key, contract), temporary entries are hidden
unless `--include-temporary` is passed, `--page-size` is clamped to `1..=200`, and
each page prints the cursor for the next one (or `end of results`). `--input`
reads a JSON array of state entries instead of the built-in sample.

### Tests

```bash
cargo test -p stellar-toolkit help_text
cargo test -p stellar-toolkit scaffolder
cargo test -p stellar-toolkit gas_simulator
cargo test -p stellar-toolkit state_inspector
```

---

## 6. Security, Env & Invariant Checks (Issues #115, #116, #118)

**Files:** `crates/stellar-toolkit/src/env_config.rs` · `key_hygiene.rs` ·
`invariants.rs` · `docs/KEY_MANAGEMENT.md` · `docs/THREAT_MODEL.md` ·
`docs/INFORMAL_VERIFICATION.md`

Three checks run in the CI `automated-checks` job, each exiting non-zero on a
finding. All three are also usable locally and are covered by unit tests, so a
regression fails `cargo test` before it reaches CI.

### Environment configs (Issue #118)

```bash
cargo run -p stellar-toolkit -- env validate
```

Parses `config/{dev,test,prod}.toml` with `deny_unknown_fields` and validates the
passphrase/network/endpoint triple, fee sanity, and the production safety flags.
See §3 above and `config/README.md`.

### Secret material (Issue #115)

```bash
cargo run -p stellar-toolkit -- security secrets
cargo run -p stellar-toolkit -- security secrets --path crates --path contracts --json
```

Detects `S…` secret keys, checksum-valid BIP-39 recovery phrases, literal
assignments to secret-named fields, and committed `.env` files. Findings are
**masked** (`S…AB12`), so running the scan cannot leak a key into a CI log.
Placeholders are ignored, and `// key-hygiene: allow` suppresses a line that has
to show a real shape. The unit tests include one that scans this repository, so
a committed key fails `cargo test` as well. Guidance and the rotation runbook
are in [`docs/KEY_MANAGEMENT.md`](KEY_MANAGEMENT.md).

### Informal verification (Issue #116)

```bash
cargo run -p stellar-toolkit -- verify invariants               # fixed seed, CI gate
cargo run -p stellar-toolkit -- verify invariants --iterations 5000 --seed 12345
```

Samples randomised inputs against stated invariants (Merkle inclusion and
non-forgery, fee-ladder escalation, pagination totality, wrapper width, and the
secret scanner itself) and prints the seed that reproduces any counterexample.
The seed is fixed by default so a CI failure is reproducible locally. See
[`docs/INFORMAL_VERIFICATION.md`](INFORMAL_VERIFICATION.md) and
[`docs/THREAT_MODEL.md`](THREAT_MODEL.md).

---

## 7. Runbook Checklist

- [ ] CI green on PR (`fmt`, `clippy`, `build`, `test`, `wasm` reproducibility diff = 0)
- [ ] `./scripts/reproducible-build.sh` → `wasm-checksums.txt` committed or attached to Release
- [ ] `./scripts/verify-bytecode.sh --docker` passes (local == Docker)
- [ ] Tag `vX.Y.Z` → Release created with `dist/*.wasm` + checksums
- [ ] `config/<env>.toml` reviewed; secrets set in GitHub Environment `dev`/`test`/`prod`
- [ ] Prod deploy requires manual approval in GitHub Environments
- [ ] Monitoring snapshot: `cargo run -p stellar-toolkit -- monitoring dashboard` → no hash mismatches
- [ ] Snapshot restore verified: `cargo run -p stellar-toolkit -- monitoring restore` → all files `OK`
- [ ] Codegen checks green: `cargo run -p stellar-toolkit -- codegen check`
- [ ] Prometheus + Grafana up, `WasmHashMismatch` alert not firing
- [ ] `logs/deployment-audit.log` appended on every deploy (audit trail)
- [ ] `cargo run -p stellar-toolkit -- env validate` → no errors
- [ ] `cargo run -p stellar-toolkit -- security secrets` → no findings
- [ ] `cargo run -p stellar-toolkit -- verify invariants` → all invariants pass

---

## References

- ADR-0002: Soroban WASM compilation pipeline
- `SECURITY.md` — disclosure & cold-storage guidance
- `docs/KEY_MANAGEMENT.md` — key tiers, cold-storage signing, rotation runbook
- `docs/THREAT_MODEL.md` — attack surface, mitigations, automated checks
- `docs/INFORMAL_VERIFICATION.md` — the property harness and its invariants
- `config/README.md` — environment config contract
- `SPEC.md` §9 Watchtower + §13 Security

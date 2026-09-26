# Monitoring Dashboard — Testnet Contracts

**Issue:** #121 Build monitoring dashboard for testnet contracts

## Overview

The monitoring dashboard polls Horizon and Soroban RPC, verifies deployed WASM hashes against the reproducible build, and exposes Prometheus metrics + Grafana + a static HTML dashboard.

## Components

- **CLI:** `crates/stellar-toolkit/src/monitoring_dashboard.rs` — `cargo run -p stellar-toolkit -- monitoring dashboard|check|restore`
- **Static UI:** `monitoring/dashboard/index.html` — browser fetch to `horizon-testnet.stellar.org` + `soroban-testnet.stellar.org`, auto-refresh 30s
- **Prometheus:** `monitoring/prometheus.yml` — scrapes `localhost:9091/metrics` (output of `monitoring dashboard`)
- **Alerts:** `monitoring/alert-rules.yml` — `ContractNotFound`, `AnomalousTxVolume`, `HorizonDown`, `WasmHashMismatch`, `HighFailedTxRate`
- **Grafana:** `monitoring/grafana-dashboard.json` — import into Grafana at `http://localhost:3000`

## Quickstart

```bash
# Build contracts first (so WASM exists for hash check)
./scripts/reproducible-build.sh

# Generate snapshot
cargo run -p stellar-toolkit -- monitoring dashboard --output target/monitoring --print-metrics
open target/monitoring/report.html
cat target/monitoring/metrics.txt

# Verify the snapshot against its checksums.sha256 manifest (issue #248)
cargo run -p stellar-toolkit -- monitoring restore --snapshot target/monitoring

# CI check (fails on WASM hash mismatch)
cargo run -p stellar-toolkit -- monitoring check --checksums target/reproducible/wasm-checksums.txt

# Live stack
docker compose up prometheus grafana
# Prometheus http://localhost:9090  Grafana http://localhost:3000 (admin/admin)
```

## Metrics

| Metric | Type | Labels |
|--------|------|--------|
| `stellar_contract_up` | gauge | `contract_id` (1 = healthy) |
| `stellar_contract_wasm_hash_mismatch` | gauge | `contract_id` (1 = mismatch) |
| `stellar_horizon_up` | gauge | — |
| `stellar_soroban_up` | gauge | — |

`WasmHashMismatch` bridges reproducible builds (#119) and releases (#120): if deployed bytecode ≠ locally built WASM, the alert fires.

## Tests

```bash
cargo test -p stellar-toolkit monitoring_dashboard -- --nocapture
```

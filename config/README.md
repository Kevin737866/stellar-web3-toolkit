# Environment Configurations

Multi-environment deploy configs for `stellar-toolkit` contracts.

| Env | File | Network | RPC |
|-----|------|---------|-----|
| `dev` | `config/dev.toml` | local quickstart | `localhost:8001` |
| `test` | `config/test.toml` | testnet | `soroban-testnet.stellar.org` |
| `prod` | `config/prod.toml` | mainnet | `soroban.stellar.org` |

## Usage

```bash
# Select env via STELLAR_NETWORK or --config flag (env var takes precedence)
STELLAR_NETWORK=testnet stellar-toolkit deploy --config config/test.toml contracts/amm-pool
# Or rely on .env:
cp config/test.toml .env  # then edit secrets separately
```

Secrets (STELLAR_SECRET_KEY) **must** be provided via environment or GitHub Actions
`secrets.STELLAR_SECRET_KEY_*` — never committed.

See `.github/workflows/release.yml` for how GitHub Environments (`dev`, `test`, `prod`)
gate mainnet deploys behind manual approval.

## Validating a config

A config that parses is not a config that is safe to deploy with, so the configs
are checked against an explicit contract (issue #118). The same check runs in
the CI `automated-checks` job.

```bash
# Every environment
cargo run -p stellar-toolkit -- env validate

# One environment, or machine readable
cargo run -p stellar-toolkit -- env validate --env prod
cargo run -p stellar-toolkit -- env validate --json

# What a given environment actually resolves to
cargo run -p stellar-toolkit -- env list
cargo run -p stellar-toolkit -- env show test
```

`env validate` exits non-zero on any **error** finding; **warnings** are reported
without failing. What it enforces:

| Rule | Severity |
|------|----------|
| Unknown tables/keys (`deny_unknown_fields`) — a typo cannot silently disable a block | error |
| `[env] name` must be one of `dev`, `test`, `prod`, and must match the filename | error |
| `stellar_network` must be `local`, `testnet` or `mainnet` | error |
| `soroban_network_passphrase` must be the passphrase belonging to that network | error |
| `horizon_url` / `soroban_rpc_url` / `monitoring.horizon_poll_url` must be http(s) URLs | error |
| A mainnet config must not point at a testnet endpoint, and vice versa | error |
| `deploy.fee` must be a non-zero stroop amount; `timeout_seconds` non-zero | error |
| `prod` must set `auto_fund = false` (Friendbot is a public faucet) | error |
| `prod` must ship a `[security]` block with `require_multisig` and `cold_storage_signing` | error |
| `prod` should configure `[monitoring]` with `alert_on_failure` | warning |
| `confirmations = 0` reports success before inclusion | warning |

Adding a key to a config therefore means teaching the validator about it —
which is the point: an unrecognised key is an error, not a silently ignored
line.

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

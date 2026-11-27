# Offline Validation for Deployment Configuration (Issue #327)

`stellar-toolkit deploy validate-offline` checks a deployment spec
(`deploy/<name>.toml`) without touching the network or Horizon. It runs every
structural and semantic check at the point where mistakes are cheapest to fix —
before signing or submitting anything.

## Why it exists

Environment configs (`config/{dev,test,prod}.toml`, validated by
`stellar-toolkit env validate`) describe *where* to deploy. Deployment specs
describe *what* to deploy: which contracts, which compiled WASM artifact, which
account signs, what fee and timeout to use. Without offline validation these
errors only surface as confusing RPC rejections:

| Mistake | When it fails without offline validation |
|---------|------------------------------------------|
| WASM path typo | at upload, with an `IoError` |
| `admin_account = "SINVALIDKEY"` | at signing, with a strkey error |
| `fee = "1000.5"` | at signing, with a type error |
| `timeout_seconds = 0` | transaction expires before it is built |
| `contract_id = "GABC..."` on a contract (G instead of C) | at submission with an XDR decode error |
| Unknown TOML key | silently ignored, hiding a misconfiguration |

## Configuration format

A deployment spec lives in `deploy/<name>.toml`. The `name` field must match
the filename stem; the validator enforces this so `--spec prod.toml` cannot
silently load a testnet spec.

```toml
name = "testnet"
admin_account = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN"

[network]
# One of: dev, test, prod.  Links to config/<environment>.toml.
environment = "test"

[submit]
fee = "1000"            # stroops, integer — "1000.5" is rejected
timeout_seconds = 60    # must be > 0
confirmations = 2       # 0 warns unless dry_run = true
dry_run = false         # true = build the transaction but do not submit

[contracts.amm_pool]
wasm_path = "target/wasm32v1-none/release/amm_pool.wasm"
# contract_id = "CABC..."   # required on prod upgrades, optional on testnet
# admin_account = "GABC..."  # per-contract override of the top-level signer

[contracts.amm_factory]
wasm_path = "target/wasm32v1-none/release/amm_factory.wasm"
```

Unknown keys in any section are rejected: a misspelled key cannot silently
disable a contract entry.

## Checks performed

All checks are **offline** — no network call is ever made.

| Field | Check | Severity |
|-------|-------|----------|
| `name` | matches the filename stem | error |
| `admin_account` | starts with `G`, 56 chars, uppercase Base32 | error |
| `network.environment` | one of `dev`, `test`, `prod` | error |
| `submit.fee` | positive integer (stroops) | error |
| `submit.timeout_seconds` | greater than zero | error |
| `submit.confirmations` | zero without `dry_run = true` | warning |
| `contracts.*` | at least one entry | error |
| `contracts.*.wasm_path` | non-empty, file exists, starts with `\0asm` | error |
| `contracts.*.contract_id` | starts with `C`, 56 chars, uppercase Base32 | error |
| `contracts.*.admin_account` | same rules as top-level | error |
| prod + no `contract_id` | warns about accidental first-time deploy | warning |

The WASM magic byte check (`\0asm`) catches non-WASM files (ELF binaries,
empty files, text) that would otherwise be accepted by the filesystem check and
then fail with an opaque XDR error at upload time.

## CLI usage

```sh
# Validate a spec; exits non-zero on any error finding.
stellar-toolkit deploy validate-offline deploy/testnet.toml

# Validate with explicit workspace root (resolves wasm_path relative to it).
stellar-toolkit deploy validate-offline deploy/testnet.toml \
    --workspace /path/to/workspace

# Machine-readable output for CI scripts.
stellar-toolkit deploy validate-offline deploy/testnet.toml --json

# Report errors and warnings but always exit zero (useful in advisory mode).
stellar-toolkit deploy validate-offline deploy/testnet.toml --warn-only
```

## Library API

```rust
use stellar_toolkit::deploy_config::{DeploymentSpec, DeploymentValidator};
use std::path::Path;

let spec = DeploymentSpec::load(Path::new("deploy/testnet.toml"))?;
let report = DeploymentValidator::new(Path::new(".")).validate(&spec);

if !report.passed() {
    for finding in &report.findings {
        eprintln!("{}: {} — {}", finding.severity.as_str(), finding.field, finding.message);
    }
    std::process::exit(1);
}
```

## Relationship to `env validate`

`env validate` and `deploy validate-offline` check different layers:

| Command | Validates | File |
|---------|-----------|------|
| `stellar-toolkit env validate` | network endpoints, passphrases, security flags | `config/{dev,test,prod}.toml` |
| `stellar-toolkit deploy validate-offline` | WASM artifacts, accounts, fees, contract IDs | `deploy/<name>.toml` |

Both should pass before any deployment. Run them together in CI:

```yaml
- run: stellar-toolkit env validate --dir config
- run: stellar-toolkit deploy validate-offline deploy/testnet.toml
```

## Compatibility

The `DeploymentSpec` struct uses `#[serde(deny_unknown_fields)]` on every
section. Adding a new key to an existing spec is backwards-incompatible at the
file level (old toolkit versions will reject it). New **optional** fields added
to the struct are forward-compatible: existing files do not need to be updated.

The `DeploymentValidationReport` JSON schema is stable. New optional fields may
be added to the `findings` objects in future releases; parsers should ignore
unknown keys.

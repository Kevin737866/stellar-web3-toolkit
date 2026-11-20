# WASM Hash Provenance

**Issue:** [#182](https://github.com/Kevin737866/stellar-web3-toolkit/issues/182) — *WASM hash provenance*

`wasm-checksums.txt` records *what* a build produced. It cannot say *what it was
built from*, so when a hash changes the reader cannot tell a deliberate rebuild
from a regression. This document covers the manifest that records the missing
half, and how CI uses it.

## The gap

`scripts/verify-bytecode.sh --diff` classifies artifacts as added, removed or
changed, but every "changed" verdict is the same verdict. A toolchain bump, a
lockfile update and an accidentally rebuilt artifact all read as `changed`, so
the only way to know which one happened is to inspect the diff by hand.

## The manifest

`wasm-provenance.json` sits next to `wasm-checksums.txt` and adds the build
inputs to the artifact hashes:

```json
{
  "schema_version": 1,
  "generated_at": "1763500000",
  "inputs": {
    "toolchain": "1.98.1",
    "source_date_epoch": "0",
    "cargo_lock_sha256": "…",
    "rust_toolchain_sha256": "…",
    "git_commit": "…"
  },
  "artifacts": {
    "amm_pool.wasm": { "sha256": "…", "size_bytes": 41234 }
  }
}
```

Every input is optional. A partial checkout with no `.git` or no `Cargo.lock`
still records and verifies; an input that cannot be observed is `null` rather
than a difference, so a shallow clone does not produce false drift.

## Recording and verifying

```bash
# after a reproducible build
stellar-toolkit monitoring provenance-record

# check a build against the recorded manifest
stellar-toolkit monitoring provenance-verify

# machine-readable
stellar-toolkit monitoring provenance-verify --json
```

`scripts/reproducible-build.sh` records the manifest automatically; the step is
a warning, not a failure, because the checksums it writes are still valid
evidence on their own.

## Verdicts

| Situation | Report | Exit |
| --- | --- | --- |
| Artifacts and inputs unchanged | `match` for every artifact, `build inputs: unchanged` | 0 |
| Artifact changed, an input also changed | `hash_mismatch`, `build inputs changed: cargo_lock` | 1 (0 with `--allow-explained`) |
| Artifact changed, no input changed | `hash_mismatch`, `build inputs: unchanged` | 1 |
| Artifact deleted | `missing` | 1 |
| Artifact present but never recorded | `unrecorded` | 1 |

The distinction that matters is the second and third rows: the same artifact
difference is *explained* by a changed input and *unexplained* without one.
`ProvenanceReport::unexplained()` is the list CI gates on.

## Schema

`schema_version` is checked on load. A manifest written by a newer toolkit is
refused (`ManifestError::UnsupportedSchema`) instead of being silently
misinterpreted, so an older binary cannot report a false pass.

## Relationship to the dashboard

`monitoring dashboard` and `monitoring check` compare a deployed contract's hash
against `wasm-checksums.txt` and emit `stellar_contract_wasm_hash_mismatch`.
Provenance answers the follow-up question those alerts raise: given a mismatch,
was this build supposed to be different?

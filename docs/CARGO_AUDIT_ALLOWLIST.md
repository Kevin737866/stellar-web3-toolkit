# Cargo Audit Allowlist

`cargo audit` compares `Cargo.lock` against the RustSec advisory database. Some
advisories cannot be fixed on the schedule a project needs, so they have to be
accepted knowingly. This document explains how that acceptance works here, and
`audit-allowlist.toml` is the record of it.

## Why a file, and not `cargo audit --ignore`

`cargo audit --ignore RUSTSEC-...` lives in a CI script, where nobody reads it
and nothing expires. An allowlist in the repository is reviewable, and this
repository checks it with:

```bash
cargo run -p stellar-toolkit -- security audit
```

That command runs `cargo audit --json` and applies four rules:

| Rule | Fails the check | Rationale |
| --- | --- | --- |
| Every entry has a usable reason (≥ 12 characters) | yes | A bare advisory id tells a reviewer nothing |
| Every expiry is a real `YYYY-MM-DD` date | yes | A typo must not silently disable the expiry |
| No entry has lapsed | yes | A suppression has to be renewed deliberately, not by neglect |
| Every reported advisory is suppressed | yes | A new advisory must not slip in behind a maintained-looking list |
| Every entry is still reported by the audit | no (warning) | Residue is worth cleaning, not worth blocking a merge |

The expiry rule is the load-bearing one. Without it an allowlist only grows: the
advisory stops being reported once it is fixed upstream, the entry stays, and
the next reader cannot tell which entries still matter.

## Process

1. Run the check and read what it says:

   ```bash
   cargo run -p stellar-toolkit -- security audit
   ```

2. **Try to fix it first.** Most advisories have a patch release. In this
   repository the count went from 15 advisories to 1 by updating `reqwest` from
   0.11 to 0.12, which moved the whole `rustls` 0.21 chain to a fixed version.
   `cargo update -p <crate>` and a dependency bump are always preferable to an
   entry in this file.

3. If there is genuinely no fix, add an entry with a reason that says *why this
   workspace is not affected* and *what would make it affected*:

   ```toml
   [[deny.ignore]]
   id = "RUSTSEC-YYYY-NNNN"
   reason = "the vulnerable path needs X; we only call Y"
   expires = "YYYY-MM-DD"
   ```

4. Set `expires` to the date by which you expect a fix, or the date you are
   willing to re-argue the case. Both are honest; an entry without an expiry is
   how allowlists rot.

## Current entries

### `RUSTSEC-2026-0387` — `crypto-bigint` timing variability

`crypto-bigint` 0.5.5 has constant-time operations that are not actually
constant-time. The fix landed in 0.7.6, a different semver major, so nothing in
the 0.5.x line can take it.

The dependency is transitive through the Stellar toolchain and not through our
code:

```
soroban-sdk 21 -> soroban-env-host -> k256 -> elliptic-curve -> crypto-bigint 0.5.5
```

`k256` uses `crypto-bigint` for secp256k1 ECDSA. The contracts in this workspace
verify Ed25519 signatures through the Soroban host's own implementation, and no
secret-dependent `crypto-bigint` operation runs in `crates/`. The entry expires
on 2027-05-31; remove it as soon as a `soroban-sdk` release moves to
`crypto-bigint` 0.7.

## When this check is wrong

If an entry's reason says the vulnerable code is unreachable, and the code
becomes reachable, the entry is now wrong even though the check still passes.
The reason field exists so that a reviewer changing the reachability can find
the claim and delete the entry.

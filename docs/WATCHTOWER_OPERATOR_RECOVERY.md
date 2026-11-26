# Watchtower Operator Key and Data Recovery

**Issue:** [#377](https://github.com/Kevin737866/stellar-web3-toolkit/issues/377) — *Document watchtower operator key and data recovery procedures*

A watchtower cannot answer a breach if the node holding the honest channel
state and the durable justice actions is lost. This change gives operators a
signed, portable recovery bundle and a restore path that refuses to act on
tampered, malformed or misconfigured data. The operator key is a secret held by
the operator; it never travels with the bundle or appears in logs.

## Interface

The API lives in `crates/watchtower/src/recovery.rs` and is re-exported as
`watchtower::recovery`.

| Entry point | Purpose |
| --- | --- |
| `OperatorKey::generate()` | Create a fresh 32-byte operator key. |
| `OperatorKey::from_hex(&str)` | Load a 64-character hex key from a secret manager. |
| `OperatorKey::from_env(name)` | Load the same key from an environment variable. |
| `OperatorKey::fingerprint()` | Eight hex characters identifying the key in logs. |
| `RecoveryBundle::verify(&key)` | Check structure and HMAC signature before use. |
| `RecoveryBundle::resign(&current, &next)` | Rotate the operator key on a verified bundle. |
| `Watchtower::export_recovery_bundle(&key)` | Export a signed snapshot of durable data. |
| `Watchtower::restore_from_bundle(config, &key, &bundle)` | Restore into a fresh store chosen by `config.db_path`. |
| `Watchtower::restore_from_bundle_with_storage(config, &key, &bundle, storage)` | Restore into a caller-supplied empty backend. |

```rust
use watchtower::recovery::OperatorKey;
use watchtower::{Watchtower, WatchtowerConfig};

let key = OperatorKey::from_env("WATCHTOWER_OPERATOR_KEY")?;
let bundle = watchtower.export_recovery_bundle(&key)?;

// On the replacement node, with a new process and an empty store:
let restored = Watchtower::restore_from_bundle(WatchtowerConfig::default(), &key, &bundle)?;
let pending = restored.pending_justice_actions()?;
let submitted = restored.retry_pending_justice().await;
```

`RecoveryPayload` contains `version`, `created_at`, `network_passphrase`,
`subscriptions`, `channel_states`, `channel_updates`, `alerts` and
`justice_actions`. The HMAC-SHA256 signature covers the canonical JSON
serialization of all of those fields. `RecoveryBundle` carries the payload and
the signature; it deliberately does not carry the key.

## Key handling

- Generate one key per operator (or per recovery domain), store it in a secret
  manager, and inject it at runtime. The default environment variable name is
  `WATCHTOWER_OPERATOR_KEY`, but `from_env(name)` accepts any name.
- `OperatorKey` has no serde implementation and its `Debug` output is
  `<redacted>`, so it cannot be accidentally serialized into a config file, a
  bundle, or a log line. Log `fingerprint()` instead; it is not a secret.
- Hex parsing rejects wrong length and non-hex characters with
  `RecoveryError::InvalidKey`. A missing environment variable is an error, not
  a generated fallback key.
- To rotate, call `bundle.resign(&old_key, &new_key)`. Rotation verifies the old
  signature first, so a bundle signed by an unknown key cannot be re-signed.
  Destroy the old key only after the replacement node has restored and verified
  the bundle.

## Restore invariants

`RecoveryBundle::verify` runs structural validation before the signature check,
and `restore_from_bundle*` checks the network passphrase before writing. A
restore is rejected when:

- the format version is not `1` or `created_at` is zero;
- the passphrase is empty or does not match the configured network;
- a subscription, channel state, alert, or justice action id is empty or
  duplicated;
- a channel state or update refers to a channel with no subscription;
- an alert has a zero timestamp;
- breach evidence has an empty channel id or transaction hash, a zero
  detection timestamp, a non-advancing sequence, or a negative total balance.
  Balance conservation itself is checked by `JusticeService::validate_breach`
  (issue #371) before an action is first persisted; recovery re-checks the
  shape of the persisted evidence;
- a `Submitted`/`Confirmed` action has no transaction hash, or a
  `Pending`/`Failed` action carries one;
- the signature does not verify with the supplied key.

The target backend must be **empty**. Recovery never overwrites an existing
store; a non-empty target is rejected with `WatchtowerError::StorageError`.
Writes happen only after every check passes. If a write fails, the partially
written store is discarded and no `Watchtower` is returned. Justice actions are
restored with their original ids and `Pending` status, so replay is safe and
does not create duplicates.

## Configuration and compatibility

No new `WatchtowerConfig` field is required; the key is supplied explicitly to
each call. Existing `Watchtower::new`, monitoring and health-check behaviour is
unchanged, and callers that never export or restore see no difference.

`StorageBackend` gained one **defaulted** method, `get_all_justice_actions`.
Existing implementations still compile, but `export_recovery_bundle` fails with
a `QueryError` rather than silently exporting only pending actions. Custom
backends that need recovery must override it to return every persisted action.
The in-memory backend does; the SQLite placeholder returns an empty list, which
matches the fact that it persists no rows.

`WatchtowerError` gained no new variants; recovery failures map to
`InvalidConfiguration` (bad key, signature, format or network) or
`StorageError` (backend read/write failure or non-empty target).

## Runbook

1. **Detect.** `check_storage_health()` reports an unhealthy backend, or the
   node is being decommissioned.
2. **Export.** On the healthiest reachable node, load the operator key and call
   `export_recovery_bundle`. Keep the bundle on trusted transport; it contains
   channel and breach details even though it contains no key.
3. **Verify.** Call `bundle.verify(&key)` before moving on. If rotating keys,
   call `resign` and verify with the new key.
4. **Provision.** Start a replacement watchtower with an empty backend and the
   same network passphrase. Call `restore_from_bundle` (or the explicit-storage
   variant with a fresh store).
5. **Replay.** Call `pending_justice_actions()` and
   `retry_pending_justice()`. A wrong key or network fails before any write, so
   a failed step 4 can be retried with corrected inputs.
6. **Rotate.** Once replay succeeds, rotate the operator key and destroy the
   old secret.

See [Watchtower Storage Health Checks](WATCHTOWER_STORAGE_HEALTH.md) for the
probe that triggers this procedure and [Breach Evidence Validation](BREACH_EVIDENCE_VALIDATION.md)
for the invariants applied before an action is ever persisted.

## Validation

`cargo test -p watchtower` runs 57 crate unit tests and 11 integration tests:
unit coverage for key parsing, redaction, signature verification, tampering,
key rotation and every payload invariant; integration coverage for export,
restore, replay, wrong key, tampered bundle, wrong network, non-empty target and
rotation. The changed crate files are formatted with `rustfmt --edition 2021`;
`cargo fmt --all -- --check` remains the workspace-wide formatting gate.

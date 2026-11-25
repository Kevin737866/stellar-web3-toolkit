# Watchtower Storage Backend Health Checks

**Issue:** [#375](https://github.com/Kevin737866/stellar-web3-toolkit/issues/375) — *Add health checks for watchtower storage backends*

A watchtower that cannot read or persist its storage cannot protect a channel:
a breach response is only as reliable as the record of the honest state and the
durable justice action behind it. This change gives operators an explicit,
actionable way to ask "is the backend I am relying on actually working?" before
they trust the watchtower with that responsibility.

## Interface

The health-check API lives in `crates/watchtower`:

| Entry point | Purpose |
| --- | --- |
| `StorageBackend::check_health()` | Probe the backend with the default options. |
| `StorageBackend::check_health_with(&options)` | Probe with caller-supplied options (recommended for operators). |
| `Watchtower::check_storage_health()` | On-demand probe using the watchtower's configured options. |
| `Watchtower::check_storage_health_with(&options)` | On-demand probe with explicit options. |
| `Watchtower::last_storage_health()` | Read the most recent cached report. |
| `Watchtower::with_storage(config, storage)` | Construct a watchtower over a caller-provided backend (also the injection point for tests). |

```rust
use watchtower::storage::StorageHealthCheckOptions;
use watchtower::Watchtower;

let watchtower = Watchtower::new(config)?;

let report = watchtower.check_storage_health_with(&StorageHealthCheckOptions {
    max_latency_ms: 2_000,
    probe_writes: true,
})?;

if !report.is_healthy() {
    // The report carries the backend name, probe outcomes and actionable reasons.
    tracing::warn!(summary = %report.summary(), "watchtower storage is not healthy");
}
```

`StorageHealthReport` contains:

- `backend` — the backend's `backend_name()` (`in-memory`, `sqlite`, or a custom name).
- `state` — `Healthy`, `Degraded`, or `Unhealthy`.
- `checked_at`, `elapsed_ms` — when the probe ran and how long it took.
- `read_ok` — whether `get_subscriptions()` succeeded.
- `write_probe_ok` — `Some(bool)` when a write probe ran, `None` otherwise.
- `details` — human-readable reasons, including the underlying storage error.

## Probe semantics

1. **Validate first.** `StorageHealthCheckOptions::validate` rejects
   `max_latency_ms == 0` with `StorageError::HealthCheckError`. No probe runs and
   no state changes when options are invalid.
2. **Read probe.** A failed read produces an `Unhealthy` report with the backend
   error in `details`. It is a health result, not an API error.
3. **Write probe (opt-in).** With `probe_writes: true`, a uniquely named sentinel
   *subscription* is written, read back, and removed. The sentinel never uses a
   real channel ID. Cleanup is attempted on every path, including a failed write
   or failed verification, and a cleanup failure is reported with the sentinel
   key so an operator can remove it manually. Pending justice actions, alerts,
   and channel states are never touched by a probe.
4. **Latency budget.** Exceeding `max_latency_ms` makes an otherwise healthy
   report `Degraded`; it does not downgrade an already `Unhealthy` result.
   An `Unhealthy` state always takes precedence.

The SQLite backend is still a placeholder: operations return success without
persisting rows. Its probe therefore returns `Degraded` with a message that
durability cannot be verified, rather than claiming health or fabricating a
failing write. Once SQLite persistence is implemented, its `check_health_with`
override is the single place to update.

## Configuration

New fields on `WatchtowerConfig` (both annotated with `#[serde(default)]`):

| Field | Default | Meaning |
| --- | --- | --- |
| `storage_health_check_interval_secs` | `0` | Seconds between automatic probes in the monitor loop. `0` disables them. |
| `storage_health_check.max_latency_ms` | `1_000` | Maximum acceptable probe duration; must be greater than zero. |
| `storage_health_check.probe_writes` | `false` | Include the write/read/delete sentinel probe. |

Invalid options are rejected at construction time with
`WatchtowerError::InvalidConfiguration`, and again on explicit calls to
`check_storage_health_with`. Nothing is silently replaced with a default.

When automatic checks are enabled, the monitor loop probes after each scan when
the interval has elapsed. The timestamp is stamped *before* probing so a failing
backend cannot cause every scan to repeat an expensive check. Both automatic and
on-demand probes cache the report and emit an `AlertType::HealthCheckFailed`
alert (component `storage`, `Critical` severity) for a degraded or unhealthy
backend. Alerts are also persisted to storage on a best-effort basis; the
in-memory alert remains available if the backend itself rejects the write.

## Compatibility

- `StorageBackend` gained three **defaulted** methods: `backend_name`,
  `check_health`, and `check_health_with`. Existing implementations compile
  unchanged and receive a generic read/write probe with backend name `custom`.
- `WatchtowerConfig` gained two fields with serde defaults, so old config files
  still deserialize. Serialized configs now include the new fields.
- Automatic probes are disabled by default. Callers that do not request a
  health check see exactly the previous monitoring behaviour.
- `WatchtowerStats` and `WatchtowerStatus` are unchanged.

## Operator recovery

1. `check_storage_health()` (or the automatic alert) reports `Unhealthy`.
2. Fix the backend (connectivity, permissions, disk, or swap the backend via
   `Watchtower::with_storage`).
3. Re-run the probe. Once it reports `Healthy`, call
   `Watchtower::pending_justice_actions()` and then
   `Watchtower::retry_pending_justice()`.

Because justice actions are persisted *before* submission (issue #368) and
probes never modify them, failed or skipped submissions are still present and
safe to replay after recovery. See [Breach Evidence Validation](BREACH_EVIDENCE_VALIDATION.md)
for the invariants enforced before an action is ever persisted.

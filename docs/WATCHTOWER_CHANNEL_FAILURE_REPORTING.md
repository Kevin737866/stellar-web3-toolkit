# Per-channel monitoring failure reporting (Issue #374)

## Behavior

The watchtower scans every subscribed channel on each tick. Before this change a
failed scan was only logged; callers had no way to see which channel failed, how
often, or whether it recovered. Now each failed scan produces an observable,
per-channel [`ChannelFailureReport`] and a durable alert, while the loop
continues to every remaining channel.

A failure on channel A:

- increments A's `consecutive_failures` and refreshes its timestamps;
- publishes a `ChannelMonitorFailed` alert, persisted through the configured
  `StorageBackend`;
- never changes B's report, state, subscription or justice actions;
- never stops or restarts the monitoring loop.

A later successful scan of A marks the active incident `recovered` and emits a
single `ChannelMonitorRecovered` alert. Repeated successful scans are safe and
do not produce duplicate alerts (retry safety).

## Interface

All APIs live on `watchtower::Watchtower` (in-memory state is also reachable via
`state()`):

| API | Purpose |
| --- | --- |
| `report_channel_failure(channel_id, reason)` | Explicitly report a failed scan for a subscribed channel. Persists the alert *before* changing in-memory state. |
| `channel_failure_report(channel_id)` | Latest report for one channel, including recovered incidents. |
| `channel_failure_reports()` | All reports, sorted by channel id. |
| `active_channel_failure_reports()` | Only channels still failing. |
| `total_monitor_failures()` | Sum of consecutive failures across current incidents. |
| `clear_channel_failure(channel_id)` | Forget a report (operator recovery). Idempotent. |
| `retry_channel(channel_id)` | Re-check one channel; clears it on success, increments its failure count on error. |
| `monitor()` | Access to `ChannelMonitor::inject_failure` / `clear_injected_failure` for simulation and tests. |

`ChannelFailureReport` exposes `channel_id`, `error`, `consecutive_failures`,
`first_failed_at`, `last_failed_at`, `recovered`, `last_recovered_at`, plus
`is_active()` and an actionable `message()`.

```rust,ignore
use watchtower::{monitor::MonitorError, Watchtower, WatchtowerConfig};

let tower = Watchtower::new(WatchtowerConfig::default())?;
tower.subscribe("channel-a".to_string())?;

tower.monitor().inject_failure(
    "channel-a",
    MonitorError::NetworkError("rpc unavailable".to_string()),
);
tower.start().await?;
// ... later: inspect tower.active_channel_failure_reports()

tower.monitor().clear_injected_failure("channel-a");
tower.retry_channel("channel-a").await?; // recovers only this channel
tower.stop();
# Ok::<(), watchtower::WatchtowerError>(())
```

## Configuration

No new configuration fields are required. Existing settings keep their meaning:

- `scan_interval_secs` controls how often reports are refreshed;
- `auto_justice` continues to govern justice submission. A rejected or failed
  justice submission is reported as that channel's failure but still lets the
  channel state update and the other channels be scanned;
- the configured `StorageBackend` receives the failure/recovery alerts. In
  `InMemoryStorage` they are available via `storage().get_alerts(limit)`;
  `SqliteStorage` is currently a simulation stub that accepts writes but does
  not yet durably persist them.

Failure reasons must be non-blank and at most `MAX_FAILURE_REASON_LEN` (2048)
bytes. Oversized input is rejected, never truncated.

## Invariants and errors

- **Breach evidence validation** remains in `JusticeService::validate_breach`;
  failure reporting never bypasses it. Validation errors become that channel's
  failure report and leave pending justice actions untouched for retry.
- **Durable actions** first: `report_channel_failure` persists the alert before
  updating the registry, so a storage error returns `WatchtowerError::StorageError`
  with no partial state change. Background loop failures use best-effort
  persistence so a storage outage cannot stop monitoring.
- **Retry safety**: `retry_channel` is idempotent for healthy channels and only
  clears a report after a successful re-check; a failed retry returns
  `WatchtowerError::NetworkError` with the channel id and retry hint.
- **Operator recovery**: `clear_channel_failure` and `pending_justice_actions` /
  `retry_pending_justice` remain independent — clearing a monitor report never
  alters justice evidence or subscriptions.
- Blank/unknown channel ids yield `WatchtowerError::InvalidChannel`; blank or
  oversized reasons yield `WatchtowerError::InvalidFailureReason`.

## Compatibility

All additions are additive. `WatchtowerConfig`, `WatchtowerStats`, the
`StorageBackend` trait and existing alert constructors are unchanged, so callers
that do not use failure reporting keep their behavior and compile unchanged.
`AlertType` gains two variants, so exhaustive matches on that enum must add
`ChannelMonitorFailed` and `ChannelMonitorRecovered` arms (or a wildcard arm).

## Validation

- `cargo fmt --all -- --check`
- `cargo test -p watchtower`
- Integration: `crates/watchtower/tests/channel_failure_reporting.rs`

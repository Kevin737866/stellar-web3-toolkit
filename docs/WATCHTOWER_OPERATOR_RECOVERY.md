# Watchtower Operator Key & Data Recovery Procedures

This operational runbook covers key management, encrypted state retention, crash recovery of persisted justice actions, monitoring lag triage, and alert delivery troubleshooting for `crates/watchtower`.

---

## 1. Operator Signing Key Management & Recovery

The watchtower signs and submits penalty ("justice") transactions on Stellar using an operator keypair isolated from channel counterparty keys.

### Backup & Custody
1. **Cold encrypted backup:** Store the operator secret seed encrypted in an offline HSM or KMS-wrapped envelope before enabling `auto_justice = true`.
2. **Passphrase & network binding:** Verify `WatchtowerConfig.network_passphrase` matches the target Stellar network (`Test SDF Network ; September 2015` vs `Public Global Stellar Network ; September 2015`) before signing.
3. **Key rotation:**
   * Provision the replacement operator key and fund its XLM fee reserve (`justice_fee_budget`).
   * Drain any `JusticeTxStatus::Pending` or `Submitted` records using the outgoing key.
   * Switch configuration to the new key and archive the outgoing key read-only until all active channel timelocks expire.

### Suspected Key Compromise
1. Set `auto_justice = false` and call `watchtower.stop()` immediately.
2. Rotate the operator signing account and revoke any multi-sig signers associated with the compromised public key.
3. Audit recent entries via `storage.get_justice_actions_for_channel(channel_id)` and `storage.get_alerts(limit)`.

---

## 2. Persisted Justice Action Recovery (#368, #369)

Justice intent is persisted durably in `StorageBackend` **before** network submission under deterministic key `action_id = "{channel_id}:{breach_tx_hash}"`:

* If the watchtower crashes *before* updating status to `JusticeTxStatus::Submitted`, on restart operators can query persisted `JusticeTxStatus::Pending` records and safely re-evaluate or broadcast them without duplicating already-handled breaches.
* Transient storage errors (`StorageError::TransientError`) are retried automatically up to `RetryPolicy.max_retries` using idempotent upserts keyed by `action_id`.

---

## 3. Encrypted State Retention & Restoration (#372)

Encrypted channel recovery blobs are bounded by `EncryptedStateRetentionPolicy`:
* `max_entries`: Maximum retained channel entries (must be `> 0`, default `10_000`).
* `max_age_secs`: Maximum retention window in seconds (default 30 days).
* `max_total_bytes`: Aggregate ciphertext budget (must be `> 0`, default 64 MiB).

### Recovery Steps
1. Call `storage.health_check()` (#375) to confirm storage availability and responsiveness.
2. Restore the latest encrypted backup snapshot and DB file (`WatchtowerConfig.db_path`).
3. Verify restored subscriptions via `watchtower.persisted_subscriptions()`.
4. Run `encrypted_state.enforce_retention(now)` to evict expired blobs deterministically before resuming channel scans.

---

## 4. Monitoring Lag, Per-Channel Faults & Alert Triage (#370, #373, #374)

* **Lag (`WatchtowerStatus.monitoring_lag_ledgers`):** Calculated as `network_head_ledger.saturating_sub(last_seen_ledger)`. Sustained lag indicates Horizon/RPC throttling or excessive `scan_interval_secs`.
* **Per-channel errors (`WatchtowerStatus.per_channel_failures`):** Transient failures on one channel emit `AlertType::HealthCheckFailed` and never stall monitoring on healthy channels.
* **Alert delivery retries (`AlertDeliveryManager`):** Alerts receive deterministic `delivery_id` values (`dlv_<hash>`) so webhook consumers can safely deduplicate retried deliveries.

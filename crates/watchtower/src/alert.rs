//! # Retryable Alert Delivery Module
//!
//! Provides durable, idempotent, retryable alert delivery with explicit
//! [`DeliveryId`] tracking for the watchtower service.
//!
//! ## Persist-first & Retry Safety
//!
//! Every alert targeted at a destination is assigned a deterministic
//! [`DeliveryId`] derived from `(alert.id, destination)` (or an explicit
//! validated [`DeliveryId`]). Before any network transport is invoked:
//!
//! 1. The inputs (`alert.id`, `destination`, `DeliveryId`, and
//!    [`AlertDeliveryConfig`]) are validated; invalid inputs are rejected
//!    explicitly with no state mutation.
//! 2. An [`AlertDelivery`] record in [`DeliveryStatus::Pending`] is persisted to
//!    [`StorageBackend`].
//! 3. [`AlertTransport::deliver`] is invoked with a [`DeliveryPayload`] that
//!    carries the `delivery_id` so downstream receivers can deduplicate retries.
//! 4. On transient failure, `attempts` is incremented, `next_retry_at` is
//!    scheduled with capped exponential backoff, and the record stays
//!    `Pending` until `max_attempts` is reached.
//! 5. On permanent failure or once `max_attempts` is reached, the record
//!    transitions to [`DeliveryStatus::Failed`].
//! 6. Operators can inspect pending deliveries and trigger recovery via
//!    [`AlertDeliveryService::retry_pending_deliveries`] or
//!    [`AlertDeliveryService::retry_delivery`].

use crate::storage::{StorageBackend, StorageError};
use crate::Alert;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use thiserror::Error;
use tracing::{info, warn};

/// Maximum allowed length for a [`DeliveryId`].
const MAX_DELIVERY_ID_LEN: usize = 128;

/// Boxed future alias used by [`AlertTransport`] to avoid external async-trait
/// macro dependencies while keeping the trait object-safe.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Validated, non-empty identifier for a single alert delivery target.
///
/// A `DeliveryId` remains constant across all retry attempts for the same
/// alert and destination so downstream webhook receivers can deduplicate
/// retried deliveries safely.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeliveryId(String);

impl DeliveryId {
    /// Validate and construct a [`DeliveryId`] from an arbitrary string.
    pub fn new(id: impl Into<String>) -> Result<Self, AlertDeliveryError> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(AlertDeliveryError::InvalidDeliveryId(
                "delivery_id must not be empty".to_string(),
            ));
        }
        if id.len() > MAX_DELIVERY_ID_LEN {
            return Err(AlertDeliveryError::InvalidDeliveryId(format!(
                "delivery_id exceeds maximum length of {MAX_DELIVERY_ID_LEN} bytes"
            )));
        }
        if id.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(AlertDeliveryError::InvalidDeliveryId(
                "delivery_id must not contain whitespace or control characters".to_string(),
            ));
        }
        Ok(Self(id))
    }

    /// Derive a deterministic [`DeliveryId`] from `(alert_id, destination)`.
    ///
    /// Re-enqueuing the same alert for the same destination yields the same
    /// `DeliveryId`, making persist-first enqueueing idempotent across restarts.
    pub fn for_alert(alert_id: &str, destination: &str) -> Result<Self, AlertDeliveryError> {
        validate_alert_id(alert_id)?;
        validate_destination(destination)?;

        let mut hasher = Sha256::new();
        hasher.update(alert_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(destination.as_bytes());
        let digest = hasher.finalize();

        let mut hex = String::with_capacity(4 + 32);
        hex.push_str("dlv_");
        for byte in &digest[..16] {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        Ok(Self(hex))
    }

    /// Generate a fresh random [`DeliveryId`].
    pub fn generate() -> Self {
        Self(format!("dlv_{}", crate::uuid_v4()))
    }

    /// Return the underlying string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DeliveryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for DeliveryId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Validate that an alert ID is non-empty and safe.
pub(crate) fn validate_alert_id(alert_id: &str) -> Result<(), AlertDeliveryError> {
    if alert_id.trim().is_empty() {
        return Err(AlertDeliveryError::InvalidAlert(
            "alert.id must not be empty".to_string(),
        ));
    }
    if alert_id.chars().any(char::is_control) {
        return Err(AlertDeliveryError::InvalidAlert(
            "alert.id must not contain control characters".to_string(),
        ));
    }
    Ok(())
}

/// Validate an alert delivery destination URL.
///
/// Only `http://` and `https://` URLs with a non-empty host and no whitespace
/// or control characters are accepted.
pub fn validate_destination(destination: &str) -> Result<(), AlertDeliveryError> {
    if destination.trim().is_empty() {
        return Err(AlertDeliveryError::InvalidDestination(
            "destination must not be empty".to_string(),
        ));
    }
    if destination
        .chars()
        .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(AlertDeliveryError::InvalidDestination(
            "destination must not contain whitespace or control characters".to_string(),
        ));
    }
    let rest = destination
        .strip_prefix("https://")
        .or_else(|| destination.strip_prefix("http://"))
        .ok_or_else(|| {
            AlertDeliveryError::InvalidDestination(
                "destination must use http:// or https:// scheme".to_string(),
            )
        })?;

    if rest.is_empty() || rest.starts_with('/') || rest.starts_with('?') || rest.starts_with('#') {
        return Err(AlertDeliveryError::InvalidDestination(
            "destination must include a host".to_string(),
        ));
    }

    Ok(())
}

/// Configuration for retryable alert delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertDeliveryConfig {
    /// Maximum total delivery attempts before marking [`DeliveryStatus::Failed`].
    pub max_attempts: u32,
    /// Initial retry backoff in seconds after the first failed attempt.
    pub initial_backoff_secs: u64,
    /// Upper bound on exponential retry backoff in seconds.
    pub max_backoff_secs: u64,
}

impl Default for AlertDeliveryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_backoff_secs: 5,
            max_backoff_secs: 300,
        }
    }
}

impl AlertDeliveryConfig {
    /// Validate that all retry parameters are safe and consistent.
    pub fn validate(&self) -> Result<(), AlertDeliveryError> {
        if self.max_attempts == 0 {
            return Err(AlertDeliveryError::InvalidConfig(
                "max_attempts must be at least 1".to_string(),
            ));
        }
        if self.initial_backoff_secs == 0 {
            return Err(AlertDeliveryError::InvalidConfig(
                "initial_backoff_secs must be at least 1".to_string(),
            ));
        }
        if self.max_backoff_secs < self.initial_backoff_secs {
            return Err(AlertDeliveryError::InvalidConfig(
                "max_backoff_secs must be >= initial_backoff_secs".to_string(),
            ));
        }
        Ok(())
    }

    /// Compute the capped exponential backoff in seconds for the given
    /// 1-based failed attempt count.
    pub fn backoff_for_attempt(&self, attempts: u32) -> u64 {
        let shift = attempts.saturating_sub(1).min(30);
        let multiplier = 1u64 << shift;
        self.initial_backoff_secs
            .saturating_mul(multiplier)
            .min(self.max_backoff_secs)
    }
}

/// Lifecycle status of an [`AlertDelivery`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    /// Persisted and awaiting initial delivery or a scheduled retry.
    Pending,
    /// Successfully delivered to the destination.
    Delivered,
    /// Permanently failed after a non-retryable error or exhausting retries.
    Failed,
}

/// Durable record of an alert delivery with its stable [`DeliveryId`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDelivery {
    /// Stable idempotency/delivery identifier preserved across all retries.
    pub delivery_id: DeliveryId,
    /// Alert being delivered.
    pub alert: Alert,
    /// Target destination (e.g. webhook URL).
    pub destination: String,
    /// Current lifecycle status.
    pub status: DeliveryStatus,
    /// Number of delivery attempts executed so far.
    pub attempts: u32,
    /// Maximum attempts permitted for this delivery.
    pub max_attempts: u32,
    /// Most recent delivery error, if any.
    pub last_error: Option<String>,
    /// Unix timestamp (seconds) after which the next retry is due.
    pub next_retry_at: u64,
    /// Unix timestamp when this delivery record was created.
    pub created_at: u64,
    /// Unix timestamp of the most recent state transition.
    pub updated_at: u64,
    /// Unix timestamp when delivery succeeded, if [`DeliveryStatus::Delivered`].
    pub delivered_at: Option<u64>,
}

impl AlertDelivery {
    /// Create a new [`AlertDelivery`] in [`DeliveryStatus::Pending`].
    pub fn new(
        delivery_id: DeliveryId,
        alert: Alert,
        destination: impl Into<String>,
        max_attempts: u32,
        now: u64,
    ) -> Result<Self, AlertDeliveryError> {
        validate_alert_id(&alert.id)?;
        let destination = destination.into();
        validate_destination(&destination)?;
        if max_attempts == 0 {
            return Err(AlertDeliveryError::InvalidConfig(
                "max_attempts must be at least 1".to_string(),
            ));
        }

        Ok(Self {
            delivery_id,
            alert,
            destination,
            status: DeliveryStatus::Pending,
            attempts: 0,
            max_attempts,
            last_error: None,
            next_retry_at: now,
            created_at: now,
            updated_at: now,
            delivered_at: None,
        })
    }

    /// Return `true` if this delivery is `Pending` and its backoff has elapsed.
    pub fn is_due(&self, now: u64) -> bool {
        self.status == DeliveryStatus::Pending && self.next_retry_at <= now
    }

    /// Build the [`DeliveryPayload`] for the next attempt.
    pub fn payload(&self) -> DeliveryPayload {
        DeliveryPayload {
            delivery_id: self.delivery_id.clone(),
            alert_id: self.alert.id.clone(),
            destination: self.destination.clone(),
            message: self.alert.message(),
            alert: self.alert.clone(),
            attempt: self.attempts.saturating_add(1),
        }
    }

    /// Record a successful delivery attempt.
    pub fn mark_delivered(&mut self, now: u64) {
        self.attempts = self.attempts.saturating_add(1);
        self.status = DeliveryStatus::Delivered;
        self.last_error = None;
        self.updated_at = now;
        self.delivered_at = Some(now);
    }

    /// Record a failed delivery attempt, transitioning to `Failed` when the
    /// error is non-retryable or `max_attempts` has been reached.
    pub fn record_failure(&mut self, error: &AlertDeliveryError, backoff_secs: u64, now: u64) {
        self.attempts = self.attempts.saturating_add(1);
        self.last_error = Some(error.to_string());
        self.updated_at = now;

        if !error.is_retryable() || self.attempts >= self.max_attempts {
            self.status = DeliveryStatus::Failed;
        } else {
            self.status = DeliveryStatus::Pending;
            self.next_retry_at = now.saturating_add(backoff_secs);
        }
    }
}

/// Payload passed to [`AlertTransport::deliver`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryPayload {
    /// Stable delivery identifier for receiver-side deduplication.
    pub delivery_id: DeliveryId,
    /// Alert identifier.
    pub alert_id: String,
    /// Destination URL.
    pub destination: String,
    /// Human-readable alert message.
    pub message: String,
    /// Full alert payload.
    pub alert: Alert,
    /// 1-based attempt number for this delivery.
    pub attempt: u32,
}

/// Transport abstraction for delivering watchtower alerts.
pub trait AlertTransport: Send + Sync {
    /// Deliver `payload` to its destination.
    ///
    /// Implementations should return [`AlertDeliveryError::TransientFailure`]
    /// for retryable network/5xx errors and
    /// [`AlertDeliveryError::PermanentFailure`] for non-retryable 4xx/config
    /// errors.
    fn deliver<'a>(
        &'a self,
        payload: &'a DeliveryPayload,
    ) -> BoxFuture<'a, Result<(), AlertDeliveryError>>;
}

/// Default simulated webhook transport that validates the destination and logs
/// each delivery with its [`DeliveryId`].
#[derive(Debug, Default, Clone)]
pub struct WebhookAlertTransport;

impl AlertTransport for WebhookAlertTransport {
    fn deliver<'a>(
        &'a self,
        payload: &'a DeliveryPayload,
    ) -> BoxFuture<'a, Result<(), AlertDeliveryError>> {
        Box::pin(async move {
            validate_destination(&payload.destination)?;
            info!(
                delivery_id = %payload.delivery_id,
                alert_id = %payload.alert_id,
                destination = %payload.destination,
                attempt = payload.attempt,
                "Delivered watchtower alert"
            );
            Ok(())
        })
    }
}

/// Summary of a [`AlertDeliveryService::retry_pending_deliveries`] pass.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryReport {
    /// Pending deliveries that were due and attempted.
    pub attempted: usize,
    /// Deliveries that succeeded on this pass.
    pub delivered: usize,
    /// Deliveries that failed transiently and remain `Pending`.
    pub rescheduled: usize,
    /// Deliveries that transitioned to `Failed` (exhausted or permanent).
    pub failed: usize,
    /// Pending deliveries skipped because their `next_retry_at` is in the future.
    pub skipped_not_due: usize,
}

/// Service that persists and delivers watchtower alerts with retry safety.
#[derive(Clone)]
pub struct AlertDeliveryService {
    config: AlertDeliveryConfig,
    storage: Arc<dyn StorageBackend>,
    transport: Arc<dyn AlertTransport>,
}

impl AlertDeliveryService {
    /// Construct a new [`AlertDeliveryService`] after validating `config`.
    pub fn new(
        config: AlertDeliveryConfig,
        storage: Arc<dyn StorageBackend>,
        transport: Arc<dyn AlertTransport>,
    ) -> Result<Self, AlertDeliveryError> {
        config.validate()?;
        Ok(Self {
            config,
            storage,
            transport,
        })
    }

    /// Return the active delivery configuration.
    pub fn config(&self) -> &AlertDeliveryConfig {
        &self.config
    }

    /// Enqueue `alert` for delivery to `destination` and attempt immediate
    /// delivery.
    ///
    /// Derives a deterministic [`DeliveryId`] from `(alert.id, destination)`.
    /// If a delivery with that ID is already [`DeliveryStatus::Delivered`],
    /// this returns the existing record without re-invoking the transport.
    pub async fn enqueue_and_deliver(
        &self,
        alert: &Alert,
        destination: &str,
    ) -> Result<AlertDelivery, AlertDeliveryError> {
        let delivery_id = DeliveryId::for_alert(&alert.id, destination)?;
        self.enqueue_with_id_and_deliver(delivery_id, alert, destination)
            .await
    }

    /// Enqueue `alert` with an explicit [`DeliveryId`] and attempt immediate
    /// delivery.
    pub async fn enqueue_with_id_and_deliver(
        &self,
        delivery_id: DeliveryId,
        alert: &Alert,
        destination: &str,
    ) -> Result<AlertDelivery, AlertDeliveryError> {
        validate_alert_id(&alert.id)?;
        validate_destination(destination)?;

        if let Some(existing) = self
            .storage
            .get_alert_delivery(delivery_id.as_str())
            .map_err(|e| AlertDeliveryError::StorageError(e.to_string()))?
        {
            return match existing.status {
                DeliveryStatus::Delivered => Ok(existing),
                DeliveryStatus::Failed => Err(AlertDeliveryError::TerminalFailure {
                    delivery_id: existing.delivery_id.to_string(),
                    reason: existing
                        .last_error
                        .unwrap_or_else(|| "delivery previously failed".to_string()),
                }),
                DeliveryStatus::Pending => self.attempt_delivery(existing).await,
            };
        }

        let now = current_timestamp();
        let delivery = AlertDelivery::new(
            delivery_id,
            alert.clone(),
            destination,
            self.config.max_attempts,
            now,
        )?;

        self.storage
            .store_alert_delivery(&delivery)
            .map_err(|e| AlertDeliveryError::StorageError(e.to_string()))?;

        self.attempt_delivery(delivery).await
    }

    /// Retry all due [`DeliveryStatus::Pending`] deliveries from storage.
    pub async fn retry_pending_deliveries(&self) -> Result<RetryReport, AlertDeliveryError> {
        let pending = self
            .storage
            .get_pending_alert_deliveries()
            .map_err(|e| AlertDeliveryError::StorageError(e.to_string()))?;

        let now = current_timestamp();
        let mut report = RetryReport::default();

        for delivery in pending {
            if !delivery.is_due(now) {
                report.skipped_not_due += 1;
                continue;
            }

            report.attempted += 1;
            match self.attempt_delivery(delivery.clone()).await {
                Ok(_) => {
                    report.delivered += 1;
                }
                Err(err) => {
                    if let Some(updated) = self
                        .storage
                        .get_alert_delivery(delivery.delivery_id.as_str())
                        .map_err(|e| AlertDeliveryError::StorageError(e.to_string()))?
                    {
                        match updated.status {
                            DeliveryStatus::Failed => report.failed += 1,
                            DeliveryStatus::Pending => report.rescheduled += 1,
                            DeliveryStatus::Delivered => report.delivered += 1,
                        }
                    } else if err.is_retryable() {
                        report.rescheduled += 1;
                    } else {
                        report.failed += 1;
                    }
                }
            }
        }

        Ok(report)
    }

    /// Operator recovery entry point: immediately retry a specific delivery by
    /// its [`DeliveryId`], bypassing any pending backoff timer.
    ///
    /// Returns `Ok(delivery)` idempotently if already [`DeliveryStatus::Delivered`].
    pub async fn retry_delivery(
        &self,
        delivery_id: &DeliveryId,
    ) -> Result<AlertDelivery, AlertDeliveryError> {
        let delivery = self
            .storage
            .get_alert_delivery(delivery_id.as_str())
            .map_err(|e| AlertDeliveryError::StorageError(e.to_string()))?
            .ok_or_else(|| AlertDeliveryError::NotFound(delivery_id.to_string()))?;

        match delivery.status {
            DeliveryStatus::Delivered => Ok(delivery),
            DeliveryStatus::Failed => Err(AlertDeliveryError::TerminalFailure {
                delivery_id: delivery.delivery_id.to_string(),
                reason: delivery
                    .last_error
                    .unwrap_or_else(|| "delivery exhausted max_attempts".to_string()),
            }),
            DeliveryStatus::Pending => self.attempt_delivery(delivery).await,
        }
    }

    /// Retrieve all [`DeliveryStatus::Pending`] alert deliveries.
    pub fn pending_deliveries(&self) -> Result<Vec<AlertDelivery>, AlertDeliveryError> {
        self.storage
            .get_pending_alert_deliveries()
            .map_err(|e| AlertDeliveryError::StorageError(e.to_string()))
    }

    /// Look up a specific [`AlertDelivery`] by its [`DeliveryId`].
    pub fn get_delivery(
        &self,
        delivery_id: &DeliveryId,
    ) -> Result<Option<AlertDelivery>, AlertDeliveryError> {
        self.storage
            .get_alert_delivery(delivery_id.as_str())
            .map_err(|e| AlertDeliveryError::StorageError(e.to_string()))
    }

    async fn attempt_delivery(
        &self,
        mut delivery: AlertDelivery,
    ) -> Result<AlertDelivery, AlertDeliveryError> {
        if delivery.attempts >= delivery.max_attempts {
            let reason = delivery
                .last_error
                .clone()
                .unwrap_or_else(|| "max_attempts reached".to_string());
            delivery.status = DeliveryStatus::Failed;
            delivery.updated_at = current_timestamp();
            self.storage
                .update_alert_delivery(&delivery)
                .map_err(|e| AlertDeliveryError::StorageError(e.to_string()))?;
            return Err(AlertDeliveryError::TerminalFailure {
                delivery_id: delivery.delivery_id.to_string(),
                reason,
            });
        }

        let payload = delivery.payload();
        match self.transport.deliver(&payload).await {
            Ok(()) => {
                delivery.mark_delivered(current_timestamp());
                self.storage
                    .update_alert_delivery(&delivery)
                    .map_err(|e| AlertDeliveryError::StorageError(e.to_string()))?;
                Ok(delivery)
            }
            Err(err) => {
                let next_attempt = delivery.attempts.saturating_add(1);
                let backoff = self.config.backoff_for_attempt(next_attempt);
                delivery.record_failure(&err, backoff, current_timestamp());
                self.storage
                    .update_alert_delivery(&delivery)
                    .map_err(|e| AlertDeliveryError::StorageError(e.to_string()))?;

                warn!(
                    delivery_id = %delivery.delivery_id,
                    attempts = delivery.attempts,
                    max_attempts = delivery.max_attempts,
                    status = ?delivery.status,
                    error = %err,
                    "Watchtower alert delivery failed"
                );
                Err(err)
            }
        }
    }
}

/// Errors produced by [`AlertDeliveryService`] and [`DeliveryId`] validation.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AlertDeliveryError {
    #[error("Invalid delivery ID: {0}")]
    InvalidDeliveryId(String),

    #[error("Invalid alert destination: {0}")]
    InvalidDestination(String),

    #[error("Invalid alert: {0}")]
    InvalidAlert(String),

    #[error("Invalid alert delivery configuration: {0}")]
    InvalidConfig(String),

    #[error("Alert delivery not found: {0}")]
    NotFound(String),

    #[error("Alert delivery {delivery_id} failed permanently: {reason}")]
    TerminalFailure { delivery_id: String, reason: String },

    #[error("Transient delivery failure for {delivery_id}: {reason}")]
    TransientFailure { delivery_id: String, reason: String },

    #[error("Permanent delivery failure for {delivery_id}: {reason}")]
    PermanentFailure { delivery_id: String, reason: String },

    #[error("Storage error during alert delivery: {0}")]
    StorageError(String),
}

impl AlertDeliveryError {
    /// Return `true` when the failure is transient and safe to retry.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::TransientFailure { .. })
    }
}

impl From<StorageError> for AlertDeliveryError {
    fn from(err: StorageError) -> Self {
        Self::StorageError(err.to_string())
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryStorage;
    use parking_lot::Mutex;
    use std::collections::VecDeque;

    struct ScriptedTransport {
        outcomes: Mutex<VecDeque<Result<(), AlertDeliveryError>>>,
        seen_payloads: Mutex<Vec<DeliveryPayload>>,
    }

    impl ScriptedTransport {
        fn new(outcomes: Vec<Result<(), AlertDeliveryError>>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into()),
                seen_payloads: Mutex::new(Vec::new()),
            }
        }

        fn seen(&self) -> Vec<DeliveryPayload> {
            self.seen_payloads.lock().clone()
        }
    }

    impl AlertTransport for ScriptedTransport {
        fn deliver<'a>(
            &'a self,
            payload: &'a DeliveryPayload,
        ) -> BoxFuture<'a, Result<(), AlertDeliveryError>> {
            self.seen_payloads.lock().push(payload.clone());
            let next = self.outcomes.lock().pop_front().unwrap_or(Ok(()));
            Box::pin(async move { next })
        }
    }

    struct FailingStoreBackend;

    impl StorageBackend for FailingStoreBackend {
        fn store_channel_state(
            &self,
            _channel_id: &str,
            _state: &crate::monitor::ChannelMonitorState,
        ) -> Result<(), StorageError> {
            Ok(())
        }
        fn get_channel_state(
            &self,
            _channel_id: &str,
        ) -> Result<Option<crate::monitor::ChannelMonitorState>, StorageError> {
            Ok(None)
        }
        fn store_alert(&self, _alert: &Alert) -> Result<(), StorageError> {
            Ok(())
        }
        fn get_alerts(&self, _limit: usize) -> Result<Vec<Alert>, StorageError> {
            Ok(Vec::new())
        }
        fn store_channel_update(
            &self,
            _update: &crate::monitor::ChannelUpdate,
        ) -> Result<(), StorageError> {
            Ok(())
        }
        fn get_channel_update(
            &self,
            _channel_id: &str,
        ) -> Result<Option<crate::monitor::ChannelUpdate>, StorageError> {
            Ok(None)
        }
        fn store_subscription(&self, _channel_id: &str) -> Result<(), StorageError> {
            Ok(())
        }
        fn get_subscriptions(&self) -> Result<Vec<String>, StorageError> {
            Ok(Vec::new())
        }
        fn remove_subscription(&self, _channel_id: &str) -> Result<(), StorageError> {
            Ok(())
        }
        fn compact(
            &self,
            _policy: &crate::storage::CompactionPolicy,
        ) -> Result<crate::storage::CompactionReport, StorageError> {
            Ok(crate::storage::CompactionReport::default())
        }
        fn store_justice_action(
            &self,
            _action: &crate::justice::JusticeAction,
        ) -> Result<(), StorageError> {
            Ok(())
        }
        fn get_justice_action(
            &self,
            _id: &str,
        ) -> Result<Option<crate::justice::JusticeAction>, StorageError> {
            Ok(None)
        }
        fn get_pending_justice_actions(
            &self,
        ) -> Result<Vec<crate::justice::JusticeAction>, StorageError> {
            Ok(Vec::new())
        }
        fn update_justice_action_status(
            &self,
            _id: &str,
            _status: crate::justice::ActionStatus,
            _tx_hash: Option<&str>,
        ) -> Result<(), StorageError> {
            Ok(())
        }
        fn store_alert_delivery(&self, _delivery: &AlertDelivery) -> Result<(), StorageError> {
            Err(StorageError::DatabaseError("disk full".to_string()))
        }
        fn get_alert_delivery(
            &self,
            _delivery_id: &str,
        ) -> Result<Option<AlertDelivery>, StorageError> {
            Ok(None)
        }
        fn get_pending_alert_deliveries(&self) -> Result<Vec<AlertDelivery>, StorageError> {
            Ok(Vec::new())
        }
        fn update_alert_delivery(&self, _delivery: &AlertDelivery) -> Result<(), StorageError> {
            Ok(())
        }
    }

    #[test]
    fn delivery_id_validation_rejects_invalid_inputs() {
        assert!(matches!(
            DeliveryId::new(""),
            Err(AlertDeliveryError::InvalidDeliveryId(_))
        ));
        assert!(matches!(
            DeliveryId::new("   "),
            Err(AlertDeliveryError::InvalidDeliveryId(_))
        ));
        assert!(matches!(
            DeliveryId::new("has space"),
            Err(AlertDeliveryError::InvalidDeliveryId(_))
        ));
        assert!(matches!(
            DeliveryId::new("a".repeat(MAX_DELIVERY_ID_LEN + 1)),
            Err(AlertDeliveryError::InvalidDeliveryId(_))
        ));
        assert!(DeliveryId::new("dlv_valid-123").is_ok());
    }

    #[test]
    fn destination_validation_rejects_unsafe_urls() {
        assert!(validate_destination("").is_err());
        assert!(validate_destination("ftp://example.com").is_err());
        assert!(validate_destination("https://").is_err());
        assert!(validate_destination("https://example.com/hook with space").is_err());
        assert!(validate_destination("https://hooks.example.com/alerts").is_ok());
        assert!(validate_destination("http://127.0.0.1:8080/webhook").is_ok());
    }

    #[test]
    fn config_validation_and_backoff_boundaries() {
        let bad_attempts = AlertDeliveryConfig {
            max_attempts: 0,
            ..AlertDeliveryConfig::default()
        };
        assert!(matches!(
            bad_attempts.validate(),
            Err(AlertDeliveryError::InvalidConfig(_))
        ));

        let bad_backoff = AlertDeliveryConfig {
            initial_backoff_secs: 60,
            max_backoff_secs: 30,
            ..AlertDeliveryConfig::default()
        };
        assert!(matches!(
            bad_backoff.validate(),
            Err(AlertDeliveryError::InvalidConfig(_))
        ));

        let cfg = AlertDeliveryConfig {
            max_attempts: 5,
            initial_backoff_secs: 10,
            max_backoff_secs: 100,
        };
        assert_eq!(cfg.backoff_for_attempt(1), 10);
        assert_eq!(cfg.backoff_for_attempt(2), 20);
        assert_eq!(cfg.backoff_for_attempt(4), 80);
        assert_eq!(cfg.backoff_for_attempt(5), 100);
        assert_eq!(cfg.backoff_for_attempt(100), 100);
    }

    #[tokio::test]
    async fn transient_failure_preserves_delivery_id_across_retry() {
        let storage = Arc::new(InMemoryStorage::new());
        let transport = Arc::new(ScriptedTransport::new(vec![
            Err(AlertDeliveryError::TransientFailure {
                delivery_id: "ignored".to_string(),
                reason: "503 unavailable".to_string(),
            }),
            Ok(()),
        ]));
        let service = AlertDeliveryService::new(
            AlertDeliveryConfig::default(),
            storage.clone(),
            transport.clone(),
        )
        .unwrap();

        let alert = Alert::breach_attempt("chan-1".to_string(), 1, 2);
        let dest = "https://hooks.example.com/watchtower";

        let err = service.enqueue_and_deliver(&alert, dest).await.unwrap_err();
        assert!(err.is_retryable());

        let pending = service.pending_deliveries().unwrap();
        assert_eq!(pending.len(), 1);
        let delivery_id = pending[0].delivery_id.clone();
        assert_eq!(pending[0].status, DeliveryStatus::Pending);
        assert_eq!(pending[0].attempts, 1);

        let recovered = service.retry_delivery(&delivery_id).await.unwrap();
        assert_eq!(recovered.status, DeliveryStatus::Delivered);
        assert_eq!(recovered.attempts, 2);
        assert_eq!(recovered.delivery_id, delivery_id);

        let seen = transport.seen();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].delivery_id, seen[1].delivery_id);
        assert_eq!(seen[0].attempt, 1);
        assert_eq!(seen[1].attempt, 2);

        // Idempotent retry on an already-delivered ID does not re-send.
        let idempotent = service.retry_delivery(&delivery_id).await.unwrap();
        assert_eq!(idempotent.status, DeliveryStatus::Delivered);
        assert_eq!(transport.seen().len(), 2);
    }

    #[tokio::test]
    async fn permanent_failure_and_max_attempts_mark_failed() {
        let storage = Arc::new(InMemoryStorage::new());
        let transport = Arc::new(ScriptedTransport::new(vec![Err(
            AlertDeliveryError::PermanentFailure {
                delivery_id: "dlv".to_string(),
                reason: "410 gone".to_string(),
            },
        )]));
        let service =
            AlertDeliveryService::new(AlertDeliveryConfig::default(), storage, transport).unwrap();

        let alert = Alert::breach_attempt("chan-2".to_string(), 1, 2);
        let dest = "https://hooks.example.com/watchtower";
        let delivery_id = DeliveryId::for_alert(&alert.id, dest).unwrap();

        assert!(service.enqueue_and_deliver(&alert, dest).await.is_err());
        let record = service.get_delivery(&delivery_id).unwrap().unwrap();
        assert_eq!(record.status, DeliveryStatus::Failed);
        assert_eq!(record.attempts, 1);

        assert!(matches!(
            service.retry_delivery(&delivery_id).await,
            Err(AlertDeliveryError::TerminalFailure { .. })
        ));
    }

    #[tokio::test]
    async fn storage_failure_prevents_transport_invocation() {
        let storage = Arc::new(FailingStoreBackend);
        let transport = Arc::new(ScriptedTransport::new(vec![Ok(())]));
        let service =
            AlertDeliveryService::new(AlertDeliveryConfig::default(), storage, transport.clone())
                .unwrap();

        let alert = Alert::breach_attempt("chan-3".to_string(), 1, 2);
        let err = service
            .enqueue_and_deliver(&alert, "https://hooks.example.com/watchtower")
            .await
            .unwrap_err();
        assert!(matches!(err, AlertDeliveryError::StorageError(_)));
        assert!(transport.seen().is_empty());
    }
}

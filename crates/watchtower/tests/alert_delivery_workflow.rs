//! Integration tests for retryable watchtower alert delivery with delivery IDs.

use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;
use watchtower::alert::{
    AlertDeliveryConfig, AlertDeliveryError, AlertTransport, BoxFuture, DeliveryId,
    DeliveryPayload, DeliveryStatus,
};
use watchtower::{Alert, Watchtower, WatchtowerConfig, WatchtowerError};

struct FlakyWebhookTransport {
    outcomes: Mutex<VecDeque<Result<(), AlertDeliveryError>>>,
    received: Mutex<Vec<DeliveryPayload>>,
}

impl FlakyWebhookTransport {
    fn new(outcomes: Vec<Result<(), AlertDeliveryError>>) -> Self {
        Self {
            outcomes: Mutex::new(outcomes.into()),
            received: Mutex::new(Vec::new()),
        }
    }

    fn received(&self) -> Vec<DeliveryPayload> {
        self.received.lock().clone()
    }
}

impl AlertTransport for FlakyWebhookTransport {
    fn deliver<'a>(
        &'a self,
        payload: &'a DeliveryPayload,
    ) -> BoxFuture<'a, Result<(), AlertDeliveryError>> {
        self.received.lock().push(payload.clone());
        let outcome = self.outcomes.lock().pop_front().unwrap_or(Ok(()));
        Box::pin(async move { outcome })
    }
}

#[tokio::test]
async fn watchtower_alert_delivery_recovers_with_stable_delivery_id() {
    let transport = Arc::new(FlakyWebhookTransport::new(vec![
        Err(AlertDeliveryError::TransientFailure {
            delivery_id: "initial".to_string(),
            reason: "upstream 502".to_string(),
        }),
        Ok(()),
    ]));

    let config = WatchtowerConfig {
        alert_webhook_url: Some("https://ops.example.com/watchtower-alerts".to_string()),
        alert_delivery: AlertDeliveryConfig {
            max_attempts: 3,
            initial_backoff_secs: 60,
            max_backoff_secs: 300,
        },
        ..Default::default()
    };

    let watchtower = Watchtower::with_alert_transport(config, transport.clone()).unwrap();
    let alert = Alert::breach_attempt("channel-integration-1".to_string(), 10, 12);

    // Initial delivery fails transiently; error is surfaced and record stays Pending.
    let err = watchtower.deliver_alert(&alert).await.unwrap_err();
    assert!(matches!(err, WatchtowerError::AlertDeliveryFailed(_)));

    let pending = watchtower.pending_alert_deliveries().unwrap();
    assert_eq!(pending.len(), 1);
    let delivery_id: DeliveryId = pending[0].delivery_id.clone();
    assert_eq!(pending[0].status, DeliveryStatus::Pending);
    assert_eq!(pending[0].attempts, 1);

    // Automatic retry pass respects backoff and skips the not-yet-due record.
    let skipped = watchtower.retry_pending_alerts().await.unwrap();
    assert_eq!(skipped.attempted, 0);
    assert_eq!(skipped.skipped_not_due, 1);

    // Operator recovery retries immediately by delivery ID.
    let delivered = watchtower.retry_alert_delivery(&delivery_id).await.unwrap();
    assert_eq!(delivered.status, DeliveryStatus::Delivered);
    assert_eq!(delivered.attempts, 2);
    assert_eq!(delivered.delivery_id, delivery_id);
    assert!(watchtower.pending_alert_deliveries().unwrap().is_empty());

    // Receiver observed the exact same delivery ID on both attempts.
    let received = transport.received();
    assert_eq!(received.len(), 2);
    assert_eq!(received[0].delivery_id, delivery_id);
    assert_eq!(received[1].delivery_id, delivery_id);
    assert_eq!(received[0].attempt, 1);
    assert_eq!(received[1].attempt, 2);

    let stored = watchtower
        .get_alert_delivery(&delivery_id)
        .unwrap()
        .expect("delivery record should be persisted");
    assert_eq!(stored.status, DeliveryStatus::Delivered);
}

//! Integration tests for the locally documented partial-funding recovery path
//! (#357): create → detect → recover → use, and the abort alternative.

use payment_channel::funding::{FundingResolution, FundingSide};
use payment_channel::{
    ChannelManager, ChannelStatus, PaymentChannelError, PaymentDirection, SignatureSigner,
};

struct DigestSigner;

impl SignatureSigner for DigestSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PaymentChannelError> {
        Ok(message.to_vec())
    }

    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        _public_key: &[u8],
    ) -> Result<bool, PaymentChannelError> {
        Ok(message == signature)
    }

    fn public_key(&self) -> Vec<u8> {
        vec![7u8; 32]
    }
}

async fn partially_funded_channel(timeout: u32) -> (ChannelManager, String) {
    let manager = ChannelManager::new(Box::new(DigestSigner));
    let state = manager
        .create_channel("alice".to_string(), "bob".to_string(), 1_000, 0, timeout, 0)
        .await
        .expect("channel creation");
    manager
        .set_remote_public_key(&state.channel_id, vec![8u8; 32])
        .expect("counterparty key");
    (manager, state.channel_id)
}

#[tokio::test]
async fn a_partially_funded_channel_is_recovered_before_it_is_used() {
    let (manager, channel_id) = partially_funded_channel(100).await;
    let recovery = manager
        .open_funding_recovery(&channel_id, FundingSide::Local, 500, 10)
        .expect("recovery opened");

    assert_eq!(
        manager
            .execute_payment_at(&channel_id, 100, PaymentDirection::ToThem, 11)
            .unwrap_err(),
        PaymentChannelError::ChannelAwaitingFunding {
            channel_id: channel_id.clone()
        }
    );

    let signature = recovery.digest().to_vec();
    let recovered = manager
        .complete_funding_recovery(&channel_id, 500, &signature, 11)
        .expect("outstanding funds supplied");
    assert_eq!(recovered.status, ChannelStatus::Open);
    assert_eq!(recovered.their_balance, 500);
    assert_eq!(
        manager
            .get_funding_recovery(&channel_id)
            .unwrap()
            .resolution,
        FundingResolution::Completed
    );

    manager
        .execute_payment_at(&channel_id, 100, PaymentDirection::ToThem, 12)
        .expect("the recovered channel is usable again");
    assert_eq!(manager.get_channel(&channel_id).unwrap().our_balance, 900);
}

#[tokio::test]
async fn an_abandoned_funding_leg_is_closed_after_the_deadline() {
    let (manager, channel_id) = partially_funded_channel(10).await;
    let recovery = manager
        .open_funding_recovery(&channel_id, FundingSide::Local, 500, 10)
        .expect("recovery opened");
    let signature = recovery.digest().to_vec();

    assert!(matches!(
        manager.abort_funding_recovery(&channel_id, &signature, 20),
        Err(PaymentChannelError::FundingDeadlineNotReached { .. })
    ));

    let aborted = manager
        .abort_funding_recovery(&channel_id, &signature, 21)
        .expect("deadline passed");
    assert_eq!(aborted.status, ChannelStatus::ForceClosed);
    assert_eq!(
        manager
            .get_funding_recovery(&channel_id)
            .unwrap()
            .resolution,
        FundingResolution::Aborted
    );
    assert!(matches!(
        manager.complete_funding_recovery(&channel_id, 500, &signature, 22),
        Err(PaymentChannelError::InvalidState(_))
    ));
}

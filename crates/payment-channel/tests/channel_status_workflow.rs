//! Integration tests for pending HTLC count and capacity in channel status (issue #355).

use std::sync::Arc;
use payment_channel::{
    ChannelStatus, Ed25519Signer, HtlcDirection, HtlcState, PaymentChannelError,
    PaymentChannelManager,
};

#[test]
fn channel_status_tracks_pending_htlc_count_and_capacity_across_lifecycle() {
    let signer = Arc::new(Ed25519Signer::generate());
    let manager = PaymentChannelManager::new(signer);
    let channel_id = manager
        .open_channel("alice".to_string(), "bob".to_string(), 600, 400, 100, 10)
        .unwrap();

    let initial = manager.get_channel_status(&channel_id).unwrap();
    assert_eq!(initial.status, ChannelStatus::Open);
    assert_eq!(initial.pending_htlc_count, 0);
    assert_eq!(initial.pending_htlc_amount, 0);
    assert_eq!(initial.capacity, 1_000);
    assert_eq!(initial.available_capacity, 1_000);

    // Construct a state with active + settled HTLCs and verify status_info.
    let mut state = manager.get_channel(&channel_id).unwrap();
    state.pending_htlcs.push(HtlcState {
        htlc_id: "htlc-1".to_string(),
        amount: 200,
        hashlock: vec![1; 32],
        timelock: 500,
        is_claimed: false,
        is_refunded: false,
        preimage: None,
        direction: HtlcDirection::Outgoing,
    });
    state.pending_htlcs.push(HtlcState {
        htlc_id: "htlc-2-settled".to_string(),
        amount: 100,
        hashlock: vec![2; 32],
        timelock: 500,
        is_claimed: true,
        is_refunded: false,
        preimage: Some(vec![3; 32]),
        direction: HtlcDirection::Incoming,
    });

    let with_htlc = state.status_info().unwrap();
    assert_eq!(with_htlc.pending_htlc_count, 1);
    assert_eq!(with_htlc.pending_htlc_amount, 200);
    assert_eq!(with_htlc.capacity, 1_000);
    assert_eq!(with_htlc.available_capacity, 800);

    // Missing channel returns actionable ChannelNotFound error.
    let err = manager.get_channel_status("nonexistent").unwrap_err();
    assert!(matches!(err, PaymentChannelError::ChannelNotFound(_)));
}

use soroban_sdk::{symbol_short, Address, Bytes, BytesN, Env, Symbol};
use crate::{AtomicSwap, DataKey, HtlcContract, SwapStatus, SwapEvent};

#[test]
fn test_create_swap() {
    let env = Env::default();
    let contract_id = env.register_contract(None, HtlcContract);
    let client = HtlcContractClient::new(&env, &contract_id);

    let participant = Address::random(&env);
    let initiator_asset = Address::random(&env);
    let participant_asset = Address::random(&env);
    let hash_lock = BytesN::from_array(&env, &[1; 32]);
    let initiator_amount = 1000;
    let participant_amount = 500;
    let timeout_hours = 24;

    let swap_id = client.create_swap(
        &participant,
        &hash_lock,
        &initiator_asset,
        &participant_asset,
        &initiator_amount,
        &participant_amount,
        &timeout_hours,
    );

    // Verify swap was created
    let swap = client.get_swap(&swap_id);
    assert_eq!(swap.participant, participant);
    assert_eq!(swap.hash_lock, hash_lock);
    assert_eq!(swap.initiator_asset, initiator_asset);
    assert_eq!(swap.participant_asset, participant_asset);
    assert_eq!(swap.initiator_amount, initiator_amount);
    assert_eq!(swap.participant_amount, participant_amount);
    assert_eq!(swap.status, SwapStatus::Pending);
}

#[test]
fn test_complete_swap() {
    let env = Env::default();
    let contract_id = env.register_contract(None, HtlcContract);
    let client = HtlcContractClient::new(&env, &contract_id);

    let participant = Address::random(&env);
    let initiator_asset = Address::random(&env);
    let participant_asset = Address::random(&env);
    let preimage = Bytes::from_slice(&env, b"secret_preimage");
    let hash_lock = env.crypto().sha256(&preimage);
    let initiator_amount = 1000;
    let participant_amount = 500;
    let timeout_hours = 24;

    let swap_id = client.create_swap(
        &participant,
        &hash_lock,
        &initiator_asset,
        &participant_asset,
        &initiator_amount,
        &participant_amount,
        &timeout_hours,
    );

    // Complete the swap
    client.complete_swap(&swap_id, &preimage);

    // Verify swap is completed
    let swap = client.get_swap(&swap_id);
    assert_eq!(swap.status, SwapStatus::Completed);
    assert_eq!(swap.preimage, Some(preimage));
}

#[test]
fn test_complete_swap_invalid_preimage() {
    let env = Env::default();
    let contract_id = env.register_contract(None, HtlcContract);
    let client = HtlcContractClient::new(&env, &contract_id);

    let participant = Address::random(&env);
    let initiator_asset = Address::random(&env);
    let participant_asset = Address::random(&env);
    let hash_lock = BytesN::from_array(&env, &[1; 32]);
    let wrong_preimage = Bytes::from_slice(&env, b"wrong_secret");
    let initiator_amount = 1000;
    let participant_amount = 500;
    let timeout_hours = 24;

    let swap_id = client.create_swap(
        &participant,
        &hash_lock,
        &initiator_asset,
        &participant_asset,
        &initiator_amount,
        &participant_amount,
        &timeout_hours,
    );

    // Try to complete with wrong preimage - should fail
    let result = env.try_invoke_contract(
        &contract_id,
        &symbol_short!("complete_swap"),
        (swap_id.clone(), wrong_preimage),
    );
    assert!(result.is_err());
}

#[test]
fn test_refund_swap() {
    let env = Env::default();
    let contract_id = env.register_contract(None, HtlcContract);
    let client = HtlcContractClient::new(&env, &contract_id);

    let participant = Address::random(&env);
    let initiator_asset = Address::random(&env);
    let participant_asset = Address::random(&env);
    let hash_lock = BytesN::from_array(&env, &[1; 32]);
    let initiator_amount = 1000;
    let participant_amount = 500;
    let timeout_hours = 1; // Short timeout for testing

    let swap_id = client.create_swap(
        &participant,
        &hash_lock,
        &initiator_asset,
        &participant_asset,
        &initiator_amount,
        &participant_amount,
        &timeout_hours,
    );

    // Advance time past timeout
    env.ledger().set(10000, 10000, 1);

    // Refund the swap
    client.refund_swap(&swap_id);

    // Verify swap is refunded
    let swap = client.get_swap(&swap_id);
    assert_eq!(swap.status, SwapStatus::Refunded);
}

#[test]
fn test_refund_before_timeout() {
    let env = Env::default();
    let contract_id = env.register_contract(None, HtlcContract);
    let client = HtlcContractClient::new(&env, &contract_id);

    let participant = Address::random(&env);
    let initiator_asset = Address::random(&env);
    let participant_asset = Address::random(&env);
    let hash_lock = BytesN::from_array(&env, &[1; 32]);
    let initiator_amount = 1000;
    let participant_amount = 500;
    let timeout_hours = 24;

    let swap_id = client.create_swap(
        &participant,
        &hash_lock,
        &initiator_asset,
        &participant_asset,
        &initiator_amount,
        &participant_amount,
        &timeout_hours,
    );

    // Try to refund before timeout - should fail
    let result = env.try_invoke_contract(
        &contract_id,
        &symbol_short!("refund_swap"),
        swap_id,
    );
    assert!(result.is_err());
}

#[test]
fn test_can_complete() {
    let env = Env::default();
    let contract_id = env.register_contract(None, HtlcContract);
    let client = HtlcContractClient::new(&env, &contract_id);

    let participant = Address::random(&env);
    let initiator_asset = Address::random(&env);
    let participant_asset = Address::random(&env);
    let hash_lock = BytesN::from_array(&env, &[1; 32]);
    let initiator_amount = 1000;
    let participant_amount = 500;
    let timeout_hours = 24;

    let swap_id = client.create_swap(
        &participant,
        &hash_lock,
        &initiator_asset,
        &participant_asset,
        &initiator_amount,
        &participant_amount,
        &timeout_hours,
    );

    // Should be able to complete initially
    assert!(client.can_complete(&swap_id));

    // Advance time past timeout
    env.ledger().set(100000, 100000, 1);

    // Should not be able to complete after timeout
    assert!(!client.can_complete(&swap_id));
}

#[test]
fn test_can_refund() {
    let env = Env::default();
    let contract_id = env.register_contract(None, HtlcContract);
    let client = HtlcContractClient::new(&env, &contract_id);

    let participant = Address::random(&env);
    let initiator_asset = Address::random(&env);
    let participant_asset = Address::random(&env);
    let hash_lock = BytesN::from_array(&env, &[1; 32]);
    let initiator_amount = 1000;
    let participant_amount = 500;
    let timeout_hours = 1;

    let swap_id = client.create_swap(
        &participant,
        &hash_lock,
        &initiator_asset,
        &participant_asset,
        &initiator_amount,
        &participant_amount,
        &timeout_hours,
    );

    // Should not be able to refund initially
    assert!(!client.can_refund(&swap_id));

    // Advance time past timeout
    env.ledger().set(10000, 10000, 1);

    // Should be able to refund after timeout
    assert!(client.can_refund(&swap_id));
}

#[test]
fn test_swap_events() {
    let env = Env::default();
    let contract_id = env.register_contract(None, HtlcContract);
    let client = HtlcContractClient::new(&env, &contract_id);

    let participant = Address::random(&env);
    let initiator_asset = Address::random(&env);
    let participant_asset = Address::random(&env);
    let preimage = Bytes::from_slice(&env, b"secret_preimage");
    let hash_lock = env.crypto().sha256(&preimage);
    let initiator_amount = 1000;
    let participant_amount = 500;
    let timeout_hours = 24;

    let swap_id = client.create_swap(
        &participant,
        &hash_lock,
        &initiator_asset,
        &participant_asset,
        &initiator_amount,
        &participant_amount,
        &timeout_hours,
    );

    // Check that creation event was emitted
    let events = env.events().all();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].topics[0], symbol_short!("swap_created"));
    assert_eq!(events[0].data, SwapEvent {
        swap_id: swap_id.clone(),
        status: SwapStatus::Pending,
        timestamp: env.ledger().timestamp(),
    });

    // Complete the swap
    client.complete_swap(&swap_id, &preimage);

    // Check that completion event was emitted
    let events = env.events().all();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].topics[0], symbol_short!("swap_completed"));
    assert_eq!(events[1].data, SwapEvent {
        swap_id,
        status: SwapStatus::Completed,
        timestamp: env.ledger().timestamp(),
    });
}

#[test]
fn test_get_nonexistent_swap() {
    let env = Env::default();
    let contract_id = env.register_contract(None, HtlcContract);
    let client = HtlcContractClient::new(&env, &contract_id);

    let nonexistent_swap_id = BytesN::from_array(&env, &[2; 32]);

    // Should panic when trying to get nonexistent swap
    let result = env.try_invoke_contract(
        &contract_id,
        &symbol_short!("get_swap"),
        nonexistent_swap_id,
    );
    assert!(result.is_err());
}

#[test]
fn test_multiple_swaps() {
    let env = Env::default();
    let contract_id = env.register_contract(None, HtlcContract);
    let client = HtlcContractClient::new(&env, &contract_id);

    let participant1 = Address::random(&env);
    let participant2 = Address::random(&env);
    let initiator_asset = Address::random(&env);
    let participant_asset = Address::random(&env);
    let hash_lock1 = BytesN::from_array(&env, &[1; 32]);
    let hash_lock2 = BytesN::from_array(&env, &[2; 32]);
    let initiator_amount = 1000;
    let participant_amount = 500;
    let timeout_hours = 24;

    // Create two swaps
    let swap_id1 = client.create_swap(
        &participant1,
        &hash_lock1,
        &initiator_asset,
        &participant_asset,
        &initiator_amount,
        &participant_amount,
        &timeout_hours,
    );

    let swap_id2 = client.create_swap(
        &participant2,
        &hash_lock2,
        &initiator_asset,
        &participant_asset,
        &initiator_amount,
        &participant_amount,
        &timeout_hours,
    );

    // Verify both swaps exist and are independent
    let swap1 = client.get_swap(&swap_id1);
    let swap2 = client.get_swap(&swap_id2);

    assert_eq!(swap1.participant, participant1);
    assert_eq!(swap1.hash_lock, hash_lock1);
    assert_eq!(swap2.participant, participant2);
    assert_eq!(swap2.hash_lock, hash_lock2);

    // Complete first swap
    let preimage1 = Bytes::from_slice(&env, b"secret1");
    client.complete_swap(&swap_id1, &preimage1);

    // Verify only first swap is completed
    let updated_swap1 = client.get_swap(&swap_id1);
    let updated_swap2 = client.get_swap(&swap_id2);

    assert_eq!(updated_swap1.status, SwapStatus::Completed);
    assert_eq!(updated_swap2.status, SwapStatus::Pending);
}

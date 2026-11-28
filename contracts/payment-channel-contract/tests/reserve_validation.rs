//! Integration tests for channel reserve validation before payment acceptance (#356).

use payment_channel_contract::{PaymentChannel, PaymentChannelClient, PaymentChannelError};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env};

fn signature(env: &Env) -> BytesN<64> {
    BytesN::from_array(env, &[0u8; 64])
}

#[test]
fn integration_channel_reserve_workflow_across_payments_htlcs_topup_and_close() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, PaymentChannel);
    let client = PaymentChannelClient::new(&env, &contract_id);

    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    // 1. Initialize channel with 1,000 each and a 200 per-participant reserve.
    let channel_id = client.initialize_with_reserve(&alice, &bob, &1_000, &1_000, &3_600, &0, &200);
    let sig = signature(&env);

    // 2. Normal payment leaving Alice at 500 (>= 200) succeeds.
    client.update_state(&channel_id, &500, &1_500, &sig, &sig);
    let state = client.get_channel_state(&channel_id);
    assert_eq!(state.balance_a, 500);
    assert_eq!(state.balance_b, 1_500);
    assert_eq!(state.sequence_number, 1);

    // 3. Payment breaching Alice's reserve (100 < 200) is rejected with ReserveNotMet
    //    and leaves the on-chain state unchanged.
    assert_eq!(
        client.try_update_state(&channel_id, &100, &1_900, &sig, &sig),
        Err(Ok(PaymentChannelError::ReserveNotMet))
    );
    assert_eq!(client.get_channel_state(&channel_id), state);

    // 4. HTLC of 300 leaves Alice at exact reserve (200 == 200) and succeeds.
    let hashlock = BytesN::from_array(&env, &[7u8; 32]);
    let timelock = env.ledger().sequence() + 20;
    let _htlc_id = client.create_htlc(&channel_id, &hashlock, &timelock, &300, &bob);
    assert_eq!(client.get_channel_state(&channel_id).balance_a, 200);

    // 5. Additional HTLC of 1 would drop Alice below reserve and is rejected.
    let hashlock_2 = BytesN::from_array(&env, &[8u8; 32]);
    assert_eq!(
        client.try_create_htlc(&channel_id, &hashlock_2, &timelock, &1, &bob),
        Err(Ok(PaymentChannelError::ReserveNotMet))
    );

    // 6. Topping up Alice restores capacity above reserve so further HTLCs succeed.
    client.top_up(&channel_id, &500, &alice);
    let _htlc_id_2 = client.create_htlc(&channel_id, &hashlock_2, &timelock, &400, &bob);
    assert_eq!(client.get_channel_state(&channel_id).balance_a, 300);

    // 7. Existing channels without reserve (initialize) preserve old behavior (can drain to 0).
    let no_reserve_id = client.initialize(&alice, &bob, &500, &500, &3_600, &0);
    client.update_state(&no_reserve_id, &0, &1_000, &sig, &sig);
    assert_eq!(client.get_channel_state(&no_reserve_id).balance_a, 0);

    // 8. Cooperative close on the no-reserve channel settles cleanly.
    client.cooperative_close(&no_reserve_id, &0, &1_000, &sig, &sig);
    assert!(client.get_channel_state(&no_reserve_id).is_cooperative_close);
}

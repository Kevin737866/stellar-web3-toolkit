//! Integration tests for settlement on a signed channel state (#352): a state
//! the channel has already superseded must be refused.

use payment_channel_contract::{PaymentChannel, PaymentChannelClient, PaymentChannelError};
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{Address, BytesN, Env, InvokeError, TryFromVal};

struct Fixture {
    env: Env,
    client: PaymentChannelClient<'static>,
    channel_id: BytesN<32>,
}

fn fixture() -> Fixture {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, PaymentChannel);
    let client = PaymentChannelClient::new(&env, &contract_id);

    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let channel_id = client.initialize(&alice, &bob, &1_000, &1_000, &3_600, &0);

    Fixture {
        env,
        client,
        channel_id,
    }
}

fn signature(env: &Env) -> BytesN<64> {
    BytesN::from_array(env, &[0u8; 64])
}

fn settle_call(
    f: &Fixture,
    balance_a: i128,
    balance_b: i128,
    signed_sequence: u32,
) -> Result<Result<(), soroban_sdk::ConversionError>, Result<PaymentChannelError, InvokeError>> {
    f.client.try_settle_signed_state(
        &f.channel_id,
        &balance_a,
        &balance_b,
        &signed_sequence,
        &signature(&f.env),
        &signature(&f.env),
    )
}

fn settle_err(f: &Fixture, balance_a: i128, balance_b: i128, sequence: u32) -> PaymentChannelError {
    match settle_call(f, balance_a, balance_b, sequence) {
        Ok(Ok(())) => panic!("the settlement should have been rejected"),
        Ok(Err(conversion)) => panic!("the result did not convert: {conversion:?}"),
        Err(Ok(error)) => error,
        Err(Err(invoke)) => panic!("the call never reached the contract: {invoke:?}"),
    }
}

fn settle_events(f: &Fixture) -> usize {
    f.env
        .events()
        .all()
        .iter()
        .filter(|(_, topics, _)| match topics.get(0) {
            Some(topic) => soroban_sdk::String::try_from_val(&f.env, &topic)
                .is_ok_and(|name| name == soroban_sdk::String::from_str(&f.env, "channel_settled")),
            None => false,
        })
        .count()
}

/// Move the channel's sequence number forward through real payments.
fn advance_sequence(f: &Fixture, updates: u32) {
    for _ in 0..updates {
        let state = f.client.get_channel_state(&f.channel_id);
        let (a, b) = (state.balance_a - 10, state.balance_b + 10);
        f.client.update_state(
            &f.channel_id,
            &a,
            &b,
            &signature(&f.env),
            &signature(&f.env),
        );
    }
}

#[test]
fn a_newer_signed_state_settles_the_channel() {
    let f = fixture();

    match settle_call(&f, 1_200, 800, 3) {
        Ok(Ok(())) => {}
        Ok(Err(conversion)) => panic!("the result did not convert: {conversion:?}"),
        Err(Ok(error)) => panic!("a newer state must settle: {error:?}"),
        Err(Err(invoke)) => panic!("the call never reached the contract: {invoke:?}"),
    }

    let state = f.client.get_channel_state(&f.channel_id);
    assert_eq!(state.balance_a, 1_200);
    assert_eq!(state.balance_b, 800);
    assert_eq!(state.sequence_number, 3);
    assert_eq!(state.close_sequence, 3);
    assert!(state.is_cooperative_close);
    assert_eq!(settle_events(&f), 1);
}

#[test]
fn a_stale_signed_state_is_refused() {
    let f = fixture();
    advance_sequence(&f, 5);
    let settled_before = f.client.get_channel_state(&f.channel_id);
    assert_eq!(settled_before.sequence_number, 5);

    // An older, more favourable split kept from before the channel moved on.
    assert_eq!(
        settle_err(&f, 1_500, 500, 2),
        PaymentChannelError::StaleState
    );

    let after = f.client.get_channel_state(&f.channel_id);
    assert_eq!(
        after, settled_before,
        "a rejected settlement must leave the channel untouched"
    );
    assert!(!after.is_cooperative_close);
    assert_eq!(settle_events(&f), 0);
}

#[test]
fn the_recorded_sequence_itself_is_stale() {
    let f = fixture();
    advance_sequence(&f, 1);

    // Equal is not newer: replaying the current state must not rewrite the split.
    assert_eq!(
        settle_err(&f, 900, 1_100, 1),
        PaymentChannelError::StaleState
    );
    assert!(
        !f.client
            .get_channel_state(&f.channel_id)
            .is_cooperative_close
    );
}

#[test]
fn a_sequence_gap_is_accepted() {
    let f = fixture();

    // A participant may have missed intermediate updates, so the signed
    // sequence only has to be newer than the recorded one.
    match settle_call(&f, 1_100, 900, 9) {
        Ok(Ok(())) => {}
        other => panic!("a newer sequence must settle: {other:?}"),
    }
    assert_eq!(f.client.get_channel_state(&f.channel_id).sequence_number, 9);
}

#[test]
fn a_settlement_that_does_not_conserve_the_total_is_refused() {
    let f = fixture();

    assert_eq!(
        settle_err(&f, 1_500, 900, 3),
        PaymentChannelError::BalanceMismatch
    );
    assert_eq!(
        settle_err(&f, -1, 2_001, 3),
        PaymentChannelError::InvalidBalance
    );
    assert_eq!(f.client.get_channel_state(&f.channel_id).sequence_number, 0);
}

#[test]
fn a_settlement_is_refused_while_an_htlc_is_outstanding() {
    let f = fixture();
    let receiver = Address::generate(&f.env);
    let hashlock = BytesN::from_array(&f.env, &[3u8; 32]);
    f.client
        .create_htlc(&f.channel_id, &hashlock, &2_000, &100, &receiver);

    assert_eq!(
        settle_err(&f, 1_000, 1_000, 5),
        PaymentChannelError::ActiveHtlcsExist
    );
}

#[test]
fn settlement_is_terminal() {
    let f = fixture();
    match settle_call(&f, 1_200, 800, 3) {
        Ok(Ok(())) => {}
        other => panic!("the first settlement must succeed: {other:?}"),
    }

    // A later, newer state cannot reopen a channel that has already settled.
    assert_eq!(
        settle_err(&f, 900, 1_100, 4),
        PaymentChannelError::ChannelAlreadyClosed
    );
    assert_eq!(settle_events(&f), 1);
}

#[test]
fn settling_an_unknown_channel_reports_not_found() {
    let f = fixture();
    let unknown = BytesN::from_array(&f.env, &[9u8; 32]);

    match f.client.try_settle_signed_state(
        &unknown,
        &1_000,
        &1_000,
        &3,
        &signature(&f.env),
        &signature(&f.env),
    ) {
        Ok(Ok(())) => panic!("an unknown channel cannot settle"),
        Ok(Err(conversion)) => panic!("the result did not convert: {conversion:?}"),
        Err(Ok(error)) => assert_eq!(error, PaymentChannelError::ChannelNotFound),
        Err(Err(invoke)) => panic!("the call never reached the contract: {invoke:?}"),
    }
}

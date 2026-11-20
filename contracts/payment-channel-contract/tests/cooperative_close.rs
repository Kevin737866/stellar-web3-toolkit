//! Integration tests for the payment-channel contract's cooperative close
//! (#351): a close must be safe to retry.

use payment_channel_contract::{PaymentChannel, PaymentChannelClient, PaymentChannelError};
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{Address, BytesN, Env, InvokeError, TryFromVal};

type TryResult<T> =
    Result<Result<T, soroban_sdk::ConversionError>, Result<PaymentChannelError, InvokeError>>;

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

/// `try_*` returns `Result<Result<T, ConversionError>, Result<E, InvokeError>>`:
/// the outer `Err` carries the contract's own error, while an `InvokeError`
/// means the call never reached the contract (a host failure, not a rejection).
fn contract_error<T, C, E>(result: Result<Result<T, C>, Result<E, InvokeError>>) -> E
where
    C: std::fmt::Debug,
    E: std::fmt::Debug,
{
    match result {
        Ok(Ok(_)) => panic!("the call should have been rejected"),
        Ok(Err(conversion)) => panic!("the result did not convert: {conversion:?}"),
        Err(Ok(error)) => error,
        Err(Err(invoke)) => panic!("the call never reached the contract: {invoke:?}"),
    }
}

fn close_call(
    f: &Fixture,
    channel_id: &BytesN<32>,
    balance_a: i128,
    balance_b: i128,
) -> TryResult<()> {
    f.client.try_cooperative_close(
        channel_id,
        &balance_a,
        &balance_b,
        &signature(&f.env),
        &signature(&f.env),
    )
}

fn close(f: &Fixture, balance_a: i128, balance_b: i128) {
    match close_call(f, &f.channel_id, balance_a, balance_b) {
        Ok(Ok(())) => {}
        Ok(Err(conversion)) => panic!("the result did not convert: {conversion:?}"),
        Err(Ok(error)) => panic!("the close was rejected: {error:?}"),
        Err(Err(invoke)) => panic!("the call never reached the contract: {invoke:?}"),
    }
}

fn close_err(f: &Fixture, balance_a: i128, balance_b: i128) -> PaymentChannelError {
    contract_error(close_call(f, &f.channel_id, balance_a, balance_b))
}

fn close_events(f: &Fixture) -> usize {
    f.env
        .events()
        .all()
        .iter()
        .filter(|(_, topics, _)| match topics.get(0) {
            Some(topic) => soroban_sdk::String::try_from_val(&f.env, &topic)
                .is_ok_and(|name| name == soroban_sdk::String::from_str(&f.env, "channel_close")),
            None => false,
        })
        .count()
}

#[test]
fn a_cooperative_close_settles_the_agreed_split() {
    let f = fixture();

    close(&f, 1_200, 800);

    let state = f.client.get_channel_state(&f.channel_id);
    assert_eq!(state.balance_a, 1_200);
    assert_eq!(state.balance_b, 800);
    assert!(state.is_cooperative_close);
    assert_eq!(state.close_sequence, state.sequence_number);
    assert_eq!(close_events(&f), 1);
}

#[test]
fn retrying_the_same_close_is_a_no_op() {
    let f = fixture();

    close(&f, 1_200, 800);
    let settled = f.client.get_channel_state(&f.channel_id);

    for _ in 0..3 {
        close(&f, 1_200, 800);
    }

    let after = f.client.get_channel_state(&f.channel_id);
    assert_eq!(after, settled, "a retry must not change the settlement");
    assert_eq!(
        after.sequence_number, settled.sequence_number,
        "a retry must not advance the sequence number"
    );
    assert_eq!(
        close_events(&f),
        1,
        "a retry must not publish a second close event"
    );
}

#[test]
fn a_retry_with_a_different_split_is_rejected() {
    let f = fixture();

    close(&f, 1_200, 800);
    let settled = f.client.get_channel_state(&f.channel_id);

    let err = close_err(&f, 800, 1_200);
    assert_eq!(err, PaymentChannelError::ChannelAlreadyClosed);

    assert_eq!(
        f.client.get_channel_state(&f.channel_id),
        settled,
        "a rejected retry must leave the settlement untouched"
    );
    assert_eq!(close_events(&f), 1);
}

#[test]
fn a_close_that_does_not_conserve_the_total_is_rejected() {
    let f = fixture();

    assert_eq!(
        close_err(&f, 1_000, 500),
        PaymentChannelError::BalanceMismatch
    );
    assert_eq!(
        close_err(&f, -1, 2_001),
        PaymentChannelError::InvalidBalance
    );

    let state = f.client.get_channel_state(&f.channel_id);
    assert!(!state.is_cooperative_close);
    assert_eq!(state.sequence_number, 0);
}

#[test]
fn a_close_is_refused_while_an_htlc_is_outstanding() {
    let f = fixture();
    let receiver = Address::generate(&f.env);
    let hashlock = BytesN::from_array(&f.env, &[3u8; 32]);

    f.client
        .create_htlc(&f.channel_id, &hashlock, &2_000, &100, &receiver);

    assert_eq!(
        close_err(&f, 1_000, 1_000),
        PaymentChannelError::ActiveHtlcsExist
    );

    let state = f.client.get_channel_state(&f.channel_id);
    assert!(!state.is_cooperative_close);
}

#[test]
fn a_settled_channel_cannot_be_mutated_afterwards() {
    let f = fixture();
    close(&f, 1_200, 800);

    let hashlock = BytesN::from_array(&f.env, &[4u8; 32]);
    let receiver = Address::generate(&f.env);
    let alice = f.client.get_channel_state(&f.channel_id).participant_a;

    assert_eq!(
        contract_error(f.client.try_update_state(
            &f.channel_id,
            &900,
            &1_100,
            &signature(&f.env),
            &signature(&f.env),
        )),
        PaymentChannelError::ChannelAlreadyClosed
    );
    assert_eq!(
        contract_error(
            f.client
                .try_create_htlc(&f.channel_id, &hashlock, &2_000, &10, &receiver,)
        ),
        PaymentChannelError::ChannelAlreadyClosed
    );
    assert_eq!(
        contract_error(f.client.try_top_up(&f.channel_id, &100, &alice)),
        PaymentChannelError::ChannelAlreadyClosed
    );
    assert_eq!(
        contract_error(
            f.client
                .try_initiate_unilateral_close(&f.channel_id, &alice)
        ),
        PaymentChannelError::ChannelAlreadyClosed
    );
}

#[test]
fn closing_an_unknown_channel_reports_not_found() {
    let f = fixture();
    let unknown = BytesN::from_array(&f.env, &[9u8; 32]);

    assert_eq!(
        contract_error(close_call(&f, &unknown, 1_000, 1_000)),
        PaymentChannelError::ChannelNotFound
    );
}

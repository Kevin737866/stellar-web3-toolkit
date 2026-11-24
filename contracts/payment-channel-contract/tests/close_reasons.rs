//! Integration tests for the payment-channel contract's close reasons (#350):
//! every close path must leave a stable, externally readable reason.

use payment_channel_contract::{
    CloseReason, PaymentChannel, PaymentChannelClient, PaymentChannelError,
};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, InvokeError};

struct Fixture {
    env: Env,
    client: PaymentChannelClient<'static>,
    alice: Address,
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
        alice,
        channel_id,
    }
}

fn signature(env: &Env) -> BytesN<64> {
    BytesN::from_array(env, &[0u8; 64])
}

/// `try_*` returns `Result<Result<T, ConversionError>, Result<E, InvokeError>>`:
/// the outer `Err` carries the contract's own error, while an `InvokeError`
/// means the call never reached the contract.
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

fn reason(f: &Fixture) -> CloseReason {
    f.client.get_close_reason(&f.channel_id)
}

#[test]
fn an_open_channel_reports_not_closed() {
    let f = fixture();

    assert_eq!(reason(&f), CloseReason::NotClosed);
    assert_eq!(
        f.client.get_channel_state(&f.channel_id).close_reason,
        CloseReason::NotClosed,
        "the reason must agree with the full channel state"
    );
}

#[test]
fn a_signed_settlement_reports_signed_settlement() {
    let f = fixture();

    f.client.update_state(
        &f.channel_id,
        &1_100,
        &900,
        &signature(&f.env),
        &signature(&f.env),
    );
    assert_eq!(
        reason(&f),
        CloseReason::NotClosed,
        "an update is not a close"
    );

    f.client.settle_signed_state(
        &f.channel_id,
        &1_200,
        &800,
        &2,
        &signature(&f.env),
        &signature(&f.env),
    );

    assert_eq!(reason(&f), CloseReason::SignedSettlement);
    let state = f.client.get_channel_state(&f.channel_id);
    assert_eq!(state.close_reason, CloseReason::SignedSettlement);
    assert!(state.is_cooperative_close);
}

#[test]
fn a_cooperative_close_reports_cooperative_and_survives_a_retry() {
    let f = fixture();

    f.client.cooperative_close(
        &f.channel_id,
        &1_200,
        &800,
        &signature(&f.env),
        &signature(&f.env),
    );
    assert_eq!(reason(&f), CloseReason::Cooperative);

    // The idempotent retry succeeds and must not rewrite the reason.
    f.client.cooperative_close(
        &f.channel_id,
        &1_200,
        &800,
        &signature(&f.env),
        &signature(&f.env),
    );
    assert_eq!(reason(&f), CloseReason::Cooperative);

    // A retry with a different split is refused, and still does not rewrite it.
    assert_eq!(
        contract_error(f.client.try_cooperative_close(
            &f.channel_id,
            &800,
            &1_200,
            &signature(&f.env),
            &signature(&f.env),
        )),
        PaymentChannelError::ChannelAlreadyClosed
    );
    assert_eq!(reason(&f), CloseReason::Cooperative);
}

#[test]
fn a_unilateral_close_reports_unilateral() {
    let f = fixture();

    f.client.initiate_unilateral_close(&f.channel_id, &f.alice);

    assert_eq!(reason(&f), CloseReason::Unilateral);
    assert_eq!(
        f.client.get_channel_state(&f.channel_id).close_reason,
        CloseReason::Unilateral
    );
}

#[test]
fn a_rejected_close_leaves_the_channel_open_and_usable() {
    let f = fixture();

    // The split does not conserve the channel total.
    assert_eq!(
        contract_error(f.client.try_cooperative_close(
            &f.channel_id,
            &1_000,
            &500,
            &signature(&f.env),
            &signature(&f.env),
        )),
        PaymentChannelError::BalanceMismatch
    );
    assert_eq!(reason(&f), CloseReason::NotClosed);

    // No partial state update: the channel still accepts a payment.
    f.client.update_state(
        &f.channel_id,
        &900,
        &1_100,
        &signature(&f.env),
        &signature(&f.env),
    );
    assert_eq!(f.client.get_channel_state(&f.channel_id).sequence_number, 1);
    assert_eq!(reason(&f), CloseReason::NotClosed);
}

#[test]
fn an_unauthorized_close_is_rejected_and_records_nothing() {
    let f = fixture();
    let stranger = Address::generate(&f.env);

    assert_eq!(
        contract_error(
            f.client
                .try_initiate_unilateral_close(&f.channel_id, &stranger)
        ),
        PaymentChannelError::UnauthorizedParticipant
    );
    assert_eq!(reason(&f), CloseReason::NotClosed);
}

#[test]
fn an_unknown_channel_has_no_close_reason() {
    let f = fixture();
    let unknown = BytesN::from_array(&f.env, &[9u8; 32]);

    assert_eq!(
        contract_error(f.client.try_get_close_reason(&unknown)),
        PaymentChannelError::ChannelNotFound
    );
}

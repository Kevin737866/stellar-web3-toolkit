//! Integration tests for bounded dispute-period validation on force-close
//! requests (#353).
//!
//! `force_close` is the entry point that lets a participant override the
//! channel's configured `timeout` with an explicit `dispute_period_secs`.
//! The contract must:
//!
//! * accept any period within [`MIN_DISPUTE_PERIOD_SECS`..=`MAX_DISPUTE_PERIOD_SECS`];
//! * reject a period below the minimum with `DisputePeriodTooShort`;
//! * reject a period above the maximum with `DisputePeriodTooLong`;
//! * enforce all the same participant-authorization, channel-lifecycle, and
//!   HTLC-safety invariants as `initiate_unilateral_close`.

use payment_channel_contract::{
    PaymentChannel, PaymentChannelClient, PaymentChannelError, MAX_DISPUTE_PERIOD_SECS,
    MIN_DISPUTE_PERIOD_SECS,
};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, InvokeError};

// ── helpers ──────────────────────────────────────────────────────────────────

struct Fixture {
    env: Env,
    client: PaymentChannelClient<'static>,
    channel_id: BytesN<32>,
    alice: Address,
    bob: Address,
}

fn fixture() -> Fixture {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, PaymentChannel);
    let client = PaymentChannelClient::new(&env, &contract_id);

    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    // Initialize with a small timeout that is well below the dispute-period
    // bounds, so that force_close has observable effect when it overrides it.
    let channel_id = client.initialize(&alice, &bob, &5_000, &5_000, &3_600, &0);

    Fixture {
        env,
        client,
        channel_id,
        alice,
        bob,
    }
}

fn sig(env: &Env) -> BytesN<64> {
    BytesN::from_array(env, &[0u8; 64])
}

fn contract_error<T, C, E>(
    result: Result<Result<T, C>, Result<E, InvokeError>>,
) -> E
where
    C: std::fmt::Debug,
    E: std::fmt::Debug,
{
    match result {
        Ok(Ok(_)) => panic!("the call should have been rejected"),
        Ok(Err(c)) => panic!("result did not convert: {c:?}"),
        Err(Ok(e)) => e,
        Err(Err(i)) => panic!("call never reached the contract: {i:?}"),
    }
}

// ── normal-case tests ─────────────────────────────────────────────────────────

#[test]
fn force_close_at_minimum_period_records_close_and_returns_withdraw_time() {
    let f = fixture();

    let withdraw_time = f
        .client
        .force_close(&f.channel_id, &f.alice, &MIN_DISPUTE_PERIOD_SECS);

    let state = f.client.get_channel_state(&f.channel_id);
    assert_ne!(state.close_time, 0, "close_time must be set");
    assert_eq!(state.timeout, MIN_DISPUTE_PERIOD_SECS);
    assert_eq!(
        withdraw_time,
        state.close_time + MIN_DISPUTE_PERIOD_SECS as u64,
        "withdraw_time is close_time + dispute_period"
    );
}

#[test]
fn force_close_at_maximum_period_is_accepted() {
    let f = fixture();

    let withdraw_time = f
        .client
        .force_close(&f.channel_id, &f.bob, &MAX_DISPUTE_PERIOD_SECS);

    let state = f.client.get_channel_state(&f.channel_id);
    assert_eq!(state.timeout, MAX_DISPUTE_PERIOD_SECS);
    assert_eq!(
        withdraw_time,
        state.close_time + MAX_DISPUTE_PERIOD_SECS as u64
    );
}

#[test]
fn force_close_overrides_channels_configured_timeout() {
    let f = fixture();
    let original_timeout = f.client.get_channel_state(&f.channel_id).timeout;

    // Use a period that differs from the channel's configured timeout.
    let custom = MIN_DISPUTE_PERIOD_SECS + 7_200;
    assert_ne!(
        custom, original_timeout,
        "pre-condition: custom period must differ from configured timeout"
    );

    f.client.force_close(&f.channel_id, &f.alice, &custom);

    let state = f.client.get_channel_state(&f.channel_id);
    assert_eq!(state.timeout, custom, "timeout must be updated to the caller-supplied period");
}

#[test]
fn force_close_advances_the_sequence_number() {
    let f = fixture();
    let seq_before = f.client.get_channel_state(&f.channel_id).sequence_number;

    f.client
        .force_close(&f.channel_id, &f.alice, &MIN_DISPUTE_PERIOD_SECS);

    let seq_after = f.client.get_channel_state(&f.channel_id).sequence_number;
    assert_eq!(seq_after, seq_before + 1);
}

#[test]
fn force_close_either_participant_may_initiate() {
    // Alice closes one channel; Bob closes a separate channel.
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, PaymentChannel);
    let client = PaymentChannelClient::new(&env, &contract_id);

    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    let ch_a = client.initialize(&alice, &bob, &1_000, &1_000, &3_600, &0);
    let ch_b = client.initialize(&alice, &bob, &1_000, &1_000, &3_600, &0);

    client.force_close(&ch_a, &alice, &MIN_DISPUTE_PERIOD_SECS);
    client.force_close(&ch_b, &bob, &MIN_DISPUTE_PERIOD_SECS);

    assert_ne!(client.get_channel_state(&ch_a).close_time, 0);
    assert_ne!(client.get_channel_state(&ch_b).close_time, 0);
}

// ── boundary / failure tests ──────────────────────────────────────────────────

#[test]
fn period_below_minimum_is_rejected_with_dispute_period_too_short() {
    let f = fixture();

    let err = contract_error(
        f.client
            .try_force_close(&f.channel_id, &f.alice, &(MIN_DISPUTE_PERIOD_SECS - 1)),
    );
    assert_eq!(err, PaymentChannelError::DisputePeriodTooShort);

    // No state mutation on failure.
    let state = f.client.get_channel_state(&f.channel_id);
    assert_eq!(state.close_time, 0, "channel must remain open");
}

#[test]
fn zero_period_is_rejected_with_dispute_period_too_short() {
    let f = fixture();

    let err = contract_error(f.client.try_force_close(&f.channel_id, &f.alice, &0_u32));
    assert_eq!(err, PaymentChannelError::DisputePeriodTooShort);
}

#[test]
fn period_above_maximum_is_rejected_with_dispute_period_too_long() {
    let f = fixture();

    let err = contract_error(
        f.client
            .try_force_close(&f.channel_id, &f.alice, &(MAX_DISPUTE_PERIOD_SECS + 1)),
    );
    assert_eq!(err, PaymentChannelError::DisputePeriodTooLong);

    let state = f.client.get_channel_state(&f.channel_id);
    assert_eq!(state.close_time, 0, "channel must remain open");
}

#[test]
fn u32_max_period_is_rejected_with_dispute_period_too_long() {
    let f = fixture();

    let err = contract_error(f.client.try_force_close(&f.channel_id, &f.alice, &u32::MAX));
    assert_eq!(err, PaymentChannelError::DisputePeriodTooLong);
}

#[test]
fn unauthorized_caller_is_rejected_even_with_valid_period() {
    let f = fixture();
    let stranger = Address::generate(&f.env);

    let err = contract_error(
        f.client
            .try_force_close(&f.channel_id, &stranger, &MIN_DISPUTE_PERIOD_SECS),
    );
    assert_eq!(err, PaymentChannelError::UnauthorizedParticipant);

    let state = f.client.get_channel_state(&f.channel_id);
    assert_eq!(state.close_time, 0);
}

#[test]
fn already_closed_channel_is_rejected() {
    let f = fixture();

    // Cooperatively close first.
    f.client.cooperative_close(
        &f.channel_id,
        &5_000,
        &5_000,
        &sig(&f.env),
        &sig(&f.env),
    );

    let err = contract_error(
        f.client
            .try_force_close(&f.channel_id, &f.alice, &MIN_DISPUTE_PERIOD_SECS),
    );
    assert_eq!(err, PaymentChannelError::ChannelAlreadyClosed);
}

#[test]
fn channel_with_active_htlcs_cannot_be_force_closed() {
    let f = fixture();
    let receiver = Address::generate(&f.env);
    let hashlock = BytesN::from_array(&f.env, &[5u8; 32]);

    f.client
        .create_htlc(&f.channel_id, &hashlock, &2_000, &500, &receiver);

    let err = contract_error(
        f.client
            .try_force_close(&f.channel_id, &f.alice, &MIN_DISPUTE_PERIOD_SECS),
    );
    assert_eq!(err, PaymentChannelError::ActiveHtlcsExist);

    let state = f.client.get_channel_state(&f.channel_id);
    assert_eq!(state.close_time, 0);
}

#[test]
fn unknown_channel_reports_channel_not_found() {
    let f = fixture();
    let unknown = BytesN::from_array(&f.env, &[0xffu8; 32]);

    let err = contract_error(
        f.client
            .try_force_close(&unknown, &f.alice, &MIN_DISPUTE_PERIOD_SECS),
    );
    assert_eq!(err, PaymentChannelError::ChannelNotFound);
}

//! Integration tests for the partial-funding recovery path (#357).
//!
//! A channel whose second funding leg never arrived must be unusable until the
//! outstanding funds are supplied or the funded side aborts after the deadline.

use payment_channel_contract::{
    FundingRecovery, FundingResolution, PaymentChannel, PaymentChannelClient, PaymentChannelError,
};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, InvokeError};

struct Fixture {
    env: Env,
    client: PaymentChannelClient<'static>,
    channel_id: BytesN<32>,
    funded: Address,
    pending: Address,
}

fn fixture(timeout: u32) -> Fixture {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, PaymentChannel);
    let client = PaymentChannelClient::new(&env, &contract_id);
    let funded = Address::generate(&env);
    let pending = Address::generate(&env);
    // The second participant's funding transaction never arrived.
    let channel_id = client.initialize(&funded, &pending, &1_000, &0, &timeout, &0);
    Fixture {
        env,
        client,
        channel_id,
        funded,
        pending,
    }
}

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

#[test]
fn completing_the_outstanding_funding_restores_the_channel() {
    let f = fixture(100);
    let recovery: FundingRecovery = f
        .client
        .open_funding_recovery(&f.channel_id, &f.funded, &500);
    assert_eq!(recovery.resolution, FundingResolution::Pending);
    assert_eq!(recovery.outstanding, 500);
    assert_eq!(recovery.deadline_ledger, 100);

    let dummy = BytesN::from_array(&f.env, &[0u8; 64]);
    assert_eq!(
        contract_error(
            f.client
                .try_update_state(&f.channel_id, &900, &100, &dummy, &dummy,)
        ),
        PaymentChannelError::ChannelAwaitingFunding
    );

    assert_eq!(
        contract_error(f.client.try_complete_funding_recovery(&f.channel_id, &400)),
        PaymentChannelError::FundingAmountMismatch
    );

    f.client.complete_funding_recovery(&f.channel_id, &500);
    let state = f.client.get_channel_state(&f.channel_id);
    assert_eq!(state.balance_a, 1_000);
    assert_eq!(state.balance_b, 500);
    assert_eq!(state.total_balance, 1_500);
    assert_eq!(state.sequence_number, 1);
    assert_eq!(
        f.client.get_funding_recovery(&f.channel_id).resolution,
        FundingResolution::Completed
    );

    // Retry after a lost response is a no-op.
    f.client.complete_funding_recovery(&f.channel_id, &500);
    let retried = f.client.get_channel_state(&f.channel_id);
    assert_eq!(retried, state);
}

#[test]
fn aborting_after_the_deadline_closes_the_channel() {
    let f = fixture(60);
    f.client
        .open_funding_recovery(&f.channel_id, &f.funded, &500);

    assert_eq!(
        contract_error(f.client.try_abort_funding_recovery(&f.channel_id)),
        PaymentChannelError::FundingDeadlineNotReached
    );
    assert!(
        !f.client
            .get_channel_state(&f.channel_id)
            .is_cooperative_close
    );

    f.env.ledger().set_sequence_number(61);
    f.client.abort_funding_recovery(&f.channel_id);

    let state = f.client.get_channel_state(&f.channel_id);
    assert!(state.is_cooperative_close);
    assert_eq!(state.close_sequence, state.sequence_number);
    assert_eq!(
        f.client.get_funding_recovery(&f.channel_id).resolution,
        FundingResolution::Aborted
    );

    f.client.abort_funding_recovery(&f.channel_id);
    assert_eq!(f.client.get_channel_state(&f.channel_id), state);
}

#[test]
fn late_completion_is_refused_without_changing_the_channel() {
    let f = fixture(60);
    f.client
        .open_funding_recovery(&f.channel_id, &f.funded, &500);
    let before = f.client.get_channel_state(&f.channel_id);

    f.env.ledger().set_sequence_number(61);
    assert_eq!(
        contract_error(f.client.try_complete_funding_recovery(&f.channel_id, &500)),
        PaymentChannelError::FundingRecoveryExpired
    );
    assert_eq!(f.client.get_channel_state(&f.channel_id), before);
    assert_eq!(
        f.client.get_funding_recovery(&f.channel_id).resolution,
        FundingResolution::Pending
    );
}

#[test]
fn unsafe_or_duplicate_recovery_requests_are_refused() {
    let f = fixture(100);
    let stranger = Address::generate(&f.env);

    assert_eq!(
        contract_error(
            f.client
                .try_open_funding_recovery(&f.channel_id, &stranger, &500)
        ),
        PaymentChannelError::UnauthorizedParticipant
    );
    assert_eq!(
        contract_error(
            f.client
                .try_open_funding_recovery(&f.channel_id, &f.pending, &500)
        ),
        PaymentChannelError::InvalidFundingAmount
    );
    assert_eq!(
        contract_error(
            f.client
                .try_open_funding_recovery(&f.channel_id, &f.funded, &0)
        ),
        PaymentChannelError::InvalidFundingAmount
    );

    f.client
        .open_funding_recovery(&f.channel_id, &f.funded, &500);
    assert_eq!(
        contract_error(
            f.client
                .try_open_funding_recovery(&f.channel_id, &f.funded, &500)
        ),
        PaymentChannelError::FundingRecoveryExists
    );
    assert_eq!(
        contract_error(
            f.client
                .try_complete_funding_recovery(&BytesN::from_array(&f.env, &[9u8; 32]), &500)
        ),
        PaymentChannelError::FundingRecoveryNotFound
    );
}

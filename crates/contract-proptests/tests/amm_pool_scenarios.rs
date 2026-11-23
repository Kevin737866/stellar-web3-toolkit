//! A representative AMM workflow expressed with the scenario testing DSL.

use amm_pool::{AmmPool, AmmPoolClient};
use contract_proptests::Scenario;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::token::{StellarAssetClient, TokenClient};
use soroban_sdk::{Address, Env};

struct PoolScenario {
    env: Env,
    token_a: Address,
    token_b: Address,
    pool_id: Address,
    user: Address,
    output: i128,
}

impl PoolScenario {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_a = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let token_b = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let pool_id = env.register_contract(None, AmmPool);
        let user = Address::generate(&env);

        Self {
            env,
            token_a,
            token_b,
            pool_id,
            user,
            output: 0,
        }
    }
}

#[test]
fn seeded_pool_swap_scenario_preserves_balances_and_reserves() {
    let scenario = Scenario::new("seeded pool swaps token A for token B")
        .given(
            "the pool is initialized and funded",
            |state: &mut PoolScenario| {
                let pool = AmmPoolClient::new(&state.env, &state.pool_id);
                let admin = Address::generate(&state.env);
                pool.initialize(&admin, &state.token_a, &state.token_b);
                StellarAssetClient::new(&state.env, &state.token_a).mint(&state.user, &10_000_000);
                StellarAssetClient::new(&state.env, &state.token_b).mint(&state.user, &10_000_000);
                pool.add_liquidity(&state.user, &1_000_000, &1_000_000, &0, &0);
                Ok(())
            },
        )
        .when(
            "the user performs an exact-input swap",
            |state: &mut PoolScenario| {
                TokenClient::new(&state.env, &state.token_a).transfer(
                    &state.user,
                    &state.pool_id,
                    &100_000,
                );
                state.output = AmmPoolClient::new(&state.env, &state.pool_id).swap(
                    &state.token_a,
                    &state.user,
                    &0,
                );
                Ok(())
            },
        )
        .then(
            "the output is positive and the pool tracks token balances",
            |state: &mut PoolScenario| {
                let pool = AmmPoolClient::new(&state.env, &state.pool_id);
                let (reserve_a, reserve_b) = pool.get_reserves();
                if state.output <= 0 {
                    return Err("swap output was not positive".into());
                }
                if TokenClient::new(&state.env, &state.token_a).balance(&state.pool_id) != reserve_a
                    || TokenClient::new(&state.env, &state.token_b).balance(&state.pool_id)
                        != reserve_b
                {
                    return Err("recorded reserves differ from token balances".into());
                }
                Ok(())
            },
        );

    scenario
        .run(&mut PoolScenario::new())
        .unwrap_or_else(|failure| panic!("{failure}"));
}

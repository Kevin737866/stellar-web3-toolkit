//! Randomized operation-sequence invariants for the AMM pool.
//!
//! Unit tests check a handful of hand-written scenarios; this drives the pool
//! with a long random mix of liquidity adds, removals and swaps and asserts the
//! accounting invariants after *every* step. That is the class of bug a
//! hand-written test tends to miss: a reservation that only breaks after an
//! unusual ordering of operations.
//!
//! Each round is its own `Env`, so a failure is reproducible from the seed and
//! the reported round alone:
//!
//! ```text
//! PROPERTY_SEED=<seed> PROPERTY_CASES=<round> cargo test -p contract-proptests --test amm_pool_invariants
//! ```

use amm_pool::{AmmPool, AmmPoolClient};
use contract_proptests::{Config, Rng};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::token::{StellarAssetClient, TokenClient};
use soroban_sdk::{Address, Env};

const ONE: i128 = 1_000_000;
/// Below this a random swap would be too small to produce a non-zero output.
const MIN_HEALTHY_RESERVE: i128 = 1_000_000;

/// How many operations each round drives through the pool.
const STEPS_PER_ROUND: u32 = 24;
/// Upper bound on rounds even when `PROPERTY_CASES` is raised: each round builds
/// a fresh `Env`, so this test is heavier than a pure-math property.
const MAX_ROUNDS: u32 = 48;

#[test]
fn pool_accounting_invariants_hold_across_random_operation_sequences() {
    let config = Config::from_env();
    let mut rng = Rng::new(config.seed ^ 0xA_11_0001);

    for round in 0..config.cases.min(MAX_ROUNDS) {
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
        let pool = AmmPoolClient::new(&env, &pool_id);
        pool.initialize(&admin, &token_a, &token_b);

        let lp = TokenClient::new(&env, &pool_id);
        let user = Address::generate(&env);
        // Generous balances so a random operation sequence is never starved by
        // the test wallet rather than by the contract under test.
        StellarAssetClient::new(&env, &token_a).mint(&user, &(1_000_000 * ONE));
        StellarAssetClient::new(&env, &token_b).mint(&user, &(1_000_000 * ONE));

        pool.add_liquidity(&user, &(1_000 * ONE), &(1_000 * ONE), &0, &0);

        for step in 0..STEPS_PER_ROUND {
            let (reserve_a, reserve_b) = pool.get_reserves();

            match rng.index(5) {
                // Add liquidity on both sides.
                0 | 1 => {
                    let amount_a = rng.i128_in(1, 100 * ONE);
                    let amount_b = rng.i128_in(1, 100 * ONE);
                    pool.add_liquidity(&user, &amount_a, &amount_b, &0, &0);
                }
                // Remove part of the LP balance, never all of it, so the pool
                // stays swappable.
                2 => {
                    let held = lp.balance(&user);
                    if held > 2 {
                        let amount = rng.i128_in(1, held - 1);
                        pool.remove_liquidity(&user, &amount, &0, &0);
                    }
                }
                // Swap token A in for token B.
                _ => {
                    if reserve_a > MIN_HEALTHY_RESERVE && reserve_b > MIN_HEALTHY_RESERVE {
                        let amount_in = rng.i128_in(1, (reserve_a / 10).max(1));
                        let k_before = reserve_a.checked_mul(reserve_b).expect("k");

                        TokenClient::new(&env, &token_a).transfer(&user, &pool_id, &amount_in);
                        pool.swap(&token_a, &user, &0);

                        let (new_a, new_b) = pool.get_reserves();
                        assert!(
                            new_a.checked_mul(new_b).expect("k") >= k_before,
                            "round {round} step {step}: k decreased across a swap"
                        );
                    }
                }
            }

            // -- invariants, after every operation ---------------------------
            let (reserve_a, reserve_b) = pool.get_reserves();
            assert!(
                reserve_a > 0 && reserve_b > 0,
                "round {round} step {step}: a reserve was drained"
            );
            // The recorded reserves must equal what the pool actually holds:
            // any drift here means an operation updated one but not the other.
            assert_eq!(
                TokenClient::new(&env, &token_a).balance(&pool_id),
                reserve_a,
                "round {round} step {step}: reserve A drifted from the real balance"
            );
            assert_eq!(
                TokenClient::new(&env, &token_b).balance(&pool_id),
                reserve_b,
                "round {round} step {step}: reserve B drifted from the real balance"
            );
            // The user always keeps a positive LP position given the loop above
            // never removes the last unit.
            assert!(
                lp.balance(&user) > 0,
                "round {round} step {step}: the LP position was emptied"
            );
        }
    }
}

#[test]
fn a_swap_never_pays_out_more_than_the_constant_product_allows() {
    // The same invariant as above but as a pure per-operation property, so a
    // failure pins down the arithmetic rather than the operation ordering.
    let config = Config::from_env();
    let mut rng = Rng::new(config.seed ^ 0xB_22_0002);

    for round in 0..config.cases.min(MAX_ROUNDS) {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().with_mut(|li| li.timestamp = 1_000);

        let admin = Address::generate(&env);
        let token_a = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let token_b = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let pool_id = env.register_contract(None, AmmPool);
        let pool = AmmPoolClient::new(&env, &pool_id);
        pool.initialize(&admin, &token_a, &token_b);

        let reserve_a = rng.i128_in(1_000 * ONE, 10_000 * ONE);
        let reserve_b = rng.i128_in(1_000 * ONE, 10_000 * ONE);
        let user = Address::generate(&env);
        StellarAssetClient::new(&env, &token_a).mint(&user, &reserve_a);
        StellarAssetClient::new(&env, &token_b).mint(&user, &reserve_b);
        pool.add_liquidity(&user, &reserve_a, &reserve_b, &0, &0);

        let (ra, rb) = pool.get_reserves();
        let amount_in = rng.i128_in(1, ra / 4);
        let k_before = ra.checked_mul(rb).expect("k");
        let b_before = TokenClient::new(&env, &token_b).balance(&user);

        TokenClient::new(&env, &token_a).transfer(&user, &pool_id, &amount_in);
        let out = pool.swap(&token_a, &user, &0);

        let b_after = TokenClient::new(&env, &token_b).balance(&user);
        assert_eq!(
            b_after - b_before,
            out,
            "round {round}: the reported output must match the tokens received"
        );
        let (new_a, new_b) = pool.get_reserves();
        assert!(
            new_a.checked_mul(new_b).expect("k") >= k_before,
            "round {round}: k decreased"
        );
        assert!(out < rb, "round {round}: the output must stay below the reserve");
    }
}

#![no_std]
#[cfg(test)]
extern crate std;

use amm_pool::AmmPoolClient;
use soroban_sdk::{contract, contractimpl, token::TokenClient, Address, Env, Vec};

#[contract]
pub struct AmmRouter;

#[contractimpl]
impl AmmRouter {
    /// Multi-hop swap: `path[k]` is the input asset for `pools[k]`.
    ///
    /// The router receives `amount_in` of `path[0]` from `user`, then routes through each pool.
    ///
    /// # Overflow and input guards (#399)
    ///
    /// The router moves amounts rather than reserves, so it does not do
    /// constant-product math itself. It still refuses anything a pool could
    /// silently mis-handle: a non-positive input, a negative slippage floor, a
    /// malformed route, or a hop that reports a non-positive output. Each hop's
    /// output is the next hop's input, and a zero or negative "output" would
    /// otherwise be forwarded as if it were a real amount.
    pub fn swap_exact_tokens_for_tokens(
        env: Env,
        user: Address,
        path: Vec<Address>,
        pools: Vec<Address>,
        amount_in: i128,
        amount_out_min: i128,
        recipient: Address,
    ) -> i128 {
        user.require_auth();
        assert!(amount_in > 0, "amount_in must be positive");
        assert!(amount_out_min >= 0, "amount_out_min must not be negative");
        assert!(path.len() >= 2, "path");
        assert!(pools.len() + 1 == path.len(), "pools");
        // `path.len() >= 2` and `pools.len() + 1 == path.len()` together
        // guarantee at least one pool, so the index is always valid.
        let last_idx = pools.len() - 1;
        let router = env.current_contract_address();

        let t0 = path.get(0).unwrap();
        TokenClient::new(&env, &t0).transfer(&user, &router, &amount_in);

        let mut running = amount_in;
        for i in 0..pools.len() {
            let pool_addr = pools.get(i).unwrap();
            let token_in = path.get(i).unwrap();
            let next_hop = if i < last_idx {
                router.clone()
            } else {
                recipient.clone()
            };

            TokenClient::new(&env, &token_in).transfer(&router, &pool_addr, &running);
            let client = AmmPoolClient::new(&env, &pool_addr);
            running = client.swap(&token_in, &next_hop, &1);
            assert!(running > 0, "pool returned a non-positive amount out");
        }

        assert!(running >= amount_out_min, "min out");
        running
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use amm_pool::{AmmPool, AmmPoolClient};
    use soroban_sdk::testutils::{Address as _, Events as _};
    use soroban_sdk::{symbol_short, Symbol, TryFromVal};

    #[test]
    fn router_rejects_invalid_amounts_and_routes_before_moving_funds() {
        let env = Env::default();
        env.mock_all_auths();
        let router_id = env.register_contract(None, AmmRouter);
        let router = AmmRouterClient::new(&env, &router_id);

        let u = Address::generate(&env);
        let a = Address::generate(&env);
        let b = Address::generate(&env);
        let path = soroban_sdk::vec![&env, a.clone(), b.clone()];
        let pools = soroban_sdk::vec![&env, Address::generate(&env)];

        // Zero, negative, and negative-min inputs are refused before any token
        // transfer, so a bad route cannot half-execute.
        assert!(router
            .try_swap_exact_tokens_for_tokens(&u, &path, &pools, &0, &0, &u)
            .is_err());
        assert!(router
            .try_swap_exact_tokens_for_tokens(&u, &path, &pools, &-5, &0, &u)
            .is_err());
        assert!(router
            .try_swap_exact_tokens_for_tokens(&u, &path, &pools, &100, &-1, &u)
            .is_err());

        // More path entries than pools + 1 is a caller bug, not a route.
        let mismatched = soroban_sdk::vec![&env, a.clone(), b, a.clone()];
        assert!(router
            .try_swap_exact_tokens_for_tokens(&u, &mismatched, &pools, &100, &0, &u)
            .is_err());

        // A route needs at least one pool.
        let single = soroban_sdk::vec![&env, a];
        let no_pools = soroban_sdk::Vec::<Address>::new(&env);
        assert!(router
            .try_swap_exact_tokens_for_tokens(&u, &single, &no_pools, &100, &0, &u)
            .is_err());
    }

    #[test]
    fn router_single_pool_swap() {
        let env = Env::default();
        env.mock_all_auths();

        let (ta, tb) = {
            let admin = Address::generate(&env);
            (
                env.register_stellar_asset_contract_v2(admin.clone())
                    .address(),
                env.register_stellar_asset_contract_v2(admin.clone())
                    .address(),
            )
        };

        let pool_id = env.register_contract(None, AmmPool);
        let pool = AmmPoolClient::new(&env, &pool_id);
        let factory = Address::generate(&env);
        pool.initialize(&factory, &ta, &tb);

        let u = Address::generate(&env);
        let router_id = env.register_contract(None, AmmRouter);
        let router = AmmRouterClient::new(&env, &router_id);

        soroban_sdk::token::StellarAssetClient::new(&env, &ta).mint(&u, &1_000_000);
        soroban_sdk::token::StellarAssetClient::new(&env, &tb).mint(&u, &1_000_000);
        pool.add_liquidity(&u, &400_000, &400_000, &1, &1);

        let path = soroban_sdk::vec![&env, ta.clone(), tb.clone()];
        let pools = soroban_sdk::vec![&env, pool_id.clone()];

        let before = TokenClient::new(&env, &tb).balance(&u);
        let out = router.swap_exact_tokens_for_tokens(&u, &path, &pools, &10_000, &1, &u);
        let after = TokenClient::new(&env, &tb).balance(&u);
        assert_eq!(after.saturating_sub(before), out);
        assert!(out > 9000);
    }

    fn create_token(env: &Env, admin: &Address) -> Address {
        env.register_stellar_asset_contract_v2(admin.clone())
            .address()
    }

    fn setup_funded_pool(
        env: &Env,
        lp: &Address,
        token_a: &Address,
        token_b: &Address,
        reserve_a: i128,
        reserve_b: i128,
    ) -> Address {
        let pool_id = env.register_contract(None, AmmPool);
        let pool = AmmPoolClient::new(env, &pool_id);
        let factory = Address::generate(env);
        pool.initialize(&factory, token_a, token_b);
        soroban_sdk::token::StellarAssetClient::new(env, token_a).mint(lp, &reserve_a);
        soroban_sdk::token::StellarAssetClient::new(env, token_b).mint(lp, &reserve_b);
        pool.add_liquidity(lp, &reserve_a, &reserve_b, &1, &1);
        pool_id
    }

    #[test]
    fn router_multi_hop_two_pools_respects_min_out() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let lp = Address::generate(&env);
        let user = Address::generate(&env);
        let recipient = Address::generate(&env);

        let ta = create_token(&env, &admin);
        let tb = create_token(&env, &admin);
        let tc = create_token(&env, &admin);

        let pool_ab = setup_funded_pool(&env, &lp, &ta, &tb, 500_000, 1_000_000);
        let pool_bc = setup_funded_pool(&env, &lp, &tb, &tc, 800_000, 400_000);

        let router_id = env.register_contract(None, AmmRouter);
        let router = AmmRouterClient::new(&env, &router_id);

        let amount_in = 20_000_i128;
        soroban_sdk::token::StellarAssetClient::new(&env, &ta).mint(&user, &amount_in);

        let expected_hop1 = amm_pool::math::amount_out(amount_in, 500_000, 1_000_000);
        let expected_hop2 = amm_pool::math::amount_out(expected_hop1, 800_000, 400_000);

        let path = soroban_sdk::vec![&env, ta.clone(), tb.clone(), tc.clone()];
        let pools = soroban_sdk::vec![&env, pool_ab.clone(), pool_bc.clone()];

        let out = router.swap_exact_tokens_for_tokens(
            &user,
            &path,
            &pools,
            &amount_in,
            &expected_hop2,
            &recipient,
        );

        assert_eq!(out, expected_hop2);
        assert_eq!(TokenClient::new(&env, &ta).balance(&user), 0);
        assert_eq!(TokenClient::new(&env, &tc).balance(&recipient), expected_hop2);
        assert_eq!(TokenClient::new(&env, &tb).balance(&router_id), 0);
        assert_eq!(
            AmmPoolClient::new(&env, &pool_ab).get_reserves(),
            (500_000 + amount_in, 1_000_000 - expected_hop1)
        );
        assert_eq!(
            AmmPoolClient::new(&env, &pool_bc).get_reserves(),
            (800_000 + expected_hop1, 400_000 - expected_hop2)
        );
    }

    #[test]
    fn router_multi_hop_three_pools_exact_min_out_boundary() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let lp = Address::generate(&env);
        let user = Address::generate(&env);
        let recipient = Address::generate(&env);

        let ta = create_token(&env, &admin);
        let tb = create_token(&env, &admin);
        let tc = create_token(&env, &admin);
        let td = create_token(&env, &admin);

        let pool_ab = setup_funded_pool(&env, &lp, &ta, &tb, 300_000, 300_000);
        let pool_bc = setup_funded_pool(&env, &lp, &tb, &tc, 300_000, 600_000);
        let pool_cd = setup_funded_pool(&env, &lp, &tc, &td, 600_000, 150_000);

        let router_id = env.register_contract(None, AmmRouter);
        let router = AmmRouterClient::new(&env, &router_id);

        let amount_in = 15_000_i128;
        soroban_sdk::token::StellarAssetClient::new(&env, &ta).mint(&user, &amount_in);

        let h1 = amm_pool::math::amount_out(amount_in, 300_000, 300_000);
        let h2 = amm_pool::math::amount_out(h1, 300_000, 600_000);
        let h3 = amm_pool::math::amount_out(h2, 600_000, 150_000);

        let path = soroban_sdk::vec![&env, ta.clone(), tb.clone(), tc.clone(), td.clone()];
        let pools = soroban_sdk::vec![&env, pool_ab, pool_bc, pool_cd];

        let out =
            router.swap_exact_tokens_for_tokens(&user, &path, &pools, &amount_in, &h3, &recipient);
        assert_eq!(out, h3);
        assert_eq!(TokenClient::new(&env, &td).balance(&recipient), h3);
    }

    #[test]
    #[should_panic(expected = "min out")]
    fn router_multi_hop_panics_when_output_below_min_out() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let lp = Address::generate(&env);
        let user = Address::generate(&env);

        let ta = create_token(&env, &admin);
        let tb = create_token(&env, &admin);
        let tc = create_token(&env, &admin);

        let pool_ab = setup_funded_pool(&env, &lp, &ta, &tb, 500_000, 500_000);
        let pool_bc = setup_funded_pool(&env, &lp, &tb, &tc, 500_000, 500_000);

        let router_id = env.register_contract(None, AmmRouter);
        let router = AmmRouterClient::new(&env, &router_id);

        let amount_in = 10_000_i128;
        soroban_sdk::token::StellarAssetClient::new(&env, &ta).mint(&user, &amount_in);

        let h1 = amm_pool::math::amount_out(amount_in, 500_000, 500_000);
        let h2 = amm_pool::math::amount_out(h1, 500_000, 500_000);

        let path = soroban_sdk::vec![&env, ta, tb, tc];
        let pools = soroban_sdk::vec![&env, pool_ab, pool_bc];

        router.swap_exact_tokens_for_tokens(&user, &path, &pools, &amount_in, &(h2 + 1), &user);
    }

    #[test]
    fn router_rejects_invalid_inputs_without_partial_state_updates() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let lp = Address::generate(&env);
        let user = Address::generate(&env);

        let ta = create_token(&env, &admin);
        let tb = create_token(&env, &admin);
        let tc = create_token(&env, &admin);

        let pool_ab = setup_funded_pool(&env, &lp, &ta, &tb, 400_000, 400_000);
        let pool_bc = setup_funded_pool(&env, &lp, &tb, &tc, 400_000, 400_000);

        let router_id = env.register_contract(None, AmmRouter);
        let router = AmmRouterClient::new(&env, &router_id);

        soroban_sdk::token::StellarAssetClient::new(&env, &ta).mint(&user, &50_000);

        let valid_path = soroban_sdk::vec![&env, ta.clone(), tb.clone(), tc.clone()];
        let valid_pools = soroban_sdk::vec![&env, pool_ab.clone(), pool_bc.clone()];

        // Zero and negative amount_in must be rejected.
        assert!(router
            .try_swap_exact_tokens_for_tokens(&user, &valid_path, &valid_pools, &0, &1, &user)
            .is_err());
        assert!(router
            .try_swap_exact_tokens_for_tokens(&user, &valid_path, &valid_pools, &-5, &1, &user)
            .is_err());

        // Negative amount_out_min must be rejected.
        assert!(router
            .try_swap_exact_tokens_for_tokens(&user, &valid_path, &valid_pools, &1_000, &-1, &user)
            .is_err());

        // Short path (< 2 tokens) and mismatched pools length must be rejected.
        let short_path = soroban_sdk::vec![&env, ta.clone()];
        let empty_pools = soroban_sdk::vec![&env];
        assert!(router
            .try_swap_exact_tokens_for_tokens(&user, &short_path, &empty_pools, &1_000, &1, &user)
            .is_err());

        let one_pool = soroban_sdk::vec![&env, pool_ab.clone()];
        assert!(router
            .try_swap_exact_tokens_for_tokens(&user, &valid_path, &one_pool, &1_000, &1, &user)
            .is_err());

        // Balances and pool reserves remain untouched after all rejected calls.
        assert_eq!(TokenClient::new(&env, &ta).balance(&user), 50_000);
        assert_eq!(
            AmmPoolClient::new(&env, &pool_ab).get_reserves(),
            (400_000, 400_000)
        );
        assert_eq!(
            AmmPoolClient::new(&env, &pool_bc).get_reserves(),
            (400_000, 400_000)
        );
    }

    #[test]
    fn router_multi_hop_integration_slippage_rollback_then_succeeds() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let lp = Address::generate(&env);
        let user = Address::generate(&env);
        let recipient = Address::generate(&env);

        let ta = create_token(&env, &admin);
        let tb = create_token(&env, &admin);
        let tc = create_token(&env, &admin);

        let pool_ab = setup_funded_pool(&env, &lp, &ta, &tb, 500_000, 500_000);
        let pool_bc = setup_funded_pool(&env, &lp, &tb, &tc, 500_000, 500_000);

        let router_id = env.register_contract(None, AmmRouter);
        let router = AmmRouterClient::new(&env, &router_id);

        let amount_in = 25_000_i128;
        soroban_sdk::token::StellarAssetClient::new(&env, &ta).mint(&user, &amount_in);

        let h1 = amm_pool::math::amount_out(amount_in, 500_000, 500_000);
        let h2 = amm_pool::math::amount_out(h1, 500_000, 500_000);

        let forward_path = soroban_sdk::vec![&env, ta.clone(), tb.clone(), tc.clone()];
        let forward_pools = soroban_sdk::vec![&env, pool_ab.clone(), pool_bc.clone()];

        // 1. Failing min_out leaves all reserves and balances unchanged.
        assert!(router
            .try_swap_exact_tokens_for_tokens(
                &user,
                &forward_path,
                &forward_pools,
                &amount_in,
                &(h2 + 1),
                &recipient,
            )
            .is_err());
        assert_eq!(TokenClient::new(&env, &ta).balance(&user), amount_in);
        assert_eq!(TokenClient::new(&env, &tc).balance(&recipient), 0);
        assert_eq!(
            AmmPoolClient::new(&env, &pool_ab).get_reserves(),
            (500_000, 500_000)
        );
        assert_eq!(
            AmmPoolClient::new(&env, &pool_bc).get_reserves(),
            (500_000, 500_000)
        );

        // 2. Retrying with exact expected output succeeds.
        let out_tc = router.swap_exact_tokens_for_tokens(
            &user,
            &forward_path,
            &forward_pools,
            &amount_in,
            &h2,
            &recipient,
        );
        assert_eq!(out_tc, h2);
        assert_eq!(TokenClient::new(&env, &tc).balance(&recipient), h2);

        // 3. Reverse 2-hop swap from recipient (tc -> tb -> ta) back to user.
        let rev_h1 = amm_pool::math::amount_out(out_tc, 500_000 - h2, 500_000 + h1);
        let rev_h2 = amm_pool::math::amount_out(rev_h1, 500_000 - h1, 500_000 + amount_in);
        let reverse_path = soroban_sdk::vec![&env, tc, tb, ta.clone()];
        let reverse_pools = soroban_sdk::vec![&env, pool_bc, pool_ab];

        let out_ta = router.swap_exact_tokens_for_tokens(
            &recipient,
            &reverse_path,
            &reverse_pools,
            &out_tc,
            &rev_h2,
            &user,
        );
        assert_eq!(out_ta, rev_h2);
        assert!(out_ta < amount_in);
        assert_eq!(TokenClient::new(&env, &ta).balance(&user), out_ta);
    }
}

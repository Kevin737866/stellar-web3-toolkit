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
    use soroban_sdk::testutils::Address as _;

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
}

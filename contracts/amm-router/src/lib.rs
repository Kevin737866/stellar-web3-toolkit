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
    /// The router receives `amount_in` of `path[0]` from `user`, then routes through each pool.
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
        assert!(path.len() >= 2, "path");
        assert!(pools.len() + 1 == path.len(), "pools");
        let router = env.current_contract_address();

        let t0 = path.get(0).unwrap();
        TokenClient::new(&env, &t0).transfer(&user, &router, &amount_in);

        let mut running = amount_in;
        let last_idx = pools.len().saturating_sub(1);
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
        }

        assert!(running >= amount_out_min, "min out");
        running
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use amm_pool::{AmmPool, AmmPoolClient};
    use soroban_sdk::testutils::{Address as _};

    #[test]
    fn router_single_pool_swap() {
        let env = Env::default();
        env.mock_all_auths();

        let (ta, tb) = {
            let admin = Address::generate(&env);
            (
                env.register_stellar_asset_contract(admin.clone()),
                env.register_stellar_asset_contract(admin.clone()),
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
        let out = router.swap_exact_tokens_for_tokens(
            &u,
            &path,
            &pools,
            &10_000,
            &1,
            &u,
        );
        let after = TokenClient::new(&env, &tb).balance(&u);
        assert_eq!(after.saturating_sub(before), out);
        assert!(out > 9000);
    }
}

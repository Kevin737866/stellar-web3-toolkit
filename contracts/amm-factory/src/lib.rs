#![no_std]
#[cfg(test)]
extern crate std;

use amm_pool::AmmPoolClient;
use soroban_sdk::{
    contract, contractimpl, contracttype, Address, Bytes, BytesN, Env,
};

/// Counter-based deploy salt (unique per pair); `get_pair` is canonical for routing.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    PoolWasmHash,
    Nonce,
    Pair(PairKey),
}

#[contracttype]
#[derive(Clone)]
pub struct PairKey {
    pub t0: Address,
    pub t1: Address,
}

#[contract]
pub struct AmmFactory;

fn sort_tokens(a: Address, b: Address) -> (Address, Address) {
    if a < b {
        (a, b)
    } else {
        (b, a)
    }
}

fn next_salt(env: &Env) -> BytesN<32> {
    let n: u64 = env.storage().instance().get(&DataKey::Nonce).unwrap_or(0);
    env.storage().instance().set(&DataKey::Nonce, &(n.saturating_add(1)));
    let mut raw = [0u8; 32];
    raw[24..32].copy_from_slice(&n.to_be_bytes());
    env.crypto().sha256(&Bytes::from_slice(env, &raw))
}

#[contractimpl]
impl AmmFactory {
    pub fn init(env: Env, admin: Address, pool_wasm_hash: BytesN<32>) {
        assert!(!env.storage().instance().has(&DataKey::Admin), "admin set");
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::PoolWasmHash, &pool_wasm_hash);
        env.storage().instance().set(&DataKey::Nonce, &0_u64);
    }

    pub fn admin(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).expect("init")
    }

    /// Create a new constant-product pair; anyone may call (permissionless pool creation).
    pub fn create_pair(env: Env, token_a: Address, token_b: Address) -> Address {
        assert!(token_a != token_b, "identical");
        let (t0, t1) = sort_tokens(token_a.clone(), token_b.clone());
        let pk = PairKey { t0: t0.clone(), t1: t1.clone() };
        assert!(
            !env.storage().instance().has(&DataKey::Pair(pk.clone())),
            "exists"
        );
        let wasm_hash: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::PoolWasmHash)
            .expect("wasm");
        let salt = next_salt(&env);
        let factory = env.current_contract_address();
        let pool = env.deployer().with_current_contract(salt).deploy(wasm_hash);
        AmmPoolClient::new(&env, &pool).initialize(&factory, &t0, &t1);
        env.storage().instance().set(&DataKey::Pair(pk), &pool);
        pool
    }

    pub fn get_pair(env: Env, token_a: Address, token_b: Address) -> Option<Address> {
        let (t0, t1) = sort_tokens(token_a, token_b);
        env.storage()
            .instance()
            .get(&DataKey::Pair(PairKey { t0, t1 }))
    }

    pub fn pool_wasm_hash(env: Env) -> BytesN<32> {
        env.storage()
            .instance()
            .get(&DataKey::PoolWasmHash)
            .expect("wasm")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use amm_pool::AmmPoolClient;
    use soroban_sdk::testutils::{Address as _};
    use std::path::Path;

    #[test]
    fn get_pair_none_before_create() {
        let env = Env::default();
        env.mock_all_auths();
        let factory_id = env.register_contract(None, AmmFactory);
        let factory = AmmFactoryClient::new(&env, &factory_id);
        let admin = Address::generate(&env);
        let hash = BytesN::from_array(&env, &[7u8; 32]);
        factory.init(&admin, &hash);
        let a = Address::generate(&env);
        let b = Address::generate(&env);
        assert!(factory.get_pair(&a, &b).is_none());
    }

    #[test]
    fn create_pair_deploys_pool() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/wasm32-unknown-unknown/release/amm_pool.wasm");
        let pool_wasm: std::vec::Vec<u8> = match std::fs::read(&path) {
            Ok(w) => w,
            Err(_) => {
                std::eprintln!(
                    "skip create_pair_deploys_pool: run `cargo build -p amm-pool --target wasm32-unknown-unknown --release` first"
                );
                return;
            }
        };

        let env = Env::default();
        env.mock_all_auths();
        let pool_hash = env.deployer().upload_contract_wasm(pool_wasm.as_slice());

        let factory_id = env.register_contract(None, AmmFactory);
        let factory = AmmFactoryClient::new(&env, &factory_id);
        let admin = Address::generate(&env);
        factory.init(&admin, &pool_hash);

        let ta = env.register_stellar_asset_contract(admin.clone());
        let tb = env.register_stellar_asset_contract(admin.clone());

        let pool_addr = factory.create_pair(&ta, &tb);
        let pool = AmmPoolClient::new(&env, &pool_addr);
        assert_eq!(pool.token_a(), ta);
        assert_eq!(pool.token_b(), tb);
        assert_eq!(factory.get_pair(&ta, &tb), Some(pool_addr.clone()));

        soroban_sdk::token::StellarAssetClient::new(&env, &ta).mint(&admin, &500_000);
        soroban_sdk::token::StellarAssetClient::new(&env, &tb).mint(&admin, &500_000);
        let u = Address::generate(&env);
        soroban_sdk::token::StellarAssetClient::new(&env, &ta).mint(&u, &100_000);
        soroban_sdk::token::StellarAssetClient::new(&env, &tb).mint(&u, &100_000);
        let _ = pool.add_liquidity(&u, &50_000, &50_000, &1, &1);
        let (ra, rb) = pool.get_reserves();
        assert!(ra > 0 && rb > 0);
    }
}

#![no_std]
#[cfg(test)]
extern crate std;

use amm_pool::AmmPoolClient;
use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, BytesN, Env};

/// Counter-based deploy salt (unique per pair); `get_pair` is canonical for routing.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    PoolWasmHash,
    // Reserved to preserve the storage-key discriminants of deployed versions.
    // Pool addresses now use deterministic pair-derived salts.
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

fn append_address(out: &mut Bytes, address: &Address) {
    // Soroban SDK 21 exposes an address's canonical StrKey representation.
    // It has a fixed length, so concatenating two encodings is unambiguous.
    let encoded = address.to_string();
    let len = encoded.len() as usize;
    assert!(len <= 64, "address strkey exceeds buffer");
    let mut buf = [0u8; 64];
    encoded.copy_into_slice(&mut buf[..len]);
    out.extend_from_slice(&buf[..len]);
}

/// Derive one deployment salt per canonical token pair. The deployer scopes
/// this salt to the current factory address, so separate factory instances do
/// not compete for the same pool address.
fn pair_salt(env: &Env, token_0: &Address, token_1: &Address) -> BytesN<32> {
    let mut preimage = Bytes::from_slice(env, b"stellar-web3-toolkit/amm-factory/pool/v1");
    append_address(&mut preimage, token_0);
    append_address(&mut preimage, token_1);
    env.crypto().sha256(&preimage).to_bytes()
}

#[contractimpl]
impl AmmFactory {
    pub fn init(env: Env, admin: Address, pool_wasm_hash: BytesN<32>) {
        admin.require_auth();

        // Retrying deployment setup with the same configuration is harmless.
        // A different configuration must never silently take over the factory.
        if let Some(existing_admin) = env.storage().instance().get::<_, Address>(&DataKey::Admin) {
            let existing_hash: BytesN<32> = env
                .storage()
                .instance()
                .get(&DataKey::PoolWasmHash)
                .expect("factory configuration is incomplete");
            assert!(
                existing_admin == admin && existing_hash == pool_wasm_hash,
                "factory already initialized with different config"
            );
            return;
        }

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::PoolWasmHash, &pool_wasm_hash);
    }

    pub fn admin(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).expect("init")
    }

    /// Create a new constant-product pair; anyone may call (permissionless pool creation).
    pub fn create_pair(env: Env, token_a: Address, token_b: Address) -> Address {
        assert!(token_a != token_b, "identical");
        let (t0, t1) = sort_tokens(token_a.clone(), token_b.clone());
        let pk = PairKey {
            t0: t0.clone(),
            t1: t1.clone(),
        };
        assert!(
            !env.storage().instance().has(&DataKey::Pair(pk.clone())),
            "exists"
        );
        let wasm_hash: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::PoolWasmHash)
            .expect("wasm");
        let salt = pair_salt(&env, &t0, &t1);
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
    use soroban_sdk::testutils::Address as _;
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
        // This is the only test that proves a built contract is actually
        // *loadable* by the Soroban host, not merely that it compiles: the host
        // validates the module before running it. That is what catches a contract
        // built for the wrong WASM target, which every other test is blind to.
        //
        // The target must match `rust-toolchain.toml`; a module built for
        // wasm32-unknown-unknown carries `reference-types` and the host rejects it
        // with "reference-types not enabled: zero byte expected".
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/wasm32v1-none/release/amm_pool.wasm");
        let pool_wasm: std::vec::Vec<u8> = if let Ok(w) = std::fs::read(&path) {
            w
        } else {
            // Skipping rather than failing keeps `cargo test` usable without a
            // prior WASM build, but it also means this test proves nothing
            // unless the build ran first. The CI `wasm` job therefore builds
            // and then runs this test explicitly.
            std::eprintln!(
                "skip create_pair_deploys_pool: run `cargo build -p amm-pool --target wasm32v1-none --release` first"
            );
            return;
        };

        let env = Env::default();
        env.mock_all_auths();
        let pool_hash = env.deployer().upload_contract_wasm(pool_wasm.as_slice());

        let factory_id = env.register_contract(None, AmmFactory);
        let factory = AmmFactoryClient::new(&env, &factory_id);
        let admin = Address::generate(&env);
        factory.init(&admin, &pool_hash);

        let ta = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let tb = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();

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

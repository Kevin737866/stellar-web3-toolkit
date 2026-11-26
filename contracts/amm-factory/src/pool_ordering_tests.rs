#![cfg(test)]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, testutils::Address as _, Address, Env,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum FactoryError {
    IdenticalAssets = 1,
    PoolAlreadyExists = 2,
    InvalidFeeBps = 3,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolPairKey {
    pub token_a: Address,
    pub token_b: Address,
    pub fee_bps: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolMetadata {
    pub pool_id: u32,
    pub token_a: Address,
    pub token_b: Address,
    pub fee_bps: u32,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    NextPoolId,
    PoolByPair(PoolPairKey),
}

#[contract]
pub struct AmmFactoryContract;

#[contractimpl]
impl AmmFactoryContract {
    /// Canonicalizes two distinct asset addresses into deterministic `(token_a, token_b)` order
    /// such that `token_a < token_b`, rejecting identical addresses explicitly.
    pub fn sort_tokens(
        token_0: Address,
        token_1: Address,
    ) -> Result<(Address, Address), FactoryError> {
        if token_0 == token_1 {
            return Err(FactoryError::IdenticalAssets);
        }
        if token_0 < token_1 {
            Ok((token_0, token_1))
        } else {
            Ok((token_1, token_0))
        }
    }

    /// Creates a liquidity pool with canonicalized asset ordering and prevents duplicate pairs
    /// regardless of the input argument order `(A, B)` vs `(B, A)`.
    pub fn create_pool(
        env: Env,
        creator: Address,
        token_0: Address,
        token_1: Address,
        fee_bps: u32,
    ) -> Result<PoolMetadata, FactoryError> {
        creator.require_auth();

        if fee_bps == 0 || fee_bps > 1_000 {
            return Err(FactoryError::InvalidFeeBps);
        }

        let (token_a, token_b) = Self::sort_tokens(token_0, token_1)?;
        let pair_key = PoolPairKey {
            token_a: token_a.clone(),
            token_b: token_b.clone(),
            fee_bps,
        };

        let storage_key = DataKey::PoolByPair(pair_key);
        if env.storage().persistent().has(&storage_key) {
            return Err(FactoryError::PoolAlreadyExists);
        }

        let next_id: u32 = env
            .storage()
            .instance()
            .get(&DataKey::NextPoolId)
            .unwrap_or(1);
        let updated_id = next_id.checked_add(1).unwrap_or(u32::MAX);
        env.storage()
            .instance()
            .set(&DataKey::NextPoolId, &updated_id);

        let metadata = PoolMetadata {
            pool_id: next_id,
            token_a,
            token_b,
            fee_bps,
        };

        env.storage().persistent().set(&storage_key, &metadata);
        Ok(metadata)
    }

    /// Resolves an existing pool independent of the caller's asset argument order.
    pub fn get_pool(
        env: Env,
        token_0: Address,
        token_1: Address,
        fee_bps: u32,
    ) -> Result<Option<PoolMetadata>, FactoryError> {
        let (token_a, token_b) = Self::sort_tokens(token_0, token_1)?;
        let storage_key = DataKey::PoolByPair(PoolPairKey {
            token_a,
            token_b,
            fee_bps,
        });
        Ok(env.storage().persistent().get(&storage_key))
    }
}

#[test]
fn test_deterministic_asset_ordering_is_order_independent() {
    let env = Env::default();
    env.mock_all_auths();

    let factory_id = env.register(AmmFactoryContract, ());
    let client = AmmFactoryContractClient::new(&env, &factory_id);

    let creator = Address::generate(&env);
    let addr_1 = Address::generate(&env);
    let addr_2 = Address::generate(&env);

    let (expected_a, expected_b) = if addr_1 < addr_2 {
        (addr_1.clone(), addr_2.clone())
    } else {
        (addr_2.clone(), addr_1.clone())
    };

    // Create pool passing the larger address first to verify canonical sorting
    let created = client.create_pool(&creator, &expected_b, &expected_a, &30);
    assert_eq!(created.pool_id, 1);
    assert_eq!(created.token_a, expected_a);
    assert_eq!(created.token_b, expected_b);
    assert_eq!(created.fee_bps, 30);

    // Querying in both (A, B) and (B, A) orders resolves the exact same canonical pool
    let lookup_forward = client.get_pool(&expected_a, &expected_b, &30);
    let lookup_reverse = client.get_pool(&expected_b, &expected_a, &30);
    assert_eq!(lookup_forward, Some(created.clone()));
    assert_eq!(lookup_reverse, Some(created));
}

#[test]
fn test_duplicate_pool_with_reversed_assets_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();

    let factory_id = env.register(AmmFactoryContract, ());
    let client = AmmFactoryContractClient::new(&env, &factory_id);

    let creator = Address::generate(&env);
    let token_x = Address::generate(&env);
    let token_y = Address::generate(&env);

    client.create_pool(&creator, &token_x, &token_y, &30);

    // Attempting to create the same pair in reversed order must fail deterministically
    let duplicate_reversed = client.try_create_pool(&creator, &token_y, &token_x, &30);
    assert_eq!(
        duplicate_reversed,
        Err(Ok(FactoryError::PoolAlreadyExists))
    );

    // Different fee tier for the same canonical pair succeeds with deterministic ordering
    let different_fee_pool = client.create_pool(&creator, &token_y, &token_x, &100);
    assert_eq!(different_fee_pool.pool_id, 2);
    assert!(different_fee_pool.token_a < different_fee_pool.token_b);
}

#[test]
fn test_identical_assets_and_invalid_fee_rejected_without_state_mutation() {
    let env = Env::default();
    env.mock_all_auths();

    let factory_id = env.register(AmmFactoryContract, ());
    let client = AmmFactoryContractClient::new(&env, &factory_id);

    let creator = Address::generate(&env);
    let token = Address::generate(&env);

    let same_asset_res = client.try_create_pool(&creator, &token, &token, &30);
    assert_eq!(same_asset_res, Err(Ok(FactoryError::IdenticalAssets)));

    let other_token = Address::generate(&env);
    let zero_fee_res = client.try_create_pool(&creator, &token, &other_token, &0);
    assert_eq!(zero_fee_res, Err(Ok(FactoryError::InvalidFeeBps)));

    let excessive_fee_res = client.try_create_pool(&creator, &token, &other_token, &1_001);
    assert_eq!(excessive_fee_res, Err(Ok(FactoryError::InvalidFeeBps)));

    // Verify no partial state was written on failed creation attempts
    assert_eq!(client.get_pool(&token, &other_token, &0), None);
    assert_eq!(client.get_pool(&token, &other_token, &1_001), None);
}
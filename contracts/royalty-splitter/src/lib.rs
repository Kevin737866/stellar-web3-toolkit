#![no_std]

//! Royalty splitter for secondary digital-asset sales (issue #147).
//!
//! The contract follows the royalty model popularised by EIP-2981, adapted to
//! Soroban and Stellar's [SEP-41](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0041.md)
//! token standard. A per-asset royalty can be split across multiple receivers,
//! each with a basis-point share. Royalties are paid out in any SEP-41 token,
//! so the splitter works with fungible tokens and NFT-style collections alike.
//!
//! `preview` computes the split without touching state; `distribute` performs
//! the SEP-41 transfers from a payer to every receiver.

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token::TokenClient, Address, Env, Vec,
};

/// Royalty shares are expressed in basis points (1 bps = 0.01%).
const MAX_BPS: u32 = 10_000;
const ROYALTY_TTL_THRESHOLD: u32 = 1_000;
const ROYALTY_TTL_BUMP: u32 = 100_000;

/// A single royalty beneficiary and their share.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receiver {
    pub recipient: Address,
    pub bps: u32,
}

/// Royalty configuration for an asset: an ordered list of receivers and the
/// total share (in basis points).
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RoyaltyInfo {
    pub receivers: Vec<Receiver>,
    pub total_bps: u32,
}

/// Identifies an asset within a collection. `token_id` is `0` for fungible
/// assets and the unique id for NFT-style assets.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetKey {
    pub collection: Address,
    pub token_id: u128,
}

/// A computed royalty payment.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payout {
    pub recipient: Address,
    pub amount: i128,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    MaxRoyaltyBps,
    DefaultRoyalty,
    Royalty(AssetKey),
}

#[contract]
pub struct RoyaltySplitter;

fn admin(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&DataKey::Admin)
        .expect("royalty splitter not initialized")
}

fn max_royalty_bps(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::MaxRoyaltyBps)
        .expect("royalty splitter not initialized")
}

fn empty_info(env: &Env) -> RoyaltyInfo {
    RoyaltyInfo {
        receivers: Vec::new(env),
        total_bps: 0,
    }
}

fn validate_receivers(env: &Env, receivers: &Vec<Receiver>) -> RoyaltyInfo {
    let cap = max_royalty_bps(env);
    let count = receivers.len();
    assert!(count > 0, "no receivers");

    let mut total_bps: u32 = 0;
    let mut i: u32 = 0;
    while i < count {
        let receiver = receivers.get(i).unwrap();
        assert!(receiver.bps > 0, "bps must be positive");

        // Reject duplicate beneficiaries so shares cannot be double-counted.
        let mut j = i + 1;
        while j < count {
            let other = receivers.get(j).unwrap();
            assert!(receiver.recipient != other.recipient, "duplicate receiver");
            j += 1;
        }

        total_bps = total_bps.saturating_add(receiver.bps);
        i += 1;
    }

    assert!(total_bps <= cap, "royalty exceeds maximum");
    assert!(total_bps <= MAX_BPS, "royalty exceeds maximum");

    RoyaltyInfo {
        receivers: receivers.clone(),
        total_bps,
    }
}

fn load_royalty(env: &Env, collection: &Address, token_id: u128) -> RoyaltyInfo {
    let key = DataKey::Royalty(AssetKey {
        collection: collection.clone(),
        token_id,
    });
    if let Some(info) = env.storage().persistent().get(&key) {
        env.storage()
            .persistent()
            .extend_ttl(&key, ROYALTY_TTL_THRESHOLD, ROYALTY_TTL_BUMP);
        return info;
    }

    env.storage()
        .instance()
        .get(&DataKey::DefaultRoyalty)
        .unwrap_or_else(|| empty_info(env))
}

fn store_royalty(env: &Env, key: &AssetKey, info: &RoyaltyInfo) {
    let storage_key = DataKey::Royalty(key.clone());
    env.storage().persistent().set(&storage_key, info);
    env.storage()
        .persistent()
        .extend_ttl(&storage_key, ROYALTY_TTL_THRESHOLD, ROYALTY_TTL_BUMP);
}

fn compute_payouts(env: &Env, info: &RoyaltyInfo, sale_price: i128) -> Vec<Payout> {
    let mut payouts: Vec<Payout> = Vec::new(env);
    let count = info.receivers.len();
    let mut i: u32 = 0;
    while i < count {
        let receiver = info.receivers.get(i).unwrap();
        let amount = sale_price
            .checked_mul(receiver.bps as i128)
            .expect("payout overflow")
            / MAX_BPS as i128;
        payouts.push_back(Payout {
            recipient: receiver.recipient,
            amount,
        });
        i += 1;
    }
    payouts
}

#[contractimpl]
impl RoyaltySplitter {
    /// One-time configuration. `max_royalty_bps` caps the total share any asset
    /// may assign to royalty receivers.
    pub fn initialize(env: Env, admin: Address, max_royalty_bps: u32) {
        assert!(
            !env.storage().instance().has(&DataKey::Admin),
            "royalty splitter already initialized"
        );
        assert!(max_royalty_bps <= MAX_BPS, "max royalty exceeds maximum");
        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::MaxRoyaltyBps, &max_royalty_bps);
    }

    /// Registers the royalty split for a specific asset.
    ///
    /// Either the contract admin or the collection contract itself may set a
    /// royalty, which lets a collection enforce its own secondary-sale terms.
    pub fn set_royalty(
        env: Env,
        caller: Address,
        collection: Address,
        token_id: u128,
        receivers: Vec<Receiver>,
    ) {
        caller.require_auth();
        let is_admin = caller == admin(&env);
        let is_collection = caller == collection;
        assert!(is_admin || is_collection, "unauthorized");

        let info = validate_receivers(&env, &receivers);
        store_royalty(&env, &AssetKey { collection: collection.clone(), token_id }, &info);

        env.events()
            .publish((symbol_short!("royalty"), collection), (token_id, info.total_bps));
    }

    /// Registers a fallback royalty used when an asset has no explicit entry.
    pub fn set_default_royalty(env: Env, caller: Address, receivers: Vec<Receiver>) {
        caller.require_auth();
        assert!(caller == admin(&env), "unauthorized");

        let info = validate_receivers(&env, &receivers);
        env.storage()
            .instance()
            .set(&DataKey::DefaultRoyalty, &info);
    }

    /// Removes an explicit royalty entry for an asset.
    pub fn clear_royalty(env: Env, caller: Address, collection: Address, token_id: u128) {
        caller.require_auth();
        let is_admin = caller == admin(&env);
        let is_collection = caller == collection;
        assert!(is_admin || is_collection, "unauthorized");

        let storage_key = DataKey::Royalty(AssetKey {
            collection: collection.clone(),
            token_id,
        });
        env.storage().persistent().remove(&storage_key);

        env.events()
            .publish((symbol_short!("clrroy"), collection), token_id);
    }

    /// Updates the global royalty cap. Admin only.
    pub fn set_max_royalty_bps(env: Env, max_bps: u32) {
        assert!(max_bps <= MAX_BPS, "max royalty exceeds maximum");
        admin(&env).require_auth();
        env.storage()
            .instance()
            .set(&DataKey::MaxRoyaltyBps, &max_bps);
    }

    /// Returns the effective royalty configuration for an asset, falling back
    /// to the default royalty when no explicit entry exists.
    pub fn royalty_info(env: Env, collection: Address, token_id: u128) -> RoyaltyInfo {
        load_royalty(&env, &collection, token_id)
    }

    /// Total royalty owed on a sale of `sale_price`, in the payment token's
    /// base units.
    pub fn total_royalty(env: Env, collection: Address, token_id: u128, sale_price: i128) -> i128 {
        assert!(sale_price >= 0, "sale price must be non-negative");
        let info = load_royalty(&env, &collection, token_id);
        sale_price
            .checked_mul(info.total_bps as i128)
            .expect("royalty overflow")
            / MAX_BPS as i128
    }

    /// Computes the per-receiver split for a sale without transferring funds.
    pub fn preview(
        env: Env,
        collection: Address,
        token_id: u128,
        sale_price: i128,
    ) -> Vec<Payout> {
        assert!(sale_price >= 0, "sale price must be non-negative");
        let info = load_royalty(&env, &collection, token_id);
        compute_payouts(&env, &info, sale_price)
    }

    /// Pays royalties for a secondary sale by transferring `sale_price`-based
    /// shares in a SEP-41 `payment_token` from the payer to each receiver.
    ///
    /// Returns the executed payouts. Shares are floored to whole base units, so
    /// the summed payouts may be less than `total_royalty` by rounding dust
    /// (which stays with the seller).
    pub fn distribute(
        env: Env,
        payer: Address,
        collection: Address,
        token_id: u128,
        sale_price: i128,
        payment_token: Address,
    ) -> Vec<Payout> {
        payer.require_auth();
        assert!(sale_price > 0, "sale price must be positive");

        let info = load_royalty(&env, &collection, token_id);
        let payouts = compute_payouts(&env, &info, sale_price);

        let token = TokenClient::new(&env, &payment_token);
        let count = payouts.len();
        let mut i: u32 = 0;
        while i < count {
            let payout = payouts.get(i).unwrap();
            if payout.amount > 0 {
                token.transfer(&payer, &payout.recipient, &payout.amount);
            }
            i += 1;
        }

        env.events().publish(
            (symbol_short!("payout"), collection),
            (token_id, sale_price, info.total_bps),
        );

        payouts
    }

    /// Returns the global royalty cap in basis points.
    pub fn get_max_royalty_bps(env: Env) -> u32 {
        max_royalty_bps(&env)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::token::{StellarAssetClient, TokenClient};

    fn setup_token(env: &Env, admin: &Address) -> Address {
        env.register_stellar_asset_contract(admin.clone())
    }

    fn receiver(address: &Address, bps: u32) -> Receiver {
        Receiver {
            recipient: address.clone(),
            bps,
        }
    }

    fn receivers(env: &Env) -> (Vec<Receiver>, Address, Address, Address) {
        let creator = Address::generate(env);
        let charity = Address::generate(env);
        let platform = Address::generate(env);
        let mut list = Vec::new(env);
        list.push_back(receiver(&creator, 500));
        list.push_back(receiver(&charity, 250));
        list.push_back(receiver(&platform, 250));
        (list, creator, charity, platform)
    }

    #[test]
    fn set_and_read_royalty() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let collection = Address::generate(&env);
        let splitter_id = env.register_contract(None, RoyaltySplitter);
        let splitter = RoyaltySplitterClient::new(&env, &splitter_id);
        splitter.initialize(&admin, &1_000);

        let (list, creator, _, _) = receivers(&env);
        splitter.set_royalty(&admin, &collection, &42_u128, &list);

        let info = splitter.royalty_info(&collection, &42_u128);
        assert_eq!(info.total_bps, 1_000);
        assert_eq!(info.receivers.len(), 3);
        assert_eq!(info.receivers.get(0).unwrap().recipient, creator);
        assert_eq!(splitter.get_max_royalty_bps(), 1_000);
    }

    #[test]
    fn preview_splits_sale_price() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let collection = Address::generate(&env);
        let splitter_id = env.register_contract(None, RoyaltySplitter);
        let splitter = RoyaltySplitterClient::new(&env, &splitter_id);
        splitter.initialize(&admin, &1_000);

        let (list, creator, charity, platform) = receivers(&env);
        splitter.set_royalty(&admin, &collection, &1_u128, &list);

        let payouts = splitter.preview(&collection, &1_u128, &1_000_i128);
        assert_eq!(payouts.len(), 3);
        assert_eq!(payouts.get(0).unwrap().recipient, creator);
        assert_eq!(payouts.get(0).unwrap().amount, 50);
        assert_eq!(payouts.get(1).unwrap().recipient, charity);
        assert_eq!(payouts.get(1).unwrap().amount, 25);
        assert_eq!(payouts.get(2).unwrap().recipient, platform);
        assert_eq!(payouts.get(2).unwrap().amount, 25);
        assert_eq!(splitter.total_royalty(&collection, &1_u128, &1_000_i128), 100);
    }

    #[test]
    fn distribute_transfers_to_all_receivers() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let payer = Address::generate(&env);
        let collection = Address::generate(&env);
        let payment = setup_token(&env, &admin);
        StellarAssetClient::new(&env, &payment).mint(&payer, &10_000);

        let splitter_id = env.register_contract(None, RoyaltySplitter);
        let splitter = RoyaltySplitterClient::new(&env, &splitter_id);
        splitter.initialize(&admin, &1_000);

        let (list, creator, charity, platform) = receivers(&env);
        splitter.set_royalty(&admin, &collection, &1_u128, &list);
        splitter.distribute(&payer, &collection, &1_u128, &1_000_i128, &payment);

        let token = TokenClient::new(&env, &payment);
        assert_eq!(token.balance(&creator), 50);
        assert_eq!(token.balance(&charity), 25);
        assert_eq!(token.balance(&platform), 25);
        assert_eq!(token.balance(&payer), 9_900);
    }

    #[test]
    fn default_royalty_is_used_as_fallback() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let collection = Address::generate(&env);
        let splitter_id = env.register_contract(None, RoyaltySplitter);
        let splitter = RoyaltySplitterClient::new(&env, &splitter_id);
        splitter.initialize(&admin, &1_000);

        let fallback = Address::generate(&env);
        let mut list = Vec::new(&env);
        list.push_back(receiver(&fallback, 100));
        splitter.set_default_royalty(&admin, &list);

        let info = splitter.royalty_info(&collection, &99_u128);
        assert_eq!(info.total_bps, 100);
        assert_eq!(info.receivers.get(0).unwrap().recipient, fallback);
    }

    #[test]
    fn collection_can_manage_its_own_royalty() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let collection = Address::generate(&env);
        let splitter_id = env.register_contract(None, RoyaltySplitter);
        let splitter = RoyaltySplitterClient::new(&env, &splitter_id);
        splitter.initialize(&admin, &1_000);

        let mut list = Vec::new(&env);
        list.push_back(receiver(&collection, 400));
        splitter.set_royalty(&collection, &collection, &3_u128, &list);
        assert_eq!(splitter.royalty_info(&collection, &3_u128).total_bps, 400);

        splitter.clear_royalty(&collection, &collection, &3_u128);
        assert_eq!(splitter.royalty_info(&collection, &3_u128).total_bps, 0);
    }

    #[test]
    fn rounding_dust_is_floored() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let collection = Address::generate(&env);
        let a = Address::generate(&env);
        let b = Address::generate(&env);
        let splitter_id = env.register_contract(None, RoyaltySplitter);
        let splitter = RoyaltySplitterClient::new(&env, &splitter_id);
        splitter.initialize(&admin, &10_000);

        // 33.33% + 33.33% of 3 base units floors to 0 + 0.
        let mut list = Vec::new(&env);
        list.push_back(Receiver {
            recipient: a.clone(),
            bps: 3_333,
        });
        list.push_back(Receiver {
            recipient: b.clone(),
            bps: 3_333,
        });
        splitter.set_royalty(&admin, &collection, &1_u128, &list);

        let payouts = splitter.preview(&collection, &1_u128, &3_i128);
        assert_eq!(payouts.get(0).unwrap().amount, 0);
        assert_eq!(payouts.get(1).unwrap().amount, 0);
    }

    #[test]
    #[should_panic(expected = "royalty exceeds maximum")]
    fn rejects_royalty_above_cap() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let collection = Address::generate(&env);
        let splitter_id = env.register_contract(None, RoyaltySplitter);
        let splitter = RoyaltySplitterClient::new(&env, &splitter_id);
        splitter.initialize(&admin, &1_000);

        let mut list = Vec::new(&env);
        list.push_back(receiver(&admin, 1_001));
        splitter.set_royalty(&admin, &collection, &1_u128, &list);
    }

    #[test]
    #[should_panic(expected = "duplicate receiver")]
    fn rejects_duplicate_receivers() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let collection = Address::generate(&env);
        let dup = Address::generate(&env);
        let splitter_id = env.register_contract(None, RoyaltySplitter);
        let splitter = RoyaltySplitterClient::new(&env, &splitter_id);
        splitter.initialize(&admin, &1_000);

        let mut list = Vec::new(&env);
        list.push_back(Receiver {
            recipient: dup.clone(),
            bps: 100,
        });
        list.push_back(Receiver { recipient: dup, bps: 200 });
        splitter.set_royalty(&admin, &collection, &1_u128, &list);
    }

    #[test]
    #[should_panic(expected = "unauthorized")]
    fn non_admin_cannot_set_default_royalty() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);
        let splitter_id = env.register_contract(None, RoyaltySplitter);
        let splitter = RoyaltySplitterClient::new(&env, &splitter_id);
        splitter.initialize(&admin, &1_000);

        let mut list = Vec::new(&env);
        list.push_back(receiver(&attacker, 100));
        splitter.set_default_royalty(&attacker, &list);
    }

    #[test]
    #[should_panic(expected = "bps must be positive")]
    fn rejects_zero_bps_receiver() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let collection = Address::generate(&env);
        let splitter_id = env.register_contract(None, RoyaltySplitter);
        let splitter = RoyaltySplitterClient::new(&env, &splitter_id);
        splitter.initialize(&admin, &1_000);

        let mut list = Vec::new(&env);
        list.push_back(receiver(&admin, 0));
        splitter.set_royalty(&admin, &collection, &1_u128, &list);
    }
}

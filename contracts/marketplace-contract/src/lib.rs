#![no_std]

//! Marketplace listing contract for digital assets (issue #146).
//!
//! Listings escrow a [SEP-41](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0041.md)
//! token (the digital asset) and settle in a second SEP-41 token used as the
//! payment currency. Any SEP-41 compliant Soroban token can be listed or used
//! for payment, so fungible tokens and NFT-style contracts (`token_id` + fixed
//! `amount`) are both supported.
//!
//! Lifecycle: `create_listing` escrows the asset, `buy` settles payment and
//! releases the asset, `cancel_listing` returns the escrow to the seller.

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token::TokenClient, Address, Env,
};

/// Fee is expressed in basis points (1 bps = 0.01%).
const MAX_FEE_BPS: u32 = 10_000;
const LISTING_TTL_THRESHOLD: u32 = 1_000;
const LISTING_TTL_BUMP: u32 = 100_000;

/// Storage keys. Instance storage holds contract-wide configuration while each
/// listing lives in persistent storage keyed by its id.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    FeeBps,
    FeeRecipient,
    NextListingId,
    Listing(u64),
}

/// Current state of a listing.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ListingStatus {
    Active,
    Sold,
    Cancelled,
}

/// A digital asset offered for sale.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Listing {
    pub id: u64,
    pub seller: Address,
    /// SEP-41 contract of the escrowed digital asset.
    pub asset: Address,
    /// `0` for fungible listings, or the unique id for NFT-style assets.
    pub token_id: u128,
    /// Units of `asset` held in escrow.
    pub amount: i128,
    /// Asking price denominated in `payment_token`.
    pub price: i128,
    /// SEP-41 contract used to settle the sale.
    pub payment_token: Address,
    pub status: ListingStatus,
    pub created_at: u32,
}

#[contract]
pub struct MarketplaceContract;

fn read_next_listing_id(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&DataKey::NextListingId)
        .unwrap_or(0)
}

fn write_next_listing_id(env: &Env, id: u64) {
    env.storage().instance().set(&DataKey::NextListingId, &id);
}

fn fee_bps(env: &Env) -> u32 {
    env.storage().instance().get(&DataKey::FeeBps).unwrap_or(0)
}

fn fee_recipient(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&DataKey::FeeRecipient)
        .expect("marketplace not initialized")
}

fn read_listing(env: &Env, listing_id: u64) -> Listing {
    let key = DataKey::Listing(listing_id);
    let listing: Listing = env
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or_else(|| panic!("listing not found"));
    env.storage()
        .persistent()
        .extend_ttl(&key, LISTING_TTL_THRESHOLD, LISTING_TTL_BUMP);
    listing
}

fn write_listing(env: &Env, listing: &Listing) {
    let key = DataKey::Listing(listing.id);
    env.storage().persistent().set(&key, listing);
    env.storage()
        .persistent()
        .extend_ttl(&key, LISTING_TTL_THRESHOLD, LISTING_TTL_BUMP);
}

#[contractimpl]
impl MarketplaceContract {
    /// One-time configuration of the marketplace fee (in basis points) and the
    /// account that collects it.
    pub fn initialize(env: Env, admin: Address, fee_bps: u32, fee_recipient: Address) {
        assert!(
            !env.storage().instance().has(&DataKey::Admin),
            "marketplace already initialized"
        );
        assert!(fee_bps <= MAX_FEE_BPS, "fee exceeds maximum");
        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::FeeBps, &fee_bps);
        env.storage()
            .instance()
            .set(&DataKey::FeeRecipient, &fee_recipient);
        write_next_listing_id(&env, 0);
    }

    /// Lists `amount` units of a SEP-41 `asset` for `price` in `payment_token`.
    ///
    /// The seller must authorize the escrow transfer; the asset is held by the
    /// marketplace until the listing is sold or cancelled. Returns the new
    /// listing id.
    pub fn create_listing(
        env: Env,
        seller: Address,
        asset: Address,
        token_id: u128,
        amount: i128,
        price: i128,
        payment_token: Address,
    ) -> u64 {
        seller.require_auth();
        assert!(amount > 0, "amount must be positive");
        assert!(price > 0, "price must be positive");

        // Escrow the digital asset (SEP-41 transfer into the marketplace).
        TokenClient::new(&env, &asset).transfer(&seller, &env.current_contract_address(), &amount);

        let id = read_next_listing_id(&env);
        write_next_listing_id(&env, id.saturating_add(1));

        let listing = Listing {
            id,
            seller: seller.clone(),
            asset,
            token_id,
            amount,
            price,
            payment_token,
            status: ListingStatus::Active,
            created_at: env.ledger().timestamp() as u32,
        };
        write_listing(&env, &listing);

        env.events()
            .publish((symbol_short!("listed"), seller), (id, amount, price));

        id
    }

    /// Purchases an active listing. The buyer pays `price` in the listing's
    /// payment token: the marketplace fee goes to the configured recipient and
    /// the remainder goes to the seller. The escrowed asset is released to the
    /// buyer. Returns the seller proceeds after fees.
    pub fn buy(env: Env, buyer: Address, listing_id: u64) -> i128 {
        buyer.require_auth();
        let mut listing = read_listing(&env, listing_id);

        assert!(
            listing.status == ListingStatus::Active,
            "listing not active"
        );
        assert!(listing.seller != buyer, "seller cannot buy own listing");

        let fee = listing
            .price
            .checked_mul(fee_bps(&env) as i128)
            .expect("fee overflow")
            / MAX_FEE_BPS as i128;
        let seller_proceeds = listing.price - fee;

        let payments = TokenClient::new(&env, &listing.payment_token);
        payments.transfer(&buyer, &listing.seller, &seller_proceeds);
        if fee > 0 {
            payments.transfer(&buyer, &fee_recipient(&env), &fee);
        }

        // Release the escrowed asset to the buyer.
        TokenClient::new(&env, &listing.asset).transfer(
            &env.current_contract_address(),
            &buyer,
            &listing.amount,
        );

        listing.status = ListingStatus::Sold;
        write_listing(&env, &listing);

        env.events().publish(
            (symbol_short!("sold"), buyer),
            (listing_id, seller_proceeds, fee),
        );

        seller_proceeds
    }

    /// Cancels an active listing and returns the escrowed asset to the seller.
    pub fn cancel_listing(env: Env, seller: Address, listing_id: u64) {
        seller.require_auth();
        let mut listing = read_listing(&env, listing_id);

        assert!(
            listing.status == ListingStatus::Active,
            "listing not active"
        );
        assert!(listing.seller == seller, "only seller can cancel");

        TokenClient::new(&env, &listing.asset).transfer(
            &env.current_contract_address(),
            &seller,
            &listing.amount,
        );

        listing.status = ListingStatus::Cancelled;
        write_listing(&env, &listing);

        env.events()
            .publish((symbol_short!("canceled"), seller), listing_id);
    }

    /// Updates the asking price of an active listing.
    pub fn update_price(env: Env, seller: Address, listing_id: u64, new_price: i128) {
        seller.require_auth();
        let mut listing = read_listing(&env, listing_id);

        assert!(
            listing.status == ListingStatus::Active,
            "listing not active"
        );
        assert!(listing.seller == seller, "only seller can update");
        assert!(new_price > 0, "price must be positive");

        listing.price = new_price;
        write_listing(&env, &listing);

        env.events()
            .publish((symbol_short!("price"), seller), (listing_id, new_price));
    }

    /// Updates the marketplace fee. Admin only.
    pub fn set_fee_bps(env: Env, fee_bps: u32) {
        assert!(fee_bps <= MAX_FEE_BPS, "fee exceeds maximum");
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("marketplace not initialized");
        admin.require_auth();
        env.storage().instance().set(&DataKey::FeeBps, &fee_bps);
    }

    /// Updates the fee recipient. Admin only.
    pub fn set_fee_recipient(env: Env, recipient: Address) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("marketplace not initialized");
        admin.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::FeeRecipient, &recipient);
    }

    /// Returns a listing by id.
    pub fn get_listing(env: Env, listing_id: u64) -> Listing {
        read_listing(&env, listing_id)
    }

    /// Total number of listings ever created.
    pub fn listing_count(env: Env) -> u64 {
        read_next_listing_id(&env)
    }

    /// Current marketplace fee in basis points.
    pub fn get_fee_bps(env: Env) -> u32 {
        fee_bps(&env)
    }

    /// Current fee recipient.
    pub fn get_fee_recipient(env: Env) -> Address {
        fee_recipient(&env)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::token::{StellarAssetClient, TokenClient};

    fn setup_token(env: &Env, admin: &Address) -> Address {
        env.register_stellar_asset_contract_v2(admin.clone())
            .address()
    }

    fn mint(env: &Env, token: &Address, to: &Address, amount: i128) {
        StellarAssetClient::new(env, token).mint(to, &amount);
    }

    fn balance(env: &Env, token: &Address, who: &Address) -> i128 {
        TokenClient::new(env, token).balance(who)
    }

    #[test]
    fn create_listing_escrows_asset() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let seller = Address::generate(&env);
        let asset = setup_token(&env, &admin);
        let payment = setup_token(&env, &admin);

        let market_id = env.register_contract(None, MarketplaceContract);
        let market = MarketplaceContractClient::new(&env, &market_id);
        market.initialize(&admin, &250, &admin);

        mint(&env, &asset, &seller, 3);
        let id = market.create_listing(&seller, &asset, &7_u128, &2_i128, &1_000_i128, &payment);

        assert_eq!(id, 0);
        assert_eq!(balance(&env, &asset, &seller), 1);
        assert_eq!(balance(&env, &asset, &market_id), 2);
        assert_eq!(market.listing_count(), 1);

        let listing = market.get_listing(&id);
        assert_eq!(listing.seller, seller);
        assert_eq!(listing.token_id, 7);
        assert_eq!(listing.amount, 2);
        assert_eq!(listing.price, 1_000);
        assert_eq!(listing.status, ListingStatus::Active);
    }

    #[test]
    fn buy_settles_payment_and_releases_asset() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let seller = Address::generate(&env);
        let buyer = Address::generate(&env);
        let fee_recipient = Address::generate(&env);
        let asset = setup_token(&env, &admin);
        let payment = setup_token(&env, &admin);

        let market_id = env.register_contract(None, MarketplaceContract);
        let market = MarketplaceContractClient::new(&env, &market_id);
        // 5% marketplace fee.
        market.initialize(&admin, &500, &fee_recipient);

        mint(&env, &asset, &seller, 1);
        mint(&env, &payment, &buyer, 1_000);

        let id = market.create_listing(&seller, &asset, &0_u128, &1_i128, &1_000_i128, &payment);
        let proceeds = market.buy(&buyer, &id);

        assert_eq!(proceeds, 950);
        assert_eq!(balance(&env, &payment, &seller), 950);
        assert_eq!(balance(&env, &payment, &fee_recipient), 50);
        assert_eq!(balance(&env, &payment, &buyer), 0);
        assert_eq!(balance(&env, &asset, &buyer), 1);
        assert_eq!(balance(&env, &asset, &market_id), 0);
        assert_eq!(market.get_listing(&id).status, ListingStatus::Sold);
    }

    #[test]
    fn cancel_listing_returns_asset() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let seller = Address::generate(&env);
        let asset = setup_token(&env, &admin);
        let payment = setup_token(&env, &admin);

        let market_id = env.register_contract(None, MarketplaceContract);
        let market = MarketplaceContractClient::new(&env, &market_id);
        market.initialize(&admin, &100, &admin);

        mint(&env, &asset, &seller, 5);
        let id = market.create_listing(&seller, &asset, &0_u128, &5_i128, &50_i128, &payment);
        assert_eq!(balance(&env, &asset, &market_id), 5);

        market.cancel_listing(&seller, &id);

        assert_eq!(balance(&env, &asset, &seller), 5);
        assert_eq!(balance(&env, &asset, &market_id), 0);
        assert_eq!(market.get_listing(&id).status, ListingStatus::Cancelled);
    }

    #[test]
    fn update_price_changes_asking_price() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let seller = Address::generate(&env);
        let asset = setup_token(&env, &admin);
        let payment = setup_token(&env, &admin);

        let market_id = env.register_contract(None, MarketplaceContract);
        let market = MarketplaceContractClient::new(&env, &market_id);
        market.initialize(&admin, &0, &admin);

        mint(&env, &asset, &seller, 1);
        let id = market.create_listing(&seller, &asset, &0_u128, &1_i128, &100_i128, &payment);
        market.update_price(&seller, &id, &250);

        assert_eq!(market.get_listing(&id).price, 250);
    }

    #[test]
    fn admin_can_update_fee_config() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let fee_recipient = Address::generate(&env);
        let new_recipient = Address::generate(&env);

        let market_id = env.register_contract(None, MarketplaceContract);
        let market = MarketplaceContractClient::new(&env, &market_id);
        market.initialize(&admin, &100, &fee_recipient);

        assert_eq!(market.get_fee_bps(), 100);
        market.set_fee_bps(&900);
        market.set_fee_recipient(&new_recipient);

        assert_eq!(market.get_fee_bps(), 900);
        assert_eq!(market.get_fee_recipient(), new_recipient);
    }

    #[test]
    #[should_panic(expected = "listing not active")]
    fn cannot_buy_sold_listing() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let seller = Address::generate(&env);
        let buyer = Address::generate(&env);
        let asset = setup_token(&env, &admin);
        let payment = setup_token(&env, &admin);

        let market_id = env.register_contract(None, MarketplaceContract);
        let market = MarketplaceContractClient::new(&env, &market_id);
        market.initialize(&admin, &0, &admin);

        mint(&env, &asset, &seller, 1);
        mint(&env, &payment, &buyer, 1_000);

        let id = market.create_listing(&seller, &asset, &0_u128, &1_i128, &1_000_i128, &payment);
        market.buy(&buyer, &id);
        market.buy(&buyer, &id);
    }

    #[test]
    #[should_panic(expected = "seller cannot buy own listing")]
    fn seller_cannot_buy_own_listing() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let seller = Address::generate(&env);
        let asset = setup_token(&env, &admin);
        let payment = setup_token(&env, &admin);

        let market_id = env.register_contract(None, MarketplaceContract);
        let market = MarketplaceContractClient::new(&env, &market_id);
        market.initialize(&admin, &0, &admin);

        mint(&env, &asset, &seller, 1);
        mint(&env, &payment, &seller, 1_000);

        let id = market.create_listing(&seller, &asset, &0_u128, &1_i128, &1_000_i128, &payment);
        market.buy(&seller, &id);
    }

    #[test]
    #[should_panic(expected = "fee exceeds maximum")]
    fn initialize_rejects_fee_above_max() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let market_id = env.register_contract(None, MarketplaceContract);
        let market = MarketplaceContractClient::new(&env, &market_id);
        market.initialize(&admin, &10_001, &admin);
    }

    #[test]
    #[should_panic(expected = "amount must be positive")]
    fn create_listing_rejects_zero_amount() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let seller = Address::generate(&env);
        let asset = setup_token(&env, &admin);
        let payment = setup_token(&env, &admin);

        let market_id = env.register_contract(None, MarketplaceContract);
        let market = MarketplaceContractClient::new(&env, &market_id);
        market.initialize(&admin, &0, &admin);

        market.create_listing(&seller, &asset, &0_u128, &0_i128, &100_i128, &payment);
    }

    #[test]
    #[should_panic(expected = "only seller can cancel")]
    fn only_seller_can_cancel() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let seller = Address::generate(&env);
        let attacker = Address::generate(&env);
        let asset = setup_token(&env, &admin);
        let payment = setup_token(&env, &admin);

        let market_id = env.register_contract(None, MarketplaceContract);
        let market = MarketplaceContractClient::new(&env, &market_id);
        market.initialize(&admin, &0, &admin);

        mint(&env, &asset, &seller, 1);
        let id = market.create_listing(&seller, &asset, &0_u128, &1_i128, &100_i128, &payment);
        market.cancel_listing(&attacker, &id);
    }
}

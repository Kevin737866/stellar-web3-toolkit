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
    ListingExpiry(u64),
}

/// An order submitted to buy or fill an active listing (issues #418, #419, #420).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Order {
    pub listing_id: u64,
    /// Expected owner/seller of the listing (issue #418).
    pub expected_seller: Option<Address>,
    /// Units of asset requested to fill (issue #420). If `None`, fills the entire remaining listing.
    pub fill_amount: Option<i128>,
    /// Maximum price the buyer is willing to pay for this fill (slippage/protection).
    pub max_price: Option<i128>,
    /// Expiry ledger sequence number; order is rejected if this precedes current ledger (issue #419).
    pub expiry_ledger: Option<u32>,
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

fn read_listing_expiry(env: &Env, listing_id: u64) -> Option<u32> {
    let key = DataKey::ListingExpiry(listing_id);
    let expiry = env.storage().persistent().get(&key);
    if expiry.is_some() {
        env.storage()
            .persistent()
            .extend_ttl(&key, LISTING_TTL_THRESHOLD, LISTING_TTL_BUMP);
    }
    expiry
}

fn write_listing_expiry(env: &Env, listing_id: u64, expiry_ledger: u32) {
    let key = DataKey::ListingExpiry(listing_id);
    env.storage().persistent().set(&key, &expiry_ledger);
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

    /// Lists `amount` units of a SEP-41 `asset` for `price` with an explicit ledger expiry (issue #419).
    pub fn create_listing_with_expiry(
        env: Env,
        seller: Address,
        asset: Address,
        token_id: u128,
        amount: i128,
        price: i128,
        payment_token: Address,
        expiry_ledger: u32,
    ) -> u64 {
        assert!(
            expiry_ledger >= env.ledger().sequence(),
            "expiry precedes current ledger"
        );
        let id = Self::create_listing(
            env.clone(),
            seller,
            asset,
            token_id,
            amount,
            price,
            payment_token,
        );
        write_listing_expiry(&env, id, expiry_ledger);
        id
    }

    /// Executes an order against an active listing with optional ownership validation,
    /// ledger expiry enforcement, and partial-fill accounting (issues #418, #419, #420).
    pub fn execute_order(env: Env, buyer: Address, order: Order) -> i128 {
        buyer.require_auth();
        let current_ledger = env.ledger().sequence();

        // 1. Validate order expiry against current ledger (issue #419)
        if let Some(order_expiry) = order.expiry_ledger {
            assert!(
                order_expiry >= current_ledger,
                "order expired: expiry precedes current ledger"
            );
        }

        let mut listing = read_listing(&env, order.listing_id);

        assert!(
            listing.status == ListingStatus::Active,
            "listing not active"
        );

        // 2. Validate listing expiry against current ledger (issue #419)
        if let Some(listing_expiry) = read_listing_expiry(&env, order.listing_id) {
            assert!(
                listing_expiry >= current_ledger,
                "listing expired: expiry precedes current ledger"
            );
        }

        // 3. Validate listing ownership (issue #418)
        assert!(listing.seller != buyer, "seller cannot buy own listing");
        if let Some(expected_seller) = order.expected_seller {
            assert!(
                listing.seller == expected_seller,
                "listing owner mismatch: expected seller does not match current seller"
            );
        }

        // 4. Partial-fill accounting (issue #420)
        let fill_amount = order.fill_amount.unwrap_or(listing.amount);
        assert!(fill_amount > 0, "fill amount must be positive");
        assert!(
            fill_amount <= listing.amount,
            "fill amount exceeds available listing amount"
        );

        let fill_price = if fill_amount == listing.amount {
            listing.price
        } else {
            listing
                .price
                .checked_mul(fill_amount)
                .expect("price overflow")
                / listing.amount
        };
        assert!(fill_price > 0, "proportional fill price must be positive");

        if let Some(max_price) = order.max_price {
            assert!(
                fill_price <= max_price,
                "fill price exceeds max price limit"
            );
        }

        let fee = fill_price
            .checked_mul(fee_bps(&env) as i128)
            .expect("fee overflow")
            / MAX_FEE_BPS as i128;
        let seller_proceeds = fill_price - fee;

        let payments = TokenClient::new(&env, &listing.payment_token);
        payments.transfer(&buyer, &listing.seller, &seller_proceeds);
        if fee > 0 {
            payments.transfer(&buyer, &fee_recipient(&env), &fee);
        }

        // Release the filled portion of the escrowed asset to the buyer.
        TokenClient::new(&env, &listing.asset).transfer(
            &env.current_contract_address(),
            &buyer,
            &fill_amount,
        );

        listing.amount -= fill_amount;
        listing.price -= fill_price;

        if listing.amount == 0 {
            listing.status = ListingStatus::Sold;
        }

        write_listing(&env, &listing);

        env.events().publish(
            (symbol_short!("order"), buyer),
            (order.listing_id, fill_amount, fill_price, listing.amount),
        );

        seller_proceeds
    }

    /// Purchases an active listing in full. Preserves legacy API and behavior 100%.
    pub fn buy(env: Env, buyer: Address, listing_id: u64) -> i128 {
        Self::execute_order(
            env,
            buyer,
            Order {
                listing_id,
                expected_seller: None,
                fill_amount: None,
                max_price: None,
                expiry_ledger: None,
            },
        )
    }

    /// Buys a partial amount of an active listing with optional constraints (issue #420).
    pub fn buy_partial(
        env: Env,
        buyer: Address,
        listing_id: u64,
        fill_amount: i128,
        expected_seller: Option<Address>,
        max_price: Option<i128>,
        expiry_ledger: Option<u32>,
    ) -> i128 {
        Self::execute_order(
            env,
            buyer,
            Order {
                listing_id,
                expected_seller,
                fill_amount: Some(fill_amount),
                max_price,
                expiry_ledger,
            },
        )
    }

    /// Returns the optional expiry ledger for a listing (issue #419).
    pub fn get_listing_expiry(env: Env, listing_id: u64) -> Option<u32> {
        read_listing_expiry(&env, listing_id)
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

    #[test]
    fn partial_fill_accounting_and_multi_buyer_completion() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let seller = Address::generate(&env);
        let buyer1 = Address::generate(&env);
        let buyer2 = Address::generate(&env);
        let fee_recipient = Address::generate(&env);
        let asset = setup_token(&env, &admin);
        let payment = setup_token(&env, &admin);

        let market_id = env.register_contract(None, MarketplaceContract);
        let market = MarketplaceContractClient::new(&env, &market_id);
        market.initialize(&admin, &500, &fee_recipient); // 5% fee

        mint(&env, &asset, &seller, 10);
        mint(&env, &payment, &buyer1, 1_000);
        mint(&env, &payment, &buyer2, 1_000);

        // Seller lists 10 units for 1,000 price (100 per unit).
        let id = market.create_listing(&seller, &asset, &0_u128, &10_i128, &1_000_i128, &payment);

        // Buyer 1 fills 4 units (proportional price = 400, fee = 20, proceeds = 380)
        let proceeds1 = market.buy_partial(
            &buyer1,
            &id,
            &4_i128,
            &Some(seller.clone()),
            &Some(400_i128),
            &None,
        );
        assert_eq!(proceeds1, 380);
        assert_eq!(balance(&env, &asset, &buyer1), 4);
        assert_eq!(balance(&env, &payment, &seller), 380);
        assert_eq!(balance(&env, &payment, &fee_recipient), 20);

        // Listing remains Active with 6 units and 600 asking price
        let listing_mid = market.get_listing(&id);
        assert_eq!(listing_mid.status, ListingStatus::Active);
        assert_eq!(listing_mid.amount, 6);
        assert_eq!(listing_mid.price, 600);

        // Buyer 2 fills remaining 6 units
        let proceeds2 = market.buy_partial(
            &buyer2,
            &id,
            &6_i128,
            &Some(seller.clone()),
            &None,
            &None,
        );
        assert_eq!(proceeds2, 570); // 600 - 30 fee
        assert_eq!(balance(&env, &asset, &buyer2), 6);
        assert_eq!(balance(&env, &payment, &seller), 950);
        assert_eq!(balance(&env, &payment, &fee_recipient), 50);

        let listing_final = market.get_listing(&id);
        assert_eq!(listing_final.status, ListingStatus::Sold);
        assert_eq!(listing_final.amount, 0);
        assert_eq!(listing_final.price, 0);
    }

    #[test]
    #[should_panic(expected = "listing owner mismatch: expected seller does not match current seller")]
    fn order_rejects_owner_mismatch() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let seller = Address::generate(&env);
        let impostor = Address::generate(&env);
        let buyer = Address::generate(&env);
        let asset = setup_token(&env, &admin);
        let payment = setup_token(&env, &admin);

        let market_id = env.register_contract(None, MarketplaceContract);
        let market = MarketplaceContractClient::new(&env, &market_id);
        market.initialize(&admin, &0, &admin);

        mint(&env, &asset, &seller, 1);
        mint(&env, &payment, &buyer, 100);

        let id = market.create_listing(&seller, &asset, &0_u128, &1_i128, &100_i128, &payment);

        market.execute_order(
            &buyer,
            &Order {
                listing_id: id,
                expected_seller: Some(impostor),
                fill_amount: None,
                max_price: None,
                expiry_ledger: None,
            },
        );
    }

    #[test]
    #[should_panic(expected = "order expired: expiry precedes current ledger")]
    fn order_rejects_expired_ledger() {
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
        mint(&env, &payment, &buyer, 100);

        let id = market.create_listing(&seller, &asset, &0_u128, &1_i128, &100_i128, &payment);

        let current = env.ledger().sequence();
        assert!(current > 0);

        market.execute_order(
            &buyer,
            &Order {
                listing_id: id,
                expected_seller: None,
                fill_amount: None,
                max_price: None,
                expiry_ledger: Some(current - 1),
            },
        );
    }

    #[test]
    #[should_panic(expected = "fill amount exceeds available listing amount")]
    fn partial_fill_rejects_excessive_amount() {
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

        mint(&env, &asset, &seller, 5);
        let id = market.create_listing(&seller, &asset, &0_u128, &5_i128, &100_i128, &payment);

        market.buy_partial(&buyer, &id, &6_i128, &None, &None, &None);
    }

    #[test]
    #[should_panic(expected = "fill price exceeds max price limit")]
    fn order_rejects_exceeded_max_price() {
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
        let id = market.create_listing(&seller, &asset, &0_u128, &1_i128, &100_i128, &payment);

        market.buy_partial(&buyer, &id, &1_i128, &None, &Some(99_i128), &None);
    }
}

//! End-to-end example integration for the marketplace + royalty splitter.
//!
//! This walks through a full secondary sale of a digital asset:
//!   1. a creator registers a royalty split for the asset,
//!   2. the owner lists the asset for sale (escrowed by the marketplace),
//!   3. a buyer purchases it (marketplace fee + seller proceeds settle),
//!   4. the royalty splitter pays the creator and platform their shares.
//!
//! Run with: `cargo test -p marketplace-contract --test integration`

use marketplace_contract::{ListingStatus, MarketplaceContract, MarketplaceContractClient};
use royalty_splitter::{Receiver, RoyaltySplitter, RoyaltySplitterClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::token::{StellarAssetClient, TokenClient};
use soroban_sdk::{Address, Env, Vec};

fn mint(env: &Env, token: &Address, to: &Address, amount: i128) {
    StellarAssetClient::new(env, token).mint(to, &amount);
}

fn balance(env: &Env, token: &Address, who: &Address) -> i128 {
    TokenClient::new(env, token).balance(who)
}

#[test]
fn secondary_sale_settles_marketplace_fee_and_royalties() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let seller = Address::generate(&env);
    let buyer = Address::generate(&env);
    let creator = Address::generate(&env);
    let platform = Address::generate(&env);

    let asset = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let payment = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();

    // Marketplace charges a 2.5% fee to the platform.
    let market_id = env.register_contract(None, MarketplaceContract);
    let market = MarketplaceContractClient::new(&env, &market_id);
    market.initialize(&admin, &250, &platform);

    // Royalty splitter caps total royalties at 10%.
    let splitter_id = env.register_contract(None, RoyaltySplitter);
    let splitter = RoyaltySplitterClient::new(&env, &splitter_id);
    splitter.initialize(&admin, &1_000);

    // Creator keeps 5%, the platform takes 2% on secondary sales.
    let mut royalty = Vec::new(&env);
    royalty.push_back(Receiver {
        recipient: creator.clone(),
        bps: 500,
    });
    royalty.push_back(Receiver {
        recipient: platform.clone(),
        bps: 200,
    });
    splitter.set_royalty(&admin, &asset, &1_u128, &royalty);

    // The seller deposits the asset into marketplace escrow.
    mint(&env, &asset, &seller, 1);
    let listing_id =
        market.create_listing(&seller, &asset, &1_u128, &1_i128, &1_000_i128, &payment);
    assert_eq!(balance(&env, &asset, &market_id), 1);

    // The buyer funds the purchase and settles it.
    mint(&env, &payment, &buyer, 2_000);
    let proceeds = market.buy(&buyer, &listing_id);

    // 2.5% marketplace fee leaves the seller 975.
    assert_eq!(proceeds, 975);
    assert_eq!(balance(&env, &payment, &seller), 975);
    assert_eq!(balance(&env, &payment, &platform), 25);
    assert_eq!(balance(&env, &asset, &buyer), 1);
    assert_eq!(balance(&env, &asset, &market_id), 0);
    assert_eq!(market.get_listing(&listing_id).status, ListingStatus::Sold);

    // Royalties are paid on the 1,000 sale price: 50 to creator, 20 to platform.
    let total = splitter.total_royalty(&asset, &1_u128, &1_000_i128);
    assert_eq!(total, 70);

    let payouts = splitter.distribute(&buyer, &asset, &1_u128, &1_000_i128, &payment);
    assert_eq!(payouts.get(0).unwrap().amount, 50);
    assert_eq!(payouts.get(1).unwrap().amount, 20);

    assert_eq!(balance(&env, &payment, &creator), 50);
    // Platform collected the 25 marketplace fee plus the 20 royalty share.
    assert_eq!(balance(&env, &payment, &platform), 45);
    // Buyer spent 1,000 on the sale and 70 on royalties.
    assert_eq!(balance(&env, &payment, &buyer), 930);
}

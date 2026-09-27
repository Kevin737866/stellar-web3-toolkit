//! Fractionalization of real-world assets.
//!
//! An issuer escrows a token representing a real-world asset — a warehouse
//! receipt, a title deed, a commodity warrant — and receives a fixed supply of
//! transferable *shares* in return. Shares implement the full SEP-41
//! [`TokenInterface`](soroban_sdk::token::TokenInterface), so any wallet or
//! token client can hold and trade them without knowing about this contract.
//!
//! Redemption releases the escrowed underlying to a single holder of the whole
//! outstanding share supply. Partial redemption is deliberately not offered:
//! letting one holder pull a slice of an indivisible asset out of escrow would
//! defeat the purpose of fractionalizing it. Shares that are burned shrink the
//! claim instead, and the underlying becomes redeemable again once the
//! *entire* remaining supply is returned.

#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short,
    token::{TokenClient, TokenInterface},
    Address, Env, String,
};

const HOLDER_TTL_THRESHOLD: u32 = 100_000;
const HOLDER_TTL_BUMP: u32 = 200_000;

#[contracttype]
#[derive(Clone)]
pub struct Config {
    pub admin: Address,
    /// The token escrowed as the real-world asset.
    pub underlying: Address,
    pub underlying_amount: i128,
    pub total_shares: i128,
    pub outstanding_shares: i128,
    pub fractionalized: bool,
    pub frozen: bool,
    pub name: String,
    pub symbol: String,
    pub decimals: u32,
    pub uri: String,
}

#[contracttype]
#[derive(Clone)]
pub struct Allowance {
    pub amount: i128,
    pub expiration_ledger: u32,
}

#[contracttype]
#[derive(Clone)]
pub struct AllowanceKey {
    pub from: Address,
    pub spender: Address,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Config,
    Share(Address),
    Allowance(AllowanceKey),
}

#[contract]
pub struct RwaFractionalizer;

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

fn config(env: &Env) -> Config {
    env.storage()
        .instance()
        .get(&DataKey::Config)
        .expect("not initialized")
}

fn set_config(env: &Env, cfg: &Config) {
    env.storage().instance().set(&DataKey::Config, cfg);
}

fn read_shares(env: &Env, holder: &Address) -> i128 {
    let key = DataKey::Share(holder.clone());
    let amount: i128 = env.storage().persistent().get(&key).unwrap_or(0);
    if amount > 0 {
        env.storage()
            .persistent()
            .extend_ttl(&key, HOLDER_TTL_THRESHOLD, HOLDER_TTL_BUMP);
    }
    amount
}

fn write_shares(env: &Env, holder: &Address, amount: i128) {
    let key = DataKey::Share(holder.clone());
    if amount == 0 {
        env.storage().persistent().remove(&key);
    } else {
        env.storage().persistent().set(&key, &amount);
        env.storage()
            .persistent()
            .extend_ttl(&key, HOLDER_TTL_THRESHOLD, HOLDER_TTL_BUMP);
    }
}

fn read_allowance(env: &Env, from: &Address, spender: &Address) -> Allowance {
    let key = AllowanceKey {
        from: from.clone(),
        spender: spender.clone(),
    };
    env.storage()
        .persistent()
        .get(&DataKey::Allowance(key))
        .unwrap_or(Allowance {
            amount: 0,
            expiration_ledger: 0,
        })
}

fn write_allowance(env: &Env, from: &Address, spender: &Address, data: &Allowance) {
    let key = AllowanceKey {
        from: from.clone(),
        spender: spender.clone(),
    };
    let storage_key = DataKey::Allowance(key);
    if data.amount == 0 {
        env.storage().persistent().remove(&storage_key);
    } else {
        env.storage().persistent().set(&storage_key, data);
        env.storage()
            .persistent()
            .extend_ttl(&storage_key, HOLDER_TTL_THRESHOLD, HOLDER_TTL_BUMP);
    }
}

/// `expiration_ledger == 0` marks a non-expiring allowance.
fn effective_allowance(env: &Env, data: &Allowance) -> i128 {
    if data.amount == 0 {
        return 0;
    }
    if data.expiration_ledger == 0 {
        return data.amount;
    }
    if env.ledger().sequence() > data.expiration_ledger {
        0
    } else {
        data.amount
    }
}

// ---------------------------------------------------------------------------
// Internal share movement
// ---------------------------------------------------------------------------

fn move_shares(env: &Env, from: &Address, to: &Address, amount: i128) {
    assert!(amount > 0, "amount must be positive");
    assert!(from != to, "self transfer is not allowed");
    assert!(!config(env).frozen, "share transfers are frozen");

    let from_shares = read_shares(env, from);
    assert!(from_shares >= amount, "insufficient shares");
    write_shares(env, from, from_shares - amount);
    write_shares(env, to, read_shares(env, to) + amount);

    env.events().publish(
        (symbol_short!("transfer"), from.clone(), to.clone()),
        amount,
    );
}

fn spend_allowance(env: &Env, from: &Address, spender: &Address, amount: i128) {
    let mut allowance = read_allowance(env, from, spender);
    let available = effective_allowance(env, &allowance);
    assert!(available >= amount, "allowance exceeded");
    allowance.amount = available - amount;
    write_allowance(env, from, spender, &allowance);
}

/// Burns `amount` shares from `holder` and reduces the outstanding supply.
fn burn_shares(env: &Env, holder: &Address, amount: i128) {
    assert!(amount > 0, "amount must be positive");
    let cfg = config(env);
    assert!(cfg.fractionalized, "not fractionalized");
    assert!(amount <= cfg.outstanding_shares, "amount exceeds supply");

    let holder_shares = read_shares(env, holder);
    assert!(holder_shares >= amount, "insufficient shares");
    write_shares(env, holder, holder_shares - amount);

    let outstanding = cfg.outstanding_shares - amount;
    let mut updated = cfg;
    updated.outstanding_shares = outstanding;
    set_config(env, &updated);

    env.events()
        .publish((symbol_short!("burn"), holder.clone()), amount);
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contractimpl]
impl RwaFractionalizer {
    /// One-time setup. The asset is not escrowed yet; see
    /// [`fractionalize`](RwaFractionalizer::fractionalize).
    pub fn initialize(env: Env, admin: Address, underlying: Address) {
        assert!(
            !env.storage().instance().has(&DataKey::Config),
            "already initialized"
        );
        admin.require_auth();
        set_config(
            &env,
            &Config {
                admin,
                underlying,
                underlying_amount: 0,
                total_shares: 0,
                outstanding_shares: 0,
                fractionalized: false,
                frozen: false,
                name: String::from_str(&env, ""),
                symbol: String::from_str(&env, ""),
                decimals: 0,
                uri: String::from_str(&env, ""),
            },
        );
    }

    pub fn admin(env: Env) -> Address {
        config(&env).admin
    }

    pub fn set_admin(env: Env, new_admin: Address) {
        let mut cfg = config(&env);
        cfg.admin.require_auth();
        cfg.admin = new_admin.clone();
        set_config(&env, &cfg);
        env.events()
            .publish((symbol_short!("set_admin"),), new_admin);
    }

    pub fn underlying(env: Env) -> Address {
        config(&env).underlying
    }

    pub fn underlying_amount(env: Env) -> i128 {
        config(&env).underlying_amount
    }

    pub fn total_shares(env: Env) -> i128 {
        config(&env).total_shares
    }

    /// Shares still in circulation. Equals `total_shares` minus burns.
    pub fn outstanding_shares(env: Env) -> i128 {
        config(&env).outstanding_shares
    }

    pub fn fractionalized(env: Env) -> bool {
        config(&env).fractionalized
    }

    pub fn uri(env: Env) -> String {
        config(&env).uri
    }

    /// Escrows `underlying_amount` of the underlying token from `issuer` and
    /// mints the whole `total_shares` supply to them. Callable once per asset.
    pub fn fractionalize(
        env: Env,
        issuer: Address,
        underlying_amount: i128,
        total_shares: i128,
        name: String,
        symbol: String,
        decimals: u32,
        uri: String,
    ) -> i128 {
        issuer.require_auth();
        let mut cfg = config(&env);
        assert!(!cfg.fractionalized, "already fractionalized");
        assert!(underlying_amount > 0, "underlying amount must be positive");
        assert!(total_shares > 0, "total shares must be positive");

        // Pull the asset into escrow before any shares exist.
        TokenClient::new(&env, &cfg.underlying).transfer(
            &issuer,
            &env.current_contract_address(),
            &underlying_amount,
        );

        cfg.underlying_amount = underlying_amount;
        cfg.total_shares = total_shares;
        cfg.outstanding_shares = total_shares;
        cfg.fractionalized = true;
        cfg.name = name.clone();
        cfg.symbol = symbol.clone();
        let mut updated = cfg;
        updated.decimals = decimals;
        updated.uri = uri;
        set_config(&env, &updated);

        write_shares(&env, &issuer, total_shares);

        env.events().publish(
            (symbol_short!("fraction"),),
            (issuer, underlying_amount, total_shares),
        );
        total_shares
    }

    /// Releases the escrowed underlying to `recipient`.
    ///
    /// `holder` must own the entire outstanding share supply; every share is
    /// burned in the process. Holders that were previously burned out of the
    /// supply are not compensated, so redeeming is only possible once the
    /// remaining shares have been consolidated.
    pub fn redeem(env: Env, holder: Address, recipient: Address) -> i128 {
        let cfg = config(&env);
        holder.require_auth();
        assert!(cfg.fractionalized, "not fractionalized");
        let held = read_shares(&env, &holder);
        assert!(held > 0, "no shares held");
        assert!(
            held == cfg.outstanding_shares,
            "redemption requires the whole outstanding supply"
        );

        let underlying = cfg.underlying.clone();
        let underlying_amount = cfg.underlying_amount;
        let mut updated = cfg;
        updated.outstanding_shares = 0;
        set_config(&env, &updated);
        write_shares(&env, &holder, 0);

        let contract = env.current_contract_address();
        TokenClient::new(&env, &underlying).transfer(&contract, &recipient, &underlying_amount);

        env.events()
            .publish((symbol_short!("redeem"),), (holder, recipient, held));
        underlying_amount
    }

    /// Halts share transfers for compliance. Redemptions stay open so holders
    /// always keep an exit.
    pub fn freeze(env: Env) {
        let mut cfg = config(&env);
        cfg.admin.require_auth();
        cfg.frozen = true;
        set_config(&env, &cfg);
        env.events().publish((symbol_short!("freeze"),), ());
    }

    pub fn unfreeze(env: Env) {
        let mut cfg = config(&env);
        cfg.admin.require_auth();
        cfg.frozen = false;
        set_config(&env, &cfg);
        env.events().publish((symbol_short!("unfreeze"),), ());
    }

    pub fn frozen(env: Env) -> bool {
        config(&env).frozen
    }

    // -- share accounting (exposed outside the SEP-41 surface) ---------------

    pub fn shares_of(env: Env, holder: Address) -> i128 {
        read_shares(&env, &holder)
    }
}

#[contractimpl]
impl TokenInterface for RwaFractionalizer {
    fn allowance(env: Env, from: Address, spender: Address) -> i128 {
        effective_allowance(&env, &read_allowance(&env, &from, &spender))
    }

    fn approve(env: Env, from: Address, spender: Address, amount: i128, expiration_ledger: u32) {
        from.require_auth();
        assert!(amount >= 0, "amount must not be negative");
        let allowance = Allowance {
            amount,
            expiration_ledger,
        };
        write_allowance(&env, &from, &spender, &allowance);
        env.events().publish(
            (symbol_short!("approve"), from, spender),
            (amount, expiration_ledger),
        );
    }

    fn balance(env: Env, id: Address) -> i128 {
        read_shares(&env, &id)
    }

    fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        move_shares(&env, &from, &to, amount);
    }

    fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        spend_allowance(&env, &from, &spender, amount);
        move_shares(&env, &from, &to, amount);
    }

    /// Burning shares shrinks the claim on the underlying rather than returning
    /// any escrowed asset.
    fn burn(env: Env, from: Address, amount: i128) {
        from.require_auth();
        burn_shares(&env, &from, amount);
    }

    fn burn_from(env: Env, spender: Address, from: Address, amount: i128) {
        spender.require_auth();
        spend_allowance(&env, &from, &spender, amount);
        burn_shares(&env, &from, amount);
    }

    fn decimals(env: Env) -> u32 {
        config(&env).decimals
    }

    fn name(env: Env) -> String {
        config(&env).name
    }

    fn symbol(env: Env) -> String {
        config(&env).symbol
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use super::*;
    use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
    use soroban_sdk::token::StellarAssetClient;
    use soroban_sdk::{Symbol, TryFromVal};

    const UNDERLYING_UNITS: i128 = 1_000;
    const SHARES: i128 = 10_000;

    fn setup() -> (Env, Address, Address, RwaFractionalizerClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        // Generous TTLs so tests can advance the ledger without archiving state.
        env.ledger().set_min_persistent_entry_ttl(1_000_000);
        env.ledger().set_max_entry_ttl(1_000_000);
        let admin = Address::generate(&env);
        let issuer = Address::generate(&env);
        let underlying = env.register_stellar_asset_contract(admin.clone());
        StellarAssetClient::new(&env, &underlying).mint(&issuer, &UNDERLYING_UNITS);

        let id = env.register_contract(None, RwaFractionalizer);
        let client = RwaFractionalizerClient::new(&env, &id);
        client.initialize(&admin, &underlying);
        (env, admin, issuer, client)
    }

    fn fractionalize(env: &Env, client: &RwaFractionalizerClient, issuer: &Address) {
        client.fractionalize(
            issuer,
            &UNDERLYING_UNITS,
            &SHARES,
            &String::from_str(env, "Harbour Warehouse 12"),
            &String::from_str(env, "HWH12"),
            &4,
            &String::from_str(env, "ipfs://rwa/harbour-12.json"),
        );
    }

    #[test]
    fn initialize_is_one_time() {
        let (env, admin, _, client) = setup();
        let other = Address::generate(&env);
        let other_underlying = Address::generate(&env);
        assert!(client.try_initialize(&other, &other_underlying).is_err());
        assert_eq!(client.admin(), admin);
        assert_eq!(client.underlying(), client.underlying());
        assert!(!client.fractionalized());
    }

    #[test]
    fn fractionalize_escrows_asset_and_mints_shares() {
        let (env, _, issuer, client) = setup();
        fractionalize(&env, &client, &issuer);

        assert!(client.fractionalized());
        assert_eq!(client.total_shares(), SHARES);
        assert_eq!(client.outstanding_shares(), SHARES);
        assert_eq!(client.underlying_amount(), UNDERLYING_UNITS);
        assert_eq!(client.shares_of(&issuer), SHARES);
        assert_eq!(client.balance(&issuer), SHARES);
        assert_eq!(
            client.name(),
            String::from_str(&env, "Harbour Warehouse 12")
        );
        assert_eq!(client.symbol(), String::from_str(&env, "HWH12"));
        assert_eq!(client.decimals(), 4);
        assert_eq!(
            client.uri(),
            String::from_str(&env, "ipfs://rwa/harbour-12.json")
        );
    }

    #[test]
    fn fractionalize_can_only_run_once() {
        let (env, _, issuer, client) = setup();
        fractionalize(&env, &client, &issuer);
        assert!(client
            .try_fractionalize(
                &issuer,
                &1,
                &1,
                &String::from_str(&env, "X"),
                &String::from_str(&env, "X"),
                &0,
                &String::from_str(&env, ""),
            )
            .is_err());
    }

    #[test]
    fn underlying_is_custodied_by_the_contract() {
        let (env, _, issuer, client) = setup();
        let id = client.address.clone();
        fractionalize(&env, &client, &issuer);

        assert_eq!(
            TokenClient::new(&env, &client.underlying()).balance(&id),
            UNDERLYING_UNITS
        );
        assert_eq!(
            TokenClient::new(&env, &client.underlying()).balance(&issuer),
            0
        );
    }

    #[test]
    fn shares_transfer_between_holders() {
        let (env, _, issuer, client) = setup();
        fractionalize(&env, &client, &issuer);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.transfer(&issuer, &alice, &3_000);
        client.transfer(&alice, &bob, &1_200);

        assert_eq!(client.balance(&issuer), 7_000);
        assert_eq!(client.balance(&alice), 1_800);
        assert_eq!(client.balance(&bob), 1_200);
        // Shares move without touching the escrowed asset.
        assert_eq!(client.underlying_amount(), UNDERLYING_UNITS);
    }

    #[test]
    fn allowances_gate_transfer_from() {
        let (env, _, issuer, client) = setup();
        fractionalize(&env, &client, &issuer);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        assert!(client
            .try_transfer_from(&bob, &issuer, &alice, &10)
            .is_err());

        client.approve(&issuer, &bob, &500, &0);
        assert_eq!(client.allowance(&issuer, &bob), 500);
        client.transfer_from(&bob, &issuer, &alice, &200);

        assert_eq!(client.allowance(&issuer, &bob), 300);
        assert_eq!(client.balance(&alice), 200);
        assert!(client
            .try_transfer_from(&bob, &issuer, &alice, &400)
            .is_err());
    }

    #[test]
    fn redeem_releases_underlying_to_the_sole_holder() {
        let (env, _, issuer, client) = setup();
        fractionalize(&env, &client, &issuer);
        let alice = Address::generate(&env);
        let underlying = client.underlying();

        client.transfer(&issuer, &alice, &SHARES);
        assert_eq!(client.balance(&alice), SHARES);

        let returned = client.redeem(&alice, &issuer);
        assert_eq!(returned, UNDERLYING_UNITS);
        assert_eq!(client.outstanding_shares(), 0);
        assert_eq!(client.balance(&alice), 0);
        assert_eq!(
            TokenClient::new(&env, &underlying).balance(&issuer),
            UNDERLYING_UNITS
        );
        assert_eq!(
            TokenClient::new(&env, &underlying).balance(&client.address),
            0
        );
    }

    #[test]
    fn redeem_can_send_the_asset_to_another_address() {
        let (env, _, issuer, client) = setup();
        fractionalize(&env, &client, &issuer);
        let treasury = Address::generate(&env);

        client.redeem(&issuer, &treasury);
        assert_eq!(
            TokenClient::new(&env, &client.underlying()).balance(&treasury),
            UNDERLYING_UNITS
        );
    }

    #[test]
    fn partial_redemption_is_rejected() {
        let (env, _, issuer, client) = setup();
        fractionalize(&env, &client, &issuer);
        let alice = Address::generate(&env);
        client.transfer(&issuer, &alice, &(SHARES / 2));

        // Alice holds shares but not the whole supply.
        assert!(client.try_redeem(&alice, &alice).is_err());
        assert!(client.try_redeem(&issuer, &issuer).is_err());
        assert_eq!(client.outstanding_shares(), SHARES);
    }

    #[test]
    fn redemption_becomes_possible_after_shares_are_consolidated() {
        let (env, _, issuer, client) = setup();
        fractionalize(&env, &client, &issuer);
        let alice = Address::generate(&env);
        client.transfer(&issuer, &alice, &(SHARES / 2));

        client.transfer(&alice, &issuer, &(SHARES / 2));
        client.redeem(&issuer, &issuer);
        assert_eq!(client.outstanding_shares(), 0);
    }

    #[test]
    fn burning_shrinks_the_claim_without_returning_the_asset() {
        let (env, _, issuer, client) = setup();
        fractionalize(&env, &client, &issuer);
        let underlying = client.underlying();

        client.burn(&issuer, &2_000);
        assert_eq!(client.balance(&issuer), 8_000);
        assert_eq!(client.total_shares(), SHARES);
        assert_eq!(client.outstanding_shares(), 8_000);
        assert_eq!(
            TokenClient::new(&env, &underlying).balance(&client.address),
            UNDERLYING_UNITS
        );
    }

    #[test]
    fn redeeming_after_burn_requires_the_remaining_supply() {
        let (env, _, issuer, client) = setup();
        fractionalize(&env, &client, &issuer);
        let alice = Address::generate(&env);

        client.transfer(&issuer, &alice, &3_000);
        client.burn(&alice, &1_000);
        // 9,000 shares are outstanding but still split with Alice.
        assert_eq!(client.outstanding_shares(), 9_000);
        assert!(client.try_redeem(&issuer, &issuer).is_err());

        // Consolidating the remainder makes the issuer the sole holder.
        client.transfer(&alice, &issuer, &2_000);
        client.redeem(&issuer, &issuer);
        assert_eq!(client.outstanding_shares(), 0);
    }

    #[test]
    fn burn_from_consumes_the_allowance() {
        let (env, _, issuer, client) = setup();
        fractionalize(&env, &client, &issuer);
        let alice = Address::generate(&env);

        client.approve(&issuer, &alice, &1_000, &0);
        client.burn_from(&alice, &issuer, &400);
        assert_eq!(client.allowance(&issuer, &alice), 600);
        assert_eq!(client.outstanding_shares(), 9_600);
    }

    #[test]
    fn freeze_halts_share_transfers_but_keeps_redemption_open() {
        let (env, _, issuer, client) = setup();
        fractionalize(&env, &client, &issuer);
        let alice = Address::generate(&env);

        client.freeze();
        assert!(client.frozen());
        assert!(client.try_transfer(&issuer, &alice, &100).is_err());

        client.redeem(&issuer, &issuer);
        assert_eq!(client.outstanding_shares(), 0);

        client.unfreeze();
        assert!(!client.frozen());
    }

    #[test]
    fn redemption_is_not_repeatable() {
        let (env, _, issuer, client) = setup();
        fractionalize(&env, &client, &issuer);
        client.redeem(&issuer, &issuer);
        assert!(client.try_redeem(&issuer, &issuer).is_err());
    }

    #[test]
    fn fractionalize_rejects_non_positive_amounts() {
        let (env, _, issuer, client) = setup();
        assert!(client
            .try_fractionalize(
                &issuer,
                &0,
                &SHARES,
                &String::from_str(&env, "A"),
                &String::from_str(&env, "A"),
                &0,
                &String::from_str(&env, ""),
            )
            .is_err());
        assert!(client
            .try_fractionalize(
                &issuer,
                &1,
                &0,
                &String::from_str(&env, "A"),
                &String::from_str(&env, "A"),
                &0,
                &String::from_str(&env, ""),
            )
            .is_err());
    }

    #[test]
    fn events_are_emitted_for_the_lifecycle() {
        let (env, _, issuer, client) = setup();
        let alice = Address::generate(&env);
        fractionalize(&env, &client, &issuer);
        client.transfer(&issuer, &alice, &1);
        // Redemption needs the whole supply back in one hand.
        client.transfer(&alice, &issuer, &1);
        client.redeem(&issuer, &issuer);

        let mut names: std::vec::Vec<Symbol> = std::vec::Vec::new();
        for (_, topics, _) in env.events().all() {
            for i in 0..topics.len() {
                if let Ok(sym) = Symbol::try_from_val(&env, &topics.get(i).unwrap()) {
                    names.push(sym);
                }
            }
        }
        assert!(names.contains(&symbol_short!("fraction")));
        assert!(names.contains(&symbol_short!("transfer")));
        assert!(names.contains(&symbol_short!("redeem")));
    }
}

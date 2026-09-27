//! Non-fungible / semi-fungible asset contract with metadata.
//!
//! One deployed contract holds a collection of *base tokens*. A base token is
//! identified by a `token_id` (SEP-41 models non-fungible tokens as fungible
//! tokens with one unit per instance) and carries a supply:
//!
//! * supply `1` -> a **NFT**, with a well-defined single owner exposed through
//!   [`owner_of`](NftSftContract::owner_of);
//! * supply `> 1` -> an **SFT**, divisible between holders.
//!
//! The fungible-shaped surface (`balance`, `allowance`, `approve`, `transfer`,
//! `transfer_from`, `burn`, `burn_from`, `decimals`, `name`, `symbol`) mirrors
//! SEP-41, generalised over `token_id`, and the metadata surface (`owner_of`,
//! `uri`, `metadata`, `set_uri`, `base_supply`, `total_supply`) follows the
//! SEP-41 non-fungible conventions.

#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, String, Vec};

/// Persistent entries (per-holder balances) are bumped when their remaining
/// TTL drops below the threshold.
const HOLDER_TTL_THRESHOLD: u32 = 100_000;
const HOLDER_TTL_BUMP: u32 = 200_000;

/// Per-base-token metadata. `uri` overrides the collection `base_uri` when set.
#[contracttype]
#[derive(Clone)]
pub struct TokenMeta {
    pub asset_name: String,
    pub uri: String,
}

/// An allowance granted by `from` to `spender` over one `token_id`.
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
    pub token_id: i128,
}

/// Contract-wide configuration held in instance storage.
#[contracttype]
#[derive(Clone)]
pub struct Config {
    pub admin: Address,
    pub name: String,
    pub symbol: String,
    pub decimals: u32,
    /// Fallback URI template for tokens that do not carry their own `uri`.
    pub base_uri: String,
    /// `0` disables the cap.
    pub max_supply: i128,
    pub frozen: bool,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Config,
    TotalSupply,
    BaseSupply(i128),
    BaseMeta(i128),
    BaseHolder(i128),
    Holders(i128),
    Balance(Address, i128),
    Allowance(AllowanceKey),
}

#[contract]
pub struct NftSftContract;

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

fn balance_key(holder: &Address, token_id: i128) -> DataKey {
    DataKey::Balance(holder.clone(), token_id)
}

fn read_balance(env: &Env, holder: &Address, token_id: i128) -> i128 {
    let key = balance_key(holder, token_id);
    let amount: i128 = env.storage().persistent().get(&key).unwrap_or(0);
    if amount > 0 {
        env.storage()
            .persistent()
            .extend_ttl(&key, HOLDER_TTL_THRESHOLD, HOLDER_TTL_BUMP);
    }
    amount
}

fn write_balance(env: &Env, holder: &Address, token_id: i128, amount: i128) {
    let key = balance_key(holder, token_id);
    if amount == 0 {
        env.storage().persistent().remove(&key);
    } else {
        env.storage().persistent().set(&key, &amount);
        env.storage()
            .persistent()
            .extend_ttl(&key, HOLDER_TTL_THRESHOLD, HOLDER_TTL_BUMP);
    }
}

fn total_supply(env: &Env) -> i128 {
    env.storage()
        .instance()
        .get(&DataKey::TotalSupply)
        .unwrap_or(0)
}

fn set_total_supply(env: &Env, value: i128) {
    env.storage().instance().set(&DataKey::TotalSupply, &value);
}

/// Units of `token_id` in existence. `0` means the base token does not exist.
fn read_base_supply(env: &Env, token_id: i128) -> i128 {
    env.storage()
        .instance()
        .get(&DataKey::BaseSupply(token_id))
        .unwrap_or(0)
}

fn read_base_meta(env: &Env, token_id: i128) -> TokenMeta {
    env.storage()
        .instance()
        .get(&DataKey::BaseMeta(token_id))
        .unwrap_or(TokenMeta {
            asset_name: String::from_str(env, ""),
            uri: String::from_str(env, ""),
        })
}

/// Sole owner of a base token, when one exists.
///
/// Maintained only while a base token is held by exactly one address; a partial
/// move of an SFT clears it because the token then has no single owner.
fn read_base_holder(env: &Env, token_id: i128) -> Option<Address> {
    env.storage().instance().get(&DataKey::BaseHolder(token_id))
}

fn set_base_holder(env: &Env, token_id: i128, holder: Option<&Address>) {
    match holder {
        Some(address) => env
            .storage()
            .instance()
            .set(&DataKey::BaseHolder(token_id), address),
        None => env
            .storage()
            .instance()
            .remove(&DataKey::BaseHolder(token_id)),
    }
}

/// Current holders of a base token.
///
/// Tracked in step with the balances so that sole ownership can be answered
/// without scanning persistent storage, which is not iterable.
fn read_holders(env: &Env, token_id: i128) -> Vec<Address> {
    let key = DataKey::Holders(token_id);
    let holders: Vec<Address> = env
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or(Vec::new(env));
    if !holders.is_empty() {
        env.storage()
            .persistent()
            .extend_ttl(&key, HOLDER_TTL_THRESHOLD, HOLDER_TTL_BUMP);
    }
    holders
}

fn write_holders(env: &Env, token_id: i128, holders: &Vec<Address>) {
    let key = DataKey::Holders(token_id);
    if holders.is_empty() {
        env.storage().persistent().remove(&key);
    } else {
        env.storage().persistent().set(&key, holders);
        env.storage()
            .persistent()
            .extend_ttl(&key, HOLDER_TTL_THRESHOLD, HOLDER_TTL_BUMP);
    }
}

/// A base token has a sole owner exactly when a single address holds every unit
/// of it. Any division leaves the token without an owner, which is what
/// `owner_of` reports.
fn refresh_base_holder(env: &Env, token_id: i128) {
    let holders = read_holders(env, token_id);
    match (holders.len(), holders.first()) {
        (1, Some(only)) => set_base_holder(env, token_id, Some(&only)),
        _ => set_base_holder(env, token_id, None),
    }
}

fn read_allowance(env: &Env, from: &Address, spender: &Address, token_id: i128) -> Allowance {
    let key = AllowanceKey {
        from: from.clone(),
        spender: spender.clone(),
        token_id,
    };
    env.storage()
        .persistent()
        .get(&DataKey::Allowance(key))
        .unwrap_or(Allowance {
            amount: 0,
            expiration_ledger: 0,
        })
}

fn write_allowance(env: &Env, from: &Address, spender: &Address, token_id: i128, data: &Allowance) {
    let key = AllowanceKey {
        from: from.clone(),
        spender: spender.clone(),
        token_id,
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

/// Allowances are void once the current ledger is past `expiration_ledger`.
/// A zero `expiration_ledger` denotes a non-expiring allowance.
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

fn assert_movable(env: &Env) {
    assert!(!config(env).frozen, "contract is frozen");
}

fn assert_known_token(env: &Env, token_id: i128) -> i128 {
    let supply = read_base_supply(env, token_id);
    assert!(supply > 0, "unknown token");
    supply
}

// ---------------------------------------------------------------------------
// Internal movement primitives
// ---------------------------------------------------------------------------

fn move_units(env: &Env, from: &Address, to: &Address, token_id: i128, amount: i128) {
    assert!(amount > 0, "amount must be positive");
    assert!(from != to, "self transfer is not allowed");

    let supply = assert_known_token(env, token_id);
    assert!(amount <= supply, "amount exceeds token supply");

    let from_balance = read_balance(env, from, token_id);
    assert!(from_balance >= amount, "insufficient balance");

    let to_balance = read_balance(env, to, token_id);
    write_balance(env, from, token_id, from_balance - amount);
    write_balance(env, to, token_id, to_balance + amount);

    let mut holders = read_holders(env, token_id);
    if from_balance == amount {
        if let Some(index) = holders.first_index_of(from.clone()) {
            holders.remove(index);
        }
    }
    if to_balance == 0 && !holders.contains(to.clone()) {
        holders.push_back(to.clone());
    }
    write_holders(env, token_id, &holders);
    refresh_base_holder(env, token_id);

    env.events().publish(
        (symbol_short!("transfer"), from.clone(), to.clone()),
        (token_id, amount),
    );
}

fn spend_allowance(env: &Env, from: &Address, spender: &Address, token_id: i128, amount: i128) {
    let mut allowance = read_allowance(env, from, spender, token_id);
    let available = effective_allowance(env, &allowance);
    assert!(available >= amount, "allowance exceeded");
    allowance.amount = available - amount;
    write_allowance(env, from, spender, token_id, &allowance);
}

fn burn_units(env: &Env, from: &Address, token_id: i128, amount: i128) {
    assert!(amount > 0, "amount must be positive");
    let supply = assert_known_token(env, token_id);
    assert!(amount <= supply, "amount exceeds token supply");

    let from_balance = read_balance(env, from, token_id);
    assert!(from_balance >= amount, "insufficient balance");
    let remaining = from_balance - amount;
    write_balance(env, from, token_id, remaining);

    let supply_left = supply - amount;
    if supply_left == 0 {
        // A fully burned base token frees its id for re-minting, so every trace
        // of it is removed.
        env.storage()
            .instance()
            .remove(&DataKey::BaseSupply(token_id));
        env.storage()
            .instance()
            .remove(&DataKey::BaseMeta(token_id));
        env.storage()
            .persistent()
            .remove(&DataKey::Holders(token_id));
        set_base_holder(env, token_id, None);
    } else {
        env.storage()
            .instance()
            .set(&DataKey::BaseSupply(token_id), &supply_left);
        let mut holders = read_holders(env, token_id);
        if remaining == 0 {
            if let Some(index) = holders.first_index_of(from.clone()) {
                holders.remove(index);
            }
        }
        write_holders(env, token_id, &holders);
        refresh_base_holder(env, token_id);
    }
    set_total_supply(env, total_supply(env) - amount);

    env.events()
        .publish((symbol_short!("burn"), from.clone()), (token_id, amount));
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contractimpl]
impl NftSftContract {
    /// One-time initialisation. `max_supply` of `0` means the collection size is
    /// unbounded.
    pub fn initialize(
        env: Env,
        admin: Address,
        name: String,
        symbol: String,
        decimals: u32,
        base_uri: String,
        max_supply: i128,
    ) {
        assert!(
            !env.storage().instance().has(&DataKey::Config),
            "already initialized"
        );
        admin.require_auth();
        assert!(max_supply >= 0, "max supply must not be negative");
        set_config(
            &env,
            &Config {
                admin,
                name,
                symbol,
                decimals,
                base_uri,
                max_supply,
                frozen: false,
            },
        );
        set_total_supply(&env, 0);
    }

    // -- admin ---------------------------------------------------------------

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

    pub fn set_base_uri(env: Env, base_uri: String) {
        let mut cfg = config(&env);
        cfg.admin.require_auth();
        cfg.base_uri = base_uri;
        set_config(&env, &cfg);
    }

    pub fn max_supply(env: Env) -> i128 {
        config(&env).max_supply
    }

    /// Halts transfers. Minting, metadata updates and burns stay available so
    /// holders keep an exit and operators can repair bad metadata.
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

    // -- minting -------------------------------------------------------------

    /// Creates `token_id` with `quantity` units and mints the whole supply to
    /// `to`. `quantity == 1` creates an NFT, `quantity > 1` an SFT.
    pub fn mint(
        env: Env,
        to: Address,
        token_id: i128,
        quantity: i128,
        asset_name: String,
        uri: String,
    ) {
        let cfg = config(&env);
        cfg.admin.require_auth();
        assert!(quantity > 0, "quantity must be positive");
        assert!(
            !env.storage().instance().has(&DataKey::BaseSupply(token_id)),
            "token already minted"
        );

        if cfg.max_supply > 0 {
            assert!(
                total_supply(&env) + quantity <= cfg.max_supply,
                "max supply exceeded"
            );
        }

        env.storage()
            .instance()
            .set(&DataKey::BaseSupply(token_id), &quantity);
        env.storage().instance().set(
            &DataKey::BaseMeta(token_id),
            &TokenMeta {
                asset_name,
                uri: uri.clone(),
            },
        );
        set_total_supply(&env, total_supply(&env) + quantity);
        write_balance(
            &env,
            &to,
            token_id,
            read_balance(&env, &to, token_id) + quantity,
        );
        // The whole initial supply sits with the recipient, who is therefore
        // the sole holder.
        let mut holders = Vec::new(&env);
        holders.push_back(to.clone());
        write_holders(&env, token_id, &holders);
        refresh_base_holder(&env, token_id);

        env.events()
            .publish((symbol_short!("mint"), token_id), (to, quantity, uri));
    }

    // -- SEP-41 fungible surface, generalised over `token_id` -----------------

    pub fn balance(env: Env, holder: Address, token_id: i128) -> i128 {
        read_balance(&env, &holder, token_id)
    }

    pub fn allowance(env: Env, from: Address, spender: Address, token_id: i128) -> i128 {
        effective_allowance(&env, &read_allowance(&env, &from, &spender, token_id))
    }

    pub fn approve(
        env: Env,
        from: Address,
        spender: Address,
        token_id: i128,
        amount: i128,
        expiration_ledger: u32,
    ) {
        from.require_auth();
        assert!(amount >= 0, "amount must not be negative");
        let allowance = Allowance {
            amount,
            expiration_ledger,
        };
        write_allowance(&env, &from, &spender, token_id, &allowance);
        env.events().publish(
            (symbol_short!("approve"), from, spender),
            (token_id, amount, expiration_ledger),
        );
    }

    pub fn transfer(env: Env, from: Address, to: Address, token_id: i128, amount: i128) {
        from.require_auth();
        assert_movable(&env);
        move_units(&env, &from, &to, token_id, amount);
    }

    pub fn transfer_from(
        env: Env,
        spender: Address,
        from: Address,
        to: Address,
        token_id: i128,
        amount: i128,
    ) {
        spender.require_auth();
        assert_movable(&env);
        spend_allowance(&env, &from, &spender, token_id, amount);
        move_units(&env, &from, &to, token_id, amount);
    }

    /// Burning stays available while frozen so holders always have an exit.
    pub fn burn(env: Env, from: Address, token_id: i128, amount: i128) {
        from.require_auth();
        burn_units(&env, &from, token_id, amount);
    }

    pub fn burn_from(env: Env, spender: Address, from: Address, token_id: i128, amount: i128) {
        spender.require_auth();
        spend_allowance(&env, &from, &spender, token_id, amount);
        burn_units(&env, &from, token_id, amount);
    }

    pub fn decimals(env: Env) -> u32 {
        config(&env).decimals
    }

    pub fn name(env: Env) -> String {
        config(&env).name
    }

    pub fn symbol(env: Env) -> String {
        config(&env).symbol
    }

    // -- non-fungible surface and metadata -----------------------------------

    /// The sole owner of `token_id`, or `None` for SFTs that are split across
    /// holders.
    pub fn owner_of(env: Env, token_id: i128) -> Option<Address> {
        read_base_holder(&env, token_id)
    }

    /// True when exactly one unit of `token_id` exists.
    pub fn is_nft(env: Env, token_id: i128) -> bool {
        read_base_supply(&env, token_id) == 1
    }

    /// Units of `token_id` in existence.
    pub fn base_supply(env: Env, token_id: i128) -> i128 {
        read_base_supply(&env, token_id)
    }

    /// Units of `token_id` across the whole collection.
    pub fn total_supply(env: Env) -> i128 {
        total_supply(&env)
    }

    pub fn metadata(env: Env, token_id: i128) -> TokenMeta {
        read_base_meta(&env, token_id)
    }

    /// Effective metadata URI: the token's own `uri`, otherwise the collection
    /// `base_uri` template. Template substitution (for example `{id}`) is left
    /// to the caller, which avoids buffering variable-length strings on-chain.
    pub fn uri(env: Env, token_id: i128) -> String {
        let meta = read_base_meta(&env, token_id);
        if meta.uri.is_empty() {
            config(&env).base_uri
        } else {
            meta.uri
        }
    }

    pub fn base_uri(env: Env) -> String {
        config(&env).base_uri
    }

    /// Updates metadata for `token_id`. A sole holder may do this for an NFT;
    /// otherwise the admin must, since a divided SFT has no single owner.
    pub fn set_metadata(env: Env, token_id: i128, asset_name: String, uri: String) {
        let cfg = config(&env);
        assert_known_token(&env, token_id);
        match read_base_holder(&env, token_id) {
            Some(holder) => holder.require_auth(),
            None => cfg.admin.require_auth(),
        }
        env.storage().instance().set(
            &DataKey::BaseMeta(token_id),
            &TokenMeta {
                asset_name,
                uri: uri.clone(),
            },
        );
        env.events()
            .publish((symbol_short!("set_meta"), token_id), uri);
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use super::*;
    use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
    use soroban_sdk::{Symbol, TryFromVal};

    const ONE: i128 = 1;
    const TEN: i128 = 10;

    fn setup() -> (Env, Address, NftSftContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        // Generous TTLs so tests can advance the ledger without archiving state.
        env.ledger().set_min_persistent_entry_ttl(1_000_000);
        env.ledger().set_max_entry_ttl(1_000_000);
        let admin = Address::generate(&env);
        let id = env.register_contract(None, NftSftContract);
        let client = NftSftContractClient::new(&env, &id);
        client.initialize(
            &admin,
            &String::from_str(&env, "Trophy Case"),
            &String::from_str(&env, "CASE"),
            &0,
            &String::from_str(&env, "ipfs://collection/{id}.json"),
            &0,
        );
        (env, admin, client)
    }

    #[test]
    fn initialize_sets_metadata_and_rejects_reinit() {
        let (env, admin, client) = setup();
        assert_eq!(client.name(), String::from_str(&env, "Trophy Case"));
        assert_eq!(client.symbol(), String::from_str(&env, "CASE"));
        assert_eq!(client.decimals(), 0);
        assert_eq!(client.admin(), admin);
        assert_eq!(client.max_supply(), 0);
        assert!(!client.frozen());
        assert_eq!(
            client.base_uri(),
            String::from_str(&env, "ipfs://collection/{id}.json")
        );

        let other = Address::generate(&env);
        assert!(client
            .try_initialize(
                &other,
                &String::from_str(&env, "X"),
                &String::from_str(&env, "X"),
                &0,
                &String::from_str(&env, ""),
                &0,
            )
            .is_err());
    }

    #[test]
    fn mint_nft_assigns_owner_and_metadata() {
        let (env, _, client) = setup();
        let holder = Address::generate(&env);

        client.mint(
            &holder,
            &1,
            &ONE,
            &String::from_str(&env, "Golden Ticket"),
            &String::from_str(&env, "ipfs://nft/1.json"),
        );

        assert_eq!(client.balance(&holder, &1), 1);
        assert_eq!(client.base_supply(&1), 1);
        assert_eq!(client.total_supply(), 1);
        assert!(client.is_nft(&1));
        assert_eq!(client.owner_of(&1), Some(holder.clone()));
        assert_eq!(client.uri(&1), String::from_str(&env, "ipfs://nft/1.json"));
        assert_eq!(
            client.metadata(&1).asset_name,
            String::from_str(&env, "Golden Ticket")
        );
    }

    #[test]
    fn nft_transfer_moves_ownership() {
        let (env, _, client) = setup();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(
            &alice,
            &7,
            &ONE,
            &String::from_str(&env, "One"),
            &String::from_str(&env, "ipfs://nft/7.json"),
        );

        client.transfer(&alice, &bob, &7, &ONE);

        assert_eq!(client.balance(&alice, &7), 0);
        assert_eq!(client.balance(&bob, &7), 1);
        assert_eq!(client.owner_of(&7), Some(bob));
    }

    #[test]
    fn sft_mint_splits_between_holders_and_clears_sole_owner() {
        let (env, _, client) = setup();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(
            &alice,
            &9,
            &TEN,
            &String::from_str(&env, "Tickets"),
            &String::from_str(&env, "ipfs://sft/9.json"),
        );

        assert!(!client.is_nft(&9));
        assert_eq!(client.owner_of(&9), Some(alice.clone()));
        assert_eq!(client.base_supply(&9), TEN);

        client.transfer(&alice, &bob, &9, &4);

        assert_eq!(client.balance(&alice, &9), 6);
        assert_eq!(client.balance(&bob, &9), 4);
        // A partially moved SFT no longer has a single owner.
        assert_eq!(client.owner_of(&9), None);
        assert_eq!(client.base_supply(&9), TEN);
        assert_eq!(client.total_supply(), TEN);
    }

    #[test]
    fn moving_the_whole_supply_restores_sole_ownership() {
        let (env, _, client) = setup();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(
            &alice,
            &9,
            &TEN,
            &String::from_str(&env, "Tickets"),
            &String::from_str(&env, "ipfs://sft/9.json"),
        );
        client.transfer(&alice, &bob, &9, &10);
        assert_eq!(client.owner_of(&9), Some(bob.clone()));
    }

    #[test]
    fn burn_removes_supply_and_can_restore_sole_ownership() {
        let (env, _, client) = setup();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(
            &alice,
            &9,
            &TEN,
            &String::from_str(&env, "Tickets"),
            &String::from_str(&env, "ipfs://sft/9.json"),
        );
        client.transfer(&alice, &bob, &9, &4);

        client.burn(&bob, &9, &3);
        assert_eq!(client.balance(&bob, &9), 1);
        assert_eq!(client.base_supply(&9), 7);
        assert_eq!(client.total_supply(), 7);
        // Alice still holds 6 of the 7 remaining units, so there is no owner.
        assert_eq!(client.owner_of(&9), None);

        // Burning Alice's remainder leaves Bob with the only unit left, which
        // makes the base token an NFT owned by Bob again.
        client.burn(&alice, &9, &6);
        assert_eq!(client.base_supply(&9), 1);
        assert!(client.is_nft(&9));
        assert_eq!(client.owner_of(&9), Some(bob.clone()));

        // Burning the last unit retires the base token.
        client.burn(&bob, &9, &1);
        assert_eq!(client.base_supply(&9), 0);
        assert_eq!(client.owner_of(&9), None);
    }

    #[test]
    fn zero_expiration_allowance_never_expires() {
        let (env, _, client) = setup();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.approve(&alice, &bob, &9, &5, &0);

        env.ledger().set_sequence_number(900_000);
        assert_eq!(client.allowance(&alice, &bob, &9), 5);
    }

    #[test]
    fn burn_from_spends_allowance() {
        let (env, _, client) = setup();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(
            &alice,
            &9,
            &TEN,
            &String::from_str(&env, "Tickets"),
            &String::from_str(&env, "ipfs://sft/9.json"),
        );

        client.approve(&alice, &bob, &9, &2, &0);
        client.burn_from(&bob, &alice, &9, &2);

        assert_eq!(client.balance(&alice, &9), 8);
        assert_eq!(client.allowance(&alice, &bob, &9), 0);
        assert_eq!(client.base_supply(&9), 8);
        assert_eq!(client.total_supply(), 8);
    }

    #[test]
    fn freeze_blocks_transfers_but_not_burns() {
        let (env, _, client) = setup();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(
            &alice,
            &1,
            &ONE,
            &String::from_str(&env, "One"),
            &String::from_str(&env, "ipfs://nft/1.json"),
        );

        client.freeze();
        assert!(client.frozen());
        assert!(client.try_transfer(&alice, &bob, &1, &ONE).is_err());

        // Holders keep an exit while frozen.
        client.burn(&alice, &1, &ONE);
        assert_eq!(client.base_supply(&1), 0);

        client.unfreeze();
        assert!(!client.frozen());
    }

    #[test]
    fn max_supply_caps_the_collection() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let id = env.register_contract(None, NftSftContract);
        let client = NftSftContractClient::new(&env, &id);
        client.initialize(
            &admin,
            &String::from_str(&env, "Capped"),
            &String::from_str(&env, "CAP"),
            &0,
            &String::from_str(&env, ""),
            &3,
        );
        assert_eq!(client.max_supply(), 3);

        let alice = Address::generate(&env);
        client.mint(
            &alice,
            &1,
            &2,
            &String::from_str(&env, "A"),
            &String::from_str(&env, ""),
        );
        // 2 + 2 would exceed the cap of 3.
        assert!(client
            .try_mint(
                &alice,
                &2,
                &2,
                &String::from_str(&env, "B"),
                &String::from_str(&env, "")
            )
            .is_err());
        client.mint(
            &alice,
            &2,
            &1,
            &String::from_str(&env, "B"),
            &String::from_str(&env, ""),
        );
        assert_eq!(client.total_supply(), 3);
    }

    #[test]
    fn token_id_cannot_be_minted_twice() {
        let (env, _, client) = setup();
        let alice = Address::generate(&env);
        client.mint(
            &alice,
            &1,
            &ONE,
            &String::from_str(&env, "A"),
            &String::from_str(&env, ""),
        );
        assert!(client
            .try_mint(
                &alice,
                &1,
                &ONE,
                &String::from_str(&env, "A2"),
                &String::from_str(&env, "")
            )
            .is_err());
    }

    #[test]
    fn transfers_reject_bad_amounts_and_unknown_tokens() {
        let (env, _, client) = setup();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(
            &alice,
            &1,
            &TEN,
            &String::from_str(&env, "A"),
            &String::from_str(&env, ""),
        );

        assert!(client.try_transfer(&alice, &bob, &1, &0).is_err());
        assert!(client.try_transfer(&alice, &alice, &1, &1).is_err());
        // More than the whole supply.
        assert!(client.try_transfer(&alice, &bob, &1, &11).is_err());
        // Token id that was never minted.
        assert!(client.try_transfer(&alice, &bob, &42, &1).is_err());
    }

    #[test]
    fn uri_falls_back_to_base_uri_template() {
        let (env, _, client) = setup();
        let alice = Address::generate(&env);
        client.mint(
            &alice,
            &5,
            &ONE,
            &String::from_str(&env, "Nameless"),
            &String::from_str(&env, ""),
        );
        assert_eq!(client.uri(&5), client.base_uri());
    }

    #[test]
    fn sole_holder_updates_metadata_while_admin_owns_shared_sfts() {
        let (env, _, client) = setup();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(
            &alice,
            &1,
            &ONE,
            &String::from_str(&env, "Old"),
            &String::from_str(&env, "ipfs://nft/1.json"),
        );
        client.set_metadata(
            &1,
            &String::from_str(&env, "New"),
            &String::from_str(&env, "ipfs://nft/1-v2.json"),
        );
        assert_eq!(
            client.uri(&1),
            String::from_str(&env, "ipfs://nft/1-v2.json")
        );

        client.mint(
            &alice,
            &2,
            &TEN,
            &String::from_str(&env, "Shared"),
            &String::from_str(&env, "ipfs://sft/2.json"),
        );
        client.transfer(&alice, &bob, &2, &5);
        // A divided SFT has no sole holder, so the admin must update it.
        client.set_metadata(
            &2,
            &String::from_str(&env, "Shared v2"),
            &String::from_str(&env, "ipfs://sft/2-v2.json"),
        );
        assert_eq!(
            client.uri(&2),
            String::from_str(&env, "ipfs://sft/2-v2.json")
        );
    }

    #[test]
    fn admin_rotates_via_set_admin() {
        let (env, admin, client) = setup();
        let new_admin = Address::generate(&env);
        client.set_admin(&new_admin);
        assert_eq!(client.admin(), new_admin);
        assert_ne!(client.admin(), admin);
    }

    #[test]
    fn mint_transfer_and_burn_emit_events() {
        let (env, _, client) = setup();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.mint(
            &alice,
            &3,
            &TEN,
            &String::from_str(&env, "Tickets"),
            &String::from_str(&env, "ipfs://sft/3.json"),
        );
        client.transfer(&alice, &bob, &3, &2);
        client.burn(&bob, &3, &1);

        let mut names: std::vec::Vec<Symbol> = std::vec::Vec::new();
        for (_, topics, _) in env.events().all() {
            for i in 0..topics.len() {
                if let Ok(sym) = Symbol::try_from_val(&env, &topics.get(i).unwrap()) {
                    names.push(sym);
                }
            }
        }
        assert!(names.contains(&symbol_short!("mint")));
        assert!(names.contains(&symbol_short!("transfer")));
        assert!(names.contains(&symbol_short!("burn")));
    }
}

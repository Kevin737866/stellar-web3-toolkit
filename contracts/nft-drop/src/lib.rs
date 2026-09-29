#![no_std]

//! Blind-mint NFT drop with phased sales (issue #149).
//!
//! This contract runs a mint drop for a collection. Buyers **blind mint** — the
//! asset is assigned to them immediately but its metadata stays hidden until
//! the admin *reveals* it after the drop, so a minter cannot cherry-pick which
//! asset they receive. Minting is gated by sale phases:
//!
//! | Phase | Meaning |
//! |---|---|
//! | `Pending` | Not on sale yet |
//! | `Allowlist` | Only allowlisted accounts may mint, at `allowlist_price` |
//! | `Public` | Anyone may mint, at `public_price` |
//! | `Ended` | Sale closed |
//!
//! `max_supply`, a per-address mint limit and an optional time window
//! (`start_time`/`end_time`, `0` disables the bound) further constrain sales.
//! Payment is collected in a SEP-41 token; the admin can withdraw the
//! proceeds.
//!
//! Privileged operations (configure setters, allowlist management, reveal,
//! withdraw) are authorised by the drop admin. When an
//! [`access_control`](Self::configure) contract (issue #148) is configured, any
//! account holding [`PERM_ADMIN`] for this collection may act as an admin too,
//! so a collection's role registry can drive the drop.

use soroban_sdk::{
    contract, contractclient, contractimpl, contracttype, symbol_short, token::TokenClient,
    Address, Env, String, Vec,
};

/// Access-control permission bit for managing a collection (issue #148).
pub const PERM_ADMIN: u32 = 0b0000_0001;

const TOKEN_TTL_THRESHOLD: u32 = 1_000;
const TOKEN_TTL_BUMP: u32 = 100_000;

/// Minimal interface to the collection access-control contract (issue #148).
#[contractclient(name = "AccessControlClient")]
pub trait AccessControlInterface {
    fn has_permission(env: Env, collection: Address, account: Address, permission: u32) -> bool;
}

/// Sale phase for the drop.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SalePhase {
    Pending,
    Allowlist,
    Public,
    Ended,
}

/// Drop configuration, stored once in instance storage.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DropConfig {
    pub admin: Address,
    /// SEP-41 token used to pay for mints.
    pub payment_token: Address,
    /// Price for mints during the `Allowlist` phase.
    pub allowlist_price: i128,
    /// Price for mints during the `Public` phase.
    pub public_price: i128,
    /// Maximum number of assets that may ever be minted.
    pub max_supply: u32,
    /// Per-address mint cap; `0` means unlimited.
    pub per_address_limit: u32,
    /// Sale opens at this ledger timestamp; `0` means no lower bound.
    pub start_time: u64,
    /// Sale closes at this ledger timestamp; `0` means no upper bound.
    pub end_time: u64,
    /// Metadata may be revealed at/after this timestamp; `0` means any time.
    pub reveal_time: u64,
    /// Optional collection access-control contract (issue #148).
    pub access_control: Option<Address>,
    pub phase: SalePhase,
}

/// Storage keys. `Config` and `Minted` live in instance storage; per-token and
/// per-account data lives in persistent storage with TTL extension.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Config,
    Minted,
    NextTokenId,
    OwnerOf(u64),
    Balance(Address),
    MintsBy(Address),
    TokenUri(u64),
    Allowlisted(Address),
}

#[contract]
pub struct NftDropContract;

fn read_config(env: &Env) -> DropConfig {
    env.storage()
        .instance()
        .get(&DataKey::Config)
        .expect("drop not configured")
}

fn write_config(env: &Env, config: &DropConfig) {
    env.storage().instance().set(&DataKey::Config, config);
}

fn read_minted(env: &Env) -> u32 {
    env.storage().instance().get(&DataKey::Minted).unwrap_or(0)
}

fn write_minted(env: &Env, minted: u32) {
    env.storage().instance().set(&DataKey::Minted, &minted);
}

fn read_next_token_id(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&DataKey::NextTokenId)
        .unwrap_or(0)
}

fn write_next_token_id(env: &Env, next: u64) {
    env.storage().instance().set(&DataKey::NextTokenId, &next);
}

fn bump(env: &Env, key: &DataKey) {
    env.storage()
        .persistent()
        .extend_ttl(key, TOKEN_TTL_THRESHOLD, TOKEN_TTL_BUMP);
}

fn owner_of(env: &Env, token_id: u64) -> Address {
    let key = DataKey::OwnerOf(token_id);
    let owner: Address = env
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or_else(|| panic!("unknown token"));
    bump(env, &key);
    owner
}

fn write_owner(env: &Env, token_id: u64, owner: &Address) {
    let key = DataKey::OwnerOf(token_id);
    env.storage().persistent().set(&key, owner);
    bump(env, &key);
}

fn balance_of(env: &Env, account: &Address) -> u32 {
    let key = DataKey::Balance(account.clone());
    env.storage().persistent().get(&key).unwrap_or(0)
}

fn write_balance(env: &Env, account: &Address, balance: u32) {
    let key = DataKey::Balance(account.clone());
    env.storage().persistent().set(&key, &balance);
    bump(env, &key);
}

fn mints_of(env: &Env, account: &Address) -> u32 {
    let key = DataKey::MintsBy(account.clone());
    env.storage().persistent().get(&key).unwrap_or(0)
}

fn write_mints(env: &Env, account: &Address, mints: u32) {
    let key = DataKey::MintsBy(account.clone());
    env.storage().persistent().set(&key, &mints);
    bump(env, &key);
}

fn is_allowlisted(env: &Env, account: &Address) -> bool {
    env.storage()
        .persistent()
        .get(&DataKey::Allowlisted(account.clone()))
        .unwrap_or(false)
}

/// Authorises `caller`: the drop admin, or — when configured — any account
/// holding [`PERM_ADMIN`] for this collection in the access-control contract.
fn require_admin(env: &Env, caller: &Address) {
    caller.require_auth();
    let config = read_config(env);
    if caller == &config.admin {
        return;
    }
    if let Some(access_control) = config.access_control {
        let allowed = AccessControlClient::new(env, &access_control).has_permission(
            &env.current_contract_address(),
            caller,
            &PERM_ADMIN,
        );
        assert!(allowed, "unauthorized");
        return;
    }
    panic!("unauthorized");
}

fn price_for(config: &DropConfig, phase: &SalePhase) -> i128 {
    match phase {
        SalePhase::Allowlist => config.allowlist_price,
        SalePhase::Public => config.public_price,
        _ => panic!("sale not active"),
    }
}

#[contractimpl]
impl NftDropContract {
    /// One-time configuration of the drop. `admin` authorises the drop and
    /// receives withdrawals.
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        env: Env,
        admin: Address,
        payment_token: Address,
        allowlist_price: i128,
        public_price: i128,
        max_supply: u32,
        per_address_limit: u32,
        start_time: u64,
        end_time: u64,
        reveal_time: u64,
        access_control: Option<Address>,
    ) {
        assert!(
            !env.storage().instance().has(&DataKey::Config),
            "drop already configured"
        );
        admin.require_auth();
        assert!(
            allowlist_price >= 0 && public_price >= 0,
            "price must be non-negative"
        );
        assert!(max_supply > 0, "max supply must be positive");
        if start_time > 0 && end_time > 0 {
            assert!(end_time >= start_time, "invalid sale window");
        }

        let config = DropConfig {
            admin,
            payment_token,
            allowlist_price,
            public_price,
            max_supply,
            per_address_limit,
            start_time,
            end_time,
            reveal_time,
            access_control,
            phase: SalePhase::Pending,
        };
        write_config(&env, &config);
        write_minted(&env, 0);
        write_next_token_id(&env, 0);

        env.events().publish(
            (symbol_short!("config"), env.current_contract_address()),
            (),
        );
    }

    /// Sets the current sale phase. Admin only.
    pub fn set_phase(env: Env, caller: Address, phase: SalePhase) {
        require_admin(&env, &caller);
        let mut config = read_config(&env);
        config.phase = phase.clone();
        write_config(&env, &config);
        env.events().publish(
            (symbol_short!("phase"), env.current_contract_address()),
            phase,
        );
    }

    /// Updates the access-control contract used for admin delegation.
    /// Admin only.
    pub fn set_access_control(env: Env, caller: Address, access_control: Option<Address>) {
        require_admin(&env, &caller);
        let mut config = read_config(&env);
        config.access_control = access_control;
        write_config(&env, &config);
        env.events().publish(
            (symbol_short!("setacl"), env.current_contract_address()),
            (),
        );
    }

    /// Updates the allowlist and public mint prices. Admin only.
    pub fn set_prices(env: Env, caller: Address, allowlist_price: i128, public_price: i128) {
        require_admin(&env, &caller);
        assert!(
            allowlist_price >= 0 && public_price >= 0,
            "price must be non-negative"
        );
        let mut config = read_config(&env);
        config.allowlist_price = allowlist_price;
        config.public_price = public_price;
        write_config(&env, &config);
    }

    /// Updates the sale window and reveal time. Admin only.
    pub fn set_times(env: Env, caller: Address, start_time: u64, end_time: u64, reveal_time: u64) {
        require_admin(&env, &caller);
        if start_time > 0 && end_time > 0 {
            assert!(end_time >= start_time, "invalid sale window");
        }
        let mut config = read_config(&env);
        config.start_time = start_time;
        config.end_time = end_time;
        config.reveal_time = reveal_time;
        write_config(&env, &config);
    }

    /// Adds accounts to the mint allowlist. Admin only.
    pub fn add_to_allowlist(env: Env, caller: Address, accounts: Vec<Address>) {
        require_admin(&env, &caller);
        let count = accounts.len();
        let mut i: u32 = 0;
        while i < count {
            let account = accounts.get(i).unwrap();
            let key = DataKey::Allowlisted(account);
            env.storage().persistent().set(&key, &true);
            bump(&env, &key);
            i += 1;
        }
        env.events().publish(
            (symbol_short!("allowlst"), env.current_contract_address()),
            count,
        );
    }

    /// Removes an account from the mint allowlist. Admin only.
    pub fn remove_from_allowlist(env: Env, caller: Address, account: Address) {
        require_admin(&env, &caller);
        env.storage()
            .persistent()
            .remove(&DataKey::Allowlisted(account.clone()));
        env.events().publish(
            (symbol_short!("unallow"), env.current_contract_address()),
            account,
        );
    }

    /// Blind mints the next asset to `buyer`, collecting the phase price.
    ///
    /// The asset owner is recorded immediately but its metadata stays hidden
    /// until revealed. Reverts when the sale is not active, outside the time
    /// window, sold out, over the per-address limit, or (during the allowlist
    /// phase) the buyer is not allowlisted. Returns the new token id.
    pub fn blind_mint(env: Env, buyer: Address) -> u64 {
        buyer.require_auth();
        let config = read_config(&env);

        assert!(
            matches!(config.phase, SalePhase::Allowlist | SalePhase::Public),
            "sale not active"
        );

        let now = env.ledger().timestamp();
        if config.start_time > 0 {
            assert!(now >= config.start_time, "sale not started");
        }
        if config.end_time > 0 {
            assert!(now <= config.end_time, "sale ended");
        }

        let minted = read_minted(&env);
        assert!(minted < config.max_supply, "sold out");

        if config.per_address_limit > 0 {
            assert!(
                mints_of(&env, &buyer) < config.per_address_limit,
                "mint limit reached"
            );
        }

        if config.phase == SalePhase::Allowlist {
            assert!(is_allowlisted(&env, &buyer), "not allowlisted");
        }
        let price = price_for(&config, &config.phase);

        if price > 0 {
            TokenClient::new(&env, &config.payment_token).transfer(
                &buyer,
                &env.current_contract_address(),
                &price,
            );
        }

        let token_id = read_next_token_id(&env);
        write_next_token_id(&env, token_id + 1);

        write_owner(&env, token_id, &buyer);
        write_balance(&env, &buyer, balance_of(&env, &buyer) + 1);
        write_mints(&env, &buyer, mints_of(&env, &buyer) + 1);
        write_minted(&env, minted + 1);

        env.events()
            .publish((symbol_short!("blindmint"), buyer), token_id);

        token_id
    }

    /// Reveals the metadata URI for a blind-minted asset. Admin only, and only
    /// at/after `reveal_time` when one is set.
    pub fn reveal(env: Env, caller: Address, token_id: u64, uri: String) {
        require_admin(&env, &caller);
        // Reverts with "unknown token" for assets that were never minted.
        owner_of(&env, token_id);

        let config = read_config(&env);
        if config.reveal_time > 0 {
            assert!(
                env.ledger().timestamp() >= config.reveal_time,
                "reveal not open"
            );
        }

        let key = DataKey::TokenUri(token_id);
        env.storage().persistent().set(&key, &uri);
        bump(&env, &key);

        env.events().publish(
            (symbol_short!("reveal"), env.current_contract_address()),
            token_id,
        );
    }

    /// Transfers an asset between accounts. Only the current owner may
    /// authorise the transfer.
    pub fn transfer(env: Env, from: Address, to: Address, token_id: u64) {
        from.require_auth();
        assert!(owner_of(&env, token_id) == from, "not token owner");

        write_owner(&env, token_id, &to);
        write_balance(&env, &from, balance_of(&env, &from) - 1);
        write_balance(&env, &to, balance_of(&env, &to) + 1);

        env.events()
            .publish((symbol_short!("transfer"), from), (to, token_id));
    }

    /// Withdraws collected mint proceeds to the admin. Admin only.
    pub fn withdraw(env: Env, caller: Address, amount: i128) {
        require_admin(&env, &caller);
        assert!(amount > 0, "amount must be positive");
        let config = read_config(&env);
        TokenClient::new(&env, &config.payment_token).transfer(
            &env.current_contract_address(),
            &config.admin,
            &amount,
        );
        env.events().publish(
            (symbol_short!("withdraw"), env.current_contract_address()),
            amount,
        );
    }

    // --- Read helpers -----------------------------------------------------

    /// Current drop configuration.
    pub fn get_config(env: Env) -> DropConfig {
        read_config(&env)
    }

    /// Current sale phase.
    pub fn phase(env: Env) -> SalePhase {
        read_config(&env).phase
    }

    /// Number of assets minted so far.
    pub fn total_supply(env: Env) -> u32 {
        read_minted(&env)
    }

    /// Owner of a minted asset.
    pub fn owner_of(env: Env, token_id: u64) -> Address {
        owner_of(&env, token_id)
    }

    /// Number of assets held by `account`.
    pub fn balance_of(env: Env, account: Address) -> u32 {
        balance_of(&env, &account)
    }

    /// Number of assets `account` has minted.
    pub fn mints_of(env: Env, account: Address) -> u32 {
        mints_of(&env, &account)
    }

    /// Whether `account` is on the mint allowlist.
    pub fn is_allowlisted(env: Env, account: Address) -> bool {
        is_allowlisted(&env, &account)
    }

    /// Whether an asset's metadata has been revealed.
    pub fn is_revealed(env: Env, token_id: u64) -> bool {
        env.storage().persistent().has(&DataKey::TokenUri(token_id))
    }

    /// Metadata URI for an asset, or an empty string while still hidden.
    pub fn token_uri(env: Env, token_id: u64) -> String {
        let key = DataKey::TokenUri(token_id);
        if !env.storage().persistent().has(&key) {
            return String::from_str(&env, "");
        }
        env.storage().persistent().get(&key).unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::testutils::Ledger as _;
    use soroban_sdk::token::StellarAssetClient;

    fn setup(
        env: &Env,
        price: i128,
        max_supply: u32,
        limit: u32,
    ) -> (Address, Address, Address, NftDropContractClient<'_>) {
        let admin = Address::generate(env);
        let payment = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let drop_id = env.register_contract(None, NftDropContract);
        let client = NftDropContractClient::new(env, &drop_id);
        client.configure(
            &admin,
            &payment,
            &price,
            &price,
            &max_supply,
            &limit,
            &0_u64,
            &10_000_u64,
            &0_u64,
            &None,
        );
        (admin, payment, drop_id, client)
    }

    fn fund(env: &Env, payment: &Address, to: &Address, amount: i128) {
        StellarAssetClient::new(env, payment).mint(to, &amount);
    }

    #[test]
    fn public_blind_mint_collects_payment_and_hides_metadata() {
        let env = Env::default();
        env.mock_all_auths();

        let (admin, payment, drop_id, drop) = setup(&env, 100, 10, 0);
        drop.set_phase(&admin, &SalePhase::Public);

        let buyer = Address::generate(&env);
        fund(&env, &payment, &buyer, 1_000);

        let token_id = drop.blind_mint(&buyer);
        assert_eq!(token_id, 0);
        assert_eq!(drop.owner_of(&token_id), buyer);
        assert_eq!(drop.balance_of(&buyer), 1);
        assert_eq!(drop.mints_of(&buyer), 1);
        assert_eq!(drop.total_supply(), 1);
        assert!(!drop.is_revealed(&token_id));
        assert_eq!(drop.token_uri(&token_id), String::from_str(&env, ""));

        // Payment moved from the buyer into the drop's escrow.
        let token = TokenClient::new(&env, &payment);
        assert_eq!(token.balance(&buyer), 900);
        assert_eq!(token.balance(&drop_id), 100);
    }

    #[test]
    fn pending_phase_cannot_mint() {
        let env = Env::default();
        env.mock_all_auths();

        let (_admin, _payment, _drop_id, drop) = setup(&env, 0, 10, 0);
        let buyer = Address::generate(&env);

        // The drop starts in the Pending phase, so minting must be rejected.
        assert!(drop.try_blind_mint(&buyer).is_err());
    }

    #[test]
    #[should_panic(expected = "sale not active")]
    fn ended_phase_cannot_mint() {
        let env = Env::default();
        env.mock_all_auths();

        let (admin, _payment, _drop_id, drop) = setup(&env, 0, 10, 0);
        drop.set_phase(&admin, &SalePhase::Ended);
        let buyer = Address::generate(&env);
        drop.blind_mint(&buyer);
    }

    #[test]
    fn allowlist_phase_requires_and_uses_allowlist_price() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let payment = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let drop_id = env.register_contract(None, NftDropContract);
        let drop = NftDropContractClient::new(&env, &drop_id);
        // allowlist 40, public 200.
        drop.configure(
            &admin,
            &payment,
            &40,
            &200,
            &10,
            &0,
            &0_u64,
            &10_000_u64,
            &0_u64,
            &None,
        );
        drop.set_phase(&admin, &SalePhase::Allowlist);

        let guest = Address::generate(&env);
        let member = Address::generate(&env);
        fund(&env, &payment, &guest, 1_000);
        fund(&env, &payment, &member, 1_000);

        // Non-allowlisted buyer is rejected during the allowlist phase.
        assert!(drop.try_blind_mint(&guest).is_err());

        let mut allow = Vec::new(&env);
        allow.push_back(member.clone());
        drop.add_to_allowlist(&admin, &allow);
        assert!(drop.is_allowlisted(&member));

        let token_id = drop.blind_mint(&member);
        assert_eq!(drop.owner_of(&token_id), member);

        let token = TokenClient::new(&env, &payment);
        assert_eq!(token.balance(&member), 960);

        drop.remove_from_allowlist(&admin, &member);
        assert!(!drop.is_allowlisted(&member));
    }

    #[test]
    fn per_address_limit_is_enforced() {
        let env = Env::default();
        env.mock_all_auths();

        let (admin, payment, _drop_id, drop) = setup(&env, 0, 10, 1);
        drop.set_phase(&admin, &SalePhase::Public);
        let buyer = Address::generate(&env);
        fund(&env, &payment, &buyer, 1_000);

        drop.blind_mint(&buyer);
        assert!(drop.try_blind_mint(&buyer).is_err());
    }

    #[test]
    #[should_panic(expected = "sold out")]
    fn max_supply_is_enforced() {
        let env = Env::default();
        env.mock_all_auths();

        let (admin, payment, _drop_id, drop) = setup(&env, 0, 1, 0);
        drop.set_phase(&admin, &SalePhase::Public);
        let first = Address::generate(&env);
        let second = Address::generate(&env);
        fund(&env, &payment, &first, 1_000);
        fund(&env, &payment, &second, 1_000);

        drop.blind_mint(&first);
        drop.blind_mint(&second);
    }

    #[test]
    fn reveal_sets_metadata_after_reveal_time() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let payment = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let drop_id = env.register_contract(None, NftDropContract);
        let drop = NftDropContractClient::new(&env, &drop_id);
        drop.configure(
            &admin,
            &payment,
            &0,
            &0,
            &10,
            &0,
            &0_u64,
            &10_000_u64,
            &500_u64,
            &None,
        );
        drop.set_phase(&admin, &SalePhase::Public);

        let buyer = Address::generate(&env);
        let token_id = drop.blind_mint(&buyer);

        // Too early to reveal.
        env.ledger().set_timestamp(100);
        assert!(drop
            .try_reveal(&admin, &token_id, &String::from_str(&env, "ipfs://a"))
            .is_err());

        env.ledger().set_timestamp(500);
        let uri = String::from_str(&env, "ipfs://asset-0");
        drop.reveal(&admin, &token_id, &uri);
        assert!(drop.is_revealed(&token_id));
        assert_eq!(drop.token_uri(&token_id), uri);
    }

    #[test]
    fn transfer_moves_ownership_and_balances() {
        let env = Env::default();
        env.mock_all_auths();

        let (admin, _payment, _drop_id, drop) = setup(&env, 0, 10, 0);
        drop.set_phase(&admin, &SalePhase::Public);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let token_id = drop.blind_mint(&alice);

        drop.transfer(&alice, &bob, &token_id);
        assert_eq!(drop.owner_of(&token_id), bob);
        assert_eq!(drop.balance_of(&alice), 0);
        assert_eq!(drop.balance_of(&bob), 1);
    }

    #[test]
    fn admin_can_withdraw_proceeds() {
        let env = Env::default();
        env.mock_all_auths();

        let (admin, payment, drop_id, drop) = setup(&env, 75, 10, 0);
        drop.set_phase(&admin, &SalePhase::Public);
        let buyer = Address::generate(&env);
        fund(&env, &payment, &buyer, 1_000);

        drop.blind_mint(&buyer);
        drop.withdraw(&admin, &75);

        let token = TokenClient::new(&env, &payment);
        assert_eq!(token.balance(&drop_id), 0);
        assert_eq!(token.balance(&admin), 75);
    }

    #[test]
    fn non_admin_cannot_reveal() {
        let env = Env::default();
        env.mock_all_auths();

        let (admin, _payment, _drop_id, drop) = setup(&env, 0, 10, 0);
        drop.set_phase(&admin, &SalePhase::Public);
        let buyer = Address::generate(&env);
        let token_id = drop.blind_mint(&buyer);

        assert!(drop
            .try_reveal(&buyer, &token_id, &String::from_str(&env, "ipfs://x"))
            .is_err());
    }

    #[test]
    #[should_panic(expected = "drop already configured")]
    fn configure_is_one_time() {
        let env = Env::default();
        env.mock_all_auths();

        let (admin, payment, _drop_id, drop) = setup(&env, 0, 10, 0);
        drop.configure(
            &admin,
            &payment,
            &0,
            &0,
            &10,
            &0,
            &0_u64,
            &10_000_u64,
            &0_u64,
            &None,
        );
    }
}

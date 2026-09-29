#![no_std]

//! Collection-level permission and access control for Soroban collections
//! (issue #148).
//!
//! A single deployment manages permissions for many collections. Each
//! collection is identified by its contract [`Address`] and has an *owner*
//! (usually the collection contract or its creator) plus per-account
//! permission bitmasks. Collections, and the contracts built around them, can
//! query [`CollectionAccessControl::has_permission`] to gate privileged
//! operations such as minting, burning, metadata updates or transfers.
//!
//! Permissions are bit flags so a caller can hold any combination:
//!
//! | Flag | Bit | Meaning |
//! |---|---|---|
//! | [`PERM_ADMIN`] | `0b00001` | Manage permissions and collection ownership |
//! | [`PERM_MINTER`] | `0b00010` | Mint new assets |
//! | [`PERM_BURNER`] | `0b00100` | Burn assets |
//! | [`PERM_METADATA`] | `0b01000` | Update asset metadata |
//! | [`PERM_TRANSFER`] | `0b10000` | Administer transfers/approvals |
//!
//! Each collection also has *default* permissions that apply to every account
//! (for example `PERM_TRANSFER` on a freely transferable collection). The
//! collection owner implicitly holds [`PERM_ALL`].

use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

/// Manage permissions and collection ownership.
pub const PERM_ADMIN: u32 = 0b0000_0001;
/// Mint new assets in the collection.
pub const PERM_MINTER: u32 = 0b0000_0010;
/// Burn assets in the collection.
pub const PERM_BURNER: u32 = 0b0000_0100;
/// Update asset metadata.
pub const PERM_METADATA: u32 = 0b0000_1000;
/// Administer transfers and approvals.
pub const PERM_TRANSFER: u32 = 0b0001_0000;
/// Every defined permission.
pub const PERM_ALL: u32 = PERM_ADMIN | PERM_MINTER | PERM_BURNER | PERM_METADATA | PERM_TRANSFER;

const PERM_TTL_THRESHOLD: u32 = 1_000;
const PERM_TTL_BUMP: u32 = 100_000;

/// Storage keys. `Admin` lives in instance storage; everything scoped to a
/// collection lives in persistent storage with TTL extension.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    /// Collection contract address -> owner.
    Owner(Address),
    /// (collection, account) -> explicitly granted permission bits.
    Permissions(Address, Address),
    /// Collection -> permissions granted to every account.
    DefaultPermissions(Address),
}

#[contract]
pub struct CollectionAccessControl;

fn admin(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&DataKey::Admin)
        .expect("access control not initialized")
}

fn owner_of(env: &Env, collection: &Address) -> Option<Address> {
    let key = DataKey::Owner(collection.clone());
    let owner = env.storage().persistent().get(&key);
    if owner.is_some() {
        env.storage()
            .persistent()
            .extend_ttl(&key, PERM_TTL_THRESHOLD, PERM_TTL_BUMP);
    }
    owner
}

fn explicit_permissions(env: &Env, collection: &Address, account: &Address) -> u32 {
    let key = DataKey::Permissions(collection.clone(), account.clone());
    if !env.storage().persistent().has(&key) {
        return 0;
    }
    env.storage()
        .persistent()
        .extend_ttl(&key, PERM_TTL_THRESHOLD, PERM_TTL_BUMP);
    env.storage().persistent().get(&key).unwrap_or(0)
}

fn default_permissions(env: &Env, collection: &Address) -> u32 {
    let key = DataKey::DefaultPermissions(collection.clone());
    if !env.storage().persistent().has(&key) {
        return 0;
    }
    env.storage()
        .persistent()
        .extend_ttl(&key, PERM_TTL_THRESHOLD, PERM_TTL_BUMP);
    env.storage().persistent().get(&key).unwrap_or(0)
}

/// Effective permissions for `account`: the collection owner holds everything,
/// otherwise the union of the default permissions and the account's explicit
/// grants.
fn effective_permissions(env: &Env, collection: &Address, account: &Address) -> u32 {
    if let Some(owner) = owner_of(env, collection) {
        if &owner == account {
            return PERM_ALL;
        }
    }
    default_permissions(env, collection) | explicit_permissions(env, collection, account)
}

fn require_collection_admin(env: &Env, caller: &Address, collection: &Address) {
    caller.require_auth();
    if caller == &admin(env) {
        return;
    }
    if let Some(owner) = owner_of(env, collection) {
        if caller == &owner {
            return;
        }
    }
    let perms = effective_permissions(env, collection, caller);
    assert!(perms & PERM_ADMIN != 0, "unauthorized");
}

fn write_permissions(env: &Env, collection: &Address, account: &Address, permissions: u32) {
    let key = DataKey::Permissions(collection.clone(), account.clone());
    if permissions == 0 {
        env.storage().persistent().remove(&key);
        return;
    }
    env.storage().persistent().set(&key, &permissions);
    env.storage()
        .persistent()
        .extend_ttl(&key, PERM_TTL_THRESHOLD, PERM_TTL_BUMP);
}

#[contractimpl]
impl CollectionAccessControl {
    /// One-time configuration. `admin` may register collections and always
    /// holds `PERM_ALL`.
    pub fn initialize(env: Env, admin: Address) {
        assert!(
            !env.storage().instance().has(&DataKey::Admin),
            "access control already initialized"
        );
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.events().publish((symbol_short!("init"), admin), ());
    }

    /// Registers a collection and sets its owner. Admin only. A collection can
    /// only be registered once.
    pub fn register_collection(env: Env, caller: Address, collection: Address, owner: Address) {
        caller.require_auth();
        assert!(caller == admin(&env), "unauthorized");

        let key = DataKey::Owner(collection.clone());
        assert!(
            !env.storage().persistent().has(&key),
            "collection already registered"
        );
        env.storage().persistent().set(&key, &owner);
        env.storage()
            .persistent()
            .extend_ttl(&key, PERM_TTL_THRESHOLD, PERM_TTL_BUMP);

        env.events()
            .publish((symbol_short!("register"), collection), owner);
    }

    /// Transfers collection ownership. Callable by the current owner or the
    /// contract admin (both of whom hold `PERM_ADMIN`).
    pub fn transfer_ownership(env: Env, caller: Address, collection: Address, new_owner: Address) {
        require_collection_admin(&env, &caller, &collection);

        let key = DataKey::Owner(collection.clone());
        assert!(
            env.storage().persistent().has(&key),
            "collection not registered"
        );
        env.storage().persistent().set(&key, &new_owner);
        env.storage()
            .persistent()
            .extend_ttl(&key, PERM_TTL_THRESHOLD, PERM_TTL_BUMP);

        env.events()
            .publish((symbol_short!("xferown"), collection), new_owner);
    }

    /// Adds `permissions` to an account's grant without disturbing existing
    /// bits. Caller must hold `PERM_ADMIN` for the collection.
    pub fn grant_permissions(
        env: Env,
        caller: Address,
        collection: Address,
        account: Address,
        permissions: u32,
    ) {
        require_collection_admin(&env, &caller, &collection);
        assert!(permissions != 0, "permissions must be non-zero");

        let current = explicit_permissions(&env, &collection, &account);
        write_permissions(&env, &collection, &account, current | permissions);

        env.events()
            .publish((symbol_short!("grant"), collection), (account, permissions));
    }

    /// Removes `permissions` from an account's grant, leaving other bits
    /// intact. Caller must hold `PERM_ADMIN` for the collection.
    pub fn revoke_permissions(
        env: Env,
        caller: Address,
        collection: Address,
        account: Address,
        permissions: u32,
    ) {
        require_collection_admin(&env, &caller, &collection);
        assert!(permissions != 0, "permissions must be non-zero");

        let current = explicit_permissions(&env, &collection, &account);
        write_permissions(&env, &collection, &account, current & !permissions);

        env.events().publish(
            (symbol_short!("revoke"), collection),
            (account, permissions),
        );
    }

    /// Overwrites an account's explicit permissions. Caller must hold
    /// `PERM_ADMIN` for the collection.
    pub fn set_permissions(
        env: Env,
        caller: Address,
        collection: Address,
        account: Address,
        permissions: u32,
    ) {
        require_collection_admin(&env, &caller, &collection);
        write_permissions(&env, &collection, &account, permissions);

        env.events().publish(
            (symbol_short!("setperms"), collection),
            (account, permissions),
        );
    }

    /// Sets the permissions granted to every account in the collection (for
    /// example `PERM_TRANSFER`). Caller must hold `PERM_ADMIN`.
    pub fn set_default_permissions(
        env: Env,
        caller: Address,
        collection: Address,
        permissions: u32,
    ) {
        require_collection_admin(&env, &caller, &collection);

        let key = DataKey::DefaultPermissions(collection.clone());
        if permissions == 0 {
            env.storage().persistent().remove(&key);
        } else {
            env.storage().persistent().set(&key, &permissions);
            env.storage()
                .persistent()
                .extend_ttl(&key, PERM_TTL_THRESHOLD, PERM_TTL_BUMP);
        }

        env.events()
            .publish((symbol_short!("setdflt"), collection), permissions);
    }

    // --- Read helpers -----------------------------------------------------

    /// Returns `true` when `account` holds *every* bit in `permission`.
    pub fn has_permission(
        env: Env,
        collection: Address,
        account: Address,
        permission: u32,
    ) -> bool {
        if permission == 0 {
            return true;
        }
        let perms = effective_permissions(&env, &collection, &account);
        perms & permission == permission
    }

    /// Effective permission bitmask for `account`, including defaults and the
    /// owner's implicit `PERM_ALL`.
    pub fn get_permissions(env: Env, collection: Address, account: Address) -> u32 {
        effective_permissions(&env, &collection, &account)
    }

    /// Owner of a registered collection.
    pub fn get_owner(env: Env, collection: Address) -> Address {
        owner_of(&env, &collection).expect("collection not registered")
    }

    /// Whether a collection has been registered.
    pub fn is_registered(env: Env, collection: Address) -> bool {
        env.storage().persistent().has(&DataKey::Owner(collection))
    }

    /// The contract-wide admin.
    pub fn get_admin(env: Env) -> Address {
        admin(&env)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    fn setup(env: &Env) -> (Address, Address, CollectionAccessControlClient<'_>) {
        let admin = Address::generate(env);
        let collection = Address::generate(env);
        let id = env.register_contract(None, CollectionAccessControl);
        let client = CollectionAccessControlClient::new(env, &id);
        client.initialize(&admin);
        (admin, collection, client)
    }

    #[test]
    fn owner_implicitly_holds_all_permissions() {
        let env = Env::default();
        env.mock_all_auths();

        let (admin, collection, client) = setup(&env);
        let owner = Address::generate(&env);
        client.register_collection(&admin, &collection, &owner);

        assert_eq!(client.get_owner(&collection), owner);
        assert!(client.is_registered(&collection));
        assert_eq!(client.get_permissions(&collection, &owner), PERM_ALL);
        assert!(client.has_permission(&collection, &owner, &PERM_MINTER));
    }

    #[test]
    fn grant_and_revoke_toggle_permission_bits() {
        let env = Env::default();
        env.mock_all_auths();

        let (admin, collection, client) = setup(&env);
        let owner = Address::generate(&env);
        let artist = Address::generate(&env);
        client.register_collection(&admin, &collection, &owner);

        assert!(!client.has_permission(&collection, &artist, &PERM_MINTER));

        client.grant_permissions(&owner, &collection, &artist, &PERM_MINTER);
        assert!(client.has_permission(&collection, &artist, &PERM_MINTER));
        // Granting a second flag does not clear the first.
        client.grant_permissions(&owner, &collection, &artist, &PERM_METADATA);
        assert!(client.has_permission(&collection, &artist, &PERM_MINTER));
        assert!(client.has_permission(&collection, &artist, &PERM_METADATA));
        assert_eq!(
            client.get_permissions(&collection, &artist),
            PERM_MINTER | PERM_METADATA
        );

        client.revoke_permissions(&owner, &collection, &artist, &PERM_MINTER);
        assert!(!client.has_permission(&collection, &artist, &PERM_MINTER));
        assert!(client.has_permission(&collection, &artist, &PERM_METADATA));
    }

    #[test]
    fn combined_permission_requires_every_bit() {
        let env = Env::default();
        env.mock_all_auths();

        let (admin, collection, client) = setup(&env);
        let artist = Address::generate(&env);
        client.register_collection(&admin, &collection, &admin);

        client.grant_permissions(&admin, &collection, &artist, &PERM_MINTER);
        assert!(client.has_permission(&collection, &artist, &PERM_MINTER));
        assert!(!client.has_permission(&collection, &artist, &(PERM_MINTER | PERM_BURNER)));
    }

    #[test]
    fn default_permissions_apply_to_everyone() {
        let env = Env::default();
        env.mock_all_auths();

        let (admin, collection, client) = setup(&env);
        client.register_collection(&admin, &collection, &admin);
        let stranger = Address::generate(&env);

        assert!(!client.has_permission(&collection, &stranger, &PERM_TRANSFER));
        client.set_default_permissions(&admin, &collection, &PERM_TRANSFER);
        assert!(client.has_permission(&collection, &stranger, &PERM_TRANSFER));
        // Defaults do not leak other permissions.
        assert!(!client.has_permission(&collection, &stranger, &PERM_MINTER));
    }

    #[test]
    fn transfer_ownership_moves_admin_rights() {
        let env = Env::default();
        env.mock_all_auths();

        let (admin, collection, client) = setup(&env);
        let owner = Address::generate(&env);
        let new_owner = Address::generate(&env);
        client.register_collection(&admin, &collection, &owner);

        assert!(client.has_permission(&collection, &owner, &PERM_ADMIN));
        client.transfer_ownership(&owner, &collection, &new_owner);

        assert_eq!(client.get_owner(&collection), new_owner);
        assert!(client.has_permission(&collection, &new_owner, &PERM_ALL));
        assert!(!client.has_permission(&collection, &owner, &PERM_ADMIN));
    }

    #[test]
    #[should_panic(expected = "unauthorized")]
    fn non_admin_cannot_grant_permissions() {
        let env = Env::default();
        env.mock_all_auths();

        let (admin, collection, client) = setup(&env);
        let owner = Address::generate(&env);
        let attacker = Address::generate(&env);
        let victim = Address::generate(&env);
        client.register_collection(&admin, &collection, &owner);

        client.grant_permissions(&attacker, &collection, &victim, &PERM_MINTER);
    }

    #[test]
    #[should_panic(expected = "unauthorized")]
    fn non_admin_cannot_register_collections() {
        let env = Env::default();
        env.mock_all_auths();

        let (_admin, collection, client) = setup(&env);
        let attacker = Address::generate(&env);
        let owner = Address::generate(&env);

        client.register_collection(&attacker, &collection, &owner);
    }

    #[test]
    #[should_panic(expected = "collection already registered")]
    fn collection_can_only_be_registered_once() {
        let env = Env::default();
        env.mock_all_auths();

        let (admin, collection, client) = setup(&env);
        let owner = Address::generate(&env);
        client.register_collection(&admin, &collection, &owner);
        client.register_collection(&admin, &collection, &owner);
    }

    #[test]
    #[should_panic(expected = "access control already initialized")]
    fn initialize_is_one_time() {
        let env = Env::default();
        env.mock_all_auths();

        let (_admin, _collection, client) = setup(&env);
        let second = Address::generate(&env);
        client.initialize(&second);
    }

    #[test]
    #[should_panic(expected = "collection not registered")]
    fn get_owner_requires_registration() {
        let env = Env::default();
        env.mock_all_auths();

        let (_admin, _collection, client) = setup(&env);
        let unknown = Address::generate(&env);
        client.get_owner(&unknown);
    }
}

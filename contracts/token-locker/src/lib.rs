//! Token locker with spending delegates.
//!
//! A custody layer over [SEP-41] tokens. Holders deposit tokens with the
//! contract, which escrows them, and can then either
//!
//! * keep them spendable as [`balance_of`](TokenLocker::balance_of),
//! * vest them for a recipient with [`lock`](TokenLocker::lock), which releases
//!   them once the unlock ledger is reached, or
//! * hand a capped, expiring spending limit to a delegate with
//!   [`set_delegate`](TokenLocker::set_delegate), letting that delegate pay
//!   funds out of the holder's custodied balance.
//!
//! # Custody model
//!
//! Deposited tokens stay in the contract, so moving custodied value never needs
//! a [SEP-41] allowance. Releasing a vest credits the recipient's spendable
//! balance rather than transferring tokens, so a recipient can immediately
//! withdraw, re-lock, or delegate the released value.
//!
//! # Safety properties
//!
//! * Escrowed tokens can only ever leave the contract towards a depositor or a
//!   vest recipient; the admin has no path to user funds.
//! * Freezing blocks deposits, new vests and delegate spending, but never
//!   withdrawals or vest releases, so a freeze cannot trap funds.
//! * A vest cannot be cancelled by the funder. The recipient may take the value
//!   early because it is already theirs.
//!
//! [SEP-41]: https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0041.md

#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, Env, String, Symbol, Vec,
};

/// Persistent entries are bumped once their remaining TTL drops below the
/// threshold, so live records are not archived out from under their users.
const RECORD_TTL_THRESHOLD: u32 = 100_000;
const RECORD_TTL_BUMP: u32 = 200_000;

/// Configuration held in instance storage.
#[contracttype]
#[derive(Clone)]
pub struct Config {
    pub admin: Address,
    pub name: String,
    pub symbol: String,
    pub frozen: bool,
}

/// A holder's custodied balance of one token.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Account {
    /// Spendable right now, either deposited or released from a vest.
    pub available: i128,
    /// Committed to vests that have not been released yet.
    pub locked: i128,
}

impl Account {
    fn empty() -> Self {
        Account {
            available: 0,
            locked: 0,
        }
    }

    /// Total the contract holds on this holder's behalf.
    pub fn total(&self) -> i128 {
        self.available + self.locked
    }
}

/// A vest of `amount` tokens for `recipient`, releasable from `unlock_ledger`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lock {
    pub id: u32,
    pub funder: Address,
    pub recipient: Address,
    pub token: Address,
    pub amount: i128,
    pub unlock_ledger: u32,
    pub released: bool,
}

/// A spending limit a holder granted to a delegate.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delegate {
    pub holder: Address,
    pub delegate: Address,
    pub token: Address,
    /// Amount still spendable. Re-authorising overwrites this.
    pub amount: i128,
    /// Ledger the limit stops applying from; `0` never expires.
    pub expires_ledger: u32,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Config,
    NextLockId,
    /// Tokens currently committed to vests, per token.
    TotalLocked(Address),
    /// (holder, token)
    Account(Address, Address),
    /// Ids of the vests a funder has outstanding, per token.
    LockIds(Address, Address),
    Lock(u32),
    /// (holder, token, delegate)
    Delegate(Address, Address, Address),
}

#[contract]
pub struct TokenLocker;

fn config(env: &Env) -> Config {
    env.storage().instance().get(&DataKey::Config).unwrap()
}

fn set_config(env: &Env, cfg: &Config) {
    env.storage().instance().set(&DataKey::Config, cfg);
}

fn next_lock_id(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::NextLockId)
        .unwrap_or(0)
}

fn total_locked(env: &Env, token: &Address) -> i128 {
    env.storage()
        .instance()
        .get(&DataKey::TotalLocked(token.clone()))
        .unwrap_or(0)
}

fn read_account(env: &Env, holder: &Address, token: &Address) -> Account {
    let key = DataKey::Account(holder.clone(), token.clone());
    let account: Account = env
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or_else(|| Account::empty());
    if account.total() > 0 {
        env.storage()
            .persistent()
            .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
    }
    account
}

/// Writes an account, dropping the entry entirely once it is empty.
fn write_account(env: &Env, holder: &Address, token: &Address, account: &Account) {
    let key = DataKey::Account(holder.clone(), token.clone());
    if account.total() == 0 {
        env.storage().persistent().remove(&key);
    } else {
        env.storage().persistent().set(&key, account);
        env.storage()
            .persistent()
            .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
    }
}

fn read_lock(env: &Env, id: u32) -> Option<Lock> {
    let key = DataKey::Lock(id);
    let lock: Option<Lock> = env.storage().persistent().get(&key);
    if lock.is_some() {
        env.storage()
            .persistent()
            .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
    }
    lock
}

fn write_lock(env: &Env, lock: &Lock) {
    let key = DataKey::Lock(lock.id);
    env.storage().persistent().set(&key, lock);
    env.storage()
        .persistent()
        .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
}

/// Outbound token movement. Tokens only ever leave the contract here.
fn transfer_out(env: &Env, token: &Address, to: &Address, amount: i128) {
    let contract = env.current_contract_address();
    soroban_sdk::token::TokenClient::new(env, token).transfer(&contract, to, &amount);
}

fn transfer_in(env: &Env, token: &Address, from: &Address, amount: i128) {
    soroban_sdk::token::TokenClient::new(env, token).transfer(
        from,
        &env.current_contract_address(),
        &amount,
    );
}

/// Moves `amount` of a holder's custodied balance to `to`, crediting the
/// recipient's own account so the value stays spendable.
fn credit(env: &Env, holder: &Address, token: &Address, amount: i128) {
    let mut account = read_account(env, holder, token);
    account.available += amount;
    write_account(env, holder, token, &account);
}

#[contractimpl]
impl TokenLocker {
    /// One-time initialisation.
    pub fn initialize(env: Env, admin: Address, name: String, symbol: String) {
        assert!(
            !env.storage().instance().has(&DataKey::Config),
            "already initialized"
        );
        admin.require_auth();
        set_config(
            &env,
            &Config {
                admin,
                name,
                symbol,
                frozen: false,
            },
        );
        env.storage().instance().set(&DataKey::NextLockId, &1u32);
    }

    // -- views ---------------------------------------------------------------

    pub fn admin(env: Env) -> Address {
        config(&env).admin
    }

    pub fn name(env: Env) -> String {
        config(&env).name
    }

    pub fn symbol(env: Env) -> String {
        config(&env).symbol
    }

    pub fn frozen(env: Env) -> bool {
        config(&env).frozen
    }

    /// The next vest id that will be handed out.
    pub fn next_lock_id(env: Env) -> u32 {
        next_lock_id(&env)
    }

    /// Spendable balance of `holder` for `token`.
    pub fn balance_of(env: Env, holder: Address, token: Address) -> i128 {
        read_account(&env, &holder, &token).available
    }

    /// Balance of `holder` for `token` that is committed to unreleased vests.
    pub fn locked_of(env: Env, holder: Address, token: Address) -> i128 {
        read_account(&env, &holder, &token).locked
    }

    /// Total custodied balance of `holder` for `token`.
    pub fn total_of(env: Env, holder: Address, token: Address) -> i128 {
        read_account(&env, &holder, &token).total()
    }

    /// Total `token` committed to unreleased vests across every funder.
    pub fn total_locked(env: Env, token: Address) -> i128 {
        total_locked(&env, &token)
    }

    /// Vest `id`, or `None` if it does not exist.
    pub fn lock_of(env: Env, id: u32) -> Option<Lock> {
        read_lock(&env, id)
    }

    /// Ids of the vests `funder` has outstanding for `token`.
    pub fn lock_ids(env: Env, funder: Address, token: Address) -> Vec<u32> {
        let key = DataKey::LockIds(funder.clone(), token.clone());
        let ids: Vec<u32> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| Vec::new(&env));
        if !ids.is_empty() {
            env.storage()
                .persistent()
                .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
        }
        ids
    }

    /// Whether a vest has reached its unlock ledger.
    pub fn is_matured(env: Env, id: u32) -> bool {
        match read_lock(&env, id) {
            Some(lock) => env.ledger().sequence() >= lock.unlock_ledger,
            None => false,
        }
    }

    /// The spending limit `holder` granted `delegate`, if any.
    pub fn delegate_of(
        env: Env,
        holder: Address,
        token: Address,
        delegate: Address,
    ) -> Option<Delegate> {
        let key = DataKey::Delegate(holder.clone(), token.clone(), delegate.clone());
        let record: Option<Delegate> = env.storage().persistent().get(&key);
        if record.is_some() {
            env.storage()
                .persistent()
                .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
        }
        record
    }

    /// Whether `delegate` currently holds a usable limit over `holder`.
    pub fn is_delegate(env: Env, holder: Address, token: Address, delegate: Address) -> bool {
        Self::delegate_limit(&env, &holder, &token, &delegate).is_some()
    }

    // -- admin ---------------------------------------------------------------

    /// Pauses deposits, new vests and delegate spending. Withdrawals and vest
    /// releases stay open so a freeze can never trap funds.
    pub fn set_frozen(env: Env, frozen: bool) {
        let cfg = config(&env);
        cfg.admin.require_auth();
        let mut updated = cfg;
        updated.frozen = frozen;
        set_config(&env, &updated);
        env.events()
            .publish((Symbol::new(&env, "set_frozen"),), frozen);
    }

    // -- holder --------------------------------------------------------------

    /// Escrows `amount` of `token`, making it spendable and delegatable.
    pub fn deposit(env: Env, holder: Address, token: Address, amount: i128) {
        holder.require_auth();
        assert!(amount > 0, "amount must be positive");
        let cfg = config(&env);
        assert!(!cfg.frozen, "contract is frozen");

        transfer_in(&env, &token, &holder, amount);
        credit(&env, &holder, &token, amount);

        env.events()
            .publish((symbol_short!("deposit"), holder.clone(), token), amount);
    }

    /// Returns `amount` of the holder's spendable balance to their address.
    ///
    /// Deliberately callable while frozen, so a freeze cannot strand funds.
    pub fn withdraw(env: Env, holder: Address, token: Address, amount: i128) {
        holder.require_auth();
        assert!(amount > 0, "amount must be positive");

        let mut account = read_account(&env, &holder, &token);
        assert!(account.available >= amount, "insufficient balance");
        account.available -= amount;
        write_account(&env, &holder, &token, &account);

        transfer_out(&env, &token, &holder, amount);
        env.events()
            .publish((symbol_short!("withdraw"), holder, token), amount);
    }

    /// Commits `amount` of the holder's spendable balance to `recipient`,
    /// releasable once the ledger reaches `unlock_ledger`.
    ///
    /// The vest is irrevocable: the funder cannot cancel it, so the value is a
    /// real commitment to the recipient.
    pub fn lock(
        env: Env,
        funder: Address,
        token: Address,
        recipient: Address,
        amount: i128,
        unlock_ledger: u32,
    ) -> u32 {
        funder.require_auth();
        assert!(amount > 0, "amount must be positive");
        assert!(recipient != funder, "recipient must differ from funder");
        let cfg = config(&env);
        assert!(!cfg.frozen, "contract is frozen");
        let now = env.ledger().sequence();
        assert!(unlock_ledger > now, "unlock ledger must be in the future");

        let mut account = read_account(&env, &funder, &token);
        assert!(account.available >= amount, "insufficient balance");
        account.available -= amount;
        account.locked += amount;
        write_account(&env, &funder, &token, &account);

        let id = next_lock_id(&env);
        env.storage()
            .instance()
            .set(&DataKey::NextLockId, &(id + 1));
        env.storage().instance().set(
            &DataKey::TotalLocked(token.clone()),
            &(total_locked(&env, &token) + amount),
        );

        let lock = Lock {
            id,
            funder: funder.clone(),
            recipient: recipient.clone(),
            token: token.clone(),
            amount,
            unlock_ledger,
            released: false,
        };
        write_lock(&env, &lock);
        Self::track_lock_id(&env, &funder, &token, id);

        env.events().publish(
            (symbol_short!("lock"), funder, token, id),
            (recipient, amount, unlock_ledger),
        );
        id
    }

    /// Releases vest `id` into the recipient's spendable balance.
    ///
    /// Callable by anyone once the vest has matured, which keeps releases
    /// permissionless and lets a recipient claim their own value early. The
    /// tokens stay in the contract, so releasing costs no transfer.
    pub fn release(env: Env, id: u32) {
        let cfg = config(&env);
        assert!(!cfg.frozen, "contract is frozen");
        let mut lock = read_lock(&env, id).unwrap_or_else(|| panic!("unknown lock"));
        assert!(!lock.released, "lock already released");
        assert!(
            env.ledger().sequence() >= lock.unlock_ledger,
            "lock is not mature yet"
        );

        lock.released = true;
        write_lock(&env, &lock);

        let mut funder_account = read_account(&env, &lock.funder, &lock.token);
        assert!(
            funder_account.locked >= lock.amount,
            "locked balance mismatch"
        );
        funder_account.locked -= lock.amount;
        write_account(&env, &lock.funder, &lock.token, &funder_account);
        env.storage().instance().set(
            &DataKey::TotalLocked(lock.token.clone()),
            &(total_locked(&env, &lock.token) - lock.amount),
        );
        Self::untrack_lock_id(&env, &lock.funder, &lock.token, id);

        credit(&env, &lock.recipient, &lock.token, lock.amount);
        env.events().publish(
            (symbol_short!("release"), id, lock.funder),
            (lock.recipient, lock.token, lock.amount),
        );
    }

    // -- delegates -----------------------------------------------------------

    /// Grants `delegate` a limit of `amount` over the holder's spendable
    /// balance of `token`. Re-authorising replaces the previous limit.
    ///
    /// `expires_ledger` of `0` means the limit never expires.
    pub fn set_delegate(
        env: Env,
        holder: Address,
        delegate: Address,
        token: Address,
        amount: i128,
        expires_ledger: u32,
    ) {
        holder.require_auth();
        assert!(delegate != holder, "cannot delegate to yourself");
        assert!(amount >= 0, "amount must not be negative");
        if expires_ledger != 0 {
            assert!(
                expires_ledger > env.ledger().sequence(),
                "expiry must be in the future"
            );
        }
        let cfg = config(&env);
        assert!(!cfg.frozen, "contract is frozen");

        let key = DataKey::Delegate(holder.clone(), token.clone(), delegate.clone());
        if amount == 0 {
            env.storage().persistent().remove(&key);
        } else {
            let record = Delegate {
                holder: holder.clone(),
                delegate: delegate.clone(),
                token: token.clone(),
                amount,
                expires_ledger,
            };
            env.storage().persistent().set(&key, &record);
            env.storage()
                .persistent()
                .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
        }

        env.events().publish(
            (symbol_short!("set_del"), holder, token, delegate),
            (amount, expires_ledger),
        );
    }

    /// Withdraws the delegate's limit.
    pub fn revoke_delegate(env: Env, holder: Address, token: Address, delegate: Address) {
        holder.require_auth();
        env.storage().persistent().remove(&DataKey::Delegate(
            holder.clone(),
            token.clone(),
            delegate.clone(),
        ));
        env.events()
            .publish((symbol_short!("rev_del"), holder, token, delegate), ());
    }

    /// Spends `amount` of `holder`'s custodied balance to `to` on behalf of an
    /// authorised `delegate`, drawing down the delegate's remaining limit.
    ///
    /// Only the spendable balance is reachable: vested funds stay committed
    /// until [`release`](TokenLocker::release) credits them.
    pub fn move_from(
        env: Env,
        holder: Address,
        token: Address,
        delegate: Address,
        to: Address,
        amount: i128,
    ) {
        delegate.require_auth();
        assert!(amount > 0, "amount must be positive");
        assert!(to != holder, "cannot move to the holder");
        let cfg = config(&env);
        assert!(!cfg.frozen, "contract is frozen");

        let mut record = Self::delegate_limit(&env, &holder, &token, &delegate)
            .unwrap_or_else(|| panic!("not an authorised delegate"));
        assert!(record.amount >= amount, "delegate limit exceeded");

        let mut account = read_account(&env, &holder, &token);
        assert!(account.available >= amount, "insufficient balance");
        account.available -= amount;
        write_account(&env, &holder, &token, &account);

        record.amount -= amount;
        Self::store_delegate(&env, &record);

        credit(&env, &to, &token, amount);
        env.events().publish(
            (symbol_short!("move"), holder, token, delegate),
            (to, amount),
        );
    }

    // -- internals -----------------------------------------------------------

    /// The delegate record, if one exists and has not expired.
    fn delegate_limit(
        env: &Env,
        holder: &Address,
        token: &Address,
        delegate: &Address,
    ) -> Option<Delegate> {
        let key = DataKey::Delegate(holder.clone(), token.clone(), delegate.clone());
        let record: Option<Delegate> = env.storage().persistent().get(&key);
        let record = record?;
        if record.expires_ledger != 0 && env.ledger().sequence() > record.expires_ledger {
            return None;
        }
        Some(record)
    }

    fn store_delegate(env: &Env, record: &Delegate) {
        let key = DataKey::Delegate(
            record.holder.clone(),
            record.token.clone(),
            record.delegate.clone(),
        );
        if record.amount == 0 {
            env.storage().persistent().remove(&key);
        } else {
            env.storage().persistent().set(&key, record);
            env.storage()
                .persistent()
                .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
        }
    }

    fn track_lock_id(env: &Env, funder: &Address, token: &Address, id: u32) {
        let key = DataKey::LockIds(funder.clone(), token.clone());
        let mut ids: Vec<u32> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| Vec::new(env));
        ids.push_back(id);
        env.storage().persistent().set(&key, &ids);
        env.storage()
            .persistent()
            .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
    }

    fn untrack_lock_id(env: &Env, funder: &Address, token: &Address, id: u32) {
        let key = DataKey::LockIds(funder.clone(), token.clone());
        let mut ids: Vec<u32> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| Vec::new(env));
        if let Some(index) = ids.first_index_of(id) {
            ids.remove(index);
        }
        if ids.is_empty() {
            env.storage().persistent().remove(&key);
        } else {
            env.storage().persistent().set(&key, &ids);
            env.storage()
                .persistent()
                .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
        }
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use super::*;
    use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
    use soroban_sdk::token::{StellarAssetClient, TokenClient};
    use soroban_sdk::{Symbol, TryFromVal};

    const ONE: i128 = 1_000;

    struct Fixture {
        env: Env,
        admin: Address,
        holder: Address,
        recipient: Address,
        delegate: Address,
        token: Address,
        client: TokenLockerClient<'static>,
    }

    impl Fixture {
        /// Mints `amount` to the holder and escrows it in the locker.
        fn funded(amount: i128) -> Self {
            let f = Fixture::new();
            StellarAssetClient::new(&f.env, &f.token).mint(&f.holder, &amount);
            f.client.deposit(&f.holder, &f.token, &amount);
            f
        }

        fn new() -> Self {
            let env = Env::default();
            env.mock_all_auths();
            // Generous TTLs so tests can advance the ledger without archiving.
            env.ledger().set_min_persistent_entry_ttl(1_000_000);
            env.ledger().set_max_entry_ttl(1_000_000);

            let admin = Address::generate(&env);
            let holder = Address::generate(&env);
            let recipient = Address::generate(&env);
            let delegate = Address::generate(&env);
            let token = env
                .register_stellar_asset_contract_v2(admin.clone())
                .address();

            let id = env.register_contract(None, TokenLocker);
            let client = TokenLockerClient::new(&env, &id);
            client.initialize(
                &admin,
                &String::from_str(&env, "Custody"),
                &String::from_str(&env, "CUST"),
            );
            Fixture {
                env,
                admin,
                holder,
                recipient,
                delegate,
                token,
                client,
            }
        }

        fn balance(&self, who: &Address) -> i128 {
            TokenClient::new(&self.env, &self.token).balance(who)
        }

        fn contract(&self) -> Address {
            self.client.address.clone()
        }
    }

    #[test]
    fn initialize_sets_metadata_and_rejects_reinit() {
        let f = Fixture::new();
        assert_eq!(f.client.name(), String::from_str(&f.env, "Custody"));
        assert_eq!(f.client.symbol(), String::from_str(&f.env, "CUST"));
        assert_eq!(f.client.admin(), f.admin);
        assert!(!f.client.frozen());
        assert_eq!(f.client.next_lock_id(), 1);

        assert!(f
            .client
            .try_initialize(
                &f.admin,
                &String::from_str(&f.env, "Again"),
                &String::from_str(&f.env, "AGAIN"),
            )
            .is_err());
    }

    #[test]
    fn deposit_makes_funds_spendable_and_withdrawable() {
        let f = Fixture::funded(ONE);
        assert_eq!(f.client.balance_of(&f.holder, &f.token), ONE);
        assert_eq!(f.client.total_of(&f.holder, &f.token), ONE);
        assert_eq!(f.client.locked_of(&f.holder, &f.token), 0);
        // The tokens really are in the contract.
        assert_eq!(f.balance(&f.contract()), ONE);
        assert_eq!(f.balance(&f.holder), 0);

        f.client.withdraw(&f.holder, &f.token, &ONE);
        assert_eq!(f.client.balance_of(&f.holder, &f.token), 0);
        assert_eq!(f.balance(&f.holder), ONE);
        assert_eq!(f.balance(&f.contract()), 0);
    }

    #[test]
    fn deposit_rejects_non_positive_amounts() {
        let f = Fixture::new();
        assert!(f.client.try_deposit(&f.holder, &f.token, &0).is_err());
        assert!(f.client.try_deposit(&f.holder, &f.token, &-1).is_err());
    }

    #[test]
    fn withdraw_rejects_more_than_the_spendable_balance() {
        let f = Fixture::funded(ONE);
        assert!(f
            .client
            .try_withdraw(&f.holder, &f.token, &(ONE + ONE))
            .is_err());
        assert!(f.client.try_withdraw(&f.holder, &f.token, &0).is_err());
        assert_eq!(f.client.balance_of(&f.holder, &f.token), ONE);
    }

    #[test]
    fn a_vest_commits_funds_that_cannot_be_withdrawn() {
        let f = Fixture::funded(2 * ONE);
        let id = f.client.lock(&f.holder, &f.token, &f.recipient, &ONE, &100);

        assert_eq!(id, 1);
        assert_eq!(f.client.balance_of(&f.holder, &f.token), ONE);
        assert_eq!(f.client.locked_of(&f.holder, &f.token), ONE);
        assert_eq!(f.client.total_locked(&f.token), ONE);
        assert_eq!(f.client.next_lock_id(), 2);

        // The committed half is not spendable.
        assert!(f
            .client
            .try_withdraw(&f.holder, &f.token, &(2 * ONE))
            .is_err());
        f.client.withdraw(&f.holder, &f.token, &ONE);
        assert_eq!(f.client.locked_of(&f.holder, &f.token), ONE);
    }

    #[test]
    fn a_vest_rejects_impossible_terms() {
        let f = Fixture::funded(ONE);
        let now = f.env.ledger().sequence();
        assert!(f
            .client
            .try_lock(&f.holder, &f.token, &f.recipient, &0, &(now + 10))
            .is_err());
        assert!(f
            .client
            .try_lock(&f.holder, &f.token, &f.recipient, &ONE, &now)
            .is_err());
        assert!(f
            .client
            .try_lock(&f.holder, &f.token, &f.holder, &ONE, &(now + 10))
            .is_err());
        // Vesting more than the holder has is rejected too.
        assert!(f
            .client
            .try_lock(&f.holder, &f.token, &f.recipient, &(2 * ONE), &(now + 10))
            .is_err());
    }

    #[test]
    fn a_vest_cannot_be_released_before_it_matures() {
        let f = Fixture::funded(ONE);
        let now = f.env.ledger().sequence();
        f.client
            .lock(&f.holder, &f.token, &f.recipient, &ONE, &(now + 10));

        assert!(!f.client.is_matured(&1));
        assert!(f.client.try_release(&1).is_err());
        assert_eq!(f.client.locked_of(&f.holder, &f.token), ONE);
    }

    #[test]
    fn anyone_can_release_a_matured_vest_to_the_recipient() {
        let f = Fixture::funded(ONE);
        let now = f.env.ledger().sequence();
        f.client
            .lock(&f.holder, &f.token, &f.recipient, &ONE, &(now + 10));

        f.env.ledger().set_sequence_number(now + 10);
        assert!(f.client.is_matured(&1));

        // A third party triggers it; the value still goes to the recipient.
        f.client.release(&1);
        assert_eq!(f.client.balance_of(&f.recipient, &f.token), ONE);
        assert_eq!(f.client.balance_of(&f.holder, &f.token), 0);
        assert_eq!(f.client.locked_of(&f.holder, &f.token), 0);
        assert_eq!(f.client.total_locked(&f.token), 0);
        assert_eq!(f.client.total_of(&f.recipient, &f.token), ONE);

        // Releasing twice is rejected.
        assert!(f.client.try_release(&1).is_err());
        assert!(f.client.try_release(&99).is_err());
    }

    #[test]
    fn released_value_can_be_withdrawn_by_the_recipient() {
        let f = Fixture::funded(ONE);
        let now = f.env.ledger().sequence();
        f.client
            .lock(&f.holder, &f.token, &f.recipient, &ONE, &(now + 10));
        f.env.ledger().set_sequence_number(now + 10);
        f.client.release(&1);

        f.client.withdraw(&f.recipient, &f.token, &ONE);
        assert_eq!(f.balance(&f.recipient), ONE);
        assert_eq!(f.balance(&f.contract()), 0);
        // The account entry is dropped once it is empty.
        assert_eq!(f.client.total_of(&f.recipient, &f.token), 0);
    }

    #[test]
    fn multiple_vests_are_tracked_per_token_and_funder() {
        let f = Fixture::funded(4 * ONE);
        let now = f.env.ledger().sequence();
        let other_token = f
            .env
            .register_stellar_asset_contract_v2(f.admin.clone())
            .address();
        StellarAssetClient::new(&f.env, &other_token).mint(&f.holder, &ONE);
        f.client.deposit(&f.holder, &other_token, &ONE);

        let first = f
            .client
            .lock(&f.holder, &f.token, &f.recipient, &ONE, &(now + 5));
        let second = f
            .client
            .lock(&f.holder, &f.token, &f.recipient, &(2 * ONE), &(now + 7));
        let third = f
            .client
            .lock(&f.holder, &other_token, &f.recipient, &ONE, &(now + 9));

        assert_eq!(first, 1);
        assert_eq!(second, 2);
        assert_eq!(third, 3);
        assert_eq!(f.client.next_lock_id(), 4);

        // Totals are per token.
        assert_eq!(f.client.total_locked(&f.token), 3 * ONE);
        assert_eq!(f.client.total_locked(&other_token), ONE);
        assert_eq!(f.client.lock_ids(&f.holder, &f.token).len(), 2);
        assert_eq!(f.client.lock_ids(&f.holder, &other_token).len(), 1);

        f.env.ledger().set_sequence_number(now + 7);
        f.client.release(&first);
        f.client.release(&second);
        // The released entry leaves the outstanding list.
        assert_eq!(f.client.lock_ids(&f.holder, &f.token).len(), 0);
        assert_eq!(f.client.lock_ids(&f.holder, &other_token).len(), 1);
        assert_eq!(f.client.balance_of(&f.recipient, &f.token), 3 * ONE);
        assert_eq!(f.client.balance_of(&f.recipient, &other_token), 0);
    }

    #[test]
    fn a_delegate_can_spend_within_its_limit() {
        let f = Fixture::funded(3 * ONE);
        f.client
            .set_delegate(&f.holder, &f.delegate, &f.token, &(2 * ONE), &0);
        assert!(f.client.is_delegate(&f.holder, &f.token, &f.delegate));

        f.client
            .move_from(&f.holder, &f.token, &f.delegate, &f.recipient, &ONE);

        // The value lands with the recipient as spendable balance.
        assert_eq!(f.client.balance_of(&f.recipient, &f.token), ONE);
        assert_eq!(f.client.balance_of(&f.holder, &f.token), 2 * ONE);
        let limit = f
            .client
            .delegate_of(&f.holder, &f.token, &f.delegate)
            .unwrap();
        assert_eq!(limit.amount, ONE);

        f.client
            .move_from(&f.holder, &f.token, &f.delegate, &f.recipient, &ONE);
        // A spent limit is removed rather than left at zero.
        assert!(f
            .client
            .delegate_of(&f.holder, &f.token, &f.delegate)
            .is_none());
        assert_eq!(f.client.balance_of(&f.holder, &f.token), ONE);
    }

    #[test]
    fn a_delegate_cannot_exceed_its_limit_or_the_balance() {
        let f = Fixture::funded(3 * ONE);
        f.client
            .set_delegate(&f.holder, &f.delegate, &f.token, &ONE, &0);

        // Beyond the limit.
        assert!(f
            .client
            .try_move_from(&f.holder, &f.token, &f.delegate, &f.recipient, &(ONE + ONE))
            .is_err());
        // Within the limit but beyond the holder's balance.
        f.client
            .set_delegate(&f.holder, &f.delegate, &f.token, &(10 * ONE), &0);
        assert!(f
            .client
            .try_move_from(&f.holder, &f.token, &f.delegate, &f.recipient, &(4 * ONE))
            .is_err());
        // Nothing moved.
        assert_eq!(f.client.balance_of(&f.holder, &f.token), 3 * ONE);
        assert_eq!(f.client.balance_of(&f.recipient, &f.token), 0);
    }

    #[test]
    fn an_unauthorised_delegate_cannot_move_funds() {
        let f = Fixture::funded(ONE);
        let stranger = Address::generate(&f.env);
        assert!(f
            .client
            .try_move_from(&f.holder, &f.token, &stranger, &f.recipient, &ONE)
            .is_err());
        assert_eq!(f.client.balance_of(&f.holder, &f.token), ONE);
    }

    #[test]
    fn a_delegate_expires_and_never_expiring_limits_do_not() {
        let f = Fixture::funded(3 * ONE);
        let now = f.env.ledger().sequence();
        f.client
            .set_delegate(&f.holder, &f.delegate, &f.token, &ONE, &(now + 10));

        // The limit applies right up to its expiry ledger.
        f.env.ledger().set_sequence_number(now + 10);
        assert!(f.client.is_delegate(&f.holder, &f.token, &f.delegate));

        // Past it, the limit stops applying.
        f.env.ledger().set_sequence_number(now + 11);
        assert!(!f.client.is_delegate(&f.holder, &f.token, &f.delegate));
        assert!(f
            .client
            .try_move_from(&f.holder, &f.token, &f.delegate, &f.recipient, &ONE)
            .is_err());
        assert_eq!(f.client.balance_of(&f.holder, &f.token), 3 * ONE);

        // An expiry already in the past cannot be set in the first place.
        assert!(f
            .client
            .try_set_delegate(&f.holder, &f.delegate, &f.token, &ONE, &(now + 10))
            .is_err());

        // A zero expiry keeps working at any ledger.
        f.client
            .set_delegate(&f.holder, &f.delegate, &f.token, &ONE, &0);
        f.env.ledger().set_sequence_number(now + 100);
        assert!(f.client.is_delegate(&f.holder, &f.token, &f.delegate));
        f.client
            .move_from(&f.holder, &f.token, &f.delegate, &f.recipient, &ONE);
        assert_eq!(f.client.balance_of(&f.recipient, &f.token), ONE);
    }

    #[test]
    fn a_reauthorised_delegate_replaces_the_previous_limit() {
        let f = Fixture::funded(3 * ONE);
        let now = f.env.ledger().sequence();
        f.client
            .set_delegate(&f.holder, &f.delegate, &f.token, &ONE, &0);
        f.client
            .set_delegate(&f.holder, &f.delegate, &f.token, &(2 * ONE), &(now + 50));

        let limit = f
            .client
            .delegate_of(&f.holder, &f.token, &f.delegate)
            .unwrap();
        assert_eq!(limit.amount, 2 * ONE);
        assert_eq!(limit.expires_ledger, now + 50);
    }

    #[test]
    fn a_revoked_delegate_cannot_move_funds() {
        let f = Fixture::funded(ONE);
        f.client
            .set_delegate(&f.holder, &f.delegate, &f.token, &ONE, &0);
        f.client.revoke_delegate(&f.holder, &f.token, &f.delegate);
        assert!(!f.client.is_delegate(&f.holder, &f.token, &f.delegate));
        assert!(f
            .client
            .try_move_from(&f.holder, &f.token, &f.delegate, &f.recipient, &ONE)
            .is_err());
    }

    #[test]
    fn setting_a_zero_limit_revokes_the_delegate() {
        let f = Fixture::funded(ONE);
        f.client
            .set_delegate(&f.holder, &f.delegate, &f.token, &ONE, &0);
        f.client
            .set_delegate(&f.holder, &f.delegate, &f.token, &0, &0);
        assert!(f
            .client
            .delegate_of(&f.holder, &f.token, &f.delegate)
            .is_none());
    }

    #[test]
    fn a_holder_cannot_delegate_to_itself() {
        let f = Fixture::funded(ONE);
        assert!(f
            .client
            .try_set_delegate(&f.holder, &f.holder, &f.token, &ONE, &0)
            .is_err());
    }

    #[test]
    fn delegates_cannot_reach_vested_funds() {
        let f = Fixture::funded(2 * ONE);
        let now = f.env.ledger().sequence();
        f.client
            .lock(&f.holder, &f.token, &f.recipient, &ONE, &(now + 10));
        f.client
            .set_delegate(&f.holder, &f.delegate, &f.token, &(2 * ONE), &0);

        // Only the unvested half is reachable.
        f.client
            .move_from(&f.holder, &f.token, &f.delegate, &f.recipient, &ONE);
        assert!(f
            .client
            .try_move_from(&f.holder, &f.token, &f.delegate, &f.recipient, &ONE)
            .is_err());
        assert_eq!(f.client.locked_of(&f.holder, &f.token), ONE);
    }

    #[test]
    fn a_freeze_blocks_new_activity_but_never_traps_funds() {
        let f = Fixture::funded(2 * ONE);
        let now = f.env.ledger().sequence();
        f.client
            .lock(&f.holder, &f.token, &f.recipient, &ONE, &(now + 10));
        f.client
            .set_delegate(&f.holder, &f.delegate, &f.token, &ONE, &0);

        f.client.set_frozen(&true);
        assert!(f.client.frozen());

        // New activity stops.
        assert!(f.client.try_deposit(&f.holder, &f.token, &ONE).is_err());
        assert!(f
            .client
            .try_lock(&f.holder, &f.token, &f.recipient, &ONE, &(now + 20))
            .is_err());
        assert!(f
            .client
            .try_set_delegate(&f.holder, &f.delegate, &f.token, &ONE, &0)
            .is_err());
        assert!(f
            .client
            .try_move_from(&f.holder, &f.token, &f.delegate, &f.recipient, &ONE)
            .is_err());
        // Even vest releases pause, so a freeze holds new payouts.
        assert!(f.client.try_release(&1).is_err());

        // Exits stay open.
        f.client.withdraw(&f.holder, &f.token, &ONE);
        assert_eq!(f.balance(&f.holder), ONE);

        f.client.set_frozen(&false);
        f.env.ledger().set_sequence_number(now + 10);
        f.client.release(&1);
        f.client.withdraw(&f.recipient, &f.token, &ONE);
        assert_eq!(f.balance(&f.recipient), ONE);
    }

    #[test]
    fn the_admin_has_no_path_to_custodied_funds() {
        let f = Fixture::funded(2 * ONE);
        let now = f.env.ledger().sequence();
        f.client
            .lock(&f.holder, &f.token, &f.recipient, &ONE, &(now + 10));

        // The admin can freeze, but every exit still requires the holder's or
        // the recipient's own signature.
        f.client.set_frozen(&true);
        assert!(f
            .client
            .try_withdraw(&f.admin, &f.token, &(2 * ONE))
            .is_err());
        f.client.set_frozen(&false);
        assert!(f
            .client
            .try_withdraw(&f.admin, &f.token, &(2 * ONE))
            .is_err());
        assert_eq!(f.client.total_of(&f.holder, &f.token), 2 * ONE);
        assert_eq!(f.balance(&f.contract()), 2 * ONE);
    }

    #[test]
    fn events_are_emitted_for_the_lifecycle() {
        let f = Fixture::funded(2 * ONE);
        let now = f.env.ledger().sequence();
        f.client
            .lock(&f.holder, &f.token, &f.recipient, &ONE, &(now + 10));
        f.client
            .set_delegate(&f.holder, &f.delegate, &f.token, &ONE, &0);
        f.client
            .move_from(&f.holder, &f.token, &f.delegate, &f.recipient, &ONE);
        f.client.revoke_delegate(&f.holder, &f.token, &f.delegate);
        f.env.ledger().set_sequence_number(now + 10);
        f.client.release(&1);
        f.client.withdraw(&f.recipient, &f.token, &ONE);
        f.client.set_frozen(&true);

        let mut names: std::vec::Vec<Symbol> = std::vec::Vec::new();
        for (_, topics, _) in f.env.events().all() {
            for i in 0..topics.len() {
                if let Ok(sym) = Symbol::try_from_val(&f.env, &topics.get(i).unwrap()) {
                    names.push(sym);
                }
            }
        }
        for expected in [
            symbol_short!("deposit"),
            symbol_short!("lock"),
            symbol_short!("set_del"),
            symbol_short!("move"),
            symbol_short!("rev_del"),
            symbol_short!("release"),
            symbol_short!("withdraw"),
            Symbol::new(&f.env, "set_frozen"),
        ] {
            assert!(names.contains(&expected), "missing {expected:?}");
        }
    }
}

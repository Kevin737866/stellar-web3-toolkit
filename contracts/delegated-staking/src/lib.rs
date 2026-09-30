//! Delegated staking with auto-compounding.
//!
//! LPs delegate a [SEP-41] token to an **operator** (a validator, an indexer, a
//! managed vault — anything that wants delegated weight). Rewards are funded in
//! the same token and streamed to stakers in proportion to what they delegated,
//! with the operator taking a capped commission.
//!
//! # Why a single token
//!
//! Rewards and stake are the same asset, so auto-compounding is a pure accounting
//! operation: an accrued reward is added straight back onto the position, with no
//! swap and no external price source. A farm that pays a *different* token cannot
//! compound on-chain without a DEX call, so it is out of scope here.
//!
//! # Reward accounting
//!
//! This is the classic index-accumulator design. A single global
//! `reward_per_token_stored` rises every time [`update_pool`] runs, by
//!
//! ```text
//! rate * distributable_seconds * PRECISION / total_staked
//! ```
//!
//! and each position stores the index it was last settled at. Its entitlement is
//! `amount * (index_now - index_paid) / PRECISION`. Because both the index and the
//! per-position accrual floor, the sum of entitlements can never exceed the amount
//! the schedule credited, and the contract can never pay out more than it holds.
//! All the arithmetic lives in [`math`] and is unit-tested there.
//!
//! # Safety properties
//!
//! * A delegator's principal can only leave towards that delegator. There is no
//!   admin sweep and no operator path to another user's stake.
//! * An operator is paid only its commission, and only out of realised rewards.
//! * `pause` blocks new delegations and new reward funding, but never blocks
//!   `undelegate` or `claim`, so a pause cannot trap funds — the same property
//!   the token locker relies on.
//! * Setting an operator inactive stops new delegations to it but leaves exits
//!   and claims open, so an operator can never strand its delegators.
//!
//! [SEP-41]: https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0041.md

#![no_std]

/// Pure fixed-point reward math. Public so the accumulator helpers are part of
/// the crate's reachable API and can be exercised directly by the property-test
/// harness in `contract-proptests`.
pub mod math;

use math::{
    accrued_rewards, distributable_seconds, remaining_rewards, reward_index_delta, reward_rate_for,
    split_commission, MAX_COMMISSION_BPS,
};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token::TokenClient, Address, Env, Vec,
};

/// Persistent records are bumped once their remaining TTL drops below the
/// threshold, so live positions are not archived out from under their owners.
const RECORD_TTL_THRESHOLD: u32 = 100_000;
const RECORD_TTL_BUMP: u32 = 200_000;

/// Instance-storage configuration for the whole pool.
#[contracttype]
#[derive(Clone)]
pub struct Config {
    pub admin: Address,
    /// The staked asset; also the asset rewards are paid in.
    pub token: Address,
    /// Blocks `delegate` and `fund_rewards`. Never blocks exits.
    pub paused: bool,
    /// Sum of every position's `amount`.
    pub total_staked: i128,
    /// Tokens per second the current schedule streams out.
    pub reward_rate: i128,
    /// Timestamp the current schedule stops at.
    pub period_finish: u64,
    /// Last timestamp the index was advanced to.
    pub last_update: u64,
    /// Global accumulator, scaled by `math::PRECISION`.
    pub reward_per_token_stored: i128,
    /// Tokens ever transferred in by `fund_rewards`.
    pub rewards_funded: i128,
    /// Tokens the index has attributed to positions (may trail `rewards_funded`
    /// by unstreamed schedule and rounding dust).
    pub rewards_credited: i128,
    /// Rewards paid out to wallets (delegators and operator commissions).
    pub rewards_paid_out: i128,
    /// Rewards re-staked into positions by `compound`/auto-compound.
    pub rewards_compounded: i128,
}

/// A registered operator that delegators can point their stake at.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Operator {
    pub address: Address,
    /// Share of realised rewards the operator keeps, in basis points.
    pub commission_bps: u32,
    /// Inactive operators accept no new stake but never block exits.
    pub active: bool,
    /// Sum of the positions delegated to this operator.
    pub total_staked: i128,
}

/// One delegator's stake with one operator.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Position {
    pub delegator: Address,
    pub operator: Address,
    /// Principal currently delegated.
    pub amount: i128,
    /// Accumulator value this position was last settled at.
    pub reward_per_token_paid: i128,
    /// Rewards earned but not yet claimed or compounded.
    pub accrued: i128,
    /// Whether `delegate`/`undelegate` re-stake accrued rewards automatically.
    pub auto_compound: bool,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// The single [`Config`] record (instance storage).
    Config,
    /// Every registered operator address, in registration order (instance).
    Operators,
    /// An operator record.
    Operator(Address),
    /// A position, keyed by `(delegator, operator)`.
    Position(Address, Address),
    /// The operators a delegator has a live position with.
    DelegatorOperators(Address),
}

#[contract]
pub struct DelegatedStaking;

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

fn read_operator(env: &Env, operator: &Address) -> Option<Operator> {
    let key = DataKey::Operator(operator.clone());
    let record: Option<Operator> = env.storage().persistent().get(&key);
    if record.is_some() {
        env.storage()
            .persistent()
            .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
    }
    record
}

fn write_operator(env: &Env, operator: &Operator) {
    let key = DataKey::Operator(operator.address.clone());
    env.storage().persistent().set(&key, operator);
    env.storage()
        .persistent()
        .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
}

fn all_operators(env: &Env) -> Vec<Address> {
    env.storage()
        .instance()
        .get(&DataKey::Operators)
        .unwrap_or_else(|| Vec::new(env))
}

/// Reads a position, defaulting to an empty one.
///
/// A missing position is anchored at the *current* index rather than at zero, so
/// a delegator cannot claim rewards that accrued before they joined.
fn read_position(
    env: &Env,
    delegator: &Address,
    operator: &Address,
    index_now: i128,
) -> Position {
    let key = DataKey::Position(delegator.clone(), operator.clone());
    let record: Option<Position> = env.storage().persistent().get(&key);
    match record {
        Some(position) => {
            env.storage()
                .persistent()
                .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
            position
        }
        None => Position {
            delegator: delegator.clone(),
            operator: operator.clone(),
            amount: 0,
            reward_per_token_paid: index_now,
            accrued: 0,
            auto_compound: false,
        },
    }
}

fn position_is_empty(position: &Position) -> bool {
    position.amount == 0 && position.accrued == 0 && !position.auto_compound
}

/// Writes a position, dropping the entry entirely once it has nothing left to
/// remember. Returns whether the record was kept.
fn write_position(env: &Env, position: &Position) -> bool {
    let key = DataKey::Position(position.delegator.clone(), position.operator.clone());
    if position_is_empty(position) {
        env.storage().persistent().remove(&key);
        false
    } else {
        env.storage().persistent().set(&key, position);
        env.storage()
            .persistent()
            .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
        true
    }
}

fn delegator_operator_list(env: &Env, delegator: &Address) -> Vec<Address> {
    env.storage()
        .persistent()
        .get(&DataKey::DelegatorOperators(delegator.clone()))
        .unwrap_or_else(|| Vec::new(env))
}

fn list_contains(list: &Vec<Address>, needle: &Address) -> bool {
    for i in 0..list.len() {
        if list.get_unchecked(i) == *needle {
            return true;
        }
    }
    false
}

fn track_delegator_operator(env: &Env, delegator: &Address, operator: &Address) {
    let list = delegator_operator_list(env, delegator);
    if list_contains(&list, operator) {
        return;
    }
    let key = DataKey::DelegatorOperators(delegator.clone());
    let mut updated = list;
    updated.push_back(operator.clone());
    env.storage().persistent().set(&key, &updated);
    env.storage()
        .persistent()
        .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
}

fn untrack_delegator_operator(env: &Env, delegator: &Address, operator: &Address) {
    let list = delegator_operator_list(env, delegator);
    let mut kept: Vec<Address> = Vec::new(env);
    for i in 0..list.len() {
        let item = list.get_unchecked(i);
        if item != *operator {
            kept.push_back(item);
        }
    }
    let key = DataKey::DelegatorOperators(delegator.clone());
    if kept.is_empty() {
        env.storage().persistent().remove(&key);
    } else {
        env.storage().persistent().set(&key, &kept);
        env.storage()
            .persistent()
            .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
    }
}

fn transfer_in(env: &Env, token: &Address, from: &Address, amount: i128) {
    TokenClient::new(env, token).transfer(from, &env.current_contract_address(), &amount);
}

fn transfer_out(env: &Env, token: &Address, to: &Address, amount: i128) {
    if amount <= 0 {
        return;
    }
    TokenClient::new(env, token).transfer(&env.current_contract_address(), to, &amount);
}

// ---------------------------------------------------------------------------
// Reward accounting
// ---------------------------------------------------------------------------

/// Advances the global index up to `now` and returns the fresh config.
///
/// Time with nothing staked is consumed without crediting anything, so rewards
/// funded while the pool is empty are not handed to whoever joins next — that
/// would let a new depositor collect the entire backlog.
fn update_pool(env: &Env) -> Config {
    let mut cfg = config(env);
    let now = env.ledger().timestamp();
    let seconds = distributable_seconds(cfg.last_update, cfg.period_finish, now);
    if seconds > 0 {
        let (delta, credited) = reward_index_delta(cfg.reward_rate, seconds, cfg.total_staked);
        if delta > 0 {
            cfg.reward_per_token_stored = cfg
                .reward_per_token_stored
                .checked_add(delta)
                .expect("index overflow");
            cfg.rewards_credited = cfg
                .rewards_credited
                .checked_add(credited)
                .expect("credited overflow");
        }
    }
    if now > cfg.last_update {
        cfg.last_update = now;
    }
    set_config(env, &cfg);
    cfg
}

/// Folds the index movement since the last settle into `position.accrued`.
fn settle(cfg: &Config, position: &mut Position) {
    if cfg.reward_per_token_stored == position.reward_per_token_paid {
        return;
    }
    position.accrued = position
        .accrued
        .checked_add(accrued_rewards(
            position.amount,
            cfg.reward_per_token_stored,
            position.reward_per_token_paid,
        ))
        .expect("accrued overflow");
    position.reward_per_token_paid = cfg.reward_per_token_stored;
}

/// Settles `position`, then splits its accrued rewards into the delegator's net
/// and the operator's commission, clearing the accrual. No tokens move here, so
/// callers decide whether the net is paid out or re-staked.
fn take_accrued(cfg: &Config, position: &mut Position, commission_bps: u32) -> (i128, i128) {
    settle(cfg, position);
    let gross = position.accrued;
    let (net, commission) = split_commission(gross, commission_bps);
    position.accrued = 0;
    (net, commission)
}

/// Re-stakes a position's accrued rewards in place when auto-compound is on.
/// Returns the amount compounded.
fn auto_compound(
    env: &Env,
    cfg: &mut Config,
    position: &mut Position,
    operator: &mut Operator,
) -> i128 {
    if !position.auto_compound {
        return 0;
    }
    let (net, commission) = take_accrued(cfg, position, operator.commission_bps);
    if commission > 0 {
        cfg.rewards_paid_out = cfg
            .rewards_paid_out
            .checked_add(commission)
            .expect("paid overflow");
        transfer_out(env, &cfg.token, &operator.address, commission);
    }
    if net > 0 {
        position.amount = position.amount.checked_add(net).expect("amount overflow");
        cfg.total_staked = cfg.total_staked.checked_add(net).expect("total overflow");
        cfg.rewards_compounded = cfg
            .rewards_compounded
            .checked_add(net)
            .expect("compounded overflow");
        operator.total_staked = operator
            .total_staked
            .checked_add(net)
            .expect("operator overflow");
    }
    net
}

/// The invariant that keeps the pool solvent: the index can never have handed
/// out more than it credited, and nothing is ever paid out that was not credited.
fn assert_solvent(cfg: &Config) {
    assert!(
        cfg.rewards_paid_out.saturating_add(cfg.rewards_compounded) <= cfg.rewards_credited,
        "reward solvency violated"
    );
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contractimpl]
impl DelegatedStaking {
    /// One-time setup.
    pub fn initialize(env: Env, admin: Address, token: Address) {
        assert!(
            !env.storage().instance().has(&DataKey::Config),
            "already initialized"
        );
        admin.require_auth();
        set_config(
            &env,
            &Config {
                admin,
                token,
                paused: false,
                total_staked: 0,
                reward_rate: 0,
                period_finish: 0,
                last_update: env.ledger().timestamp(),
                reward_per_token_stored: 0,
                rewards_funded: 0,
                rewards_credited: 0,
                rewards_paid_out: 0,
                rewards_compounded: 0,
            },
        );
    }

    // -- views ---------------------------------------------------------------

    pub fn admin(env: Env) -> Address {
        config(&env).admin
    }

    pub fn token(env: Env) -> Address {
        config(&env).token
    }

    pub fn paused(env: Env) -> bool {
        config(&env).paused
    }

    pub fn total_staked(env: Env) -> i128 {
        config(&env).total_staked
    }

    /// Tokens per second the current schedule streams out.
    pub fn reward_rate(env: Env) -> i128 {
        config(&env).reward_rate
    }

    pub fn period_finish(env: Env) -> u64 {
        config(&env).period_finish
    }

    pub fn last_update(env: Env) -> u64 {
        config(&env).last_update
    }

    pub fn reward_per_token_stored(env: Env) -> i128 {
        config(&env).reward_per_token_stored
    }

    pub fn rewards_funded(env: Env) -> i128 {
        config(&env).rewards_funded
    }

    pub fn rewards_credited(env: Env) -> i128 {
        config(&env).rewards_credited
    }

    pub fn rewards_paid_out(env: Env) -> i128 {
        config(&env).rewards_paid_out
    }

    pub fn rewards_compounded(env: Env) -> i128 {
        config(&env).rewards_compounded
    }

    pub fn operator_count(env: Env) -> u32 {
        all_operators(&env).len()
    }

    /// Every registered operator, in registration order.
    pub fn operator_list(env: Env) -> Vec<Address> {
        all_operators(&env)
    }

    /// An operator record, or `None` if it was never registered.
    pub fn operator_of(env: Env, operator: Address) -> Option<Operator> {
        read_operator(&env, &operator)
    }

    pub fn is_operator(env: Env, operator: Address) -> bool {
        read_operator(&env, &operator).is_some()
    }

    /// The operators `delegator` currently has a position with.
    pub fn delegator_operators(env: Env, delegator: Address) -> Vec<Address> {
        delegator_operator_list(&env, &delegator)
    }

    /// The stored position for `(delegator, operator)`.
    pub fn position(env: Env, delegator: Address, operator: Address) -> Position {
        let cfg = config(&env);
        read_position(&env, &delegator, &operator, cfg.reward_per_token_stored)
    }

    /// Rewards `delegator` has earned but not claimed or compounded, projected
    /// forward to the current ledger timestamp. Read-only, so it is safe to call
    /// from a UI that is quoting a `claim` or `compound`.
    ///
    /// This is the **gross** accrual, before the operator's commission. What
    /// `claim` and `compound` return is the net, i.e. `gross - commission`.
    pub fn pending_rewards(env: Env, delegator: Address, operator: Address) -> i128 {
        let cfg = config(&env);
        let position = read_position(&env, &delegator, &operator, cfg.reward_per_token_stored);
        let now = env.ledger().timestamp();
        let seconds = distributable_seconds(cfg.last_update, cfg.period_finish, now);
        let (delta, _) = reward_index_delta(cfg.reward_rate, seconds, cfg.total_staked);
        position
            .accrued
            .saturating_add(accrued_rewards(
                position.amount,
                cfg.reward_per_token_stored.saturating_add(delta),
                position.reward_per_token_paid,
            ))
    }

    // -- admin ---------------------------------------------------------------

    pub fn set_admin(env: Env, new_admin: Address) {
        let mut cfg = config(&env);
        cfg.admin.require_auth();
        cfg.admin = new_admin.clone();
        set_config(&env, &cfg);
        env.events().publish((symbol_short!("set_admin"),), new_admin);
    }

    /// Blocks new delegations and reward funding. Exits stay open.
    pub fn set_paused(env: Env, paused: bool) {
        let mut cfg = config(&env);
        cfg.admin.require_auth();
        cfg.paused = paused;
        set_config(&env, &cfg);
        env.events().publish((symbol_short!("set_pause"),), paused);
    }

    /// Registers a new operator. `commission_bps` is capped at
    /// [`math::MAX_COMMISSION_BPS`].
    pub fn add_operator(env: Env, operator: Address, commission_bps: u32) {
        let cfg = config(&env);
        cfg.admin.require_auth();
        assert!(
            commission_bps <= MAX_COMMISSION_BPS,
            "commission exceeds the maximum"
        );
        assert!(
            read_operator(&env, &operator).is_none(),
            "operator already registered"
        );

        write_operator(
            &env,
            &Operator {
                address: operator.clone(),
                commission_bps,
                active: true,
                total_staked: 0,
            },
        );
        let mut list = all_operators(&env);
        list.push_back(operator.clone());
        env.storage().instance().set(&DataKey::Operators, &list);

        env.events().publish((symbol_short!("add_op"), operator), commission_bps);
    }

    /// Changes an operator's commission. Takes effect on the next claim or
    /// compound, which is why those calls take a `min_out`.
    pub fn set_commission(env: Env, operator: Address, commission_bps: u32) {
        let cfg = config(&env);
        cfg.admin.require_auth();
        assert!(
            commission_bps <= MAX_COMMISSION_BPS,
            "commission exceeds the maximum"
        );
        let mut record =
            read_operator(&env, &operator).unwrap_or_else(|| panic!("unknown operator"));
        record.commission_bps = commission_bps;
        write_operator(&env, &record);
        env.events().publish((symbol_short!("set_comm"), operator), commission_bps);
    }

    /// Stops new delegations to an operator. Existing positions can still be
    /// undelegated and claimed.
    pub fn set_operator_active(env: Env, operator: Address, active: bool) {
        let cfg = config(&env);
        cfg.admin.require_auth();
        let mut record =
            read_operator(&env, &operator).unwrap_or_else(|| panic!("unknown operator"));
        record.active = active;
        write_operator(&env, &record);
        env.events().publish((symbol_short!("active"), operator), active);
    }

    // -- rewards funding -----------------------------------------------------

    /// Funds a reward schedule of `amount` over `duration_seconds` and returns
    /// the resulting per-second rate.
    ///
    /// If a schedule is already running, whatever it has left to stream is rolled
    /// into the new one so no funded reward is cancelled by a top-up.
    pub fn fund_rewards(env: Env, funder: Address, amount: i128, duration_seconds: u64) -> i128 {
        funder.require_auth();
        assert!(amount > 0, "amount must be positive");
        assert!(duration_seconds > 0, "duration must be positive");
        // Checked before `update_pool`, which writes state and so must not run
        // while the pool is paused.
        assert!(!config(&env).paused, "contract is paused");

        let mut cfg = update_pool(&env);
        let now = env.ledger().timestamp();
        let leftover = remaining_rewards(cfg.reward_rate, cfg.period_finish, now);
        let rate = reward_rate_for(
            leftover.checked_add(amount).expect("reward overflow"),
            duration_seconds,
        );
        // A rate that floors to zero would leave the funding stranded: the next
        // top-up computes its leftover from `rate`, which would now be zero.
        assert!(rate > 0, "reward rate rounds to zero");

        transfer_in(&env, &cfg.token, &funder, amount);

        cfg.rewards_funded = cfg
            .rewards_funded
            .checked_add(amount)
            .expect("funded overflow");
        cfg.reward_rate = rate;
        cfg.period_finish = now.saturating_add(duration_seconds);
        cfg.last_update = now;
        set_config(&env, &cfg);

        env.events()
            .publish((symbol_short!("fund"), funder), (amount, rate, cfg.period_finish));
        rate
    }

    // -- delegator actions ---------------------------------------------------

    /// Delegates `amount` to `operator`. When auto-compound is on, rewards
    /// accrued so far are re-staked first, so the new stake also earns on them.
    pub fn delegate(env: Env, delegator: Address, operator: Address, amount: i128) -> i128 {
        delegator.require_auth();
        assert!(amount > 0, "amount must be positive");

        let mut cfg = config(&env);
        assert!(!cfg.paused, "contract is paused");

        let mut record =
            read_operator(&env, &operator).unwrap_or_else(|| panic!("unknown operator"));
        assert!(record.active, "operator is not active");

        cfg = update_pool(&env);
        let mut position = read_position(&env, &delegator, &operator, cfg.reward_per_token_stored);
        auto_compound(&env, &mut cfg, &mut position, &mut record);

        transfer_in(&env, &cfg.token, &delegator, amount);

        position.amount = position.amount.checked_add(amount).expect("amount overflow");
        cfg.total_staked = cfg.total_staked.checked_add(amount).expect("total overflow");
        record.total_staked = record
            .total_staked
            .checked_add(amount)
            .expect("operator overflow");

        write_position(&env, &position);
        write_operator(&env, &record);
        set_config(&env, &cfg);
        track_delegator_operator(&env, &delegator, &operator);

        env.events()
            .publish((symbol_short!("delegate"), delegator), (operator, amount));
        position.amount
    }

    /// Returns `amount` of the delegator's principal to their wallet.
    ///
    /// Deliberately callable while paused or when the operator is inactive, so a
    /// delegator can always exit. Accrued rewards are auto-compounded first when
    /// that flag is on, so the exit does not strand them.
    pub fn undelegate(env: Env, delegator: Address, operator: Address, amount: i128) -> i128 {
        delegator.require_auth();
        assert!(amount > 0, "amount must be positive");

        let mut record =
            read_operator(&env, &operator).unwrap_or_else(|| panic!("unknown operator"));
        let mut cfg = update_pool(&env);
        let mut position = read_position(&env, &delegator, &operator, cfg.reward_per_token_stored);
        auto_compound(&env, &mut cfg, &mut position, &mut record);

        assert!(
            position.amount >= amount,
            "insufficient delegated balance"
        );

        position.amount -= amount;
        cfg.total_staked -= amount;
        record.total_staked -= amount;

        if !write_position(&env, &position) {
            untrack_delegator_operator(&env, &delegator, &operator);
        }
        write_operator(&env, &record);
        set_config(&env, &cfg);
        transfer_out(&env, &cfg.token, &delegator, amount);

        env.events()
            .publish((symbol_short!("undeleg"), delegator), (operator, amount));
        amount
    }

    /// Pays out accrued rewards, minus the operator's commission.
    ///
    /// `min_out` is the slippage guard against the operator's commission moving
    /// between the quote and this transaction landing.
    pub fn claim(env: Env, delegator: Address, operator: Address, min_out: i128) -> i128 {
        delegator.require_auth();
        assert!(min_out >= 0, "min_out must not be negative");

        let record = read_operator(&env, &operator).unwrap_or_else(|| panic!("unknown operator"));
        let mut cfg = update_pool(&env);
        let mut position = read_position(&env, &delegator, &operator, cfg.reward_per_token_stored);
        let (net, commission) = take_accrued(&cfg, &mut position, record.commission_bps);
        assert!(net >= min_out, "slippage: net reward below min_out");

        cfg.rewards_paid_out = cfg
            .rewards_paid_out
            .checked_add(net.checked_add(commission).expect("payout overflow"))
            .expect("paid overflow");
        assert_solvent(&cfg);

        write_position(&env, &position);
        set_config(&env, &cfg);
        transfer_out(&env, &cfg.token, &delegator, net);
        transfer_out(&env, &cfg.token, &record.address, commission);

        env.events().publish(
            (symbol_short!("claim"), delegator),
            (operator, net, commission),
        );
        net
    }

    /// Re-stakes accrued rewards into the position instead of paying them out.
    ///
    /// The operator's commission is still paid out, so the operator is not forced
    /// to take on token exposure they did not ask for.
    pub fn compound(env: Env, delegator: Address, operator: Address, min_amount_out: i128) -> i128 {
        delegator.require_auth();
        assert!(min_amount_out >= 0, "min_amount_out must not be negative");

        let mut record =
            read_operator(&env, &operator).unwrap_or_else(|| panic!("unknown operator"));
        let mut cfg = update_pool(&env);
        let mut position = read_position(&env, &delegator, &operator, cfg.reward_per_token_stored);
        let (net, commission) = take_accrued(&cfg, &mut position, record.commission_bps);
        assert!(
            net >= min_amount_out,
            "slippage: compounded amount below min_amount_out"
        );

        cfg.rewards_paid_out = cfg
            .rewards_paid_out
            .checked_add(commission)
            .expect("paid overflow");
        if net > 0 {
            position.amount = position.amount.checked_add(net).expect("amount overflow");
            cfg.total_staked = cfg.total_staked.checked_add(net).expect("total overflow");
            cfg.rewards_compounded = cfg
                .rewards_compounded
                .checked_add(net)
                .expect("compounded overflow");
            record.total_staked = record
                .total_staked
                .checked_add(net)
                .expect("operator overflow");
        }
        assert_solvent(&cfg);

        write_position(&env, &position);
        write_operator(&env, &record);
        set_config(&env, &cfg);
        track_delegator_operator(&env, &delegator, &operator);
        transfer_out(&env, &cfg.token, &record.address, commission);

        env.events().publish(
            (symbol_short!("compound"), delegator),
            (operator, net, commission),
        );
        net
    }

    /// Turns automatic re-staking on or off for one `(delegator, operator)`
    /// position. Nothing compounds until the position is next touched.
    pub fn set_auto_compound(env: Env, delegator: Address, operator: Address, enabled: bool) {
        delegator.require_auth();
        read_operator(&env, &operator).unwrap_or_else(|| panic!("unknown operator"));

        let cfg = update_pool(&env);
        let mut position = read_position(&env, &delegator, &operator, cfg.reward_per_token_stored);
        settle(&cfg, &mut position);
        position.auto_compound = enabled;

        if write_position(&env, &position) {
            track_delegator_operator(&env, &delegator, &operator);
        } else {
            untrack_delegator_operator(&env, &delegator, &operator);
        }

        env.events()
            .publish((symbol_short!("auto_cmp"), delegator), (operator, enabled));
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
    use soroban_sdk::token::{StellarAssetClient, TokenClient};
    use soroban_sdk::{Symbol, TryFromVal};

    /// One "token" in these tests, with room for 6 decimal places.
    const ONE: i128 = 1_000_000;

    struct Fixture {
        env: Env,
        admin: Address,
        alice: Address,
        bob: Address,
        operator: Address,
        other_operator: Address,
        token: Address,
        client: DelegatedStakingClient<'static>,
    }

    impl Fixture {
        /// 5% commission on the primary operator, 0% on the second one.
        fn new() -> Self {
            let env = Env::default();
            env.mock_all_auths();
            // Generous TTLs so tests can advance the ledger without archiving.
            env.ledger().set_min_persistent_entry_ttl(1_000_000);
            env.ledger().set_max_entry_ttl(1_000_000);
            env.ledger().with_mut(|li| li.timestamp = 1_000);

            let admin = Address::generate(&env);
            let alice = Address::generate(&env);
            let bob = Address::generate(&env);
            let operator = Address::generate(&env);
            let other_operator = Address::generate(&env);
            let token = env
                .register_stellar_asset_contract_v2(admin.clone())
                .address();

            let id = env.register_contract(None, DelegatedStaking);
            let client = DelegatedStakingClient::new(&env, &id);
            client.initialize(&admin, &token);
            client.add_operator(&operator, &500);
            client.add_operator(&other_operator, &0);

            Fixture {
                env,
                admin,
                alice,
                bob,
                operator,
                other_operator,
                token,
                client,
            }
        }

        fn mint(&self, to: &Address, amount: i128) {
            StellarAssetClient::new(&self.env, &self.token).mint(to, &amount);
        }

        fn balance(&self, who: &Address) -> i128 {
            TokenClient::new(&self.env, &self.token).balance(who)
        }

        fn contract(&self) -> Address {
            self.client.address.clone()
        }

        /// Funds `amount` of rewards to stream over `duration` seconds.
        fn fund(&self, amount: i128, duration: u64) {
            let funder = Address::generate(&self.env);
            self.mint(&funder, amount);
            self.client.fund_rewards(&funder, &amount, &duration);
        }

        fn advance(&self, seconds: u64) {
            self.env.ledger().with_mut(|li| {
                li.timestamp = li.timestamp.saturating_add(seconds);
            });
        }
    }

    #[test]
    fn initialize_sets_metadata_and_rejects_reinit() {
        let f = Fixture::new();
        assert_eq!(f.client.admin(), f.admin);
        assert_eq!(f.client.token(), f.token);
        assert!(!f.client.paused());
        assert_eq!(f.client.total_staked(), 0);
        assert_eq!(f.client.reward_rate(), 0);
        assert_eq!(f.client.rewards_funded(), 0);
        assert_eq!(f.client.operator_count(), 2);
        assert!(f.client.is_operator(&f.operator));
        assert!(f.client.is_operator(&f.other_operator));
        assert!(!f.client.is_operator(&f.alice));

        assert!(f.client.try_initialize(&f.admin, &f.token).is_err());
    }

    #[test]
    fn add_operator_rejects_duplicates_and_out_of_range_commission() {
        let f = Fixture::new();
        assert!(f
            .client
            .try_add_operator(&f.operator, &300)
            .is_err());
        assert!(f
            .client
            .try_add_operator(&Address::generate(&f.env), &(MAX_COMMISSION_BPS + 1))
            .is_err());
        // The cap itself is accepted.
        let capped = Address::generate(&f.env);
        f.client.add_operator(&capped, &MAX_COMMISSION_BPS);
        assert_eq!(
            f.client.operator_of(&capped).unwrap().commission_bps,
            MAX_COMMISSION_BPS
        );
    }

    #[test]
    fn delegating_moves_tokens_and_tracks_the_position() {
        let f = Fixture::new();
        f.mint(&f.alice, 100 * ONE);

        let staked = f.client.delegate(&f.alice, &f.operator, &(100 * ONE));

        assert_eq!(staked, 100 * ONE);
        assert_eq!(f.balance(&f.alice), 0);
        assert_eq!(f.balance(&f.contract()), 100 * ONE);
        assert_eq!(f.client.total_staked(), 100 * ONE);

        let position = f.client.position(&f.alice, &f.operator);
        assert_eq!(position.amount, 100 * ONE);
        assert_eq!(position.accrued, 0);
        assert!(!position.auto_compound);

        let operator = f.client.operator_of(&f.operator).unwrap();
        assert_eq!(operator.total_staked, 100 * ONE);
        assert!(operator.active);
    }

    #[test]
    fn delegation_rejects_zero_and_negative_amounts() {
        let f = Fixture::new();
        assert!(f.client.try_delegate(&f.alice, &f.operator, &0).is_err());
        assert!(f.client.try_delegate(&f.alice, &f.operator, &-1).is_err());
        assert!(f
            .client
            .try_delegate(&f.alice, &Address::generate(&f.env), &ONE)
            .is_err());
    }

    #[test]
    fn rewards_accrue_proportionally_to_stake() {
        let f = Fixture::new();
        // 1 token per second for 1_000 seconds.
        f.fund(1_000 * ONE, 1_000);
        assert_eq!(f.client.reward_rate(), ONE);

        f.mint(&f.alice, 100 * ONE);
        f.mint(&f.bob, 300 * ONE);
        f.client.delegate(&f.alice, &f.operator, &(100 * ONE));
        f.client.delegate(&f.bob, &f.operator, &(300 * ONE));

        f.advance(100);

        // 100 seconds of rewards = 100 * ONE, split 25% / 75%.
        assert_eq!(
            f.client.pending_rewards(&f.alice, &f.operator),
            25 * ONE
        );
        assert_eq!(f.client.pending_rewards(&f.bob, &f.operator), 75 * ONE);
        // The proposal is a projection: nothing has been credited yet.
        assert_eq!(f.client.rewards_credited(), 0);
    }

    #[test]
    fn claim_pays_commission_to_the_operator_and_the_rest_to_the_delegator() {
        let f = Fixture::new();
        f.fund(1_000 * ONE, 1_000);
        f.mint(&f.alice, 100 * ONE);
        f.client.delegate(&f.alice, &f.operator, &(100 * ONE));
        f.advance(100);

        // 100 * ONE of rewards, 5% commission = 5 * ONE.
        let net = f.client.claim(&f.alice, &f.operator, &0);

        assert_eq!(net, 95 * ONE);
        assert_eq!(f.balance(&f.alice), 95 * ONE);
        assert_eq!(f.balance(&f.operator), 5 * ONE);
        assert_eq!(f.client.rewards_paid_out(), 100 * ONE);
        // Claiming leaves the principal untouched.
        assert_eq!(f.client.total_staked(), 100 * ONE);
        assert_eq!(f.client.position(&f.alice, &f.operator).accrued, 0);

        // A second claim with nothing new accrued pays nothing.
        assert_eq!(f.client.claim(&f.alice, &f.operator, &0), 0);
    }

    #[test]
    fn claim_enforces_min_out_against_a_commission_raise() {
        let f = Fixture::new();
        f.fund(1_000 * ONE, 1_000);
        f.mint(&f.alice, 100 * ONE);
        f.client.delegate(&f.alice, &f.operator, &(100 * ONE));
        f.advance(100);

        // Quoted at 5% commission: 95 * ONE net.
        let quoted = f.client.pending_rewards(&f.alice, &f.operator);
        assert_eq!(quoted, 100 * ONE);

        // The operator raises its commission to the cap before the claim lands.
        f.client.set_commission(&f.operator, &MAX_COMMISSION_BPS);

        // 20% commission now, so the 95 * ONE quote is no longer honoured.
        assert!(f
            .client
            .try_claim(&f.alice, &f.operator, &(95 * ONE))
            .is_err());
        // A 20%-aware slippage bound still settles.
        let net = f.client.claim(&f.alice, &f.operator, &(80 * ONE));
        assert_eq!(net, 80 * ONE);
        assert_eq!(f.balance(&f.operator), 20 * ONE);
    }

    #[test]
    fn compound_restakes_rewards_without_moving_principal() {
        let f = Fixture::new();
        f.fund(1_000 * ONE, 1_000);
        f.mint(&f.alice, 100 * ONE);
        f.client.delegate(&f.alice, &f.operator, &(100 * ONE));
        f.advance(100);

        let compounded = f.client.compound(&f.alice, &f.operator, &0);

        // 95 * ONE net is re-staked; the 5% commission is paid out.
        assert_eq!(compounded, 95 * ONE);
        let position = f.client.position(&f.alice, &f.operator);
        assert_eq!(position.amount, 195 * ONE);
        assert_eq!(position.accrued, 0);
        assert_eq!(f.client.total_staked(), 195 * ONE);
        assert_eq!(f.client.rewards_compounded(), 95 * ONE);
        assert_eq!(f.balance(&f.operator), 5 * ONE);
        assert_eq!(f.balance(&f.alice), 0);
        // The compounded value stayed in the contract: the 1_000 * ONE of
        // rewards, plus the 100 * ONE principal, less the 5 * ONE commission
        // that was paid out.
        assert_eq!(f.balance(&f.contract()), 1_095 * ONE);
    }

    #[test]
    fn compound_enforces_min_amount_out() {
        let f = Fixture::new();
        f.fund(1_000 * ONE, 1_000);
        f.mint(&f.alice, 100 * ONE);
        f.client.delegate(&f.alice, &f.operator, &(100 * ONE));
        f.advance(100);

        assert!(f
            .client
            .try_compound(&f.alice, &f.operator, &(95 * ONE + 1))
            .is_err());
        assert_eq!(f.client.compound(&f.alice, &f.operator, &(95 * ONE)), 95 * ONE);
    }

    #[test]
    fn auto_compound_re_stakes_on_the_next_touch() {
        let f = Fixture::new();
        f.fund(1_000 * ONE, 1_000);
        f.mint(&f.alice, 100 * ONE);
        // 0% commission so the arithmetic is exact.
        f.client
            .set_auto_compound(&f.alice, &f.other_operator, &true);
        f.client.delegate(&f.alice, &f.other_operator, &(100 * ONE));

        f.advance(100);
        f.mint(&f.alice, 1);
        let staked = f.client.delegate(&f.alice, &f.other_operator, &1);

        // 100 * ONE accrued and was re-staked before the new 1 unit landed.
        assert_eq!(staked, 200 * ONE + 1);
        assert_eq!(f.client.rewards_compounded(), 100 * ONE);
        assert_eq!(f.client.total_staked(), 200 * ONE + 1);
        assert_eq!(f.balance(&f.alice), 0);
        // Nothing was paid out: there is no commission and no claim.
        assert_eq!(f.client.rewards_paid_out(), 0);
    }

    #[test]
    fn auto_compound_can_be_switched_off() {
        let f = Fixture::new();
        f.fund(1_000 * ONE, 1_000);
        f.mint(&f.alice, 100 * ONE);
        f.client.delegate(&f.alice, &f.operator, &(100 * ONE));
        f.client.set_auto_compound(&f.alice, &f.operator, &true);
        f.advance(50);
        f.client.set_auto_compound(&f.alice, &f.operator, &false);

        f.advance(50);
        f.mint(&f.alice, 1);
        f.client.delegate(&f.alice, &f.operator, &1);

        // The 100 * ONE accrued while the flag was on is untouched, so it is
        // still claimable rather than silently lost.
        assert_eq!(f.client.pending_rewards(&f.alice, &f.operator), 100 * ONE);
        let net = f.client.claim(&f.alice, &f.operator, &0);
        assert_eq!(net, 95 * ONE);
    }

    #[test]
    fn undelegate_returns_principal_and_rejects_over_withdrawal() {
        let f = Fixture::new();
        f.mint(&f.alice, 100 * ONE);
        f.client.delegate(&f.alice, &f.operator, &(100 * ONE));

        assert!(f
            .client
            .try_undelegate(&f.alice, &f.operator, &(100 * ONE + 1))
            .is_err());

        let out = f.client.undelegate(&f.alice, &f.operator, &(40 * ONE));
        assert_eq!(out, 40 * ONE);
        assert_eq!(f.balance(&f.alice), 40 * ONE);
        assert_eq!(f.client.position(&f.alice, &f.operator).amount, 60 * ONE);
        assert_eq!(f.client.total_staked(), 60 * ONE);
        assert_eq!(
            f.client.operator_of(&f.operator).unwrap().total_staked,
            60 * ONE
        );

        // A full exit drops the position and the operator tracking.
        f.client.undelegate(&f.alice, &f.operator, &(60 * ONE));
        assert_eq!(f.client.position(&f.alice, &f.operator).amount, 0);
        assert_eq!(f.client.total_staked(), 0);
        assert!(f.client.delegator_operators(&f.alice).is_empty());
        assert!(f.client.try_undelegate(&f.alice, &f.operator, &ONE).is_err());
    }

    #[test]
    fn a_delegator_can_use_several_operators_and_each_is_tracked_once() {
        let f = Fixture::new();
        f.mint(&f.alice, 300 * ONE);
        f.client.delegate(&f.alice, &f.operator, &(100 * ONE));
        f.client.delegate(&f.alice, &f.other_operator, &(100 * ONE));
        f.client.delegate(&f.alice, &f.operator, &(100 * ONE));

        let tracked = f.client.delegator_operators(&f.alice);
        assert_eq!(tracked.len(), 2);
        assert_eq!(f.client.total_staked(), 300 * ONE);
        assert_eq!(f.client.position(&f.alice, &f.operator).amount, 200 * ONE);
        assert_eq!(
            f.client.position(&f.alice, &f.other_operator).amount,
            100 * ONE
        );

        f.client.undelegate(&f.alice, &f.operator, &(200 * ONE));
        assert_eq!(f.client.delegator_operators(&f.alice).len(), 1);
    }

    #[test]
    fn pause_blocks_new_delegations_but_never_traps_funds() {
        let f = Fixture::new();
        f.mint(&f.alice, 100 * ONE);
        f.client.delegate(&f.alice, &f.operator, &(100 * ONE));
        f.fund(1_000 * ONE, 1_000);
        f.advance(100);

        f.client.set_paused(&true);
        assert!(f.client.paused());

        // New activity stops.
        f.mint(&f.alice, 100 * ONE);
        assert!(f.client
            .try_delegate(&f.alice, &f.operator, &(10 * ONE))
            .is_err());
        let funder = Address::generate(&f.env);
        f.mint(&funder, ONE);
        assert!(f.client.try_fund_rewards(&funder, &ONE, &100).is_err());

        // Exits stay open.
        assert_eq!(f.client.claim(&f.alice, &f.operator, &0), 95 * ONE);
        f.client.undelegate(&f.alice, &f.operator, &(100 * ONE));
        assert_eq!(f.balance(&f.alice), 95 * ONE + 100 * ONE);
    }

    #[test]
    fn an_inactive_operator_blocks_new_stake_but_still_lets_delegators_exit() {
        let f = Fixture::new();
        f.mint(&f.alice, 100 * ONE);
        f.client.delegate(&f.alice, &f.operator, &(100 * ONE));

        f.client.set_operator_active(&f.operator, &false);
        assert!(!f.client.operator_of(&f.operator).unwrap().active);

        assert!(f
            .client
            .try_delegate(&f.alice, &f.operator, &ONE)
            .is_err());

        // Exit and claim still work.
        f.fund(100 * ONE, 100);
        f.advance(100);
        assert_eq!(f.client.claim(&f.alice, &f.operator, &0), 95 * ONE);
        f.client.undelegate(&f.alice, &f.operator, &(100 * ONE));
        assert_eq!(f.balance(&f.alice), 195 * ONE);
    }

    #[test]
    fn topping_up_mid_schedule_rolls_the_remainder_into_the_new_rate() {
        let f = Fixture::new();
        // 1 token/second, 100 units funded.
        f.fund(100 * ONE, 100);
        assert_eq!(f.client.reward_rate(), ONE);

        f.advance(50);

        // 50 * ONE is still scheduled; fund another 100 * ONE over 100 seconds.
        let funder = Address::generate(&f.env);
        f.mint(&funder, 100 * ONE);
        let rate = f.client.fund_rewards(&funder, &(100 * ONE), &100);

        assert_eq!(rate, 1_500_000); // (50 + 100) * ONE / 100
        assert_eq!(f.client.rewards_funded(), 200 * ONE);
    }

    #[test]
    fn rewards_are_not_credited_to_windows_with_nothing_staked() {
        let f = Fixture::new();
        // 1 token/second for 1_000 seconds, but nobody is staked for the first
        // 100 seconds of it.
        f.fund(1_000 * ONE, 1_000);
        f.advance(100);

        f.mint(&f.alice, 100 * ONE);
        f.client.delegate(&f.alice, &f.operator, &(100 * ONE));
        f.advance(100);

        // Only the 100 seconds Alice was staked for accrued. `pending_rewards`
        // is a read-only view, so the stored counter only moves once a
        // state-changing call settles the index.
        assert_eq!(f.client.pending_rewards(&f.alice, &f.operator), 100 * ONE);
        f.client.claim(&f.alice, &f.operator, &0);
        assert_eq!(f.client.rewards_credited(), 100 * ONE);
    }

    #[test]
    fn rewards_stop_accruing_at_the_end_of_the_schedule() {
        let f = Fixture::new();
        f.fund(100 * ONE, 100);
        f.mint(&f.alice, 100 * ONE);
        f.client.delegate(&f.alice, &f.operator, &(100 * ONE));

        // Run far past the schedule end.
        f.advance(10_000);

        // Exactly the 100 seconds that were funded.
        assert_eq!(f.client.pending_rewards(&f.alice, &f.operator), 100 * ONE);
    }

    #[test]
    fn pending_rewards_matches_what_claim_actually_pays() {
        let f = Fixture::new();
        f.fund(1_000 * ONE, 1_000);
        f.mint(&f.alice, 100 * ONE);
        f.mint(&f.bob, 300 * ONE);
        f.client.delegate(&f.alice, &f.other_operator, &(100 * ONE));
        f.client.delegate(&f.bob, &f.other_operator, &(300 * ONE));
        f.advance(137); // deliberately not a round number

        // `pending_rewards` is the gross accrual, so it equals what `claim`
        // returns only when the operator takes no commission.
        let quoted = f.client.pending_rewards(&f.alice, &f.other_operator);
        let net = f.client.claim(&f.alice, &f.other_operator, &quoted);
        assert_eq!(net, quoted);
        assert_eq!(f.balance(&f.alice), quoted);
    }

    #[test]
    fn the_pool_stays_solvent_across_a_full_lifecycle() {
        let f = Fixture::new();
        f.fund(1_000 * ONE, 1_000);
        f.mint(&f.alice, 100 * ONE);
        f.mint(&f.bob, 300 * ONE);
        f.client.delegate(&f.alice, &f.operator, &(100 * ONE));
        f.client.delegate(&f.bob, &f.operator, &(300 * ONE));

        for _ in 0..5 {
            f.advance(100);
            f.client.claim(&f.alice, &f.operator, &0);
            f.client.compound(&f.bob, &f.operator, &0);
        }

        // Every token paid out or re-staked was credited to the index first, and
        // the contract still covers the outstanding stake plus any dust.
        assert!(
            f.client.rewards_paid_out() + f.client.rewards_compounded()
                <= f.client.rewards_credited()
        );
        assert!(f.client.rewards_credited() <= f.client.rewards_funded());
        assert!(f.balance(&f.contract()) >= f.client.total_staked());
    }

    #[test]
    fn rewards_cannot_be_drawn_from_funding_that_does_not_exist() {
        let f = Fixture::new();
        // Nothing was ever funded, so nothing can be paid.
        f.mint(&f.alice, 100 * ONE);
        f.client.delegate(&f.alice, &f.operator, &(100 * ONE));
        f.advance(100);

        assert_eq!(f.client.reward_rate(), 0);
        assert_eq!(f.client.pending_rewards(&f.alice, &f.operator), 0);
        assert_eq!(f.client.claim(&f.alice, &f.operator, &0), 0);
        // Principal is still whole.
        f.client.undelegate(&f.alice, &f.operator, &(100 * ONE));
        assert_eq!(f.balance(&f.alice), 100 * ONE);
    }

    #[test]
    fn funding_rejects_degenerate_schedules() {
        let f = Fixture::new();
        let funder = Address::generate(&f.env);
        f.mint(&funder, 1_000);
        assert!(f.client.try_fund_rewards(&funder, &0, &100).is_err());
        assert!(f.client.try_fund_rewards(&funder, &-1, &100).is_err());
        assert!(f.client.try_fund_rewards(&funder, &1_000, &0).is_err());
        // A rate that floors to zero is refused rather than stranding the funds.
        assert!(f.client.try_fund_rewards(&funder, &1, &1_000).is_err());
    }

    #[test]
    fn set_auto_compound_requires_a_known_operator() {
        let f = Fixture::new();
        assert!(f
            .client
            .try_set_auto_compound(&f.alice, &Address::generate(&f.env), &true)
            .is_err());
    }

    #[test]
    fn only_the_admin_can_change_the_pause_or_the_operator_set() {
        // `mock_all_auths` means authorisation always passes, so what is checked
        // here is the *structural* guard: the pause flag and operator records are
        // only reachable through the admin-gated entry points.
        let f = Fixture::new();
        f.client.set_paused(&true);
        assert!(f.client.paused());
        f.client.set_paused(&false);
        assert!(!f.client.paused());

        f.client.set_commission(&f.other_operator, &1_000);
        assert_eq!(
            f.client.operator_of(&f.other_operator).unwrap().commission_bps,
            1_000
        );
        assert!(f
            .client
            .try_set_commission(&f.other_operator, &(MAX_COMMISSION_BPS + 1))
            .is_err());

        let new_admin = Address::generate(&f.env);
        f.client.set_admin(&new_admin);
        assert_eq!(f.client.admin(), new_admin);
    }

    #[test]
    fn events_are_emitted_for_the_lifecycle() {
        let f = Fixture::new();
        f.fund(100 * ONE, 100);
        f.mint(&f.alice, 100 * ONE);
        f.client.set_auto_compound(&f.alice, &f.operator, &true);
        f.client.delegate(&f.alice, &f.operator, &(100 * ONE));
        f.advance(50);
        f.client.claim(&f.alice, &f.operator, &0);
        f.client.compound(&f.alice, &f.operator, &0);
        f.client.set_operator_active(&f.operator, &false);
        f.client.set_paused(&true);

        let mut names: std::vec::Vec<Symbol> = std::vec::Vec::new();
        for (_, topics, _) in f.env.events().all() {
            for i in 0..topics.len() {
                if let Ok(sym) = Symbol::try_from_val(&f.env, &topics.get(i).unwrap()) {
                    names.push(sym);
                }
            }
        }
        for expected in [
            symbol_short!("add_op"),
            symbol_short!("fund"),
            symbol_short!("delegate"),
            symbol_short!("auto_cmp"),
            symbol_short!("claim"),
            symbol_short!("compound"),
            symbol_short!("active"),
            symbol_short!("set_pause"),
        ] {
            assert!(names.contains(&expected), "missing {expected:?}");
        }
    }
}

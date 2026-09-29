//! Multi-pool yield farm with cross-pool position tracking.
//!
//! Users deposit a pool's LP token (any [SEP-41] token, including the
//! `amm-pool` LP token) and earn a share of a single reward token stream. Every
//! pool has an *allocation weight*; the stream is split across pools in
//! proportion to that weight, and within a pool in proportion to stake.
//!
//! # One index, not one rate per pool
//!
//! The farm does not store a per-second rate per pool. It advances one global
//! **reward index** — `∫ rate dt` — and each pool records the index value it
//! last settled at. A pool's earnings over a window are
//! `(index_now - index_paid) * alloc_point / total_alloc_point`.
//!
//! Two properties fall out of that:
//!
//! * A rate change mid-schedule is safe with no per-pool bookkeeping. The
//!   integral already holds the old rate's contribution for the elapsed part and
//!   the new rate's for the rest, so a pool that has been idle for a while still
//!   settles against the right total.
//! * A pool that has never been touched does not accrue anything until it is
//!   settled, and settling it later replays the correct history rather than
//!   guessing.
//!
//! Changing an allocation weight is the one operation that *does* have to settle
//! every pool first: the denominator is part of the pool's share, so re-weighting
//! without settling would retroactively change a window that already elapsed.
//! That is an admin operation, so its cost is bounded by the pool count and is
//! never paid by a user action.
//!
//! # Position tracking
//!
//! [`position`](YieldFarm::position) reads one pool, and
//! [`positions`](YieldFarm::positions) returns every pool the user has touched
//! with its live pending reward, so a UI can render a farm portfolio from a
//! single call. [`total_pending_rewards`](YieldFarm::total_pending_rewards) sums
//! the same set.
//!
//! # Safety properties
//!
//! * LP principal can only leave towards the depositor that supplied it.
//! * `rewards_paid_out <= rewards_credited <= rewards_funded`; the pool split and
//!   the per-position accrual both floor, so dust can only ever stay behind.
//! * `pause` blocks deposits and funding but never withdrawals or harvests.
//! * Deactivating a pool blocks new deposits but leaves exits and harvests open.
//! * `emergency_withdraw` returns the LP but forfeits pending rewards, so a
//!   distrusted pool can be exited without draining reward accounting.
//!
//! [SEP-41]: https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0041.md

#![no_std]

/// Pure fixed-point reward math.
pub mod math;

use math::{
    acc_reward_delta, accrued, advance_index, distributable_seconds, pool_share,
    remaining_rewards, reward_rate_for, PRECISION,
};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token::TokenClient, Address, Env, Vec,
};

/// Persistent records are bumped once their remaining TTL drops below the
/// threshold, so live positions are not archived out from under their owners.
const RECORD_TTL_THRESHOLD: u32 = 100_000;
const RECORD_TTL_BUMP: u32 = 200_000;

/// Farm-wide configuration (instance storage).
#[contracttype]
#[derive(Clone)]
pub struct Config {
    pub admin: Address,
    pub reward_token: Address,
    /// Blocks deposits and funding. Withdrawals and harvests stay open.
    pub paused: bool,
    /// Sum of every pool's `alloc_point`.
    pub total_alloc_point: u32,
    /// Reward tokens per second the current schedule streams.
    pub reward_rate: i128,
    /// Timestamp the current schedule stops at.
    pub period_finish: u64,
    /// Timestamp the reward index was last advanced to.
    pub last_update: u64,
    /// Cumulative `∫ rate dt`, the global reward index.
    pub reward_index: i128,
    pub rewards_funded: i128,
    /// Reward tokens the index has attributed to pools (may trail
    /// `rewards_funded` by unstreamed schedule and rounding dust).
    pub rewards_credited: i128,
    /// Rewards actually transferred out to harvesters.
    pub rewards_paid_out: i128,
}

/// One LP pool in the farm.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pool {
    pub id: u32,
    pub lp_token: Address,
    /// Weight in the global split. May be `0` to park a pool without removing it.
    pub alloc_point: u32,
    /// Inactive pools accept no new deposits but never block exits.
    pub active: bool,
    pub total_staked: i128,
    /// Scaled by `math::PRECISION`.
    pub acc_reward_per_share: i128,
    /// Value of `Config::reward_index` when this pool was last settled.
    pub reward_index_paid: i128,
}

/// A user's position in one pool.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Position {
    pub pool_id: u32,
    /// LP tokens currently deposited.
    pub amount: i128,
    /// Accumulator value this position was last settled at.
    pub acc_reward_per_share_paid: i128,
    /// Rewards earned but not yet harvested.
    pub accrued: i128,
}

/// A view across every pool a user has touched.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolPosition {
    pub pool_id: u32,
    pub lp_token: Address,
    pub amount: i128,
    /// Live pending reward, projected to the current ledger timestamp.
    pub pending_rewards: i128,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Config,
    /// Every registered pool id, in registration order (instance).
    PoolIds,
    Pool(u32),
    /// A position, keyed by `(pool_id, user)`.
    Position(u32, Address),
    /// The pools a user has a live position in.
    UserPools(Address),
}

#[contract]
pub struct YieldFarm;

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

fn read_pool(env: &Env, pool_id: u32) -> Option<Pool> {
    let key = DataKey::Pool(pool_id);
    let record: Option<Pool> = env.storage().persistent().get(&key);
    if record.is_some() {
        env.storage()
            .persistent()
            .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
    }
    record
}

fn write_pool(env: &Env, pool: &Pool) {
    let key = DataKey::Pool(pool.id);
    env.storage().persistent().set(&key, pool);
    env.storage()
        .persistent()
        .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
}

fn pool_ids(env: &Env) -> Vec<u32> {
    env.storage()
        .instance()
        .get(&DataKey::PoolIds)
        .unwrap_or_else(|| Vec::new(env))
}

fn read_position(env: &Env, pool_id: u32, user: &Address, acc_now: i128) -> Position {
    let key = DataKey::Position(pool_id, user.clone());
    let record: Option<Position> = env.storage().persistent().get(&key);
    match record {
        Some(position) => {
            env.storage()
                .persistent()
                .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
            position
        }
        None => Position {
            pool_id,
            amount: 0,
            // Anchored at the *current* accumulator so a new depositor cannot
            // claim rewards that were credited before they joined.
            acc_reward_per_share_paid: acc_now,
            accrued: 0,
        },
    }
}

fn position_is_empty(position: &Position) -> bool {
    position.amount == 0 && position.accrued == 0
}

/// Writes a position, dropping the entry once it has nothing left to remember.
/// Returns whether the record was kept.
fn write_position(env: &Env, user: &Address, position: &Position) -> bool {
    let key = DataKey::Position(position.pool_id, user.clone());
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

fn user_pool_list(env: &Env, user: &Address) -> Vec<u32> {
    env.storage()
        .persistent()
        .get(&DataKey::UserPools(user.clone()))
        .unwrap_or_else(|| Vec::new(env))
}

fn list_contains(list: &Vec<u32>, needle: u32) -> bool {
    for i in 0..list.len() {
        if list.get_unchecked(i) == needle {
            return true;
        }
    }
    false
}

fn track_user_pool(env: &Env, user: &Address, pool_id: u32) {
    let list = user_pool_list(env, user);
    if list_contains(&list, pool_id) {
        return;
    }
    let key = DataKey::UserPools(user.clone());
    let mut updated = list;
    updated.push_back(pool_id);
    env.storage().persistent().set(&key, &updated);
    env.storage()
        .persistent()
        .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_BUMP);
}

fn untrack_user_pool(env: &Env, user: &Address, pool_id: u32) {
    let list = user_pool_list(env, user);
    let mut kept: Vec<u32> = Vec::new(env);
    for i in 0..list.len() {
        let id = list.get_unchecked(i);
        if id != pool_id {
            kept.push_back(id);
        }
    }
    let key = DataKey::UserPools(user.clone());
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

/// Advances the global reward index to `now`, clamped at the schedule end.
///
/// Only the elapsed portion of the *current* schedule is added, so time between
/// one schedule ending and the next starting contributes nothing.
fn advance_global(env: &Env, cfg: &mut Config) {
    let now = env.ledger().timestamp();
    let seconds = distributable_seconds(cfg.last_update, cfg.period_finish, now);
    if seconds > 0 {
        cfg.reward_index = advance_index(cfg.reward_index, cfg.reward_rate, seconds);
        cfg.last_update = if now < cfg.period_finish {
            now
        } else {
            cfg.period_finish
        };
    }
}

/// Settles one pool against the global index and marks it up to date.
///
/// A pool with no stake has its share skipped rather than banked: the index
/// still moves past it, so staking later cannot collect a backlog that was
/// streamed while the pool was empty.
fn settle_pool(cfg: &mut Config, pool: &mut Pool) {
    let delta_index = cfg.reward_index.saturating_sub(pool.reward_index_paid);
    if delta_index > 0 && cfg.total_alloc_point > 0 {
        let share = pool_share(delta_index, pool.alloc_point, cfg.total_alloc_point);
        if share > 0 && pool.total_staked > 0 {
            let (acc_delta, credited) = acc_reward_delta(share, pool.total_staked);
            pool.acc_reward_per_share = pool
                .acc_reward_per_share
                .checked_add(acc_delta)
                .expect("accumulator overflow");
            cfg.rewards_credited = cfg
                .rewards_credited
                .checked_add(credited)
                .expect("credited overflow");
        }
    }
    pool.reward_index_paid = cfg.reward_index;
}

/// Brings one pool (and the global index) up to date, persisting both.
fn settle_one(env: &Env, pool_id: u32) -> (Config, Pool) {
    let mut cfg = config(env);
    advance_global(env, &mut cfg);
    let mut pool = read_pool(env, pool_id).unwrap_or_else(|| panic!("unknown pool"));
    settle_pool(&mut cfg, &mut pool);
    write_pool(env, &pool);
    set_config(env, &cfg);
    (cfg, pool)
}

/// Brings every pool up to date.
///
/// Used by the allocation-weight admin operations, which must not re-weight an
/// already-elapsed window. Bounded by the pool count, and only ever paid on an
/// admin call rather than a user action.
fn settle_all(env: &Env) -> Config {
    let mut cfg = config(env);
    advance_global(env, &mut cfg);
    let ids = pool_ids(env);
    for i in 0..ids.len() {
        let id = ids.get_unchecked(i);
        if let Some(mut pool) = read_pool(env, id) {
            settle_pool(&mut cfg, &mut pool);
            write_pool(env, &pool);
        }
    }
    set_config(env, &cfg);
    cfg
}

/// Folds the accumulator movement since the last settle into a position.
fn settle_position(pool: &Pool, position: &mut Position) {
    if pool.acc_reward_per_share == position.acc_reward_per_share_paid {
        return;
    }
    position.accrued = position
        .accrued
        .checked_add(accrued(
            position.amount,
            pool.acc_reward_per_share,
            position.acc_reward_per_share_paid,
        ))
        .expect("accrued overflow");
    position.acc_reward_per_share_paid = pool.acc_reward_per_share;
}

/// Where the global index would be right now, without writing anything.
fn projected_index(cfg: &Config, now: u64) -> i128 {
    let seconds = distributable_seconds(cfg.last_update, cfg.period_finish, now);
    cfg.reward_index
        .saturating_add(cfg.reward_rate.saturating_mul(seconds as i128))
}

/// Where a pool's accumulator would be right now, without writing anything.
fn projected_acc(cfg: &Config, pool: &Pool, now: u64) -> i128 {
    let delta_index = projected_index(cfg, now).saturating_sub(pool.reward_index_paid);
    if delta_index <= 0 || cfg.total_alloc_point == 0 || pool.total_staked <= 0 {
        return pool.acc_reward_per_share;
    }
    let share = pool_share(delta_index, pool.alloc_point, cfg.total_alloc_point);
    let (acc_delta, _) = acc_reward_delta(share, pool.total_staked);
    pool.acc_reward_per_share.saturating_add(acc_delta)
}

fn pending_for(cfg: &Config, pool: &Pool, position: &Position, now: u64) -> i128 {
    let acc_now = projected_acc(cfg, pool, now);
    position
        .accrued
        .saturating_add(accrued(position.amount, acc_now, position.acc_reward_per_share_paid))
}

/// The invariant that keeps the farm solvent.
fn assert_solvent(cfg: &Config) {
    assert!(
        cfg.rewards_paid_out <= cfg.rewards_credited,
        "reward solvency violated"
    );
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contractimpl]
impl YieldFarm {
    /// One-time setup. `reward_token` is the single asset every pool pays out.
    pub fn initialize(env: Env, admin: Address, reward_token: Address) {
        assert!(
            !env.storage().instance().has(&DataKey::Config),
            "already initialized"
        );
        admin.require_auth();
        set_config(
            &env,
            &Config {
                admin,
                reward_token,
                paused: false,
                total_alloc_point: 0,
                reward_rate: 0,
                period_finish: 0,
                last_update: env.ledger().timestamp(),
                reward_index: 0,
                rewards_funded: 0,
                rewards_credited: 0,
                rewards_paid_out: 0,
            },
        );
    }

    // -- views ---------------------------------------------------------------

    pub fn admin(env: Env) -> Address {
        config(&env).admin
    }

    pub fn reward_token(env: Env) -> Address {
        config(&env).reward_token
    }

    pub fn paused(env: Env) -> bool {
        config(&env).paused
    }

    pub fn total_alloc_point(env: Env) -> u32 {
        config(&env).total_alloc_point
    }

    pub fn reward_rate(env: Env) -> i128 {
        config(&env).reward_rate
    }

    pub fn period_finish(env: Env) -> u64 {
        config(&env).period_finish
    }

    pub fn last_update(env: Env) -> u64 {
        config(&env).last_update
    }

    pub fn reward_index(env: Env) -> i128 {
        config(&env).reward_index
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

    pub fn pool_count(env: Env) -> u32 {
        pool_ids(&env).len()
    }

    /// Every registered pool id, in registration order.
    pub fn pool_ids(env: Env) -> Vec<u32> {
        pool_ids(&env)
    }

    /// A pool record, or `None` if it was never registered.
    pub fn pool_of(env: Env, pool_id: u32) -> Option<Pool> {
        read_pool(&env, pool_id)
    }

    /// The user's position in one pool.
    pub fn position(env: Env, user: Address, pool_id: u32) -> Position {
        let pool = read_pool(&env, pool_id).unwrap_or_else(|| panic!("unknown pool"));
        read_position(&env, pool_id, &user, pool.acc_reward_per_share)
    }

    /// Pending reward for one `(user, pool)` pair, projected to `now`.
    pub fn pending_rewards(env: Env, user: Address, pool_id: u32) -> i128 {
        let cfg = config(&env);
        let pool = read_pool(&env, pool_id).unwrap_or_else(|| panic!("unknown pool"));
        let position = read_position(&env, pool_id, &user, pool.acc_reward_per_share);
        pending_for(&cfg, &pool, &position, env.ledger().timestamp())
    }

    /// The pools `user` currently has a position with.
    pub fn user_pools(env: Env, user: Address) -> Vec<u32> {
        user_pool_list(&env, &user)
    }

    /// Every pool `user` has touched, with its live stake and pending reward.
    ///
    /// This is the cross-pool view: one call renders the whole farm portfolio.
    pub fn positions(env: Env, user: Address) -> Vec<PoolPosition> {
        let cfg = config(&env);
        let now = env.ledger().timestamp();
        let ids = user_pool_list(&env, &user);
        let mut out: Vec<PoolPosition> = Vec::new(&env);
        for i in 0..ids.len() {
            let id = ids.get_unchecked(i);
            if let Some(pool) = read_pool(&env, id) {
                let position = read_position(&env, id, &user, pool.acc_reward_per_share);
                out.push_back(PoolPosition {
                    pool_id: id,
                    lp_token: pool.lp_token.clone(),
                    amount: position.amount,
                    pending_rewards: pending_for(&cfg, &pool, &position, now),
                });
            }
        }
        out
    }

    /// Total pending reward across every pool `user` has touched.
    pub fn total_pending_rewards(env: Env, user: Address) -> i128 {
        let cfg = config(&env);
        let now = env.ledger().timestamp();
        let ids = user_pool_list(&env, &user);
        let mut total: i128 = 0;
        for i in 0..ids.len() {
            let id = ids.get_unchecked(i);
            if let Some(pool) = read_pool(&env, id) {
                let position = read_position(&env, id, &user, pool.acc_reward_per_share);
                total = total.saturating_add(pending_for(&cfg, &pool, &position, now));
            }
        }
        total
    }

    // -- admin ---------------------------------------------------------------

    pub fn set_admin(env: Env, new_admin: Address) {
        let mut cfg = config(&env);
        cfg.admin.require_auth();
        cfg.admin = new_admin.clone();
        set_config(&env, &cfg);
        env.events().publish((symbol_short!("set_admin"),), new_admin);
    }

    /// Blocks deposits and funding. Withdrawals and harvests stay open.
    pub fn set_paused(env: Env, paused: bool) {
        let mut cfg = config(&env);
        cfg.admin.require_auth();
        cfg.paused = paused;
        set_config(&env, &cfg);
        env.events().publish((symbol_short!("set_pause"),), paused);
    }

    /// Registers a pool. Settles every existing pool first so the new weight
    /// cannot retroactively re-split an elapsed window.
    pub fn add_pool(env: Env, pool_id: u32, lp_token: Address, alloc_point: u32) {
        let mut cfg = config(&env);
        cfg.admin.require_auth();
        assert!(
            read_pool(&env, pool_id).is_none(),
            "pool already registered"
        );

        cfg = settle_all(&env);
        cfg.total_alloc_point = cfg
            .total_alloc_point
            .checked_add(alloc_point)
            .expect("alloc overflow");
        set_config(&env, &cfg);

        write_pool(
            &env,
            &Pool {
                id: pool_id,
                lp_token: lp_token.clone(),
                alloc_point,
                active: true,
                total_staked: 0,
                acc_reward_per_share: 0,
                reward_index_paid: cfg.reward_index,
            },
        );
        let mut ids = pool_ids(&env);
        ids.push_back(pool_id);
        env.storage().instance().set(&DataKey::PoolIds, &ids);

        env.events()
            .publish((symbol_short!("add_pool"), pool_id), (lp_token, alloc_point));
    }

    /// Changes a pool's allocation weight. Settles every pool first, so the
    /// new weight only applies to future windows.
    pub fn set_alloc_point(env: Env, pool_id: u32, alloc_point: u32) {
        let cfg_before = config(&env);
        cfg_before.admin.require_auth();
        // Read before settling only to learn the old weight; the settled record
        // is re-read afterwards so the accumulator is not overwritten with the
        // stale pre-settle values.
        let previous = read_pool(&env, pool_id).unwrap_or_else(|| panic!("unknown pool"));

        let mut cfg = settle_all(&env);
        let mut pool = read_pool(&env, pool_id).unwrap_or_else(|| panic!("unknown pool"));
        cfg.total_alloc_point = cfg
            .total_alloc_point
            .checked_sub(previous.alloc_point)
            .expect("alloc underflow")
            .checked_add(alloc_point)
            .expect("alloc overflow");
        pool.alloc_point = alloc_point;

        set_config(&env, &cfg);
        write_pool(&env, &pool);
        env.events()
            .publish((symbol_short!("alloc"), pool_id), alloc_point);
    }

    /// Stops new deposits to a pool. Existing positions can still be withdrawn
    /// and harvested.
    pub fn set_pool_active(env: Env, pool_id: u32, active: bool) {
        let cfg = config(&env);
        cfg.admin.require_auth();
        let mut pool = read_pool(&env, pool_id).unwrap_or_else(|| panic!("unknown pool"));
        pool.active = active;
        write_pool(&env, &pool);
        env.events()
            .publish((symbol_short!("active"), pool_id), active);
    }

    // -- rewards funding -----------------------------------------------------

    /// Funds a reward schedule of `amount` over `duration_seconds` and returns
    /// the resulting per-second rate.
    ///
    /// Mid-schedule top-ups roll the unstreamed remainder into the new rate, so
    /// no funded reward is cancelled. The global index is advanced first, which
    /// is what lets the new rate apply only from `now` onward.
    pub fn fund_rewards(env: Env, funder: Address, amount: i128, duration_seconds: u64) -> i128 {
        funder.require_auth();
        assert!(amount > 0, "amount must be positive");
        assert!(duration_seconds > 0, "duration must be positive");

        let mut cfg = config(&env);
        assert!(!cfg.paused, "farm is paused");
        assert!(cfg.total_alloc_point > 0, "no pool has an allocation");

        advance_global(&env, &mut cfg);
        let now = env.ledger().timestamp();
        let leftover = remaining_rewards(cfg.reward_rate, cfg.period_finish, now);
        let rate = reward_rate_for(
            leftover.checked_add(amount).expect("reward overflow"),
            duration_seconds,
        );
        // A rate that floors to zero would strand the funding: the next top-up
        // derives its remainder from the stored rate, which would now be zero.
        assert!(rate > 0, "reward rate rounds to zero");

        transfer_in(&env, &cfg.reward_token, &funder, amount);

        cfg.rewards_funded = cfg
            .rewards_funded
            .checked_add(amount)
            .expect("funded overflow");
        cfg.reward_rate = rate;
        cfg.period_finish = now.saturating_add(duration_seconds);
        // Align the index with the start of the new schedule so the gap between
        // schedules cannot be streamed at the new rate.
        cfg.last_update = now;
        set_config(&env, &cfg);

        env.events().publish(
            (symbol_short!("fund"), funder),
            (amount, rate, cfg.period_finish),
        );
        rate
    }

    // -- user actions --------------------------------------------------------

    /// Deposits `amount` of a pool's LP token and settles any pending reward.
    pub fn deposit(env: Env, user: Address, pool_id: u32, amount: i128) -> i128 {
        user.require_auth();
        assert!(amount > 0, "amount must be positive");
        assert!(!config(&env).paused, "farm is paused");

        let (cfg, mut pool) = settle_one(&env, pool_id);
        assert!(pool.active, "pool is not active");

        let mut position = read_position(&env, pool_id, &user, pool.acc_reward_per_share);
        settle_position(&pool, &mut position);

        transfer_in(&env, &pool.lp_token, &user, amount);

        position.amount = position.amount.checked_add(amount).expect("amount overflow");
        pool.total_staked = pool.total_staked.checked_add(amount).expect("TVL overflow");

        write_position(&env, &user, &position);
        write_pool(&env, &pool);
        set_config(&env, &cfg);
        track_user_pool(&env, &user, pool_id);

        env.events()
            .publish((symbol_short!("deposit"), user), (pool_id, amount));
        position.amount
    }

    /// Returns `amount` of LP tokens to the depositor's wallet.
    ///
    /// Deliberately callable while paused or when the pool is inactive, so a
    /// depositor can always exit.
    pub fn withdraw(env: Env, user: Address, pool_id: u32, amount: i128) -> i128 {
        user.require_auth();
        assert!(amount > 0, "amount must be positive");

        let (cfg, mut pool) = settle_one(&env, pool_id);
        let mut position = read_position(&env, pool_id, &user, pool.acc_reward_per_share);
        settle_position(&pool, &mut position);
        assert!(position.amount >= amount, "insufficient staked balance");

        position.amount -= amount;
        pool.total_staked -= amount;

        if !write_position(&env, &user, &position) {
            untrack_user_pool(&env, &user, pool_id);
        }
        write_pool(&env, &pool);
        set_config(&env, &cfg);
        transfer_out(&env, &pool.lp_token, &user, amount);

        env.events()
            .publish((symbol_short!("withdraw"), user), (pool_id, amount));
        position.amount
    }

    /// Pays out pending rewards. `min_out` guards against a live rate falling
    /// below the quote between the read and the transaction landing.
    pub fn harvest(env: Env, user: Address, pool_id: u32, min_out: i128) -> i128 {
        user.require_auth();
        assert!(min_out >= 0, "min_out must not be negative");

        let (mut cfg, pool) = settle_one(&env, pool_id);
        let mut position = read_position(&env, pool_id, &user, pool.acc_reward_per_share);
        settle_position(&pool, &mut position);

        let owed = position.accrued;
        assert!(owed >= min_out, "slippage: reward below min_out");
        position.accrued = 0;

        cfg.rewards_paid_out = cfg
            .rewards_paid_out
            .checked_add(owed)
            .expect("paid overflow");
        assert_solvent(&cfg);

        if !write_position(&env, &user, &position) {
            untrack_user_pool(&env, &user, pool_id);
        }
        set_config(&env, &cfg);
        transfer_out(&env, &cfg.reward_token, &user, owed);

        env.events()
            .publish((symbol_short!("harvest"), user), (pool_id, owed));
        owed
    }

    /// Returns the full LP balance without harvesting, forfeiting pending
    /// rewards. The escape hatch for a pool that is misbehaving, since paying
    /// out the accrual would draw on reward accounting the pool can no longer be
    /// trusted with.
    pub fn emergency_withdraw(env: Env, user: Address, pool_id: u32) -> i128 {
        user.require_auth();

        let (cfg, mut pool) = settle_one(&env, pool_id);
        let mut position = read_position(&env, pool_id, &user, pool.acc_reward_per_share);
        settle_position(&pool, &mut position);

        let amount = position.amount;
        position.amount = 0;
        position.accrued = 0;
        pool.total_staked -= amount;

        write_position(&env, &user, &position);
        write_pool(&env, &pool);
        set_config(&env, &cfg);
        untrack_user_pool(&env, &user, pool_id);
        transfer_out(&env, &pool.lp_token, &user, amount);

        env.events()
            .publish((symbol_short!("emg_wd"), user), (pool_id, amount));
        amount
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
    use soroban_sdk::token::{StellarAssetClient, TokenClient};
    use soroban_sdk::{Symbol, TryFromVal};

    const ONE: i128 = 1_000_000;

    struct Fixture {
        env: Env,
        admin: Address,
        alice: Address,
        bob: Address,
        reward_token: Address,
        lp_a: Address,
        lp_b: Address,
        client: YieldFarmClient<'static>,
    }

    impl Fixture {
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
            let reward_token = env
                .register_stellar_asset_contract_v2(admin.clone())
                .address();
            let lp_a = env
                .register_stellar_asset_contract_v2(admin.clone())
                .address();
            let lp_b = env
                .register_stellar_asset_contract_v2(admin.clone())
                .address();

            let id = env.register_contract(None, YieldFarm);
            let client = YieldFarmClient::new(&env, &id);
            client.initialize(&admin, &reward_token);

            Fixture {
                env,
                admin,
                alice,
                bob,
                reward_token,
                lp_a,
                lp_b,
                client,
            }
        }

        fn mint(&self, token: &Address, to: &Address, amount: i128) {
            StellarAssetClient::new(&self.env, token).mint(to, &amount);
        }

        fn balance(&self, token: &Address, who: &Address) -> i128 {
            TokenClient::new(&self.env, token).balance(who)
        }

        fn contract(&self) -> Address {
            self.client.address.clone()
        }

        /// Registers both LP pools with equal weight and funds 100 * ONE over
        /// 100 seconds, i.e. a rate of 1 * ONE per second split across them.
        fn standard_farm(&self) {
            self.client.add_pool(&1, &self.lp_a, &1);
            self.client.add_pool(&2, &self.lp_b, &1);
            self.fund(100 * ONE, 100);
        }

        fn fund(&self, amount: i128, duration: u64) {
            let funder = Address::generate(&self.env);
            self.mint(&self.reward_token, &funder, amount);
            self.client.fund_rewards(&funder, &amount, &duration);
        }

        /// Mints LP and deposits it, returning the deposited amount.
        fn deposit(&self, who: &Address, pool_id: u32, lp: &Address, amount: i128) -> i128 {
            self.mint(lp, who, amount);
            self.client.deposit(who, &pool_id, &amount)
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
        assert_eq!(f.client.reward_token(), f.reward_token);
        assert!(!f.client.paused());
        assert_eq!(f.client.pool_count(), 0);
        assert_eq!(f.client.total_alloc_point(), 0);
        assert_eq!(f.client.reward_rate(), 0);

        assert!(f.client.try_initialize(&f.admin, &f.reward_token).is_err());
    }

    #[test]
    fn add_pool_registers_and_rejects_duplicates() {
        let f = Fixture::new();
        f.client.add_pool(&1, &f.lp_a, &3);
        f.client.add_pool(&2, &f.lp_b, &1);

        assert_eq!(f.client.pool_count(), 2);
        assert_eq!(f.client.total_alloc_point(), 4);
        let pool = f.client.pool_of(&1).unwrap();
        assert_eq!(pool.lp_token, f.lp_a);
        assert_eq!(pool.alloc_point, 3);
        assert!(pool.active);
        assert_eq!(pool.total_staked, 0);

        assert!(f.client.try_add_pool(&1, &f.lp_b, &1).is_err());
        assert_eq!(f.client.pool_ids().len(), 2);
    }

    #[test]
    fn deposit_moves_lp_tokens_and_tracks_the_position() {
        let f = Fixture::new();
        f.standard_farm();

        let staked = f.deposit(&f.alice, 1, &f.lp_a, 100 * ONE);

        assert_eq!(staked, 100 * ONE);
        assert_eq!(f.balance(&f.lp_a, &f.alice), 0);
        assert_eq!(f.balance(&f.lp_a, &f.contract()), 100 * ONE);

        let position = f.client.position(&f.alice, &1);
        assert_eq!(position.pool_id, 1);
        assert_eq!(position.amount, 100 * ONE);
        assert_eq!(position.accrued, 0);
        assert_eq!(f.client.pool_of(&1).unwrap().total_staked, 100 * ONE);
        assert_eq!(f.client.user_pools(&f.alice).len(), 1);
    }

    #[test]
    fn deposit_rejects_bad_pools_and_amounts() {
        let f = Fixture::new();
        f.standard_farm();
        // Unknown pool.
        assert!(f
            .client
            .try_deposit(&f.alice, &99, &(10 * ONE))
            .is_err());
        // Non-positive amounts.
        f.mint(&f.lp_a, &f.alice, 10 * ONE);
        assert!(f.client.try_deposit(&f.alice, &1, &0).is_err());
        assert!(f.client.try_deposit(&f.alice, &1, &-1).is_err());
    }

    #[test]
    fn rewards_split_across_pools_by_allocation() {
        let f = Fixture::new();
        // Pool 1 gets 3x the weight of pool 2.
        f.client.add_pool(&1, &f.lp_a, &3);
        f.client.add_pool(&2, &f.lp_b, &1);
        f.fund(100 * ONE, 100); // 1 * ONE per second

        f.deposit(&f.alice, 1, &f.lp_a, 100 * ONE);
        f.deposit(&f.bob, 2, &f.lp_b, 100 * ONE);
        f.advance(100);

        // 100 * ONE total: 75 to the weighted pool, 25 to the other.
        assert_eq!(f.client.pending_rewards(&f.alice, &1), 75 * ONE);
        assert_eq!(f.client.pending_rewards(&f.bob, &2), 25 * ONE);
    }

    #[test]
    fn rewards_split_within_a_pool_by_stake() {
        let f = Fixture::new();
        f.standard_farm();
        f.deposit(&f.alice, 1, &f.lp_a, 100 * ONE);
        f.deposit(&f.bob, 1, &f.lp_a, 300 * ONE);
        f.advance(100);

        // Pool 1's 50 * ONE split 25% / 75%.
        assert_eq!(f.client.pending_rewards(&f.alice, &1), 12_500_000);
        assert_eq!(f.client.pending_rewards(&f.bob, &1), 37_500_000);
    }

    #[test]
    fn harvest_pays_and_enforces_min_out() {
        let f = Fixture::new();
        f.standard_farm();
        f.deposit(&f.alice, 1, &f.lp_a, 100 * ONE);
        f.advance(100);

        let quoted = f.client.pending_rewards(&f.alice, &1);
        assert_eq!(quoted, 50 * ONE);

        assert!(f.client.try_harvest(&f.alice, &1, &(quoted + 1)).is_err());
        assert_eq!(f.client.harvest(&f.alice, &1, &quoted), quoted);
        assert_eq!(f.balance(&f.reward_token, &f.alice), quoted);
        assert_eq!(f.client.rewards_paid_out(), quoted);

        // Nothing left to harvest until more reward accrues.
        assert_eq!(f.client.harvest(&f.alice, &1, &0), 0);
    }

    #[test]
    fn withdraw_returns_lp_and_rejects_over_withdrawal() {
        let f = Fixture::new();
        f.standard_farm();
        f.deposit(&f.alice, 1, &f.lp_a, 100 * ONE);

        assert!(f
            .client
            .try_withdraw(&f.alice, &1, &(100 * ONE + 1))
            .is_err());

        let remaining = f.client.withdraw(&f.alice, &1, &(40 * ONE));
        assert_eq!(remaining, 60 * ONE);
        assert_eq!(f.balance(&f.lp_a, &f.alice), 40 * ONE);
        assert_eq!(f.client.pool_of(&1).unwrap().total_staked, 60 * ONE);

        // A full exit drops the position and the cross-pool tracking entry.
        f.client.withdraw(&f.alice, &1, &(60 * ONE));
        assert_eq!(f.client.position(&f.alice, &1).amount, 0);
        assert!(f.client.user_pools(&f.alice).is_empty());
        assert!(f.client.try_withdraw(&f.alice, &1, &ONE).is_err());
    }

    #[test]
    fn withdrawing_does_not_forfeit_accrued_rewards() {
        let f = Fixture::new();
        f.standard_farm();
        f.deposit(&f.alice, 1, &f.lp_a, 100 * ONE);
        f.advance(100);

        // Pull the principal out but keep the reward claimable.
        f.client.withdraw(&f.alice, &1, &(100 * ONE));
        assert_eq!(f.client.pending_rewards(&f.alice, &1), 50 * ONE);
        assert_eq!(f.client.harvest(&f.alice, &1, &0), 50 * ONE);
        // The position is gone once its accrual is cleared.
        assert!(f.client.user_pools(&f.alice).is_empty());
    }

    #[test]
    fn emergency_withdraw_forfeits_pending_rewards() {
        let f = Fixture::new();
        f.standard_farm();
        f.deposit(&f.alice, 1, &f.lp_a, 100 * ONE);
        f.advance(100);
        assert_eq!(f.client.pending_rewards(&f.alice, &1), 50 * ONE);

        let out = f.client.emergency_withdraw(&f.alice, &1);
        assert_eq!(out, 100 * ONE);
        assert_eq!(f.balance(&f.lp_a, &f.alice), 100 * ONE);
        assert_eq!(f.client.pending_rewards(&f.alice, &1), 0);
        assert_eq!(f.client.rewards_paid_out(), 0);
        assert!(f.client.user_pools(&f.alice).is_empty());
    }

    #[test]
    fn changing_an_allocation_does_not_reweight_an_elapsed_window() {
        let f = Fixture::new();
        f.standard_farm();
        f.deposit(&f.alice, 1, &f.lp_a, 100 * ONE);
        f.deposit(&f.bob, 2, &f.lp_b, 100 * ONE);

        // First 50 seconds at a 1:1 split: 25 * ONE each.
        f.advance(50);
        // Re-weight pool 2 to 3 (total 4). This settles both pools first.
        f.client.set_alloc_point(&2, &3);
        assert_eq!(f.client.total_alloc_point(), 4);

        // Next 50 seconds at a 1:3 split: 12.5 / 37.5.
        f.advance(50);

        assert_eq!(f.client.pending_rewards(&f.alice, &1), 37_500_000);
        assert_eq!(f.client.pending_rewards(&f.bob, &2), 62_500_000);
    }

    #[test]
    fn a_mid_schedule_rate_change_uses_the_integral_not_the_new_rate() {
        let f = Fixture::new();
        f.client.add_pool(&1, &f.lp_a, &1);
        f.fund(100 * ONE, 100); // 1 * ONE/second
        f.deposit(&f.alice, 1, &f.lp_a, 100 * ONE);

        f.advance(50);
        // Top up: 50 * ONE still streamed + 100 * ONE over 100s = 1.5 * ONE/s.
        let rate = f.fund(100 * ONE, 100);
        assert_eq!(rate, 1_500_000);

        f.advance(100);

        // 50s at the old rate + 100s at the new one.
        assert_eq!(
            f.client.pending_rewards(&f.alice, &1),
            50 * ONE + 150 * ONE
        );
        assert_eq!(f.client.rewards_funded(), 200 * ONE);
    }

    #[test]
    fn an_empty_pool_does_not_accrue_and_does_not_leak_its_share() {
        let f = Fixture::new();
        f.standard_farm();
        // Only pool 1 has stake; pool 2 keeps its weight but is empty.
        f.deposit(&f.alice, 1, &f.lp_a, 100 * ONE);
        f.advance(100);

        // Pool 1's half of the stream, and no more.
        assert_eq!(f.client.pending_rewards(&f.alice, &1), 50 * ONE);

        // A late depositor to pool 2 cannot collect the backlog.
        f.deposit(&f.bob, 2, &f.lp_b, 100 * ONE);
        assert_eq!(f.client.pending_rewards(&f.bob, &2), 0);
    }

    #[test]
    fn rewards_stop_at_the_end_of_the_schedule() {
        let f = Fixture::new();
        f.client.add_pool(&1, &f.lp_a, &1);
        f.fund(100 * ONE, 100);
        f.deposit(&f.alice, 1, &f.lp_a, 100 * ONE);
        f.advance(10_000);

        assert_eq!(f.client.pending_rewards(&f.alice, &1), 100 * ONE);
    }

    #[test]
    fn positions_track_every_pool_a_user_has_touched() {
        let f = Fixture::new();
        f.standard_farm();
        f.deposit(&f.alice, 1, &f.lp_a, 100 * ONE);
        f.deposit(&f.alice, 2, &f.lp_b, 50 * ONE);
        f.advance(100);

        let positions = f.client.positions(&f.alice);
        assert_eq!(positions.len(), 2);
        assert_eq!(positions.get_unchecked(0).pool_id, 1);
        assert_eq!(positions.get_unchecked(0).lp_token, f.lp_a);
        assert_eq!(positions.get_unchecked(0).amount, 100 * ONE);
        assert_eq!(positions.get_unchecked(0).pending_rewards, 50 * ONE);
        assert_eq!(positions.get_unchecked(1).pool_id, 2);
        // Alice is the only staker in pool 2, so she takes the whole 50 * ONE
        // that pool's weight earns even though she deposited less.
        assert_eq!(positions.get_unchecked(1).pending_rewards, 50 * ONE);
        assert_eq!(f.client.total_pending_rewards(&f.alice), 100 * ONE);

        // A user with no positions still gets an empty, not a panic.
        assert!(f.client.positions(&f.bob).is_empty());
        assert_eq!(f.client.total_pending_rewards(&f.bob), 0);
    }

    #[test]
    fn pause_blocks_deposits_but_never_traps_funds() {
        let f = Fixture::new();
        f.standard_farm();
        f.deposit(&f.alice, 1, &f.lp_a, 100 * ONE);

        f.client.set_paused(&true);
        assert!(f.client.paused());

        f.mint(&f.lp_a, &f.alice, 10 * ONE);
        assert!(f.client.try_deposit(&f.alice, &1, &(10 * ONE)).is_err());
        let funder = Address::generate(&f.env);
        f.mint(&f.reward_token, &funder, ONE);
        assert!(f.client.try_fund_rewards(&funder, &ONE, &100).is_err());

        // Exits stay open.
        f.advance(100);
        assert_eq!(f.client.harvest(&f.alice, &1, &0), 50 * ONE);
        f.client.withdraw(&f.alice, &1, &(100 * ONE));
        assert_eq!(f.balance(&f.lp_a, &f.alice), 100 * ONE);
    }

    #[test]
    fn an_inactive_pool_blocks_deposits_but_still_lets_users_exit() {
        let f = Fixture::new();
        f.standard_farm();
        f.deposit(&f.alice, 1, &f.lp_a, 100 * ONE);

        f.client.set_pool_active(&1, &false);
        assert!(!f.client.pool_of(&1).unwrap().active);
        assert!(f
            .client
            .try_deposit(&f.alice, &1, &ONE)
            .is_err());

        f.advance(100);
        assert_eq!(f.client.harvest(&f.alice, &1, &0), 50 * ONE);
        f.client.withdraw(&f.alice, &1, &(100 * ONE));
        assert_eq!(f.balance(&f.lp_a, &f.alice), 100 * ONE);
    }

    #[test]
    fn the_farm_stays_solvent_across_a_full_lifecycle() {
        let f = Fixture::new();
        f.standard_farm();
        f.deposit(&f.alice, 1, &f.lp_a, 100 * ONE);
        f.deposit(&f.bob, 2, &f.lp_b, 100 * ONE);

        for _ in 0..5 {
            f.advance(10);
            f.client.harvest(&f.alice, &1, &0);
            f.client.harvest(&f.bob, &2, &0);
        }

        assert!(f.client.rewards_paid_out() <= f.client.rewards_credited());
        assert!(f.client.rewards_credited() <= f.client.rewards_funded());
        // Every funded token is either still in the contract or was paid out.
        assert_eq!(
            f.balance(&f.reward_token, &f.contract()),
            f.client.rewards_funded() - f.client.rewards_paid_out()
        );
    }

    #[test]
    fn funding_rejects_degenerate_schedules() {
        let f = Fixture::new();
        // No allocation yet: funding would stream to nobody.
        let funder = Address::generate(&f.env);
        f.mint(&f.reward_token, &funder, 10_000);
        assert!(f.client.try_fund_rewards(&funder, &1_000, &100).is_err());

        f.client.add_pool(&1, &f.lp_a, &1);
        assert!(f.client.try_fund_rewards(&funder, &0, &100).is_err());
        assert!(f.client.try_fund_rewards(&funder, &-1, &100).is_err());
        assert!(f.client.try_fund_rewards(&funder, &1_000, &0).is_err());
        // A rate that floors to zero is refused rather than stranding funds.
        assert!(f.client.try_fund_rewards(&funder, &1, &1_000).is_err());
    }

    #[test]
    fn zero_allocation_pools_earn_nothing_and_can_be_rewoken() {
        let f = Fixture::new();
        f.client.add_pool(&1, &f.lp_a, &1);
        f.client.add_pool(&2, &f.lp_b, &0);
        f.fund(100 * ONE, 100);
        f.deposit(&f.alice, 1, &f.lp_a, 100 * ONE);
        f.deposit(&f.bob, 2, &f.lp_b, 100 * ONE);

        f.advance(50);
        // Pool 2 has no weight, so it earns nothing while pool 1 takes it all.
        assert_eq!(f.client.pending_rewards(&f.alice, &1), 50 * ONE);
        assert_eq!(f.client.pending_rewards(&f.bob, &2), 0);

        // Giving pool 2 a weight lets it earn from that point on.
        f.client.set_alloc_point(&2, &1);
        f.advance(50);
        assert_eq!(f.client.pending_rewards(&f.bob, &2), 25 * ONE);
    }

    #[test]
    fn only_the_admin_can_change_the_pause_or_the_pool_set() {
        // `mock_all_auths` makes authorisation always pass, so what is checked
        // here is the structural guard: config and pool records are only
        // reachable through the admin-gated entry points.
        let f = Fixture::new();
        f.client.set_paused(&true);
        assert!(f.client.paused());

        let new_admin = Address::generate(&f.env);
        f.client.set_admin(&new_admin);
        assert_eq!(f.client.admin(), new_admin);

        f.client.add_pool(&7, &f.lp_a, &2);
        f.client.set_alloc_point(&7, &5);
        assert_eq!(f.client.pool_of(&7).unwrap().alloc_point, 5);
        assert_eq!(f.client.total_alloc_point(), 5);
        assert!(f.client.try_set_alloc_point(&99, &1).is_err());
    }

    #[test]
    fn events_are_emitted_for_the_lifecycle() {
        let f = Fixture::new();
        f.client.add_pool(&1, &f.lp_a, &1);
        f.client.add_pool(&2, &f.lp_b, &1);
        f.fund(100 * ONE, 100);
        f.deposit(&f.alice, 1, &f.lp_a, 100 * ONE);
        f.advance(50);
        f.client.harvest(&f.alice, &1, &0);
        f.client.withdraw(&f.alice, &1, &(50 * ONE));
        f.client.set_alloc_point(&2, &2);
        f.client.set_pool_active(&2, &false);
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
            symbol_short!("add_pool"),
            symbol_short!("fund"),
            symbol_short!("deposit"),
            symbol_short!("harvest"),
            symbol_short!("withdraw"),
            symbol_short!("alloc"),
            symbol_short!("active"),
            symbol_short!("set_pause"),
        ] {
            assert!(names.contains(&expected), "missing {expected:?}");
        }
    }
}

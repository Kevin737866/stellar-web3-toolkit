#![no_std]
//! Constant-product AMM pool.
//!
//! # Overflow policy (#399)
//!
//! Every mutation of a reserve, an LP balance, the LP total supply or an
//! allowance goes through the checked helpers in [`math`], which abort the
//! invocation with a message naming the field and operands. Nothing on these
//! paths uses `saturating_*`: saturating a reserve at `i128::MAX` would leave
//! the stored reserve out of sync with the tokens the pool actually holds and
//! silently misprice every later swap. A panic is safe here because Soroban
//! rolls back the whole invocation, so a failed operation never leaves partial
//! state behind.
//!
//! The only intentional saturation left is the TWAP accumulator in
//! `grow_cumulative`: it is a derived, monotonically increasing oracle value
//! rather than a balance, and clamping it is a documented degradation instead
//! of an accounting error.

// Public so the quorum/quorum-status helpers and `sqrt_u128` are part of the
// crate's reachable API: as a private module their `pub` items tripped
// `dead_code` under `clippy -D warnings`.
pub mod math;

use math::{
    amount_out, checked_add_amount, checked_mul_div, checked_sub_amount, flash_k_ok,
    liquidity_amounts_first_deposit, quote,
};
use soroban_sdk::token::{TokenClient, TokenInterface};
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, IntoVal, String};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Factory,
    TokenA,
    TokenB,
    ReserveA,
    ReserveB,
    TotalLp,
    TsLast,
    CumA,
    CumB,
    Bal(Address),
    Allow(AllowKey),
    FlashSwapActive,
}

#[contracttype]
#[derive(Clone)]
pub struct AllowKey {
    pub from: Address,
    pub spender: Address,
}

#[contracttype]
#[derive(Clone)]
pub struct AllowanceData {
    pub amount: i128,
    pub expiration_ledger: u32,
}

#[contract]
pub struct AmmPool;

fn read_i128(env: &Env, key: &DataKey) -> i128 {
    env.storage().instance().get(key).unwrap_or(0)
}

fn write_i128(env: &Env, key: DataKey, v: i128) {
    env.storage().instance().set(&key, &v);
}

fn read_addr(env: &Env, key: &DataKey) -> Option<Address> {
    env.storage().instance().get(key)
}

fn write_addr(env: &Env, key: DataKey, v: &Address) {
    env.storage().instance().set(&key, v);
}

fn get_factory(env: &Env) -> Address {
    read_addr(env, &DataKey::Factory).expect("factory")
}

fn get_tokens(env: &Env) -> (Address, Address) {
    (
        read_addr(env, &DataKey::TokenA).expect("ta"),
        read_addr(env, &DataKey::TokenB).expect("tb"),
    )
}

fn reserves(env: &Env) -> (i128, i128) {
    (
        read_i128(env, &DataKey::ReserveA),
        read_i128(env, &DataKey::ReserveB),
    )
}

fn set_reserves(env: &Env, a: i128, b: i128) {
    write_i128(env, DataKey::ReserveA, a);
    write_i128(env, DataKey::ReserveB, b);
}

fn assert_not_in_flash_swap(env: &Env) {
    assert!(
        !env.storage()
            .instance()
            .get(&DataKey::FlashSwapActive)
            .unwrap_or(false),
        "reentrant call during flash swap"
    );
}

fn total_lp(env: &Env) -> i128 {
    read_i128(env, &DataKey::TotalLp)
}

fn set_total_lp(env: &Env, v: i128) {
    write_i128(env, DataKey::TotalLp, v);
}

fn grow_cumulative(env: &Env) {
    let now = env.ledger().timestamp();
    let last = read_i128(env, &DataKey::TsLast) as u64;
    let dt = (now.saturating_sub(last)) as i128;
    if dt > 0 {
        let (ra, rb) = reserves(env);
        let ca = read_i128(env, &DataKey::CumA);
        let cb = read_i128(env, &DataKey::CumB);
        write_i128(env, DataKey::CumA, ca.saturating_add(ra.saturating_mul(dt)));
        write_i128(env, DataKey::CumB, cb.saturating_add(rb.saturating_mul(dt)));
    }
    write_i128(env, DataKey::TsLast, now as i128);
}

fn lp_balance_read(env: &Env, id: &Address) -> i128 {
    env.storage()
        .instance()
        .get(&DataKey::Bal(id.clone()))
        .unwrap_or(0)
}

fn lp_balance_write(env: &Env, id: Address, v: i128) {
    env.storage().instance().set(&DataKey::Bal(id), &v);
}

fn allowance_load(env: &Env, from: Address, spender: Address) -> AllowanceData {
    let k = AllowKey { from, spender };
    env.storage()
        .instance()
        .get(&DataKey::Allow(k))
        .unwrap_or(AllowanceData {
            amount: 0,
            expiration_ledger: 0,
        })
}

fn allowance_store(env: &Env, from: Address, spender: Address, data: AllowanceData) {
    let k = AllowKey { from, spender };
    env.storage().instance().set(&DataKey::Allow(k), &data);
}

fn allowance_effective(env: &Env, data: &AllowanceData) -> i128 {
    let ledger = env.ledger().sequence();
    if data.amount == 0 {
        return 0;
    }
    if data.expiration_ledger < ledger {
        0
    } else {
        data.amount
    }
}

fn mint_lp(env: &Env, to: Address, amount: i128) {
    assert!(amount > 0, "mint lp");
    let b = lp_balance_read(env, &to);
    lp_balance_write(env, to, checked_add_amount(b, amount, "lp balance mint"));
    set_total_lp(
        env,
        checked_add_amount(total_lp(env), amount, "lp total supply mint"),
    );
}

fn burn_lp(env: &Env, from: Address, amount: i128) {
    assert!(amount > 0, "burn lp");
    let b = lp_balance_read(env, &from);
    assert!(b >= amount, "bal");
    lp_balance_write(env, from, checked_sub_amount(b, amount, "lp balance burn"));
    set_total_lp(
        env,
        checked_sub_amount(total_lp(env), amount, "lp total supply burn"),
    );
}

fn burn_lp_withdraw(env: &Env, from: Address, amount: i128) {
    let pool = env.current_contract_address();
    let (reserve_a, reserve_b) = reserves(env);
    let supply = total_lp(env);
    assert!(amount > 0 && supply > 0, "burn w");
    let amount_a = checked_mul_div(amount, reserve_a, supply, "withdraw amount A");
    let amount_b = checked_mul_div(amount, reserve_b, supply, "withdraw amount B");
    grow_cumulative(env);
    burn_lp(env, from.clone(), amount);
    let (ta, tb) = get_tokens(env);
    TokenClient::new(env, &ta).transfer(&pool, &from, &amount_a);
    TokenClient::new(env, &tb).transfer(&pool, &from, &amount_b);
    set_reserves(
        env,
        checked_sub_amount(reserve_a, amount_a, "reserve A withdraw"),
        checked_sub_amount(reserve_b, amount_b, "reserve B withdraw"),
    );
    grow_cumulative(env);
}

#[contractimpl]
impl AmmPool {
    /// One-time init (typically called by factory right after deploy).
    pub fn initialize(env: Env, factory: Address, token_a: Address, token_b: Address) {
        assert!(!env.storage().instance().has(&DataKey::Factory), "init");
        factory.require_auth();
        assert!(token_a != token_b, "tokens");
        write_addr(&env, DataKey::Factory, &factory);
        write_addr(&env, DataKey::TokenA, &token_a);
        write_addr(&env, DataKey::TokenB, &token_b);
        write_i128(&env, DataKey::ReserveA, 0);
        write_i128(&env, DataKey::ReserveB, 0);
        write_i128(&env, DataKey::TotalLp, 0);
        write_i128(&env, DataKey::TsLast, env.ledger().timestamp() as i128);
        write_i128(&env, DataKey::CumA, 0);
        write_i128(&env, DataKey::CumB, 0);
    }

    pub fn get_reserves(env: Env) -> (i128, i128) {
        reserves(&env)
    }

    pub fn factory(env: Env) -> Address {
        get_factory(&env)
    }

    pub fn token_a(env: Env) -> Address {
        get_tokens(&env).0
    }

    pub fn token_b(env: Env) -> Address {
        get_tokens(&env).1
    }

    /// Spot price oracle helper: cumulative reserves × time (integrator TWAP off-chain).
    pub fn observe(env: Env) -> (i128, i128, u64) {
        grow_cumulative(&env);
        (
            read_i128(&env, &DataKey::CumA),
            read_i128(&env, &DataKey::CumB),
            env.ledger().timestamp(),
        )
    }

    /// Deposits `token_a` and `token_b` and mints LP shares.
    ///
    /// LP share minting rounds **down** (floor) via `checked_mint_lp_shares` so
    /// depositors never receive more shares than backed by their proportional deposit.
    pub fn add_liquidity(
        env: Env,
        user: Address,
        amount_a_desired: i128,
        amount_b_desired: i128,
        min_a: i128,
        min_b: i128,
    ) -> i128 {
        assert_not_in_flash_swap(&env);
        user.require_auth();
        assert!(amount_a_desired > 0 && amount_b_desired > 0, "amounts");
        let pool = env.current_contract_address();
        let (ta, tb) = get_tokens(&env);
        let (reserve_a, reserve_b) = reserves(&env);

        let (amount_a, amount_b) = if reserve_a == 0 && reserve_b == 0 {
            (amount_a_desired, amount_b_desired)
        } else {
            let b_opt = quote(amount_a_desired, reserve_a, reserve_b);
            if b_opt <= amount_b_desired {
                assert!(b_opt >= min_b, "min b");
                (amount_a_desired, b_opt)
            } else {
                let a_opt = quote(amount_b_desired, reserve_b, reserve_a);
                assert!(a_opt >= min_a, "min a");
                (a_opt, amount_b_desired)
            }
        };

        assert!(amount_a >= min_a && amount_b >= min_b, "slippage add");

        let supply = total_lp(&env);
        let liq =
            checked_mint_lp_shares(amount_a, amount_b, reserve_a, reserve_b, supply).expect("liq");
        assert!(liq > 0, "liq");

        TokenClient::new(&env, &ta).transfer(&user, &pool, &amount_a);
        TokenClient::new(&env, &tb).transfer(&user, &pool, &amount_b);

        grow_cumulative(&env);

        let liq = if total_lp(&env) == 0 {
            liquidity_amounts_first_deposit(amount_a, amount_b)
        } else {
            let supply = total_lp(&env);
            let l1 = checked_mul_div(amount_a, supply, reserve_a, "add liquidity LP for A");
            let l2 = checked_mul_div(amount_b, supply, reserve_b, "add liquidity LP for B");
            l1.min(l2)
        };
        assert!(liq > 0, "liq");
        let new_a = checked_add_amount(reserve_a, amount_a, "reserve A deposit");
        let new_b = checked_add_amount(reserve_b, amount_b, "reserve B deposit");
        set_reserves(&env, new_a, new_b);
        mint_lp(&env, user, liq);
        grow_cumulative(&env);
        liq
    }

    /// Burns `lp_amount` LP shares and redeems proportional `token_a` and `token_b`.
    ///
    /// Token redemption rounds **down** (floor) via `checked_redeem_amounts` so
    /// redeemers cannot withdraw more reserves than their proportional share entitles them to.
    pub fn remove_liquidity(
        env: Env,
        user: Address,
        lp_amount: i128,
        min_a: i128,
        min_b: i128,
    ) -> (i128, i128) {
        assert_not_in_flash_swap(&env);
        user.require_auth();
        assert!(lp_amount > 0, "lp");
        let pool = env.current_contract_address();
        let (reserve_a, reserve_b) = reserves(&env);
        let supply = total_lp(&env);
        assert!(supply > 0, "supply");

        let amount_a = checked_mul_div(lp_amount, reserve_a, supply, "remove liquidity amount A");
        let amount_b = checked_mul_div(lp_amount, reserve_b, supply, "remove liquidity amount B");
        assert!(amount_a >= min_a && amount_b >= min_b, "slippage rm");

        grow_cumulative(&env);
        burn_lp(&env, user.clone(), lp_amount);

        let (ta, tb) = get_tokens(&env);
        TokenClient::new(&env, &ta).transfer(&pool, &user, &amount_a);
        TokenClient::new(&env, &tb).transfer(&pool, &user, &amount_b);

        set_reserves(
            &env,
            checked_sub_amount(reserve_a, amount_a, "reserve A removal"),
            checked_sub_amount(reserve_b, amount_b, "reserve B removal"),
        );
        grow_cumulative(&env);
        (amount_a, amount_b)
    }

    /// Assumes `token_in` already transferred to this pool in this transaction.
    pub fn swap(env: Env, token_in: Address, to: Address, min_out: i128) -> i128 {
        assert_not_in_flash_swap(&env);
        assert!(to != env.current_contract_address(), "to");
        let pool = env.current_contract_address();
        let (ta, tb) = get_tokens(&env);
        let (reserve_a, reserve_b) = reserves(&env);
        assert!(reserve_a > 0 && reserve_b > 0, "reserves");

        let (reserve_in, reserve_out, token_out) = if token_in == ta {
            (reserve_a, reserve_b, tb.clone())
        } else if token_in == tb {
            (reserve_b, reserve_a, ta.clone())
        } else {
            panic!("token_in");
        };

        let bal_in = TokenClient::new(&env, &token_in).balance(&pool);
        // A balance below the recorded reserve means the pool's accounting has
        // already drifted from the token it holds; swapping against the
        // difference would pay out from a phantom input.
        let amount_in = checked_sub_amount(bal_in, reserve_in, "swap input balance");
        assert!(amount_in > 0, "amount_in");

        let out = amount_out(amount_in, reserve_in, reserve_out);
        assert!(out >= min_out, "slippage swap");
        assert!(out < reserve_out, "out");

        grow_cumulative(&env);
        let new_in = checked_add_amount(reserve_in, amount_in, "reserve in after swap");
        let new_out = checked_sub_amount(reserve_out, out, "reserve out after swap");
        if token_in == ta {
            set_reserves(&env, new_in, new_out);
        } else {
            set_reserves(&env, new_out, new_in);
        }

        TokenClient::new(&env, &token_out).transfer(&pool, &to, &out);
        grow_cumulative(&env);
        out
    }

    /// Flash swap: sends assets out, invokes `on_flash` on `callback`, then enforces constant-product K (fee on repaid leg).
    pub fn flash_swap(
        env: Env,
        recipient: Address,
        amount_a_out: i128,
        amount_b_out: i128,
        callback: Address,
    ) {
        assert_not_in_flash_swap(&env);
        assert!(amount_a_out >= 0 && amount_b_out >= 0, "out amt");
        assert!(amount_a_out > 0 || amount_b_out > 0, "need out");
        let pool = env.current_contract_address();
        let (ta, tb) = get_tokens(&env);
        let (old_a, old_b) = reserves(&env);
        assert!(old_a > 0 && old_b > 0, "liquidity");
        assert!(
            amount_a_out < old_a && amount_b_out < old_b,
            "liquidity out"
        );

        env.storage()
            .instance()
            .set(&DataKey::FlashSwapActive, &true);
        grow_cumulative(&env);

        if amount_a_out > 0 {
            TokenClient::new(&env, &ta).transfer(&pool, &recipient, &amount_a_out);
        }
        if amount_b_out > 0 {
            TokenClient::new(&env, &tb).transfer(&pool, &recipient, &amount_b_out);
        }

        let _: () = env.invoke_contract(
            &callback,
            &soroban_sdk::symbol_short!("on_flash"),
            (pool.clone(), recipient.clone(), amount_a_out, amount_b_out).into_val(&env),
        );

        let bal_a = TokenClient::new(&env, &ta).balance(&pool);
        let bal_b = TokenClient::new(&env, &tb).balance(&pool);
        assert!(
            flash_k_ok(bal_a, bal_b, old_a, old_b, amount_a_out, amount_b_out),
            "k flash"
        );
        set_reserves(&env, bal_a, bal_b);
        grow_cumulative(&env);
        env.storage().instance().remove(&DataKey::FlashSwapActive);
    }
}

#[contractimpl]
impl TokenInterface for AmmPool {
    fn allowance(env: Env, from: Address, spender: Address) -> i128 {
        let a = allowance_load(&env, from, spender);
        allowance_effective(&env, &a)
    }

    fn approve(env: Env, from: Address, spender: Address, amount: i128, expiration_ledger: u32) {
        assert_not_in_flash_swap(&env);
        from.require_auth();
        allowance_store(
            &env,
            from,
            spender,
            AllowanceData {
                amount,
                expiration_ledger,
            },
        );
    }

    fn balance(env: Env, id: Address) -> i128 {
        lp_balance_read(&env, &id)
    }

    fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        assert_not_in_flash_swap(&env);
        from.require_auth();
        assert!(amount > 0, "amt");
        let b = lp_balance_read(&env, &from);
        assert!(b >= amount, "bal");
        lp_balance_write(
            &env,
            from,
            checked_sub_amount(b, amount, "lp transfer from"),
        );
        let b_to = lp_balance_read(&env, &to);
        lp_balance_write(&env, to, checked_add_amount(b_to, amount, "lp transfer to"));
    }

    fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        assert_not_in_flash_swap(&env);
        spender.require_auth();
        assert!(amount > 0, "amt");
        let mut al = allowance_load(&env, from.clone(), spender.clone());
        let eff = allowance_effective(&env, &al);
        assert!(eff >= amount, "allow");
        al.amount = checked_sub_amount(eff, amount, "allowance spend");
        allowance_store(&env, from.clone(), spender, al);

        let b = lp_balance_read(&env, &from);
        assert!(b >= amount, "bal");
        lp_balance_write(
            &env,
            from.clone(),
            checked_sub_amount(b, amount, "lp transfer_from from"),
        );
        let b_to = lp_balance_read(&env, &to);
        lp_balance_write(
            &env,
            to,
            checked_add_amount(b_to, amount, "lp transfer_from to"),
        );
    }

    fn burn(env: Env, from: Address, amount: i128) {
        assert_not_in_flash_swap(&env);
        from.require_auth();
        burn_lp_withdraw(&env, from, amount);
    }

    fn burn_from(env: Env, spender: Address, from: Address, amount: i128) {
        assert_not_in_flash_swap(&env);
        spender.require_auth();
        let mut al = allowance_load(&env, from.clone(), spender.clone());
        let eff = allowance_effective(&env, &al);
        assert!(eff >= amount, "allow");
        al.amount = checked_sub_amount(eff, amount, "allowance spend on burn");
        allowance_store(&env, from.clone(), spender.clone(), al);
        burn_lp_withdraw(&env, from, amount);
    }

    fn decimals(_env: Env) -> u32 {
        18
    }

    fn name(env: Env) -> String {
        String::from_str(&env, "Constant-Product AMM LP")
    }

    fn symbol(env: Env) -> String {
        String::from_str(&env, "CLP")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger as _};
    use soroban_sdk::token::{StellarAssetClient, TokenClient};

    #[contracttype]
    #[derive(Clone)]
    enum CallbackKey {
        TokenA,
    }

    #[contract]
    struct ReentrantFlashCallback;

    #[contractimpl]
    impl ReentrantFlashCallback {
        pub fn set_token_a(env: Env, token_a: Address) {
            env.storage().instance().set(&CallbackKey::TokenA, &token_a);
        }

        pub fn on_flash(
            env: Env,
            pool_id: Address,
            recipient: Address,
            amount_a_out: i128,
            amount_b_out: i128,
        ) {
            assert_eq!(amount_b_out, 0, "test callback expects no token B output");
            let callback_id = env.current_contract_address();
            let pool = AmmPoolClient::new(&env, &pool_id);
            assert!(
                pool.try_flash_swap(&recipient, &1, &0, &callback_id)
                    .is_err(),
                "nested flash swap should be rejected"
            );

            let token_a: Address = env
                .storage()
                .instance()
                .get(&CallbackKey::TokenA)
                .expect("token A configured");
            TokenClient::new(&env, &token_a).transfer(&recipient, &pool_id, &(amount_a_out + 4));
        }
    }

    fn setup_tokens(env: &Env) -> (Address, Address) {
        let admin = Address::generate(env);
        env.mock_all_auths();
        let a = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let b = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        (a, b)
    }

    fn mint(env: &Env, token: Address, to: Address, amt: i128) {
        StellarAssetClient::new(env, &token).mint(&to, &amt);
    }

    #[test]
    fn swap_and_liquidity_math() {
        let env = Env::default();
        env.mock_all_auths();
        let (ta, tb) = setup_tokens(&env);
        let pool_id = env.register_contract(None, AmmPool);
        let pool = AmmPoolClient::new(&env, &pool_id);
        let factory = Address::generate(&env);
        pool.initialize(&factory, &ta, &tb);

        let u1 = Address::generate(&env);
        mint(&env, ta.clone(), u1.clone(), 10_000_000);
        mint(&env, tb.clone(), u1.clone(), 10_000_000);

        pool.add_liquidity(&u1, &1_000_000, &4_000_000, &1, &1_000_000);
        let (ra, rb) = pool.get_reserves();
        assert_eq!(ra, 1_000_000);
        assert_eq!(rb, 4_000_000);

        let out_before = TokenClient::new(&env, &tb).balance(&u1);
        TokenClient::new(&env, &ta).transfer(&u1, &pool_id, &100_000);
        let got = pool.swap(&ta, &u1, &1);
        let out_after = TokenClient::new(&env, &tb).balance(&u1);
        assert!(out_after > out_before);
        assert_eq!(got, out_after.saturating_sub(out_before));
        assert!(got > 300_000);
    }

    #[test]
    fn lp_token_transfer_and_burn_via_remove() {
        let env = Env::default();
        env.mock_all_auths();
        let (ta, tb) = setup_tokens(&env);
        let pool_id = env.register_contract(None, AmmPool);
        let pool = AmmPoolClient::new(&env, &pool_id);
        let factory = Address::generate(&env);
        pool.initialize(&factory, &ta, &tb);
        let u = Address::generate(&env);
        mint(&env, ta.clone(), u.clone(), 10_000_000);
        mint(&env, tb.clone(), u.clone(), 10_000_000);
        let lp = pool.add_liquidity(&u, &1_000_000, &1_000_000, &1, &1);
        assert!(lp > 0);
        let tclient = TokenClient::new(&env, &pool_id);
        assert_eq!(tclient.balance(&u), lp);
        tclient.transfer(&u, &factory, &(lp / 2));
        assert_eq!(tclient.balance(&factory), lp / 2);
    }

    #[test]
    fn oracle_cumulative_moves() {
        let env = Env::default();
        env.mock_all_auths();
        let (ta, tb) = setup_tokens(&env);
        let pool_id = env.register_contract(None, AmmPool);
        let pool = AmmPoolClient::new(&env, &pool_id);
        let factory = Address::generate(&env);
        pool.initialize(&factory, &ta, &tb);
        let u = Address::generate(&env);
        mint(&env, ta.clone(), u.clone(), 10_000_000);
        mint(&env, tb.clone(), u.clone(), 10_000_000);
        pool.add_liquidity(&u, &500_000, &500_000, &1, &1);
        let (c0, d0, _) = pool.observe();
        env.ledger().with_mut(|li| {
            li.timestamp = li.timestamp.saturating_add(100);
            li.sequence_number = li.sequence_number.saturating_add(10);
        });
        TokenClient::new(&env, &ta).transfer(&u, &pool_id, &1_000);
        let _ = pool.swap(&ta, &u, &1);
        let (c1, d1, _) = pool.observe();
        assert!(c1 > c0 || d1 > d0);
    }

    #[test]
    fn flash_swap_rejects_reentrant_pool_mutations() {
        let env = Env::default();
        env.mock_all_auths();
        let (ta, tb) = setup_tokens(&env);
        let pool_id = env.register_contract(None, AmmPool);
        let pool = AmmPoolClient::new(&env, &pool_id);
        let factory = Address::generate(&env);
        pool.initialize(&factory, &ta, &tb);

        let liquidity_provider = Address::generate(&env);
        mint(&env, ta.clone(), liquidity_provider.clone(), 10_000_000);
        mint(&env, tb.clone(), liquidity_provider.clone(), 10_000_000);
        pool.add_liquidity(&liquidity_provider, &1_000_000, &1_000_000, &0, &0);

        let callback_id = env.register_contract(None, ReentrantFlashCallback);
        ReentrantFlashCallbackClient::new(&env, &callback_id).set_token_a(&ta);
        mint(&env, ta, callback_id.clone(), 4);
        pool.flash_swap(&callback_id, &1_000, &0, &callback_id);

        assert_eq!(pool.get_reserves(), (1_000_004, 1_000_000));
    }

    #[test]
    fn proportional_deposit_rejects_a_quote_that_overflows_i128() {
        let env = Env::default();
        env.mock_all_auths();
        let (ta, tb) = setup_tokens(&env);
        let pool_id = env.register_contract(None, AmmPool);
        let pool = AmmPoolClient::new(&env, &pool_id);
        pool.initialize(&Address::generate(&env), &ta, &tb);

        let u = Address::generate(&env);
        mint(&env, ta.clone(), u.clone(), 10_000_000);
        mint(&env, tb.clone(), u.clone(), 10_000_000);
        pool.add_liquidity(&u, &1_000_000, &1_000_000, &1, &1);

        // Push the LP supply to the i128 boundary. `1_001 * supply` then has no
        // representable product and the old `saturating_mul` would have quoted
        // `i128::MAX` LP instead of failing.
        env.as_contract(&pool_id, || {
            env.storage()
                .instance()
                .set(&DataKey::TotalLp, &(i128::MAX - 1));
        });
        let before = pool.get_reserves();

        assert!(
            pool.try_add_liquidity(&u, &1_001, &1_001, &1, &1).is_err(),
            "an overflowing LP quote must abort the deposit"
        );
        // The aborted call must leave no partial update behind.
        assert_eq!(pool.get_reserves(), before);
        assert_eq!(pool.balance(&u), 1_000_000);
    }

    #[test]
    fn lp_transfer_to_a_saturated_balance_is_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (ta, tb) = setup_tokens(&env);
        let pool_id = env.register_contract(None, AmmPool);
        let pool = AmmPoolClient::new(&env, &pool_id);
        pool.initialize(&Address::generate(&env), &ta, &tb);

        let u = Address::generate(&env);
        mint(&env, ta.clone(), u.clone(), 1_000_000);
        mint(&env, tb.clone(), u.clone(), 1_000_000);
        let lp = pool.add_liquidity(&u, &1_000, &1_000, &1, &1);

        let recipient = Address::generate(&env);
        env.as_contract(&pool_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Bal(recipient.clone()), &i128::MAX);
        });

        let token = TokenClient::new(&env, &pool_id);
        assert!(
            token.try_transfer(&u, &recipient, &1).is_err(),
            "adding to a saturated LP balance must abort instead of capping"
        );
        assert_eq!(token.balance(&u), lp);
    }

    #[test]
    fn active_flash_swap_guard_rejects_lp_token_mutations() {
        let env = Env::default();
        env.mock_all_auths();
        let pool_id = env.register_contract(None, AmmPool);
        env.as_contract(&pool_id, || {
            env.storage()
                .instance()
                .set(&DataKey::FlashSwapActive, &true);
        });

        let pool = AmmPoolClient::new(&env, &pool_id);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        assert!(pool.try_approve(&owner, &spender, &1, &10).is_err());
    }
}

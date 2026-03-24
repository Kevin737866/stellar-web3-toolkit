#![no_std]

mod math;

use math::{amount_out, flash_k_ok, liquidity_amounts_first_deposit, quote};
use soroban_sdk::{
    contract, contractimpl, contracttype, Address, Env, IntoVal, String,
};
use soroban_sdk::token::{TokenClient, TokenInterface};

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
    env.storage().instance().get(&DataKey::Bal(id.clone())).unwrap_or(0)
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
    lp_balance_write(env, to, b.saturating_add(amount));
    set_total_lp(env, total_lp(env).saturating_add(amount));
}

fn burn_lp(env: &Env, from: Address, amount: i128) {
    assert!(amount > 0, "burn lp");
    let b = lp_balance_read(env, &from);
    assert!(b >= amount, "bal");
    lp_balance_write(env, from, b - amount);
    set_total_lp(env, total_lp(env).saturating_sub(amount));
}

fn burn_lp_withdraw(env: &Env, from: Address, amount: i128) {
    let pool = env.current_contract_address();
    let (reserve_a, reserve_b) = reserves(env);
    let supply = total_lp(env);
    assert!(amount > 0 && supply > 0, "burn w");
    let amount_a = amount
        .saturating_mul(reserve_a)
        .checked_div(supply)
        .unwrap();
    let amount_b = amount
        .saturating_mul(reserve_b)
        .checked_div(supply)
        .unwrap();
    grow_cumulative(env);
    burn_lp(env, from.clone(), amount);
    let (ta, tb) = get_tokens(env);
    TokenClient::new(env, &ta).transfer(&pool, &from, &amount_a);
    TokenClient::new(env, &tb).transfer(&pool, &from, &amount_b);
    set_reserves(
        env,
        reserve_a.saturating_sub(amount_a),
        reserve_b.saturating_sub(amount_b),
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

    pub fn add_liquidity(
        env: Env,
        user: Address,
        amount_a_desired: i128,
        amount_b_desired: i128,
        min_a: i128,
        min_b: i128,
    ) -> i128 {
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

        TokenClient::new(&env, &ta).transfer(&user, &pool, &amount_a);
        TokenClient::new(&env, &tb).transfer(&user, &pool, &amount_b);

        grow_cumulative(&env);

        let liq = if total_lp(&env) == 0 {
            liquidity_amounts_first_deposit(amount_a, amount_b)
        } else {
            let l1 = amount_a
                .saturating_mul(total_lp(&env))
                .checked_div(reserve_a)
                .unwrap_or(0);
            let l2 = amount_b
                .saturating_mul(total_lp(&env))
                .checked_div(reserve_b)
                .unwrap_or(0);
            l1.min(l2)
        };
        assert!(liq > 0, "liq");
        let new_a = reserve_a.saturating_add(amount_a);
        let new_b = reserve_b.saturating_add(amount_b);
        set_reserves(&env, new_a, new_b);
        mint_lp(&env, user, liq);
        grow_cumulative(&env);
        liq
    }

    pub fn remove_liquidity(
        env: Env,
        user: Address,
        lp_amount: i128,
        min_a: i128,
        min_b: i128,
    ) -> (i128, i128) {
        user.require_auth();
        assert!(lp_amount > 0, "lp");
        let pool = env.current_contract_address();
        let (reserve_a, reserve_b) = reserves(&env);
        let supply = total_lp(&env);
        assert!(supply > 0, "supply");

        let amount_a = lp_amount
            .saturating_mul(reserve_a)
            .checked_div(supply)
            .unwrap();
        let amount_b = lp_amount
            .saturating_mul(reserve_b)
            .checked_div(supply)
            .unwrap();
        assert!(amount_a >= min_a && amount_b >= min_b, "slippage rm");

        grow_cumulative(&env);
        burn_lp(&env, user.clone(), lp_amount);

        let (ta, tb) = get_tokens(&env);
        TokenClient::new(&env, &ta).transfer(&pool, &user, &amount_a);
        TokenClient::new(&env, &tb).transfer(&pool, &user, &amount_b);

        set_reserves(
            &env,
            reserve_a.saturating_sub(amount_a),
            reserve_b.saturating_sub(amount_b),
        );
        grow_cumulative(&env);
        (amount_a, amount_b)
    }

    /// Assumes `token_in` already transferred to this pool in this transaction.
    pub fn swap(env: Env, token_in: Address, to: Address, min_out: i128) -> i128 {
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
        let amount_in = bal_in.saturating_sub(reserve_in);
        assert!(amount_in > 0, "amount_in");

        let out = amount_out(amount_in, reserve_in, reserve_out);
        assert!(out >= min_out, "slippage swap");
        assert!(out < reserve_out, "out");

        grow_cumulative(&env);
        let new_in = reserve_in.saturating_add(amount_in);
        let new_out = reserve_out.saturating_sub(out);
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
        assert!(amount_a_out >= 0 && amount_b_out >= 0, "out amt");
        assert!(amount_a_out > 0 || amount_b_out > 0, "need out");
        let pool = env.current_contract_address();
        let (ta, tb) = get_tokens(&env);
        let (old_a, old_b) = reserves(&env);
        assert!(old_a > 0 && old_b > 0, "liquidity");
        assert!(amount_a_out < old_a && amount_b_out < old_b, "liquidity out");

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
    }
}

#[contractimpl]
impl TokenInterface for AmmPool {
    fn allowance(env: Env, from: Address, spender: Address) -> i128 {
        let a = allowance_load(&env, from, spender);
        allowance_effective(&env, &a)
    }

    fn approve(env: Env, from: Address, spender: Address, amount: i128, expiration_ledger: u32) {
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
        from.require_auth();
        assert!(amount > 0, "amt");
        let b = lp_balance_read(&env, &from);
        assert!(b >= amount, "bal");
        lp_balance_write(&env, from, b - amount);
        let b_to = lp_balance_read(&env, &to);
        lp_balance_write(&env, to, b_to.saturating_add(amount));
    }

    fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        assert!(amount > 0, "amt");
        let mut al = allowance_load(&env, from.clone(), spender.clone());
        let eff = allowance_effective(&env, &al);
        assert!(eff >= amount, "allow");
        let new_allow = eff.saturating_sub(amount);
        al.amount = new_allow;
        allowance_store(&env, from.clone(), spender, al);

        let b = lp_balance_read(&env, &from);
        assert!(b >= amount, "bal");
        lp_balance_write(&env, from.clone(), b - amount);
        let b_to = lp_balance_read(&env, &to);
        lp_balance_write(&env, to, b_to.saturating_add(amount));
    }

    fn burn(env: Env, from: Address, amount: i128) {
        from.require_auth();
        burn_lp_withdraw(&env, from, amount);
    }

    fn burn_from(env: Env, spender: Address, from: Address, amount: i128) {
        spender.require_auth();
        let mut al = allowance_load(&env, from.clone(), spender.clone());
        let eff = allowance_effective(&env, &al);
        assert!(eff >= amount, "allow");
        al.amount = eff.saturating_sub(amount);
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

    fn setup_tokens(env: &Env) -> (Address, Address) {
        let admin = Address::generate(env);
        env.mock_all_auths();
        let a = env.register_stellar_asset_contract(admin.clone());
        let b = env.register_stellar_asset_contract(admin.clone());
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
}

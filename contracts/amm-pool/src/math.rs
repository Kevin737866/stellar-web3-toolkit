//! Fixed-point style constant-product math (Uniswap V2–style 0.3% fee on input).

/// Swap fee: 0.3% → multiply input amount by 997 / 1000 before applying x*y=k.
pub const FEE_NUM: i128 = 997;
pub const FEE_DEN: i128 = 1000;

pub fn amount_out(amount_in: i128, reserve_in: i128, reserve_out: i128) -> i128 {
    assert!(amount_in > 0, "amount_in");
    assert!(reserve_in > 0 && reserve_out > 0, "reserves");
    let amount_in_with_fee = amount_in
        .checked_mul(FEE_NUM)
        .unwrap()
        .checked_div(FEE_DEN)
        .unwrap();
    let numerator = amount_in_with_fee.checked_mul(reserve_out).unwrap();
    let denominator = reserve_in.checked_add(amount_in_with_fee).unwrap();
    assert!(denominator > 0, "denominator");
    numerator.checked_div(denominator).unwrap()
}

/// For addition/removal: quote token B needed for exact A (no fee).
pub fn quote(amount_a: i128, reserve_a: i128, reserve_b: i128) -> i128 {
    assert!(amount_a > 0 && reserve_a > 0 && reserve_b > 0, "quote");
    amount_a
        .checked_mul(reserve_b)
        .unwrap()
        .checked_div(reserve_a)
        .unwrap()
}

pub fn sqrt_u128(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

pub fn liquidity_amounts_first_deposit(amount_a: i128, amount_b: i128) -> i128 {
    let p = (amount_a as u128)
        .checked_mul(amount_b as u128)
        .expect("product overflow");
    sqrt_u128(p) as i128
}

/// Uniswap V2–style K check after flash repayment (`balance*` are live token balances of the pool).
pub fn flash_k_ok(
    balance_a: i128,
    balance_b: i128,
    reserve_a: i128,
    reserve_b: i128,
    amount_a_out: i128,
    amount_b_out: i128,
) -> bool {
    let amount_a_in = if balance_a > reserve_a.saturating_sub(amount_a_out) {
        balance_a.saturating_sub(reserve_a.saturating_sub(amount_a_out))
    } else {
        0
    };
    let amount_b_in = if balance_b > reserve_b.saturating_sub(amount_b_out) {
        balance_b.saturating_sub(reserve_b.saturating_sub(amount_b_out))
    } else {
        0
    };

    if amount_a_in == 0 && amount_b_in == 0 {
        return false;
    }

    let balance_a_adj = balance_a
        .saturating_mul(1000)
        .saturating_sub(amount_a_in.saturating_mul(3));
    let balance_b_adj = balance_b
        .saturating_mul(1000)
        .saturating_sub(amount_b_in.saturating_mul(3));

    if balance_a_adj <= 0 || balance_b_adj <= 0 {
        return false;
    }

    let k_old = reserve_a.saturating_mul(reserve_b).saturating_mul(1_000_000);
    balance_a_adj.saturating_mul(balance_b_adj) >= k_old
}

#[cfg(test)]
mod math_tests {
    use super::flash_k_ok;

    #[test]
    fn flash_repay_satisfies_k() {
        let reserve_a = 2_000_000i128;
        let reserve_b = 2_000_000i128;
        let amount_a_out = 10_000i128;
        let amount_b_out = 10_000i128;
        let pay_a = 10_200i128;
        let pay_b = 10_200i128;
        let balance_a = reserve_a - amount_a_out + pay_a;
        let balance_b = reserve_b - amount_b_out + pay_b;
        assert!(flash_k_ok(
            balance_a,
            balance_b,
            reserve_a,
            reserve_b,
            amount_a_out,
            amount_b_out
        ));
    }
}

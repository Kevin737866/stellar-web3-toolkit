//! Property tests over the contracts' pure math.
//!
//! Each property states an invariant that must hold for *every* input, not just
//! the hand-picked ones a unit test would use. Run with a bigger sweep with:
//!
//! ```text
//! PROPERTY_CASES=100000 cargo test -p contract-proptests --test math_properties
//! ```

use amm_pool::math::{
    amount_out, count_distinct_voters, flash_k_ok, liquidity_amounts_first_deposit, quote,
    quorum_status, sqrt_u128, FEE_DEN, FEE_NUM,
};
use contract_proptests::{check_default, expect, Rng};

const MAX_RESERVE: i128 = 1_000_000_000;

#[test]
fn sqrt_u128_is_the_floor_root() {
    check_default(
        "sqrt_u128 is the floor of the square root",
        |rng: &mut Rng| rng.next_u128(),
        |n| {
            let root = sqrt_u128(*n);
            let square = root.checked_mul(root);
            expect(
                square.is_some() && square.unwrap() <= *n,
                "root^2 must not exceed n",
            )?;
            // `(root + 1)^2 > n` is skipped exactly at the boundary where
            // `root + 1 == 2^64`, whose true square is 2^128 and therefore
            // greater than every `u128`.
            let next = root + 1;
            if next < (1u128 << 64) {
                expect(next * next > *n, "(root + 1)^2 must exceed n")?;
            }
            Ok(())
        },
    );
}

#[test]
fn sqrt_u128_is_monotonic() {
    check_default(
        "sqrt_u128 is monotonic",
        |rng: &mut Rng| {
            // Shifted down so the samples spread over the whole range rather
            // than clustering at the top.
            let a = rng.next_u128() >> 2;
            let b = rng.next_u128() >> 2;
            (a.min(b), a.max(b))
        },
        |(low, high)| expect(sqrt_u128(*low) <= sqrt_u128(*high), "sqrt must not decrease"),
    );
}

#[test]
fn a_swap_output_never_drains_the_output_reserve() {
    check_default(
        "a swap output stays strictly below the output reserve",
        |rng: &mut Rng| {
            let reserve_in = rng.i128_in(1, MAX_RESERVE);
            let reserve_out = rng.i128_in(1, MAX_RESERVE);
            let amount_in = rng.i128_in(1, reserve_in);
            (amount_in, reserve_in, reserve_out)
        },
        |(amount_in, reserve_in, reserve_out)| {
            let out = amount_out(*amount_in, *reserve_in, *reserve_out);
            expect(out >= 0, "an output must never be negative")?;
            expect(
                out < *reserve_out,
                "an output must leave the reserve non-empty",
            )
        },
    );
}

#[test]
fn a_swap_output_is_monotonic_in_the_input() {
    check_default(
        "a larger swap input never yields a smaller output",
        |rng: &mut Rng| {
            let reserve_in = rng.i128_in(1_000, MAX_RESERVE);
            let reserve_out = rng.i128_in(1_000, MAX_RESERVE);
            let small = rng.i128_in(1, 100_000);
            let extra = rng.i128_in(0, 100_000);
            (small, small + extra, reserve_in, reserve_out)
        },
        |(a, b, reserve_in, reserve_out)| expect(
            amount_out(*a, *reserve_in, *reserve_out) <= amount_out(*b, *reserve_in, *reserve_out),
            "output must not decrease as the input grows",
        ),
    );
}

#[test]
fn the_fee_never_helps_the_trader() {
    check_default(
        "the 0.3% fee can only reduce the output",
        |rng: &mut Rng| {
            let reserve_in = rng.i128_in(1_000, MAX_RESERVE);
            let reserve_out = rng.i128_in(1_000, MAX_RESERVE);
            let amount_in = rng.i128_in(1, reserve_in);
            (amount_in, reserve_in, reserve_out)
        },
        |(amount_in, reserve_in, reserve_out)| {
            let out = amount_out(*amount_in, *reserve_in, *reserve_out);
            let fee_free = amount_in
                .checked_mul(*reserve_out)
                .expect("product")
                .checked_div(*reserve_in)
                .expect("reserve is positive");
            expect(out <= fee_free, "a fee-bearing output must not beat the fee-free one")
        },
    );
}

#[test]
fn constant_product_never_decreases_across_a_swap() {
    check_default(
        "x * y never decreases across a swap",
        |rng: &mut Rng| {
            let reserve_in = rng.i128_in(1_000, 1_000_000);
            let reserve_out = rng.i128_in(1_000, 1_000_000);
            let amount_in = rng.i128_in(1, reserve_in);
            (amount_in, reserve_in, reserve_out)
        },
        |(amount_in, reserve_in, reserve_out)| {
            let out = amount_out(*amount_in, *reserve_in, *reserve_out);
            let k_before = reserve_in.checked_mul(*reserve_out).expect("k");
            let new_in = reserve_in + amount_in;
            let new_out = reserve_out - out;
            let k_after = new_in.checked_mul(new_out).expect("k");
            expect(k_after >= k_before, "k must not fall on a swap")
        },
    );
}

#[test]
fn a_quote_is_monotonic_in_the_amount() {
    check_default(
        "quote is monotonic in the amount",
        |rng: &mut Rng| {
            let reserve_a = rng.i128_in(1_000, 1_000_000);
            let reserve_b = rng.i128_in(1_000, 1_000_000);
            let small = rng.i128_in(1, 10_000);
            let extra = rng.i128_in(0, 10_000);
            (small, small + extra, reserve_a, reserve_b)
        },
        |(a, b, reserve_a, reserve_b)| expect(
            quote(*a, *reserve_a, *reserve_b) <= quote(*b, *reserve_a, *reserve_b),
            "quote must not decrease as the amount grows",
        ),
    );
}

#[test]
fn the_first_deposit_mints_no_more_than_the_geometric_mean() {
    check_default(
        "sqrt(a * b) never exceeds min(a, b)",
        |rng: &mut Rng| {
            let a = rng.i128_in(1, 1_000_000_000);
            let b = rng.i128_in(1, 1_000_000_000);
            (a, b)
        },
        |(a, b)| {
            let liquidity = liquidity_amounts_first_deposit(*a, *b);
            expect(
                liquidity <= (*a).min(*b),
                "the minted liquidity must not exceed min(a, b)",
            )?;
            let square = liquidity.checked_mul(liquidity);
            expect(
                square.is_some() && square.unwrap() <= a * b,
                "the minted liquidity must satisfy lp^2 <= a * b",
            )
        },
    );
}

#[test]
fn quorum_is_a_faithful_threshold() {
    check_default(
        "quorum is met exactly when the confirmations reach the threshold",
        |rng: &mut Rng| {
            let n = rng.u32_in(1, 64);
            let m = rng.u32_in(1, n);
            let received = rng.u32_in(0, n);
            (m, n, received)
        },
        |(m, n, received)| {
            let status = quorum_status(*m, *n, *received);
            expect(
                status.is_met() == (*received >= *m),
                "met iff received >= m",
            )?;
            if status.is_met() {
                expect(status.missing() == 0, "a met quorum is missing nothing")
            } else {
                expect(
                    status.missing() == *m - *received,
                    "the missing count must be m - received",
                )
            }
        },
    );
}

#[test]
fn distinct_voter_counting_is_capped_and_order_independent() {
    check_default(
        "distinct voter counting ignores duplicates, order and out-of-range entries",
        |rng: &mut Rng| {
            let n = rng.u32_in(1, 24);
            let len = rng.index(10);
            let mut voters = Vec::new();
            for _ in 0..len {
                // Deliberately includes entries at and beyond `n`.
                voters.push(rng.u32_in(0, n + 2));
            }
            let mut reversed = voters.clone();
            reversed.reverse();
            (n, voters, reversed)
        },
        |(n, voters, reversed)| {
            let forward = count_distinct_voters(voters.as_slice(), *n);
            let backward = count_distinct_voters(reversed.as_slice(), *n);
            expect(forward == backward, "counting must not depend on order")?;
            expect(forward <= *n, "a count cannot exceed the validator set")
        },
    );
}

#[test]
fn an_unrepaid_flash_swap_is_rejected() {
    check_default(
        "a flash swap with nothing repaid fails the k check",
        |rng: &mut Rng| {
            let reserve_a = rng.i128_in(1_000, 1_000_000);
            let reserve_b = rng.i128_in(1_000, 1_000_000);
            let out_a = rng.i128_in(1, reserve_a / 2);
            (reserve_a, reserve_b, out_a)
        },
        |(reserve_a, reserve_b, out_a)| {
            // Balances show the borrowed amount left and nothing returned.
            let balance_a = reserve_a - out_a;
            expect(
                !flash_k_ok(balance_a, *reserve_b, *reserve_a, *reserve_b, *out_a, 0),
                "an unrepaid flash must not satisfy k",
            )
        },
    );
}

#[test]
fn a_fee_paying_flash_repayment_is_accepted() {
    check_default(
        "repaying the grossed-up amount satisfies the k check",
        |rng: &mut Rng| {
            let reserve_a = rng.i128_in(10_000, 1_000_000);
            let reserve_b = rng.i128_in(10_000, 1_000_000);
            let out_a = rng.i128_in(1, reserve_a / 4);
            (reserve_a, reserve_b, out_a)
        },
        |(reserve_a, reserve_b, out_a)| {
            // ceil(out * 1000 / 997) is enough; one extra unit makes the
            // inequality strict regardless of the flooring.
            let repay = out_a * FEE_DEN / FEE_NUM + 1;
            let balance_a = reserve_a - out_a + repay;
            expect(
                flash_k_ok(balance_a, *reserve_b, *reserve_a, *reserve_b, *out_a, 0),
                "a repaid flash must satisfy k",
            )
        },
    );
}

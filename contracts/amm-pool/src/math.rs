//! Fixed-point style constant-product math (Uniswap V2–style 0.3% fee on input).
//!
//! Also holds the small amount-quantity helpers a pool needs: an overflow-free
//! integer square root and an exact m-of-n quorum threshold. Both live here
//! rather than in a new module or behind a `#[contractimpl]` because they are
//! pure `u128`/`u32` arithmetic with no `Env`, no storage and no contract
//! attributes — `math.rs` is already that layer, already carries a
//! `#[cfg(test)] mod math_tests`, and putting them anywhere else would only add
//! a file without making them more testable.

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

/// Floor of the square root of `n`.
///
/// # Why bit-by-bit rather than Newton
///
/// The obvious Newton iteration `y = (x + n/x) / 2` is *not* overflow-safe:
/// `x + n/x` overflows `u128` whenever both terms are large (e.g. the first
/// iteration from `x = n` computes `n + 1`). This module is used from
/// `liquidity_amounts_first_deposit`, and the workspace release profile sets
/// `overflow-checks = true`, so such an overflow is a panic inside a contract
/// rather than a silent wrap — either way a pool's first-deposit quote breaks
/// for very large reserves.
///
/// This is the classic restoring long-division square root: it uses only
/// shifts, adds, subtracts and comparisons, so it cannot overflow and needs no
/// division at all. `rem` is the running remainder, `root` the root so far, and
/// `bit` walks the powers of four from `2^126` (the largest power of four that
/// fits in a `u128`) down to `4^0`. At every step `root` is at most `2^64 - 1`
/// and `bit` at most `2^126`, so `root + bit` is at most `2^126 + 2^64` and can
/// never wrap; the `rem >= root + bit` guard keeps `rem` non-negative.
///
/// Invariant: on exit `root == floor(sqrt(n))`, i.e. `root^2 <= n` and
/// `(root + 1)^2 > n`. `math_tests` asserts exactly that over the whole
/// boundary range, including `u128::MAX`.
pub fn sqrt_u128(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    let mut rem = n;
    let mut root = 0u128;
    let mut bit = 1u128 << 126;
    while bit > rem {
        bit >>= 2;
    }
    while bit != 0 {
        if rem >= root + bit {
            rem -= root + bit;
            root = (root >> 1) + bit;
        } else {
            root >>= 1;
        }
        bit >>= 2;
    }
    root
}

/// Outcome of an m-of-n quorum check.
///
/// A richer type than a bare `bool` on purpose: a caller driving a UI or a
/// retry loop needs to know *how far* from quorum it is, and a `bool` cannot
/// express that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumStatus {
    /// Quorum reached.
    Met { required: u32, received: u32 },
    /// Quorum not reached.
    NotMet {
        required: u32,
        received: u32,
        /// Further distinct confirmations needed to reach quorum.
        missing: u32,
    },
}

impl QuorumStatus {
    /// Whether quorum is met.
    pub fn is_met(&self) -> bool {
        matches!(self, QuorumStatus::Met { .. })
    }

    /// How many distinct confirmations are still needed (0 once met).
    pub fn missing(&self) -> u32 {
        match self {
            QuorumStatus::Met { .. } => 0,
            QuorumStatus::NotMet { missing, .. } => *missing,
        }
    }
}

/// Evaluate an m-of-n quorum threshold against a count of *distinct*
/// confirmations.
///
/// All arithmetic is exact integer arithmetic; there is no floating point
/// anywhere in this decision, so no rounding can flip a threshold.
///
/// # Preconditions
///
/// * `n == 0` — rejected. There is no validator set to be a quorum of.
/// * `m == 0` — rejected. A threshold of zero is never a meaningful quorum and
///   would make an empty set "quorate".
/// * `m > n` — rejected. Unsatisfiable, and almost always a caller bug.
/// * `received > n` — rejected; a count of distinct confirmations cannot
///   exceed the set size.
///
/// Preconditions use `assert!`, matching the rest of this module. Because
/// `1 <= m <= n` is enforced, quorum is always eventually reachable: there is
/// no "round is dead" state for this function to report, and inventing one
/// would mean lying about the validator set.
pub fn quorum_status(m: u32, n: u32, received: u32) -> QuorumStatus {
    assert!(n > 0, "quorum: n must be non-zero");
    assert!(m > 0 && m <= n, "quorum: m must be in 1..=n");
    assert!(received <= n, "quorum: received cannot exceed n");

    if received >= m {
        QuorumStatus::Met {
            required: m,
            received,
        }
    } else {
        QuorumStatus::NotMet {
            required: m,
            received,
            missing: m - received,
        }
    }
}

/// Count distinct validator indices in `voters`, ignoring out-of-range entries.
///
/// Duplicate confirmations are collapsed: a validator that answers twice must
/// not count twice, otherwise a single validator can manufacture quorum alone.
/// Because the result is capped at `n`, `received <= n` always holds, which is
/// what [`quorum_status`] requires.
///
/// # Implementation
///
/// This module is `#![no_std]` and has no allocator, so no allocation-backed
/// set is available. For validator sets of up to 64 — which covers every real
/// deployment — a `u64` bitmask makes this a single pass. Larger sets fall back
/// to an O(k^2) scan, which is fine because `k` (the number of confirmations
/// actually received) is small in any protocol that needs a quorum at all.
pub fn count_distinct_voters(voters: &[u32], n: u32) -> u32 {
    if n <= 64 {
        let mut mask = 0u64;
        for v in voters {
            if *v < n {
                mask |= 1u64 << *v;
            }
        }
        mask.count_ones()
    } else {
        let mut distinct = 0u32;
        for (i, v) in voters.iter().enumerate() {
            if *v >= n {
                continue;
            }
            let already = voters[..i].iter().any(|other| other == v);
            if !already {
                distinct += 1;
            }
        }
        distinct
    }
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

    let k_old = reserve_a
        .saturating_mul(reserve_b)
        .saturating_mul(1_000_000);
    balance_a_adj.saturating_mul(balance_b_adj) >= k_old
}

#[cfg(test)]
mod math_tests {
    use super::flash_k_ok;
    use super::{count_distinct_voters, quorum_status, sqrt_u128, QuorumStatus};

    /// Assert the *defining* property of a floor square root, `r^2 <= n` and
    /// `(r + 1)^2 > n`, without ever computing a square that overflows `u128`.
    ///
    /// `r^2` is computed with `checked_mul`; if it overflows the assertion fails
    /// outright rather than passing vacuously. `(r + 1)^2` is only computed when
    /// `r + 1 <= 2^64 - 1`; at the single boundary case `r + 1 == 2^64` the
    /// true square is `2^128`, which is greater than every `u128`, so the
    /// inequality holds without being evaluated.
    fn assert_floor_sqrt(n: u128) {
        let r = sqrt_u128(n);
        assert!(r <= u64::MAX as u128, "sqrt must fit in 64 bits for {n}");
        let square = r.checked_mul(r).expect("r*r must not overflow");
        assert!(square <= n, "r*r <= n violated for {n}: {r}");
        let next = r + 1; // cannot overflow: r <= 2^64 - 1
        if next < (1u128 << 64) {
            assert!(next * next > n, "(r+1)^2 > n violated for {n}: r={r}");
        }
    }

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

    #[test]
    fn sqrt_small_values() {
        // 0 and 1 are the early-return cases; 2 and 3 straddle the first
        // non-trivial branch.
        assert_eq!(sqrt_u128(0), 0);
        assert_eq!(sqrt_u128(1), 1);
        assert_eq!(sqrt_u128(2), 1);
        assert_eq!(sqrt_u128(3), 1);
        assert_eq!(sqrt_u128(4), 2);
        assert_eq!(sqrt_u128(8), 2);
        assert_eq!(sqrt_u128(9), 3);
    }

    #[test]
    fn sqrt_exhaustive_low_range() {
        for n in 0u128..=100_000 {
            assert_floor_sqrt(n);
        }
    }

    #[test]
    fn sqrt_around_perfect_squares() {
        // Both sides of every perfect square up to 10^8, where the old Newton
        // loop is already 40+ iterations.
        for k in 1u128..=10_000 {
            let sq = k * k;
            assert_eq!(sqrt_u128(sq), k, "sqrt({k}^2)");
            assert_eq!(sqrt_u128(sq - 1), k - 1, "sqrt({k}^2 - 1)");
            assert_eq!(sqrt_u128(sq + 1), k, "sqrt({k}^2 + 1)");
            assert_floor_sqrt(sq - 1);
            assert_floor_sqrt(sq);
            assert_floor_sqrt(sq + 1);
        }
    }

    #[test]
    fn sqrt_u128_boundaries() {
        // `u128::MAX` is the input that overflowed `x + 1` in the old
        // implementation. Its floor root is `2^64 - 1`.
        let max = u128::MAX;
        assert_eq!(sqrt_u128(max), u64::MAX as u128);
        assert_floor_sqrt(max);
        assert_floor_sqrt(max - 1);
        assert_floor_sqrt(1u128 << 127);
        assert_floor_sqrt((1u128 << 127) - 1);
        assert_floor_sqrt(1u128 << 64);
        assert_floor_sqrt((1u128 << 64) - 1);
        assert_floor_sqrt(1u128 << 63);
        assert_eq!(sqrt_u128(1u128 << 64), 1u128 << 32);
        assert_eq!(sqrt_u128(1u128 << 126), 1u128 << 63);
    }

    #[test]
    fn sqrt_large_perfect_squares_and_neighbours() {
        let mut k: u128 = 1;
        // Walk k from 1 to ~2^32 - 1 in 9973 steps and also hit the top of the
        // range exactly, so both the "large perfect square" and the
        // "boundary between two of them" cases are covered.
        while k < (1u128 << 32) {
            let sq = k * k;
            assert_eq!(sqrt_u128(sq), k);
            assert_eq!(sqrt_u128(sq - 1), k - 1);
            assert_eq!(sqrt_u128(sq + 1), k);
            k += 9973;
        }
        let top = u64::MAX as u128;
        assert_eq!(sqrt_u128(top * top), top);
        assert_eq!(sqrt_u128(top * top - 1), top - 1);
        assert_eq!(sqrt_u128(top * top + 1), top);
        assert_floor_sqrt(top * top);
        assert_floor_sqrt(top * top - 1);
    }

    #[test]
    fn sqrt_pseudorandom_sweep() {
        // Deterministic LCG so the sweep is reproducible without a RNG
        // dependency in a no_std crate.
        let mut state: u128 = 0x2545_F491_4F6C_DD1D;
        for _ in 0..20_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            assert_floor_sqrt(state);
        }
    }

    #[test]
    fn quorum_exact_threshold() {
        assert_eq!(
            quorum_status(3, 5, 3),
            QuorumStatus::Met {
                required: 3,
                received: 3
            }
        );
        assert!(quorum_status(3, 5, 3).is_met());
        assert_eq!(quorum_status(1, 1, 1).missing(), 0);
        assert!(quorum_status(5, 5, 5).is_met());
    }

    #[test]
    fn quorum_one_below_threshold() {
        let s = quorum_status(3, 5, 2);
        assert!(!s.is_met());
        assert_eq!(
            s,
            QuorumStatus::NotMet {
                required: 3,
                received: 2,
                missing: 1
            }
        );
        assert_eq!(s.missing(), 1);
    }

    #[test]
    fn quorum_one_above_threshold() {
        assert_eq!(
            quorum_status(3, 5, 4),
            QuorumStatus::Met {
                required: 3,
                received: 4
            }
        );
    }

    #[test]
    fn zero_confirmations_never_reach_quorum() {
        // `m == 0` and `n == 0` are rejected outright (see the `should_panic`
        // cases below), so "all zero" can never mean "quorum trivially met".
        assert_eq!(quorum_status(1, 5, 0).missing(), 1);
        assert_eq!(quorum_status(5, 5, 0).missing(), 5);
    }

    #[test]
    #[should_panic(expected = "quorum: m must be in 1..=n")]
    fn quorum_rejects_zero_threshold() {
        let _ = quorum_status(0, 5, 0);
    }

    #[test]
    #[should_panic(expected = "quorum: m must be in 1..=n")]
    fn quorum_rejects_m_greater_than_n() {
        let _ = quorum_status(6, 5, 5);
    }

    #[test]
    #[should_panic(expected = "quorum: n must be non-zero")]
    fn quorum_rejects_empty_validator_set() {
        let _ = quorum_status(1, 0, 0);
    }

    #[test]
    #[should_panic(expected = "quorum: n must be non-zero")]
    fn quorum_rejects_all_zero() {
        let _ = quorum_status(0, 0, 0);
    }

    #[test]
    #[should_panic(expected = "quorum: received cannot exceed n")]
    fn quorum_rejects_impossible_confirmation_count() {
        let _ = quorum_status(1, 3, 4);
    }

    #[test]
    fn missing_counts_down_to_zero() {
        for received in 0..3u32 {
            let s = quorum_status(3, 5, received);
            assert!(!s.is_met());
            assert_eq!(s.missing(), 3 - received);
        }
        assert_eq!(quorum_status(3, 5, 3).missing(), 0);
    }

    #[test]
    fn duplicate_confirmations_count_once() {
        // One validator shouting five times must not reach a 3-of-5 quorum.
        let votes = [1u32, 1, 1, 1, 1];
        let received = count_distinct_voters(&votes, 5);
        assert_eq!(received, 1);
        assert!(!quorum_status(3, 5, received).is_met());
    }

    #[test]
    fn distinct_confirmations_count_once_each() {
        assert_eq!(count_distinct_voters(&[0, 1, 2, 3, 4], 5), 5);
        assert_eq!(count_distinct_voters(&[4, 3, 2, 1, 0], 5), 5);
        assert_eq!(count_distinct_voters(&[0, 0, 2, 2, 2, 4], 5), 3);
        assert!(quorum_status(3, 5, count_distinct_voters(&[0, 0, 2, 2, 2, 4], 5)).is_met());
    }

    #[test]
    fn empty_vote_set_never_reaches_quorum() {
        assert_eq!(count_distinct_voters(&[], 5), 0);
        let s = quorum_status(1, 5, count_distinct_voters(&[], 5));
        assert!(!s.is_met());
        assert_eq!(s.missing(), 1);
    }

    #[test]
    fn out_of_range_votes_are_ignored() {
        assert_eq!(count_distinct_voters(&[0, 1, 99, 100], 5), 2);
        assert_eq!(count_distinct_voters(&[99, 98], 5), 0);
        // The bitmask path (n <= 64) and the scan path (n > 64) must agree on
        // the entries they both consider in range.
        let votes = [0u32, 1, 65, 66, 65];
        assert_eq!(count_distinct_voters(&votes, 100), 4);
        assert_eq!(count_distinct_voters(&votes, 64), 2);
    }

    #[test]
    fn large_validator_set_uses_the_fallback_path() {
        let mut votes = [0u32; 100];
        for (i, slot) in votes.iter_mut().enumerate() {
            *slot = i as u32;
        }
        votes[3] = 1;
        votes[4] = 1;
        // 100 slots, but 3 and 4 never appear and 1 appears three times.
        assert_eq!(count_distinct_voters(&votes, 100), 98);
        assert!(quorum_status(60, 100, count_distinct_voters(&votes, 100)).is_met());
        assert!(!quorum_status(99, 100, count_distinct_voters(&votes, 100)).is_met());
    }
}

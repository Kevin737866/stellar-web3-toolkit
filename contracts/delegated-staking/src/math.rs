//! Fixed-point reward accounting for delegated staking.
//!
//! All reward distribution is done with an integer accumulator rather than
//! floating point, so the result is deterministic across hosts and identical on
//! a 32-bit and a 64-bit machine. There is no rounding *in* a token amount: the
//! index is scaled up by [`PRECISION`], proportional shares are computed in that
//! scaled domain, and the result is floored back to whole tokens. Flooring only
//! ever leaves dust in the contract, never pays out more than was funded.
//!
//! # Why `PRECISION` is `1e12` and not `1e18`
//!
//! The accumulator is `reward_per_token_stored`, an `i128`, and the accrual for
//! a position is
//!
//! ```text
//! amount * (index_now - index_paid) / PRECISION
//! ```
//!
//! `amount * index` must fit in an `i128` (`i128::MAX ≈ 1.7e38`). A 1e18 scale
//! would overflow for a position of `1e24` base units (one million tokens at 18
//! decimals) as soon as the index passed `1e14`, which a long-lived pool reaches
//! quickly. At 1e12 the same position tolerates an index up to `1e26`, which no
//! realistic reward rate reaches. The workspace release profile sets
//! `overflow-checks = true`, so an overflow here would be a contract panic, not
//! a silent wrap — another reason to keep the scale as low as precision allows.

/// Scale of the reward-per-token accumulator. Also the divisor that converts a
/// scaled index delta back into token base units.
pub const PRECISION: i128 = 1_000_000_000_000; // 1e12

/// Basis-point denominator: `10_000 bps = 100%`.
pub const BPS_DENOMINATOR: i128 = 10_000;

/// Hard cap on an operator's commission: `2_000 bps = 20%`.
///
/// A cap is what makes the "delegated" part safe: without it, an operator could
/// raise its commission to 100% between a delegator's quote and the transaction
/// landing, which is exactly the kind of front-running the `min_out` parameter
/// on `claim`/`compound` exists to catch.
pub const MAX_COMMISSION_BPS: u32 = 2_000;

/// Seconds a reward window actually distributes over.
///
/// Rewards stop accruing at `period_finish`, so a window that runs past the end
/// of the schedule contributes only up to that end. Equally, a window that
/// starts after the schedule ended contributes nothing. `last_update` can be
/// ahead of `period_finish` once the schedule has expired, hence the `0` guard.
pub fn distributable_seconds(last_update: u64, period_finish: u64, now: u64) -> u64 {
    let end = if now < period_finish { now } else { period_finish };
    if end <= last_update {
        0
    } else {
        end - last_update
    }
}

/// Rewards still owed by the current schedule, i.e. `rate *` time remaining.
///
/// Used when a new funding round starts mid-schedule: the unspent remainder is
/// rolled into the new rate instead of being silently cancelled.
pub fn remaining_rewards(reward_rate: i128, period_finish: u64, now: u64) -> i128 {
    if reward_rate <= 0 || now >= period_finish {
        return 0;
    }
    reward_rate
        .checked_mul((period_finish - now) as i128)
        .expect("remaining reward overflow")
}

/// Turns a funded amount into a per-second rate.
///
/// Integer division floors, so the schedule can pay out slightly *less* than was
/// funded; the dust stays in the contract. Paying out more would be a solvency
/// bug, so flooring is the correct direction.
pub fn reward_rate_for(amount: i128, duration_seconds: u64) -> i128 {
    assert!(amount > 0, "reward amount must be positive");
    assert!(duration_seconds > 0, "reward duration must be positive");
    amount / duration_seconds as i128
}

/// Index delta for one window, and the token amount that delta attributes back
/// to stakers.
///
/// The second value is deliberately not `rate * elapsed`: it is the index delta
/// floored back to tokens, so `rewards_credited` is exactly the sum the index can
/// hand out. Using the raw `rate * elapsed` would overstate the liability by the
/// rounding dust and make the solvency invariant look violated.
///
/// Returns `(0, 0)` when there is nothing to distribute — no stake, no rate, or
/// no elapsed time — so callers do not need to special-case a fresh pool.
pub fn reward_index_delta(
    reward_rate: i128,
    elapsed_seconds: u64,
    total_staked: i128,
) -> (i128, i128) {
    if reward_rate <= 0 || elapsed_seconds == 0 || total_staked <= 0 {
        return (0, 0);
    }
    let rewards = reward_rate
        .checked_mul(elapsed_seconds as i128)
        .expect("reward overflow");
    let delta = rewards
        .checked_mul(PRECISION)
        .expect("index overflow")
        / total_staked;
    let credited = delta
        .checked_mul(total_staked)
        .expect("credited overflow")
        / PRECISION;
    (delta, credited)
}

/// Rewards a position has earned since `index_paid`.
///
/// `index_now` is either `reward_per_token_stored` (settled) or the projected
/// index (the read-only `pending_rewards` view). Monotonicity is enforced by the
/// `<=` guard so a freshly created position, whose `index_paid` equals the
/// current index, accrues `0` rather than underflowing.
pub fn accrued_rewards(amount: i128, index_now: i128, index_paid: i128) -> i128 {
    if amount <= 0 || index_now <= index_paid {
        return 0;
    }
    (index_now - index_paid)
        .checked_mul(amount)
        .expect("accrual overflow")
        / PRECISION
}

/// Splits `gross` into `(delegator_net, operator_commission)`.
///
/// `commission_bps` must be at most [`MAX_COMMISSION_BPS`]; `add_operator` and
/// `set_commission` enforce that at the boundary, and this assert keeps the
/// invariant local so the split can never hand the operator the whole reward.
/// The operator's cut floors, so the delegator keeps any rounding remainder.
pub fn split_commission(gross: i128, commission_bps: u32) -> (i128, i128) {
    assert!(
        commission_bps <= MAX_COMMISSION_BPS,
        "commission exceeds the maximum"
    );
    if gross <= 0 {
        return (0, 0);
    }
    let commission = gross
        .checked_mul(commission_bps as i128)
        .expect("commission overflow")
        / BPS_DENOMINATOR;
    (gross - commission, commission)
}

#[cfg(test)]
mod math_tests {
    use super::*;

    #[test]
    fn nothing_to_distribute_returns_zero() {
        assert_eq!(reward_index_delta(0, 100, 1_000), (0, 0));
        assert_eq!(reward_index_delta(10, 0, 1_000), (0, 0));
        assert_eq!(reward_index_delta(10, 100, 0), (0, 0));
        assert_eq!(reward_index_delta(10, 100, -5), (0, 0));
    }

    #[test]
    fn index_delta_and_credited_are_consistent() {
        // 5 tokens/second for 100 seconds over 1_000 staked = 500 tokens.
        let (delta, credited) = reward_index_delta(5, 100, 1_000);
        assert_eq!(credited, 500);
        // The index alone would hand out exactly `credited` when applied to the
        // whole stake, which is what `rewards_credited` records.
        assert_eq!(delta * 1_000 / PRECISION, credited);
    }

    #[test]
    fn credited_never_exceeds_the_funded_amount() {
        // Deliberately awkward numbers so the division floors.
        for total in [3i128, 7, 999, 1_000_000] {
            let (_, credited) = reward_index_delta(1, 86_400, total);
            assert!(credited <= 86_400, "credited {credited} > funded");
        }
    }

    #[test]
    fn accrual_floors_and_guards_underflow() {
        // A position with nothing staked earns nothing.
        assert_eq!(accrued_rewards(0, PRECISION * 10, 0), 0);
        // An index that went backwards (never happens on chain) is treated as 0
        // rather than underflowing.
        assert_eq!(accrued_rewards(100, 5, 9), 0);
        // 100 staked across an index move of 0.5 tokens/token = 50.
        let half = PRECISION / 2;
        assert_eq!(accrued_rewards(100, half, 0), 50);
        // Sub-token dust is floored to zero rather than rounded up.
        assert_eq!(accrued_rewards(1, PRECISION - 1, 0), 0);
    }

    #[test]
    fn distributable_seconds_caps_at_the_period_end() {
        // Window entirely inside the schedule.
        assert_eq!(distributable_seconds(100, 200, 150), 50);
        // Window runs past the end: only up to the end counts.
        assert_eq!(distributable_seconds(150, 200, 250), 50);
        // Window starts after the schedule ended.
        assert_eq!(distributable_seconds(250, 200, 300), 0);
        // Exactly at the boundary is a zero-length window.
        assert_eq!(distributable_seconds(200, 200, 200), 0);
        // `last_update` ahead of the period end (expired schedule).
        assert_eq!(distributable_seconds(300, 200, 350), 0);
    }

    #[test]
    fn remaining_rewards_drops_to_zero_at_the_end() {
        assert_eq!(remaining_rewards(10, 200, 100), 1_000);
        assert_eq!(remaining_rewards(10, 200, 200), 0);
        assert_eq!(remaining_rewards(10, 200, 300), 0);
        assert_eq!(remaining_rewards(0, 200, 100), 0);
    }

    #[test]
    fn rate_floors_and_rejects_degenerate_inputs() {
        assert_eq!(reward_rate_for(1_000, 100), 10);
        // 100 over 3 seconds floors to 33/s, leaving 1 unit of dust.
        assert_eq!(reward_rate_for(100, 3), 33);
        assert_eq!(reward_rate_for(2, 10), 0);
    }

    #[test]
    #[should_panic(expected = "duration must be positive")]
    fn rate_rejects_zero_duration() {
        let _ = reward_rate_for(100, 0);
    }

    #[test]
    fn commission_split_sums_back_to_the_gross() {
        for bps in [0u32, 1, 500, 1_000, MAX_COMMISSION_BPS] {
            for gross in [0i128, 1, 3, 99, 10_000, 123_457] {
                let (net, commission) = split_commission(gross, bps);
                assert_eq!(net + commission, gross, "bps={bps} gross={gross}");
                assert!(net >= 0 && commission >= 0);
            }
        }
    }

    #[test]
    fn commission_never_exceeds_the_cap_share() {
        // The operator can never take more than the cap, no matter the gross.
        let (net, commission) = split_commission(1_000_000, MAX_COMMISSION_BPS);
        assert_eq!(commission, 200_000);
        assert_eq!(net, 800_000);
    }

    #[test]
    fn a_zero_commission_leaves_the_delegator_whole() {
        assert_eq!(split_commission(12_345, 0), (12_345, 0));
    }

    #[test]
    #[should_panic(expected = "commission exceeds the maximum")]
    fn commission_above_the_cap_is_rejected() {
        let _ = split_commission(1_000, MAX_COMMISSION_BPS + 1);
    }
}

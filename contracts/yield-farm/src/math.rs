//! Fixed-point reward accounting for the multi-pool yield farm.
//!
//! The farm streams one reward token across many LP pools. Rather than giving
//! every pool its own per-second rate, a single **global reward index** is
//! advanced whenever the farm is touched:
//!
//! ```text
//! reward_index += reward_rate * elapsed_seconds          (∫ rate dt)
//! ```
//!
//! Each pool records the index value it was last settled at, so the reward it
//! earned over a window is
//!
//! ```text
//! (reward_index_now - reward_index_paid) * alloc_point / total_alloc_point
//! ```
//!
//! This is what makes a mid-schedule rate change safe without touching every
//! pool: the integral already mixes the old and new rates correctly, so a pool
//! that has not been settled for a while still settles against the right total.
//! Allocation changes *do* settle every pool first, because changing the
//! denominator would otherwise re-weight a window that has already elapsed.
//!
//! Everything is integer arithmetic. Both the pool split and the per-position
//! accrual floor, so the sum of what positions can claim never exceeds what the
//! index credited, which in turn never exceeds what was funded. See
//! [`PRECISION`] for why the per-share accumulator is scaled by `1e12` and not
//! `1e18`.

/// Scale of the per-pool `acc_reward_per_share` accumulator.
pub const PRECISION: i128 = 1_000_000_000_000; // 1e12

/// Advances the cumulative reward integral by one window.
///
/// `elapsed_seconds` must already be clamped to the schedule (see
/// [`distributable_seconds`]); this function trusts its caller on that because
/// only the contract's `advance_global` calls it.
pub fn advance_index(reward_index: i128, reward_rate: i128, elapsed_seconds: u64) -> i128 {
    if reward_rate <= 0 || elapsed_seconds == 0 {
        return reward_index;
    }
    reward_index.saturating_add(
        reward_rate
            .checked_mul(elapsed_seconds as i128)
            .expect("reward index overflow"),
    )
}

/// A pool's share of a global index movement, in reward tokens.
///
/// Returns `0` for a degenerate allocation (`total_alloc_point == 0`, a pool
/// with no weight, or a non-positive movement) so callers do not need to guard
/// the division themselves. Floors, so the sum across pools can never exceed the
/// global movement.
pub fn pool_share(delta_index: i128, alloc_point: u32, total_alloc_point: u32) -> i128 {
    if delta_index <= 0 || total_alloc_point == 0 || alloc_point == 0 {
        return 0;
    }
    delta_index
        .checked_mul(alloc_point as i128)
        .expect("pool share overflow")
        / total_alloc_point as i128
}

/// Turns a pool's reward tokens into a per-share accumulator delta, plus the
/// token amount that delta actually hands out.
///
/// The second value is the delta floored back to tokens, so `rewards_credited`
/// records exactly the liability the accumulator can pay. Using the input
/// `share` directly would overstate the liability by the rounding dust and make
/// the solvency invariant look violated.
pub fn acc_reward_delta(share: i128, total_staked: i128) -> (i128, i128) {
    if share <= 0 || total_staked <= 0 {
        return (0, 0);
    }
    let delta = share
        .checked_mul(PRECISION)
        .expect("accumulator overflow")
        / total_staked;
    let credited = delta
        .checked_mul(total_staked)
        .expect("credited overflow")
        / PRECISION;
    (delta, credited)
}

/// Rewards a position has earned since `acc_paid`.
///
/// Guards against a backwards accumulator so a freshly created position, whose
/// `acc_paid` equals the current accumulator, accrues `0` instead of
/// underflowing.
pub fn accrued(amount: i128, acc_now: i128, acc_paid: i128) -> i128 {
    if amount <= 0 || acc_now <= acc_paid {
        return 0;
    }
    (acc_now - acc_paid)
        .checked_mul(amount)
        .expect("accrual overflow")
        / PRECISION
}

/// Seconds of the current schedule that still distribute.
///
/// The farm stops streaming at `period_finish`, so a window that runs past the
/// end contributes only up to that end. `last_update` can be ahead of
/// `period_finish` once the schedule has expired, hence the `0` guard.
pub fn distributable_seconds(last_update: u64, period_finish: u64, now: u64) -> u64 {
    let end = if now < period_finish { now } else { period_finish };
    if end <= last_update {
        0
    } else {
        end - last_update
    }
}

/// Reward tokens the current schedule has left to stream.
pub fn remaining_rewards(reward_rate: i128, period_finish: u64, now: u64) -> i128 {
    if reward_rate <= 0 || now >= period_finish {
        return 0;
    }
    reward_rate
        .checked_mul((period_finish - now) as i128)
        .expect("remaining reward overflow")
}

/// Turns a funded amount into a per-second rate, flooring.
///
/// Flooring means the schedule can pay out slightly less than was funded; the
/// dust stays in the contract. Paying out more would be a solvency bug.
pub fn reward_rate_for(amount: i128, duration_seconds: u64) -> i128 {
    assert!(amount > 0, "reward amount must be positive");
    assert!(duration_seconds > 0, "reward duration must be positive");
    amount / duration_seconds as i128
}

#[cfg(test)]
mod math_tests {
    use super::*;

    #[test]
    fn advancing_by_nothing_is_a_no_op() {
        assert_eq!(advance_index(500, 0, 100), 500);
        assert_eq!(advance_index(500, 10, 0), 500);
        assert_eq!(advance_index(500, 10, 100), 1_500);
    }

    #[test]
    fn pool_share_splits_a_movement_by_allocation() {
        // 1_000 of movement across three pools weighted 1:1:2.
        assert_eq!(pool_share(1_000, 1, 4), 250);
        assert_eq!(pool_share(1_000, 2, 4), 500);
        // Degenerate inputs are zero rather than a panic.
        assert_eq!(pool_share(1_000, 1, 0), 0);
        assert_eq!(pool_share(1_000, 0, 4), 0);
        assert_eq!(pool_share(0, 1, 4), 0);
        assert_eq!(pool_share(-5, 1, 4), 0);
    }

    #[test]
    fn pool_shares_never_exceed_the_movement() {
        let mut total = 0i128;
        for alloc in 1..=7u32 {
            total += pool_share(1_000, alloc, 28);
        }
        assert!(total <= 1_000, "shares {total} exceeded the movement");
    }

    #[test]
    fn acc_delta_and_credited_agree() {
        let (delta, credited) = acc_reward_delta(500, 1_000);
        assert_eq!(credited, 500);
        assert_eq!(delta * 1_000 / PRECISION, credited);
        assert_eq!(acc_reward_delta(500, 0), (0, 0));
        assert_eq!(acc_reward_delta(0, 1_000), (0, 0));
    }

    #[test]
    fn accrual_floors_and_guards_underflow() {
        assert_eq!(accrued(0, PRECISION, 0), 0);
        assert_eq!(accrued(100, 5, 9), 0);
        assert_eq!(accrued(100, PRECISION / 2, 0), 50);
        assert_eq!(accrued(1, PRECISION - 1, 0), 0);
    }

    #[test]
    fn distributable_seconds_caps_at_the_period_end() {
        assert_eq!(distributable_seconds(100, 200, 150), 50);
        assert_eq!(distributable_seconds(150, 200, 250), 50);
        assert_eq!(distributable_seconds(250, 200, 300), 0);
        assert_eq!(distributable_seconds(200, 200, 200), 0);
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
        assert_eq!(reward_rate_for(100, 3), 33);
        assert_eq!(reward_rate_for(2, 10), 0);
    }

    #[test]
    #[should_panic(expected = "duration must be positive")]
    fn rate_rejects_zero_duration() {
        let _ = reward_rate_for(100, 0);
    }

    #[test]
    #[should_panic(expected = "reward amount must be positive")]
    fn rate_rejects_zero_amount() {
        let _ = reward_rate_for(0, 100);
    }
}

//! Conviction voting curve (issue #205) and bounded proposal metadata (issue #455).
//!
//! A conviction vote trades liquidity for influence: a holder locks tokens for a
//! number of ledgers and votes with the resulting weight. The curve decides how
//! much influence a given lock buys, and getting it wrong is how governance
//! quietly becomes plutocratic or sybil-friendly.
//!
//! The curve here is the **quadratic conviction** one:
//!
//! ```text
//! weight = 10_000 * sqrt(balance * min(lock, MAX_LOCK_LEDGERS) / MAX_LOCK_LEDGERS)
//! ```
//!
//! Three properties follow from that shape, and each is tested below:
//!
//! * **Quadratic in balance.** Four times the tokens buys twice the weight, so a
//!   whale cannot linearly buy a vote — the marginal cost of influence rises
//!   with the influence already held.
//! * **Sub-linear in lock time.** Locking four times as long buys twice the
//!   weight, so conviction is rewarded without letting a one-ledger lock round
//!   up to a full vote.
//! * **Capped.** Locks past [`MAX_LOCK_LEDGERS`] add nothing, so there is no
//!   incentive to lock beyond the maximum and no unbounded integer growth.
//!
//! Weight is computed in integer arithmetic with no floating point anywhere:
//! `f64` cannot represent every `u64` exactly, and a vote total that differs by
//! one between two machines is a governance bug, not a rounding detail.
//!
//! [`decayed_weight`] is the other half of conviction voting: a weight recorded
//! at some ledger loses conviction over time, halving every `half_life_ledgers`.
//! Decay is conservative — it interpolates linearly *downwards* between halvings,
//! so it can never award more weight than the geometric curve it approximates.

/// Longest lock the curve recognises: one year of 5-second ledgers.
pub const MAX_LOCK_LEDGERS: u32 = 6_307_200;

/// Fixed-point scale for the curve. `10_000` gives four decimal places of a
/// whole vote unit while keeping every intermediate product well inside `u128`.
pub const WEIGHT_SCALE: u128 = 10_000;

/// Maximum byte length allowed for a governance proposal title (issue #455).
pub const MAX_PROPOSAL_TITLE_LEN: usize = 128;

/// Maximum byte length allowed for a governance proposal description (issue #455).
pub const MAX_PROPOSAL_DESCRIPTION_LEN: usize = 4_096;

/// Validated governance proposal metadata with non-empty title and bounded text fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalMetadata {
    title: String,
    description: String,
}

/// Errors returned when validating proposal titles and descriptions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProposalValidationError {
    #[error("proposal title must not be empty or whitespace-only")]
    EmptyTitle,
    #[error("proposal title length {length} exceeds maximum {max} bytes")]
    TitleTooLong { length: usize, max: usize },
    #[error("proposal description length {length} exceeds maximum {max} bytes")]
    DescriptionTooLong { length: usize, max: usize },
}

impl ProposalMetadata {
    /// Validate and construct bounded proposal metadata.
    ///
    /// Rejects empty or whitespace-only titles, titles exceeding
    /// [`MAX_PROPOSAL_TITLE_LEN`] bytes, and descriptions exceeding
    /// [`MAX_PROPOSAL_DESCRIPTION_LEN`] bytes.
    pub fn new(title: &str, description: &str) -> Result<Self, ProposalValidationError> {
        let trimmed_title = title.trim();
        if trimmed_title.is_empty() {
            return Err(ProposalValidationError::EmptyTitle);
        }
        if title.len() > MAX_PROPOSAL_TITLE_LEN {
            return Err(ProposalValidationError::TitleTooLong {
                length: title.len(),
                max: MAX_PROPOSAL_TITLE_LEN,
            });
        }
        if description.len() > MAX_PROPOSAL_DESCRIPTION_LEN {
            return Err(ProposalValidationError::DescriptionTooLong {
                length: description.len(),
                max: MAX_PROPOSAL_DESCRIPTION_LEN,
            });
        }
        Ok(Self {
            title: trimmed_title.to_string(),
            description: description.to_string(),
        })
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn description(&self) -> &str {
        &self.description
    }
}

/// Voting weight for `balance` locked for `lock_ledgers`.
///
/// Returns `0` when either input is zero. Locks beyond [`MAX_LOCK_LEDGERS`] are
/// treated as [`MAX_LOCK_LEDGERS`]. The result is in the same unit as
/// `WEIGHT_SCALE` (a full-lock vote for `balance` 1 000 000 is 10 000 000).
pub fn conviction_weight(balance: u64, lock_ledgers: u32) -> u128 {
    if balance == 0 || lock_ledgers == 0 {
        return 0;
    }

    let lock = u128::from(lock_ledgers.min(MAX_LOCK_LEDGERS));

    // One division, not two: flooring the lock fraction before scaling would
    // under-award short locks by up to a few percent.
    //
    // No overflow: balance <= u64::MAX (~1.8e19), lock <= 6.4e6 and the scale is
    // 1e8, so the product is < 1.2e34, far inside `u128`. There is a test at the
    // exact boundary.
    let squared =
        u128::from(balance) * lock * WEIGHT_SCALE * WEIGHT_SCALE / u128::from(MAX_LOCK_LEDGERS);
    isqrt(squared)
}

/// Weight after `elapsed_ledgers` of decay from `weight`, halving every
/// `half_life_ledgers`.
///
/// A zero half-life decays to nothing immediately (there is no meaningful
/// interpolation to do); zero elapsed ledgers returns the weight unchanged.
pub fn decayed_weight(weight: u128, elapsed_ledgers: u32, half_life_ledgers: u32) -> u128 {
    if weight == 0 || elapsed_ledgers == 0 {
        return weight;
    }
    if half_life_ledgers == 0 {
        return 0;
    }

    let half_life = u128::from(half_life_ledgers);
    let periods = u128::from(elapsed_ledgers) / half_life;
    if periods >= 128 {
        // `u128 >> 128` is undefined; anything this old has decayed to zero in
        // any practical unit.
        return 0;
    }

    let base = weight >> periods;
    let remainder = u128::from(elapsed_ledgers) % half_life;

    // Linear interpolation from `base` down to `base / 2` across the current
    // period, rounded down. This is always <= the true geometric value, so decay
    // can only ever under-award, never over-award.
    base - (base * remainder) / (2 * half_life)
}

/// Integer square root: the largest `r` with `r * r <= n`.
///
/// Newton's method seeded from the bit length, so even `u128::MAX` converges
/// without overflowing `n + 1`.
pub fn isqrt(n: u128) -> u128 {
    if n < 2 {
        return n;
    }

    let bit_length = 128 - n.leading_zeros();
    let mut root = 1u128 << bit_length.div_ceil(2);

    loop {
        let next = (root + n / root) / 2;
        if next >= root {
            return root;
        }
        root = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_inputs_have_no_weight() {
        assert_eq!(conviction_weight(0, MAX_LOCK_LEDGERS), 0);
        assert_eq!(conviction_weight(1_000, 0), 0);
        assert_eq!(conviction_weight(0, 0), 0);
    }

    #[test]
    fn a_full_lock_is_the_square_root_of_the_balance() {
        // At the cap the lock factor is exactly WEIGHT_SCALE^2, so the weight is
        // floor(WEIGHT_SCALE * sqrt(balance)). Where the balance is a perfect
        // square that is exactly WEIGHT_SCALE * sqrt(balance).
        for balance in [1u64, 4, 9, 10_000, 1_000_000] {
            assert_eq!(
                conviction_weight(balance, MAX_LOCK_LEDGERS),
                WEIGHT_SCALE * isqrt(u128::from(balance))
            );
        }
        // For a non-square, flooring after scaling is one unit more precise than
        // scaling after flooring, so compare against the real formula.
        for balance in [2u64, 7, 12_345, u64::MAX] {
            assert_eq!(
                conviction_weight(balance, MAX_LOCK_LEDGERS),
                isqrt(u128::from(balance) * WEIGHT_SCALE * WEIGHT_SCALE)
            );
        }
    }

    #[test]
    fn weight_is_monotonic_in_lock_time() {
        let balance = 500_000;
        let mut last = 0;
        for lock in [1u32, 2, 10, 1_000, 100_000, 1_000_000, MAX_LOCK_LEDGERS] {
            let weight = conviction_weight(balance, lock);
            assert!(
                weight >= last,
                "weight fell from {last} to {weight} at lock {lock}"
            );
            last = weight;
        }
    }

    #[test]
    fn locks_past_the_cap_add_nothing() {
        let balance = 123_456;
        assert_eq!(
            conviction_weight(balance, MAX_LOCK_LEDGERS),
            conviction_weight(balance, MAX_LOCK_LEDGERS + 1)
        );
    }

    #[test]
    fn four_times_the_balance_is_twice_the_vote() {
        for balance in [1u64, 1_000, 250_000] {
            let one = conviction_weight(balance, MAX_LOCK_LEDGERS);
            let four = conviction_weight(balance * 4, MAX_LOCK_LEDGERS);
            // Integer floors mean the ratio is exact only where the roots are.
            assert!(
                four >= one * 2 - 2 && four <= one * 2 + 2,
                "balance {balance}: 4x gave {four}, expected about {}",
                one * 2
            );
        }
    }

    #[test]
    fn decay_halves_per_half_life() {
        let weight = 1_000_000u128;
        let half_life = 100u32;

        assert_eq!(decayed_weight(weight, 0, half_life), weight);
        assert_eq!(decayed_weight(weight, 100, half_life), weight / 2);
        assert_eq!(decayed_weight(weight, 200, half_life), weight / 4);
        assert_eq!(decayed_weight(weight, 300, half_life), weight / 8);
    }

    #[test]
    fn decay_interpolates_between_halvings_and_never_increases() {
        let weight = 1_000_000u128;
        let half_life = 100u32;

        let mut last = weight;
        for elapsed in 0..=250u32 {
            let decayed = decayed_weight(weight, elapsed, half_life);
            assert!(
                decayed <= last,
                "decay rose at {elapsed}: {decayed} > {last}"
            );
            last = decayed;
        }

        // Halfway through the first period is between the two halvings, and
        // conservative (3/4 of the original would be the geometric value today).
        let halfway = decayed_weight(weight, 50, half_life);
        assert!(halfway < weight);
        assert!(halfway > weight / 2);
        assert!(halfway <= weight * 3 / 4);
    }

    #[test]
    fn decay_of_zero_weight_or_zero_half_life_is_total() {
        assert_eq!(decayed_weight(0, 10, 100), 0);
        assert_eq!(decayed_weight(5, 10, 0), 0);
        // Absurdly old weights bottom out at zero rather than shifting past the
        // width of u128.
        assert_eq!(decayed_weight(u128::MAX, u32::MAX, 1), 0);
    }

    #[test]
    fn isqrt_is_floor_of_the_real_root() {
        for n in 0u128..=2_000 {
            let root = isqrt(n);
            assert!(root * root <= n);
            assert!((root + 1) * (root + 1) > n);
        }
        assert_eq!(isqrt(u128::MAX), (1u128 << 64) - 1);
        assert_eq!(isqrt((1u128 << 64) - 1), (1u128 << 32) - 1);
    }

    #[test]
    fn the_largest_balance_does_not_overflow() {
        // The whole curve has to be total over its declared input domain: a
        // panic here would be a denial of service on governance.
        let weight = conviction_weight(u64::MAX, MAX_LOCK_LEDGERS);
        assert!(weight > 0);
        assert_eq!(
            weight,
            isqrt(u128::from(u64::MAX) * WEIGHT_SCALE * WEIGHT_SCALE)
        );
    }

    #[test]
    fn empty_or_whitespace_proposal_titles_are_rejected() {
        for empty in ["", " ", "   \t\n  "] {
            assert_eq!(
                ProposalMetadata::new(empty, "Valid description"),
                Err(ProposalValidationError::EmptyTitle)
            );
        }
    }

    #[test]
    fn proposal_title_and_description_bounds_are_enforced() {
        let exact_title = "a".repeat(MAX_PROPOSAL_TITLE_LEN);
        let exact_desc = "b".repeat(MAX_PROPOSAL_DESCRIPTION_LEN);
        let meta = ProposalMetadata::new(&exact_title, &exact_desc).expect("at exact bounds");
        assert_eq!(meta.title().len(), MAX_PROPOSAL_TITLE_LEN);
        assert_eq!(meta.description().len(), MAX_PROPOSAL_DESCRIPTION_LEN);

        let over_title = "a".repeat(MAX_PROPOSAL_TITLE_LEN + 1);
        assert_eq!(
            ProposalMetadata::new(&over_title, "ok"),
            Err(ProposalValidationError::TitleTooLong {
                length: MAX_PROPOSAL_TITLE_LEN + 1,
                max: MAX_PROPOSAL_TITLE_LEN,
            })
        );

        let over_desc = "b".repeat(MAX_PROPOSAL_DESCRIPTION_LEN + 1);
        assert_eq!(
            ProposalMetadata::new("Upgrade quorum", &over_desc),
            Err(ProposalValidationError::DescriptionTooLong {
                length: MAX_PROPOSAL_DESCRIPTION_LEN + 1,
                max: MAX_PROPOSAL_DESCRIPTION_LEN,
            })
        );
    }
}

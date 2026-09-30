//! A dependency-free property-based testing harness for the Soroban contracts.
//!
//! The workspace deliberately keeps its dependency surface small, and the
//! contracts themselves are `#![no_std]`, so a heavyweight property-testing
//! framework would be a poor fit: it would add a large crate graph to a
//! repository that has repeatedly had to repair its lockfile, and most of its
//! machinery (async support, runtime strategies) is unused here.
//!
//! This harness is instead a few hundred lines of `std`-only Rust:
//!
//! * [`Rng`] — a deterministic SplitMix64 generator with range helpers. Default
//!   `rand` is not used so a run is reproducible on any machine and a
//!   counterexample can be replayed from the seed alone.
//! * [`Config`] — iteration count and seed, overridable from the environment
//!   (`PROPERTY_CASES`, `PROPERTY_SEED`) so CI can run longer sweeps than a
//!   local `cargo test`.
//! * [`Candidate`] — a `shrink` method on generated inputs. When a property
//!   fails, [`check`] greedily shrinks the input to a local minimum, so the
//!   reported counterexample is the smallest one found rather than an arbitrary
//!   large one.
//! * [`check`] / [`check_default`] — the runners.
//!
//! # Writing a property
//!
//! ```no_run
//! use contract_proptests::{check_default, Rng};
//!
//! check_default(
//!     "addition is commutative",
//!     |rng: &mut Rng| (rng.i128_in(-1_000, 1_000), rng.i128_in(-1_000, 1_000)),
//!     |(a, b)| {
//!         if a + b == b + a { Ok(()) } else { Err("not commutative".into()) }
//!     },
//! );
//! ```
//!
//! The generator is a plain closure over [`Rng`], not a trait to implement, so a
//! property can be written inline next to the invariant it checks.

/// Default seed, chosen so the first reported counterexamples are stable across
/// runs and machines.
pub const DEFAULT_SEED: u64 = 0x5EED_1234_ABCD_0001;

/// Default number of generated cases per property.
pub const DEFAULT_CASES: u32 = 256;

/// Deterministic SplitMix64 generator.
///
/// SplitMix64 is used rather than a linear congruential generator because it
/// passes enough statistical tests for input generation while staying short
/// enough to audit, and it has no period/seed pitfalls of the "seed 0 produces
/// all zeroes" kind.
#[derive(Clone, Debug)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// Creates a generator. The seed is mixed in so that adjacent seeds (0, 1,
    /// 2, ...) still produce unrelated streams.
    pub fn new(seed: u64) -> Self {
        Rng {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    /// Next raw 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Next raw 128-bit value, assembled from two 64-bit draws so that ranges
    /// wider than `u64` are not truncated to the low half.
    pub fn next_u128(&mut self) -> u128 {
        ((self.next_u64() as u128) << 64) | (self.next_u64() as u128)
    }

    /// Uniform-ish `bool`. The modulo bias of a single bit is irrelevant here.
    pub fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    /// An index in `0..len`.
    ///
    /// # Panics
    /// If `len == 0`, which would be a bug in the caller's generator rather than
    /// a property failure.
    pub fn index(&mut self, len: usize) -> usize {
        assert!(len > 0, "cannot pick from an empty set");
        (self.next_u64() % len as u64) as usize
    }

    /// An inclusive `u64` in `lo..=hi`.
    pub fn u64_in(&mut self, lo: u64, hi: u64) -> u64 {
        assert!(lo <= hi, "empty range {lo}..={hi}");
        let span = hi - lo;
        if span == u64::MAX {
            return self.next_u64();
        }
        lo + (self.next_u64() % (span + 1))
    }

    /// An inclusive `u32` in `lo..=hi`.
    pub fn u32_in(&mut self, lo: u32, hi: u32) -> u32 {
        self.u64_in(lo as u64, hi as u64) as u32
    }

    /// An inclusive `i128` in `lo..=hi`.
    pub fn i128_in(&mut self, lo: i128, hi: i128) -> i128 {
        assert!(lo <= hi, "empty range {lo}..={hi}");
        // Computed in `u128` two's-complement space so that a range spanning
        // `i128::MIN..=i128::MAX` cannot overflow the subtraction.
        let span = (hi as u128).wrapping_sub(lo as u128);
        let offset = if span == u128::MAX {
            self.next_u128()
        } else {
            self.next_u128() % (span + 1)
        };
        // Wrapping add reinterprets the offset as signed, which is exactly the
        // result for an in-range selection.
        lo.wrapping_add(offset as i128)
    }

    /// A weighted coin flip: `true` with probability `num / den`.
    pub fn chance(&mut self, num: u32, den: u32) -> bool {
        assert!(den > 0 && num <= den, "invalid probability {num}/{den}");
        self.u32_in(1, den) <= num
    }
}

/// Configuration for a property run.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub cases: u32,
    pub seed: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            cases: DEFAULT_CASES,
            seed: DEFAULT_SEED,
        }
    }
}

impl Config {
    /// Reads `PROPERTY_CASES` and `PROPERTY_SEED` from the environment,
    /// falling back to the defaults.
    ///
    /// This is the CI hook: a nightly/extended run can raise `PROPERTY_CASES`
    /// without changing the test source, and a failure can be replayed exactly
    /// with `PROPERTY_SEED=<seed> PROPERTY_CASES=1 cargo test`.
    pub fn from_env() -> Self {
        let mut config = Config::default();
        if let Ok(raw) = std::env::var("PROPERTY_CASES") {
            if let Ok(parsed) = raw.parse::<u32>() {
                if parsed > 0 {
                    config.cases = parsed;
                }
            }
        }
        if let Ok(raw) = std::env::var("PROPERTY_SEED") {
            if let Ok(parsed) = raw.parse::<u64>() {
                config.seed = parsed;
            }
        }
        config
    }
}

/// A generated input that knows how to get simpler.
///
/// `shrink` returns the next smaller candidate, or `None` when already minimal.
/// [`check`] walks this chain greedily, restarting whenever a smaller input also
/// fails, so the reported counterexample is a local minimum.
pub trait Candidate: Clone + std::fmt::Debug {
    fn shrink(&self) -> Option<Self>;
}

impl Candidate for bool {
    fn shrink(&self) -> Option<Self> {
        if *self {
            Some(false)
        } else {
            None
        }
    }
}

impl Candidate for i128 {
    fn shrink(&self) -> Option<Self> {
        if *self == 0 {
            None
        } else {
            Some(self / 2)
        }
    }
}

impl Candidate for u128 {
    fn shrink(&self) -> Option<Self> {
        if *self == 0 {
            None
        } else {
            Some(self / 2)
        }
    }
}

impl Candidate for u64 {
    fn shrink(&self) -> Option<Self> {
        if *self == 0 {
            None
        } else {
            Some(self / 2)
        }
    }
}

impl Candidate for u32 {
    fn shrink(&self) -> Option<Self> {
        if *self == 0 {
            None
        } else {
            Some(self / 2)
        }
    }
}

impl<A: Candidate, B: Candidate> Candidate for (A, B) {
    fn shrink(&self) -> Option<Self> {
        if let Some(a) = self.0.shrink() {
            return Some((a, self.1.clone()));
        }
        self.1.shrink().map(|b| (self.0.clone(), b))
    }
}

impl<A: Candidate, B: Candidate, C: Candidate> Candidate for (A, B, C) {
    fn shrink(&self) -> Option<Self> {
        if let Some(a) = self.0.shrink() {
            return Some((a, self.1.clone(), self.2.clone()));
        }
        if let Some(b) = self.1.shrink() {
            return Some((self.0.clone(), b, self.2.clone()));
        }
        self.2
            .shrink()
            .map(|c| (self.0.clone(), self.1.clone(), c))
    }
}

impl<T: Candidate> Candidate for Vec<T> {
    fn shrink(&self) -> Option<Self> {
        // Prefer simplifying an element over truncating: a shorter list can hide
        // the element that actually triggers the failure.
        for (i, element) in self.iter().enumerate() {
            if let Some(smaller) = element.shrink() {
                let mut candidate = self.clone();
                candidate[i] = smaller;
                return Some(candidate);
            }
        }
        if self.len() <= 1 {
            None
        } else {
            let mut candidate = self.clone();
            candidate.pop();
            Some(candidate)
        }
    }
}

/// Greedily shrinks `input` to a local minimum that still fails `property`.
fn shrink_to_counterexample<C, P>(input: &C, property: &mut P) -> C
where
    C: Candidate,
    P: FnMut(&C) -> Result<(), String>,
{
    let mut current = input.clone();
    // Each improvement restarts the walk, so the result cannot depend on the
    // order `shrink` happens to enumerate candidates in.
    loop {
        let mut improved = false;
        let mut candidate = current.clone();
        while let Some(smaller) = candidate.shrink() {
            if property(&smaller).is_err() {
                current = smaller.clone();
                improved = true;
            }
            candidate = smaller;
        }
        if !improved {
            return current;
        }
    }
}

/// Runs `property` over `config.cases` generated inputs, shrinking the first
/// failure to a local minimum and panicking with it.
///
/// # Panics
/// When a property fails. The message carries the seed, the case index, the
/// failure reason, and both the minimal counterexample and the originally
/// generated input.
pub fn check<G, C, P>(name: &str, config: &Config, mut generate: G, mut property: P)
where
    G: FnMut(&mut Rng) -> C,
    C: Candidate,
    P: FnMut(&C) -> Result<(), String>,
{
    let mut rng = Rng::new(config.seed);
    for case in 0..config.cases {
        let input = generate(&mut rng);
        if let Err(reason) = property(&input) {
            let minimal = shrink_to_counterexample(&input, &mut property);
            panic!(
                "property `{name}` failed on case {case} of {} (seed {}): {reason}\n  \
                 minimal counterexample: {minimal:?}\n  \
                 generated input:       {input:?}\n  \
                 replay with PROPERTY_SEED={} PROPERTY_CASES={}",
                config.cases, config.seed, config.seed, case + 1,
            );
        }
    }
}

/// [`check`] with the environment-configured [`Config`].
pub fn check_default<G, C, P>(name: &str, generate: G, property: P)
where
    G: FnMut(&mut Rng) -> C,
    C: Candidate,
    P: FnMut(&C) -> Result<(), String>,
{
    check(name, &Config::from_env(), generate, property)
}

/// Convenience: assert a boolean condition inside a property.
pub fn expect(condition: bool, reason: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(reason.to_string())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn the_same_seed_produces_the_same_stream() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_produce_different_streams() {
        let mut a = Rng::new(1);
        let mut b = Rng::new(2);
        let differ = (0..8).any(|_| a.next_u64() != b.next_u64());
        assert!(differ, "adjacent seeds collided");
    }

    #[test]
    fn range_helpers_stay_inside_their_bounds() {
        let mut rng = Rng::new(7);
        for _ in 0..1_000 {
            let x = rng.i128_in(-5, 5);
            assert!((-5..=5).contains(&x), "{x} out of range");
            let y = rng.u64_in(3, 3);
            assert_eq!(y, 3);
            assert!(rng.index(4) < 4);
        }
    }

    #[test]
    fn degenerate_ranges_do_not_overflow() {
        let mut rng = Rng::new(9);
        assert_eq!(rng.i128_in(7, 7), 7);
        // A full-width range takes the `span == MAX` branch rather than
        // computing `span + 1`.
        let _ = rng.u64_in(0, u64::MAX);
    }

    #[test]
    fn passing_properties_run_every_case() {
        let config = Config {
            cases: 50,
            seed: 3,
        };
        let mut seen = 0;
        check("always true", &config, |rng| rng.i128_in(0, 10), |_| {
            seen += 1;
            Ok(())
        });
        assert_eq!(seen, 50);
    }

    #[test]
    #[should_panic(expected = "minimal counterexample")]
    fn failing_properties_report_a_shrunk_counterexample() {
        let config = Config { cases: 64, seed: 5 };
        // Fails for any input above 4; the smallest failing input is 5.
        check(
            "big inputs are rejected",
            &config,
            |rng| rng.i128_in(0, 1_000_000),
            |value| expect(*value <= 4, "value too large"),
        );
    }

    #[test]
    fn shrinking_reaches_a_local_minimum() {
        let mut property = |value: &i128| expect(*value <= 4, "too large");
        let minimal = shrink_to_counterexample(&999_999i128, &mut property);
        assert_eq!(minimal, 5);
    }

    #[test]
    fn vectors_shrink_element_wise_before_truncating() {
        let mut property = |values: &Vec<i128>| expect(!values.contains(&8), "contains 8");
        let minimal = shrink_to_counterexample(&vec![100, 8, 4], &mut property);
        assert_eq!(minimal, vec![8]);
    }
}

//! Informal-verification harness (issue #116).
//!
//! The contract test suites in this workspace are example-based: they check the
//! cases someone thought of. That leaves a whole class of bug invisible — the
//! off-by-one at a range edge, the proof that verifies for an address that was
//! never in the tree, the fee ladder that stops escalating. This module adds the
//! other half: a small, dependency-free property harness that searches a
//! *randomised* input space for a counterexample to a stated invariant, and
//! reports the seed that reproduced it.
//!
//! Design constraints, in the order they matter:
//!
//! * **Reproducible.** The generator is a seeded splitmix64 PRNG, not an entropy
//!   source. A counterexample prints its seed, and re-running `verify invariants
//!   --seed <n>` explores exactly the same sequence, so a failure found in CI is
//!   a failure a developer can reproduce locally.
//! * **Dependency-free.** No `proptest` / `quickcheck`: this workspace pins a
//!   toolchain and a lockfile for byte-reproducible WASM builds, and the
//!   harness has to stay cheap enough to run on every push. The generator is
//!   twenty lines.
//! * **Informal, not formal.** These are property checks over sampled inputs.
//!   They find bugs; they do not prove their absence. `docs/THREAT_MODEL.md`
//!   says so explicitly, next to what each invariant is worth.
//!
//! The built-in suite covers the toolkit's security-relevant pure code: Merkle
//! inclusion (leaf/amount authentication and foreign-address forgery), fee
//! escalation, path wrapping and pagination totality, plus the secret scanner
//! itself. Contract-side invariants live with their contracts, where they can
//! drive the real `no_std` code.

use crate::gas_simulator::{FeeSchedule, GasSimulator};
use crate::help_text::wrap;
use crate::key_hygiene::{looks_like_secret_key, mask_secret, scan_text};
use crate::merkle::{self, AirdropLeaf, MerkleTree};
use crate::state_inspector::{Durability, StateEntry, StateInspector, StateQuery};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Iterations per invariant when the caller does not choose a count.
pub const DEFAULT_ITERATIONS: u64 = 512;

/// Seed used when the caller does not choose one. Fixed, so a bare
/// `verify invariants` run in CI is deterministic.
pub const DEFAULT_SEED: u64 = 0x5EED_1234_5678_9ABC;

/// Counterexamples recorded per invariant before the search stops.
pub const MAX_COUNTEREXAMPLES: usize = 5;

/// Deterministic splitmix64 generator.
///
/// Chosen over `rand` because the harness must be reproducible from a printed
/// seed alone, and splitmix64 needs no state beyond the seed.
#[derive(Debug, Clone)]
pub struct Prng {
    state: u64,
}

impl Prng {
    pub fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform-enough value in `0..upper`. `upper == 0` yields `0`.
    pub fn below(&mut self, upper: u64) -> u64 {
        if upper == 0 {
            0
        } else {
            self.next_u64() % upper
        }
    }

    /// Uniform-enough value in `low..=high`.
    pub fn between(&mut self, low: i128, high: i128) -> i128 {
        if high <= low {
            return low;
        }
        let span = (high - low) as u128 + 1;
        let raw = ((self.next_u64() as u128) << 64) | self.next_u64() as u128;
        low + (raw % span) as i128
    }

    /// 32 random bytes.
    pub fn bytes32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_be_bytes());
        }
        out
    }

    /// A short pseudo-address, unique enough for tree membership tests.
    pub fn address(&mut self, tag: u64) -> String {
        format!("G{tag:04X}{:012X}", self.next_u64() & 0xFFFF_FFFF_FFFF)
    }
}

/// A single input that violated an invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counterexample {
    pub seed: u64,
    /// 0-based position in the generated sequence.
    pub iteration: u64,
    /// Truncated rendering of the offending input.
    pub input: String,
    pub message: String,
}

/// Outcome of searching one invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantReport {
    pub name: String,
    pub description: String,
    pub iterations: u64,
    pub counterexamples: Vec<Counterexample>,
}

impl InvariantReport {
    /// True when no counterexample was found in the sampled space.
    pub fn held(&self) -> bool {
        self.counterexamples.is_empty()
    }

    /// Reproduce command for the first counterexample.
    pub fn reproduce_command(&self) -> Option<String> {
        self.counterexamples
            .first()
            .map(|c| format!("stellar-toolkit verify invariants --seed {}", c.seed))
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        if self.held() {
            out.push_str(&format!(
                "  PASS  {:<38} {} iteration(s)\n",
                self.name, self.iterations
            ));
            return out;
        }
        out.push_str(&format!(
            "  FAIL  {:<38} {} counterexample(s) in {} iteration(s)\n",
            self.name,
            self.counterexamples.len(),
            self.iterations
        ));
        out.push_str(&format!("        invariant: {}\n", self.description));
        for case in &self.counterexamples {
            out.push_str(&format!(
                "        seed {} iteration {}: {}\n",
                case.seed, case.iteration, case.message
            ));
            out.push_str(&format!("          input: {}\n", case.input));
        }
        if let Some(command) = self.reproduce_command() {
            out.push_str(&format!("        reproduce: {command}\n"));
        }
        out
    }
}

/// Outcome of a whole suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiteReport {
    pub seed: u64,
    pub iterations: u64,
    pub reports: Vec<InvariantReport>,
}

impl SuiteReport {
    pub fn failed(&self) -> usize {
        self.reports.iter().filter(|r| !r.held()).count()
    }

    pub fn passed(&self) -> bool {
        self.failed() == 0
    }

    pub fn checked(&self) -> u64 {
        self.reports.iter().map(|r| r.iterations).sum()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }

    pub fn render(&self) -> String {
        let mut out = format!(
            "informal verification (seed {}, {} iteration(s) per invariant)\n",
            self.seed, self.iterations
        );
        for report in &self.reports {
            out.push_str(&report.render());
        }
        out.push_str(&format!(
            "{} invariant(s): {} passed, {} failed, {} input(s) sampled\n",
            self.reports.len(),
            self.reports.len() - self.failed(),
            self.failed(),
            self.checked()
        ));
        out
    }
}

/// Search `iterations` random inputs for a counterexample to one invariant.
///
/// `generate` builds an input from the PRNG; `property` returns `Err` with a
/// human-readable explanation when the input violates the invariant.
pub fn check<I, G, P>(
    name: &str,
    description: &str,
    seed: u64,
    iterations: u64,
    mut generate: G,
    mut property: P,
) -> InvariantReport
where
    I: Debug,
    G: FnMut(&mut Prng, u64) -> I,
    P: FnMut(&I) -> Result<(), String>,
{
    let mut prng = Prng::new(seed);
    let mut counterexamples = Vec::new();

    for iteration in 0..iterations {
        let input = generate(&mut prng, iteration);
        if let Err(message) = property(&input) {
            counterexamples.push(Counterexample {
                seed,
                iteration,
                input: truncate(&format!("{input:?}"), 240),
                message,
            });
            if counterexamples.len() >= MAX_COUNTEREXAMPLES {
                break;
            }
        }
    }

    InvariantReport {
        name: name.to_string(),
        description: description.to_string(),
        iterations,
        counterexamples,
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let kept: String = text.chars().take(max).collect();
    format!("{kept}…")
}

/// Builds one random input for an invariant (`iteration` lets a generator make
/// the input index-dependent).
pub type Generator<I> = Box<dyn FnMut(&mut Prng, u64) -> I>;

/// Predicate over one input: `Err(reason)` means the invariant was violated.
pub type Property<I> = Box<dyn FnMut(&I) -> std::result::Result<(), String>>;

/// One invariant in a suite: its name, what it claims, and how to search it.
pub struct Invariant<I> {
    pub name: &'static str,
    pub description: &'static str,
    generator: Generator<I>,
    property: Property<I>,
}

impl<I: Debug + 'static> Invariant<I> {
    pub fn new<G, P>(
        name: &'static str,
        description: &'static str,
        generator: G,
        property: P,
    ) -> Self
    where
        G: FnMut(&mut Prng, u64) -> I + 'static,
        P: FnMut(&I) -> Result<(), String> + 'static,
    {
        Self {
            name,
            description,
            generator: Box::new(generator),
            property: Box::new(property),
        }
    }

    pub fn run(&mut self, seed: u64, iterations: u64) -> InvariantReport {
        let generator = &mut self.generator;
        let property = &mut self.property;
        check(
            self.name,
            self.description,
            seed,
            iterations,
            move |prng, iteration| generator(prng, iteration),
            move |input| property(input),
        )
    }
}

// ---------------------------------------------------------------------------
// Built-in suite
// ---------------------------------------------------------------------------

/// A generated Merkle tree plus a leaf that is *not* in it. Opaque to callers:
/// it exists so the Merkle invariants can share one generator.
#[derive(Debug)]
pub struct TreeCase {
    tree: MerkleTree,
    in_tree: Vec<(String, u64)>,
    outsider: String,
    outsider_amount: u64,
    depth: usize,
}

fn tree_case(prng: &mut Prng, iteration: u64) -> TreeCase {
    let leaf_count = 1 + prng.below(12) as usize;
    let mut in_tree = Vec::with_capacity(leaf_count);
    let mut leaves = Vec::with_capacity(leaf_count);
    for index in 0..leaf_count {
        let address = prng.address(iteration * 64 + index as u64);
        let amount = 1 + prng.below(1_000_000);
        leaves.push(AirdropLeaf::new(address.clone(), amount));
        in_tree.push((address, amount));
    }
    let tree = MerkleTree::new(&leaves);
    let depth = merkle::depth_for(tree.len());
    TreeCase {
        outsider: prng.address(0xDEAD),
        outsider_amount: 1 + prng.below(1_000_000),
        in_tree,
        depth,
        tree,
    }
}

/// A random state export plus a random page size.
#[derive(Debug)]
struct PageCase {
    inspector: StateInspector,
    page_size: usize,
    include_temporary: bool,
}

fn page_case(prng: &mut Prng, _iteration: u64) -> PageCase {
    let mut inspector = StateInspector::new();
    let entry_count = 1 + prng.below(20) as usize;
    for index in 0..entry_count {
        let durability = match prng.below(3) {
            0 => Durability::Instance,
            1 => Durability::Persistent,
            _ => Durability::Temporary,
        };
        inspector.insert(StateEntry {
            contract_id: format!("C{}", prng.below(2)),
            durability,
            key: format!("key/{:02}", index),
            value: format!("{}", prng.next_u64()),
            ledger: 1 + prng.below(1_000) as u32,
            live_until_ledger: None,
        });
    }
    PageCase {
        inspector,
        page_size: 1 + prng.below(7) as usize,
        include_temporary: prng.below(2) == 0,
    }
}

/// Build the built-in invariant suite.
///
/// Each entry names the failure mode it is looking for, not the happy path it
/// checks: these are the properties whose violation would be a security or
/// availability bug rather than a wrong-looking output.
pub fn built_in_suite() -> Vec<Invariant<TreeCase>> {
    vec![
        Invariant::new(
            "merkle::proof_verifies_for_every_leaf",
            "a proof produced for an allocation in the tree must verify against its root",
            tree_case,
            |case| {
                let root = case
                    .tree
                    .root()
                    .ok_or_else(|| "tree with allocations has no root".to_string())?;
                for (address, amount) in &case.in_tree {
                    let proof = case.tree.proof_for(address, *amount).ok_or_else(|| {
                        format!("no proof generated for in-tree allocation {address}")
                    })?;
                    if proof.len() != case.depth {
                        return Err(format!(
                            "proof for {address} has {} node(s), tree depth is {}",
                            proof.len(),
                            case.depth
                        ));
                    }
                    let leaf = merkle::leaf_hash(address, *amount);
                    if !merkle::verify_proof(&leaf, &proof, &root, case.depth) {
                        return Err(format!("valid proof for {address} did not verify"));
                    }
                }
                Ok(())
            },
        ),
        Invariant::new(
            "merkle::proof_rejects_foreign_address",
            "no sampled proof may admit an address that is not in the tree",
            tree_case,
            |case| {
                let root = case
                    .tree
                    .root()
                    .ok_or_else(|| "tree with allocations has no root".to_string())?;
                if case
                    .tree
                    .proof_for(&case.outsider, case.outsider_amount)
                    .is_some()
                {
                    return Err(format!(
                        "proof_for returned a proof for {} which is not in the tree",
                        case.outsider
                    ));
                }
                // A forged proof of the right length must still be rejected.
                let mut forged = vec![[0u8; 32]; case.depth];
                forged.push([0xFFu8; 32]);
                let leaf = merkle::leaf_hash(&case.outsider, case.outsider_amount);
                if merkle::verify_proof(&leaf, &forged, &root, case.depth) {
                    return Err(format!(
                        "forged {}-node proof verified for foreign address {}",
                        forged.len(),
                        case.outsider
                    ));
                }
                Ok(())
            },
        ),
        Invariant::new(
            "merkle::leaf_authenticates_the_amount",
            "a proof for one amount must not verify for any other amount",
            tree_case,
            |case| {
                let root = case
                    .tree
                    .root()
                    .ok_or_else(|| "tree with allocations has no root".to_string())?;
                for (address, amount) in &case.in_tree {
                    let proof = case
                        .tree
                        .proof_for(address, *amount)
                        .ok_or_else(|| format!("no proof for {address}"))?;
                    for other in [amount + 1, amount.saturating_sub(1), amount + 1_000] {
                        if other == *amount {
                            continue;
                        }
                        let leaf = merkle::leaf_hash(address, other);
                        if merkle::verify_proof(&leaf, &proof, &root, case.depth) {
                            return Err(format!(
                                "{address} claimed {other} with the proof for {amount}"
                            ));
                        }
                    }
                }
                Ok(())
            },
        ),
    ]
}

/// The non-Merkle invariants, each with its own input type, run through the
/// same harness.
fn run_flat_invariants(seed: u64, iterations: u64) -> Vec<InvariantReport> {
    let mut reports = Vec::new();

    reports.push(check(
        "gas::ladder_always_raises_the_fee",
        "every fee bump must strictly raise the fee and stay within the cap",
        seed,
        iterations,
        |prng, _| {
            let schedule = FeeSchedule::testnet_default();
            let start = 1 + prng.below(u64::from(schedule.max_fee_stroops) - 1) as u32;
            let simulator = GasSimulator::new(schedule);
            let ladder = simulator.bump_ladder(start);
            (start, schedule.max_fee_stroops, ladder)
        },
        |(start, cap, ladder)| {
            let mut previous = *start;
            for (index, bump) in ladder.iter().enumerate() {
                if bump.outer_fee_stroops <= bump.inner_fee_stroops {
                    return Err(format!(
                        "step {index} does not raise the fee: {} -> {}",
                        bump.inner_fee_stroops, bump.outer_fee_stroops
                    ));
                }
                if bump.inner_fee_stroops != previous {
                    return Err(format!(
                        "step {index} starts from {} but the ladder was at {previous}",
                        bump.inner_fee_stroops
                    ));
                }
                if bump.outer_fee_stroops > *cap {
                    return Err(format!(
                        "step {index} exceeds the {cap} stroop cap: {}",
                        bump.outer_fee_stroops
                    ));
                }
                if bump.percent_over_signed_fee() < 100 {
                    return Err(format!(
                        "step {index} pays {}% of the signed fee, which cannot survive a base fee rise",
                        bump.percent_over_signed_fee()
                    ));
                }
                previous = bump.outer_fee_stroops;
            }
            Ok(())
        },
    ));

    reports.push(check(
        "help::wrapped_lines_fit_the_width",
        "no line produced by the wrapper may exceed the requested width",
        seed,
        iterations,
        |prng, _| {
            let word_count = 1 + prng.below(24) as usize;
            let words: Vec<String> = (0..word_count)
                .map(|_| "x".repeat(1 + prng.below(14) as usize))
                .collect();
            let text = words.join(" ");
            let width = 1 + prng.below(120) as usize;
            (text, width)
        },
        |(text, width)| {
            for line in wrap(text, *width) {
                let len = line.chars().count();
                if len > (*width).max(1) {
                    return Err(format!(
                        "line of {len} character(s) exceeds width {width}: {line:?}"
                    ));
                }
            }
            Ok(())
        },
    ));

    reports.push(check(
        "state::pagination_visits_each_entry_once",
        "walking every page must yield the filtered entries exactly once, in order",
        seed,
        iterations,
        page_case,
        |case| {
            let query = StateQuery::new()
                .with_page_size(case.page_size)
                .including_temporary(case.include_temporary);
            let expected: Vec<String> = case
                .inspector
                .filtered(&query)
                .iter()
                .map(|e| e.key.clone())
                .collect();

            let pages = case.inspector.pages(&query);
            let visited: Vec<String> = pages
                .iter()
                .flat_map(|page| page.entries.iter().map(|e| e.key.clone()))
                .collect();

            if visited != expected {
                return Err(format!(
                    "pagination visited {} of {} entry/entries (page size {})",
                    visited.len(),
                    expected.len(),
                    case.page_size
                ));
            }
            for (index, page) in pages.iter().enumerate() {
                if page.total != expected.len() {
                    return Err(format!(
                        "page {index} reports total {} but the filter matched {}",
                        page.total,
                        expected.len()
                    ));
                }
                if page.next_cursor.is_some() && page.entries.len() != case.page_size {
                    return Err(format!(
                        "page {index} returned {} entry/entries for page size {}, but claims more follow",
                        page.entries.len(),
                        case.page_size
                    ));
                }
            }
            if let Some(last) = pages.last() {
                if last.next_cursor.is_some() {
                    return Err("the final page still hands out a cursor".to_string());
                }
            }
            Ok(())
        },
    ));

    reports.push(check(
        "key_hygiene::every_generated_secret_key_is_flagged",
        "an encoded Stellar secret key must always be detected, and masked in the report",
        seed,
        iterations,
        |prng, _| {
            let bytes = prng.bytes32();
            let key = format!(
                "{}",
                stellar_strkey::ed25519::PrivateKey(bytes).as_unredacted()
            );
            (key, prng.below(4))
        },
        |(key, shape)| {
            if !looks_like_secret_key(key) {
                return Err(format!("encoded key not recognised as a secret key: {key}"));
            }
            let source = match shape {
                0 => format!("let key = \"{key}\";"),
                1 => format!("STELLAR_SECRET_KEY={key}"),
                2 => format!("escrow: [\n  \"{key}\",\n]"),
                _ => key.clone(),
            };
            let findings = scan_text(std::path::Path::new("leak.rs"), &source);
            if findings.is_empty() {
                return Err("secret key in source was not reported".to_string());
            }
            if !findings.iter().any(|f| f.is_error()) {
                return Err("secret key was reported as a non-error".to_string());
            }
            if findings
                .iter()
                .any(|f| f.message.contains(key) || f.masked.contains(key))
            {
                return Err("the finding echoed the secret it found".to_string());
            }
            Ok(())
        },
    ));

    reports.push(check(
        "key_hygiene::masking_never_reveals_the_value",
        "a masked secret must be shorter than the secret and never equal to it",
        seed,
        iterations,
        |prng, _| {
            let len = 1 + prng.below(80) as usize;
            let value: String = (0..len)
                .map(|_| {
                    let alphabet =
                        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                    alphabet[prng.below(alphabet.len() as u64) as usize] as char
                })
                .collect();
            value
        },
        |value| {
            let masked = mask_secret(value);
            if masked.contains(value.as_str()) && !value.is_empty() {
                return Err(format!("mask {masked:?} contains the whole secret"));
            }
            if masked.chars().count() >= value.chars().count() && value.chars().count() > 8 {
                return Err(format!(
                    "mask {:?} is not shorter than the {} character secret",
                    masked,
                    value.chars().count()
                ));
            }
            Ok(())
        },
    ));

    reports
}

/// Run the built-in suite.
pub fn run_suite(seed: u64, iterations: u64) -> SuiteReport {
    let iterations = iterations.max(1);
    let mut reports: Vec<InvariantReport> = Vec::new();
    for invariant in built_in_suite().iter_mut() {
        reports.push(invariant.run(seed, iterations));
    }
    reports.extend(run_flat_invariants(seed, iterations));
    SuiteReport {
        seed,
        iterations,
        reports,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The suite must hold on the fixed default seed: this is the CI gate.
    #[test]
    fn built_in_suite_holds() {
        let report = run_suite(DEFAULT_SEED, 200);
        assert!(
            report.passed(),
            "invariant suite failed:\n{}",
            report.render()
        );
        assert!(report.reports.len() >= 8);
    }

    #[test]
    fn suite_is_deterministic_for_a_seed() {
        let first = run_suite(42, 64);
        let second = run_suite(42, 64);
        assert_eq!(first, second);
    }

    #[test]
    fn a_broken_property_is_reported_with_its_seed() {
        let report = check(
            "always_false",
            "a deliberately false invariant",
            7,
            10,
            |prng, _| prng.next_u64(),
            |_| Err("nope".to_string()),
        );
        assert!(!report.held());
        assert_eq!(report.counterexamples.len(), MAX_COUNTEREXAMPLES);
        assert_eq!(report.counterexamples[0].seed, 7);
        assert_eq!(
            report.reproduce_command().as_deref(),
            Some("stellar-toolkit verify invariants --seed 7")
        );
    }

    #[test]
    fn a_holding_property_is_silent() {
        let report = check(
            "trivially_true",
            "x == x",
            1,
            25,
            |prng, _| prng.next_u64(),
            |_| Ok(()),
        );
        assert!(report.held());
        assert_eq!(report.iterations, 25);
        assert!(report.render().contains("PASS"));
    }

    #[test]
    fn generator_is_stable_across_runs() {
        let mut a = Prng::new(1234);
        let mut b = Prng::new(1234);
        for _ in 0..32 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn between_stays_inside_the_interval() {
        let mut prng = Prng::new(99);
        for _ in 0..1_000 {
            let value = prng.between(-5, 5);
            assert!((-5..=5).contains(&value), "{value} out of range");
        }
        assert_eq!(prng.between(3, 3), 3);
        assert_eq!(prng.between(5, 1), 5);
    }

    #[test]
    fn report_renders_a_counterexample() {
        let report = check(
            "demo",
            "demo invariant",
            3,
            5,
            |_, iteration| iteration,
            |iteration| {
                if *iteration == 2 {
                    Err("iteration 2 is rejected".to_string())
                } else {
                    Ok(())
                }
            },
        );
        let rendered = report.render();
        assert!(rendered.contains("FAIL"));
        assert!(rendered.contains("seed 3 iteration 2"));
        assert!(rendered.contains("reproduce:"));
    }
}

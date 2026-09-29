# Property-Based Testing for the Contracts

Implements issue [#152](https://github.com/Kevin737866/stellar-web3-toolkit/issues/152)
in `crates/contract-proptests`.

## Test strategy

The contracts have three layers, and each needs a different kind of test:

| Layer | Example | Best tool |
| --- | --- | --- |
| Pure math | `amm_pool::math::sqrt_u128`, `amount_out`, `quorum_status` | Property tests over the whole input domain. |
| Contract accounting | reserves, LP supply, reward indices, solvency | Randomized operation sequences that assert invariants after every step. |
| Specific behaviours | "remove more than you deposited fails" | Hand-written unit tests inside each contract (already present). |

Property tests do not replace the unit tests in each contract; they cover the
input space those tests sample. A hand-written test proves "this scenario works";
a property test looks for the scenario nobody thought of.

The invariants this suite asserts are the ones that would lose user funds:

- `sqrt_u128(n)` returns `floor(sqrt(n))` for every `u128`, including the
  boundary where a naive implementation overflows.
- A swap output is non-negative, strictly below the output reserve, monotonic in
  the input, and never better than the fee-free quote; `x * y` never decreases.
- `quote` and the first-deposit liquidity are monotonic and bounded.
- A quorum threshold is met exactly when confirmations reach `m`, and distinct
  confirmations are counted once, in any order, ignoring out-of-range entries.
- A flash swap with nothing repaid fails the `k` check, and one repaid at the
  0.3% rate passes.
- After **every** operation in a random sequence: the pool's recorded reserves
  equal the tokens it actually holds, both reserves stay positive, the LP
  position stays positive, and `k` never falls.

## The harness

`crates/contract-proptests/src/lib.rs` is a dependency-free harness rather than
a wrapper around an existing framework. The workspace keeps a deliberately small
dependency surface and the contracts are `#![no_std]`; a heavyweight framework
would add a large crate graph for machinery — async strategies, runtime
configuration — that these tests do not use.

| Piece | Purpose |
| --- | --- |
| `Rng` | Deterministic SplitMix64 with inclusive range helpers (`i128_in`, `u64_in`, `u32_in`, `index`, `bool`, `chance`). Deterministic so a counterexample replays from the seed alone. |
| `Config` | Iteration count and seed, read from `PROPERTY_CASES` / `PROPERTY_SEED`. |
| `Candidate` | A `shrink` method implemented for the numeric types, `bool`, tuples and `Vec`. |
| `check` / `check_default` | Runners that shrink the first failure to a local minimum and panic with it. |
| `expect` | Small helper for a boolean assertion with a reason. |

A failing property reports the seed, the case index, the reason, the minimal
counterexample, the originally generated input, and the exact command to replay
it:

```text
property `a swap output stays strictly below the output reserve` failed on case 41
of 1024 (seed 20260929): an output must leave the reserve non-empty
  minimal counterexample: (1, 1, 1)
  generated input:       (813, 977, 1)
  replay with PROPERTY_SEED=20260929 PROPERTY_CASES=42
```

Because shrinking walks toward smaller inputs, `(1, 1, 1)` points straight at the
boundary case, which is where the bug almost always is.

## Running

```bash
# The suite with the default 256 cases per property.
cargo test -p contract-proptests

# A longer sweep.
PROPERTY_CASES=100000 cargo test -p contract-proptests --release

# Replay a single reported failure exactly.
PROPERTY_SEED=20260929 PROPERTY_CASES=42 cargo test -p contract-proptests -- --nocapture
```

Every property test resolves its `Config` from the environment, so the same
binary runs a quick local check and an extended CI sweep with no code change.

## CI integration

The `proptest` job in `.github/workflows/ci.yml` runs the suite twice, with two
different seeds (1024 cases on a pinned seed, 512 on a second seed). A property
that only holds for one random stream is not a property, so the second seed is
the cheap check that the generators are not accidentally degenerate.

`contract-proptests` is a `std` harness, not a deployable contract, so it is
excluded from the `wasm32v1-none` builds in `.github/workflows/ci.yml` alongside
the other host crates.

## Adding a property

Add a function to `crates/contract-proptests/tests/math_properties.rs` (pure
math) or a new file in that directory (contract behaviour):

```rust
#[test]
fn my_invariant_always_holds() {
    check_default(
        "a human-readable statement of the invariant",
        |rng: &mut Rng| {
            let reserve = rng.i128_in(1, 1_000_000);
            let amount = rng.i128_in(1, reserve);
            (amount, reserve)
        },
        |(amount, reserve)| expect(amount <= reserve, "the pair must satisfy its own precondition"),
    );
}
```

Keep the generator's output type shrinkable — plain numbers, tuples, and `Vec`
already are. If a new type is needed, implement `Candidate` for it and prefer
shrinking toward the simplest failing case.

## Coverage

Line coverage for the workspace is provided separately by the coverage tooling
added in [#154](https://github.com/Kevin737866/stellar-web3-toolkit/issues/154)
(`scripts/coverage.sh` and `docs/COVERAGE.md`). The two are complementary: this
suite finds the inputs that break an invariant, coverage reports which lines no
test reached at all.

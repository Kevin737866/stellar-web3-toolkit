# Informal Verification

Issue #116. This document describes the property harness in
`crates/stellar-toolkit/src/invariants.rs` and the invariants it enforces.

## What it is, and what it is not

The contract and tooling test suites in this workspace are **example-based**:
they assert the cases someone thought of. The harness adds the other half — it
samples randomised inputs looking for a counterexample to a *stated property*.
When it finds one it stops, reports the input, and prints the seed that
reproduces it.

It is **informal**: passing means no counterexample was found in the sampled
space, not that the property holds for every input. It finds bugs; it does not
prove their absence. For the security-relevant properties, pair it with the
example-based tests that pin the rejection paths (the `#[should_panic]` cases).

Two deliberate constraints:

* **Reproducible.** The generator is a seeded splitmix64 PRNG, so a failure found
  in CI is reproducible locally with `--seed`. A random seed would make a
  nightly failure impossible to investigate.
* **Dependency-free.** No `proptest`/`quickcheck`. This workspace pins a
  toolchain and lockfile for byte-reproducible WASM builds; the harness has to
  stay cheap enough to run on every push and must not perturb the build graph.

---

## Usage

```bash
# Run the built-in suite on the fixed default seed (what CI runs).
cargo run -p stellar-toolkit -- verify invariants

# A specific seed and a wider search, for working on one code path.
cargo run -p stellar-toolkit -- verify invariants --seed 12345 --iterations 5000

# Machine-readable report (seed, iterations, counterexamples).
cargo run -p stellar-toolkit -- verify invariants --json
```

Exit code is non-zero when any invariant is violated. Every failure prints the
seed, the iteration, the offending input, and a `reproduce:` command.

```
informal verification (seed 6840143425043995324, 64 iteration(s) per invariant)
  PASS  merkle::proof_rejects_foreign_address  64 iteration(s)
  FAIL  gas::ladder_always_raises_the_fee       1 counterexample(s) in 27 iteration(s)
        invariant: every fee bump must strictly raise the fee and stay within the cap
        seed 6840143425043995324 iteration 26: step 1 does not raise the fee: 500 -> 500
          input: (500, 10000000, [FeeBump { .. }])
        reproduce: stellar-toolkit verify invariants --seed 6840143425043995324
```

---

## The invariants

| Name | Property |
|------|----------|
| `merkle::proof_verifies_for_every_leaf` | A proof generated for an allocation in the tree verifies against the root at the published depth — honest claimants can always claim. |
| `merkle::proof_rejects_foreign_address` | `proof_for` returns nothing for an address outside the tree, and a forged proof of the right length does not verify — nobody can mint an allocation. |
| `merkle::leaf_authenticates_the_amount` | A proof for one amount does not verify for any other amount, so the claimant cannot choose what they are owed. |
| `gas::ladder_always_raises_the_fee` | Every bump in the escalation ladder strictly raises the fee, starts from the previous step, stays within `max_fee_stroops`, and never pays less than the fee that was signed — a retry loop can neither stall nor drain the account. |
| `help::wrapped_lines_fit_the_width` | No line produced by `wrap` exceeds the requested width, including tokens longer than the width — safety text cannot scroll out of view. |
| `state::pagination_visits_each_entry_once` | Walking every page yields exactly the filtered entries, in order, once each; intermediate pages are full and the final page hands out no cursor — an audit cannot silently miss state. |
| `key_hygiene::every_generated_secret_key_is_flagged` | Any encoded Stellar secret key is detected by `security secrets`, reported as an error, and never echoed in the finding. |
| `key_hygiene::masking_never_reveals_the_value` | A masked secret is strictly shorter than the secret and never contains it, so the scanner cannot leak a key into a CI transcript. |

Each generator produces a *fresh* input per iteration: Merkle trees of 1–12
leaves with a known outsider, fee ladders from random start fees, random state
exports with random page sizes, random texts and widths, random key material.

---

## Adding an invariant

An invariant is a name, a claim in one sentence, a generator and a predicate:

```rust
use crate::invariants::{check, Prng};

let report = check(
    "amm::swap_never_drains_a_reserve",
    "amount_out must be strictly less than reserve_out",
    seed,
    iterations,
    |prng, _| {
        let reserve_in = 1 + prng.below(1_000_000) as i128;
        let reserve_out = 1 + prng.below(1_000_000) as i128;
        let amount_in = 1 + prng.below(reserve_in as u64) as i128;
        (reserve_in, reserve_out, amount_in)
    },
    |(reserve_in, reserve_out, amount_in)| {
        let out = amm_pool::math::amount_out(*amount_in, *reserve_in, *reserve_out);
        if out >= *reserve_out {
            return Err(format!("quote {out} drains a reserve of {reserve_out}"));
        }
        Ok(())
    },
);
assert!(report.held(), "{}", report.render());
```

Rules of thumb:

1. **State the failure, not the happy path.** The description should read as the
   thing that must never happen.
2. **Fail with a reason.** `Err(String)` is shown verbatim next to the input;
   "assertion failed" wastes the counterexample.
3. **Generate the edges on purpose.** Include `0`, `1`, `u128::MAX`, empty
   collections and duplicate keys in the generator's range — that is where the
   bugs are.
4. **Keep the input small and printable.** The counterexample is truncated at
   240 characters; a giant struct hides the field that matters.
5. **Put it where the code lives.** Invariants over contract math belong in the
   contract crate, where they can drive the real `no_std` code; the built-in
   suite here covers the host-side toolkit because that is what this crate owns.

## Relationship to the other checks

| Check | Question it answers |
|-------|--------------------|
| `cargo test` | Do the cases we thought of pass? |
| `verify invariants` | Does a sampled search find a case we did not think of? |
| `scripts/reproducible-build.sh` | Is the artifact the one we reviewed? |
| `security secrets` | Is key material out of the tree? |
| `env validate` | Does each environment agree with its own contract? |

## See also

- [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) — the attack surface these invariants defend
- [`docs/INFRA_RUNBOOK.md`](INFRA_RUNBOOK.md) — where the checks run in CI

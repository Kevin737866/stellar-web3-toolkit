# Coverage Reporting

Implements issue [#154](https://github.com/Kevin737866/stellar-web3-toolkit/issues/154)
via `scripts/coverage.sh` and `.github/workflows/coverage.yml`.

## What it produces

| Output | Path | Useful for |
| --- | --- | --- |
| LCOV | `target/coverage/lcov.info` | editors (VS Code "Coverage Gutters", Neovim), badge services, `genhtml` |
| HTML | `target/coverage/html/index.html` | browsing the uncovered lines per file |
| Summary | `target/coverage/summary.txt` | the per-file percentage table, also posted to the CI job summary |

## Running it

```bash
# Prerequisites, once:
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked

# Generate every report.
./scripts/coverage.sh

# Faster: a single package, no HTML.
./scripts/coverage.sh -p amm-pool --lcov --output-path /tmp/amm.info

# Open the HTML report when done.
cargo llvm-cov --workspace --all-features --html --open
```

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `COVERAGE_DIR` | `target/coverage` | Output directory. |
| `COVERAGE_MIN_LINES` | `0` | Fail below this line-coverage percentage. `0` disables the gate. |
| `COVERAGE_IGNORE` | see below | `--ignore-filename-regex` filter. |

Any extra arguments are forwarded to `cargo llvm-cov`, so `./scripts/coverage.sh -p token-locker`
or `./scripts/coverage.sh --release` work as expected.

## Why LLVM source-based coverage

The alternatives were considered and rejected:

- **`cargo-tarpaulin` (ptrace sampling)** mis-attributes the suite here. The
  contracts are `#![no_std]` and most tests run inside the Soroban test host, so
  the sampler sees time in the host rather than in the contract source and
  reports implausible per-file numbers.
- **Instrumenting only the contracts** would hide the host tooling
  (`stellar-toolkit`, the routers, the simulators) that this repository also
  ships and tests.

`cargo-llvm-cov` instruments the actual source and is the approach the Rust
project itself recommends.

## The default filter

```text
(^|/)(tests|benches)/|crates/contract-proptests/|/target/|/rustc/
```

Test-only directories and the property-test harness are not shipped product code.
Counting them would let the headline percentage drift while contract coverage
stayed flat. Override with `COVERAGE_IGNORE` when you specifically want them.

Two things still inflate the number and are worth knowing when reading it:

- `#[cfg(test)]` modules inside a contract's `src/lib.rs` are counted as product
  lines. Splitting them into `tests/` would remove the inflation, and the filter
  above would then exclude them automatically.
- Generated glue the macro emits (client methods, contract spec accessors) is
  attributed to the `#[contractimpl]` block and is not hand-written.

Treat the number as a trend line, not a target.

## CI

`.github/workflows/coverage.yml` runs on pushes to `main`/`develop`/feature
branches and on pull requests to `main`/`develop`. It installs
`cargo-llvm-cov --locked` (so a tool release cannot silently change the numbers
mid-review), runs `scripts/coverage.sh`, posts the summary table to the run's job
summary, and uploads the LCOV and HTML reports as artifacts.

The `coverage` job is deliberately separate from `ci.yml`: coverage needs an
instrumented rebuild of everything plus the `llvm-tools-preview` component, and
folding it into the main pipeline would slow every unrelated push.

## Ratcheting the gate

`COVERAGE_MIN_LINES` starts at `0`, which reports without failing. To turn it
into a gate:

1. Run the suite, or open the latest `Coverage` run and read the `TOTAL` line of
   the job summary.
2. Round the line percentage *down* to a round number and set
   `COVERAGE_MIN_LINES` in `.github/workflows/coverage.yml` to that value, so a
   small amount of churn does not fail unrelated PRs.
3. Raise it as coverage improves. Never lower it without explaining why in the
   PR — a falling gate is the signal the tooling exists to produce.

You can also apply a gate locally without touching CI:

```bash
COVERAGE_MIN_LINES=70 ./scripts/coverage.sh
```

## Relationship to the property tests

These are complementary, not duplicates:

- The property suite added in [#152](https://github.com/Kevin737866/stellar-web3-toolkit/issues/152)
  (`docs/PROPERTY_TESTING.md`) searches the input space for the case that breaks
  an invariant.
- Coverage reports which lines no test reached at all — including lines a
  property test never needs to execute because the generator does not produce the
  input that reaches them.

A suspiciously high coverage number with a weak property suite is possible; so is
thorough properties with a low number because whole modules are unreached. Read
them together.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `error: no such command: llvm-cov` | `cargo install cargo-llvm-cov --locked` has not been run, or `~/.cargo/bin` is not on `PATH`. |
| `error: could not find llvm-profdata` | `rustup component add llvm-tools-preview` is missing for the active toolchain. |
| The run recompiles everything | Expected: coverage needs instrumented artifacts, so it cannot reuse the normal `target/` cache. `cargo clean` is not required between runs, only between toolchain changes. |
| A package shows `0.00%` | It has no tests, or its tests live only in another package's `tests/` (which the filter excludes from *its* numbers). Check `cargo test -p <package>`. |

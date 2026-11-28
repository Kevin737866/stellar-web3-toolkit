# Bounded Fuzz Runs and Seed Diagnostics

Implements issue [#382](https://github.com/Kevin737866/stellar-web3-toolkit/issues/382)
in `crates/channel-simulator/src/fuzz.rs`.

A topology fuzz run had exactly one bound: `iterations`. That is enough on a
laptop and not enough in CI, where a pathological topology generator loop or a
slower machine turns a nominal 64-iteration run into an open-ended one. And
when a run did report an invariant violation, the failure named its
per-iteration seed but not the seed of the run, so reproducing "the run that
failed" meant re-deriving how the iteration seed was derived.

## What changed

| Piece | Behavior |
| --- | --- |
| `TopologyFuzzConfig::max_duration_ms` | Optional wall-clock budget for the whole run. `None` (the default) keeps the previous `iterations`-only behavior. |
| `MAX_FUZZ_DURATION_MS` | Hard ceiling on a configured budget (24 hours). |
| `FuzzTermination` | `Completed` or `DurationBudgetExceeded`; tells a caller whether the run finished its configured work. |
| `FuzzReport::termination`, `elapsed_ms`, `max_duration_ms`, `seed` | Every report now says why it stopped, how long it took, and which seed produced it. |
| `FuzzReport::was_truncated()` | Convenience predicate for the budget case. |
| `FuzzFailure::run_seed`, `FuzzFailure::replay_hint()` | Each failure names both its own seed and the run seed, plus a copy-pasteable replay line. |
| `FuzzReport::summarize()` | First line always carries `seed=0x…`, the topology and iteration counts, elapsed time and the failure count; truncated runs add a note about the exhausted budget. |
| `validate_run_limits()` (public) | Shared validation used by `try_new` and `try_run`. |

## Bounded execution

The budget is checked *between* iterations, not inside one. A run therefore
always stops on an iteration boundary, which keeps the report meaningful: the
topologies counted in `iterations` are complete, and the truncation is a
property of the run rather than of an interleaved topology. `elapsed_ms` is the
measured duration of the whole run, so the caller can tell "finished just in
time" from "stopped early".

Suggested CI configuration:

```rust
let fuzzer = TopologyFuzzer::try_new(TopologyFuzzConfig {
    iterations: 256,
    seed: 0x00C0_FFEE,
    max_duration_ms: Some(30_000),
    ..TopologyFuzzConfig::default()
})?;

let report = fuzzer.try_run()?;
assert!(report.is_clean(), "{}", report.summarize());
```

## Invalid input is rejected, not substituted

`max_duration_ms: Some(0)` and any value above `MAX_FUZZ_DURATION_MS` return
`SimulatorError::InvalidConfig` from `try_new` / `try_run`. A zero budget would
otherwise mean "run nothing", which looks like a clean run; clamping an
oversized one would silently change the caller's intent. `TopologyFuzzer::new`
still does no validation, matching the existing constructor behavior — use
`try_new` when the configuration is not a compile-time constant.

## Failure diagnostics

A failure prints, and reports, everything needed to replay it:

```text
topology fuzz: seed=0x0000000000c0ffee 4 topologies in 3ms, ... 4 failures
  [random iteration=0 seed=0x0000000000c0ffee] config: disconnect_probability must be finite and in [0.0, 1.0], got 2
```

`FuzzFailure::replay_hint()` returns the same tuple in one line:

```text
replay with seed=0x0000000000c0ffee iteration=0 (run seed=0x0000000000c0ffee, topology=random, invariant=config)
```

Passing `failure.iteration` to `TopologyFuzzer::run_iteration` reproduces that
single iteration deterministically; the tests assert exactly that.

## Compatibility

- The only new required field is `FuzzReport`'s, which callers construct through
  `Default`.
- `TopologyFuzzConfig` gained one `#[serde(default)]` field, so existing JSON
  configurations still deserialize.
- `FuzzFailure` gained `run_seed`. It is a plain struct, not part of a serialized
  wire format, so nothing downstream breaks.
- With `max_duration_ms: None` the RNG sequence, iteration order and results are
  unchanged from before this change.

# Deterministic Event Ordering for Concurrent Simulation Inputs

Implements issue [#385](https://github.com/Kevin737866/stellar-web3-toolkit/issues/385)
in `crates/channel-simulator/src/events.rs`.

## The problem

`run_stress_test` was a placeholder: it ignored its `concurrent` argument and
called `run_simulation`. Making it actually concurrent would have introduced a
reproducibility bug that no seed could fix — if several producers submit
payments, the order they arrive in is decided by thread scheduling. The same seed
would then produce the same *set* of payments in a different order, and routing,
fee totals, path lengths and every derived statistic would differ between runs.

A simulation whose input order is a property of the operating system is not a
simulation, it is a sampling of one.

## The order

`SimulationEvent` carries `timestamp`, `sequence`, `source`, `destination` and
`amount`. Events sort by:

| Priority | Field | Why |
| --- | --- | --- |
| 1 | `timestamp` | Logical time is the only real causal ordering. |
| 2 | `source` | Lexicographic; breaks ties without consulting arrival. |
| 3 | `destination` | Lexicographic. |
| 4 | `amount` | Numeric. |
| 5 | `sequence` | The producer's submission counter, last. |

`sequence` is deliberately last. It is the one field that reflects *when* a
producer submitted something, so ordering by it earlier would reintroduce the
dependency on producer timing that this module exists to remove. Two events that
agree on every field including `sequence` are indistinguishable, so their
relative order cannot affect the result.

## Interface

```rust
pub struct SimulationEvent {
    pub timestamp: u64,
    pub sequence: u64,
    pub source: String,
    pub destination: String,
    pub amount: i128,
}

impl SimulationEvent {
    pub fn new(timestamp, sequence, source, destination, amount) -> Result<Self, SimulatorError>;
    pub fn validate(&self) -> Result<(), SimulatorError>;
    pub fn order_key(&self) -> (u64, &str, &str, i128, u64);
}

pub fn order_events<I: IntoIterator<Item = SimulationEvent>>(events: I) -> Vec<SimulationEvent>;
```

On the simulator:

| Method | Behavior |
| --- | --- |
| `run_simulation()` | Generates payments, then executes them in canonical order. |
| `run_events(Vec<SimulationEvent>)` | Validates the events, sorts them canonically, executes. The only way to feed explicit inputs to a simulation. |
| `run_stress_test(concurrent)` | Splits `num_payments` across `concurrent` threads, each producing a batch from a seed derived from the simulator's seed, then merges, sorts and executes. |
| `seed()` | The seed the RNG was actually created with, including a drawn one. |

Batch seeds are derived as `seed + batch * 0x9E3779B97F4A7C15`, so the
per-producer input streams are fixed by the simulator's seed alone and do not
depend on which thread starts first.

## Guarantees

- **Permutation invariance.** For any permutation `p` of the same events,
  `run_events(p) == run_events(events)`, including every statistic.
- **Producer-count determinism.** `run_stress_test(n)` twice returns identical
  statistics. A different `n` is a different simulation (different batches), but
  is itself deterministic.
- **Ordered generation.** `run_simulation` also executes in canonical order, so
  the generator's insertion order can never leak into results.
- **Replayable.** `Simulator::seed()` reports the resolved seed, so a run that
  drew a random seed can be reproduced by passing it back in the configuration.

## Scope: routing ties are a separate question

Canonical ordering guarantees that the same inputs execute in the same order,
and the tests assert full `SimulationStats` equality across input permutations on
one simulator. It cannot make the router itself deterministic: when two routes
have exactly equal cost, `channel_router`'s priority queue breaks the tie by its
internal hash order, so two *separate* simulator instances can pick different
equal-cost paths and report different fee totals for the same seed. Settlement
counts and routed value are unaffected, which is what the cross-instance test
asserts. Fixing the tie-break belongs in `channel-router` and is out of scope
for this issue.

## Invalid input

`run_events` rejects, before executing anything:

| Input | Error |
| --- | --- |
| Empty event list | `InvalidEvent("no simulation events were supplied")` |
| Unknown source or destination | `InvalidEvent("event N has unknown source '…'")` |
| Payment to itself | `InvalidEvent("event N pays X to itself")` |
| Non-positive amount | `InvalidEvent("event N has a non-positive amount (…")` |
| Network not initialized | `SimulationError("cannot run simulation on an empty network…")` |
| `run_stress_test(0)` | `InvalidConfig("concurrent must be at least 1")` |

`run_events` validates the whole batch before the first payment is routed, so a
bad event at index 90 does not leave 89 payments executed and statistics
half-updated.

## Compatibility

- `run_simulation` keeps its signature and result type; the only difference is
  that payments execute in canonical rather than generation order.
- `run_stress_test` keeps its signature; it now uses the `concurrent` argument
  instead of ignoring it.
- `SimulatorError` gained `InvalidEvent(String)`.
- `Simulator` gained a private `seed` field and a `seed()` accessor; construction
  is unchanged.

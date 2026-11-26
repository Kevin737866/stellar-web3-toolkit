# Channel Liquidity Depletion in Network Simulations

Implements issue [#384](https://github.com/Kevin737866/stellar-web3-toolkit/issues/384)
in `crates/channel-simulator/src/liquidity.rs`.

## The problem

The simulator routed every payment against the balances the network was
generated with. Channel capacity was checked, but never spent: one channel could
settle an unlimited number of payments, and the reported success rate was a
property of the topology and the fee schedule only. A network that could carry
ten payments and one that could carry a million produced the same report.

Real channels are finite and directional. A payment from A to B lowers the A→B
side and raises the B→A side. Once a side is empty, no further payment can use it
in that direction, whatever the topology says.

## The model

`SimulatorConfig::liquidity_model` selects the behavior:

| Value | Effect |
| --- | --- |
| `LiquidityModel::Static` (default) | Balances are generated once and never change. Previous behavior, unchanged. |
| `LiquidityModel::Depleting` | Every routed payment moves value across each channel it uses. |

With `Depleting`, a payment that the router found against current balances is
applied to the graph before it is counted as successful. If applying fails — a
hop no longer has the capacity, which can happen when a route was computed
against state another update changed — the payment counts as failed and the
error is logged. It is not silently recorded as settled.

```rust
let config = SimulatorConfig {
    liquidity_model: LiquidityModel::Depleting,
    ..SimulatorConfig::default()
};
let simulator = Simulator::new(config);
simulator.initialize_network()?;
let stats = simulator.run_simulation().await?;

println!("{} settlements, {} channels with a dry side",
         stats.successful_payments, stats.depleted_channels);
```

## Interface

| Item | Purpose |
| --- | --- |
| `LiquidityModel` | `Static` / `Depleting`; `Default` is `Static`, `name()` is stable for logs. |
| `apply_route_liquidity(&mut NetworkGraph, &Route) -> Result<LiquidityUpdate, SimulatorError>` | Atomically applies a routed payment to the channels it uses. |
| `LiquidityUpdate { hops_applied, channels_emptied, value_moved }` | What one payment did. |
| `available_liquidity(graph, channel_id, from) -> Option<i128>` | Capacity on a channel in the direction leaving `from`. |
| `depleted_channels(graph) -> usize` | Channels with no capacity left in at least one direction. |
| `SimulationStats::depleted_channels` | The same count, reported at the end of a simulation. |
| `Simulator::depleted_channels()` | The live count for the current network. |

## Invariants

- **Conservation.** For every channel, `capacity_a_to_b + capacity_b_to_a` is
  identical before and after any number of payments. Value moves across a
  channel; it is not created or destroyed.
- **No negative capacity.** A hop that needs more than the sending side holds is
  rejected; capacities never go below zero.
- **Atomicity.** `apply_route_liquidity` validates the whole route against a
  scratch copy of the affected balances first. A rejection at hop 3 leaves hops
  1 and 2 unapplied, so a failed payment cannot leave the network half-updated.
- **Reproducibility.** Two simulations with the same seed produce the same
  balances, the same settlement count and the same dry-channel count.

## Errors

| Error | Cause |
| --- | --- |
| `SimulatorError::InsufficientLiquidity { channel_id, needed, available }` | The hop needs more than the sending side holds. Names the channel and both numbers. |
| `SimulatorError::InvalidRouteHop { hop, from, to }` | The hop's channel is missing or does not connect `from` to `to`. |
| `SimulatorError::InvalidConfig` | A hop forwards a non-positive amount. |
| `SimulatorError::SimulationError` | The route has no hops. |

## Depletion can help or hurt

Moving balances is not monotonically bad for throughput. It strands liquidity on
long chains of same-direction payments, and it *rebalances* channels that a later
payment needs in the reverse direction. A test in the crate asserts only that the
model changes what settles, rather than assuming a direction; the interesting
result of a simulation is which effect dominates for the topology under test.

## Determinism fix that this work needed

Reproducible depletion exposed two pre-existing sources of run-to-run drift, both
now fixed in `crates/channel-simulator/src/lib.rs`:

1. `initialize_network` drew channel endpoints from `HashMap::keys()`, whose
   iteration order is randomised per map, so the same seed produced a different
   topology in every process. Node IDs are now sorted before the edge loop.
2. `run_simulation` only sorted node IDs when disconnection modeling was
   enabled, so payment endpoints came from `HashMap` order in every other run.
   The sort is now unconditional.

Both are one-line changes; without them, "the same seed produces the same
simulation" — which every other guarantee here depends on — was false.

## Compatibility

- `SimulatorConfig::liquidity_model` is `#[serde(default)]` and defaults to
  `Static`, so existing configurations and results are unchanged.
- `SimulationStats::depleted_channels` is `#[serde(default)]`.
- `SimulatorError` gained two variants; existing matches that use a wildcard arm
  or the variants they care about are unaffected.
- `SimulatedPayment` and the public simulation API are unchanged.

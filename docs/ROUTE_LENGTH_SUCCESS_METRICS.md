# Payment Success-Rate Metrics by Route Length

Implements issue [#383](https://github.com/Kevin737866/stellar-web3-toolkit/issues/383)
in `crates/channel-simulator/src/metrics.rs`.

`SimulationStats` reported one aggregate `success_rate`. That number cannot
distinguish two networks with the same average and completely different
behavior: one that fails every payment uniformly, and one that routes every
direct payment but nothing longer than three hops. The second is the common
failure mode of a payment-channel network — liquidity concentrates on short
routes — and the aggregate hides it.

`SimulationStats::success_by_route_length` now reports the same simulation
broken down by hop count.

## Interface

```rust
pub struct RouteLengthBucket {
    pub route_length: usize,   // hops; 1 == a direct channel
    pub attempted: usize,
    pub successful: usize,
    pub failed: usize,
    pub value_routed: i128,
}

pub struct PaymentSuccessMetrics {
    pub by_route_length: BTreeMap<usize, RouteLengthBucket>,
    pub unroutable: usize,
}
```

| Method | Returns |
| --- | --- |
| `RouteLengthBucket::success_rate()` | Success percentage for that length, `0.0` for an empty bucket. |
| `PaymentSuccessMetrics::record(len, success, amount)` | Records one outcome; rejects `Some(0)`, a zero route length, and non-positive amounts. |
| `bucket(len)` / `success_rate_for(len)` | The bucket, or its rate, if that length was attempted. |
| `route_lengths()` | Attempted lengths in ascending order. |
| `min_route_length()` / `max_route_length()` | Shortest and longest attempted route. |
| `total_attempted()` / `total_successful()` | Sums across buckets plus `unroutable`. |
| `overall_success_rate()` | Success percentage including unroutable attempts. |
| `best_route_length()` | The length with the highest success rate, ties broken toward the shorter route. |
| `hop_distance(graph, source, destination)` | Shortest hop distance ignoring capacity and fees; `None` if unreachable. |

## How a payment is assigned a length

| Outcome | Bucket |
| --- | --- |
| Routed | Hops in the route the router returned. |
| Failed, but a path exists | Shortest hop distance between source and destination in the topology. |
| Failed, no path at all | `unroutable`, outside every bucket. |

Failures are bucketed by topological distance rather than dropped, because
dropping them inflates the success rate of exactly the long routes under
investigation: a payment that fails because no four-hop route has capacity is a
failure *of four-hop routing*. The denominator of a bucket is therefore
"payments that needed about this many hops", not "payments that had a route".

## Determinism and invariants

`by_route_length` is a `BTreeMap`, so iteration, comparison and serialized form
are ordered by length and identical across runs with the same seed. The
integration test asserts the decomposition is exact:

```
sum(bucket.attempted) + unroutable == total_payments
sum(bucket.successful)              == successful_payments
sum(bucket.value_routed)            == total_value_routed
bucket.attempted                    == bucket.successful + bucket.failed
```

`value_routed` uses saturating addition, so an adversarial amount cannot wrap
the metric negative.

## Invalid input

`record` returns an error and leaves the metric untouched for:

- `Some(0)` — no route has zero hops (`SimulatorError::InvalidRouteLength`).
- an amount of `0` or less (`SimulatorError::InvalidConfig`).

Silently folding these into a bucket would make the shortest bucket describe
payments it does not, and would let a bogus amount contaminate `value_routed`.

## Compatibility

- `SimulationStats::success_by_route_length` is `#[serde(default)]`, so
  previously serialized statistics deserialize with an empty breakdown.
- No existing field changed meaning or type; `success_rate` keeps its previous
  definition.
- `SimulatorError` gained `InvalidRouteLength(usize)`. Existing matches use a
  wildcard arm or the variants they care about, so this is additive.

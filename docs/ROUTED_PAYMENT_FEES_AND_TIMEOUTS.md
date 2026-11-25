# Routed Payment Fee and Timeout Calculation Examples

**Issue:** [#367](https://github.com/Kevin737866/stellar-web3-toolkit/issues/367) — *Document fee and timeout calculation examples for routed payments*

`crates/channel-router` now has an executable version of the fee and CLTV
calculation that used to live only in prose: [`PaymentPlanner`](../crates/channel-router/src/quote.rs).
The examples below use the public `plan_route` entry point, so a change to the
formulas breaks the tests instead of silently invalidating the documentation.

## Interface

```rust
use channel_router::{plan_route, QuoteOptions, RouteRequest};

let options = QuoteOptions::new(current_ledger, final_expiry)
    .with_deadline(1_200)          // optional
    .with_min_cltv_delta(1);       // optional
let plan = plan_route(&graph, &request, options)?;

let sender_pays = plan.quote.sender_amount;
let destination_receives = plan.quote.delivered_amount;
let upstream_expiry = plan.quote.hops[0].expiry_height;
```

`plan_route` returns a `PaymentPlan` containing the selected `Route` and the
`RouteQuote` used to select it. The quote's `hops` are in source-to-destination
order and carry both the amount forwarded on that channel and the HTLC expiry
height. The function takes `&NetworkGraph` and never mutates it; a failed plan
returns an error and produces no partial route.

### Configuration

| Field | Meaning | Required |
| --- | --- | --- |
| `current_ledger` | Ledger at which the quote is produced | Yes |
| `final_expiry` | Ledger at which the destination is expected to claim | Yes |
| `fee_cap` | Per-channel and per-route fee ceiling | Defaults to `FeeCap::protocol()` |
| `deadline` | Latest acceptable upstream HTLC expiry | Optional; falls back to `RouteRequest::payment_metadata.payment_expiry` |
| `min_cltv_delta` | Smallest acceptable channel CLTV delta | Defaults to `1`; `0` is rejected |

There is deliberately no implicit ledger height. A quote produced without a
ledger context cannot claim that its time locks are safe, so
`QuoteOptions::new` requires both ledger values and `PaymentPlanner::new`
rejects a final expiry that has already passed.

## Fee formula

For a channel forwarding `A` units:

```text
fee = base_fee + floor(A * fee_rate_ppm / 1_000_000) + floor(cltv_delta * 10 / 1_440)
```

The time-lock term is the same ~1 stroop per day used by
`calculate_channel_fee`. Integer division is part of the contract: a 40-block
delta contributes `floor(40 * 10 / 1_440) = 0`, while 144_000 blocks
contribute `1_000`.

The planner computes fees **backwards from the destination** so that
`RouteRequest::amount` is exactly what the destination receives. Starting with
`amount_at_destination = amount`, for each hop from last to first:

```text
fee_i              = fee(channel_i, amount_at_i)
required_capacity_i = amount_at_i + fee_i
amount_at_{i-1}     = required_capacity_i
```

`required_capacity_i` is also checked against the channel's capacity in the
direction of travel. The source pays `amount + sum(fee_i)`.

## Worked example

Alice (`N0`) pays Carol (`N2`) 1,000,000 stroops over two channels:

| Channel | Direction | `base_fee` | `fee_rate` | `cltv_delta` | Capacity |
| --- | --- | ---: | ---: | ---: | ---: |
| `ch1` | N0 → N1 | 10 | 500 ppm | 40 | 2,000,000 |
| `ch2` | N1 → N2 | 5 | 1,000 ppm | 30 | 2,000,000 |

### Fees

1. Final hop `ch2` forwards 1,000,000:
   `fee = 5 + floor(1,000,000 * 1,000 / 1,000,000) + 0 = 1,005`.
   N1 must therefore provide `1,001,005`.
2. First hop `ch1` forwards 1,001,005:
   `fee = 10 + floor(1,001,005 * 500 / 1,000,000) + 0 = 510`.
   Alice pays `1,001,515` in total.

| Quantity | Value |
| --- | ---: |
| Destination receives | 1,000,000 |
| `ch2` fee | 1,005 |
| `ch1` fee | 510 |
| Total fee | 1,515 |
| Source pays | 1,001,515 |

Both channels have enough capacity in the direction of travel: `ch2` needs
1,001,005 and `ch1` needs 1,001,515 against 2,000,000 available. The protocol
cap allows at most `floor(1,000,000 * 20,000 / 1,000,000) + 200,000 = 220,000`
for the route, so 1,515 is well within bounds.

### CLTV expiries

Let the destination claim at ledger 1,000. Expiries are chained upstream by
each channel's delta:

```text
ch2 (N1 -> N2) expiry = 1,000 + 30 = 1,030
ch1 (N0 -> N1) expiry = 1,030 + 40 = 1,070
```

If Carol claims on-chain at ledger 1,000, Bob has 30 ledgers on the downstream
HTLC and Alice's HTLC does not expire until 1,070. With `current_ledger = 900`
the first HTLC offers 170 ledgers of safety, which satisfies a
`required_cltv_delta` of 150 or less. A deadline of 1,200 is also satisfied
because the upstream expiry 1,070 is not later than the deadline.

## Invariants and errors

The planner rejects a candidate rather than substituting a default:

| Invariant | Error |
| --- | --- |
| Positive amount, distinct nodes, sane hop limit and fee budget | `InvalidRequest`, `BelowDustLimit`, `AmountExceedsMaximum` |
| Channel is enabled and has capacity in the direction of travel | `InsufficientCapacity`, `ChannelNotFound` |
| HTLC fits `[min_htlc_size, max_htlc_size]` | `BelowDustLimit`, `HtlcSizeExceeded` |
| Per-hop and total fees stay within `FeeCap` and the fee budget | `HopFeeCapExceeded`, `RouteFeeCapExceeded`, `FeeExceedsBudget` |
| CLTV delta is positive and expiries do not overflow `u32` | `UnsafeCltvDelta`, `ExpiryOverflow` |
| Payment is not already expired and upstream expiry meets deadline / required delta | `PaymentExpired`, `DeadlineExceeded`, `InsufficientCltvDelta` |

If no path survives, the most specific failure encountered is returned; if no
channel was reachable at all, `NoPathFound` is returned instead.

## Deterministic selection

Neighbours are visited in channel-ID order and candidates are compared by
`(total_fee, total_cltv_delta, hop_count, channel_ids)`. Equal quotes therefore
select the same route on every call, independent of hash-map iteration order.
This key is used by `PaymentPlanner` only.

## Compatibility

This is additive:

- `find_best_route`, `find_best_route_with_cap`, and
  [`Pathfinder`](../crates/channel-router/src/pathfinder.rs) are unchanged.
  They continue to estimate each hop's fee from the amount that has arrived at
  that hop, growing from `RouteRequest::amount`.
- `PaymentPlanner` uses exact-delivery (backward) pricing. Its `quote.total_fee`
  can therefore differ from `find_best_route`'s `route.total_fees`; callers
  should not mix the two models in one budget calculation.
- The new `RouteHop.expiry_height` values are written by the planner. Existing
  searches still report `0` for that field, as before.
- No existing struct field, error variant meaning, or public function was
  removed or repurposed; the new error variants are additive.

## Validation

```bash
cargo fmt --all -- --check
cargo test -p channel-router
cargo test -p channel-router --test routed_payment_quote_workflow
```

The integration test recomputes the worked example through the public API and
feeds the resulting route into `FeeCap::check_route`.

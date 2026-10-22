# Conviction Voting Curve (Issue #205)

`stellar_toolkit::conviction` is the vote-weight curve the toolkit exposes to
governance front-ends. It answers one question: *if a holder locks `balance`
tokens for `lock_ledgers`, how much vote weight do they get?*

## The curve

```text
weight = 10_000 * sqrt( balance * min(lock, MAX_LOCK_LEDGERS) / MAX_LOCK_LEDGERS )
```

* `MAX_LOCK_LEDGERS = 6_307_200` — one year of 5-second ledgers.
* `WEIGHT_SCALE = 10_000` — four decimal places of a whole vote unit.
* Everything is `u128` integer arithmetic. There is no floating point anywhere,
  because `f64` cannot represent every `u64` exactly and a vote total that
  differs by one between two machines is a governance bug, not a rounding
  detail.

```rust
use stellar_toolkit::conviction::{conviction_weight, decayed_weight, MAX_LOCK_LEDGERS};

// A full-year lock of 1 000 000 tokens is worth 10 000 000 vote units.
let weight = conviction_weight(1_000_000, MAX_LOCK_LEDGERS);

// Half a year is worth about 70.7% of that.
let half = conviction_weight(1_000_000, MAX_LOCK_LEDGERS / 2);
```

## Properties, and why each is there

| Property | Consequence |
| --- | --- |
| Quadratic in balance (`4x` tokens ≈ `2x` weight) | A whale cannot buy a vote linearly; the marginal price of influence rises with the influence already held |
| Sub-linear in lock time (`4x` lock ≈ `2x` weight) | Conviction is rewarded without letting a one-ledger lock round up to a full vote |
| Capped at `MAX_LOCK_LEDGERS` | No incentive to lock beyond the maximum, and no unbounded integer growth |
| Total over the whole input domain | `conviction_weight(u64::MAX, …)` does not overflow or panic; a panic here would be a denial of service on governance |
| Monotonic in both arguments | More balance or a longer lock can never reduce weight |

## Decay

`decayed_weight(weight, elapsed_ledgers, half_life_ledgers)` halves conviction
every half-life and interpolates **downwards** between halvings:

```rust
let weight = 1_000_000u128;
assert_eq!(decayed_weight(weight, 0, 100), weight);
assert_eq!(decayed_weight(weight, 100, 100), weight / 2);
assert_eq!(decayed_weight(weight, 200, 100), weight / 4);
```

Between halvings the result is the linear interpolation from `base` down to
`base / 2`, rounded down. That is always at or below the true geometric value, so
decay can only under-award — never over-award — a vote.

## What this curve does and does not protect against

* **Reduces whale dominance.** Quadratic weighting makes a single large holder
  pay super-linearly for influence. That is the point.
* **Does not resist balance splitting on its own.** Quadratic curves are
  sybil-sensitive: splitting one balance into `k` accounts yields
  `k * sqrt(balance / k) = sqrt(k * balance)`, which is *more* weight than one
  account. The curve must be paired with an identity or one-account-per-voter
  rule (for example the account-abstraction session keys in
  `crates/stellar-toolkit/src/session_keys.rs`); it is not a substitute for one.
* **Does not decide eligibility.** Quorum, thresholds, proposal lifecycle and
  delegation are out of scope here — this module computes weight only.

## Tests

`cargo test -p stellar-toolkit --lib conviction` covers the exact cap value,
monotonicity in both arguments, the cap on over-long locks, the quadratic ratio,
decay halving/interpolation/monotonicity, integer square root correctness
(including `u128::MAX`), and the `u64::MAX` overflow boundary.

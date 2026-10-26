# Fixed-Point Quadratic Pricing for the AMM

**Issue:** [#207](https://github.com/Kevin737866/stellar-web3-toolkit/issues/207) — *Quadratic math fixed-point*

`contracts/amm-pool/src/math.rs` already provides the pool's constant-product
arithmetic and an overflow-free integer square root. This change adds the other
half of the curve layer: a fixed-point quadratic solver and the pool-pricing
question that actually needs one — *how much input moves the spot price to a
target?*

Both are integer-only. The pool runs on Soroban with `overflow-checks = true`,
so a wrapped coefficient would be a panic inside a contract; every operation here
is checked and returns `None` rather than wrapping.

## The pricing question

The pool charges 0.3% on the input, so an input of `dx` of the input asset pays
out

```text
dy = 997 * dx * R_out / (1000 * R_in + 997 * dx)
```

and leaves the spot price at

```text
p(dx) = (R_out - dy) / (R_in + dx)
      = 1000 * R_in * R_out / ((R_in + dx) * (1000 * R_in + 997 * dx))
```

`p(dx)` is strictly decreasing in `dx`: buying the input asset can only make it
cheaper. Setting `p(dx) = T` and clearing the denominator gives a quadratic in
`dx`:

```text
997*T * dx^2  +  1997*R_in*T * dx  +  (1000*R_in^2*T - 1000*R_in*R_out) = 0
```

With `T` below the current spot price the constant term is negative, so the two
roots have opposite signs and the answer is the positive one.

## API

```rust
use amm_pool::math::{amount_in_for_price, solve_quadratic_scaled, QuadraticSolution, ROOT_SCALE};

// Reserves price the input asset at 4 units of the output; push it to 3.
let dx = amount_in_for_price(1_000_000, 4_000_000, 3, 1).unwrap();
assert!((150_000..160_000).contains(&dx));

// Already at or above the target: no input is needed.
assert_eq!(amount_in_for_price(1_000_000, 4_000_000, 4, 1), Some(0));

// The general solver works on plain integer coefficients and returns roots
// scaled by ROOT_SCALE.
assert_eq!(
    solve_quadratic_scaled(1, -5, 6),
    Some(QuadraticSolution::Two {
        smaller: 2 * ROOT_SCALE,
        larger: 3 * ROOT_SCALE,
    })
);
```

### `amount_in_for_price`

* **Smallest input, not an estimate.** The closed-form root is truncated, so
  the result is checked against the exact price formula and stepped up until the
  target is genuinely met. The returned `dx` is therefore the first integer input
  whose price is at or below the target — `dx - 1` is still above it.
* **Exact comparison.** Prices are compared by cross-multiplying rationals
  (`num * target_den <= target_num * den`), so the boundary decision does not go
  through floating point.
* **`Some(0)` when the target is at or above the spot price.** Nothing has to be
  bought; returning an error would force callers to duplicate the comparison.
* **`None` for non-positive reserves or target components, and for `i128`
  overflow.** A caller always knows whether it received a quote.

### `solve_quadratic_scaled`

`a*x^2 + b*x + c = 0`, with roots in units of `1 / ROOT_SCALE` (`10^-6`).

* `None` when `a == 0` (not quadratic) or when any intermediate product
  overflows.
* Discriminant computed exactly; negative discriminant returns
  `QuadraticSolution::None` (the enum variant, distinct from the `None` return
  that means "could not represent the problem").
* Roots are ordered `smaller <= larger` even for a negative `a`.

## Precision contract

When the discriminant is a perfect square and both divisions are exact, roots are
exact to `1 / ROOT_SCALE`. Otherwise:

```text
|r / ROOT_SCALE - true_root| < 1 / (2 * |a|) + 1 / ROOT_SCALE
```

The first term is the floor on `sqrt(discriminant)` propagated through the `2a`
denominator; the second is truncation to the fixed-point grid. The bound is
documented rather than hidden because a caller that needs a one-sided guarantee
must verify the result against its own predicate — which is exactly what
`amount_in_for_price` does.

For the pricing use case the bound is far below one input unit: `a` is at least
`997 * target_num`, so the error is under `1/1994` of a base unit, and the
verification loop converges in at most a couple of steps. `MAX_PRICING_STEPS`
bounds the loop at 8 as a backstop and returns `None` instead of looping if that
bound is ever exhausted.

## Why not floating point

`f64` cannot represent every `i128` exactly, and a price comparison that differs
by one unit between two machines is a consensus difference, not a rounding
detail. The AMM is deterministic by construction; this module keeps it that way.

## Tests

`cargo test -p amm-pool` covers:

* perfect-square, repeated, negative-leading-coefficient, negative-root,
  irrational-root and no-real-root quadratics, plus linear and overflow
  rejection;
* the documented precision bound on an irrational root (`x^2 - 2x - 1 = 0`);
* price targeting across four pool shapes and four targets: the returned input
  meets the target and one unit less does not;
* `Some(0)` exactly at and above the spot price, including an unreduced target;
* rejection of zero/negative reserves and targets, and coefficient overflow.

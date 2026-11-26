# Route policy failure reporting (Issue #365)

## Behavior

`find_best_route` returns a single `RoutingError` when no route is found. That
error cannot tell a caller whether a path existed but was censored by a policy,
which channel was responsible, or which value broke the rule. The explanatory
API enumerates simple candidate paths and reports **every rejection** with the
candidate's channel ids and the exact rule it failed.

Evaluation is pure: the graph, request and policy are never mutated. A failed
evaluation therefore cannot leave partial state behind.

## Interface

```rust,ignore
use channel_router::{
    evaluate_route_policy, find_best_route_with_policy,
    policy::RoutingPolicy, RouteRequest, RoutePolicyError,
};

let report = evaluate_route_policy(&graph, &request, &policy)?;
if !report.has_route() {
    for failure in &report.failures {
        // e.g. "candidate greedy hop 0: channel greedy fee rate 6000 ppm exceeds cap 5000 ppm"
        println!("{}", failure.message());
    }
}

let route = find_best_route_with_policy(&graph, &request, &policy)?;
# Ok::<(), channel_router::RoutePolicyError>(())
```

| API | Purpose |
| --- | --- |
| `evaluate_route_policy(graph, request, policy)` | `Result<RouteEvaluationReport, RoutePolicyError>` with all candidate outcomes. |
| `find_best_route_with_policy(graph, request, policy)` | `Result<Route, RoutePolicyError>`; on rejection the error carries the full report. |
| `RouteEvaluationReport` | `origin`, `destination`, `amount`, `candidates_evaluated`, `accepted`, `failures`, `has_route()`, `message()`. |
| `CandidateRouteFailure` | `route` (channel/node ids, amount, fees, CLTV), `hop_index`, `reason`, `message()`. |
| `PolicyFailureReason` | Typed reason: excluded channel/node, disabled channel, fee rate/base fee/hop fee caps, insufficient liquidity, HTLC bounds, hop limit, route fee budget, CLTV/expiry violations. |

Existing `find_best_route`, `find_best_route_with_cap` and `find_k_routes`
remain unchanged and keep their `RoutingError` return types.

## Configuration

No new configuration fields. The caller supplies a `RoutingPolicy`, which is
validated explicitly rather than clamped:

- `max_hops` must be in `1..=MAX_ROUTE_HOPS`, `max_fee_bps` in `1..=10_000`,
  `max_fee_rate` positive, `max_base_fee` non-negative, and
  `0 < min_amount <= max_amount`.
- `RouteRequest` must have distinct non-blank endpoints, a positive amount not
  exceeding `MAX_ROUTE_AMOUNT`, a hop limit in range when set, a non-negative
  fee budget, and a non-zero payment expiry when set.
- When `request.max_hops` or `max_fee_budget` is absent, the policy's explicit
  `max_hops` / `max_fee_bps` are used. Nothing is silently defaulted from a
  different source.

`MAX_EVALUATED_CANDIDATES` (256) bounds a dense graph's explanation work;
exceeding it returns `RoutePolicyError::CandidateLimitExceeded`.

## Invariants and errors

- **Liquidity**: each hop's available capacity in the forwarding direction must
  cover the amount plus upstream fees, and the amount must be inside the
  channel's HTLC bounds.
- **Fee bounds**: advertised fee rate/base fee, computed hop fee and total route
  fee are checked against both the protocol `FeeCap` and the policy.
- **Timeout safety**: accumulated CLTV must meet `required_cltv_delta` and must
  not exceed `payment_expiry` when provided.
- **Deterministic selection**: neighbours are visited in channel-id order and
  accepted routes are sorted by `(total_fees, hop_count, channel_ids)`; equal
  cost routes never depend on hash-map iteration.
- **Actionable errors**: invalid requests/policies return `InvalidRequest` /
  `InvalidPolicy`; no simple path returns `NoCandidates`; all-rejected returns
  `Rejected(report)` whose `Display` is the report summary.

## Compatibility

All additions are additive: no existing type, function signature, constant or
feature gate changed. New public items are `policy_report` and the two
functions above. Callers that do not opt in observe identical search behavior.

## Validation

- `cargo fmt --all -- --check`
- `cargo test -p channel-router`
- Integration: `crates/channel-router/tests/policy_failure_report.rs`

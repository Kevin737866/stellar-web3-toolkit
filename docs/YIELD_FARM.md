# Multi-Pool Yield Farm

Implements issue [#151](https://github.com/Kevin737866/stellar-web3-toolkit/issues/151)
in `contracts/yield-farm`.

## Overview

Users deposit a pool's LP token (any [SEP-41] token, including the `amm-pool`
LP token) and earn a share of one reward token stream. Pools carry an
*allocation weight*; the stream splits across pools by weight and within a pool
by stake. Every user position is tracked per pool, and the cross-pool views
render a whole farm portfolio in one call.

[SEP-41]: https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0041.md

## Interface

| Function | Notes |
| --- | --- |
| `initialize(admin, reward_token)` | One-time. `reward_token` is the single asset every pool pays out. |
| `add_pool(pool_id, lp_token, alloc_point)` | Admin. Settles every existing pool first. |
| `set_alloc_point(pool_id, alloc_point)` | Admin. Settles every pool first so an elapsed window is not re-weighted. |
| `set_pool_active(pool_id, active)` | Blocks new deposits; exits and harvests stay open. |
| `set_paused(paused)` | Blocks deposits and funding only. |
| `set_admin(new_admin)` | Current admin authorises the handover. |
| `fund_rewards(funder, amount, duration_seconds) -> i128` | Streams `amount` over `duration_seconds`, rolling any unstreamed remainder into the new rate. Returns the per-second rate. |
| `deposit(user, pool_id, amount) -> i128` | Deposits LP, settling any pending reward first. Returns the new stake. |
| `withdraw(user, pool_id, amount) -> i128` | Returns LP to the wallet. Works while paused or while the pool is inactive. |
| `harvest(user, pool_id, min_out) -> i128` | Pays pending rewards. `min_out` is the slippage guard. |
| `emergency_withdraw(user, pool_id) -> i128` | Returns all LP immediately, forfeiting pending rewards. |

Views: `admin`, `reward_token`, `paused`, `total_alloc_point`, `reward_rate`,
`period_finish`, `last_update`, `reward_index`, `rewards_funded`,
`rewards_credited`, `rewards_paid_out`, `pool_count`, `pool_ids`, `pool_of`,
`position`, `pending_rewards`, `user_pools`, `positions`, and
`total_pending_rewards`.

## Position tracking across pools

| View | Returns |
| --- | --- |
| `position(user, pool_id)` | The single-pool `Position`: stake, accumulator checkpoint, and settled accrual. |
| `positions(user)` | A `PoolPosition` per pool the user has touched: `pool_id`, `lp_token`, `amount`, and live `pending_rewards`. |
| `total_pending_rewards(user)` | The sum of the pending rewards across those pools. |

`positions` is the cross-pool view: one call is enough to render a farm
portfolio, with no off-chain enumeration of pool ids.

## Reward accounting

The farm stores one global **reward index** rather than a per-second rate per
pool:

```text
reward_index += reward_rate * elapsed_seconds          (∫ rate dt)
```

A pool's earnings over a window are

```text
(index_now - index_paid) * alloc_point / total_alloc_point
acc_delta = pool_share * PRECISION / total_staked
pending   = amount * (acc_now - acc_paid) / PRECISION
```

Two consequences worth knowing:

- **Rate changes need no per-pool bookkeeping.** The integral already mixes the
  old rate for the elapsed part and the new rate for the rest, so a pool that has
  not been settled for a while still settles against the right total.
- **Allocation changes settle every pool first.** The denominator is part of a
  pool's share, so re-weighting without settling would retroactively change a
  window that already elapsed. That is an admin operation, never a user action.

All divisions floor, so the sum of positions' entitlements can never exceed what
the index credited, which never exceeds what was funded.

### Accounting invariant

```text
rewards_paid_out <= rewards_credited <= rewards_funded
```

`assert_solvent` enforces the first inequality on every harvest; the lifecycle
test `the_farm_stays_solvent_across_a_full_lifecycle` additionally checks that
the contract's reward-token balance equals `rewards_funded - rewards_paid_out`.

## Economic parameters

| Parameter | Value | Where |
| --- | --- | --- |
| Accumulator scale | `1e12` | `math::PRECISION` |
| Pool split | `alloc_point / total_alloc_point`, floored | `math::pool_share` |
| Reward schedule | funded amount / duration, floored | `math::reward_rate_for` |
| Rounding direction | always floor (dust stays in the contract) | `math::pool_share`, `math::acc_reward_delta`, `math::accrued` |

Behaviour to be aware of before setting weights:

- **An empty pool does not bank its share.** If a pool has no stake, the index
  still moves past it, so a later depositor cannot collect a backlog streamed
  while the pool was empty.
- **A zero-weight pool earns nothing** and can be re-weighted later; it earns
  only from the moment it has weight again.
- **A rate that rounds to zero is rejected.** `fund_rewards` refuses a schedule
  whose `amount / duration` floors to `0`, because the next top-up derives its
  remainder from the stored rate and would otherwise lose the funding.
- **Funding requires a non-zero total allocation**, otherwise the stream would
  go nowhere.

## Safety properties

- LP principal can only leave towards the depositor that supplied it.
- `pause` blocks deposits and funding but never withdrawals or harvests.
- Deactivating a pool blocks new deposits but leaves exits and harvests open.
- `emergency_withdraw` forfeits pending rewards, so exiting a distrusted pool
  cannot drain reward accounting.

## Running the tests

```bash
cargo test -p yield-farm --all-features -- --nocapture
```

The suite covers the cross-pool split, the within-pool split, `min_out`
enforcement, allocation changes not re-weighting elapsed windows, mid-schedule
rate changes, empty and zero-weight pools, schedule expiry, the cross-pool
`positions` view, pause/inactive exits, emergency withdrawal, solvency over a
full lifecycle, and the emitted events. The pure math has its own suite in
`contracts/yield-farm/src/math.rs`.

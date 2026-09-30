# Delegated Staking with Auto-Compounding

Implements issue [#150](https://github.com/Kevin737866/stellar-web3-toolkit/issues/150)
in `contracts/delegated-staking`.

## Overview

Delegators point a [SEP-41] token at an **operator** (a validator, an indexer, a
managed vault) and earn a stream of rewards funded by anyone. The operator takes
a capped commission out of realised rewards; everything else belongs to the
delegator. Because stake and rewards are the same asset, an accrued reward can be
re-staked with pure accounting — that is the auto-compounding path.

A farm that pays a *different* token cannot compound on-chain without a DEX call,
so it is deliberately out of scope.

[SEP-41]: https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0041.md

## Interface

| Function | Notes |
| --- | --- |
| `initialize(admin, token)` | One-time. `token` is both the staked and the rewarded asset. |
| `add_operator(operator, commission_bps)` | Admin. Commission is capped at `MAX_COMMISSION_BPS`. |
| `set_commission(operator, commission_bps)` | Admin. Applies from the next claim/compound. |
| `set_operator_active(operator, active)` | Stops new delegations; exits stay open. |
| `set_paused(paused)` | Blocks `delegate` and `fund_rewards` only. |
| `set_admin(new_admin)` | Current admin authorises the handover. |
| `fund_rewards(funder, amount, duration_seconds) -> i128` | Streams `amount` over `duration_seconds`, rolling any unstreamed remainder into the new rate. Returns the per-second rate. |
| `delegate(delegator, operator, amount) -> i128` | Deposits principal. Auto-compounds first when the flag is on. Returns the new position size. |
| `undelegate(delegator, operator, amount) -> i128` | Returns principal to the delegator's wallet. Works while paused or while the operator is inactive. |
| `claim(delegator, operator, min_out) -> i128` | Pays net rewards to the delegator and commission to the operator. `min_out` is the slippage guard. |
| `compound(delegator, operator, min_amount_out) -> i128` | Re-stakes net rewards; commission is still paid out. |
| `set_auto_compound(delegator, operator, enabled)` | Turns automatic re-staking on/off for one position. |

Views: `admin`, `token`, `paused`, `total_staked`, `reward_rate`, `period_finish`,
`last_update`, `reward_per_token_stored`, `rewards_funded`, `rewards_credited`,
`rewards_paid_out`, `rewards_compounded`, `operator_count`, `operator_list`,
`operator_of`, `is_operator`, `delegator_operators`, `position`, and
`pending_rewards` (the **gross** accrual projected to the current ledger
timestamp; `claim`/`compound` return the net, i.e. gross less the operator's
commission).

## Reward accounting

A single global index `reward_per_token_stored` rises by

```text
rate * distributable_seconds * PRECISION / total_staked
```

on every state-changing call, and each position remembers the index it was last
settled at. A position's entitlement is

```text
amount * (index_now - index_paid) / PRECISION
```

Both divisions floor, so the sum of entitlements can never exceed what the index
credited, and the contract can never pay out more than it received. The dust stays
in the contract.

`PRECISION` is `1e12` (`math::PRECISION`). See the module docs in
`contracts/delegated-staking/src/math.rs` for why the accumulator is not scaled by
`1e18`: `amount * index` has to fit in an `i128`, and the release profile enables
`overflow-checks`, so an over-large scale would panic rather than silently wrap.

### Accounting invariant

```text
rewards_paid_out + rewards_compounded <= rewards_credited <= rewards_funded
```

`assert_solvent` enforces the first inequality on every claim and compound; the
lifecycle test `the_pool_stays_solvent_across_a_full_lifecycle` checks all three.

## Economic parameters

| Parameter | Value | Where |
| --- | --- | --- |
| Accumulator scale | `1e12` | `math::PRECISION` |
| Commission denominator | `10_000` bps | `math::BPS_DENOMINATOR` |
| Maximum commission | `2_000` bps (20%) | `math::MAX_COMMISSION_BPS` |
| Reward schedule | funded amount / duration, floored | `math::reward_rate_for` |
| Rounding direction | always floor (keeps dust in the contract) | `math::reward_index_delta`, `math::accrued_rewards`, `math::split_commission` |

Things worth knowing before setting parameters:

- **A rate that rounds to zero is rejected.** `fund_rewards` refuses a schedule
  whose `amount / duration` floors to `0`, because the next top-up derives its
  remainder from the stored rate and would otherwise lose the funding.
- **Time with no stake is not credited.** If nobody is staked while a schedule is
  running, that window contributes nothing, so a late depositor cannot collect the
  backlog.
- **The commission cap is what makes `min_out` meaningful.** Without it an operator
  could raise commission to 100% between a delegator's quote and the transaction
  landing.
- **The operator is never forced into token exposure.** Compounding re-stakes the
  delegator's share only; commission is always paid out.

## Safety properties

- Principal can only leave towards the delegator that supplied it. There is no
  admin sweep and no operator path to another user's stake.
- An operator is paid only its commission, and only out of realised rewards.
- `pause` blocks new delegations and funding but never blocks `undelegate` or
  `claim`.
- Deactivating an operator blocks new delegations to it but leaves exits and
  claims open, so an operator cannot strand its delegators.
- A position that is fully emptied (no principal, no accrual, no auto-compound
  flag) is deleted, and its entry is removed from the delegator's operator list.

## Running the tests

```bash
cargo test -p delegated-staking --all-features -- --nocapture
```

The suite covers the proportional accrual, commission split and cap, `min_out`
enforcement against a commission raise, compounding and auto-compounding,
pause/inactive exits, schedule roll-over, zero-stake windows, schedule expiry,
solvency over a full lifecycle, and the emitted events. The pure math has its own
suite in `contracts/delegated-staking/src/math.rs`.

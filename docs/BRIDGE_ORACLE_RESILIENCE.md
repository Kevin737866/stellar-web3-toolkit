# Bridge Oracle Quorum Resilience

**Issue:** [#211](https://github.com/Kevin737866/stellar-web3-toolkit/issues/211) — *Bridge oracle quorum*

Quorum has two questions, and a bridge needs both answered:

| Question | Inputs | Where |
| --- | --- | --- |
| *Do this batch of confirmations release this transfer?* | verified confirmations, amounts, ages | issue #210's batch evaluator |
| *With the oracles reachable right now, can the bridge settle at all — and how close is it to stopping?* | configured `n`/`m`, reachable oracle positions | `stellar_toolkit::oracle_resilience` (this document) |

They fail differently. A bridge can be perfectly quorate for the transfer in front
of it and one operator restart away from being unable to settle anything. Batch
evaluation cannot see that; it only ever looks at the confirmations it was given.

## The analysis

Given `n` oracles, a threshold `m`, and the positions of the oracles currently
reachable, `assess_quorum_liveness(n, m, &online)` reports:

| Field | Meaning |
| --- | --- |
| `online` | Distinct, in-range oracles reported reachable |
| `reachable` | `online >= m` — some transfer can reach quorum |
| `missing` | Further reachable oracles needed (`m - online`, `0` when reachable) |
| `online_failure_tolerance` | Reachable oracles that can still fail while quorum remains possible (`online - m`, `0` when unreachable) |
| `total_failure_tolerance` | Oracles anywhere in the set that can be offline while quorum remains possible (`n - m`) |
| `ignored_out_of_range` | Reported positions that are not members of the set |
| `ignored_duplicates` | Repeated positions in the report |

```rust
use stellar_toolkit::oracle_resilience::assess_quorum_liveness;

// 3-of-5, all five reachable: two may fail before settlement stops.
let liveness = assess_quorum_liveness(5, 3, &[0, 1, 2, 3, 4])?;
assert!(liveness.is_reachable());
assert_eq!(liveness.online_failure_tolerance, 2);

// Exactly at quorum: every online oracle is now critical.
let liveness = assess_quorum_liveness(5, 3, &[0, 1, 2])?;
assert!(liveness.every_online_oracle_is_critical());

// Below quorum: blocked, and retries will not help.
let liveness = assess_quorum_liveness(5, 3, &[0, 1])?;
assert!(!liveness.is_reachable());
assert_eq!(liveness.missing, 1);
```

## How to alert on it

| Signal | Meaning | Response |
| --- | --- | --- |
| `!is_reachable()` | Settlement is **blocked**. `missing` says how many keys are needed | Page: recover an oracle or roll the set; relayer retries are futile |
| `every_online_oracle_is_critical()` | Exactly at quorum; the next failure blocks settlement | Warn: restore a redundant oracle before it becomes an incident |
| `online_failure_tolerance == 1` | One failure away from blocking | Watch |
| `ignored_out_of_range > 0` | The monitoring inventory does not match the configured set | Fix the inventory; the reachable count is still truthful |
| `ignored_duplicates > 0` | The feed reports the same oracle twice | Fix the feed; quorum itself is unaffected |

`total_failure_tolerance` is the static design margin (`n - m`). It is useful when
choosing a set, but it is not the number to alert on: a bridge with `n = 5`,
`m = 3` and only three reachable oracles has a comfortable design margin and zero
operational margin.

## Why this is not part of the batch evaluator

The batch evaluator from issue #210 needs signer identities, amounts and a
freshness window; this module needs only a configuration and reachable positions.
Combining them would force a liveness call to invent a transfer and a batch, and
would couple monitoring to the confirmation path's data sources. Keeping the
analysis separate also means it can be run from a status page that has no access
to confirmation contents at all.

## Behaviour on messy input

* **Out-of-range positions are ignored and counted.** A stale inventory left over
  from a set rotation must not be able to report an unreachable bridge as
  reachable, and it must not make the analysis fail either — monitoring has to
  describe the truth it can see.
* **Duplicates collapse.** One oracle listed three times is one reachable oracle,
  because quorum is over distinct keys.
* **Any `n` is accepted.** The oracle-set type caps sets at 64 members; this
  analysis deliberately does not, so a misconfigured 100-oracle bridge can still
  be described rather than refused.
* **Invalid configurations are errors, not silent zeros.** `n = 0`, `m = 0` and
  `m > n` return `LivenessError`; they cannot describe any bridge and must not be
  reported as "blocked" alongside a real liveness failure.

## Tests

`cargo test -p stellar-toolkit oracle_resilience` covers:

* exactly-at-quorum (no tolerance, every online oracle critical);
* one short (blocked, `missing = 1`);
* a full set (design margin reported);
* an empty reachability report;
* out-of-range and duplicate positions, both ignored and counted;
* a 1-of-1 bridge online and offline;
* a 100-oracle set to prove there is no artificial cap;
* a wide set with one duplicate and one stale position ending exactly at quorum;
* invalid `n`/`m` configurations returning `LivenessError`.

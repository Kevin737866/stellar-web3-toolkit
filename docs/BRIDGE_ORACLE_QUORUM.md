# Bridge Oracle Confirmation Quorum

**Issue:** [#210](https://github.com/Kevin737866/stellar-web3-toolkit/issues/210) — *Bridge oracle quorum*

A bridge releases a transfer when an m-of-n oracle set agrees on it. The rule is
simple to state and easy to implement unsafely: the interesting cases are not
"enough confirmations arrived" but the four ways a batch of confirmations can lie.

`stellar_toolkit::bridge_oracle` evaluates a batch into a verdict and reports why
entries were discarded.

## The four hazards

| Hazard | What it looks like | Why counting naively is unsafe |
| --- | --- | --- |
| Duplicate signer | One oracle signs the same transfer three times | Three rows look like three votes; one key reaches quorum alone |
| Unknown signer | A confirmation from an address outside the configured set | Counting it inflates the tally; rejecting the whole batch makes the relayer's view of the set a liveness dependency |
| Stale or future confirmation | A signature from an earlier attempt, or dated after the ledger being evaluated | It can be replayed for a later transfer, or counted before the work it attests to exists |
| Equivocation | Two different amounts each reach the threshold, or one oracle signs two amounts | Releasing either amount is arbitrary; releasing both is a double spend |

The module handles all four. Confirmations from unknown oracles and from outside
the age window are **ignored and counted**, never counted toward quorum and never
a hard error. An oracle that supplies two different amounts has **all** of its
votes discarded: letting either vote stand would let one misbehaving key decide
which amount the bridge releases.

## API

```rust
use stellar_toolkit::bridge_oracle::{
    OracleConfirmation, OracleSet, QuorumVerdict,
};

let set = OracleSet::new(
    vec!["GORACLEA".into(), "GORACLEB".into(), "GORACLEC".into()],
    2, // 2-of-3
)?;

let batch = vec![
    OracleConfirmation {
        oracle: "GORACLEA".into(),
        transfer_id: "transfer-1".into(),
        amount: 500,
        ledger: 100,
    },
    OracleConfirmation {
        oracle: "GORACLEB".into(),
        transfer_id: "transfer-1".into(),
        amount: 500,
        ledger: 98,
    },
];

let report = set.evaluate("transfer-1", &batch, 100, 10);
assert_eq!(
    report.verdict,
    QuorumVerdict::Confirmed { amount: 500, signers: 2 }
);
assert_eq!(report.accepted, 2);
assert!(report.verdict.is_confirmed());
```

### `OracleSet::new(oracles, threshold)`

Construction is validation: the set is non-empty, has at most `MAX_ORACLES` (64)
unique members, and the threshold is in `1..=n`. A zero threshold would make an
empty batch quorate; a threshold above `n` is unsatisfiable. Both fail at
construction instead of at settlement time.

### `OracleSet::evaluate(transfer_id, confirmations, current_ledger, max_age_ledgers)`

Only confirmations for `transfer_id` are considered. A confirmation counts when:

1. its oracle is in the set;
2. its ledger is not in the future and is at most `max_age_ledgers` behind
   `current_ledger` (the window is inclusive, so `age == max_age` counts);
3. it does not contradict that oracle's other confirmation.

Verdicts:

| Verdict | Meaning |
| --- | --- |
| `Confirmed { amount, signers }` | Exactly one amount reached the threshold. `signers` may exceed the threshold. |
| `Pending { best_amount, signers, required, missing }` | No amount reached the threshold. The largest agreeing group and the number of further confirmations needed are reported, so a relayer can distinguish "one short" from "nothing arrived". |
| `Equivocal { first_amount, ..., second_amount, ... }` | Two or more amounts each reached the threshold. **Neither may be released**; the report names the two largest groups. |

`confirmed_amount()` returns the releasable amount only for `Confirmed`, and
`is_confirmed()` is the boolean a caller should gate on.

### `QuorumReport`

| Field | Meaning |
| --- | --- |
| `accepted` | Distinct, in-set, fresh oracles that contributed a vote |
| `ignored_unknown` | Confirmations from addresses outside the set |
| `ignored_stale` | Confirmations from the future or older than the window |
| `ignored_duplicate` | Repeated confirmations from the same oracle for the same amount |
| `ignored_conflicting` | Votes discarded because the same oracle gave two amounts |

The counters are not diagnostics for their own sake: a batch that lost entries to
unknown or stale confirmations looks identical to one that simply received too
few, and an operator has to tell those apart before escalating.

## Scope

The module is pure and host-side. It evaluates a batch the caller already fetched
— from Horizon, an RPC indexer, or the bridge contract's events — and it does not
sign, verify cryptographic signatures, submit a release, or hold state. Signature
verification belongs at the boundary that receives the batch, so that a caller
cannot accidentally treat an unverified row as a vote.

Freshness is a caller policy, not a constant: `max_age_ledgers = 0` means only
confirmations from `current_ledger` itself count, which is appropriate for a
strict relayer and unusable for one that batches.

## Tests

`cargo test -p stellar-toolkit bridge_oracle` covers:

* set validation: empty, duplicate, oversized, threshold outside `1..=n`;
* confirmations at, one below, and above the threshold, with the `missing`
  count;
* one oracle signing repeatedly not reaching quorum;
* unknown oracles ignored and counted;
* stale, window-edge and future-dated confirmations;
* confirmations for another transfer;
* equivocation between two quorate amounts;
* one oracle's contradictory votes both discarded, including a later repeat;
* a larger mixed batch where only distinct fresh members count.

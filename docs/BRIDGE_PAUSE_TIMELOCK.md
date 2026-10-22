# Bridge Pause Timelock

**Issue:** [#239](https://github.com/Kevin737866/stellar-web3-toolkit/issues/239) — *Bridge pause timelock*

**Contract:** `contracts/bridge-pause-guard` (`bridge_pause_guard.wasm`)

A bridge needs to stop outflows *now* when something is draining it, and it needs
that stop to be impossible to use quietly. Those goals pull in opposite
directions: an instant pause is easy to abuse (a compromised guardian freezes
the bridge with no warning), and a slow pause is useless against an attack
already in progress.

`bridge-pause-guard` keeps both by separating the two halves of a pause.

## The state machine

```
                    request_pause(guardian, reason)          activate_pause()
        OPEN  ──────────────────────────────────────▶  PENDING(n)  ──────────────▶  PAUSED
          ▲                 effective = now + pause_delay       │  now >= effective
          │                                                      │
          │   cancel_pending(admin)                              │  request_unpause(admin)
          └──────────────────────────────────────────────────────┘  effective = now + unpause_delay
                                                                         │
        OPEN  ◀────────────────────  activate_unpause()  ◀──  PENDING(u)
                                       now >= effective
```

* `PENDING` is a claim already visible on-chain: the event carries who asked, the
  ledger it lands on, and why. Nothing is blocked yet.
* `PAUSED` is the only state in which value must not move, and reaching it takes
  `pause_delay` ledgers of public notice.

## API

| Function | Caller | Effect |
| --- | --- | --- |
| `initialize(admin, guardians, pause_delay, unpause_delay)` | admin | Write-once install; validates both delays and the guardian set |
| `request_pause(guardian, reason) -> u32` | any guardian | Announce a pause, return its effective ledger. Idempotent: asking again keeps the original ledger |
| `activate_pause() -> bool` | anyone | Land the pause once `now >= effective` |
| `request_unpause(admin) -> u32` | admin | Announce a resume, return its effective ledger. Idempotent |
| `activate_unpause() -> bool` | anyone | Land the resume once `now >= effective` |
| `cancel_pending(admin)` | admin | Drop a pending change before it lands |
| `assert_unpaused()` | the bridge | Aborts while paused — the gate every value-moving path calls |
| `add_guardian(admin, g)` / `remove_guardian(admin, g)` | admin | Manage the pause authority set (the last guardian cannot be removed) |
| `config()`, `is_paused()`, `is_guardian(who)`, `guardians()`, `pending_change()`, `pause_delay()`, `unpause_delay()` | anyone | Read-only queries |

### Events

| Topics | Data |
| --- | --- |
| `(pause, request)` | `(guardian, effective_ledger, reason)` |
| `(pause, activate)` | `(requested_by, effective_ledger)` |
| `(pause, cancel)` | `(requested_by, effective_ledger)` |
| `(unpause, request)` | `(admin, effective_ledger)` |
| `(unpause, activate)` | `(requested_by, effective_ledger)` |
| `(guardian, add)` / `(guardian, remove)` | `guardian` |
| `(init)` | `(pause_delay, unpause_delay)` |

## Guarantees, and why each one is there

| Property | Why it matters |
| --- | --- |
| A pause can never land in the ledger it was requested in (`pause_delay >= MIN_PAUSE_DELAY`, 1) | A silent freeze — one that no user could see coming — is the failure mode the timelock exists to prevent |
| `unpause_delay >= pause_delay` | A bridge that resumes faster than it pauses has a pause that is decoration; resuming must be the *slower*, more observable direction |
| Both delays are within `[MIN_PAUSE_DELAY, MAX_PAUSE_DELAY]` (1 … 17 280 ≈ one day) | Past the ceiling the tool stops being an incident response and becomes a way to hold the bridge hostage |
| Re-requesting a pending pause returns the *original* effective ledger | The countdown belongs to the bridge, not to the first guardian: otherwise one guardian could stall a pause forever, or reset a rival's clock |
| `activate_*` is permissionless | A pause cannot fail to land just because the guardians stopped transacting |
| Only the admin can request or cancel a resume | A compromised guardian key must not be able to lift a pause; the admin is the one party who can also be slow |
| The pause reason is an event, never stored state | A guardian-supplied free-text field in instance storage would let any guardian grow contract state without bound |
| The last guardian cannot be removed | A bridge with no guardian has no one who can raise a pause |
| Quorum is not implemented (any single guardian may request) | Deliberate: a pause that needs quorum is a pause an attacker can outrun. Quorum-style protection is applied to the *resume* instead, via the delay and the admin role |

Since the guardian set is capped at `MAX_GUARDIANS` (10) and duplicates are
rejected at `initialize`, the set stays small enough to name, and a guardian
cannot be counted twice by `remove_guardian`.

### Checking a delay policy before deploying (issue #208)

`initialize` enforces these bounds, so a bad pair is caught on-chain — but only
when the deployment transaction runs. The deployer, the release config and the
runbook all need the same answer *before* that point, which is what
`stellar_toolkit::timelock` provides:

```rust
use stellar_toolkit::timelock::{DelayKind, TimelockPolicy};

let policy = TimelockPolicy::new(pause_delay, unpause_delay)?; // same rules as initialize
let effective = policy.effective_ledger(requested_ledger, DelayKind::Pause);

assert!(!policy.is_effective(requested_ledger, DelayKind::Pause, requested_ledger));
assert!(policy.is_effective(requested_ledger, DelayKind::Pause, effective));
```

Construction is validation: a `TimelockPolicy` value always satisfies
`MIN_PAUSE_DELAY <= pause <= resume <= MAX_PAUSE_DELAY`, so a caller cannot
forget the check. `effective_ledger` saturates instead of wrapping — near the
top of the ledger range a request must become never-actionable, not
immediately-actionable.

The constants are duplicated because the contract is `no_std` and the tooling
crate does not link it. Both sides pin them in tests (`the_constants_match_the_bridge_contract`
and the install-validation tests), so a change on one side fails the other.

`verify invariants` — the CI gate in `automated-checks` — runs two checks over
sampled delay pairs and request ledgers:

| Check | What it proves |
| --- | --- |
| `timelock::pause_never_lands_in_its_request_ledger` | Every accepted policy pauses and resumes strictly after the request ledger, one ledger early is still refused, the effective ledger is actionable, and the resume is never faster than the pause |
| `timelock::resume_is_never_faster_than_pause` | `TimelockPolicy::new` accepts exactly the pairs `initialize` accepts — no missing bound, no extra one |

## Using the gate from a bridge

```rust
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Bridge;

#[contractimpl]
impl Bridge {
    pub fn release(env: Env, to: Address, amount: i128) {
        // First line of every value-moving path. Aborting here is the whole
        // point of the guard: a bridged transfer that cannot be stopped is a
        // transfer that will be drained.
        bridge_pause_guard::BridgePauseGuardClient::new(
            &env,
            &guard_id(&env),
        )
        .assert_unpaused();

        // … move the value
    }
}
```

## Runbook

### Routine: a pause is requested

1. Alert on the `(pause, request)` event. It carries the reason and the ledger
   the pause lands on.
2. Confirm the request is expected (who asked, what the reason says, whether
   on-chain activity agrees). The `pause_delay` window is exactly the time
   intended for this check.
3. If the request is *not* expected and cannot be justified, the admin calls
   `cancel_pending` before the effective ledger. This drops the request without
   pausing anything.
4. If it is justified, do nothing: `activate_pause` is permissionless and lands
   at the effective ledger. Anyone (including monitoring) may call it.

### Incident: the bridge is paused

1. Treat all value movement as halted. Nothing is silently half-applied: the
   pause is checked before the first side effect.
2. Find the cause from the reason on the request event and the on-chain
   evidence, not from chat.
3. Fix the cause, then have the admin call `request_unpause`. The bridge stays
   paused for the whole `unpause_delay` — this window is for verification, and
   it is deliberately the slower direction.
4. `activate_unpause` lands the resume; confirm the gate opens
   (`assert_unpaused` no longer aborts) before resuming traffic.

### Emergency: a pause must go up immediately

Deploy-time configuration only: `pause_delay` is `MIN_PAUSE_DELAY` (1 ledger) if
instant incident response is required. Even then the pause cannot take effect in
the requesting ledger, and it is always announced first. Do not set
`pause_delay` to zero — the contract refuses it.

### Key compromise: a guardian is compromised

1. The attacker can at worst *request* pauses, which are visible and cancellable
   by the admin during the delay.
2. Remove the compromised guardian with `remove_guardian(admin, guardian)`. A
   removed guardian can no longer request; a pending pause they started stays
   cancellable.
3. Rotation is `add_guardian` then `remove_guardian` — the set is never empty in
   between.

### Key compromise: the admin is compromised

The admin can cancel pending pauses and resume the bridge — that is the exposure,
and it is bounded by `unpause_delay`, which fires the same `(unpause, request)`
event an honest resume would. Alert on `(unpause, request)` with the same
priority as a pause request.

## Alerting

| Event | Severity | Why |
| --- | --- | --- |
| `(pause, request)` | warning | Expected during incidents; unexpected requests are the signal |
| `(pause, activate)` | critical | Value movement is now halted |
| `(pause, cancel)` | info | A request was withdrawn — worth reconciling with the requester |
| `(unpause, request)` | warning | Resume announced; the delay is the review window |
| `(unpause, activate)` | critical | Value movement is resuming |
| `(guardian, add)` / `(guardian, remove)` | critical | The pause authority set changed — reconcile with the change process |
| `(init)` | info | Deployment; verify the delays and the guardian set against the intended configuration |

## Tests

`cargo test -p bridge-pause-guard` — 22 tests, covering:

* install validation: write-once, non-empty and non-duplicated guardian set, delay
  bounds, and `unpause_delay >= pause_delay`;
* the timelock: nothing pauses in the requesting ledger, `activate_pause` is
  refused one ledger early and lands at the effective ledger;
* idempotence: a second guardian's request returns the original ledger, and a
  repeat unpause request returns the original ledger;
* the gate: `assert_unpaused` passes on an open bridge, aborts while paused, and
  passes again after a resume;
* authority: non-guardians cannot request, guardians cannot request a resume,
  non-admins cannot cancel or change the guardian set;
* cancellation: a pending pause or resume can be dropped before it lands, and a
  cancelled request cannot be activated afterwards;
* guardian management: add/remove, duplicates refused, capacity cap, and the last
  guardian cannot be removed;
* a full pause → resume → pause cycle, and the request event carrying the reason,
  the actor and the effective ledger.

`cargo clippy -p bridge-pause-guard --all-targets --all-features -- -D warnings`,
`cargo fmt -p bridge-pause-guard -- --check` and
`cargo build -p bridge-pause-guard --target wasm32v1-none --release` are clean, so
the contract is deployable on Soroban.

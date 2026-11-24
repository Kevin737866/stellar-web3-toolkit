# Recovery path for partially funded channels (#357)

## Problem

A payment channel can exist in local or contract state before both funding
transactions have landed on chain. If Alice's funding confirms and Bob's fails,
is dropped, or is never submitted, the channel claims a balance that does not
exist. Paying or settling against that state would settle against funds nobody
holds. Before this change there was no way to record that condition: the state
looked `Open`, and the only exits were cooperative close or unilateral close,
neither of which says what happened to the missing leg.

## Lifecycle

```
                 open_funding_recovery
Open ─────────────────────────────────► AwaitingFunding
 ▲                                          │
 │                                          │ complete_funding_recovery
 │                                          │ (pending side, before deadline)
 │                                          ▼
 └──────────────────────────────────── Open (funds supplied)
                                          │
                                          │ abort_funding_recovery
                                          │ (funded side, after deadline)
                                          ▼
                                     ForceClosed / closed
```

While a recovery is pending, every state-changing operation is refused with
`ChannelAwaitingFunding` (crate) or `ChannelAwaitingFunding` (contract) —
payments, settlement, rebalance, HTLC creation/claim/refund, top-up, and close.
That is what keeps the partially funded state from being spent.

Both resolutions are idempotent: retrying with the same input after success
returns success without a second balance change, event, or snapshot.

## Crate interface (`crates/payment-channel`)

| API | Purpose |
|-----|---------|
| `ChannelManager::open_funding_recovery(channel_id, funded_side, outstanding, ledger_height)` | Record the missing leg; move the channel to `ChannelStatus::AwaitingFunding` |
| `ChannelManager::complete_funding_recovery(channel_id, amount, signature, ledger_height)` | Pending side supplies exactly `outstanding` before the deadline |
| `ChannelManager::abort_funding_recovery(channel_id, signature, ledger_height)` | Funded side closes the channel after the deadline |
| `ChannelManager::get_funding_recovery(channel_id)` | Inspect the recovery record |
| `funding::FundingRecovery`, `FundingSide`, `FundingResolution` | Public record and enums |

`FundingRecovery::digest()` binds the channel ID, funded side, outstanding
amount, and both ledger heights. The completing or aborting participant must
sign that digest; a signature from one recovery cannot be replayed on another.
The deadline is `opened_at + channel.timeout`, treated as a ledger height.

## Contract interface (`contracts/payment-channel-contract`)

| Entry point | Purpose |
|-------------|---------|
| `open_funding_recovery(channel_id, funded_participant, outstanding)` | Funded participant authorises the recovery record |
| `complete_funding_recovery(channel_id, amount)` | Pending participant supplies the outstanding amount |
| `abort_funding_recovery(channel_id)` | Funded participant closes after the deadline |
| `get_funding_recovery(channel_id)` | Read the record |

The recovery record is stored under its own `StorageKey::FundingRecovery`,
separately from `ChannelState`. `initialize`, `update_state`, `top_up`, the HTLC
entry points, and the close entry points are unchanged for callers that never
open a recovery. `timeout` (already validated as at least 60 seconds by
`initialize`) is interpreted as a ledger count for the deadline check so the
boundary is observable without waiting on timestamps.

## Invariants and errors

- **Authorization**: the funded side opens and aborts; the pending side
  completes. Each must `require_auth` (contract) or sign the recovery digest
  (crate). Wrong participants get `UnauthorizedParticipant` /
  `FundingUnauthorized`.
- **Boundaries**: completion is rejected after the deadline
  (`FundingRecoveryExpired`); abort is rejected before it
  (`FundingDeadlineNotReached`). In the crate, a stale ledger height is also
  rejected with `ReorgDetected`.
- **Amounts**: only the exact outstanding amount is accepted
  (`FundingAmountMismatch`); non-positive amounts are rejected at open.
- **No partial writes**: all validation happens before any state is stored. In
  the crate a failed snapshot restores the previous state; in the contract the
  channel and recovery records are written together.
- **Reorg safety**: a reorg that removes the height where the recovery opened
  cancels the recovery in the crate's local manager.

## Operational example

1. Detect the failed leg (funding transaction missing from the ledger).
2. Call `open_funding_recovery` naming the side whose funds did confirm.
3. Either ask the pending side to fund and call `complete_funding_recovery`, or
   wait out the deadline and call `abort_funding_recovery`.
4. On abort, return the locked asset using the funding transaction's own refund
   path; the state change records that resolution. It does not move assets by
   itself.

## Compatibility

New enum variants are added (`ChannelStatus::AwaitingFunding`, the crate error
variants, contract error codes 31–37). Existing channel states and stored
channel records deserialize unchanged because no existing struct fields were
removed or retyped. No new configuration file or environment variable is
introduced; the deadline derives from the channel's existing `timeout` and the
crate's existing `history_depth`.

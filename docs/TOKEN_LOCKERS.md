# Token Lockers and Delegates

Implements issue [#257](https://github.com/Kevin737866/stellar-web3-toolkit/issues/257)
(retry of #70) in `contracts/token-locker`.

## Overview

A custody layer over
[SEP-41](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0041.md)
tokens. Holders deposit tokens with the contract, which escrows them, and can
then either

- keep them spendable as `balance_of`,
- **vest** them for a recipient with `lock`, which releases them once the unlock
  ledger is reached, or
- hand a capped, expiring **spending limit** to a delegate with `set_delegate`,
  letting that delegate pay funds out of the holder's custodied balance.

The locker is a custodian, not a token: it deliberately does not implement the
SEP-41 token interface, because the value it holds is always an underlying
SEP-41 token.

## Custody model

Deposited tokens stay in the contract, so moving custodied value never needs a
SEP-41 allowance. Releasing a vest credits the recipient's **spendable balance**
rather than transferring tokens, so a recipient can immediately withdraw,
re-lock, or delegate the released value. Every outbound transfer is authorised
by the address receiving it.

## Interface

### Holder

| Function | Notes |
| --- | --- |
| `deposit(holder, token, amount)` | Escrows `amount` and makes it spendable. |
| `withdraw(holder, token, amount)` | Returns spendable balance to the holder. Callable while frozen. |
| `lock(funder, token, recipient, amount, unlock_ledger) -> u32` | Commits spendable balance to `recipient`. Irrevocable. |
| `release(id)` | Credits a matured vest to the recipient. Callable by anyone once mature. |

### Delegates

| Function | Notes |
| --- | --- |
| `set_delegate(holder, delegate, token, amount, expires_ledger)` | Grants a limit. Re-authorising replaces it; `amount` of `0` revokes. `expires_ledger` of `0` never expires. |
| `revoke_delegate(holder, token, delegate)` | Withdraws the limit. |
| `move_from(holder, token, delegate, to, amount)` | The delegate spends `amount` of the holder's **spendable** balance, drawing down the limit. |

### Admin and views

`initialize(admin, name, symbol)`, `set_frozen(bool)`, `admin`, `name`,
`symbol`, `frozen`, `next_lock_id`, `balance_of`, `locked_of`, `total_of`,
`total_locked`, `lock_of`, `lock_ids`, `is_matured`, `delegate_of`,
`is_delegate`.

## Usage

```rust
let client = TokenLockerClient::new(&env, &id);
client.initialize(&admin, &name, &symbol);

// Custody.
client.deposit(&holder, &token, &3_000);
client.withdraw(&holder, &token, &1_000);

// Vest 500 to a recipient from ledger 100.
let id = client.lock(&holder, &token, &recipient, &500, &100);
assert!(client.try_release(&id).is_err());          // not mature yet
env.ledger().set_sequence_number(100);
client.release(&id);                                 // anyone may trigger this
assert_eq!(client.balance_of(&recipient, &token), 500);

// Delegated spending, capped and expiring.
client.set_delegate(&holder, &delegate, &token, &800, &500);
client.move_from(&holder, &token, &delegate, &payee, &300);
assert_eq!(client.balance_of(&payee, &token), 300);
```

## Design decisions

**A vest cannot be cancelled by the funder.** A lock that the funder could
revoke would not be a commitment, so the value is irrevocably earmarked for the
recipient. The recipient *can* take it early, because it is already theirs.

**Releases are permissionless.** Anyone may call `release` once a vest matures.
That keeps maturation from depending on the recipient transacting, and it does
not widen access to the funds, which still land in the recipient's balance.

**Delegates can only reach the spendable balance.** Vested funds stay committed
until `release` credits them, so a delegate can never pull money out from under
a vest.

**A spent limit is removed rather than left at zero**, so `delegate_of` returns
`None` once a limit is exhausted and expired limits stop applying on their own.

## Security notes

- **The admin has no path to user funds.** Escrowed tokens can only leave the
  contract towards a depositor or a vest recipient, and both of those require
  the recipient's own signature. The admin can freeze, nothing more.
- **A freeze cannot trap funds.** `set_frozen` blocks deposits, new vests,
  delegate limits and delegate spending, but `withdraw` stays open. Vest
  releases do pause, so a freeze holds new payouts while existing holders retain
  an exit.
- Every state-changing entry point authorises the party it acts for:
  `holder.require_auth()` for deposits, withdrawals and limit changes,
  `delegate.require_auth()` for delegated moves.
- `move_from` rejects `to == holder`, so a delegate cannot burn a limit for no
  effect.
- Vest ids increment monotonically from `1` and a released vest cannot be
  released twice.

## Storage

- **Instance**: `Config`, `NextLockId`, `TotalLocked(token)`.
- **Persistent**: `Account(holder, token)`, `Lock(id)`, `LockIds(funder, token)`,
  `Delegate(holder, token, delegate)`, each with a TTL bump on read and write
  following `docs/SOROBAN_STORAGE_BEST_PRACTICES.md`. An `Account` entry is
  removed entirely once its balance reaches zero.

## Tests

`cargo test -p token-locker` — 22 tests covering the deposit/withdraw round
trip, vest commitment and immaturity, permissionless release, released value
being withdrawable, multiple vests tracked per token and funder, delegates
inside and beyond their limits, expiry and never-expiring limits, re-authorising
and revoking, delegates being unable to reach vested funds, freeze semantics,
the admin having no path to funds, and event emission.

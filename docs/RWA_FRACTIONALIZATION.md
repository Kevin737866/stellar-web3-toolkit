# RWA Fractionalization

Implements issue [#255](https://github.com/Kevin737866/stellar-web3-toolkit/issues/255)
(retry of #68) in `contracts/rwa-fractionalizer`.

## Overview

An issuer escrows a whole off-chain-backed asset — property, a treasury bill, a
private allocation — and receives a SEP-41 **share token** in return. Shares
transfer and burn freely as a fungible token. Once every share has returned to
one address, that holder can redeem and take the underlying asset back.

This is the shape described by
[SEP-56 (Tokenized Vault Standard)](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0056.md):
a SEP-41 share token over an escrowed underlying, where withdrawal burns the
shares.

## Interface

### Admin

| Function | Notes |
| --- | --- |
| `initialize(admin, underlying)` | One-time. `underlying` must be a SEP-41 token. |
| `set_admin(new_admin)` | Current admin authorises the handover. |
| `freeze()` / `unfreeze()` / `frozen()` | Halts share transfers and new fractionalizations. Redemptions stay open so holders always keep an exit. |

### Lifecycle

| Function | Notes |
| --- | --- |
| `fractionalize(issuer, total_shares, decimals, uri)` | Escrows the issuer's whole underlying balance and mints `total_shares` shares to them. One-time. |
| `redeem(holder, recipient) -> i128` | Requires `holder` to own the **entire** outstanding share supply. Burns all of it and releases the underlying to `recipient`. |

### Share token ([SEP-41](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0041.md))

`name`, `symbol`, `decimals`, `balance`, `allowance`, `approve`, `transfer`,
`transfer_from`, `burn`, `burn_from` — the full standard interface, so the share
token is a first-class token in any SEP-41 wallet or AMM.

### Views

`admin`, `underlying`, `underlying_amount`, `total_shares`,
`outstanding_shares`, `fractionalized`, `uri`, `frozen`, `shares_of`.

## Usage

```rust
let client = RwaFractionalizerClient::new(&env, &id);
client.initialize(&admin, &underlying_token);

// Issuer holds 1,000 units of the underlying and fractionalizes them.
client.fractionalize(&issuer, &10_000, &2, &String::from_str(&env, "ipfs://rwa/1"));

// Shares behave as an ordinary fungible token.
client.transfer(&issuer, &alice, &5_000);
client.transfer_from(&alice, &bob, &alice, &carol, &1_000);

// Redemption needs the whole supply back in one hand.
assert!(client.try_redeem(&alice, &alice).is_err());
client.transfer(&carol, &alice, &4_000);
client.redeem(&alice, &alice);            // underlying returns to Alice
```

## Redemption and burns

Two rules are enforced strictly, because getting either wrong would let someone
extract value the contract does not hold:

- **Redemption requires the whole outstanding supply.** A partial redemption
  would need a pro-rata asset split and would be impossible to do honestly
  while shares are still being burned elsewhere.
- **Burning shrinks the claim without returning the asset.** A holder who burns
  shares reduces `outstanding_shares`; those burned shares are not compensated.
  Holders burned out of the supply are therefore not compensated, so redemption
  is only possible once the remaining shares have been consolidated.

Both invariants are covered by tests, including the case where shares were
divided, partially burned, and then re-consolidated.

## Storage

- **Instance**: `Config` (admin, underlying, underlying amount, total and
  outstanding shares, decimals, uri, frozen flag).
- **Persistent**: `Shares(address)` with a TTL bump on read and write,
  following `docs/SOROBAN_STORAGE_BEST_PRACTICES.md`.

## Security notes

- The underlying is pulled from the issuer in the same call that mints shares,
  so no share can exist without its backing.
- `fractionalize` runs once; there is no path to mint shares for an
  already-fractionalized asset.
- Freezing blocks transfers and new fractionalizations but never redemption, so
  a compliance freeze cannot trap holders.
- Shares obey SEP-41 allowances, so a spender's limit is consumed on
  `transfer_from` and `burn_from`.

## Tests

`cargo test -p rwa-fractionalizer` — 17 tests covering escrowing, the
one-shot guard, share transfers, allowance gating, full-supply redemption,
redemption to a third party, rejection of partial redemption, burn semantics,
and event emission.

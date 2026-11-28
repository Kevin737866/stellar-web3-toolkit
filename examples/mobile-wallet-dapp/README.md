# Mobile Wallet Dapp Example

**Issue:** [#128](https://github.com/Kevin737866/stellar-web3-toolkit/issues/128) — *Add mobile wallet dapp example*

A phone-sized dapp that talks to this toolkit's contracts: connect a wallet, send a
payment, read and write contract state, hand a payment to a wallet app with a
SEP-7 deep link, and recover an account from a BIP-39 phrase.

It is deliberately dependency-light and framework-free — plain ES modules, one
`index.html` — so the whole path from a signature request to a confirmed ledger
entry is readable in a few files.

## What it demonstrates

| Flow | Where |
| --- | --- |
| Connect a wallet (extension, or injected provider in tests) | `src/wallet.mjs` → `createWallet` |
| Build, sign, submit and confirm a payment | `src/wallet.mjs` → `sendPayment` |
| Read contract state (simulate, decode, never sign) | `src/wallet.mjs` → `readContract` |
| Write contract state (`prepareTransaction` → wallet → submit → confirm) | `src/wallet.mjs` → `invokeContract` |
| Refuse a Soroban call whose authorization entries came back unsigned | `src/wallet.mjs` → `assertAuthEntriesSigned` |
| Hand a payment to a wallet app on a phone (SEP-7) | `src/deeplink.mjs` |
| Recover an account from a recovery phrase, and fund it on testnet | `src/recovery.mjs` |
| BIP-39 + SLIP-0010 derivation matching the Rust toolkit wallet | `src/mnemonic.mjs` |

## Prerequisites

- Node.js 20 or newer (`node --version`)
- A browser wallet extension (Freighter) for the desktop flow — on a phone there
  is no extension, and the deep link is what replaces it
- A deployed contract to point at (see below); the example ships with none,
  because a hard-coded contract id would silently point at someone else's

## Run it

```bash
cd examples/mobile-wallet-dapp
npm install

# Dev server, reachable from a phone on the same network
npm run dev            # http://localhost:5173, and http://<your-lan-ip>:5173

# Static bundle for a deployment
npm run build && npm run preview
```

Point it at a network and a contract without editing code:

```
http://localhost:5173/?network=testnet&contract=C…
```

`?network=` accepts `testnet` or `mainnet` and an unknown name is refused rather
than defaulted, because silently talking to the wrong chain is how a testnet dapp
ends up spending real value. `?contract=` sets the contract the "Contract"
section talks to; without it the built-in default is empty and the app says so
instead of building an invalid transaction.

To deploy a contract to point at:

```bash
# from the repository root
cargo build --workspace --exclude stellar-toolkit --exclude stellar-did \
  --exclude payment-channel --exclude channel-router --exclude channel-simulator \
  --exclude watchtower --exclude atomic-swap --exclude contract-proptests \
  --target wasm32v1-none --release
stellar contract deploy --wasm target/wasm32v1-none/release/token_locker.wasm \
  --source <your-testnet-key> --network testnet
```

## The flows

### 1. Connect and pay

`connect()` asks the wallet for access and validates that what comes back is a
Stellar account (`G…`). `sendPayment()` then builds a payment, has the wallet sign
it, submits it and polls until it is in a ledger. Signing is always a call into
the wallet — this code never holds a secret for that path.

Amounts are validated before they reach a transaction: at most 7 decimal places,
strictly positive, and no scientific notation. Every amount stays a string, since
rounding stroops through a float is how a 0.0000001 difference becomes a failed
transaction.

### 2. Read and write contract state

- **Read** — `readContract()` builds the invocation, simulates it and decodes the
  return value. Nothing is signed and nothing is submitted.
- **Write** — `invokeContract()` builds the call, asks the RPC to
  `prepareTransaction` (which fills in the footprint and the authorization entries
  the host demands), has the wallet sign it, submits it and confirms it.

After signing, `assertAuthEntriesSigned()` re-reads the envelope and refuses it
if any address-credential authorization entry is still empty. That check exists
because the failure it prevents is otherwise invisible: the transaction is
accepted by the network, fails in the ledger, and the reason is an XDR detail
rather than a sentence. If it fires, the wallet in use does not sign Soroban
authorization entries, and the message says so.

Arguments are converted explicitly: numbers and `bigint`s are `i128` (what every
amount in this workspace is), a `G…` account or `C…` contract is an `address`,
other strings are text, and anything else has to say what it is —
`{ type: 'u32', value: 1234 }`.

### 3. Phone handoff (SEP-7)

A mobile browser has no extension wallet, so "Build deep link" produces a
`web+stellar:pay?…` URI and "Open in wallet app" hands it to the operating system.
The wallet signs and submits; the dapp never sees a key.

SEP-7 caps the URI at 300 characters and some wallets silently drop anything
longer, so an over-long link is returned with a warning instead of being sent as
if it were fine.

### 4. Recovery

1. **Validate** the phrase — and say which problem it has: wrong number of words,
   a word that is not in the BIP-39 list, or a failed checksum. Those need
   different fixes.
2. **Derive** the account with BIP-39 + SLIP-0010 at `m/44'/148'/index'`, the same
   derivation the toolkit's Rust wallet uses.
3. **Look up** the account. A failure that is *not* "account not found" is
   reported as a failure — a phrase is never treated as unrecoverable because a
   request timed out.
4. **Create** the account on testnet with Friendbot, if it has no history. On
   mainnet there is no faucet, so that case is explained rather than attempted.

## Tests

```bash
npm test        # node --test test/*.test.mjs
```

50 tests, no network and no browser, because every I/O boundary is injected:
`server`, `provider`, `fetch` and `sleep` are parameters of the factory functions.
What they cover:

- **`test/mnemonic.test.mjs`** — the `abandon … about` vector derives exactly the
  account and secret that `stellar-toolkit wallet recover --show-secret` prints
  (`GB3JDWCQJCWMJ3IILWIGDTQJJC5567PGVEVXSCVPEQOTDN64VJBDQBYX`), which is what keeps
  the browser and the Rust implementations from drifting apart; account indices
  differ; each class of invalid phrase is rejected with its own reason.
- **`test/wallet.test.mjs`** — payments and contract calls are built with the
  right network passphrase, destination, amount, contract, method and arguments;
  reads are simulated and never signed; the fail path for a rejected
  transaction, a transaction that never lands, and one that fails in the ledger;
  polling stops on the ledger that includes the transaction; amounts, addresses
  and contract ids are validated before any network call; and the auth-entry guard
  catches a hand-built Soroban envelope whose authorization entry is unsigned
  while accepting a signed one.
- **`test/deeplink.test.mjs`** — SEP-7 links carry and round-trip destination,
  amount, asset code/issuer, memo, callback and message, survive a `&`/`#` in a
  memo, warn when they exceed the 300-character limit, and refuse bad input.
- **`test/recovery.test.mjs`** — every step of the recovery flow, including
  Friendbot funding, a Friendbot failure, a network failure that is *not* mistaken
  for a missing account, mainnet's lack of a faucet, and `create: false`.

The UI is verified by building it (`npm run build`); there is no browser in CI to
click through, so `src/app.mjs` is kept to DOM plumbing and all logic lives in the
tested modules.

## Security notes

- **Never paste a mainnet recovery phrase into a web page.** This example derives
  the key in the page so the flow is visible end to end, which means the phrase is
  in that tab's memory. It is not persisted, logged or sent anywhere, but a real
  deployment should keep phrase handling inside the wallet app and give the dapp
  only an address and a signature.
- The dapp never asks for, stores or transmits a secret key on the wallet path.
- `?network=` is validated, so a typo cannot silently move value on another chain.
- Deep links are the only thing handed to another app, and they contain no key
  material.

## Layout

```
examples/mobile-wallet-dapp/
├── index.html            # mobile-first UI (16px inputs, 44px targets, no framework)
├── src/
│   ├── app.mjs           # DOM wiring only
│   ├── config.mjs        # networks, contract ids, ?network= / ?contract= resolution
│   ├── deeplink.mjs      # SEP-7 build/parse/open
│   ├── mnemonic.mjs      # BIP-39 validation + SLIP-0010 derivation
│   ├── recovery.mjs      # validate → derive → look up → create
│   └── wallet.mjs        # connect, build, sign, submit, confirm, read/write contracts
├── test/                 # node --test, no network, no browser
└── vite.config.mjs       # dev server + static bundle
```

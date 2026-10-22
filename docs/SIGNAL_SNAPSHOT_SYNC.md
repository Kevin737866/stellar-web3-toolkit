# Off-Chain Signal Snapshot Sync (Issue #206)

Governance discussion happens off-chain. A vote has to name something both sides
agree on, so `stellar_toolkit::signal_sync` keeps a **deterministic mirror** of a
signal feed: it folds a list of signals into a `SignalSnapshot`, reports exactly
what changed, and refuses the changes that would make the mirror lie.

## The model

A `Signal` is what the snapshot needs to *name* a post, not a copy of it:

| Field | Meaning |
| --- | --- |
| `id` | Stable feed id, e.g. `forum:proposal/42` |
| `author` | Author handle as the feed reports it |
| `title` | Title as the feed reports it |
| `body_sha256` | sha256 of the body, lowercase hex |
| `updated_at` | Feed-assigned revision time |

The body itself is never stored: a vote commits to `(id, hash)`, and the snapshot
does not inherit the forum's retention or moderation problems.

```rust
use stellar_toolkit::signal_sync::{Signal, SignalSnapshot};

let mut snapshot = SignalSnapshot::empty();
let feed = vec![
    Signal::new("forum/1", "alice", "Raise the fee cap", b"full proposal body", 100),
    Signal::new("forum/2", "bob", "Fund the auditor", b"another body", 200),
];

let report = snapshot.sync(feed)?;
assert_eq!(report.added, vec!["forum/1", "forum/2"]);
println!("{}", report.render());
// signals: 2 added, 0 updated, 0 removed, 0 unchanged (digest 3f2c…)
```

## The digest

`SignalSnapshot::digest()` is a sha256 over id-sorted signals, with every
variable-length field length-prefixed and a domain separator in front. That
gives two properties a mirror needs:

* **Order independence.** Two mirrors that received the same signals in a
  different order produce the same digest.
* **Injectivity at field boundaries.** `author = "ab", title = "c"` cannot collide
  with `author = "a", title = "bc"`.

Two mirrors can compare a single hash instead of shipping the whole snapshot, and
a vote can commit to that hash.

## Refusals, not repairs

A sync either applies completely or leaves the snapshot byte-for-byte unchanged.
Every one of these aborts the whole sync:

| Error | Trigger | Why refuse instead of applying |
| --- | --- | --- |
| `EmptyFeed` | Empty feed while the snapshot holds signals | A transient outage returning `[]` must not erase the mirror |
| `StaleSignal` | `incoming.updated_at < stored.updated_at` | Applying it would rewind an edit someone already voted on |
| `ConflictingUpdate` | Same timestamp, different content | The feed is ambiguous; picking one side invents an answer |
| `DuplicateSignal` | The same id twice in one feed | One of the two would be silently dropped |
| `InvalidSignal` | Empty id/author/title, or a malformed `body_sha256` | A signal that cannot be named cannot be voted on |

`updated_at` is the *feed's* ordering, not wall-clock time: the toolkit does not
trust the local clock to sequence a remote feed.

## Persistence

`SignalSnapshot` and `Signal` derive `Serialize`/`Deserialize`, so a mirror can be
stored as JSON and restored without losing its digest:

```rust
let json = serde_json::to_string_pretty(&snapshot)?;
let restored: SignalSnapshot = serde_json::from_str(&json)?;
assert_eq!(restored.digest(), snapshot.digest());
```

`SNAPSHOT_VERSION` is bumped when the on-disk shape changes incompatibly; it is
part of the digest, so an old snapshot can never be mistaken for a new one.

## What it does not do

* **It does not fetch.** The caller supplies the feed; transport, pagination and
  retries belong to whatever reads the forum.
* **It does not authenticate the feed.** A signature over the snapshot hash is a
  separate step — see `docs/KEY_MANAGEMENT.md` for the signing boundary.
* **It does not vote.** Weights come from `docs/CONVICTION_VOTING.md`; this
  module only guarantees both sides are looking at the same signals.

## Tests

`cargo test -p stellar-toolkit --lib signal_sync` covers first sync, idempotent
re-sync, updates and removals, stale and ambiguous edits (asserting the snapshot
is untouched), duplicate and invalid signals, empty-feed protection, digest order
independence and field-boundary sensitivity, JSON round-tripping, and that the
body is hashed rather than stored.

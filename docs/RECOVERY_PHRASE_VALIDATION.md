# Recovery Phrase Validation with Word-Position Errors (issue #330)

`crates/stellar-toolkit` now validates a recovery phrase **before** any key is
derived. A rejected phrase reports which word to look at, instead of only
saying that "something" was wrong. No word from the phrase is ever copied into
an error message: the phrase is bearer key material, so even a single word is
sensitive.

## Interface

```rust
use stellar_toolkit::wallet::{
    validate_recovery_phrase, RecoveryPhraseError, RecoveryPhraseIssue,
    RecoveryPhraseIssueKind, RECOVERY_PHRASE_WORD_COUNTS,
};

match validate_recovery_phrase(phrase) {
    Ok(()) => { /* the phrase is usable with `recover_wallet` */ }
    Err(error) => {
        for issue in error.issues() {
            // issue.kind, issue.position (1-based), issue.message
            eprintln!("{}", issue.message);
        }
    }
}
```

* `validate_recovery_phrase(&str) -> Result<(), RecoveryPhraseError>` is pure:
  it derives no seed, writes no file, and holds no key material.
* `RecoveryPhraseIssue` carries `kind`, an optional 1-based `position`, and a
  secret-safe `message`. `RecoveryPhraseIssueKind` is one of `empty_phrase`,
  `invalid_word_count`, `unknown_word`, `checksum_mismatch` (serde names).
* `RecoveryPhraseError` implements `Display` and `std::error::Error`; its
  `Display` starts with `invalid recovery phrase`, followed by one clause per
  issue. Its `Debug` is also safe to log.
* `RECOVERY_PHRASE_WORD_COUNTS` is `[12, 15, 18, 21, 24]`.

## What is reported

| Input | Finding | Position |
|-------|---------|----------|
| Empty or whitespace-only | `empty_phrase` | none |
| 1, 13, 23, 25, … words | `invalid_word_count` (names the count found) | none |
| Word not in the English BIP-39 wordlist | `unknown_word`, one finding per bad word | each 1-based position |
| Known words, wrong checksum, one nearby word repairs it | `checksum_mismatch` ("looks like a typo") | that word's position |
| Known words, wrong checksum, no single nearby repair | `checksum_mismatch` | final word (it stores the checksum bits) |
| Several plausible single-word repairs | `checksum_mismatch` (lists the positions) | none (ambiguous) |

The checksum heuristic only considers replacement words within two edits of
the word supplied. BIP-39 checksums are at most 8 bits, so *any* position has
many wordlist replacements that satisfy them; without the "small edit" rule
the checker would blame almost every word and the result would not be
actionable. A transposition or a completely different word therefore falls
back to the final-word hint rather than guessing.

## CLI

```bash
# Validate only; prints no secret key or account id.
stellar-toolkit wallet validate "<twelve to twenty-four words>"

# Recovery now fails early with the same word-position guidance.
stellar-toolkit wallet recover "<phrase>"
```

On success `wallet validate` prints `Recovery phrase is valid (N words).` and
exits 0. On failure it exits non-zero and the error names the offending word
position. The parsed CLI command redacts `phrase` in its `Debug` output, as
`wallet recover` already did.

## Security invariants

* **Secrets:** no phrase word, seed, or derived key appears in a finding, in
  `Debug`, or in CLI output from `validate`. `wallet recover` keeps printing the
  wallet only after validation succeeds.
* **Failure reporting:** all unknown-word positions are returned in one pass,
  in phrase order, so a user can fix the phrase in one edit session.
* **Recovery / state:** validation is side-effect free; a failed check cannot
  leave partially derived keys or a partially imported wallet behind.
* **Authorization:** no new privileged operation is introduced. Validation is
  a local, offline check and does not contact Horizon or Friendbot.

## Compatibility

* `recover_wallet(&str) -> Result<GeneratedWallet>` keeps its signature and its
  output for valid phrases. Its invalid-input error keeps the
  `invalid recovery phrase` prefix but now includes word positions instead of
  the upstream parser's generic message. Callers that only check `is_err()` are
  unaffected.
* `wallet validate` is an additional subcommand; existing `wallet generate`,
  `recover`, `fund` and `sign` behavior is unchanged.
* The accepted language remains English BIP-39 with a 24-word default from
  `wallet generate`; other word counts are accepted when already in a user's
  backup. There is no new configuration or environment variable.
* Validation deliberately does not accept a BIP-39 passphrase: the toolkit
  derives Stellar keys with an empty passphrase, so accepting one here would
  suggest a phrase is usable when recovery would derive a different account.

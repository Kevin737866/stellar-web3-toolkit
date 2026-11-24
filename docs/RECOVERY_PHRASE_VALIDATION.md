# Actionable Recovery-Phrase Validation

**Issue:** [#330](https://github.com/Kevin737866/stellar-web3-toolkit/issues/330) — *Validate recovery phrases with actionable word-position errors*

`wallet recover` used to reject a mistyped phrase with the parser's raw text
("mnemonic contains an unknown word (word 6)"), which is hard to act on when the
user is holding a numbered paper backup. Worse, the error did not distinguish a
typo in one word from a checksum failure caused by swapping two valid words.

The wallet now exposes a validation step that reports **which word position**
is wrong, and `wallet recover` uses it before deriving anything.

## Interface

All of the following live in `crates/stellar-toolkit/src/wallet.rs` and are
re-exported at the crate root:

```rust
pub const VALID_PHRASE_WORD_COUNTS: [usize; 5] = [12, 15, 18, 21, 24];

pub enum PhraseIssue {
    Empty,                                    // blank input
    WordCount { found: usize },               // not 12/15/18/21/24
    UnknownWords { positions: Vec<usize> },   // 1-based, all bad words
    InvalidChecksum { final_word_position: usize },
    Rejected,                                 // parser reason without a position
}

pub struct PhraseValidation {
    pub word_count: usize,
    pub issue: Option<PhraseIssue>,
}

pub fn validate_recovery_phrase(phrase: &str) -> PhraseValidation;
```

`PhraseIssue::message()` and `PhraseValidation::error_message()` render an
actionable explanation. `PhraseValidation::is_valid()` is a convenience for
`issue.is_none()`.

Positions are **1-based** to match how people count words on paper. Every bad
word is reported, not just the first one, so two typos take one correction
round instead of two.

### What each issue tells the user

| Issue | Message (shape) | Why it is actionable |
| --- | --- | --- |
| `Empty` | `the recovery phrase is empty` | No input was supplied. |
| `WordCount { found: 25 }` | `expected 12, 15, 18, 21, or 24 words; found 25` | States both the actual and the accepted counts. |
| `UnknownWords { positions: [3, 19] }` | `words 3 and 19 are not in the BIP-39 English wordlist` | Names the exact positions to compare with the backup. |
| `InvalidChecksum { final_word_position: 24 }` | `BIP-39 checksum mismatch; word 24 is the final word and carries the checksum, but any mistyped or swapped word can cause this` | The checksum lives in the final word, but a swap of two valid words also breaks it — the message says so instead of implying a single culprit. |
| `Rejected` | `the recovery phrase was rejected by the BIP-39 parser` | Defensive fallback; not reachable for English phrases with a valid count and known words. |

## Secret handling

* **No word is ever echoed.** The recovery phrase is a bearer credential equal
  to the `S…` secret key (`docs/KEY_MANAGEMENT.md`). Errors name the *position*,
  never the word, so a mistyped phrase cannot leak into logs or CI output.
* **Validation is pure.** It derives no seed, makes no network call, writes no
  file, and keeps no copy of the phrase. `wallet validate` therefore exists as a
  safe way to check a phrase without printing a key.
* **`Debug` is redacted.** `WalletCommand::Validate` follows the existing
  `Recover`/`Sign` pattern and logs `Validate { phrase: "<redacted>" }`.
* **`recover_wallet` validates first.** A bad phrase fails before
  `slip10_derive` runs, so there is no partially derived key or wallet state.

## CLI

```bash
# Check without deriving a key (phrase stays out of shell history and `ps`):
printf '%s\n' "<your 24 words>" | stellar-toolkit wallet validate

# Or pass it as an argument, as `wallet recover` does:
stellar-toolkit wallet validate "<your 24 words>"

# Recovery now reports the position on failure:
stellar-toolkit wallet recover "<your 24 words with a typo>"
# wallet error: invalid recovery phrase: word 7 is not in the BIP-39 English wordlist
```

Omitting `PHRASE` reads exactly one line from stdin; a blank line is reported as
`the recovery phrase is empty` rather than being treated as no input.

## Configuration

There is nothing to configure. The language is fixed to BIP-39 English (the
same as `wallet generate`/`wallet recover`), the accepted word counts are the
BIP-39 set above, and validation uses the crate's existing `bip39` dependency —
no new feature flag or environment variable is required.

## Compatibility

* **Additive API.** `validate_recovery_phrase`, `PhraseIssue`,
  `PhraseValidation`, and `VALID_PHRASE_WORD_COUNTS` are new public items. No
  existing signature or type changed.
* **Valid phrases behave identically.** `recover_wallet` still derives at
  `m/44'/148'/0'` and returns the same account and secret; only the *error text*
  for invalid phrases is more specific. The `invalid recovery phrase:` prefix
  is preserved for callers that match on it.
* **Invalid input is never substituted.** The validator does not normalize a
  bad word to a similar one, pad a 23-word phrase, or fall back to a default
  passphrase. Callers receive a structured issue and decide what to do.
* **Whitespace tolerance is unchanged.** Both validation and recovery use
  `split_whitespace()`, so leading, trailing, and repeated whitespace keeps
  working exactly as before. Non-normalized Unicode is still reported as an
  unknown word at its position.
* **No contract changes.** The feature is confined to `crates/stellar-toolkit`;
  Soroban contracts and their entry points are untouched.

## Validation

```bash
cargo fmt --all -- --check
cargo test -p stellar-toolkit
cargo run -p stellar-toolkit -- security secrets
```

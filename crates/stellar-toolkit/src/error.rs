use crate::key_hygiene::{looks_like_secret_key, mask_secret};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ToolkitError {
    #[error("compilation failed: {0}")]
    CompilationFailed(String),
    #[error("session error: {0}")]
    // Reserved for session-key errors; not raised yet.
    #[allow(dead_code)]
    Session(String),
    #[error("execution error: {0}")]
    ExecutionError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("wallet error: {0}")]
    Wallet(String),
    #[error("treasury error: {0}")]
    Treasury(String),
    #[error("amount overflow: {0}")]
    AmountOverflow(String),
    #[error("insufficient treasury balance: have {0}, need {1}")]
    InsufficientBalance(i128, i128),
    #[error("stream {0} not found")]
    StreamNotFound(String),
    #[error("stream {0} is cancelled")]
    StreamCancelled(String),
    #[error("invalid stream schedule: {0}")]
    InvalidSchedule(String),
    #[error("glossary error: {0}")]
    Glossary(String),
    #[error("contract spec error: {0}")]
    ContractSpec(String),
    #[error("horizon error: {0}")]
    Horizon(String),
    #[error("horizon pagination error: {0}")]
    HorizonPagination(#[from] crate::horizon::HorizonPaginationError),
}

pub type Result<T> = std::result::Result<T, ToolkitError>;

/// Placeholder that replaces a recovery phrase found in error output.
pub const REDACTED_PHRASE: &str = "<redacted recovery phrase>";

/// Shortest recognised recovery phrase length (12 words, BIP-39).
const MIN_PHRASE_WORDS: usize = 12;

impl ToolkitError {
    /// Render the error with any secret-bearing value masked (#331).
    ///
    /// This is the form the CLI prints and the form logs should use. `Display`
    /// and `Debug` stay as they are so the derivation chain (`#[from]`,
    /// `source()`) and existing message assertions keep working; the redaction
    /// is applied exactly where the message leaves the process.
    #[must_use]
    pub fn redacted(&self) -> String {
        redact_secret_material(&self.to_string())
    }
}

/// Mask secret-bearing values in free text (#331).
///
/// Two shapes are recognised, both of which have a fixed format that makes a
/// false positive very unlikely:
///
/// * **Stellar secret keys** — a bare `S` followed by 55 base32 characters,
///   wherever it appears in the line (including inside backticks or quotes).
///   Replaced by [`mask_secret`]'s `S…ABCD` form.
/// * **Recovery phrases** — a run of 12 or more consecutive lowercase words.
///   Replaced as a whole by [`REDACTED_PHRASE`], because masking a single word
///   of a phrase would leave the rest of it readable.
///
/// Public account ids (`G…`), transaction hashes, paths and ordinary prose are
/// left untouched: this is a guard rail that keeps a mistake from printing a key,
/// not a general-purpose secret scanner (see `crate::key_hygiene` for that).
///
/// The function is idempotent: running it over already-redacted text changes
/// nothing, which matters because errors can pass through it more than once as
/// they bubble up.
#[must_use]
pub fn redact_secret_material(text: &str) -> String {
    // Each span keeps the whitespace that preceded its word, so the output has
    // exactly the original spacing and newlines apart from the masked values.
    let spans = split_spans(text);

    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < spans.len() {
        let (separator, word) = spans[index];

        // A recovery phrase: a maximal run of phrase-shaped words.
        let mut end = index;
        while end < spans.len() && is_phrase_word(spans[end].1) {
            end += 1;
        }
        if end - index >= MIN_PHRASE_WORDS {
            out.push_str(separator);
            out.push_str(REDACTED_PHRASE);
            // Keep punctuation that trailed the last word of the phrase.
            out.push_str(trailing_punctuation(spans[end - 1].1));
            index = end;
            continue;
        }

        out.push_str(separator);
        out.push_str(&redact_secret_key(word));
        index += 1;
    }
    out
}

/// Split `text` into `(leading whitespace, word)` spans.
///
/// Unlike `split_inclusive`, a run of several whitespace characters stays with
/// the word that follows it, so a phrase separated by more than one space is
/// still one run of words.
fn split_spans(text: &str) -> Vec<(&str, &str)> {
    let mut spans = Vec::new();
    let mut index = 0;
    while index < text.len() {
        let separator_start = index;
        while let Some(ch) = text[index..].chars().next() {
            if !ch.is_whitespace() {
                break;
            }
            index += ch.len_utf8();
        }
        let separator = &text[separator_start..index];

        let word_start = index;
        while let Some(ch) = text[index..].chars().next() {
            if ch.is_whitespace() {
                break;
            }
            index += ch.len_utf8();
        }
        spans.push((separator, &text[word_start..index]));
    }
    spans
}

/// Punctuation after the last alphabetic character of `word`.
fn trailing_punctuation(word: &str) -> &str {
    let core = word.trim_end_matches(|c: char| !c.is_ascii_alphabetic());
    &word[core.len()..]
}

/// Replace Stellar secret keys inside one token, keeping surrounding punctuation.
///
/// A strkey is alphanumeric, so the token is scanned for maximal alphanumeric
/// fragments. That catches `key`, `"key":`, `STELLAR_SECRET_KEY=key` and
/// `(key);` without needing to know which separator the message used.
fn redact_secret_key(token: &str) -> String {
    let mut out = String::with_capacity(token.len());
    let mut index = 0;
    while index < token.len() {
        let Some(ch) = token[index..].chars().next() else {
            break;
        };
        if !ch.is_ascii_alphanumeric() {
            out.push(ch);
            index += ch.len_utf8();
            continue;
        }

        let start = index;
        while let Some(inner) = token[index..].chars().next() {
            if !inner.is_ascii_alphanumeric() {
                break;
            }
            index += inner.len_utf8();
        }
        let fragment = &token[start..index];
        if looks_like_secret_key(fragment) {
            out.push_str(&mask_secret(fragment));
        } else {
            out.push_str(fragment);
        }
    }
    out
}

/// True when `word` (punctuation stripped) is shaped like a BIP-39 word.
fn is_phrase_word(word: &str) -> bool {
    let trimmed = word.trim_matches(|c: char| !c.is_ascii_alphabetic());
    (3..=8).contains(&trimmed.chars().count())
        && trimmed.chars().all(|c| c.is_ascii_lowercase())
        // An already-redacted placeholder is not phrase material.
        && !trimmed.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A strkey-shaped secret, assembled so this file holds no secret literal.
    fn secret_fixture() -> String {
        format!("S{}", "A".repeat(55))
    }

    fn phrase_fixture() -> String {
        let mut words = vec!["abandon"; 23];
        words.push("art");
        words.join(" ")
    }

    #[test]
    fn masks_a_secret_key_anywhere_in_the_message() {
        let secret = secret_fixture();
        for text in [
            format!("wallet error: invalid secret key `{secret}`: checksum"),
            format!("failed to sign with {secret}"),
            format!("secret={secret}"),
        ] {
            let redacted = redact_secret_material(&text);
            assert!(
                !redacted.contains(&secret),
                "secret survived redaction: {redacted}"
            );
            assert!(
                redacted.contains("SA…AAAA"),
                "the masked form should identify the key: {redacted}"
            );
        }
    }

    #[test]
    fn masks_a_whole_recovery_phrase() {
        let phrase = phrase_fixture();
        let redacted = redact_secret_material(&format!("recovered phrase: {phrase}!"));
        assert!(!redacted.contains("abandon"), "phrase leaked: {redacted}");
        assert!(redacted.contains(REDACTED_PHRASE));
        assert!(
            redacted.ends_with('!'),
            "punctuation must survive: {redacted}"
        );
    }

    #[test]
    fn leaves_public_ids_paths_and_prose_alone() {
        let account = "GDUMMYACCOUNTFORTESTONLYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let messages = [
            format!("funded {account} (tx 1234abc)"),
            "could not read config/dev.toml: No such file or directory".to_string(),
            "invalid amount: expected a positive integer".to_string(),
            REDACTED_PHRASE.to_string(),
        ];
        for message in messages {
            assert_eq!(
                redact_secret_material(&message),
                message,
                "ordinary text must not change"
            );
        }
    }

    #[test]
    fn is_idempotent() {
        let text = format!(
            "wallet error: invalid secret key `{}`; phrase: {}",
            secret_fixture(),
            phrase_fixture()
        );
        let once = redact_secret_material(&text);
        assert_eq!(redact_secret_material(&once), once);
    }

    #[test]
    fn preserves_newlines_and_spacing() {
        let text = format!("first line\n\n  key: {}\nlast", secret_fixture());
        let redacted = redact_secret_material(&text);
        assert_eq!(redacted.lines().count(), 4);
        assert!(redacted.starts_with("first line\n\n  key: S"));
        assert!(redacted.ends_with("\nlast"));
    }

    #[test]
    fn toolkit_error_redacted_masks_an_embedded_secret() {
        let secret = secret_fixture();
        let error = ToolkitError::Wallet(format!("keystore authentication failed for `{secret}`"));
        let rendered = error.redacted();
        assert!(!rendered.contains(&secret), "secret leaked: {rendered}");
        assert!(rendered.starts_with("wallet error: keystore authentication failed"));
        // `redacted()` does not alter the error itself.
        assert!(error.to_string().contains(&secret));
    }
}

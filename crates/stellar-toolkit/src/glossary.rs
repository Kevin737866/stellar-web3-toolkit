//! Glossary lookup: the terminal equivalent of a hover tooltip.
//!
//! `docs/GLOSSARY.md` is the single source of truth for the toolkit's
//! terminology. Rather than duplicating those definitions into Rust literals —
//! which guarantees they drift the first time someone edits the Markdown —
//! this module **parses the Markdown at runtime**. The parser is deliberately
//! small and targets exactly the shape `GLOSSARY.md` uses: a
//! `### **Term**` heading followed by prose, with `---` horizontal rules and
//! `##` headings closing sections.
//!
//! # Locating the file
//!
//! A compiled binary's working directory is not guaranteed, so
//! [`Glossary::discover`] searches a fixed, documented order and stops at the
//! first hit:
//!
//! 1. an explicit `--glossary <path>` argument,
//! 2. the `STELLAR_TOOLKIT_GLOSSARY` environment variable,
//! 3. walking up from the current working directory looking for
//!    `docs/GLOSSARY.md`,
//! 4. walking up from the executable's own location (covers `target/debug/`
//!    and installed binaries inside a checkout),
//! 5. the compile-time `CARGO_MANIFEST_DIR` of this crate, resolved to the
//!    workspace `docs/` directory (works for `cargo run` / `cargo test`).
//!
//! # Match ladder
//!
//! Lookup tries progressively looser strategies and reports which one hit, so
//! the result is always explainable. Every tier is deterministic: candidates
//! within a tier are ordered by (number of extra words, then term length, then
//! alphabetical), so the same query always yields the same answer.
//!
//! 1. `Exact` — byte-for-byte.
//! 2. `CaseInsensitive` — ASCII case-folded.
//! 3. `Prefix` — the query starts a term (`sorob` → `Soroban`), **or** the term
//!    is a prefix of the query, which catches a half-typed multi-word term.
//! 4. `Substring` — the query appears inside the term (`rpc` → `Soroban RPC`).
//! 5. `AllWords` — every whitespace-separated word of the query appears in the
//!    term, which is what makes `hashed timelock` find
//!    `Hashed Timelock Contract (HTLC)`.
//! 6. `Fuzzy` — the query's characters appear in order (a subsequence), so
//!    `sorobn` still finds `Soroban`.
//!
//! No fuzzy library and no edit-distance table: a subsequence test is a few
//! lines, has no tuning parameters, and cannot produce a different answer on a
//! different machine.
//!
//! # Fragility, stated plainly
//!
//! This is a Markdown parser for one known file, not a general CommonMark
//! implementation. It handles `###`-or-deeper headings, `**bold**` term
//! markers, `---` rules, and fenced code blocks (a `###` inside a fence is not
//! treated as a heading). It does **not** handle setext headings, HTML, nested
//! blockquotes, or a term heading with trailing prose after the bold run. The
//! `GLOSSARY.md` conformance test in this module parses the real file, so a
//! change to that file's structure fails loudly rather than silently dropping
//! terms.

use crate::error::{Result, ToolkitError};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Relative location of the glossary within the repository.
const GLOSSARY_RELATIVE: &str = "docs/GLOSSARY.md";

/// Environment variable that overrides glossary discovery.
const GLOSSARY_ENV: &str = "STELLAR_TOOLKIT_GLOSSARY";

/// One glossary term and its definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GlossaryEntry {
    /// The term exactly as written in the Markdown, e.g. `Hashed Timelock Contract (HTLC)`.
    pub term: String,
    /// Anchor for this term, matching the explicit
    /// `<a id="...">` markers in `docs/GLOSSARY.md`.
    pub anchor: String,
    /// The prose definition, verbatim, with Markdown inline code left intact.
    pub definition: String,
}

/// Which strategy in the match ladder produced a hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MatchKind {
    Exact,
    CaseInsensitive,
    Prefix,
    Substring,
    AllWords,
    Fuzzy,
}

impl MatchKind {
    /// Human label used in terminal output.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::CaseInsensitive => "case-insensitive",
            Self::Prefix => "prefix",
            Self::Substring => "substring",
            Self::AllWords => "all-words",
            Self::Fuzzy => "fuzzy",
        }
    }
}

/// A successful lookup: the winning entry, how it matched, and any runners-up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Lookup {
    pub entry: GlossaryEntry,
    pub kind: MatchKind,
    /// Other terms that also matched, best first. Useful as "see also".
    pub also_matches: Vec<GlossaryEntry>,
}

/// The parsed contents of a glossary Markdown document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Glossary {
    pub entries: Vec<GlossaryEntry>,
}

/// Deterministic ordering key for candidate entries within a match tier:
/// fewest extra words, then shortest term, then alphabetical.
fn rank(entry: &GlossaryEntry) -> (usize, usize, &str) {
    (
        entry.term.split_whitespace().count(),
        entry.term.chars().count(),
        entry.term.as_str(),
    )
}

/// The documented anchor slug for a term.
///
/// Lowercase the term, drop the bold markers, replace every run of
/// non-alphanumeric characters with a single hyphen, and trim leading and
/// trailing hyphens. This is deliberately **identical to GitHub's own heading
/// slug algorithm**, so `Hashed Timelock Contract (HTLC)` slugs to
/// `hashed-timelock-contract-htlc` whether or not the explicit `<a id>`
/// marker below the heading is present. Matching GitHub is the point: a link
/// works in every renderer, and re-rendering the Markdown without the explicit
/// anchors does not break a single incoming link.
pub fn anchor_for(term: &str) -> String {
    let mut out = String::with_capacity(term.len());
    let mut pending_hyphen = false;
    for ch in term.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            if pending_hyphen && !out.is_empty() {
                out.push('-');
            }
            pending_hyphen = false;
            out.push(ch.to_ascii_lowercase());
        } else {
            // Defer the hyphen so trailing punctuation never produces a
            // trailing separator, and runs do not double up.
            pending_hyphen = true;
        }
    }
    out
}

impl Glossary {
    /// Parses a glossary Markdown document.
    ///
    /// A `###`-or-deeper heading introduces a term; `**bold**` markers around
    /// the term are stripped when present. The definition is every following
    /// non-empty line up to the next heading, a `---` rule, a fence, or EOF.
    /// Headings with no prose beneath them are skipped, since they are section
    /// labels rather than terms.
    pub fn parse(markdown: &str) -> Self {
        let mut entries: Vec<GlossaryEntry> = Vec::new();
        // (term, declared anchor if the file provided one, definition lines)
        let mut current: Option<(String, Option<String>, Vec<String>)> = None;
        let mut in_fence = false;

        for raw_line in markdown.lines() {
            let line = raw_line.trim_end_matches('\r');
            let trimmed = line.trim();

            // Fenced code blocks are opaque: a `###` inside one is not a term.
            if trimmed.starts_with("```") {
                in_fence = !in_fence;
                if let Some((term, anchor, body)) = current.take() {
                    push_entry(&mut entries, term, anchor, body);
                }
                continue;
            }
            if in_fence {
                continue;
            }

            let is_heading = trimmed.starts_with('#');
            let is_rule = trimmed == "---" || trimmed == "***" || trimmed == "___";

            if is_heading {
                // A new heading closes whatever definition we were collecting.
                if let Some((term, anchor, body)) = current.take() {
                    push_entry(&mut entries, term, anchor, body);
                }
                if trimmed.starts_with("###") {
                    let term = strip_bold(heading_text(trimmed));
                    if !term.is_empty() {
                        current = Some((term, None, Vec::new()));
                    }
                }
                continue;
            }

            if is_rule {
                if let Some((term, anchor, body)) = current.take() {
                    push_entry(&mut entries, term, anchor, body);
                }
                continue;
            }

            // The explicit anchor marker sits between a heading and its prose.
            // Record it rather than letting it leak into the definition — and
            // checking it against `anchor_for` is what keeps the Markdown and
            // this module from drifting apart.
            if let Some(id) = parse_anchor(trimmed) {
                if let Some((_, ref mut anchor, _)) = current {
                    *anchor = Some(id);
                }
                continue;
            }

            if let Some((_, _, ref mut body)) = current {
                if !trimmed.is_empty() {
                    body.push(trimmed.to_string());
                }
            }
        }

        if let Some((term, anchor, body)) = current.take() {
            push_entry(&mut entries, term, anchor, body);
        }

        Self { entries }
    }

    /// Reads and parses a glossary file.
    pub fn from_path(path: &Path) -> Result<Self> {
        let markdown = std::fs::read_to_string(path).map_err(|e| {
            ToolkitError::Glossary(format!("cannot read glossary at {}: {e}", path.display()))
        })?;
        Ok(Self::parse(&markdown))
    }

    /// All terms, in document order.
    pub fn terms(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.term.as_str()).collect()
    }

    /// Looks up a term using the documented match ladder.
    ///
    /// Returns `None` when nothing matches at any tier, which callers must treat
    /// as a failure rather than an empty success.
    pub fn lookup(&self, query: &str) -> Option<Lookup> {
        let q = query.trim();
        if q.is_empty() {
            return None;
        }
        let q_ci = q.to_ascii_lowercase();

        for kind in [
            MatchKind::Exact,
            MatchKind::CaseInsensitive,
            MatchKind::Prefix,
            MatchKind::Substring,
            MatchKind::AllWords,
            MatchKind::Fuzzy,
        ] {
            let mut hits: Vec<&GlossaryEntry> = self
                .entries
                .iter()
                // `Exact` is the only tier that must see the term unmodified;
                // every other tier compares against the case-folded term.
                .filter(|e| match kind {
                    MatchKind::Exact => e.term == q,
                    _ => matches(kind, &e.term.to_ascii_lowercase(), &q_ci),
                })
                .collect();

            if hits.is_empty() {
                continue;
            }
            hits.sort_by_key(|e| rank(e));

            let also_matches = if kind == MatchKind::Exact {
                // Terms are unique keys in practice, and a byte-exact hit needs
                // no "see also".
                Vec::new()
            } else {
                hits[1..].iter().map(|e| (*e).clone()).collect()
            };

            return Some(Lookup {
                entry: hits[0].clone(),
                kind,
                also_matches,
            });
        }
        None
    }

    /// Terms closest to a query, for a "did you mean" list when nothing matched.
    pub fn suggestions(&self, query: &str, limit: usize) -> Vec<GlossaryEntry> {
        let q = query.trim().to_ascii_lowercase();
        if q.is_empty() {
            return Vec::new();
        }
        let mut scored: Vec<(usize, &GlossaryEntry)> = self
            .entries
            .iter()
            .filter_map(|e| {
                let term_ci = e.term.to_ascii_lowercase();
                edit_distance(&q, &term_ci).map(|d| (d, e))
            })
            .collect();
        // Nearest first, then deterministic alphabetical tie-break.
        scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.term.cmp(&b.1.term)));
        scored
            .into_iter()
            .take(limit)
            .map(|(_, e)| e.clone())
            .collect()
    }
}

/// Recognise a standalone anchor marker such as `<a id="atomic-swap"></a>`.
///
/// Returns the id. Anything that is not exactly an anchor marker returns
/// `None` and is treated as ordinary prose, so a definition that happens to
/// mention HTML is never dropped.
fn parse_anchor(line: &str) -> Option<String> {
    let rest = line.strip_prefix("<a id=\"")?;
    let id = rest.strip_suffix("\"></a>")?;
    if id.is_empty() {
        return None;
    }
    Some(id.to_string())
}

fn push_entry(
    entries: &mut Vec<GlossaryEntry>,
    term: String,
    declared_anchor: Option<String>,
    body: Vec<String>,
) {
    if body.is_empty() {
        return;
    }
    let definition = body.join(" ");
    entries.push(GlossaryEntry {
        // Prefer the id the file states, so the code reports what other docs
        // should actually link to.
        anchor: declared_anchor.unwrap_or_else(|| anchor_for(&term)),
        term,
        definition,
    });
}

/// Strip the leading `#`s and surrounding whitespace from a heading line.
fn heading_text(line: &str) -> &str {
    line.trim_start_matches('#').trim()
}

/// Strip a surrounding `**bold**` run, if the whole term is wrapped in one.
fn strip_bold(text: &str) -> String {
    let t = text.trim();
    if let Some(inner) = t.strip_prefix("**").and_then(|s| s.strip_suffix("**")) {
        return inner.trim().to_string();
    }
    t.to_string()
}

/// One tier of the match ladder, evaluated against a case-folded term.
fn matches(kind: MatchKind, term_ci: &str, query_ci: &str) -> bool {
    match kind {
        MatchKind::Exact | MatchKind::CaseInsensitive => term_ci == query_ci,
        MatchKind::Prefix => {
            // Either the query starts the term, or the term is a prefix of a
            // half-typed multi-word query.
            term_ci.starts_with(query_ci) || query_ci.starts_with(term_ci)
        }
        MatchKind::Substring => term_ci.contains(query_ci),
        MatchKind::AllWords => {
            let words: Vec<&str> = query_ci.split_whitespace().collect();
            !words.is_empty() && words.iter().all(|w| term_ci.contains(w))
        }
        MatchKind::Fuzzy => is_subsequence(query_ci, term_ci),
    }
}

/// Whether every character of `needle` appears in `haystack`, in order.
fn is_subsequence(needle: &str, haystack: &str) -> bool {
    let mut chars = haystack.chars();
    needle.chars().all(|c| chars.any(|h| h == c))
}

/// Levenshtein distance, used only to rank "did you mean" suggestions.
/// Returns `None` when the distance is too large to be a plausible typo.
fn edit_distance(a: &str, b: &str) -> Option<usize> {
    /// Distances above this are not suggestions, they are noise.
    const MAX: usize = 3;

    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();

    // Trim the common prefix/suffix first: most of a term's length is shared.
    let mut start = 0;
    while start < a.len() && start < b.len() && a[start] == b[start] {
        start += 1;
    }
    let mut end = 0;
    while end < a.len() - start
        && end < b.len() - start
        && a[a.len() - 1 - end] == b[b.len() - 1 - end]
    {
        end += 1;
    }
    let a = &a[start..a.len() - end];
    let b = &b[start..b.len() - end];

    if a.is_empty() {
        return if b.len() <= MAX { Some(b.len()) } else { None };
    }
    if b.is_empty() {
        return if a.len() <= MAX { Some(a.len()) } else { None };
    }

    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        std::mem::swap(&mut prev, &mut cur);
    }

    let d = prev[b.len()];
    if d <= MAX {
        Some(d)
    } else {
        None
    }
}

/// Find `docs/GLOSSARY.md` by walking up from `start`.
fn search_upward(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let candidate = d.join(GLOSSARY_RELATIVE);
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = d.parent();
    }
    None
}

/// Locate the glossary using the documented search order.
pub fn discover(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        if !p.is_file() {
            return Err(ToolkitError::Glossary(format!(
                "glossary not found at {}",
                p.display()
            )));
        }
        return Ok(p.to_path_buf());
    }

    if let Ok(p) = std::env::var(GLOSSARY_ENV) {
        let path = PathBuf::from(&p);
        if path.is_file() {
            return Ok(path);
        }
        return Err(ToolkitError::Glossary(format!(
            "{GLOSSARY_ENV} points at {}, which is not a file",
            path.display()
        )));
    }

    if let Ok(cwd) = std::env::current_dir() {
        if let Some(p) = search_upward(&cwd) {
            return Ok(p);
        }
    }

    // A binary built into `target/<profile>/` sits below the workspace root.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            if let Some(p) = search_upward(dir) {
                return Ok(p);
            }
        }
    }

    // Compile-time fallback: this crate lives at <workspace>/crates/stellar-toolkit.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(p) = search_upward(&manifest) {
        return Ok(p);
    }

    Err(ToolkitError::Glossary(format!(
        "could not locate {GLOSSARY_RELATIVE}; pass --glossary <path> or set {GLOSSARY_ENV}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A miniature glossary in the exact shape of `docs/GLOSSARY.md`.
    const SAMPLE: &str = "\
# Stellar & Soroban Protocol Glossary

Some intro prose that is not a term.

---

## Terms & Concepts

### **Account**
A public-key address on the Stellar ledger.

### **Soroban RPC**
An JSON-RPC endpoint dedicated to interacting with Soroban smart contracts.

### **Hashed Timelock Contract (HTLC)**
A class of smart contract using hashlocks and timelocks.

---

## Additional Resources
- [Stellar Developer Documentation](https://developers.stellar.org/)
";

    fn sample() -> Glossary {
        Glossary::parse(SAMPLE)
    }

    #[test]
    fn test_parses_terms_from_sample() {
        let g = sample();
        assert_eq!(
            g.terms(),
            vec!["Account", "Soroban RPC", "Hashed Timelock Contract (HTLC)"]
        );
        assert_eq!(
            g.entries[0].definition,
            "A public-key address on the Stellar ledger."
        );
    }

    #[test]
    fn test_bold_markers_and_rule_separators_are_handled() {
        let g = sample();
        // `**` stripped from the term.
        assert!(g.terms().contains(&"Account"));
        // The `---` rule stopped the last definition before "Additional Resources".
        let htlc = g.lookup("Hashed Timelock Contract (HTLC)").unwrap();
        assert_eq!(
            htlc.entry.definition,
            "A class of smart contract using hashlocks and timelocks."
        );
        assert!(!htlc.entry.definition.contains("Additional Resources"));
        // The bullet list under `##` is not swallowed as a definition either.
        assert!(!g
            .entries
            .iter()
            .any(|e| e.definition.contains("[Stellar Developer")));
    }

    #[test]
    fn test_exact_match() {
        let g = sample();
        let hit = g.lookup("Account").unwrap();
        assert_eq!(hit.kind, MatchKind::Exact);
        assert_eq!(hit.entry.term, "Account");
        assert!(hit.also_matches.is_empty());
    }

    #[test]
    fn test_case_insensitive_match() {
        let g = sample();
        let hit = g.lookup("account").unwrap();
        assert_eq!(hit.kind, MatchKind::CaseInsensitive);
        assert_eq!(hit.entry.term, "Account");

        let hit = g.lookup("SOROBAN RPC").unwrap();
        assert_eq!(hit.kind, MatchKind::CaseInsensitive);
        assert_eq!(hit.entry.term, "Soroban RPC");
    }

    #[test]
    fn test_multi_word_exact_and_case_insensitive() {
        let g = sample();
        assert_eq!(g.lookup("Soroban RPC").unwrap().kind, MatchKind::Exact);
        assert_eq!(g.lookup("soroban rpc").unwrap().entry.term, "Soroban RPC");
    }

    #[test]
    fn test_prefix_match_for_partially_typed_term() {
        let g = sample();
        // A prefix of the term.
        let hit = g.lookup("sorob").unwrap();
        assert_eq!(hit.kind, MatchKind::Prefix);
        assert_eq!(hit.entry.term, "Soroban RPC");

        // The term is a prefix of the query — half-typed multi-word term.
        let hit = g.lookup("Soroban RP").unwrap();
        assert_eq!(hit.entry.term, "Soroban RPC");
    }

    #[test]
    fn test_substring_match() {
        let g = sample();
        let hit = g.lookup("rpc").unwrap();
        assert_eq!(hit.kind, MatchKind::Substring);
        assert_eq!(hit.entry.term, "Soroban RPC");
    }

    #[test]
    fn test_all_words_match_for_reordered_or_partial_multi_word_query() {
        let g = sample();
        let hit = g.lookup("timelock hashed").unwrap();
        assert_eq!(hit.kind, MatchKind::AllWords);
        assert_eq!(hit.entry.term, "Hashed Timelock Contract (HTLC)");
    }

    #[test]
    fn test_fuzzy_near_miss() {
        let g = sample();
        let hit = g.lookup("sorobn").unwrap();
        assert_eq!(hit.kind, MatchKind::Fuzzy);
        assert_eq!(hit.entry.term, "Soroban RPC");

        let hit = g.lookup("acount").unwrap();
        assert_eq!(hit.entry.term, "Account");
    }

    #[test]
    fn test_no_match_returns_none_and_suggests_nearby() {
        let g = sample();
        assert!(g.lookup("quantum blockchain").is_none());

        let suggestions = g.suggestions("acount", 3);
        assert_eq!(suggestions[0].term, "Account");
        // A wildly different query offers nothing rather than nonsense.
        assert!(g.suggestions("qqqqqqqqqqqqqqqq", 3).is_empty());
    }

    #[test]
    fn test_empty_query_matches_nothing() {
        let g = sample();
        assert!(g.lookup("").is_none());
        assert!(g.lookup("   ").is_none());
    }

    #[test]
    fn test_also_matches_are_ranked_deterministically() {
        // "Lock" is itself a term, so a lowercase query resolves at the
        // case-insensitive tier and needs no "see also".
        let g = Glossary::parse(
            "### **Lock**\nA short one.\n\n### **Lockbox**\nA longer one.\n\n### **Padlock**\nAlso longer.\n",
        );
        let hit = g.lookup("lock").unwrap();
        assert_eq!(hit.kind, MatchKind::CaseInsensitive);
        assert_eq!(hit.entry.term, "Lock");
        assert!(hit.also_matches.is_empty());

        // Without a "Lock" term, "lock" is a *prefix* of Lockbox but a
        // *suffix* of Padlock, so the prefix tier wins and Padlock is excluded.
        let g2 = Glossary::parse("### **Lockbox**\nOne.\n\n### **Padlock**\nTwo.\n");
        let hit = g2.lookup("lock").unwrap();
        assert_eq!(hit.kind, MatchKind::Prefix);
        assert_eq!(hit.entry.term, "Lockbox");
        assert!(hit.also_matches.is_empty());

        // A query that only appears inside terms reaches the substring tier.
        // The documented ranking is (fewest words, then SHORTEST, then
        // alphabetical), so `Beta Lock` (9 chars) wins outright; of the two
        // 10-char terms `Alpha Lock` then beats `Gamma Lock` alphabetically.
        let g3 = Glossary::parse(
            "### **Alpha Lock**\nOne.\n\n### **Beta Lock**\nTwo.\n\n### **Gamma Lock**\nThree.\n",
        );
        let hit = g3.lookup("lock").unwrap();
        assert_eq!(hit.kind, MatchKind::Substring);
        assert_eq!(hit.entry.term, "Beta Lock");
        let also: Vec<&str> = hit.also_matches.iter().map(|e| e.term.as_str()).collect();
        assert_eq!(also, vec!["Alpha Lock", "Gamma Lock"]);

        // With equal word count AND length, the tie-break is alphabetical.
        let g4 = Glossary::parse(
            "### **Zeta Lock**\nOne.\n\n### **Iota Lock**\nTwo.\n\n### **Beta Lock**\nThree.\n",
        );
        let hit = g4.lookup("lock").unwrap();
        assert_eq!(hit.entry.term, "Beta Lock");
        let also: Vec<&str> = hit.also_matches.iter().map(|e| e.term.as_str()).collect();
        assert_eq!(also, vec!["Iota Lock", "Zeta Lock"]);

        // Repeated lookups are stable.
        for _ in 0..5 {
            assert_eq!(g4.lookup("lock").unwrap().entry.term, "Beta Lock");
        }
    }

    #[test]
    fn test_heading_without_prose_is_skipped() {
        let g = Glossary::parse("## Terms\n\n### **Empty**\n\n### **Real**\nHas prose.\n");
        assert_eq!(g.terms(), vec!["Real"]);
    }

    #[test]
    fn test_non_bold_term_heading_is_supported() {
        let g = Glossary::parse("### Ledger\nThe state database.\n");
        assert_eq!(g.lookup("Ledger").unwrap().entry.term, "Ledger");
    }

    #[test]
    fn test_windows_line_endings_do_not_leak_into_definitions() {
        let g = Glossary::parse("### **Account**\r\nA public-key address.\r\n");
        assert_eq!(g.entries[0].definition, "A public-key address.");
    }

    #[test]
    fn test_fenced_code_heading_is_not_a_term() {
        let g = Glossary::parse(
            "### **Real**\nProse here.\n\n```\n### **NotATerm**\n```\n\n### **Second**\nMore prose.\n",
        );
        let terms = g.terms();
        assert!(terms.contains(&"Real"));
        assert!(terms.contains(&"Second"));
        assert!(!terms.contains(&"NotATerm"), "fenced heading leaked in");
    }

    #[test]
    fn test_anchor_slugs_are_predictable() {
        assert_eq!(anchor_for("Account"), "account");
        assert_eq!(anchor_for("Atomic Swap"), "atomic-swap");
        assert_eq!(
            anchor_for("Hashed Timelock Contract (HTLC)"),
            "hashed-timelock-contract-htlc"
        );
        assert_eq!(anchor_for("WASM (WebAssembly)"), "wasm-webassembly");
        assert_eq!(
            anchor_for("XDR (External Data Representation)"),
            "xdr-external-data-representation"
        );
        assert_eq!(anchor_for("Soroban RPC"), "soroban-rpc");
        // No trailing or doubled hyphens.
        assert_eq!(
            anchor_for("  Punctuation, everywhere!  "),
            "punctuation-everywhere"
        );
    }

    #[test]
    fn test_edit_distance_basics() {
        assert_eq!(edit_distance("abc", "abc"), Some(0));
        assert_eq!(edit_distance("abc", "abd"), Some(1));
        assert_eq!(edit_distance("account", "acount"), Some(1));
        assert_eq!(edit_distance("", "abc"), Some(3));
        assert_eq!(edit_distance("abc", ""), Some(3));
        // Beyond the threshold: no suggestion.
        assert_eq!(edit_distance("abcdefgh", "zzzzzzzz"), None);
    }

    #[test]
    fn test_subsequence_helper() {
        assert!(is_subsequence("abc", "aXbXc"));
        assert!(!is_subsequence("abc", "acb"));
        assert!(is_subsequence("", "anything"));
        assert!(is_subsequence("abc", "abc"));
    }

    /// The real `docs/GLOSSARY.md` must parse cleanly: every `### **Term**`
    /// becomes an entry, every entry gets a definition, and every term has an
    /// explicit anchor in the file so other docs can link to it.
    #[test]
    fn test_real_glossary_md_conforms() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join(GLOSSARY_RELATIVE);
        let glossary = Glossary::from_path(&path)
            .unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()));

        assert_eq!(
            glossary.terms(),
            vec![
                "Account",
                "Atomic Swap",
                "Footprint",
                "Hashed Timelock Contract (HTLC)",
                "Horizon",
                "Ledger",
                "Operation",
                "Preimage",
                "Soroban",
                "Soroban RPC",
                "Trustline",
                "WASM (WebAssembly)",
                "XDR (External Data Representation)",
            ],
            "the parser must find every real term, in document order"
        );

        // Bold markers were stripped, so no term contains an asterisk.
        for e in &glossary.entries {
            assert!(!e.term.contains('*'), "unstripped bold marker: {}", e.term);
            assert!(!e.term.is_empty());
            assert!(
                e.definition.len() > 20,
                "suspiciously short definition for {}",
                e.term
            );
            // The `---` rule must have closed the last definition.
            assert!(
                !e.definition.contains("Additional Resources"),
                "definition for {} ran past the section rule",
                e.term
            );
            // The explicit anchor marker must not leak into the prose.
            assert!(
                !e.definition.contains("<a id="),
                "anchor marker leaked into the definition for {}",
                e.term
            );
            // And the id written in the file must equal the documented slug,
            // so the Markdown and this module cannot drift apart.
            assert_eq!(
                e.anchor,
                anchor_for(&e.term),
                "anchor in GLOSSARY.md disagrees with the documented slug for {}",
                e.term
            );
        }

        // Every term is resolvable, and the anchors really are in the file.
        let markdown = std::fs::read_to_string(&path).unwrap();
        for e in &glossary.entries {
            let marker = format!(r#"<a id="{}"></a>"#, e.anchor);
            assert!(
                markdown.contains(&marker),
                "GLOSSARY.md is missing anchor {} for term {}",
                e.anchor,
                e.term
            );
            // And the anchor really does resolve the term.
            assert_eq!(glossary.lookup(&e.term).unwrap().entry.term, e.term);
        }
    }

    #[test]
    fn test_anchor_marker_is_parsed_not_treated_as_prose() {
        let g = Glossary::parse("### **Account**\n<a id=\"account\"></a>\nA public-key address.\n");
        assert_eq!(g.entries[0].definition, "A public-key address.");
        assert_eq!(g.entries[0].anchor, "account");
    }

    #[test]
    fn test_missing_anchor_marker_falls_back_to_computed_slug() {
        let g = Glossary::parse("### **Atomic Swap**\nA trade mechanism.\n");
        assert_eq!(g.entries[0].anchor, "atomic-swap");
    }

    #[test]
    fn test_anchor_recogniser_is_narrow() {
        assert_eq!(parse_anchor(r#"<a id="x"></a>"#), Some("x".to_string()));
        assert_eq!(parse_anchor(r#"<a id=""></a>"#), None);
        // Not a standalone marker: must be treated as prose, not dropped.
        assert_eq!(parse_anchor(r#"see <a id="x"></a> inline"#), None);
        assert_eq!(parse_anchor("plain text"), None);
        assert_eq!(parse_anchor(r#"<a name="x"></a>"#), None);
    }

    #[test]
    fn test_discover_finds_the_real_glossary() {
        let path = discover(None).expect("discovery should locate docs/GLOSSARY.md");
        assert!(path.is_file());
        assert!(path.ends_with("docs/GLOSSARY.md"));
        assert!(Glossary::from_path(&path).is_ok());
    }

    #[test]
    fn test_discover_rejects_a_missing_explicit_path() {
        let err = discover(Some(Path::new("/definitely/not/here/GLOSSARY.md"))).unwrap_err();
        assert!(err.to_string().contains("glossary not found"));
    }
}

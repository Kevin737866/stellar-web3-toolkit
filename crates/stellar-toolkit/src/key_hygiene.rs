//! Secret-material hygiene checks (issue #115).
//!
//! Key management starts with not leaking the keys. This module is the
//! automated half of `docs/KEY_MANAGEMENT.md`: it scans a working tree for
//! material that must never be committed — Stellar secret keys, recovery
//! phrases and real `.env` files — and reports every hit with the value
//! **masked**, so running the scanner cannot itself leak the secret into a CI
//! log.
//!
//! Three design points:
//!
//! * **Findings never contain the secret.** Only a masked form (`S…AB12`) and
//!   the location are reported. A scanner that echoes what it found turns a
//!   leaked key into a leaked key *in the build log*.
//! * **Checksum-verified mnemonics outrank pattern matches.** The toolkit
//!   already depends on `bip39`, so a candidate phrase whose checksum validates
//!   is an error; one that merely *looks* like a phrase is a warning. That keeps
//!   the check usable on documentation without drowning it in false positives.
//! * **Placeholders are not findings.** `<your-secret-key>`, `${STELLAR_SECRET_KEY}`
//!   and the like are what documentation and `.env.example` are made of.
//!
//! The scan is deliberately text-based and dependency-free beyond what the
//! crate already uses; it is a guard rail, not a replacement for a full secret
//! scanner with git-history support (see the audit guidance in
//! `docs/KEY_MANAGEMENT.md`).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Longest file the scanner will read, in bytes. Anything larger is reported as
/// skipped rather than read into memory.
pub const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Directories that never contain source worth scanning.
const SKIPPED_DIRS: [&str; 6] = ["target", ".git", "node_modules", ".cargo", "dist", ".venv"];

/// Files that are templates, not secrets.
const TEMPLATE_SUFFIXES: [&str; 4] = [".example", ".sample", ".template", ".dist"];

/// Inline escape hatch, for documentation that must show a real format.
pub const ALLOW_MARKER: &str = "key-hygiene: allow";

/// What kind of material was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    /// A Stellar secret key (`S…`, 56 base32 characters).
    StellarSecretKey,
    /// A recovery phrase whose BIP-39 checksum validates.
    RecoveryPhrase,
    /// Text that looks like a recovery phrase but fails the checksum.
    RecoveryPhraseCandidate,
    /// An assignment such as `STELLAR_SECRET_KEY = "…"` with a real value.
    SecretAssignment,
    /// A committed `.env` file.
    EnvFile,
}

impl SecretKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StellarSecretKey => "stellar_secret_key",
            Self::RecoveryPhrase => "recovery_phrase",
            Self::RecoveryPhraseCandidate => "recovery_phrase_candidate",
            Self::SecretAssignment => "secret_assignment",
            Self::EnvFile => "env_file",
        }
    }

    /// Whether a hit of this kind fails the scan.
    pub fn is_error(&self) -> bool {
        !matches!(self, Self::RecoveryPhraseCandidate)
    }
}

/// How sure the scanner is that the hit is real material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// The value was validated (BIP-39 checksum) or is unambiguous (strkey, env file).
    High,
    /// The value matches a pattern but was not validated.
    Medium,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
        }
    }
}

/// One piece of material that must not be committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub path: String,
    /// 1-based line number, or `None` for a whole-file finding.
    pub line: Option<usize>,
    pub kind: SecretKind,
    pub confidence: Confidence,
    /// Masked value: never the secret itself.
    pub masked: String,
    pub message: String,
}

impl Finding {
    pub fn is_error(&self) -> bool {
        self.kind.is_error()
    }
}

/// Result of scanning a tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    /// Directories the scan started from.
    pub roots: Vec<String>,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub findings: Vec<Finding>,
}

impl ScanReport {
    pub fn errors(&self) -> usize {
        self.findings.iter().filter(|f| f.is_error()).count()
    }

    pub fn warnings(&self) -> usize {
        self.findings.len() - self.errors()
    }

    /// True when nothing that must not be committed was found.
    pub fn passed(&self) -> bool {
        self.errors() == 0
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for finding in &self.findings {
            let location = match finding.line {
                Some(line) => format!("{}:{line}", finding.path),
                None => finding.path.clone(),
            };
            out.push_str(&format!(
                "{:<7} {:<28} {}\n        {}\n",
                finding.confidence.as_str(),
                finding.kind.as_str(),
                location,
                finding.message
            ));
        }
        out.push_str(&format!(
            "scanned {} file(s), skipped {} — {} error(s), {} warning(s)\n",
            self.files_scanned,
            self.files_skipped,
            self.errors(),
            self.warnings()
        ));
        if self.findings.is_empty() {
            out.push_str("no secret material found\n");
        }
        out
    }
}

/// Mask a value so it can appear in a report: prefix and last four characters
/// only. Short values are masked completely.
pub fn mask_secret(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "…".to_string();
    }
    let head: String = chars.iter().take(2).collect();
    let tail: String = chars.iter().skip(chars.len() - 4).collect();
    format!("{head}…{tail}")
}

/// True when `value` is an obvious placeholder rather than a real secret.
pub fn is_placeholder(value: &str) -> bool {
    let trimmed = value.trim().trim_matches(|c| c == '"' || c == '\'').trim();
    if trimmed.is_empty() {
        return true;
    }
    let lowered = trimmed.to_lowercase();
    if trimmed.starts_with('<') && trimmed.ends_with('>') {
        return true;
    }
    if trimmed.starts_with("${") && trimmed.ends_with('}') {
        return true;
    }
    if trimmed.starts_with("$") {
        return true;
    }
    if trimmed.starts_with("{{") && trimmed.ends_with("}}") {
        return true;
    }
    // Repeated filler characters (`xxxxxxxx`, `********`, `........`) and the
    // conventional "SXXX..." shapes used in docs.
    let distinct: std::collections::BTreeSet<char> = trimmed.chars().collect();
    if distinct.len() <= 2 && trimmed.len() >= 4 {
        return true;
    }
    if lowered.contains("your_") || lowered.contains("your-") {
        return true;
    }
    const PLACEHOLDERS: [&str; 12] = [
        "changeme",
        "change_me",
        "placeholder",
        "redacted",
        "todo",
        "example",
        "dummy",
        "test_key",
        "not_a_real",
        "secret_here",
        "insert_",
        "replace_me",
    ];
    PLACEHOLDERS.iter().any(|p| lowered.contains(p))
}

/// True when `token` is shaped like a Stellar secret key: `S` followed by 55
/// base32 characters.
pub fn looks_like_secret_key(token: &str) -> bool {
    let mut chars = token.chars();
    if chars.next() != Some('S') {
        return false;
    }
    let rest: Vec<char> = chars.collect();
    rest.len() == 55
        && rest
            .iter()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(c))
}

/// Field names whose assignment must not carry a real value.
const SECRET_FIELD_NAMES: [&str; 6] = [
    "stellar_secret_key",
    "secret_key",
    "private_key",
    "seed_phrase",
    "mnemonic",
    "signing_key",
];

/// Extract a candidate value from an `NAME = value` / `NAME: value` line.
fn assignment_value(line: &str) -> Option<(String, String)> {
    let (name, rest) = line.split_once('=').or_else(|| line.split_once(':'))?;
    let name = name
        .trim()
        .trim_start_matches('#')
        .trim()
        .trim_start_matches("export ")
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .to_lowercase();
    if name.is_empty() || name.contains(' ') {
        return None;
    }
    let raw = rest.trim().trim_start_matches('=').trim();
    literal_value(raw).map(|value| (name, value))
}

/// The literal on the right-hand side of an assignment, if there is one.
///
/// Only real literals count. `mnemonic: phrase,` in Rust source assigns a
/// *variable*, and reporting it would make the scanner unusable on code that
/// merely passes key material around — which is most of the code that handles
/// keys. A quoted string is always taken; a bare token is taken only when it is
/// a single opaque value rather than an expression.
fn literal_value(raw: &str) -> Option<String> {
    if raw.len() >= 2 {
        let quoted = (raw.starts_with('"') && raw.ends_with('"'))
            || (raw.starts_with('\'') && raw.ends_with('\''));
        if quoted {
            return Some(raw[1..raw.len() - 1].to_string());
        }
    }
    if raw.is_empty() || raw.contains(char::is_whitespace) {
        return None;
    }
    if raw.ends_with([',', ';', ')', ']', '}', '(', '{']) {
        return None;
    }
    if raw.starts_with(['&', '*', '!']) {
        return None;
    }
    Some(raw.to_string())
}

/// Scan one file's text. `path` is only used for the report.
pub fn scan_text(path: &Path, text: &str) -> Vec<Finding> {
    let path_str = path.display().to_string();
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut findings = Vec::new();

    // A committed `.env` is a finding on its own: it is where real keys live.
    if file_name == ".env"
        || (file_name.starts_with(".env.")
            && !TEMPLATE_SUFFIXES
                .iter()
                .any(|suffix| file_name.ends_with(suffix)))
    {
        findings.push(Finding {
            path: path_str.clone(),
            line: None,
            kind: SecretKind::EnvFile,
            confidence: Confidence::High,
            masked: file_name.clone(),
            message: "environment files hold real keys and must not be committed; \
                      keep a committed `.env.example` instead"
                .to_string(),
        });
    }

    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        if line.contains(ALLOW_MARKER) {
            continue;
        }

        // 1. A literal Stellar secret key, wherever it appears.
        for token in line.split(|c: char| {
            !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '+' || c == '/')
        }) {
            if looks_like_secret_key(token) {
                findings.push(Finding {
                    path: path_str.clone(),
                    line: Some(line_number),
                    kind: SecretKind::StellarSecretKey,
                    confidence: Confidence::High,
                    masked: mask_secret(token),
                    message: "Stellar secret key in source; load it from the environment instead"
                        .to_string(),
                });
            }
        }

        // 2. An assignment to a secret-looking field with a real value.
        if let Some((name, value)) = assignment_value(line) {
            if SECRET_FIELD_NAMES.contains(&name.as_str()) && !is_placeholder(&value) {
                findings.push(Finding {
                    path: path_str.clone(),
                    line: Some(line_number),
                    kind: SecretKind::SecretAssignment,
                    confidence: Confidence::High,
                    masked: mask_secret(&value),
                    message: format!("`{name}` is assigned a literal value"),
                });
            }
        }

        // 3. A recovery phrase: a quoted run of 12+ words, validated against the
        //    BIP-39 checksum when possible.
        for candidate in quoted_word_runs(line) {
            let word_count = candidate.split_whitespace().count();
            if ![12usize, 15, 18, 21, 24].contains(&word_count) || is_placeholder(&candidate) {
                continue;
            }
            let valid =
                bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &candidate).is_ok();
            findings.push(Finding {
                path: path_str.clone(),
                line: Some(line_number),
                kind: if valid {
                    SecretKind::RecoveryPhrase
                } else {
                    SecretKind::RecoveryPhraseCandidate
                },
                confidence: if valid {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                masked: mask_secret(&candidate),
                message: if valid {
                    format!("valid {word_count}-word recovery phrase; anyone holding it controls the account")
                } else {
                    format!("{word_count}-word phrase-shaped string (checksum invalid)")
                },
            });
        }
    }

    findings
}

/// Quoted strings that consist of 12+ lowercase words.
fn quoted_word_runs(line: &str) -> Vec<String> {
    let mut runs = Vec::new();
    for quote in ['"', '\''] {
        let mut parts = line.split(quote);
        // Odd indices are inside quotes.
        parts.next();
        for (index, part) in parts.enumerate() {
            if index % 2 == 1 {
                continue;
            }
            if is_word_run(part) {
                runs.push(part.trim().to_string());
            }
        }
    }
    runs
}

fn is_word_run(text: &str) -> bool {
    let words: Vec<&str> = text.split_whitespace().collect();
    words.len() >= 12
        && words.iter().all(|w| {
            let len = w.chars().count();
            (3..=8).contains(&len) && w.chars().all(|c| c.is_ascii_lowercase())
        })
}

/// Scan `roots` recursively.
pub fn scan_paths(roots: &[PathBuf]) -> ScanReport {
    let mut report = ScanReport {
        roots: roots.iter().map(|r| r.display().to_string()).collect(),
        files_scanned: 0,
        files_skipped: 0,
        findings: Vec::new(),
    };

    for root in roots {
        if root.is_file() {
            scan_file(root, &mut report);
            continue;
        }
        walk(root, &mut report);
    }
    report
        .findings
        .sort_by(|a, b| (a.path.as_str(), a.line).cmp(&(b.path.as_str(), b.line)));
    report
}

fn walk(dir: &Path, report: &mut ScanReport) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if path.is_dir() {
            // Only known build/VCS directories are skipped. Dot-directories
            // are *not* skipped wholesale: `.github/` is where a deploy
            // secret most often gets committed.
            if SKIPPED_DIRS.contains(&name.as_str()) {
                report.files_skipped += 1;
                continue;
            }
            walk(&path, report);
        } else if path.is_file() {
            scan_file(&path, report);
        }
    }
}

fn scan_file(path: &Path, report: &mut ScanReport) {
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() > MAX_FILE_BYTES => {
            report.files_skipped += 1;
            return;
        }
        Ok(_) => {}
        Err(_) => {
            report.files_skipped += 1;
            return;
        }
    }
    // Binary or non-UTF-8 files are skipped: secrets in a compiled artifact are
    // already covered by "the key was in the repo" and would produce noise.
    let Ok(text) = std::fs::read_to_string(path) else {
        report.files_skipped += 1;
        return;
    };
    report.files_scanned += 1;
    report.findings.extend(scan_text(path, &text));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A strkey-shaped secret. Assembled rather than written out so that this
    /// file — which is scanned by `the_workspace_itself_is_clean` — does not
    /// contain a secret-looking literal.
    fn secret_fixture() -> String {
        format!("S{}", "A".repeat(55))
    }

    /// The canonical BIP-39 test vector: 23 x `abandon` plus `art`. Assembled
    /// for the same reason.
    fn vector_phrase() -> String {
        let mut words = vec!["abandon"; 23];
        words.push("art");
        words.join(" ")
    }

    /// Twelve lowercase words with no valid BIP-39 checksum.
    fn phrase_shaped_candidate() -> String {
        [
            "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
            "juliet", "kilo", "lima",
        ]
        .join(" ")
    }

    #[test]
    fn detects_a_stellar_secret_key() {
        let key = secret_fixture();
        let findings = scan_text(Path::new("src/config.rs"), &format!("let key = \"{key}\";"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, SecretKind::StellarSecretKey);
        assert!(findings[0].is_error());
        // The report must not contain the secret.
        assert!(!findings[0].masked.contains(&key));
    }

    #[test]
    fn a_public_account_id_is_not_a_secret() {
        let account = "GDUMMYACCOUNTFORTESTONLYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let findings = scan_text(Path::new("README.md"), account);
        assert!(findings.is_empty(), "public keys are not secrets");
    }

    #[test]
    fn detects_a_checksum_valid_recovery_phrase() {
        let phrase = vector_phrase();
        let findings = scan_text(
            Path::new("docs/example.md"),
            &format!("phrase: \"{phrase}\""),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, SecretKind::RecoveryPhrase);
        assert_eq!(findings[0].confidence, Confidence::High);
        assert!(findings[0].is_error());
    }

    #[test]
    fn a_phrase_shaped_string_without_a_valid_checksum_is_a_warning() {
        let phrase = phrase_shaped_candidate();
        let findings = scan_text(
            Path::new("docs/example.md"),
            &format!("phrase: \"{phrase}\""),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, SecretKind::RecoveryPhraseCandidate);
        assert!(!findings[0].is_error());
    }

    #[test]
    fn detects_secret_assignments_but_not_placeholders() {
        let real = scan_text(
            Path::new(".env.example"),
            &format!("STELLAR_SECRET_KEY=\"{}\"", secret_fixture()),
        );
        assert!(real.iter().any(|f| f.kind == SecretKind::StellarSecretKey));

        let placeholder = scan_text(
            Path::new(".env.example"),
            "STELLAR_SECRET_KEY=<your-secret-key>\nSECRET_KEY=${STELLAR_SECRET_KEY}\nMNEMONIC=changeme",
        );
        assert!(
            placeholder.is_empty(),
            "placeholders must not be reported: {placeholder:?}"
        );
    }

    #[test]
    fn detects_an_assignment_with_an_opaque_value() {
        let findings = scan_text(Path::new("config.toml"), "private_key = \"hunter2hunter2\"");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, SecretKind::SecretAssignment);
        assert!(!findings[0].masked.contains("hunter2"));
    }

    #[test]
    fn flags_a_committed_env_file_but_not_templates() {
        let committed = scan_text(Path::new(".env"), "STELLAR_NETWORK=testnet");
        assert!(committed.iter().any(|f| f.kind == SecretKind::EnvFile));

        for template in [".env.example", ".env.sample", ".env.template"] {
            let findings = scan_text(Path::new(template), "STELLAR_NETWORK=testnet");
            assert!(
                findings.is_empty(),
                "{template} is a template, not a secret: {findings:?}"
            );
        }
    }

    #[test]
    fn an_allow_marker_suppresses_the_line() {
        let line = format!("let key = \"{}\"; // {ALLOW_MARKER}", secret_fixture());
        assert!(scan_text(Path::new("docs/KEY_MANAGEMENT.md"), &line).is_empty());
    }

    #[test]
    fn mask_keeps_only_the_ends() {
        assert_eq!(mask_secret("SDUMMYKEYFORTESTONLYAAAA"), "SD…AAAA");
        assert_eq!(mask_secret("short"), "…");
    }

    #[test]
    fn scanning_a_tree_skips_build_output() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("target/debug")).expect("mkdir");
        let key = secret_fixture();
        std::fs::write(dir.path().join("target/debug/leak.txt"), &key).expect("write");
        std::fs::write(
            dir.path().join("src.rs"),
            format!("const K: &str = \"{key}\";"),
        )
        .expect("write");

        let report = scan_paths(&[dir.path().to_path_buf()]);
        assert_eq!(report.errors(), 1, "only the tracked file is a finding");
        assert!(!report.passed());
        assert!(report.files_skipped >= 1);
    }

    #[test]
    fn the_workspace_itself_is_clean() {
        // The repository is scanned with its own check, so a leaked key in this
        // very commit fails the test suite.
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..");
        let report = scan_paths(&[root]);
        assert!(
            report.passed(),
            "secret material found in the repository:\n{}",
            report.render()
        );
    }
}

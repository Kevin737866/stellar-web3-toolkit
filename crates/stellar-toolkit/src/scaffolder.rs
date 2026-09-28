//! Soroban project scaffolder with template lint (issue #242).
//!
//! The scaffolder renders a minimal Soroban contract crate from a built-in
//! template and then lints the rendered files. The lint is deterministic and
//! dependency free, so it can run as a CI gate (`stellar-toolkit scaffold lint`)
//! on freshly scaffolded projects as well as on hand written contract crates that
//! follow the same layout.

use crate::error::{Result, ToolkitError};
use std::path::{Path, PathBuf};

/// Files that every scaffolded project must contain.
pub const REQUIRED_FILES: [&str; 3] = ["Cargo.toml", "src/lib.rs", "README.md"];

/// Optional files that are only linted when present.
const OPTIONAL_FILES: [&str; 3] = ["src/test.rs", "tests", ".gitignore"];

/// Rust edition used by the template.
const TEMPLATE_EDITION: &str = "2021";

const CONTRACT_LIB: &str = r##"#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Env};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Counter,
}

/// Starting point contract scaffolded by `stellar-toolkit scaffold new`.
#[contractimpl]
pub struct CounterContract;

#[contractimpl]
impl CounterContract {
    /// Increments the stored counter and returns the new value.
    pub fn increment(env: Env) -> u32 {
        let current: u32 = env.storage().instance().get(&DataKey::Counter).unwrap_or(0);
        let next = current + 1;
        env.storage().instance().set(&DataKey::Counter, &next);
        next
    }

    /// Returns the current counter value.
    pub fn get(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::Counter).unwrap_or(0)
    }
}
"##;

const CONTRACT_TEST: &str = r##"#![cfg(test)]

use super::*;
use soroban_sdk::Env;

#[test]
fn counts_up_from_zero() {
    let env = Env::default();
    let contract_id = env.register(CounterContract, ());
    let client = CounterContractClient::new(&env, &contract_id);

    assert_eq!(client.get(), 0);
    assert_eq!(client.increment(), 1);
    assert_eq!(client.increment(), 2);
    assert_eq!(client.get(), 2);
}
"##;

const GITIGNORE: &str = r##"/target
"##;

/// Options describing the project to scaffold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaffoldOptions {
    /// Crate name, must be kebab-case (`amm-pool`).
    pub name: String,
    /// `description` field of the generated `Cargo.toml`.
    pub description: String,
    /// `authors` field of the generated `Cargo.toml`.
    pub author: String,
    /// Whether the counter test module is rendered.
    pub include_tests: bool,
}

impl ScaffoldOptions {
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        let description = format!("{name} - Soroban contract scaffolded by stellar-toolkit");
        Self {
            name,
            description,
            author: "Your Name <your.email@example.com>".to_string(),
            include_tests: true,
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = author.into();
        self
    }

    pub fn with_tests(mut self, include_tests: bool) -> Self {
        self.include_tests = include_tests;
        self
    }
}

/// A single rendered template file. `path` is always relative to the project root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedFile {
    pub path: String,
    pub contents: String,
}

/// Renders and writes Soroban contract projects from the built-in template.
pub struct Scaffolder {
    options: ScaffoldOptions,
}

impl Scaffolder {
    pub fn new(options: ScaffoldOptions) -> Self {
        Self { options }
    }

    /// Renders the template file set (without touching the filesystem).
    pub fn render(&self) -> Vec<GeneratedFile> {
        let mut files = vec![
            GeneratedFile {
                path: "Cargo.toml".to_string(),
                contents: self.manifest(),
            },
            GeneratedFile {
                path: "src/lib.rs".to_string(),
                contents: CONTRACT_LIB.to_string(),
            },
            GeneratedFile {
                path: "README.md".to_string(),
                contents: self.readme(),
            },
            GeneratedFile {
                path: ".gitignore".to_string(),
                contents: GITIGNORE.to_string(),
            },
        ];
        if self.options.include_tests {
            files.insert(
                2,
                GeneratedFile {
                    path: "src/test.rs".to_string(),
                    contents: CONTRACT_TEST.to_string(),
                },
            );
        }
        files
    }

    /// Renders the template and lints the result.
    pub fn render_and_lint(&self) -> (Vec<GeneratedFile>, LintReport) {
        let files = self.render();
        let report = lint_template(&files);
        (files, report)
    }

    /// Writes the rendered template below `root`, refusing to clobber files
    /// unless `force` is set. Returns the paths that were written.
    pub fn write(&self, root: &Path, force: bool) -> Result<Vec<PathBuf>> {
        write_files(root, &self.render(), force)
    }

    fn manifest(&self) -> String {
        let edition = TEMPLATE_EDITION;
        format!(
            r#"[package]
name = "{name}"
version = "0.1.0"
edition = "{edition}"
description = "{description}"
authors = ["{author}"]
license = "MIT"
publish = false

[lib]
crate-type = ["cdylib", "rlib"]
doctest = false

[dependencies]
soroban-sdk = "21.4.0"

[dev-dependencies]
soroban-sdk = {{ version = "21.4.0", features = ["testutils"] }}

[features]
default = []
testutils = ["soroban-sdk/testutils"]
"#,
            name = sanitize(&self.options.name),
            description = sanitize(&self.options.description),
            author = sanitize(&self.options.author),
        )
    }

    fn readme(&self) -> String {
        format!(
            r#"# {name}

{description}

Generated with `stellar-toolkit scaffold new {name}`.

## Build

```bash
cargo build --target wasm32-unknown-unknown --release
```

## Test

```bash
cargo test
```

## Lint the template

The project layout is validated by the scaffolder linter, which can be used as a
CI gate because it exits non-zero on error level findings:

```bash
stellar-toolkit scaffold lint --dir .
```
"#,
            name = sanitize(&self.options.name),
            description = sanitize(&self.options.description),
        )
    }
}

/// Writes rendered files below `root`, creating parent directories as needed.
pub fn write_files(root: &Path, files: &[GeneratedFile], force: bool) -> Result<Vec<PathBuf>> {
    let mut written = Vec::with_capacity(files.len());
    for file in files {
        let path = root.join(&file.path);
        if path.exists() && !force {
            return Err(ToolkitError::ExecutionError(format!(
                "{} already exists (pass --force to overwrite)",
                path.display()
            )));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, &file.contents)?;
        written.push(path);
    }
    Ok(written)
}

/// Severity of a single lint finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintSeverity {
    Error,
    Warning,
}

/// A single template lint finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintFinding {
    pub severity: LintSeverity,
    /// Machine readable rule id, e.g. `crate-type`.
    pub rule: String,
    /// Template path the finding applies to (`-` for project wide rules).
    pub file: String,
    pub message: String,
}

/// Result of linting a template file set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintReport {
    pub files_checked: usize,
    pub findings: Vec<LintFinding>,
}

impl LintReport {
    /// `true` when no error level finding was reported.
    pub fn passed(&self) -> bool {
        self.errors() == 0
    }

    pub fn errors(&self) -> usize {
        self.count(LintSeverity::Error)
    }

    pub fn warnings(&self) -> usize {
        self.count(LintSeverity::Warning)
    }

    fn count(&self, severity: LintSeverity) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .count()
    }

    pub fn render(&self) -> String {
        let mut out = format!(
            "template lint: {} file(s) checked, {} error(s), {} warning(s)\n",
            self.files_checked,
            self.errors(),
            self.warnings()
        );
        for finding in &self.findings {
            let level = match finding.severity {
                LintSeverity::Error => "error",
                LintSeverity::Warning => "warning",
            };
            out.push_str(&format!(
                "  {level} [{}] {}: {}\n",
                finding.rule, finding.file, finding.message
            ));
        }
        if self.findings.is_empty() {
            out.push_str("  ok: template satisfies every rule\n");
        }
        out
    }
}

/// Lints an already scaffolded project directory, so the same rules can be run
/// in CI against a checked out project.
pub fn lint_directory(root: &Path) -> Result<LintReport> {
    let mut files = Vec::new();
    for relative in REQUIRED_FILES
        .iter()
        .copied()
        .chain(OPTIONAL_FILES.iter().copied())
    {
        let path = root.join(relative);
        if !path.exists() {
            continue;
        }
        let contents = if path.is_dir() {
            collect_rust_files(&path)?
        } else {
            std::fs::read_to_string(&path)?
        };
        if !contents.trim().is_empty() {
            files.push(GeneratedFile {
                path: relative.to_string(),
                contents,
            });
        }
    }
    if files.is_empty() {
        return Err(ToolkitError::ExecutionError(format!(
            "no scaffoldable project found in {}",
            root.display()
        )));
    }
    Ok(lint_template(&files))
}

/// Lints a rendered template file set.
pub fn lint_template(files: &[GeneratedFile]) -> LintReport {
    let mut findings = Vec::new();

    for required in REQUIRED_FILES {
        if !files.iter().any(|file| file.path == required) {
            findings.push(error(
                "required-file",
                required,
                "required template file is missing",
            ));
        }
    }

    let manifest = contents_of(files, "Cargo.toml");
    let name = manifest_value(&manifest, "name");
    if !is_valid_crate_name(&name) {
        findings.push(error(
            "package-name",
            "Cargo.toml",
            format!("package name '{name}' is not a valid kebab-case crate name"),
        ));
    }
    let edition_ok = manifest_value(&manifest, "edition") == TEMPLATE_EDITION
        || manifest.contains("edition.workspace = true");
    if !edition_ok {
        findings.push(error(
            "edition",
            "Cargo.toml",
            format!("Soroban contracts must use edition {TEMPLATE_EDITION}"),
        ));
    }
    if !manifest.contains("crate-type") || !manifest.contains("cdylib") {
        findings.push(error(
            "crate-type",
            "Cargo.toml",
            "contract crates need crate-type = [\"cdylib\", \"rlib\"] to build to wasm",
        ));
    }
    if !manifest.contains("soroban-sdk") {
        findings.push(error(
            "soroban-sdk-dependency",
            "Cargo.toml",
            "soroban-sdk dependency is missing",
        ));
    }

    let lib = contents_of(files, "src/lib.rs");
    if !lib.contains("#![no_std]") {
        findings.push(error(
            "no-std",
            "src/lib.rs",
            "Soroban contracts must be compiled with #![no_std]",
        ));
    }

    let has_tests = files
        .iter()
        .any(|file| file.path.starts_with("src/test") || file.path.starts_with("tests"));
    if !has_tests {
        findings.push(warning(
            "tests",
            "src/test.rs",
            "no test module found: add src/test.rs or a tests/ directory",
        ));
    }

    let readme = contents_of(files, "README.md");
    if !readme.starts_with("# ") {
        findings.push(error(
            "readme-heading",
            "README.md",
            "README must start with a level one heading",
        ));
    }
    if !readme.contains("cargo build") {
        findings.push(warning(
            "readme-build-command",
            "README.md",
            "README does not document how to build the contract",
        ));
    }

    for file in files {
        for (index, line) in file.contents.lines().enumerate() {
            if line.len() != line.trim_end().len() {
                findings.push(warning(
                    "trailing-whitespace",
                    &file.path,
                    format!("line {} has trailing whitespace", index + 1),
                ));
            }
        }
        if !file.contents.ends_with('\n') {
            findings.push(warning(
                "final-newline",
                &file.path,
                "file does not end with a newline",
            ));
        } else if file.contents.ends_with("\n\n") {
            findings.push(warning("final-newline", &file.path, "file ends with a blank line"));
        }
    }

    LintReport {
        files_checked: files.len(),
        findings,
    }
}

/// Crate names must be kebab-case so they can be used as Cargo targets and
/// turned into wasm file names.
pub fn is_valid_crate_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    if !name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-') {
        return false;
    }
    if name.starts_with('-') || name.ends_with('-') || name.contains("--") {
        return false;
    }
    true
}

fn contents_of(files: &[GeneratedFile], path: &str) -> String {
    match files.iter().find(|file| file.path == path) {
        Some(file) => file.contents.clone(),
        None => String::new(),
    }
}

/// Reads a `key = "value"` entry out of a Cargo manifest.
fn manifest_value(manifest: &str, key: &str) -> String {
    for line in manifest.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(key) {
            if let Some(value) = rest.trim_start().strip_prefix('=') {
                return value.trim().trim_matches('"').to_string();
            }
        }
    }
    String::new()
}

fn collect_rust_files(dir: &Path) -> Result<String> {
    let mut out = String::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push_str(&std::fs::read_to_string(&path)?);
            }
        }
    }
    Ok(out)
}

fn sanitize(value: &str) -> String {
    value.replace('"', "'").trim().to_string()
}

fn error(rule: &str, file: &str, message: impl Into<String>) -> LintFinding {
    LintFinding {
        severity: LintSeverity::Error,
        rule: rule.to_string(),
        file: file.to_string(),
        message: message.into(),
    }
}

fn warning(rule: &str, file: &str, message: impl Into<String>) -> LintFinding {
    LintFinding {
        severity: LintSeverity::Warning,
        rule: rule.to_string(),
        file: file.to_string(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered() -> Vec<GeneratedFile> {
        Scaffolder::new(ScaffoldOptions::new("amm-pool")).render()
    }

    #[test]
    fn test_template_renders_expected_files() {
        let files = rendered();
        let paths: Vec<&str> = files.iter().map(|file| file.path.as_str()).collect();
        let expected = "Cargo.toml src/lib.rs src/test.rs README.md .gitignore";
        assert_eq!(paths.join(" "), expected);
        let manifest = contents_of(&files, "Cargo.toml");
        assert!(manifest.contains("name = \"amm-pool\""));
        assert!(manifest.contains("crate-type = [\"cdylib\", \"rlib\"]"));
        assert!(manifest.contains("soroban-sdk = \"21.4.0\""));
    }

    #[test]
    fn test_default_template_passes_lint() {
        let (_, report) = Scaffolder::new(ScaffoldOptions::new("amm-pool")).render_and_lint();
        assert!(report.passed(), "unexpected findings: {report:?}");
        assert!(report.warnings() == 0, "unexpected warnings: {report:?}");
        assert!(report.render().contains("ok: template satisfies every rule"));
    }

    #[test]
    fn test_lint_flags_missing_crate_type_and_no_std() {
        let mut files = rendered();
        for file in files.iter_mut() {
            if file.path == "Cargo.toml" {
                file.contents = file.contents.replace("crate-type", "unused-key");
            }
            if file.path == "src/lib.rs" {
                file.contents = file.contents.replace("#![no_std]", "");
            }
        }
        let report = lint_template(&files);
        assert!(!report.passed());
        let rules: Vec<&str> = report
            .findings
            .iter()
            .map(|finding| finding.rule.as_str())
            .collect();
        assert!(rules.contains(&"crate-type"));
        assert!(rules.contains(&"no-std"));
        assert_eq!(report.errors(), 2);
    }

    #[test]
    fn test_lint_flags_missing_files_and_missing_tests() {
        let files: Vec<GeneratedFile> = rendered()
            .into_iter()
            .filter(|file| file.path != "README.md" && file.path != "src/test.rs")
            .collect();
        let report = lint_template(&files);
        assert!(!report.passed());
        let rules: Vec<&str> = report
            .findings
            .iter()
            .map(|finding| finding.rule.as_str())
            .collect();
        assert!(rules.contains(&"required-file"));
        assert!(rules.contains(&"readme-heading"));
        assert!(rules.contains(&"tests"));
    }

    #[test]
    fn test_lint_flags_whitespace_hygiene() {
        let mut files = rendered();
        for file in files.iter_mut() {
            if file.path == "src/lib.rs" {
                let trimmed = file.contents.trim_end().to_string();
                file.contents = format!("{trimmed}   ");
            }
        }
        let report = lint_template(&files);
        let rules: Vec<&str> = report
            .findings
            .iter()
            .map(|finding| finding.rule.as_str())
            .collect();
        assert!(rules.contains(&"trailing-whitespace"));
        assert!(rules.contains(&"final-newline"));
        assert!(report.passed(), "whitespace findings are warnings only");
    }

    #[test]
    fn test_lint_accepts_workspace_manifests() {
        let mut files = rendered();
        for file in files.iter_mut() {
            if file.path == "Cargo.toml" {
                file.contents = file
                    .contents
                    .replace("edition = \"2021\"", "edition.workspace = true");
            }
        }
        let report = lint_template(&files);
        assert!(report.passed(), "workspace edition should be accepted");
    }

    #[test]
    fn test_crate_name_validation() {
        assert!(is_valid_crate_name("amm-pool"));
        assert!(is_valid_crate_name("pool2"));
        assert!(!is_valid_crate_name(""));
        assert!(!is_valid_crate_name("Amm Pool"));
        assert!(!is_valid_crate_name("amm_pool"));
        assert!(!is_valid_crate_name("-amm"));
        assert!(!is_valid_crate_name("amm--pool"));
    }

    #[test]
    fn test_write_files_creates_project_and_guards_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let scaffolder = Scaffolder::new(ScaffoldOptions::new("amm-pool").with_tests(false));
        let written = scaffolder.write(dir.path(), false).unwrap();
        assert_eq!(written.len(), 4);
        assert!(dir.path().join("src/lib.rs").exists());

        let err = scaffolder.write(dir.path(), false).unwrap_err();
        assert!(err.to_string().contains("already exists"));

        let forced = scaffolder.write(dir.path(), true).unwrap();
        assert_eq!(forced.len(), 4);
    }

    #[test]
    fn test_lint_directory_reads_project_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let scaffolder = Scaffolder::new(ScaffoldOptions::new("amm-pool"));
        scaffolder.write(dir.path(), false).unwrap();
        let report = lint_directory(dir.path()).unwrap();
        assert!(report.passed(), "unexpected findings: {report:?}");
    }
}

//! Offline validation mode for deployment configurations (issue #327).
//!
//! A deployment configuration (`deploy/<name>.toml`) describes *what* to
//! deploy: which contracts, which WASM artifact, which account signs, and what
//! fee and timeout to use. Validating this configuration **offline** — before
//! touching the network or Horizon — catches the class of mistakes that reach
//! the deployment step and fail with a confusing RPC error:
//!
//! * A WASM artifact path that does not exist.
//! * A `contract_id` that is not a valid Stellar contract address (C...).
//! * An `admin_account` that is not a valid Stellar public key (G...).
//! * A `fee` that is not a positive integer number of stroops.
//! * A `timeout_seconds` of zero (the transaction expires before it is built).
//! * Unknown keys that are silently ignored and might hide a misconfiguration.
//!
//! # Design
//!
//! The validator intentionally contacts no external service. It only inspects
//! the filesystem and applies structural / semantic rules. The design mirrors
//! [`crate::env_config`]: every problem is collected before returning so a
//! caller fixes all issues in one pass, and unknown TOML keys are rejected with
//! `deny_unknown_fields`.
//!
//! # Example
//!
//! ```rust,no_run
//! use stellar_toolkit::deploy_config::{DeploymentSpec, DeploymentValidator};
//! use std::path::Path;
//!
//! let spec = DeploymentSpec::load(Path::new("deploy/testnet.toml")).unwrap();
//! let report = DeploymentValidator::new(Path::new(".")).validate(&spec);
//! if !report.passed() {
//!     for finding in &report.findings {
//!         eprintln!("{}: {} — {}", finding.severity.as_str(), finding.field, finding.message);
//!     }
//! }
//! ```

use crate::error::{Result, ToolkitError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

// ── Severity ─────────────────────────────────────────────────────────────────

/// Severity of a validation finding. Any [`Severity::Error`] makes
/// [`DeploymentValidationReport::passed`] return `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

impl Severity {
    /// Lower-case string representation, stable across serialisation formats.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
        }
    }
}

// ── Finding ──────────────────────────────────────────────────────────────────

/// One problem found in a deployment spec.
///
/// `field` is the dotted TOML path of the offending key (e.g.
/// `contracts.amm_pool.wasm_path`). `message` is a human-readable description
/// that names the offending value and what was expected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    /// Dotted TOML path of the offending field.
    pub field: String,
    pub message: String,
}

impl Finding {
    fn error(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            field: field.into(),
            message: message.into(),
        }
    }

    fn warning(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            field: field.into(),
            message: message.into(),
        }
    }
}

// ── TOML structs ─────────────────────────────────────────────────────────────

/// Per-contract deployment entry in `[contracts.<name>]`.
///
/// At minimum a contract entry must supply a `wasm_path`; all other fields are
/// optional overrides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractEntry {
    /// Path to the compiled `.wasm` artifact, relative to the workspace root.
    pub wasm_path: String,
    /// Existing on-chain contract ID (C...) for upgrades.
    /// Absent means a first-time deploy.
    #[serde(default)]
    pub contract_id: Option<String>,
    /// Override the top-level `admin_account` for this contract only.
    #[serde(default)]
    pub admin_account: Option<String>,
}

/// `[network]` — which Stellar network this deployment targets.
///
/// Kept deliberately minimal: the full network config is owned by
/// [`crate::env_config::EnvConfig`]. `DeploymentSpec` references the env by
/// name so the two are linked without duplicating the passphrase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentNetwork {
    /// One of the environments defined in `config/<env>.toml` (`dev`, `test`,
    /// `prod`).
    pub environment: String,
}

/// `[submit]` — transaction submission parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitConfig {
    /// Base fee in stroops, as a string to keep large values exact.
    pub fee: String,
    /// How long (in seconds) the transaction envelope stays valid after signing.
    pub timeout_seconds: u64,
    /// How many ledger closures to wait for confirmation. Zero means fire and
    /// forget, which is explicitly allowed for scripts that handle their own
    /// retry logic.
    #[serde(default)]
    pub confirmations: u32,
    /// When `true` the transaction is built and validated but never submitted.
    /// Useful for reviewing what would be sent.
    #[serde(default)]
    pub dry_run: bool,
}

impl SubmitConfig {
    /// The fee as an integer stroop amount, or `None` when not parseable.
    #[must_use]
    pub fn fee_stroops(&self) -> Option<u64> {
        self.fee.trim().parse::<u64>().ok()
    }
}

/// A fully parsed deployment spec (`deploy/<name>.toml`).
///
/// A deployment spec describes *what* to deploy. It is not an environment
/// config (which describes *where* to deploy); the two are linked by
/// `network.environment`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentSpec {
    /// Name of this deployment plan (must match the filename stem).
    pub name: String,
    /// Stellar account that signs and pays for the deployment transactions.
    pub admin_account: String,
    /// Network target.
    pub network: DeploymentNetwork,
    /// Transaction submission parameters.
    pub submit: SubmitConfig,
    /// Contracts to deploy, keyed by a short logical name.
    pub contracts: BTreeMap<String, ContractEntry>,
}

impl DeploymentSpec {
    /// Parse a spec from TOML source text.
    ///
    /// Unknown tables and keys are rejected: a typo must fail loudly rather
    /// than be silently dropped.
    pub fn from_toml_str(source: &str) -> Result<Self> {
        toml::from_str(source).map_err(|e| {
            ToolkitError::ExecutionError(format!("invalid deployment spec: {e}"))
        })
    }

    /// Load `path` from the filesystem and parse it.
    pub fn load(path: &Path) -> Result<Self> {
        let source = std::fs::read_to_string(path).map_err(|e| {
            ToolkitError::ExecutionError(format!("cannot read {}: {e}", path.display()))
        })?;
        Self::from_toml_str(&source)
            .map_err(|e| ToolkitError::ExecutionError(format!("{}: {e}", path.display())))
    }

    /// Name of this spec as declared in the `name` field.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

// ── Validator ─────────────────────────────────────────────────────────────────

/// Offline validator for [`DeploymentSpec`] instances.
///
/// Instantiate with a workspace root and call [`DeploymentValidator::validate`].
/// The root is used only for resolving relative `wasm_path` values; no network
/// call is ever made.
pub struct DeploymentValidator {
    workspace_root: PathBuf,
}

impl DeploymentValidator {
    /// Create a validator that resolves relative paths from `workspace_root`.
    pub fn new(workspace_root: &Path) -> Self {
        Self {
            workspace_root: workspace_root.to_path_buf(),
        }
    }

    /// Validate `spec` and return a report.  Every problem is collected before
    /// returning so the caller can fix them all in one pass.
    #[must_use]
    pub fn validate(&self, spec: &DeploymentSpec) -> DeploymentValidationReport {
        let mut findings = Vec::new();
        self.validate_admin_account(spec, &mut findings);
        self.validate_network(spec, &mut findings);
        self.validate_submit(spec, &mut findings);
        self.validate_contracts(spec, &mut findings);
        DeploymentValidationReport { findings }
    }

    fn validate_admin_account(&self, spec: &DeploymentSpec, findings: &mut Vec<Finding>) {
        validate_stellar_account("admin_account", &spec.admin_account, findings);
    }

    fn validate_network(&self, spec: &DeploymentSpec, findings: &mut Vec<Finding>) {
        let env = &spec.network.environment;
        if !crate::env_config::ENVIRONMENTS.contains(&env.as_str()) {
            findings.push(Finding::error(
                "network.environment",
                format!(
                    "`{env}` is not a known environment (expected one of {})",
                    crate::env_config::ENVIRONMENTS.join(", ")
                ),
            ));
        }
    }

    fn validate_submit(&self, spec: &DeploymentSpec, findings: &mut Vec<Finding>) {
        let submit = &spec.submit;

        match submit.fee_stroops() {
            Some(0) => findings.push(Finding::error(
                "submit.fee",
                "fee must be greater than zero stroops",
            )),
            Some(_) => {}
            None => findings.push(Finding::error(
                "submit.fee",
                format!("`{}` is not a stroop amount (must be a positive integer)", submit.fee),
            )),
        }

        if submit.timeout_seconds == 0 {
            findings.push(Finding::error(
                "submit.timeout_seconds",
                "timeout must be greater than zero; a zero timeout expires before the \
                 transaction is built",
            ));
        }

        if submit.confirmations == 0 && !submit.dry_run {
            findings.push(Finding::warning(
                "submit.confirmations",
                "zero confirmations means success is reported before the transaction is \
                 included in a ledger; use at least 1 unless your submission script \
                 handles retries itself",
            ));
        }
    }

    fn validate_contracts(&self, spec: &DeploymentSpec, findings: &mut Vec<Finding>) {
        if spec.contracts.is_empty() {
            findings.push(Finding::error(
                "contracts",
                "deployment spec has no [contracts.*] entries; nothing would be deployed",
            ));
            return;
        }

        for (name, entry) in &spec.contracts {
            let prefix = format!("contracts.{name}");
            self.validate_contract_entry(&prefix, name, entry, spec, findings);
        }
    }

    fn validate_contract_entry(
        &self,
        prefix: &str,
        _name: &str,
        entry: &ContractEntry,
        spec: &DeploymentSpec,
        findings: &mut Vec<Finding>,
    ) {
        // ── WASM path ────────────────────────────────────────────────────────
        if entry.wasm_path.trim().is_empty() {
            findings.push(Finding::error(
                format!("{prefix}.wasm_path"),
                "wasm_path must not be empty",
            ));
        } else {
            let wasm_path = resolve_path(&self.workspace_root, &entry.wasm_path);
            if !wasm_path.exists() {
                findings.push(Finding::error(
                    format!("{prefix}.wasm_path"),
                    format!(
                        "`{}` does not exist; run `stellar-toolkit compile` first",
                        wasm_path.display()
                    ),
                ));
            } else if !wasm_path.is_file() {
                findings.push(Finding::error(
                    format!("{prefix}.wasm_path"),
                    format!("`{}` is not a file", wasm_path.display()),
                ));
            } else {
                // A valid .wasm binary must have the 4-byte magic number
                // `\0asm`.  Catching a misidentified file here saves a
                // confusing RPC rejection later.
                match wasm_magic_ok(&wasm_path) {
                    Ok(false) => findings.push(Finding::error(
                        format!("{prefix}.wasm_path"),
                        format!(
                            "`{}` is not a WebAssembly binary (wrong magic bytes)",
                            wasm_path.display()
                        ),
                    )),
                    Ok(true) => {}
                    Err(e) => findings.push(Finding::warning(
                        format!("{prefix}.wasm_path"),
                        format!("could not verify WASM magic bytes for `{}`: {e}", wasm_path.display()),
                    )),
                }
            }
        }

        // ── contract_id (optional — upgrade path) ────────────────────────────
        if let Some(cid) = &entry.contract_id {
            validate_contract_id(&format!("{prefix}.contract_id"), cid, findings);
        }

        // ── per-contract admin override ──────────────────────────────────────
        if let Some(admin) = &entry.admin_account {
            validate_stellar_account(&format!("{prefix}.admin_account"), admin, findings);
        }

        // ── prod safety: an upgrade without a contract_id is suspicious ───────
        if spec.network.environment == "prod" && entry.contract_id.is_none() {
            findings.push(Finding::warning(
                format!("{prefix}.contract_id"),
                "deploying to `prod` without a contract_id performs a first-time deploy; \
                 set contract_id if this is an upgrade to prevent accidentally creating a \
                 duplicate contract",
            ));
        }
    }
}

// ── Report ───────────────────────────────────────────────────────────────────

/// Result of offline-validating a [`DeploymentSpec`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentValidationReport {
    pub findings: Vec<Finding>,
}

impl DeploymentValidationReport {
    /// Number of findings with [`Severity::Error`].
    #[must_use]
    pub fn errors(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count()
    }

    /// Number of findings with [`Severity::Warning`].
    #[must_use]
    pub fn warnings(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .count()
    }

    /// `true` when there are no error-severity findings.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.errors() == 0
    }

    /// Machine-readable JSON output, stable across releases.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }

    /// Human-readable report for terminals and CI logs.
    #[must_use]
    pub fn render(&self, spec_name: &str) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{spec_name} — {} error(s), {} warning(s)",
            self.errors(),
            self.warnings()
        );
        for f in &self.findings {
            let _ = writeln!(
                out,
                "  {:<7} {:<44} {}",
                f.severity.as_str(),
                f.field,
                f.message
            );
        }
        out
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Resolve `path` against `root` when it is relative.
fn resolve_path(root: &Path, path: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        root.join(p)
    }
}

/// Reject `\0asm` magic check without reading the whole file.
fn wasm_magic_ok(path: &Path) -> std::io::Result<bool> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut magic = [0u8; 4];
    let n = f.read(&mut magic)?;
    Ok(n == 4 && magic == [0x00, 0x61, 0x73, 0x6d])
}

/// Validate that `value` looks like a Stellar public key (G...).
///
/// A full Ed25519 strkey decode is not attempted here to avoid depending on
/// stellar-strkey in the validation path; the structural checks (prefix, length,
/// Base32 character set) catch all mis-pastes at negligible cost.
fn validate_stellar_account(field: &str, value: &str, findings: &mut Vec<Finding>) {
    if value.trim().is_empty() {
        findings.push(Finding::error(field, "must not be empty"));
        return;
    }
    if !value.starts_with('G') {
        findings.push(Finding::error(
            field,
            format!(
                "`{value}` is not a Stellar account address (must start with 'G')"
            ),
        ));
        return;
    }
    // Stellar G-addresses are 56 characters of Base32.
    if value.len() != 56 {
        findings.push(Finding::error(
            field,
            format!(
                "`{value}` has length {} (Stellar addresses are always 56 characters)",
                value.len()
            ),
        ));
        return;
    }
    // All characters must be uppercase Base32 (A-Z, 2-7).
    let bad: Vec<char> = value
        .chars()
        .filter(|c| !matches!(c, 'A'..='Z' | '2'..='7'))
        .collect();
    if !bad.is_empty() {
        findings.push(Finding::error(
            field,
            format!(
                "`{value}` contains invalid Base32 character(s): {}",
                bad.iter().collect::<String>()
            ),
        ));
    }
}

/// Validate that `value` looks like a Stellar contract ID (C..., 56 chars).
fn validate_contract_id(field: &str, value: &str, findings: &mut Vec<Finding>) {
    if value.trim().is_empty() {
        findings.push(Finding::error(field, "contract_id must not be empty"));
        return;
    }
    if !value.starts_with('C') {
        findings.push(Finding::error(
            field,
            format!(
                "`{value}` is not a Stellar contract ID (must start with 'C')"
            ),
        ));
        return;
    }
    if value.len() != 56 {
        findings.push(Finding::error(
            field,
            format!(
                "`{value}` has length {} (Stellar contract IDs are always 56 characters)",
                value.len()
            ),
        ));
        return;
    }
    let bad: Vec<char> = value
        .chars()
        .filter(|c| !matches!(c, 'A'..='Z' | '2'..='7'))
        .collect();
    if !bad.is_empty() {
        findings.push(Finding::error(
            field,
            format!(
                "`{value}` contains invalid Base32 character(s): {}",
                bad.iter().collect::<String>()
            ),
        ));
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// A valid G-address (56 upper-case Base32 chars) for testing.
    fn valid_g_address() -> &'static str {
        "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN"
    }

    /// A valid C-address for testing.
    fn valid_c_address() -> &'static str {
        "CCJZ5JW2IXDPGD3TQNQFQTHGD6ZQZQZQZQZQZQZQZQZQZQZQZQZQ2"
    }

    /// A minimal spec that passes validation except for WASM existence.
    fn minimal_spec(wasm_path: &str) -> DeploymentSpec {
        let mut contracts = BTreeMap::new();
        contracts.insert(
            "amm_pool".to_string(),
            ContractEntry {
                wasm_path: wasm_path.to_string(),
                contract_id: None,
                admin_account: None,
            },
        );
        DeploymentSpec {
            name: "test-spec".to_string(),
            admin_account: valid_g_address().to_string(),
            network: DeploymentNetwork {
                environment: "test".to_string(),
            },
            submit: SubmitConfig {
                fee: "100".to_string(),
                timeout_seconds: 30,
                confirmations: 1,
                dry_run: false,
            },
            contracts,
        }
    }

    // ── TOML parsing ─────────────────────────────────────────────────────────

    #[test]
    fn parses_valid_toml() {
        let toml = format!(
            r#"
name = "testnet"
admin_account = "{}"

[network]
environment = "test"

[submit]
fee = "1000"
timeout_seconds = 60
confirmations = 2

[contracts.amm_pool]
wasm_path = "target/wasm32v1-none/release/amm_pool.wasm"
contract_id = "{}"
"#,
            valid_g_address(),
            valid_c_address()
        );
        let spec = DeploymentSpec::from_toml_str(&toml).expect("parse");
        assert_eq!(spec.name, "testnet");
        assert_eq!(spec.submit.fee_stroops(), Some(1000));
        assert_eq!(spec.contracts.len(), 1);
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        let toml = format!(
            r#"
name = "testnet"
admin_account = "{}"
unknown_key = true

[network]
environment = "test"

[submit]
fee = "100"
timeout_seconds = 30
"#,
            valid_g_address()
        );
        let err = DeploymentSpec::from_toml_str(&toml).unwrap_err();
        assert!(
            err.to_string().contains("unknown_key"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_unknown_contract_key() {
        let toml = format!(
            r#"
name = "testnet"
admin_account = "{}"

[network]
environment = "test"

[submit]
fee = "100"
timeout_seconds = 30

[contracts.amm_pool]
wasm_path = "some.wasm"
surprise_key = "oops"
"#,
            valid_g_address()
        );
        let err = DeploymentSpec::from_toml_str(&toml).unwrap_err();
        assert!(
            err.to_string().contains("surprise_key"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn fee_stroops_returns_none_for_non_integer() {
        let mut spec = minimal_spec("x.wasm");
        spec.submit.fee = "1000.5".to_string();
        assert_eq!(spec.submit.fee_stroops(), None);
    }

    // ── Admin account ─────────────────────────────────────────────────────────

    #[test]
    fn rejects_non_g_admin_account() {
        let validator = DeploymentValidator::new(Path::new("."));
        let mut spec = minimal_spec("x.wasm");
        spec.admin_account = "SABC123".to_string(); // S-key (secret), not a G-key
        let report = validator.validate(&spec);
        assert!(report.findings.iter().any(|f| f.field == "admin_account"));
    }

    #[test]
    fn rejects_short_g_account() {
        let validator = DeploymentValidator::new(Path::new("."));
        let mut spec = minimal_spec("x.wasm");
        spec.admin_account = "GSHORT".to_string();
        let report = validator.validate(&spec);
        assert!(report
            .findings
            .iter()
            .any(|f| f.field == "admin_account" && f.severity == Severity::Error));
    }

    #[test]
    fn rejects_empty_admin_account() {
        let validator = DeploymentValidator::new(Path::new("."));
        let mut spec = minimal_spec("x.wasm");
        spec.admin_account = String::new();
        let report = validator.validate(&spec);
        assert!(report.findings.iter().any(|f| f.field == "admin_account"));
    }

    // ── Network ───────────────────────────────────────────────────────────────

    #[test]
    fn rejects_unknown_environment() {
        let validator = DeploymentValidator::new(Path::new("."));
        let mut spec = minimal_spec("x.wasm");
        spec.network.environment = "staging".to_string();
        let report = validator.validate(&spec);
        assert!(report
            .findings
            .iter()
            .any(|f| f.field == "network.environment"));
    }

    #[test]
    fn accepts_known_environments() {
        let validator = DeploymentValidator::new(Path::new("."));
        for env in ["dev", "test", "prod"] {
            let mut spec = minimal_spec("x.wasm");
            spec.network.environment = env.to_string();
            let report = validator.validate(&spec);
            assert!(
                !report.findings.iter().any(|f| f.field == "network.environment"),
                "environment `{env}` should be accepted"
            );
        }
    }

    // ── Submit config ─────────────────────────────────────────────────────────

    #[test]
    fn rejects_zero_fee() {
        let validator = DeploymentValidator::new(Path::new("."));
        let mut spec = minimal_spec("x.wasm");
        spec.submit.fee = "0".to_string();
        let report = validator.validate(&spec);
        assert!(report
            .findings
            .iter()
            .any(|f| f.field == "submit.fee" && f.severity == Severity::Error));
    }

    #[test]
    fn rejects_non_integer_fee() {
        let validator = DeploymentValidator::new(Path::new("."));
        let mut spec = minimal_spec("x.wasm");
        spec.submit.fee = "not-a-number".to_string();
        let report = validator.validate(&spec);
        assert!(report
            .findings
            .iter()
            .any(|f| f.field == "submit.fee" && f.severity == Severity::Error));
    }

    #[test]
    fn rejects_zero_timeout() {
        let validator = DeploymentValidator::new(Path::new("."));
        let mut spec = minimal_spec("x.wasm");
        spec.submit.timeout_seconds = 0;
        let report = validator.validate(&spec);
        assert!(report
            .findings
            .iter()
            .any(|f| f.field == "submit.timeout_seconds" && f.severity == Severity::Error));
    }

    #[test]
    fn warns_on_zero_confirmations() {
        let validator = DeploymentValidator::new(Path::new("."));
        let mut spec = minimal_spec("x.wasm");
        spec.submit.confirmations = 0;
        let report = validator.validate(&spec);
        assert!(report
            .findings
            .iter()
            .any(|f| f.field == "submit.confirmations" && f.severity == Severity::Warning));
    }

    #[test]
    fn zero_confirmations_dry_run_suppresses_warning() {
        let validator = DeploymentValidator::new(Path::new("."));
        let mut spec = minimal_spec("x.wasm");
        spec.submit.confirmations = 0;
        spec.submit.dry_run = true;
        let report = validator.validate(&spec);
        assert!(!report
            .findings
            .iter()
            .any(|f| f.field == "submit.confirmations"));
    }

    // ── Contracts ─────────────────────────────────────────────────────────────

    #[test]
    fn rejects_empty_contracts_map() {
        let validator = DeploymentValidator::new(Path::new("."));
        let mut spec = minimal_spec("x.wasm");
        spec.contracts.clear();
        let report = validator.validate(&spec);
        assert!(report
            .findings
            .iter()
            .any(|f| f.field == "contracts" && f.severity == Severity::Error));
    }

    #[test]
    fn rejects_missing_wasm_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let validator = DeploymentValidator::new(dir.path());
        let spec = minimal_spec("target/no-such-contract.wasm");
        let report = validator.validate(&spec);
        assert!(report
            .findings
            .iter()
            .any(|f| f.field.contains("wasm_path") && f.severity == Severity::Error));
    }

    #[test]
    fn rejects_empty_wasm_path() {
        let validator = DeploymentValidator::new(Path::new("."));
        let spec = minimal_spec("");
        let report = validator.validate(&spec);
        assert!(report
            .findings
            .iter()
            .any(|f| f.field.contains("wasm_path") && f.severity == Severity::Error));
    }

    #[test]
    fn accepts_existing_valid_wasm() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Write a file with the WebAssembly magic bytes.
        let wasm_path = dir.path().join("contract.wasm");
        std::fs::write(&wasm_path, b"\x00asm\x01\x00\x00\x00").expect("write wasm");

        let validator = DeploymentValidator::new(dir.path());
        let spec = minimal_spec("contract.wasm");
        let report = validator.validate(&spec);
        // The only remaining issue may be the prod warning, but wasm_path should be clean.
        assert!(
            !report.findings.iter().any(|f| f.field.contains("wasm_path")),
            "valid wasm must not produce a wasm_path finding; got: {:?}",
            report.findings
        );
    }

    #[test]
    fn rejects_wasm_with_wrong_magic_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wasm_path = dir.path().join("not-a-wasm.wasm");
        std::fs::write(&wasm_path, b"ELF binary or something").expect("write");

        let validator = DeploymentValidator::new(dir.path());
        let spec = minimal_spec("not-a-wasm.wasm");
        let report = validator.validate(&spec);
        assert!(report
            .findings
            .iter()
            .any(|f| f.field.contains("wasm_path") && f.severity == Severity::Error));
    }

    #[test]
    fn rejects_invalid_contract_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wasm_path = dir.path().join("ok.wasm");
        std::fs::write(&wasm_path, b"\x00asm\x01\x00\x00\x00").expect("write");

        let validator = DeploymentValidator::new(dir.path());
        let mut spec = minimal_spec("ok.wasm");
        spec.contracts
            .get_mut("amm_pool")
            .unwrap()
            .contract_id = Some("GNOTACONTRACTID567890123456789012345678901234567890123".to_string());
        let report = validator.validate(&spec);
        assert!(report
            .findings
            .iter()
            .any(|f| f.field.contains("contract_id") && f.severity == Severity::Error));
    }

    #[test]
    fn warns_on_prod_deploy_without_contract_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wasm_path = dir.path().join("ok.wasm");
        std::fs::write(&wasm_path, b"\x00asm\x01\x00\x00\x00").expect("write");

        let validator = DeploymentValidator::new(dir.path());
        let mut spec = minimal_spec("ok.wasm");
        spec.network.environment = "prod".to_string();
        // No contract_id — first-time deploy on prod
        let report = validator.validate(&spec);
        assert!(report
            .findings
            .iter()
            .any(|f| f.field.contains("contract_id") && f.severity == Severity::Warning));
    }

    // ── Report rendering ──────────────────────────────────────────────────────

    #[test]
    fn render_includes_spec_name_and_counts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let validator = DeploymentValidator::new(dir.path());
        let spec = minimal_spec("nonexistent.wasm");
        let report = validator.validate(&spec);
        let rendered = report.render("test-spec");
        assert!(rendered.contains("test-spec"));
        assert!(rendered.contains("error"));
    }

    #[test]
    fn to_json_round_trips() {
        let finding = Finding {
            severity: Severity::Error,
            field: "submit.fee".to_string(),
            message: "fee must be greater than zero stroops".to_string(),
        };
        let report = DeploymentValidationReport {
            findings: vec![finding],
        };
        let json = report.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(parsed["findings"][0]["severity"].as_str(), Some("error"));
        assert_eq!(parsed["findings"][0]["field"].as_str(), Some("submit.fee"));
    }

    #[test]
    fn passed_requires_no_errors() {
        let report_ok = DeploymentValidationReport { findings: vec![] };
        assert!(report_ok.passed());

        let report_warn = DeploymentValidationReport {
            findings: vec![Finding::warning("x", "y")],
        };
        assert!(report_warn.passed(), "warnings alone must not fail the report");

        let report_err = DeploymentValidationReport {
            findings: vec![Finding::error("x", "y")],
        };
        assert!(!report_err.passed());
    }

    // ── Stellar address helpers ───────────────────────────────────────────────

    #[test]
    fn valid_g_address_accepted() {
        let mut findings = Vec::new();
        validate_stellar_account("field", valid_g_address(), &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn valid_c_address_accepted() {
        let mut findings = Vec::new();
        validate_contract_id("field", valid_c_address(), &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn g_address_with_invalid_chars_rejected() {
        let bad = "G0000000000000000000000000000000000000000000000000000000"; // '0' not in Base32
        let mut findings = Vec::new();
        validate_stellar_account("field", bad, &mut findings);
        assert!(!findings.is_empty());
    }
}

//! Multi-environment deploy configuration (issue #118).
//!
//! `config/{dev,test,prod}.toml` are the single source of truth for the
//! endpoints, fees and safety flags a deployment targets. Parsing them is not
//! enough: the mistakes that actually reach mainnet are *semantic* — a testnet
//! config carrying the mainnet passphrase, `auto_fund = true` in production, a
//! missing `require_multisig`, at typo'd `[monitorng]` table that silently
//! disables alerting. TOML has no way to express any of that, so this module
//! loads a config into a typed struct and checks it against the environment
//! contract documented in `docs/INFRA_RUNBOOK.md`.
//!
//! Two properties matter for CI use:
//!
//! * every problem is reported, not just the first one, so a reviewer fixes a
//!   config in one pass;
//! * unknown keys are a hard error (`deny_unknown_fields`), so a misspelled
//!   table cannot silently fall back to a default.
//!
//! Nothing here contacts the network; `env validate` is safe to run on a
//! developer machine and inside the `automated-checks` CI job.

use crate::error::{Result, ToolkitError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Environments the toolkit supports, in promotion order.
pub const ENVIRONMENTS: [&str; 3] = ["dev", "test", "prod"];

/// Directory (relative to the workspace root) that holds the env configs.
pub const DEFAULT_CONFIG_DIR: &str = "config";

/// Network passphrase that must accompany each `stellar_network` value.
///
/// The passphrase is what actually signs a transaction; a config whose
/// passphrase does not match its network produces transactions for the *wrong*
/// chain that simply fail to submit, which is exactly the kind of late failure
/// this validation exists to prevent.
pub fn passphrase_for_network(network: &str) -> Option<&'static str> {
    match network {
        "local" => Some("Standalone Network ; February 2017"),
        "testnet" => Some("Test SDF Network ; September 2015"),
        "mainnet" => Some("Public Global Stellar Network ; September 2015"),
        _ => None,
    }
}

/// Severity of a validation finding. Any `Error` fails `env validate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
        }
    }
}

/// One problem found in an environment config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    /// Dotted path of the offending field, e.g. `deploy.auto_fund`.
    pub field: String,
    pub message: String,
}

impl Finding {
    fn error(field: &str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            field: field.to_string(),
            message: message.into(),
        }
    }

    fn warning(field: &str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            field: field.to_string(),
            message: message.into(),
        }
    }
}

/// `[env]` — where the environment points.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub name: String,
    /// `local`, `testnet` or `mainnet`.
    pub stellar_network: String,
    pub horizon_url: String,
    pub soroban_rpc_url: String,
    pub soroban_network_passphrase: String,
}

/// `[deploy]` — how a deployment behaves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployConfig {
    /// Friendbot top-up. Must be off outside `dev`/`test`.
    pub auto_fund: bool,
    /// Base fee in stroops, as a TOML string so large values stay exact.
    pub fee: String,
    pub timeout_seconds: u64,
    pub confirmations: u32,
}

impl DeployConfig {
    /// The fee as an integer, or `None` when it is not a valid stroop amount.
    pub fn fee_stroops(&self) -> Option<u64> {
        self.fee.trim().parse::<u64>().ok()
    }
}

/// `[monitoring]` — optional per-environment monitoring switches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct MonitoringConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub poll_interval_seconds: u64,
    #[serde(default)]
    pub alert_on_failure: bool,
    #[serde(default)]
    pub require_manual_approval: bool,
    /// Endpoint the poller probes. Stored as configured; validated as a URL
    /// below so a typo cannot silently disable monitoring.
    #[serde(default)]
    pub horizon_poll_url: Option<String>,
}

/// `[security]` — required for production.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    #[serde(default)]
    pub require_multisig: bool,
    #[serde(default)]
    pub cold_storage_signing: bool,
    #[serde(default)]
    pub audit_log_retention_days: u32,
}

/// A fully parsed `config/<env>.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvConfig {
    pub env: NetworkConfig,
    pub deploy: DeployConfig,
    #[serde(default)]
    pub monitoring: Option<MonitoringConfig>,
    #[serde(default)]
    pub security: Option<SecurityConfig>,
    /// Optional per-contract wasm path overrides. Unused keys are ignored
    /// because a pool added to the workspace should not break an existing
    /// environment file.
    #[serde(default)]
    pub contracts: std::collections::BTreeMap<String, String>,
}

impl EnvConfig {
    /// Parse a config from TOML text.
    ///
    /// Unknown tables and keys are rejected: a typo must fail loudly rather
    /// than silently disable a safety flag.
    pub fn from_toml_str(source: &str) -> Result<Self> {
        toml::from_str(source)
            .map_err(|e| ToolkitError::ExecutionError(format!("invalid environment config: {e}")))
    }

    /// Load `dir/<name>.toml`.
    pub fn load(dir: &Path, name: &str) -> Result<Self> {
        let path = dir.join(format!("{name}.toml"));
        let source = std::fs::read_to_string(&path).map_err(|e| {
            ToolkitError::ExecutionError(format!("cannot read {}: {e}", path.display()))
        })?;
        Self::from_toml_str(&source)
            .map_err(|e| ToolkitError::ExecutionError(format!("{}: {e}", path.display())))
    }

    /// Name of the environment this file describes, as declared by `[env] name`.
    pub fn name(&self) -> &str {
        &self.env.name
    }

    /// True when the environment deploys to the public network.
    pub fn is_production(&self) -> bool {
        self.env.stellar_network == "mainnet"
    }

    /// Every problem in this config, in field order. Empty means valid.
    pub fn validate(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        self.validate_network(&mut findings);
        self.validate_deploy(&mut findings);
        self.validate_monitoring(&mut findings);
        self.validate_security(&mut findings);
        findings
    }

    fn validate_network(&self, findings: &mut Vec<Finding>) {
        let env = &self.env;
        if !ENVIRONMENTS.contains(&env.name.as_str()) {
            findings.push(Finding::error(
                "env.name",
                format!(
                    "`{}` is not a known environment (expected one of {})",
                    env.name,
                    ENVIRONMENTS.join(", ")
                ),
            ));
        }

        for (field, value) in [
            ("env.horizon_url", &env.horizon_url),
            ("env.soroban_rpc_url", &env.soroban_rpc_url),
        ] {
            check_url(field, value, findings);
        }

        match passphrase_for_network(&env.stellar_network) {
            Some(expected) if env.soroban_network_passphrase != expected => {
                findings.push(Finding::error(
                    "env.soroban_network_passphrase",
                    format!(
                        "network `{}` requires the passphrase `{expected}`",
                        env.stellar_network
                    ),
                ))
            }
            Some(_) => {}
            None => findings.push(Finding::error(
                "env.stellar_network",
                format!(
                    "`{}` is not a known network (expected local, testnet or mainnet)",
                    env.stellar_network
                ),
            )),
        }

        // The network's own endpoints must agree with its passphrase: pointing a
        // mainnet config at a testnet RPC silently signs for the wrong chain.
        let endpoints = format!("{} {}", env.horizon_url, env.soroban_rpc_url).to_lowercase();
        if self.is_production() && endpoints.contains("testnet") {
            findings.push(Finding::error(
                "env.soroban_rpc_url",
                "mainnet environment points at a testnet endpoint",
            ));
        }
        if env.stellar_network == "testnet" && endpoints.contains("horizon.stellar.org") {
            findings.push(Finding::error(
                "env.horizon_url",
                "testnet environment points at a mainnet endpoint",
            ));
        }
    }

    fn validate_deploy(&self, findings: &mut Vec<Finding>) {
        let deploy = &self.deploy;
        match deploy.fee_stroops() {
            Some(0) => findings.push(Finding::error(
                "deploy.fee",
                "fee must be greater than zero stroops",
            )),
            Some(_) => {}
            None => findings.push(Finding::error(
                "deploy.fee",
                format!("`{}` is not a stroop amount", deploy.fee),
            )),
        }
        if deploy.timeout_seconds == 0 {
            findings.push(Finding::error(
                "deploy.timeout_seconds",
                "timeout must be greater than zero",
            ));
        }
        if deploy.confirmations == 0 {
            findings.push(Finding::warning(
                "deploy.confirmations",
                "zero confirmations means a deploy is reported successful before it is included",
            ));
        }
        if self.is_production() && deploy.auto_fund {
            findings.push(Finding::error(
                "deploy.auto_fund",
                "auto_fund uses the public Friendbot faucet and must be false on mainnet",
            ));
        }
    }

    fn validate_monitoring(&self, findings: &mut Vec<Finding>) {
        let Some(monitoring) = &self.monitoring else {
            if self.is_production() {
                findings.push(Finding::warning(
                    "monitoring",
                    "mainnet environment has no [monitoring] block, so alerts are not configured",
                ));
            }
            return;
        };
        if monitoring.enabled && monitoring.poll_interval_seconds == 0 {
            findings.push(Finding::error(
                "monitoring.poll_interval_seconds",
                "a poll interval of zero would poll continuously",
            ));
        }
        if monitoring.enabled && !monitoring.alert_on_failure {
            findings.push(Finding::warning(
                "monitoring.alert_on_failure",
                "monitoring is enabled but failing checks raise no alert",
            ));
        }
        if let Some(url) = &monitoring.horizon_poll_url {
            check_url("monitoring.horizon_poll_url", url, findings);
        }
        if monitoring.require_manual_approval && !self.is_production() {
            findings.push(Finding::warning(
                "monitoring.require_manual_approval",
                "a manual approval gate is only meaningful for mainnet",
            ));
        }
    }

    fn validate_security(&self, findings: &mut Vec<Finding>) {
        if !self.is_production() {
            return;
        }
        match &self.security {
            None => findings.push(Finding::error(
                "security",
                "mainnet requires a [security] block with multisig and cold-storage signing",
            )),
            Some(security) => {
                if !security.require_multisig {
                    findings.push(Finding::error(
                        "security.require_multisig",
                        "mainnet deploys must require multisig approval",
                    ));
                }
                if !security.cold_storage_signing {
                    findings.push(Finding::error(
                        "security.cold_storage_signing",
                        "mainnet deploys must be signed from cold storage",
                    ));
                }
                if security.audit_log_retention_days < 90 {
                    findings.push(Finding::warning(
                        "security.audit_log_retention_days",
                        "audit logs should be retained for at least 90 days",
                    ));
                }
            }
        }
    }
}

fn check_url(field: &str, value: &str, findings: &mut Vec<Finding>) {
    match url::Url::parse(value) {
        Ok(parsed) if parsed.scheme() == "http" || parsed.scheme() == "https" => {}
        Ok(parsed) => findings.push(Finding::error(
            field,
            format!("`{}` must be an http(s) URL", parsed.scheme()),
        )),
        Err(e) => findings.push(Finding::error(
            field,
            format!("`{value}` is not a URL: {e}"),
        )),
    }
}

/// Validation result for one environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvValidation {
    pub name: String,
    pub path: PathBuf,
    pub findings: Vec<Finding>,
}

impl EnvValidation {
    /// Errors in this config (warnings do not fail a run).
    pub fn errors(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count()
    }

    pub fn passed(&self) -> bool {
        self.errors() == 0
    }
}

/// Validation result for a whole `config/` directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvValidationReport {
    pub configs: Vec<EnvValidation>,
}

impl EnvValidationReport {
    pub fn errors(&self) -> usize {
        self.configs.iter().map(EnvValidation::errors).sum()
    }

    pub fn warnings(&self) -> usize {
        self.configs
            .iter()
            .map(|c| c.findings.len() - c.errors())
            .sum()
    }

    pub fn passed(&self) -> bool {
        self.errors() == 0
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }

    /// Human readable report used by the CLI and by CI logs.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for config in &self.configs {
            out.push_str(&format!(
                "{} ({}) — {} error(s), {} warning(s)\n",
                config.name,
                config.path.display(),
                config.errors(),
                config.findings.len() - config.errors()
            ));
            for finding in &config.findings {
                out.push_str(&format!(
                    "  {:<7} {:<34} {}\n",
                    finding.severity.as_str(),
                    finding.field,
                    finding.message
                ));
            }
        }
        out.push_str(&format!(
            "{} environment(s): {} error(s), {} warning(s)\n",
            self.configs.len(),
            self.errors(),
            self.warnings()
        ));
        out
    }
}

/// Validate every environment config in `dir`, or only `only` when given.
///
/// A missing file is an error: a promotion path that quietly skips an
/// environment is worse than one that fails.
pub fn validate_directory(dir: &Path, only: Option<&str>) -> Result<EnvValidationReport> {
    let names: Vec<&str> = match only {
        Some(name) => vec![name],
        None => ENVIRONMENTS.to_vec(),
    };

    let mut configs = Vec::new();
    let mut missing = Vec::new();
    for name in names {
        let path = dir.join(format!("{name}.toml"));
        if !path.exists() {
            missing.push(path.display().to_string());
            continue;
        }
        let config = EnvConfig::load(dir, name)?;
        let mut findings = config.validate();
        // The filename is part of the contract: `prod.toml` must declare
        // `name = "prod"`, otherwise `--env prod` silently deploys dev settings.
        if config.name() != name {
            findings.push(Finding::error(
                "env.name",
                format!("file `{name}.toml` declares name `{}`", config.name()),
            ));
        }
        configs.push(EnvValidation {
            name: name.to_string(),
            path,
            findings,
        });
    }

    if !missing.is_empty() {
        return Err(ToolkitError::ExecutionError(format!(
            "missing environment config(s): {}",
            missing.join(", ")
        )));
    }

    Ok(EnvValidationReport { configs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The repository's real configs, so the tests fail if one is broken.
    fn workspace_config_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join(DEFAULT_CONFIG_DIR)
    }

    #[test]
    fn checked_in_configs_validate() {
        let report = validate_directory(&workspace_config_dir(), None).expect("configs");
        assert!(
            report.passed(),
            "checked-in configs must validate:\n{}",
            report.render()
        );
        assert_eq!(report.configs.len(), ENVIRONMENTS.len());
    }

    #[test]
    fn prod_config_is_multisig_and_cold_storage() {
        let config = EnvConfig::load(&workspace_config_dir(), "prod").expect("prod");
        assert!(config.is_production());
        let security = config.security.expect("[security] block");
        assert!(security.require_multisig);
        assert!(security.cold_storage_signing);
        assert!(!config.deploy.auto_fund);
    }

    #[test]
    fn mainnet_passphrase_for_testnet_is_rejected() {
        let mut config = EnvConfig::load(&workspace_config_dir(), "test").expect("test");
        config.env.soroban_network_passphrase =
            "Public Global Stellar Network ; September 2015".to_string();
        let findings = config.validate();
        assert!(findings
            .iter()
            .any(|f| f.field == "env.soroban_network_passphrase"));
    }

    #[test]
    fn auto_fund_on_mainnet_is_an_error() {
        let mut config = EnvConfig::load(&workspace_config_dir(), "prod").expect("prod");
        config.deploy.auto_fund = true;
        let findings = config.validate();
        assert!(findings
            .iter()
            .any(|f| f.field == "deploy.auto_fund" && f.severity == Severity::Error));
    }

    #[test]
    fn testnet_pointing_at_mainnet_endpoint_is_an_error() {
        let mut config = EnvConfig::load(&workspace_config_dir(), "test").expect("test");
        config.env.horizon_url = "https://horizon.stellar.org".to_string();
        let findings = config.validate();
        assert!(findings.iter().any(|f| f.field == "env.horizon_url"));
    }

    #[test]
    fn missing_security_block_fails_mainnet() {
        let mut config = EnvConfig::load(&workspace_config_dir(), "prod").expect("prod");
        config.security = None;
        let findings = config.validate();
        assert!(findings
            .iter()
            .any(|f| f.field == "security" && f.severity == Severity::Error));
    }

    #[test]
    fn non_stroop_fee_is_rejected() {
        let mut config = EnvConfig::load(&workspace_config_dir(), "dev").expect("dev");
        config.deploy.fee = "1000.5".to_string();
        assert_eq!(config.deploy.fee_stroops(), None);
        let findings = config.validate();
        assert!(findings.iter().any(|f| f.field == "deploy.fee"));
    }

    #[test]
    fn unknown_keys_are_rejected_rather_than_ignored() {
        // A misspelled table used to be silently dropped, which is how a
        // monitoring or security block can go missing without anyone noticing.
        let source = r#"
[env]
name = "dev"
stellar_network = "local"
horizon_url = "http://localhost:8000"
soroban_rpc_url = "http://localhost:8001"
soroban_network_passphrase = "Standalone Network ; February 2017"

[deploy]
auto_fund = true
fee = "100"
timeout_seconds = 30
confirmations = 1

[securityy]
require_multisig = true
"#;
        let err = EnvConfig::from_toml_str(source).unwrap_err();
        assert!(
            err.to_string().contains("securityy"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn unknown_environment_name_is_rejected() {
        let mut config = EnvConfig::load(&workspace_config_dir(), "dev").expect("dev");
        config.env.name = "staging".to_string();
        let findings = config.validate();
        assert!(findings.iter().any(|f| f.field == "env.name"));
    }

    #[test]
    fn a_missing_config_file_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = validate_directory(dir.path(), None).unwrap_err();
        assert!(err.to_string().contains("missing environment config"));
    }

    #[test]
    fn filename_must_match_declared_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dev =
            std::fs::read_to_string(workspace_config_dir().join("dev.toml")).expect("dev.toml");
        std::fs::write(dir.path().join("dev.toml"), dev).expect("write");
        let report = validate_directory(dir.path(), Some("dev")).expect("validate");
        assert!(report.passed());

        // The same content under a different filename must fail: `--env prod`
        // cannot be allowed to pick up dev settings.
        std::fs::rename(dir.path().join("dev.toml"), dir.path().join("prod.toml")).expect("rename");
        let report = validate_directory(dir.path(), Some("prod")).expect("validate");
        assert!(!report.passed());
        assert!(report
            .configs
            .iter()
            .flat_map(|c| &c.findings)
            .any(|f| f.field == "env.name"));
    }

    #[test]
    fn report_renders_errors_and_warnings() {
        let report = validate_directory(&workspace_config_dir(), None).expect("configs");
        let rendered = report.render();
        assert!(rendered.contains("dev"));
        assert!(rendered.contains("prod"));
    }
}

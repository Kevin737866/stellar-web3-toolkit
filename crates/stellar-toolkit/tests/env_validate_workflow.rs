//! Integration tests for `env validate --json` output mode (issue #308).
//!
//! These tests exercise the public library API end-to-end using a temporary
//! config directory, mirroring the keystore_workflow.rs conventions.

use stellar_toolkit::{validate_directory, EnvFinding, EnvSeverity, EnvValidation, EnvValidationReport};
use std::path::PathBuf;

/// Real workspace config directory, used as a source for valid TOML.
fn workspace_config_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("config")
}

// ── Normal path ──────────────────────────────────────────────────────────────

#[test]
fn json_output_round_trips_for_a_passing_directory() {
    let report = validate_directory(&workspace_config_dir(), None)
        .expect("checked-in configs must load");

    assert!(report.passed(), "checked-in configs must be valid");

    let json = report.to_json();

    // Must produce syntactically valid JSON.
    let parsed: serde_json::Value =
        serde_json::from_str(&json).expect("to_json must emit valid JSON");

    // `configs` array must have one entry per environment.
    let configs = parsed["configs"].as_array().expect("configs array");
    assert_eq!(configs.len(), 3, "dev + test + prod");

    // Every entry must have the required keys.
    for entry in configs {
        assert!(entry["name"].is_string(), "entry.name must be a string");
        assert!(entry["path"].is_string(), "entry.path must be a string");
        assert!(
            entry["findings"].is_array(),
            "entry.findings must be an array"
        );
        assert_eq!(
            entry["findings"].as_array().unwrap().len(),
            0,
            "a valid config has zero findings"
        );
    }
}

// ── Findings are correct in JSON ─────────────────────────────────────────────

#[test]
fn json_output_includes_error_findings_with_correct_severity_string() {
    // Build a minimal report that contains a known error finding.
    let finding = EnvFinding {
        severity: EnvSeverity::Error,
        field: "deploy.auto_fund".to_string(),
        message: "auto_fund uses the public Friendbot faucet and must be false on mainnet"
            .to_string(),
    };
    let report = EnvValidationReport {
        configs: vec![EnvValidation {
            name: "prod".to_string(),
            path: workspace_config_dir().join("prod.toml"),
            findings: vec![finding],
        }],
    };

    assert!(!report.passed());
    assert_eq!(report.errors(), 1);

    let json = report.to_json();
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

    let finding_json = &parsed["configs"][0]["findings"][0];
    assert_eq!(finding_json["severity"].as_str(), Some("error"));
    assert_eq!(finding_json["field"].as_str(), Some("deploy.auto_fund"));
}

#[test]
fn json_output_includes_warning_findings_with_correct_severity_string() {
    let finding = EnvFinding {
        severity: EnvSeverity::Warning,
        field: "monitoring".to_string(),
        message: "mainnet environment has no [monitoring] block".to_string(),
    };
    let report = EnvValidationReport {
        configs: vec![EnvValidation {
            name: "prod".to_string(),
            path: workspace_config_dir().join("prod.toml"),
            findings: vec![finding],
        }],
    };

    // A warning-only report still passes.
    assert!(report.passed(), "warnings do not fail a report");
    assert_eq!(report.warnings(), 1);

    let json = report.to_json();
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

    let finding_json = &parsed["configs"][0]["findings"][0];
    assert_eq!(finding_json["severity"].as_str(), Some("warning"));
}

// ── Boundary: single-env filter ──────────────────────────────────────────────

#[test]
fn json_output_for_single_env_filter_contains_only_that_environment() {
    let report = validate_directory(&workspace_config_dir(), Some("dev"))
        .expect("dev config must load");

    let json = report.to_json();
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

    let configs = parsed["configs"].as_array().expect("configs array");
    assert_eq!(configs.len(), 1, "only one entry when --env dev is used");
    assert_eq!(configs[0]["name"].as_str(), Some("dev"));
}

// ── Failure path ─────────────────────────────────────────────────────────────

#[test]
fn json_output_for_missing_config_directory_surfaces_actionable_error() {
    let missing = PathBuf::from("/tmp/stellar-toolkit-no-such-dir-308");
    let err = validate_directory(&missing, None)
        .expect_err("missing dir must return an error");

    // The error message must be actionable: it must mention the missing file.
    let msg = err.to_string();
    assert!(
        msg.contains("missing") || msg.contains("cannot read") || msg.contains("No such file"),
        "error must name the problem, got: {msg}"
    );
}

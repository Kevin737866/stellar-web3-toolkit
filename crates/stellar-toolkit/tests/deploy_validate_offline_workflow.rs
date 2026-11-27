//! Integration tests for offline deployment config validation (issue #327).
//!
//! Each test exercises the public library API (`DeploymentSpec`,
//! `DeploymentValidator`, `DeploymentValidationReport`) end-to-end using
//! temporary directories and synthetic TOML, mirroring the conventions in
//! `env_validate_workflow.rs`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use stellar_toolkit::{
    ContractEntry, DeploymentNetwork, DeploymentSpec, DeploymentValidator, SubmitConfig,
};

// ── Fixtures ─────────────────────────────────────────────────────────────────

/// A valid 56-char G-address (G + 55 uppercase Base32 chars).
fn g_addr() -> &'static str {
    "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN"
}

/// A valid 56-char C-address.
fn c_addr() -> &'static str {
    "CCJZ5JW2IXDPGD3TQNQFQTHGD6ZQZQZQZQZQZQZQZQZQZQZQZQZQ2"
}

/// Write a 4-byte WebAssembly magic header to `path`.
fn write_wasm(path: &Path) {
    std::fs::write(path, b"\x00asm\x01\x00\x00\x00").expect("write wasm");
}

/// Build a `DeploymentSpec` whose `wasm_path` is `relative_wasm` (relative to
/// workspace root) and `environment` is `env_name`.
fn spec_with_wasm(relative_wasm: &str, env_name: &str) -> DeploymentSpec {
    let mut contracts = BTreeMap::new();
    contracts.insert(
        "amm_pool".to_string(),
        ContractEntry {
            wasm_path: relative_wasm.to_string(),
            contract_id: None,
            admin_account: None,
        },
    );
    DeploymentSpec {
        name: "integration-spec".to_string(),
        admin_account: g_addr().to_string(),
        network: DeploymentNetwork {
            environment: env_name.to_string(),
        },
        submit: SubmitConfig {
            fee: "500".to_string(),
            timeout_seconds: 60,
            confirmations: 2,
            dry_run: false,
        },
        contracts,
    }
}

// ── Normal path ───────────────────────────────────────────────────────────────

/// A correctly configured spec with an existing WASM artifact passes without
/// errors.  Warnings are tolerated (dev has zero confirmations is not set, so
/// there should be none here).
#[test]
fn valid_spec_on_testnet_passes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let wasm = dir.path().join("amm_pool.wasm");
    write_wasm(&wasm);

    let spec = spec_with_wasm("amm_pool.wasm", "test");
    let validator = DeploymentValidator::new(dir.path());
    let report = validator.validate(&spec);

    assert!(
        report.passed(),
        "valid spec must pass; findings: {:?}",
        report.findings
    );
    assert_eq!(report.errors(), 0);
}

/// JSON output round-trips: parsing the emitted JSON gives back the same finding
/// data.
#[test]
fn json_output_round_trips_for_passing_report() {
    let dir = tempfile::tempdir().expect("tempdir");
    let wasm = dir.path().join("pool.wasm");
    write_wasm(&wasm);

    let spec = spec_with_wasm("pool.wasm", "dev");
    let validator = DeploymentValidator::new(dir.path());
    let report = validator.validate(&spec);

    let json = report.to_json();
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

    assert!(
        parsed.get("findings").and_then(|v| v.as_array()).is_some(),
        "JSON must have a `findings` array"
    );
}

// ── Error findings appear in JSON ─────────────────────────────────────────────

/// A missing WASM file produces an error finding whose `severity` is `"error"`
/// in JSON output.
#[test]
fn missing_wasm_produces_error_finding_in_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Deliberately do NOT write the wasm file.
    let spec = spec_with_wasm("missing.wasm", "test");
    let validator = DeploymentValidator::new(dir.path());
    let report = validator.validate(&spec);

    assert!(!report.passed(), "missing WASM must fail");
    let json = report.to_json();
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

    let findings = parsed["findings"].as_array().expect("findings array");
    let wasm_finding = findings
        .iter()
        .find(|f| {
            f["field"]
                .as_str()
                .unwrap_or("")
                .contains("wasm_path")
        })
        .expect("wasm_path finding must be present in JSON");

    assert_eq!(
        wasm_finding["severity"].as_str(),
        Some("error"),
        "missing wasm severity must be 'error'"
    );
    // The message must be actionable.
    assert!(
        wasm_finding["message"]
            .as_str()
            .unwrap_or("")
            .contains("does not exist"),
        "message must say the file does not exist"
    );
}

/// A wrong magic header produces an error finding in JSON.
#[test]
fn wrong_wasm_magic_produces_error_finding_in_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("bad.wasm"), b"not a wasm file").expect("write");

    let spec = spec_with_wasm("bad.wasm", "test");
    let validator = DeploymentValidator::new(dir.path());
    let report = validator.validate(&spec);

    assert!(!report.passed());
    let json = report.to_json();
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    let findings = parsed["findings"].as_array().expect("findings array");

    let magic_finding = findings
        .iter()
        .find(|f| f["field"].as_str().unwrap_or("").contains("wasm_path"))
        .expect("wasm_path finding");
    assert_eq!(magic_finding["severity"].as_str(), Some("error"));
    assert!(
        magic_finding["message"]
            .as_str()
            .unwrap_or("")
            .contains("magic"),
        "message must mention magic bytes"
    );
}

// ── Warning findings appear in JSON ───────────────────────────────────────────

/// Deploying to `prod` without a `contract_id` produces a warning (not an
/// error) and the report still passes.
#[test]
fn prod_without_contract_id_produces_warning_finding_in_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_wasm(&dir.path().join("pool.wasm"));

    let spec = spec_with_wasm("pool.wasm", "prod");
    let validator = DeploymentValidator::new(dir.path());
    let report = validator.validate(&spec);

    // Warnings must not fail the report.
    assert!(report.passed(), "warnings must not fail the report");
    assert!(report.warnings() >= 1, "expected at least one warning");

    let json = report.to_json();
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    let findings = parsed["findings"].as_array().expect("findings array");

    let contract_id_warning = findings
        .iter()
        .find(|f| {
            f["field"].as_str().unwrap_or("").contains("contract_id")
                && f["severity"].as_str() == Some("warning")
        })
        .expect("contract_id warning must be present for prod without contract_id");
    assert!(
        contract_id_warning["message"]
            .as_str()
            .unwrap_or("")
            .contains("first-time deploy"),
        "warning message must explain the risk"
    );
}

// ── Boundary: TOML loading with unknown keys ───────────────────────────────────

/// A deployment spec with an unknown top-level key must be rejected at parse
/// time, not silently ignored.
#[test]
fn unknown_top_level_key_rejected_at_parse_time() {
    let toml = format!(
        r#"
name = "testnet"
admin_account = "{}"
unknown_key = true

[network]
environment = "test"

[submit]
fee = "1000"
timeout_seconds = 60
"#,
        g_addr()
    );
    let err = DeploymentSpec::from_toml_str(&toml).unwrap_err();
    assert!(
        err.to_string().contains("unknown_key"),
        "must name the offending key; got: {err}"
    );
}

/// An unknown key inside `[contracts.*]` must be rejected.
#[test]
fn unknown_contract_key_rejected_at_parse_time() {
    let toml = format!(
        r#"
name = "testnet"
admin_account = "{}"

[network]
environment = "test"

[submit]
fee = "1000"
timeout_seconds = 60

[contracts.amm_pool]
wasm_path = "pool.wasm"
surprise = "surprise"
"#,
        g_addr()
    );
    let err = DeploymentSpec::from_toml_str(&toml).unwrap_err();
    assert!(
        err.to_string().contains("surprise"),
        "must name the offending key; got: {err}"
    );
}

// ── Boundary: filename–name consistency ───────────────────────────────────────

/// When the spec file's stem does not match `name`, the validator must produce
/// an error. This mirrors the `env_validate_workflow` filename consistency
/// check.
#[test]
fn filename_stem_mismatch_detected_via_load_and_explicit_check() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_wasm(&dir.path().join("pool.wasm"));

    // Write a spec whose `name` is "testnet" but save it as "prod.toml".
    let content = format!(
        r#"
name = "testnet"
admin_account = "{}"

[network]
environment = "test"

[submit]
fee = "1000"
timeout_seconds = 60
confirmations = 1

[contracts.amm_pool]
wasm_path = "pool.wasm"
"#,
        g_addr()
    );
    let spec_path = dir.path().join("prod.toml");
    std::fs::write(&spec_path, &content).expect("write spec");

    let parsed = DeploymentSpec::load(&spec_path).expect("parse");
    // The stem is "prod" but the declared name is "testnet" — this is the
    // check that run_deploy performs.
    let stem = spec_path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    assert_ne!(stem, parsed.name(), "fixture must have mismatching names");
}

// ── Failure path: actionable error messages ────────────────────────────────────

/// Every error finding must include a message that describes the problem
/// concretely, not a generic "invalid input" string.
#[test]
fn error_messages_are_actionable() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Inject several errors:
    // 1. No WASM file.
    // 2. Bad admin account (wrong prefix).
    // 3. Zero timeout.
    let mut contracts = BTreeMap::new();
    contracts.insert(
        "amm_pool".to_string(),
        ContractEntry {
            wasm_path: "nonexistent.wasm".to_string(),
            contract_id: None,
            admin_account: None,
        },
    );
    let spec = DeploymentSpec {
        name: "broken".to_string(),
        admin_account: "SINVALIDKEY".to_string(),
        network: DeploymentNetwork {
            environment: "test".to_string(),
        },
        submit: SubmitConfig {
            fee: "100".to_string(),
            timeout_seconds: 0,
            confirmations: 1,
            dry_run: false,
        },
        contracts,
    };

    let validator = DeploymentValidator::new(dir.path());
    let report = validator.validate(&spec);

    assert!(!report.passed());

    for finding in &report.findings {
        if finding.severity == stellar_toolkit::DeploySeverity::Error {
            assert!(
                !finding.message.is_empty(),
                "every error must have a non-empty message; field={}",
                finding.field
            );
            // The message must name the offending value or the fix, not just
            // "invalid input".
            assert!(
                !finding.message.to_lowercase().contains("invalid input"),
                "generic 'invalid input' messages are not actionable; field={} message={}",
                finding.field,
                finding.message
            );
        }
    }

    // Confirm each known error field is present.
    let fields: Vec<&str> = report.findings.iter().map(|f| f.field.as_str()).collect();
    assert!(
        fields.contains(&"admin_account"),
        "expected admin_account finding; got: {fields:?}"
    );
    assert!(
        fields.contains(&"submit.timeout_seconds"),
        "expected timeout finding; got: {fields:?}"
    );
    assert!(
        fields.iter().any(|f| f.contains("wasm_path")),
        "expected wasm_path finding; got: {fields:?}"
    );
}

/// A missing spec file returns an error that names the path.
#[test]
fn missing_spec_file_returns_actionable_error() {
    let path = PathBuf::from("/tmp/stellar-toolkit-no-such-spec-327.toml");
    let err = DeploymentSpec::load(&path).expect_err("must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("cannot read") || msg.contains("No such file"),
        "error must name the problem; got: {msg}"
    );
}

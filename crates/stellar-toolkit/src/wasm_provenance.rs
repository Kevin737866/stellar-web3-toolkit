//! WASM hash provenance (issue #182).
//!
//! `wasm-checksums.txt` answers "which hash do we expect?" but not "what was it
//! built from?". Without the second answer a hash mismatch is indistinguishable
//! from an intentional rebuild, so a real regression and a toolchain bump look
//! the same in CI and someone has to bisect by hand.
//!
//! This module records the build inputs next to the artifact hashes, so a
//! verification can say *why* an artifact changed:
//!
//! ```text
//! record:  wasm-dir ──► wasm-provenance.json   (hashes + build inputs)
//! verify:  wasm-dir + wasm-provenance.json ──► ProvenanceReport
//! ```
//!
//! A mismatch with unchanged inputs is unexplained drift and fails. A mismatch
//! where the toolchain, lockfile or commit changed is reported as explained, so
//! the reader can tell a rebuild from a regression.

use crate::monitoring_dashboard::sha256_hex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Version of the manifest layout written by this module.
pub const PROVENANCE_SCHEMA_VERSION: u32 = 1;

/// Default manifest filename, written next to the checksums file.
pub const PROVENANCE_FILE: &str = "wasm-provenance.json";

/// Default artifact directory, matching `scripts/reproducible-build.sh`.
pub const DEFAULT_WASM_DIR: &str = "target/wasm32v1-none/release";

/// Default manifest path, matching `scripts/reproducible-build.sh`.
pub const DEFAULT_MANIFEST: &str = "target/reproducible/wasm-provenance.json";

/// The build inputs that decide an artifact's hash.
///
/// Every field is optional because a partial checkout (no `.git`, no
/// `Cargo.lock`) must still be able to record and verify hashes; a missing
/// input is reported as unknown rather than treated as a difference.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildInputs {
    /// `channel` from `rust-toolchain.toml`.
    pub toolchain: Option<String>,
    /// `SOURCE_DATE_EPOCH` as exported for the build.
    pub source_date_epoch: Option<String>,
    /// sha256 of `Cargo.lock`, i.e. of the resolved dependency graph.
    pub cargo_lock_sha256: Option<String>,
    /// sha256 of `rust-toolchain.toml`.
    pub rust_toolchain_sha256: Option<String>,
    /// `git rev-parse HEAD`, for "was this built from the commit I think?".
    pub git_commit: Option<String>,
}

impl BuildInputs {
    /// Reads the inputs from `workspace_root`.
    ///
    /// Never fails: an unreadable file or a missing git binary leaves the
    /// corresponding field as `None`.
    #[must_use]
    pub fn from_workspace(workspace_root: &Path) -> Self {
        Self {
            toolchain: toolchain_channel(&workspace_root.join("rust-toolchain.toml")),
            source_date_epoch: std::env::var("SOURCE_DATE_EPOCH").ok(),
            cargo_lock_sha256: sha256_of_file(&workspace_root.join("Cargo.lock")),
            rust_toolchain_sha256: sha256_of_file(&workspace_root.join("rust-toolchain.toml")),
            git_commit: git_head(workspace_root),
        }
    }

    /// Names of the inputs that differ between `self` and `other`.
    ///
    /// A field that is `None` on either side is not a difference: it means the
    /// input could not be observed, not that it changed.
    #[must_use]
    pub fn differences(&self, other: &Self) -> Vec<String> {
        let mut out = Vec::new();
        let mut note = |changed: bool, name: &str| {
            if changed {
                out.push(name.to_string());
            }
        };
        note(
            differs(self.toolchain.as_ref(), other.toolchain.as_ref()),
            "toolchain",
        );
        note(
            differs(
                self.source_date_epoch.as_ref(),
                other.source_date_epoch.as_ref(),
            ),
            "source_date_epoch",
        );
        note(
            differs(
                self.cargo_lock_sha256.as_ref(),
                other.cargo_lock_sha256.as_ref(),
            ),
            "cargo_lock",
        );
        note(
            differs(
                self.rust_toolchain_sha256.as_ref(),
                other.rust_toolchain_sha256.as_ref(),
            ),
            "rust_toolchain",
        );
        note(
            differs(self.git_commit.as_ref(), other.git_commit.as_ref()),
            "git_commit",
        );
        out
    }
}

fn differs(a: Option<&String>, b: Option<&String>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a != b,
        _ => false,
    }
}

/// One recorded artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactProvenance {
    pub sha256: String,
    pub size_bytes: u64,
}

/// The recorded provenance of a whole build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceManifest {
    pub schema_version: u32,
    /// Unix seconds the manifest was written, as a decimal string.
    pub generated_at: String,
    pub inputs: BuildInputs,
    /// Artifact file name (`amm_pool.wasm`) to its recorded hash and size.
    pub artifacts: BTreeMap<String, ArtifactProvenance>,
}

impl ProvenanceManifest {
    /// Hashes every `*.wasm` in `wasm_dir` and records the inputs.
    ///
    /// # Errors
    /// If `wasm_dir` cannot be read.
    pub fn record(workspace_root: &Path, wasm_dir: &Path) -> std::io::Result<Self> {
        let mut artifacts = BTreeMap::new();
        for (name, path) in wasm_artifacts(wasm_dir)? {
            let bytes = std::fs::read(&path)?;
            artifacts.insert(
                name,
                ArtifactProvenance {
                    sha256: sha256_hex(&bytes),
                    size_bytes: bytes.len() as u64,
                },
            );
        }
        Ok(Self {
            schema_version: PROVENANCE_SCHEMA_VERSION,
            generated_at: unix_seconds(),
            inputs: BuildInputs::from_workspace(workspace_root),
            artifacts,
        })
    }

    /// Pretty-printed JSON, the on-disk format.
    ///
    /// # Errors
    /// If serialization fails, which only happens on a programming error.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Parses a manifest written by [`ProvenanceManifest::to_json`].
    ///
    /// # Errors
    /// If the JSON is malformed or its `schema_version` is newer than this
    /// build understands.
    pub fn from_json(raw: &str) -> Result<Self, ManifestError> {
        let manifest: Self =
            serde_json::from_str(raw).map_err(|e| ManifestError::Malformed(e.to_string()))?;
        if manifest.schema_version > PROVENANCE_SCHEMA_VERSION {
            return Err(ManifestError::UnsupportedSchema {
                found: manifest.schema_version,
                supported: PROVENANCE_SCHEMA_VERSION,
            });
        }
        Ok(manifest)
    }

    /// Reads and parses a manifest from disk.
    ///
    /// # Errors
    /// If the file cannot be read or does not parse.
    pub fn load(path: &Path) -> Result<Self, ManifestError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| ManifestError::Io(path.display().to_string(), e.to_string()))?;
        Self::from_json(&raw)
    }

    /// Writes the manifest as pretty JSON atomically, creating parent directories.
    ///
    /// # Errors
    /// If serialization or the atomic write fails.
    pub fn save(&self, path: &Path) -> Result<(), ManifestError> {
        let json = self
            .to_json()
            .map_err(|e| ManifestError::Malformed(e.to_string()))?;
        crate::atomic_output::atomic_write_str(path, &json)
            .map_err(|e| ManifestError::Io(path.display().to_string(), e.to_string()))
    }
}

/// Why a manifest could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    Io(String, String),
    Malformed(String),
    UnsupportedSchema { found: u32, supported: u32 },
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, detail) => write!(f, "cannot read {path}: {detail}"),
            Self::Malformed(detail) => write!(f, "malformed provenance manifest: {detail}"),
            Self::UnsupportedSchema { found, supported } => write!(
                f,
                "provenance schema {found} is newer than the supported {supported}"
            ),
        }
    }
}

impl std::error::Error for ManifestError {}

/// What happened to one artifact during verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactStatus {
    /// Present, and its hash matches the manifest.
    Match,
    /// Present, but its hash differs from the manifest.
    HashMismatch,
    /// Recorded in the manifest but absent from the artifact directory.
    Missing,
    /// Present in the artifact directory but not recorded in the manifest.
    Unrecorded,
}

impl ArtifactStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::HashMismatch => "hash_mismatch",
            Self::Missing => "missing",
            Self::Unrecorded => "unrecorded",
        }
    }
}

/// The verdict for a single artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactVerdict {
    pub name: String,
    pub status: ArtifactStatus,
    pub expected_sha256: Option<String>,
    pub observed_sha256: Option<String>,
}

/// The outcome of verifying an artifact directory against a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceReport {
    pub artifacts: Vec<ArtifactVerdict>,
    /// Inputs that differ between the manifest and the current workspace.
    pub input_drift: Vec<String>,
}

impl ProvenanceReport {
    /// Every recorded artifact is present and unchanged.
    #[must_use]
    pub fn hashes_match(&self) -> bool {
        self.artifacts
            .iter()
            .all(|a| a.status == ArtifactStatus::Match)
    }

    /// Hashes match and the build inputs are unchanged, so this is the same
    /// build the manifest describes.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.hashes_match() && self.input_drift.is_empty()
    }

    /// Hashes differ but a build input changed, so the difference is explained
    /// by that change rather than being a regression.
    #[must_use]
    pub fn drift_is_explained(&self) -> bool {
        !self.hashes_match() && !self.input_drift.is_empty()
    }

    /// Artifacts that are not explained drift: changed or absent while every
    /// recorded input is identical.
    #[must_use]
    pub fn unexplained(&self) -> Vec<&ArtifactVerdict> {
        if self.drift_is_explained() {
            Vec::new()
        } else {
            self.artifacts
                .iter()
                .filter(|a| a.status != ArtifactStatus::Match)
                .collect()
        }
    }

    /// One line per artifact, for a CLI summary.
    #[must_use]
    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines: Vec<String> = self
            .artifacts
            .iter()
            .map(|a| {
                let mut line = format!("{}: {}", a.name, a.status.as_str());
                if a.status == ArtifactStatus::HashMismatch {
                    let expected = a.expected_sha256.as_deref().unwrap_or("unknown");
                    let observed = a.observed_sha256.as_deref().unwrap_or("unknown");
                    let _ = write!(line, " (expected {expected}, got {observed})");
                }
                line
            })
            .collect();
        if self.input_drift.is_empty() {
            lines.push("build inputs: unchanged".to_string());
        } else {
            lines.push(format!(
                "build inputs changed: {}",
                self.input_drift.join(", ")
            ));
        }
        lines
    }
}

/// Verifies the artifacts in `wasm_dir` against `manifest`.
///
/// The current workspace inputs are re-read so the report can separate
/// explained from unexplained drift.
///
/// # Errors
/// If `wasm_dir` cannot be read.
pub fn verify(
    manifest: &ProvenanceManifest,
    workspace_root: &Path,
    wasm_dir: &Path,
) -> std::io::Result<ProvenanceReport> {
    let present: BTreeMap<String, PathBuf> = wasm_artifacts(wasm_dir)?.into_iter().collect();
    let mut artifacts = Vec::new();

    for (name, recorded) in &manifest.artifacts {
        match present.get(name) {
            Some(path) => {
                let bytes = std::fs::read(path)?;
                let observed = sha256_hex(&bytes);
                let status = if observed.eq_ignore_ascii_case(&recorded.sha256) {
                    ArtifactStatus::Match
                } else {
                    ArtifactStatus::HashMismatch
                };
                artifacts.push(ArtifactVerdict {
                    name: name.clone(),
                    status,
                    expected_sha256: Some(recorded.sha256.clone()),
                    observed_sha256: Some(observed),
                });
            }
            None => artifacts.push(ArtifactVerdict {
                name: name.clone(),
                status: ArtifactStatus::Missing,
                expected_sha256: Some(recorded.sha256.clone()),
                observed_sha256: None,
            }),
        }
    }

    for name in present.keys() {
        if !manifest.artifacts.contains_key(name) {
            artifacts.push(ArtifactVerdict {
                name: name.clone(),
                status: ArtifactStatus::Unrecorded,
                expected_sha256: None,
                observed_sha256: None,
            });
        }
    }

    Ok(ProvenanceReport {
        artifacts,
        input_drift: manifest
            .inputs
            .differences(&BuildInputs::from_workspace(workspace_root)),
    })
}

/// `*.wasm` files in `dir`, sorted by name.
///
/// # Errors
/// If `dir` cannot be read.
fn wasm_artifacts(dir: &Path) -> std::io::Result<Vec<(String, PathBuf)>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "wasm") {
            let name = path
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().to_string());
            found.push((name, path));
        }
    }
    found.sort();
    Ok(found)
}

fn sha256_of_file(path: &Path) -> Option<String> {
    std::fs::read(path).ok().map(|bytes| sha256_hex(&bytes))
}

fn toolchain_channel(path: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(path).ok()?;
    raw.lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("channel"))
        .and_then(|rest| rest.trim_start().strip_prefix('='))
        .map(|value| value.trim().trim_matches('"').to_string())
}

fn git_head(root: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let commit = String::from_utf8(output.stdout).ok()?;
    let commit = commit.trim();
    if commit.is_empty() {
        None
    } else {
        Some(commit.to_string())
    }
}

fn unix_seconds() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or_else(|_| "0".to_string(), |d| d.as_secs().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_with(lock: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.98.1\"\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("Cargo.lock"), lock).unwrap();
        dir
    }

    fn wasm_dir_with(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in files {
            std::fs::write(dir.path().join(name), bytes).unwrap();
        }
        dir
    }

    #[test]
    fn a_recorded_build_verifies_clean() {
        let ws = workspace_with("lock v1");
        let wasm = wasm_dir_with(&[("amm_pool.wasm", b"pool"), ("amm_router.wasm", b"router")]);

        let manifest = ProvenanceManifest::record(ws.path(), wasm.path()).unwrap();
        assert_eq!(manifest.artifacts.len(), 2);
        assert_eq!(manifest.inputs.toolchain.as_deref(), Some("1.98.1"));
        assert!(manifest.inputs.cargo_lock_sha256.is_some());

        let report = verify(&manifest, ws.path(), wasm.path()).unwrap();
        assert!(report.hashes_match());
        assert!(report.is_clean(), "{:?}", report.summary_lines());
        assert!(report.unexplained().is_empty());
    }

    #[test]
    fn a_changed_artifact_with_identical_inputs_is_unexplained() {
        let ws = workspace_with("lock v1");
        let wasm = wasm_dir_with(&[("amm_pool.wasm", b"pool")]);
        let manifest = ProvenanceManifest::record(ws.path(), wasm.path()).unwrap();

        std::fs::write(wasm.path().join("amm_pool.wasm"), b"tampered").unwrap();
        let report = verify(&manifest, ws.path(), wasm.path()).unwrap();

        assert!(!report.hashes_match());
        assert!(!report.is_clean());
        assert!(!report.drift_is_explained());
        assert_eq!(report.unexplained().len(), 1);
        assert_eq!(report.unexplained()[0].status, ArtifactStatus::HashMismatch);
    }

    #[test]
    fn a_changed_artifact_after_a_lockfile_change_is_explained() {
        let ws = workspace_with("lock v1");
        let wasm = wasm_dir_with(&[("amm_pool.wasm", b"pool")]);
        let manifest = ProvenanceManifest::record(ws.path(), wasm.path()).unwrap();

        std::fs::write(ws.path().join("Cargo.lock"), "lock v2").unwrap();
        std::fs::write(wasm.path().join("amm_pool.wasm"), b"rebuilt").unwrap();
        let report = verify(&manifest, ws.path(), wasm.path()).unwrap();

        assert!(!report.hashes_match());
        assert!(report.drift_is_explained());
        assert!(report.unexplained().is_empty());
        assert!(report.input_drift.iter().any(|d| d == "cargo_lock"));
    }

    #[test]
    fn a_changed_toolchain_is_reported_as_input_drift() {
        let ws = workspace_with("lock v1");
        let wasm = wasm_dir_with(&[("amm_pool.wasm", b"pool")]);
        let manifest = ProvenanceManifest::record(ws.path(), wasm.path()).unwrap();

        std::fs::write(
            ws.path().join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.99.0\"\n",
        )
        .unwrap();
        let report = verify(&manifest, ws.path(), wasm.path()).unwrap();

        assert!(report.hashes_match());
        assert!(!report.is_clean(), "input drift alone must not be clean");
        assert_eq!(report.input_drift, vec!["toolchain", "rust_toolchain"]);
    }

    #[test]
    fn missing_and_unrecorded_artifacts_are_reported_separately() {
        let ws = workspace_with("lock v1");
        let wasm = wasm_dir_with(&[("amm_pool.wasm", b"pool")]);
        let manifest = ProvenanceManifest::record(ws.path(), wasm.path()).unwrap();

        std::fs::remove_file(wasm.path().join("amm_pool.wasm")).unwrap();
        std::fs::write(wasm.path().join("extra.wasm"), b"extra").unwrap();
        let report = verify(&manifest, ws.path(), wasm.path()).unwrap();

        let status = |name: &str| {
            report
                .artifacts
                .iter()
                .find(|a| a.name == name)
                .map(|a| a.status)
        };
        assert_eq!(status("amm_pool.wasm"), Some(ArtifactStatus::Missing));
        assert_eq!(status("extra.wasm"), Some(ArtifactStatus::Unrecorded));
        assert!(!report.is_clean());
    }

    #[test]
    fn a_manifest_round_trips_through_json() {
        let ws = workspace_with("lock v1");
        let wasm = wasm_dir_with(&[("amm_pool.wasm", b"pool")]);
        let manifest = ProvenanceManifest::record(ws.path(), wasm.path()).unwrap();

        let json = manifest.to_json().unwrap();
        let parsed = ProvenanceManifest::from_json(&json).unwrap();
        assert_eq!(parsed, manifest);
    }

    #[test]
    fn a_newer_schema_is_refused_rather_than_misread() {
        let json = format!(
            r#"{{"schema_version": {}, "generated_at": "0", "inputs": {{}}, "artifacts": {{}}}}"#,
            PROVENANCE_SCHEMA_VERSION + 1
        );
        assert!(matches!(
            ProvenanceManifest::from_json(&json),
            Err(ManifestError::UnsupportedSchema { .. })
        ));
    }

    #[test]
    fn malformed_json_is_rejected() {
        assert!(matches!(
            ProvenanceManifest::from_json("{not json}"),
            Err(ManifestError::Malformed(_))
        ));
    }

    #[test]
    fn a_manifest_saves_to_and_loads_from_disk() {
        let ws = workspace_with("lock v1");
        let wasm = wasm_dir_with(&[("amm_pool.wasm", b"pool")]);
        let manifest = ProvenanceManifest::record(ws.path(), wasm.path()).unwrap();

        let out = ws.path().join("nested").join(PROVENANCE_FILE);
        manifest.save(&out).unwrap();
        assert_eq!(ProvenanceManifest::load(&out).unwrap(), manifest);
    }

    #[test]
    fn a_missing_artifact_directory_is_an_error_not_an_empty_pass() {
        let ws = workspace_with("lock v1");
        let missing = ws.path().join("no-such-dir");
        assert!(ProvenanceManifest::record(ws.path(), &missing).is_err());
    }
}

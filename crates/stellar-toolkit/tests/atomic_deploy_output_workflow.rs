//! Integration tests for atomic deployment output when a command is
//! interrupted (issue #326).

use std::fs;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use stellar_toolkit::{
    atomic_write_str, ArtifactProvenance, AtomicOutputError, BuildInputs, ProvenanceManifest,
    StagedDeploymentOutput, StagedFile,
};
use tempfile::tempdir;

#[test]
fn provenance_manifest_save_is_atomic_and_round_trips() {
    let dir = tempdir().unwrap();
    let manifest_path = dir.path().join("reproducible").join("wasm-provenance.json");

    let mut manifest = ProvenanceManifest::new(BuildInputs::default());
    manifest.artifacts.insert(
        "amm_pool.wasm".to_string(),
        ArtifactProvenance {
            sha256: "deadbeef".to_string(),
            size_bytes: 1024,
        },
    );

    manifest.save(&manifest_path).expect("atomic save must succeed");
    let loaded = ProvenanceManifest::load(&manifest_path).expect("saved manifest must parse");
    assert_eq!(loaded, manifest);

    // No leftover temp files in parent directory.
    let entries: Vec<_> = fs::read_dir(manifest_path.parent().unwrap())
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert_eq!(entries.len(), 1);
}

#[test]
fn interrupted_deployment_leaves_no_partial_artifacts_and_preserves_prior_output() {
    let dir = tempdir().unwrap();
    let out_dir = dir.path().join("deploy");
    let prior_manifest = out_dir.join("manifest.json");
    atomic_write_str(&prior_manifest, "{\"deployment\":1}").unwrap();

    let interrupted = AtomicBool::new(false);
    let mut tx = StagedDeploymentOutput::new(&out_dir).unwrap();
    let staging_dir = tx.staging_dir().to_path_buf();
    tx.stage_file(Path::new("manifest.json"), b"{\"deployment\":2}")
        .unwrap();
    tx.stage_file(Path::new("addresses.json"), b"{\"pool\":\"C...\"}")
        .unwrap();

    // Simulate SIGINT arriving right before commit.
    interrupted.store(true, std::sync::atomic::Ordering::SeqCst);
    let err = tx
        .commit_if_not_interrupted(&interrupted)
        .expect_err("interrupted commit must fail");
    assert!(matches!(err, AtomicOutputError::Interrupted(_)));

    // Staging directory is cleaned up, prior manifest is untouched, and new file was not created.
    assert!(!staging_dir.exists(), "staging dir must be removed on drop");
    assert_eq!(
        fs::read_to_string(&prior_manifest).unwrap(),
        "{\"deployment\":1}"
    );
    assert!(!out_dir.join("addresses.json").exists());
}

#[test]
fn staged_file_abort_leaves_destination_untouched() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("deploy-receipt.json");
    let mut staged = StagedFile::create(&dest).unwrap();
    let tmp = staged.temp_path().to_path_buf();
    staged.write_all(b"{\"tx\":\"pending\"}").unwrap();
    assert!(tmp.exists());

    staged.abort();
    assert!(!tmp.exists());
    assert!(!dest.exists());
}

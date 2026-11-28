//! Atomic deployment output writers (issue #326).
//!
//! Deployment and build commands emit artifacts such as `wasm-provenance.json`,
//! contract-ID manifests, and checksum files. Writing directly to the final
//! destination path via `std::fs::write` truncates any existing file first and
//! leaves partial, corrupted output behind if the process is interrupted
//! mid-write (by an error, panic, or `SIGINT`/`SIGTERM`).
//!
//! This module provides staging-then-rename primitives:
//!
//! * [`atomic_write_bytes`] and [`atomic_write_str`] — write a single file
//!   atomically via a sibling temporary file + `sync_all` + `rename`.
//! * [`StagedFile`] — RAII guard for a single staged output file; if dropped
//!   before [`StagedFile::commit`] (e.g. on early error or unwind), the staging
//!   file is removed and the destination is untouched.
//! * [`StagedDeploymentOutput`] — stages a set of relative output files in a
//!   sibling staging directory and commits them together, rejecting path
//!   traversal and aborting cleanly if an interruption flag is raised.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use thiserror::Error;

static NEXT_STAGING_ID: AtomicU64 = AtomicU64::new(1);

/// Errors returned by atomic output staging and commit operations.
#[derive(Debug, Error)]
pub enum AtomicOutputError {
    #[error("invalid output target `{0}`: {1}")]
    InvalidTarget(String, String),

    #[error("unsafe relative output path `{0}`: {1}")]
    UnsafeRelativePath(String, String),

    #[error("deployment output aborted due to interruption before commit: {0}")]
    Interrupted(String),

    #[error("I/O error on `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

fn validate_target_file(target: &Path) -> Result<(&Path, &std::ffi::OsStr), AtomicOutputError> {
    if target.as_os_str().is_empty() {
        return Err(AtomicOutputError::InvalidTarget(
            String::new(),
            "target path must not be empty".to_string(),
        ));
    }
    let file_name = target.file_name().ok_or_else(|| {
        AtomicOutputError::InvalidTarget(
            target.display().to_string(),
            "target path must include a file name".to_string(),
        )
    })?;
    let parent = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    Ok((parent, file_name))
}

fn validate_relative_path(rel: &Path) -> Result<(), AtomicOutputError> {
    if rel.as_os_str().is_empty() {
        return Err(AtomicOutputError::UnsafeRelativePath(
            String::new(),
            "relative path must not be empty".to_string(),
        ));
    }
    for component in rel.components() {
        match component {
            Component::Normal(_) => {}
            Component::CurDir => {
                return Err(AtomicOutputError::UnsafeRelativePath(
                    rel.display().to_string(),
                    "`.` segments are not allowed in staged output paths".to_string(),
                ));
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(AtomicOutputError::UnsafeRelativePath(
                    rel.display().to_string(),
                    "absolute paths and `..` traversal are forbidden".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn io_err(path: &Path, source: std::io::Error) -> AtomicOutputError {
    AtomicOutputError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// RAII staged file writer that guarantees the destination is never partially
/// written if the operation is aborted or interrupted before [`StagedFile::commit`].
#[derive(Debug)]
pub struct StagedFile {
    target_path: PathBuf,
    temp_path: PathBuf,
    file: Option<File>,
    committed: bool,
}

impl StagedFile {
    /// Creates a new staging file in the same directory as `target`.
    pub fn create(target: &Path) -> Result<Self, AtomicOutputError> {
        let (parent, file_name) = validate_target_file(target)?;
        fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;

        let pid = std::process::id();
        let seq = NEXT_STAGING_ID.fetch_add(1, Ordering::Relaxed);
        let temp_name = format!(
            ".{}.tmp-{pid}-{seq}",
            file_name.to_string_lossy()
        );
        let temp_path = parent.join(temp_name);

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|e| io_err(&temp_path, e))?;

        Ok(Self {
            target_path: target.to_path_buf(),
            temp_path,
            file: Some(file),
            committed: false,
        })
    }

    /// Returns the path of the temporary staging file.
    #[must_use]
    pub fn temp_path(&self) -> &Path {
        &self.temp_path
    }

    /// Writes `bytes` into the staging file without modifying the target path.
    pub fn write_all(&mut self, bytes: &[u8]) -> Result<(), AtomicOutputError> {
        let file = self.file.as_mut().ok_or_else(|| {
            AtomicOutputError::InvalidTarget(
                self.target_path.display().to_string(),
                "staging file already finalized".to_string(),
            )
        })?;
        file.write_all(bytes)
            .map_err(|e| io_err(&self.temp_path, e))
    }

    /// Flushes, syncs to disk, and atomically renames the staging file to the
    /// target path.
    pub fn commit(mut self) -> Result<(), AtomicOutputError> {
        if let Some(mut file) = self.file.take() {
            file.flush().map_err(|e| io_err(&self.temp_path, e))?;
            file.sync_all().map_err(|e| io_err(&self.temp_path, e))?;
        }
        fs::rename(&self.temp_path, &self.target_path)
            .map_err(|e| io_err(&self.target_path, e))?;
        self.committed = true;
        Ok(())
    }

    /// Commits the staged file only if `interrupted` has not been set to `true`.
    ///
    /// If `interrupted` is `true`, the staging file is deleted and the target
    /// path remains untouched.
    pub fn commit_if_not_interrupted(
        self,
        interrupted: &AtomicBool,
    ) -> Result<(), AtomicOutputError> {
        if interrupted.load(Ordering::SeqCst) {
            let target_display = self.target_path.display().to_string();
            self.abort();
            return Err(AtomicOutputError::Interrupted(target_display));
        }
        self.commit()
    }

    /// Explicitly discards the staging file without touching the target path.
    pub fn abort(mut self) {
        self.file.take();
        let _ = fs::remove_file(&self.temp_path);
        self.committed = true;
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if !self.committed {
            self.file.take();
            let _ = fs::remove_file(&self.temp_path);
        }
    }
}

/// Atomically writes `bytes` to `target`, creating parent directories if needed.
///
/// If writing or syncing fails, `target` is left untouched (either absent or
/// retaining its previous contents).
pub fn atomic_write_bytes(target: &Path, bytes: &[u8]) -> Result<(), AtomicOutputError> {
    let mut staged = StagedFile::create(target)?;
    staged.write_all(bytes)?;
    staged.commit()
}

/// Atomically writes UTF-8 `content` to `target`.
pub fn atomic_write_str(target: &Path, content: &str) -> Result<(), AtomicOutputError> {
    atomic_write_bytes(target, content.as_bytes())
}

/// Stages multiple deployment output files in an isolated sibling directory and
/// promotes them to `target_dir` only on [`StagedDeploymentOutput::commit`].
///
/// Dropping a `StagedDeploymentOutput` without calling `commit` removes the
/// entire staging directory and leaves `target_dir` untouched.
#[derive(Debug)]
pub struct StagedDeploymentOutput {
    target_dir: PathBuf,
    staging_dir: PathBuf,
    staged_files: BTreeMap<PathBuf, PathBuf>,
    committed: bool,
}

impl StagedDeploymentOutput {
    /// Creates a new multi-file staging transaction targeting `target_dir`.
    pub fn new(target_dir: &Path) -> Result<Self, AtomicOutputError> {
        if target_dir.as_os_str().is_empty() {
            return Err(AtomicOutputError::InvalidTarget(
                String::new(),
                "target directory must not be empty".to_string(),
            ));
        }
        let parent = match target_dir.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;

        let dir_name = target_dir
            .file_name()
            .map_or_else(|| "deploy-out".to_string(), |n| n.to_string_lossy().into_owned());
        let pid = std::process::id();
        let seq = NEXT_STAGING_ID.fetch_add(1, Ordering::Relaxed);
        let staging_dir = parent.join(format!(".{dir_name}.staging-{pid}-{seq}"));
        fs::create_dir_all(&staging_dir).map_err(|e| io_err(&staging_dir, e))?;

        Ok(Self {
            target_dir: target_dir.to_path_buf(),
            staging_dir,
            staged_files: BTreeMap::new(),
            committed: false,
        })
    }

    /// Returns the path of the temporary staging directory.
    #[must_use]
    pub fn staging_dir(&self) -> &Path {
        &self.staging_dir
    }

    /// Stages a file at `rel_path` inside the deployment output directory.
    ///
    /// Rejects empty paths, absolute paths, and `..` traversal.
    pub fn stage_file(&mut self, rel_path: &Path, bytes: &[u8]) -> Result<(), AtomicOutputError> {
        validate_relative_path(rel_path)?;
        let staged_path = self.staging_dir.join(rel_path);
        if let Some(parent) = staged_path.parent() {
            fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
        }

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&staged_path)
            .map_err(|e| io_err(&staged_path, e))?;
        file.write_all(bytes).map_err(|e| io_err(&staged_path, e))?;
        file.flush().map_err(|e| io_err(&staged_path, e))?;
        file.sync_all().map_err(|e| io_err(&staged_path, e))?;

        self.staged_files
            .insert(rel_path.to_path_buf(), staged_path);
        Ok(())
    }

    /// Promotes all staged files into `target_dir` if `interrupted` is `false`.
    ///
    /// Returns the list of final destination paths on success.
    pub fn commit_if_not_interrupted(
        mut self,
        interrupted: &AtomicBool,
    ) -> Result<Vec<PathBuf>, AtomicOutputError> {
        if interrupted.load(Ordering::SeqCst) {
            return Err(AtomicOutputError::Interrupted(
                self.target_dir.display().to_string(),
            ));
        }

        fs::create_dir_all(&self.target_dir).map_err(|e| io_err(&self.target_dir, e))?;

        let mut final_paths = Vec::with_capacity(self.staged_files.len());
        for (rel_path, staged_path) in &self.staged_files {
            if interrupted.load(Ordering::SeqCst) {
                return Err(AtomicOutputError::Interrupted(
                    self.target_dir.display().to_string(),
                ));
            }
            let dest = self.target_dir.join(rel_path);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
            }
            fs::rename(staged_path, &dest).map_err(|e| io_err(&dest, e))?;
            final_paths.push(dest);
        }

        let _ = fs::remove_dir_all(&self.staging_dir);
        self.committed = true;
        Ok(final_paths)
    }

    /// Promotes all staged files into `target_dir`.
    pub fn commit(self) -> Result<Vec<PathBuf>, AtomicOutputError> {
        let not_interrupted = AtomicBool::new(false);
        self.commit_if_not_interrupted(&not_interrupted)
    }
}

impl Drop for StagedDeploymentOutput {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_dir_all(&self.staging_dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn atomic_write_creates_and_replaces_file_without_leaving_temp_files() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("nested").join("deploy.json");

        atomic_write_str(&target, r#"{"version":1}"#).expect("initial write");
        assert_eq!(fs::read_to_string(&target).unwrap(), r#"{"version":1}"#);

        atomic_write_str(&target, r#"{"version":2}"#).expect("overwrite");
        assert_eq!(fs::read_to_string(&target).unwrap(), r#"{"version":2}"#);

        let entries: Vec<_> = fs::read_dir(target.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert_eq!(entries.len(), 1, "no leftover temp files after commit");
    }

    #[test]
    fn dropping_staged_file_before_commit_preserves_existing_target_and_cleans_temp() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("deploy.json");
        atomic_write_str(&target, "original-intact").unwrap();

        let temp_path = {
            let mut staged = StagedFile::create(&target).unwrap();
            staged.write_all(b"partial-corrupted").unwrap();
            staged.temp_path().to_path_buf()
            // dropped here without commit (simulates panic/early return/interruption)
        };

        assert!(!temp_path.exists(), "temp file must be cleaned up on drop");
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "original-intact",
            "existing output must remain intact"
        );
    }

    #[test]
    fn interrupted_flag_aborts_commit_without_modifying_target() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("contract-ids.json");
        let interrupted = AtomicBool::new(true);

        let mut staged = StagedFile::create(&target).unwrap();
        staged.write_all(b"{}").unwrap();
        let err = staged
            .commit_if_not_interrupted(&interrupted)
            .expect_err("must abort when interrupted");

        assert!(matches!(err, AtomicOutputError::Interrupted(_)));
        assert!(!target.exists(), "target must not exist after interruption");
    }

    #[test]
    fn multi_file_staging_commits_all_files_and_rejects_traversal() {
        let dir = tempdir().unwrap();
        let out_dir = dir.path().join("deploy-artifacts");

        let mut tx = StagedDeploymentOutput::new(&out_dir).unwrap();
        assert!(matches!(
            tx.stage_file(Path::new("../escape.json"), b"bad"),
            Err(AtomicOutputError::UnsafeRelativePath(_, _))
        ));
        assert!(matches!(
            tx.stage_file(Path::new("/abs/path.json"), b"bad"),
            Err(AtomicOutputError::UnsafeRelativePath(_, _))
        ));

        tx.stage_file(Path::new("manifest.json"), b"{\"ok\":true}")
            .unwrap();
        tx.stage_file(Path::new("sub/checksums.txt"), b"abc  manifest.json")
            .unwrap();
        let committed = tx.commit().unwrap();
        assert_eq!(committed.len(), 2);
        assert_eq!(
            fs::read_to_string(out_dir.join("manifest.json")).unwrap(),
            "{\"ok\":true}"
        );
        assert_eq!(
            fs::read_to_string(out_dir.join("sub/checksums.txt")).unwrap(),
            "abc  manifest.json"
        );
    }

    #[test]
    fn rejects_empty_and_directory_like_targets() {
        assert!(matches!(
            atomic_write_str(Path::new(""), "x"),
            Err(AtomicOutputError::InvalidTarget(_, _))
        ));
        assert!(matches!(
            atomic_write_str(Path::new("/"), "x"),
            Err(AtomicOutputError::InvalidTarget(_, _))
        ));
    }
}

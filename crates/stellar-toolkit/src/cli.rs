use crate::error::{Result, ToolkitError};
use clap::Subcommand;
use std::path::PathBuf;
use std::process::Command;

#[derive(Subcommand, Debug)]
pub enum ToolkitCommand {
    /// Build all Soroban contract crates (wasm32-unknown-unknown release)
    Compile {
        /// Workspace root (directory containing workspace Cargo.toml)
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
    },
    /// Run every unit test in the Cargo workspace
    Test {
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
    },
    /// Show local paths for AMM contract artifacts after compile
    Contracts {
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
    },
}

impl ToolkitCommand {
    pub fn run(&self) -> Result<()> {
        match self {
            Self::Compile { workspace } => run_cargo(
                workspace,
                &[
                    "build",
                    "--workspace",
                    "--exclude",
                    "stellar-toolkit",
                    "--target",
                    "wasm32-unknown-unknown",
                    "--release",
                ],
            ),
            Self::Test { workspace } => run_cargo(workspace, &["test", "--workspace"]),
            Self::Contracts { workspace } => {
                let root = normalize_workspace_root(workspace);
                let pool = root.join("target/wasm32-unknown-unknown/release/amm_pool.wasm");
                let factory = root.join("target/wasm32-unknown-unknown/release/amm_factory.wasm");
                let router = root.join("target/wasm32-unknown-unknown/release/amm_router.wasm");
                println!("amm_pool:    {}", pool.display());
                println!("amm_factory: {}", factory.display());
                println!("amm_router:  {}", router.display());
                Ok(())
            }
        }
    }
}

fn normalize_workspace_root(workspace: &PathBuf) -> PathBuf {
    let start = if workspace.as_os_str().is_empty() || workspace == &PathBuf::from(".") {
        std::env::var("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
    } else {
        workspace.clone()
    };

    let mut dir = start.as_path();
    loop {
        let manifest = dir.join("Cargo.toml");
        if manifest.exists() {
            if let Ok(s) = std::fs::read_to_string(&manifest) {
                if s.contains("contracts/amm-pool") {
                    return dir.to_path_buf();
                }
            }
        }
        match dir.parent() {
            Some(p) => dir = p,
            None => return start,
        }
    }
}

fn run_cargo(workspace: &PathBuf, args: &[&str]) -> Result<()> {
    let root = normalize_workspace_root(workspace);
    let st = Command::new("cargo")
        .args(args)
        .current_dir(&root)
        .status()
        .map_err(|e| ToolkitError::CompilationFailed(e.to_string()))?;
    if !st.success() {
        return Err(ToolkitError::CompilationFailed(format!(
            "cargo {} failed in {}",
            args.join(" "),
            root.display()
        )));
    }
    Ok(())
}

use crate::error::{Result, ToolkitError};
use clap::Subcommand;
use std::path::{Path, PathBuf};
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
    /// Wallet commands: recovery phrases, keypair derivation, funding, signing
    #[command(subcommand)]
    Wallet(WalletCommand),
    /// Monitoring dashboard for testnet contracts (Horizon + Soroban health, WASM verification)
    #[command(subcommand)]
    Monitoring(MonitoringCommand),
    /// Typed TypeScript client codegen for contract interfaces
    #[command(subcommand)]
    Codegen(CodegenCommand),
}

#[derive(Subcommand, Debug)]
pub enum CodegenCommand {
    /// Generate the typed TypeScript client (deduplicated imports, bigint-safe types)
    Ts {
        /// Contract interface spec in JSON (defaults to the bundled AMM pool spec)
        #[arg(long)]
        spec: Option<PathBuf>,
        /// Output directory for the generated client
        #[arg(long, default_value = "target/ts-client")]
        output: PathBuf,
    },
    /// Run the codegen checks: duplicate imports and bigint integer mapping
    Check {
        /// Contract interface spec in JSON (defaults to the bundled AMM pool spec)
        #[arg(long)]
        spec: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum MonitoringCommand {
    /// Generate a monitoring snapshot (JSON + HTML + Prometheus metrics) for testnet contracts
    Dashboard {
        /// Workspace root
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        /// Output directory for reports
        #[arg(long, default_value = "target/monitoring")]
        output: PathBuf,
        /// Optional checksums file (sha256sum output) to verify WASM hashes
        #[arg(long)]
        checksums: Option<PathBuf>,
        /// Print Prometheus metrics to stdout as well
        #[arg(long, default_value_t = false)]
        print_metrics: bool,
    },
    /// Check endpoint reachability and WASM hash determinism (CI-friendly, exits non-zero on mismatch)
    Check {
        /// Workspace root
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        /// Optional checksums file
        #[arg(long)]
        checksums: Option<PathBuf>,
    },
    /// Verify a saved snapshot against its sha256 manifest (exits non-zero on mismatch)
    Restore {
        /// Snapshot directory containing dashboard.json, metrics.txt, report.html, checksums.sha256
        #[arg(long, default_value = "target/monitoring")]
        snapshot: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub enum WalletCommand {
    /// Generate a 24-word recovery phrase and derive a Stellar keypair
    Generate,
    /// Recover a Stellar keypair from an existing recovery phrase
    Recover {
        /// The BIP-39 recovery phrase (quote it for shell safety)
        phrase: String,
    },
    /// Fund a Stellar account on testnet using the Friendbot faucet
    Fund {
        /// The account id (G...) to fund
        account: String,
    },
    /// Sign a message/transaction envelope (hex) with a secret key (S...)
    Sign {
        /// Stellar secret key (S...)
        secret: String,
        /// Message / transaction envelope as hex
        message: String,
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
            Self::Wallet(wallet) => run_wallet(wallet),
            Self::Monitoring(cmd) => run_monitoring(cmd),
            Self::Codegen(cmd) => run_codegen(cmd),
        }
    }
}

impl CodegenCommand {
    fn spec_path(&self) -> Option<&PathBuf> {
        match self {
            Self::Ts { spec, .. } => spec.as_ref(),
            Self::Check { spec } => spec.as_ref(),
        }
    }
}

fn run_codegen(cmd: &CodegenCommand) -> Result<()> {
    use crate::ts_codegen::{run_checks, ContractSpec, TsClientGenerator};
    let root = normalize_workspace_root(&PathBuf::from("."));
    let spec = match cmd.spec_path() {
        Some(path) => ContractSpec::from_json_file(&resolve_path(&root, path))
            .map_err(|e| ToolkitError::ExecutionError(format!("load spec: {e}")))?,
        None => ContractSpec::amm_pool(),
    };
    match cmd {
        CodegenCommand::Ts { output, .. } => {
            let generator = TsClientGenerator::new(spec);
            let dir = resolve_path(&root, output);
            let paths = generator
                .write_to_dir(&dir)
                .map_err(|e| ToolkitError::ExecutionError(e.to_string()))?;
            println!(
                "Generated {}Client for {} ({} functions)",
                generator.spec().name,
                generator.spec().contract_id,
                generator.spec().functions.len()
            );
            for path in &paths {
                println!("  {}", path.display());
            }
            Ok(())
        }
        CodegenCommand::Check { .. } => {
            let problems = run_checks(&spec);
            for problem in &problems {
                eprintln!("codegen check: {problem}");
            }
            if problems.is_empty() {
                println!("codegen check: PASS (imports deduplicated, 64-bit+ integers as bigint)");
                return Ok(());
            }
            Err(ToolkitError::ExecutionError(format!(
                "{} codegen check problem(s)",
                problems.len()
            )))
        }
    }
}

fn resolve_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn run_wallet(wallet: &WalletCommand) -> Result<()> {
    use crate::wallet;
    match wallet {
        WalletCommand::Generate => {
            let w = wallet::generate_wallet()?;
            print_wallet(&w);
            println!("\n⚠  Write down your recovery phrase and store it somewhere safe. ");
            println!("Anyone with it controls the account. It is shown only once.");
            Ok(())
        }
        WalletCommand::Recover { phrase } => {
            let w = wallet::recover_wallet(phrase)?;
            print_wallet(&w);
            Ok(())
        }
        WalletCommand::Fund { account } => wallet::fund_account(account),
        WalletCommand::Sign { secret, message } => {
            let signature = wallet::sign_message(secret, message)?;
            println!("{signature}");
            Ok(())
        }
    }
}

fn print_wallet(w: &crate::wallet::GeneratedWallet) {
    println!("Recovery phrase:");
    println!("  {}", w.mnemonic);
    println!("Secret key:      {}", w.secret);
    println!("Account (G):     {}", w.account);
}

fn run_monitoring(cmd: &MonitoringCommand) -> Result<()> {
    use crate::monitoring_dashboard::{
        restore_snapshot, MonitorConfig, MonitoringDashboard, SNAPSHOT_CHECKSUMS,
    };
    let root = normalize_workspace_root(&PathBuf::from("."));
    match cmd {
        MonitoringCommand::Dashboard {
            workspace,
            output,
            checksums,
            print_metrics,
        } => {
            let root = normalize_workspace_root(workspace);
            let mut cfg = MonitorConfig::testnet_default();
            if let Some(cs) = checksums {
                let cs_path = if cs.is_absolute() {
                    cs.clone()
                } else {
                    root.join(cs)
                };
                if cs_path.exists() {
                    cfg.load_checksums(&cs_path).map_err(|e| {
                        ToolkitError::ExecutionError(format!("load checksums: {e}"))
                    })?;
                }
            } else {
                // auto-detect common locations
                for cand in [
                    root.join("wasm-checksums.txt"),
                    root.join("dist/wasm-checksums.txt"),
                    root.join("target/reproducible/wasm-checksums.txt"),
                ] {
                    if cand.exists() {
                        let _ = cfg.load_checksums(&cand);
                        break;
                    }
                }
            }
            let dash = MonitoringDashboard::new(cfg, root.clone());
            let out_dir = if output.is_absolute() {
                output.clone()
            } else {
                root.join(output)
            };
            let report = dash.generate_report();
            let (json_path, html_path) = dash
                .write_reports(&out_dir)
                .map_err(|e| ToolkitError::ExecutionError(e.to_string()))?;
            println!("Dashboard report written:");
            println!("  JSON: {}", json_path.display());
            println!("  HTML: {}", html_path.display());
            println!("  Metrics: {}", out_dir.join("metrics.txt").display());
            println!(
                "  Checksums: {}",
                out_dir.join(SNAPSHOT_CHECKSUMS).display()
            );
            println!(
                "Summary: {}/{} healthy, {} hash mismatches",
                report.summary.healthy, report.summary.total, report.summary.hash_mismatches
            );
            if *print_metrics {
                println!(
                    "\n--- Prometheus metrics ---\n{}",
                    dash.prometheus_metrics(&report)
                );
            }
            if report.summary.hash_mismatches > 0 {
                eprintln!("WARNING: WASM hash mismatch detected — run scripts/verify-bytecode.sh");
            }
            Ok(())
        }
        MonitoringCommand::Check {
            workspace,
            checksums,
        } => {
            let root = normalize_workspace_root(workspace);
            let mut cfg = MonitorConfig::testnet_default();
            if let Some(cs) = checksums {
                let cs_path = if cs.is_absolute() {
                    cs.clone()
                } else {
                    root.join(cs)
                };
                cfg.load_checksums(&cs_path)
                    .map_err(|e| ToolkitError::ExecutionError(format!("load checksums: {e}")))?;
            }
            let dash = MonitoringDashboard::new(cfg, root);
            let report = dash.generate_report();
            for c in &report.contracts {
                println!(
                    "{}: {:?} hash_match={:?} horizon={} soroban={}",
                    c.name, c.health, c.hash_match, c.horizon_reachable, c.soroban_reachable
                );
                for a in &c.alerts {
                    eprintln!("  ALERT [{:?}] {}: {}", a.severity, a.rule, a.message);
                }
            }
            if report.summary.hash_mismatches > 0 {
                return Err(ToolkitError::ExecutionError(format!(
                    "hash mismatch in {} contract(s)",
                    report.summary.hash_mismatches
                )));
            }
            Ok(())
        }
        MonitoringCommand::Restore { snapshot } => {
            let dir = resolve_path(&root, snapshot);
            let restore =
                restore_snapshot(&dir).map_err(|e| ToolkitError::ExecutionError(e.to_string()))?;
            println!(
                "Snapshot {}: {} verified, {} mismatched, {} missing",
                restore.snapshot_dir,
                restore.verified.len(),
                restore.mismatched.len(),
                restore.missing.len()
            );
            for file in &restore.verified {
                println!("  OK       {file}");
            }
            for file in &restore.mismatched {
                eprintln!("  MISMATCH {file}");
            }
            for file in &restore.missing {
                eprintln!("  MISSING  {file}");
            }
            if !restore.is_clean() {
                return Err(ToolkitError::ExecutionError(
                    "snapshot restore failed checksum verification".to_string(),
                ));
            }
            Ok(())
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

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
    /// Wallet commands: recovery phrases, keypair derivation, funding, signing
    #[command(subcommand)]
    Wallet(WalletCommand),
    /// Monitoring dashboard for testnet contracts (Horizon + Soroban health, WASM verification)
    #[command(subcommand)]
    Monitoring(MonitoringCommand),
    /// Look up a term in docs/GLOSSARY.md
    #[command(subcommand)]
    Glossary(GlossaryCommand),
    /// Migration tooling for contract interface changes
    #[command(subcommand)]
    Migration(MigrationCommand),
}

/// Output shape for `migration diff`.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationFormat {
    /// Human-readable report.
    Text,
    /// Machine-readable JSON.
    Json,
}

#[derive(Subcommand, Debug)]
pub enum MigrationCommand {
    /// Diff two contract interface snapshots and report what changed
    Diff {
        /// The "before" contract spec JSON
        before: PathBuf,
        /// The "after" contract spec JSON
        after: PathBuf,
        /// Output format
        #[arg(long, value_enum, default_value = "text")]
        format: MigrationFormat,
        /// Exit non-zero when a breaking change is found
        #[arg(long, default_value_t = false)]
        fail_on_breaking: bool,
    },
}

/// Output shape for `glossary lookup`.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlossaryFormat {
    /// Decorated block, meant for a terminal. The default when stdout is a TTY.
    Human,
    /// One `Term: definition` line per match, for grep and scripts.
    Plain,
    /// Machine-readable JSON.
    Json,
}

#[derive(Subcommand, Debug)]
pub enum GlossaryCommand {
    /// Show the definition of a glossary term
    Lookup {
        /// The term to look up (quote multi-word terms)
        term: String,
        /// Path to the glossary Markdown (default: auto-discover docs/GLOSSARY.md)
        #[arg(long)]
        glossary: Option<PathBuf>,
        /// Output format (default: human on a terminal, plain when piped)
        #[arg(long, value_enum)]
        format: Option<GlossaryFormat>,
    },
    /// List every glossary term with its anchor
    List {
        /// Path to the glossary Markdown (default: auto-discover docs/GLOSSARY.md)
        #[arg(long)]
        glossary: Option<PathBuf>,
        /// Output format
        #[arg(long, value_enum)]
        format: Option<GlossaryFormat>,
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
            Self::Glossary(cmd) => run_glossary(cmd),
            Self::Migration(cmd) => run_migration(cmd),
        }
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
    use crate::monitoring_dashboard::{MonitorConfig, MonitoringDashboard};
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
    }
}

fn run_glossary(cmd: &GlossaryCommand) -> Result<()> {
    use crate::glossary::{self, Glossary, GlossaryEntry, Lookup};
    use std::io::IsTerminal;

    let (glossary_path, term, format) = match cmd {
        GlossaryCommand::Lookup {
            term,
            glossary: path,
            format,
        } => (path, Some(term.as_str()), *format),
        GlossaryCommand::List {
            glossary: path,
            format,
        } => (path, None, *format),
    };

    let path = glossary::discover(glossary_path.as_deref())?;
    let book = Glossary::from_path(&path)?;

    // Decorate only when a human is actually looking at the terminal; the
    // moment stdout is a pipe or a file, drop to plain so `grep` and `jq` work.
    let stdout = std::io::stdout();
    let format = format.unwrap_or(if stdout.is_terminal() {
        GlossaryFormat::Human
    } else {
        GlossaryFormat::Plain
    });

    match term {
        Some(term) => {
            let Lookup {
                entry,
                kind,
                also_matches,
            } = book.lookup(term).ok_or_else(|| {
                // A miss is a failure, not an empty success. Suggestions go to
                // stderr so stdout stays clean for the caller.
                let suggestions = book.suggestions(term, 3);
                if !suggestions.is_empty() {
                    let names: Vec<&str> = suggestions.iter().map(|e| e.term.as_str()).collect();
                    eprintln!("No glossary term matches `{term}`.");
                    eprintln!("Did you mean: {}?", names.join(", "));
                    eprintln!("Try `stellar-toolkit glossary list` for all terms.");
                } else {
                    eprintln!("No glossary term matches `{term}`.");
                    eprintln!("Try `stellar-toolkit glossary list` for all terms.");
                }
                ToolkitError::Glossary(format!("no glossary term matches `{term}`"))
            })?;

            match format {
                GlossaryFormat::Json => {
                    let payload = serde_json::json!({
                        "query": term,
                        "match": kind.label(),
                        "entry": entry,
                        "also_matches": also_matches,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&payload)
                            .map_err(|e| ToolkitError::Glossary(e.to_string()))?
                    );
                }
                GlossaryFormat::Plain => {
                    println!("{}: {}", entry.term, entry.definition);
                    for other in &also_matches {
                        println!("{}: {}", other.term, other.definition);
                    }
                }
                GlossaryFormat::Human => {
                    println!("{}", entry.term);
                    println!("{}", "=".repeat(entry.term.chars().count()));
                    println!("{}", entry.definition);
                    println!();
                    println!("anchor: #{}", entry.anchor);
                    if kind != crate::glossary::MatchKind::Exact {
                        println!("matched by: {} (for `{term}`)", kind.label());
                    }
                    if !also_matches.is_empty() {
                        let names: Vec<&str> =
                            also_matches.iter().map(|e| e.term.as_str()).collect();
                        println!("see also: {}", names.join(", "));
                    }
                }
            }
            Ok(())
        }
        None => {
            let entries: Vec<&GlossaryEntry> = book.entries.iter().collect();
            match format {
                GlossaryFormat::Json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&book.entries)
                            .map_err(|e| ToolkitError::Glossary(e.to_string()))?
                    );
                }
                GlossaryFormat::Plain => {
                    for e in entries {
                        println!("{}: {}", e.term, e.definition);
                    }
                }
                GlossaryFormat::Human => {
                    println!("Glossary terms ({}):", entries.len());
                    for e in entries {
                        println!("  {:<40} #{}", e.term, e.anchor);
                    }
                }
            }
            Ok(())
        }
    }
}

fn run_migration(cmd: &MigrationCommand) -> Result<()> {
    use crate::migration_diff;

    match cmd {
        MigrationCommand::Diff {
            before,
            after,
            format,
            fail_on_breaking,
        } => {
            let diff = migration_diff::diff_files(before, after)?;
            match format {
                MigrationFormat::Json => println!("{}", migration_diff::render_json(&diff)?),
                MigrationFormat::Text => print!("{}", migration_diff::render_text(&diff)),
            }
            if *fail_on_breaking && diff.is_breaking() {
                return Err(ToolkitError::ExecutionError(format!(
                    "{} breaking change(s) detected between {} and {}",
                    diff.breaking_lines().len(),
                    before.display(),
                    after.display()
                )));
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

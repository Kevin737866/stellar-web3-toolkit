use crate::error::{Result, ToolkitError};
use crate::help_text;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Top level `stellar-toolkit` command line interface.
///
/// `disable_help_subcommand` is required because this crate implements `help`
/// itself (`help_text::render_command_help`): clap must not add its own,
/// unwrapped, `help` subcommand on top of it.
#[derive(Parser, Debug)]
#[command(
    name = "stellar-toolkit",
    version,
    about = "Build and test Soroban AMM contracts",
    disable_help_subcommand = true
)]
pub struct App {
    #[command(subcommand)]
    pub cmd: ToolkitCommand,
}

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
    /// Scaffold a Soroban contract project from the built-in template
    #[command(subcommand)]
    Scaffold(ScaffoldCommand),
    /// Estimate Soroban transaction fees and plan fee bumps
    #[command(subcommand)]
    Gas(GasCommand),
    /// Inspect contract state with cursor based pagination
    #[command(subcommand)]
    Inspect(InspectCommand),
    /// Print the command overview wrapped to the terminal width
    Help {
        /// Wrap width in columns (defaults to $COLUMNS, otherwise 100)
        #[arg(long, default_value_t = 0)]
        width: usize,
    },
}

#[derive(Subcommand, Debug)]
pub enum ScaffoldCommand {
    /// Render the contract template, lint it, then write it to disk
    New {
        /// Crate name in kebab-case (e.g. amm-pool)
        name: String,
        /// Directory that will contain the generated project
        #[arg(long, default_value = "target/scaffold")]
        out: PathBuf,
        /// `description` field of the generated Cargo.toml
        #[arg(long)]
        description: Option<String>,
        /// `authors` field of the generated Cargo.toml
        #[arg(long)]
        author: Option<String>,
        /// Skip the generated test module
        #[arg(long, default_value_t = false)]
        no_tests: bool,
        /// Lint and print the report without writing any file
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Overwrite files that already exist
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Lint an existing project directory against the template rules
    Lint {
        /// Project directory to lint
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub enum GasCommand {
    /// Estimate the fee for a transaction profile and print the fee bump ladder
    Estimate {
        /// Number of transaction operations
        #[arg(long, default_value_t = 1)]
        operations: u32,
        /// Soroban instructions executed by the transaction
        #[arg(long, default_value_t = 100_000)]
        instructions: u32,
        /// Ledger entries in the read footprint
        #[arg(long, default_value_t = 3)]
        reads: u32,
        /// Ledger entries in the write footprint
        #[arg(long, default_value_t = 1)]
        writes: u32,
        /// Ledgers to wait for inclusion (inclusion bid)
        #[arg(long, default_value_t = 1)]
        bid_ledgers: u32,
        /// Network base fee in stroops (overrides the default schedule)
        #[arg(long)]
        base_fee: Option<u32>,
        /// Percentage added to the fee on every bump (overrides the default schedule)
        #[arg(long)]
        bump_percent: Option<u32>,
        /// Maximum number of fee bumps (overrides the default schedule)
        #[arg(long)]
        max_bumps: Option<u32>,
    },
}

#[derive(Subcommand, Debug)]
pub enum InspectCommand {
    /// Print contract state entries page by page
    State {
        /// Contract id to inspect (all contracts when omitted)
        #[arg(long)]
        contract: Option<String>,
        /// Only entries whose key starts with this prefix
        #[arg(long)]
        key_prefix: Option<String>,
        /// Include temporary entries (they are restored on ledger rollback)
        #[arg(long, default_value_t = false)]
        include_temporary: bool,
        /// Entries per page (max 200)
        #[arg(long, default_value_t = 20)]
        page_size: usize,
        /// Cursor returned by the previous page
        #[arg(long, default_value_t = 0)]
        cursor: usize,
        /// JSON state export to read instead of the built-in sample
        #[arg(long)]
        input: Option<PathBuf>,
        /// Print every page instead of a single one
        #[arg(long, default_value_t = false)]
        all_pages: bool,
        /// Print the page as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
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
            Self::Scaffold(cmd) => run_scaffold(cmd),
            Self::Gas(cmd) => run_gas(cmd),
            Self::Inspect(cmd) => run_inspect(cmd),
            Self::Help { width } => {
                let resolved = if *width == 0 {
                    help_text::help_width()
                } else {
                    *width
                };
                print!("{}", help_text::render_command_help(resolved));
                Ok(())
            }
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
    print!(
        "{}",
        crate::wallet::format_wallet_summary(w, &crate::theme::Theme::from_env())
    );
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

fn run_scaffold(cmd: &ScaffoldCommand) -> Result<()> {
    use crate::scaffolder::{lint_directory, ScaffoldOptions, Scaffolder};
    match cmd {
        ScaffoldCommand::New {
            name,
            out,
            description,
            author,
            no_tests,
            dry_run,
            force,
        } => {
            let mut options = ScaffoldOptions::new(name.clone()).with_tests(!no_tests);
            if let Some(description) = description {
                options = options.with_description(description.clone());
            }
            if let Some(author) = author {
                options = options.with_author(author.clone());
            }
            let scaffolder = Scaffolder::new(options);
            let (files, report) = scaffolder.render_and_lint();
            print!("{}", report.render());
            if !report.passed() {
                return Err(ToolkitError::ExecutionError(format!(
                    "template lint failed with {} error(s)",
                    report.errors()
                )));
            }
            if *dry_run {
                for file in &files {
                    println!("would write {}", file.path);
                }
                return Ok(());
            }
            let root = resolve_path(out);
            for path in scaffolder.write(&root, *force)? {
                println!("wrote {}", path.display());
            }
            println!("project scaffolded in {}", root.display());
            Ok(())
        }
        ScaffoldCommand::Lint { dir } => {
            let root = resolve_path(dir);
            let report = lint_directory(&root)?;
            print!("{}", report.render());
            if !report.passed() {
                return Err(ToolkitError::ExecutionError(format!(
                    "template lint failed with {} error(s)",
                    report.errors()
                )));
            }
            Ok(())
        }
    }
}

fn run_gas(cmd: &GasCommand) -> Result<()> {
    use crate::gas_simulator::{format_stroops, FeeSchedule, GasSimulator, TransactionProfile};
    match cmd {
        GasCommand::Estimate {
            operations,
            instructions,
            reads,
            writes,
            bid_ledgers,
            base_fee,
            bump_percent,
            max_bumps,
        } => {
            let mut schedule = FeeSchedule::testnet_default();
            if let Some(base_fee) = base_fee {
                schedule.base_fee_stroops = *base_fee;
            }
            if let Some(bump_percent) = bump_percent {
                schedule.bump_percent = *bump_percent;
            }
            if let Some(max_bumps) = max_bumps {
                schedule.max_bumps = *max_bumps;
            }
            let base_fee = schedule.base_fee_stroops;
            let max_fee = schedule.max_fee_stroops;

            let simulator = GasSimulator::new(schedule);
            let profile = TransactionProfile {
                operations: *operations,
                instructions: *instructions,
                ledger_reads: *reads,
                ledger_writes: *writes,
                bid_ledgers: *bid_ledgers,
            };
            let estimate = simulator.estimate(&profile);
            let breakdown = estimate.breakdown;
            println!("fee estimate for {} operation(s):", profile.operations);
            println!(
                "  base fee      {:>10} stroops  ({})",
                breakdown.base_fee,
                format_stroops(breakdown.base_fee)
            );
            println!(
                "  resource fee  {:>10} stroops  ({})",
                breakdown.resource_fee,
                format_stroops(breakdown.resource_fee)
            );
            println!(
                "  inclusion bid {:>10} stroops  ({}, {} ledger(s))",
                breakdown.inclusion_bid,
                format_stroops(breakdown.inclusion_bid),
                estimate.bid_ledgers
            );
            println!(
                "  per operation {:>10} stroops  ({})",
                breakdown.per_operation,
                format_stroops(breakdown.per_operation)
            );
            println!(
                "  total         {:>10} stroops  ({:.7} XLM)",
                estimate.total_stroops,
                estimate.total_xlm()
            );

            let inner = estimate.total_stroops;
            let bump = simulator.fee_bump(inner, inner, base_fee)?;
            println!(
                "resubmission at base fee {base_fee} stroops: outer fee {} stroops ({}), +{}% over the signed fee",
                bump.fee_source_pays(),
                format_stroops(bump.fee_source_pays()),
                bump.percent_over_signed_fee()
            );

            let ladder = simulator.bump_ladder(inner);
            if ladder.is_empty() {
                println!("fee bump ladder: no bump possible below the {max_fee} stroop cap");
            } else {
                println!(
                    "fee bump ladder ({} attempt(s), cap {max_fee} stroops):",
                    ladder.len()
                );
                for (attempt, step) in ladder.iter().enumerate() {
                    println!(
                        "  attempt {}: {} -> {} stroops ({}), +{}%",
                        attempt + 1,
                        step.inner_fee_stroops,
                        step.fee_source_pays(),
                        format_stroops(step.fee_source_pays()),
                        step.percent_over_signed_fee()
                    );
                }
            }
            if !simulator.is_bumpable(inner) {
                println!("warning: current fee already sits on the {max_fee} stroop cap");
            }
            Ok(())
        }
    }
}

fn run_inspect(cmd: &InspectCommand) -> Result<()> {
    use crate::state_inspector::{StateInspector, StateQuery};
    match cmd {
        InspectCommand::State {
            contract,
            key_prefix,
            include_temporary,
            page_size,
            cursor,
            input,
            all_pages,
            json,
        } => {
            let inspector = match input {
                Some(input) => {
                    let path = resolve_path(input);
                    let mut from_file = StateInspector::new();
                    let added = from_file.load(&path)?;
                    println!("loaded {added} state entry/entries from {}", path.display());
                    from_file
                }
                None => StateInspector::sample(),
            };
            if inspector.is_empty() {
                return Err(ToolkitError::ExecutionError(
                    "no state entries to inspect".to_string(),
                ));
            }

            let mut query = StateQuery::new()
                .with_page_size(*page_size)
                .with_cursor(*cursor)
                .including_temporary(*include_temporary);
            if let Some(contract) = contract {
                query = query.for_contract(contract.clone());
            }
            if let Some(prefix) = key_prefix {
                query = query.with_key_prefix(prefix.clone());
            }
            println!(
                "filter matched {} of {} entries",
                inspector.total(&query),
                inspector.len()
            );

            if *all_pages {
                for (index, page) in inspector.pages(&query).iter().enumerate() {
                    if index > 0 {
                        println!();
                    }
                    if *json {
                        println!("{}", page.to_json());
                    } else {
                        print!("{}", page.render());
                    }
                }
                return Ok(());
            }

            let page = inspector.page(&query);
            if *json {
                println!("{}", page.to_json());
                return Ok(());
            }
            print!("{}", page.render());
            if let Some(next) = page.next_cursor {
                println!("pass --cursor {next} to continue");
            }
            Ok(())
        }
    }
}

fn resolve_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    cwd.join(path)
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

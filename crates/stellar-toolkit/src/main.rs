//! Stellar Web3 Toolkit — builds and tests Soroban AMM workspace contracts.
//!
//! The binary is deliberately thin: every module lives in the library, so the
//! CLI and `stellar_toolkit::*` consumers can never disagree about which
//! modules exist. This file used to re-declare its own `mod` list, which
//! silently dropped modules that the CLI itself referenced.
use clap::Parser;
use stellar_toolkit::cli::App;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app = App::parse();
    info!("{:?}", app.cmd);
    if let Err(error) = app.cmd.run() {
        // Issue #331: this is the last place an error message leaves the
        // process, so it is redacted here rather than at every construction
        // site. A failure that quotes the offending value — a secret key pasted
        // where an account id belonged, say — would otherwise print that value
        // into a terminal, a CI log or a shell transcript.
        //
        // `Display` (not `Debug`) is used so the output is one actionable line
        // instead of the enum variant's debug representation.
        eprintln!("Error: {}", error.redacted());
        std::process::exit(1);
    }
}

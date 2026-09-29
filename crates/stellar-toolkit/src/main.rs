//! Stellar Web3 Toolkit — builds and tests Soroban AMM workspace contracts.
//!
//! The binary is deliberately thin: every module lives in the library, so the
//! CLI and `stellar_toolkit::*` consumers can never disagree about which
//! modules exist. This file used to re-declare its own `mod` list, which
//! silently dropped modules that the CLI itself referenced.
use clap::Parser;
use stellar_toolkit::cli::App;
use stellar_toolkit::error::Result;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app = App::parse();
    info!("{:?}", app.cmd);
    app.cmd.run()?;
    Ok(())
}

//! Stellar Web3 Toolkit — builds and tests Soroban AMM workspace contracts.
use clap::Parser;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod cli;
mod error;
mod gas_simulator;
mod help_text;
mod monitoring_dashboard;
mod scaffolder;
mod state_inspector;
mod wallet;

use crate::cli::App;
use crate::error::Result;

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

//! Stellar Web3 Toolkit — builds and tests Soroban AMM workspace contracts.
use clap::Parser;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod cli;
mod error;

use crate::cli::ToolkitCommand;
use crate::error::Result;

#[derive(Parser)]
#[command(name = "stellar-toolkit", version, about = "Build and test Soroban AMM contracts")]
struct App {
    #[command(subcommand)]
    cmd: ToolkitCommand,
}

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

use clap::{Parser, Subcommand};
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod cli;
mod compiler;
mod deployer;
mod tester;
mod config;
mod error;
mod utils;

use crate::cli::Cli;
use crate::error::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(cmd) => {
            info!("Executing command: {:?}", cmd);
            cmd.execute().await
        }
        None => {
            error!("No command specified");
            Ok(())
        }
    }
}

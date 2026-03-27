use atomic_swap::{AtomicSwapCoordinator, SwapConfig, SwapRequest};
use atomic_swap::asset::{Asset, AssetInfo};
use atomic_swap::monitor::MonitoringConfig;
use tracing::{info, error};
use tracing_subscriber;
use std::collections::HashMap;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    info!("Starting Stellar Atomic Swap Service");

    // Create configuration
    let swap_config = SwapConfig {
        default_timeout_hours: 24,
        max_timeout_hours: 168,
        min_amount: 1,
        max_amount: i128::MAX / 2,
        enable_multi_hop: true,
        fee_percentage: 0.1,
    };

    // Initialize coordinator
    let coordinator = AtomicSwapCoordinator::new(swap_config);

    // Register common assets
    coordinator.register_asset(AssetInfo::xlm()).await?;
    coordinator.register_asset(AssetInfo::custom(
        "USDC".to_string(),
        "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_string(),
        7,
    )).await?;

    // Start monitoring
    coordinator.start_monitoring().await?;

    // Example swap creation
    let request = SwapRequest {
        participant: "GD5J6QF7GHXQUSWNSKN2UE4XENIH2NQCAQPQZJ56YRCZBKZWD4FAACEF".to_string(),
        initiator_asset: Asset::XLM,
        participant_asset: Asset::Custom("USDC".to_string()),
        initiator_amount: 10000000, // 1 XLM in stroops
        participant_amount: 9500000, // 0.95 USDC
        timeout_hours: 24,
        metadata: {
            let mut meta = HashMap::new();
            meta.insert("purpose".to_string(), "test_swap".to_string());
            meta
        },
    };

    let initiator = "GA5XIGA5C7QTPTWXQHY6MCJRMTRZDOSHR6EFIBNDQTCQDG267H5CH4H2".to_string();

    match coordinator.initiate_swap(initiator, request).await {
        Ok(response) => {
            info!("Swap initiated successfully!");
            info!("Swap ID: {}", response.swap_id);
            info!("Hash Lock: {}", response.hash_lock);
            info!("Timeout Ledger: {}", response.timeout_ledger);
        }
        Err(e) => {
            error!("Failed to initiate swap: {}", e);
        }
    }

    // Keep the service running
    tokio::signal::ctrl_c().await?;
    info!("Shutting down Atomic Swap Service");

    Ok(())
}

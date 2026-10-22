use thiserror::Error;

pub type Result<T> = std::result::Result<T, AtomicSwapError>;

#[derive(Error, Debug)]
pub enum AtomicSwapError {
    #[error("Swap not found: {swap_id}")]
    SwapNotFound { swap_id: String },

    #[error("Invalid preimage for swap: {swap_id}")]
    InvalidPreimage { swap_id: String },

    #[error("Swap has expired: {swap_id}")]
    SwapExpired { swap_id: String },

    #[error("Swap already completed: {swap_id}")]
    SwapAlreadyCompleted { swap_id: String },

    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: i128, available: i128 },

    #[error("Asset not supported: {asset}")]
    UnsupportedAsset { asset: String },

    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Stellar RPC error: {0}")]
    StellarRpcError(String),

    #[error("Invalid timeout: {timeout_hours} hours")]
    InvalidTimeout { timeout_hours: u32 },

    #[error("Invalid amount: {amount}")]
    InvalidAmount { amount: i128 },

    #[error("Invalid address: {address}")]
    InvalidAddress { address: String },

    #[error("Preimage generation failed: {0}")]
    PreimageGenerationError(String),

    #[error("Hash computation failed: {0}")]
    HashComputationError(String),

    #[error("Contract interaction failed: {0}")]
    ContractError(String),

    #[error("Transaction failed: {0}")]
    TransactionError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Cross-chain replay protection refused the transfer (#238). The source
    /// variant is preserved so a caller can tell a replay from a chain
    /// mismatch without parsing the message.
    #[error(transparent)]
    Replay(#[from] crate::replay::ReplayError),

    /// Bounded coordination retry budget exhausted for a swap operation (#215).
    #[error(
        "Retry budget exhausted for {operation} on swap {swap_id}: {attempts}/{max_retries} attempts used"
    )]
    RetryBudgetExhausted {
        swap_id: String,
        operation: String,
        attempts: u32,
        max_retries: u32,
    },
}

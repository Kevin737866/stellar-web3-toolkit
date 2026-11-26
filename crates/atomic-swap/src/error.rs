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

    /// An offer was presented for signing at or after its deadline (#389).
    ///
    /// Signing an expired offer would authorise a trade the counterparty can no
    /// longer settle, so the signing path refuses it before computing any
    /// commitment. The deadline and the current ledger are included so the
    /// caller can tell a slightly late attempt from a stale offer.
    #[error(
        "Offer {offer_id} expired at ledger {expires_at_ledger} (signing requested at ledger {current_ledger})"
    )]
    OfferExpired {
        offer_id: String,
        expires_at_ledger: u32,
        current_ledger: u32,
    },

    /// A refund was requested while the swap was still inside its settlement
    /// window, before the timeout ledger had passed (#396).
    ///
    /// At this point the preimage path is still open, so refunding would let a
    /// participant claw back funds while the counterparty could still settle.
    /// The timeout and current ledgers are included so an operator knows exactly
    /// how long to wait.
    ///
    /// Compatibility: this is a new, distinct error. Before #396 the refund path
    /// returned `SwapExpired` for this case, which claimed a timeout that had
    /// not happened.
    #[error(
        "Cannot refund swap {swap_id}: timeout ledger {timeout_ledger} has not passed (current ledger {current_ledger})"
    )]
    RefundBeforeTimeout {
        swap_id: String,
        timeout_ledger: u32,
        current_ledger: u32,
    },

    #[error("Swap already completed: {swap_id}")]
    SwapAlreadyCompleted { swap_id: String },

    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: i128, available: i128 },

    #[error("Asset not supported: {asset}")]
    UnsupportedAsset { asset: String },

    /// An asset identifier is not a well-formed Stellar asset (#388).
    ///
    /// An offer is signed off-chain and settled on-chain, so a malformed code or
    /// issuer cannot be caught by the chain at signing time: it would be
    /// discovered only after a counterparty had committed. The offer path
    /// therefore rejects it up front, naming the asset and the defect.
    #[error("Invalid asset identifier `{asset}`: {reason}")]
    InvalidAssetIdentifier { asset: String, reason: String },

    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Stellar RPC error: {0}")]
    StellarRpcError(String),

    #[error("Invalid timeout: {timeout_hours} hours")]
    InvalidTimeout { timeout_hours: u32 },

    /// An offer's expiry ledger does not leave a usable window (#388).
    ///
    /// An offer that expires at or before the ledger it was created at can
    /// never be accepted, so it is refused instead of being advertised.
    #[error(
        "Invalid offer expiry: expires_at_ledger {expires_at_ledger} must be later than created_at_ledger {created_at_ledger}"
    )]
    InvalidOfferExpiry {
        created_at_ledger: u32,
        expires_at_ledger: u32,
    },

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

    /// An idempotency key was malformed (#212).
    #[error("Invalid idempotency key: {reason}")]
    InvalidIdempotencyKey { reason: String },

    /// An idempotency key was already bound to a different initiation (#212).
    #[error("Idempotency key `{key}` is already bound to a different swap request")]
    IdempotencyConflict { key: String },

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

    /// A state transition could not be persisted before it was applied (#390).
    ///
    /// The transition is *not* applied when this is returned: the journal is the
    /// source of truth, so a record that cannot be written must stop the
    /// transition rather than leave memory and disk disagreeing.
    #[error(transparent)]
    Journal(#[from] crate::journal::JournalError),
}

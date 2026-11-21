//! # Payment Channel Library
//!
//! High-level library for managing Stellar payment channels.
//! This library provides a Rust API for creating, managing, and closing
//! payment channels, as well as executing off-chain payments.

pub mod reorg;

use parking_lot::RwLock;
use reorg::{ReorgError, ReorgLog};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use thiserror::Error;

/// Payment channel errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PaymentChannelError {
    #[error("Channel not found: {0}")]
    ChannelNotFound(String),

    #[error("Insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: i128, need: i128 },

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Signature error: {0}")]
    SignatureError(String),

    #[error("HTLC error: {0}")]
    HtlcError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Channel closed: {0}")]
    ChannelClosed(String),

    #[error(
        "Reorg detected on channel {channel_id}: update at ledger height {incoming} is not after the recorded height {recorded}"
    )]
    ReorgDetected {
        channel_id: String,
        recorded: u32,
        incoming: u32,
    },

    #[error(
        "Channel {channel_id} has no state at or below ledger height {height}; resync from chain is required"
    )]
    NoStateForReorg { channel_id: String, height: u32 },

    #[error("Unauthorized participant: {0}")]
    UnauthorizedParticipant(String),
}

/// Channel status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelStatus {
    /// Channel is open and ready for payments
    Open,
    /// Channel is being closed cooperatively
    Closing,
    /// Channel was closed cooperatively
    Closed,
    /// Channel was force-closed
    ForceClosed,
    /// Channel is in dispute
    Dispute,
}

/// Local channel state for a participant
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalChannelState {
    /// Channel ID
    pub channel_id: String,
    /// Our address
    pub our_address: String,
    /// Their address
    pub their_address: String,
    /// Our current balance
    pub our_balance: i128,
    /// Their current balance
    pub their_balance: i128,
    /// Channel status
    pub status: ChannelStatus,
    /// Current sequence number
    pub sequence_number: u32,
    /// Funding transaction hash
    pub funding_tx_hash: Option<String>,
    /// Closing transaction hash (if closed)
    pub closing_tx_hash: Option<String>,
    /// Channel timeout (for unilateral close)
    pub timeout: u32,
    /// Fee percentage for routing
    pub fee_percentage: u32,
    /// Pending HTLCs
    pub pending_htlcs: Vec<HtlcState>,
    /// Local secret for signing
    pub local_secret: Vec<u8>,
    /// Remote public key
    pub remote_public_key: Vec<u8>,
}

/// HTLC state
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HtlcState {
    /// HTLC ID
    pub htlc_id: String,
    /// Amount
    pub amount: i128,
    /// Hash lock
    pub hashlock: Vec<u8>,
    /// Time lock
    pub timelock: u32,
    /// Whether we've claimed it
    pub is_claimed: bool,
    /// Whether we've refunded it
    pub is_refunded: bool,
    /// The preimage (if we know it)
    pub preimage: Option<Vec<u8>>,
    /// Direction (incoming/outgoing)
    pub direction: HtlcDirection,
}

/// HTLC direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HtlcDirection {
    /// HTLC is incoming (they're paying us)
    Incoming,
    /// HTLC is outgoing (we're paying them)
    Outgoing,
}

/// Payment request
#[derive(Debug, Clone)]
pub struct PaymentRequest {
    /// Amount to pay
    pub amount: i128,
    /// Payment identifier (for idempotency)
    pub payment_id: Option<String>,
    /// Optional memo
    pub memo: Option<Vec<u8>>,
    /// Custom hashlock (for keysend-style payments)
    pub custom_hashlock: Option<Vec<u8>>,
    /// CLTV delta for the HTLC
    pub cltv_delta: Option<u32>,
}

/// Payment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentResult {
    /// Whether the payment succeeded
    pub success: bool,
    /// Preimage (for received HTLCs)
    pub preimage: Option<Vec<u8>>,
    /// HTLC ID (if applicable)
    pub htlc_id: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// What a reorg did to the manager's channels
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgReport {
    /// The height the chain forked at.
    pub fork_height: u32,
    /// Channels restored from a snapshot at or below the fork height.
    pub rolled_back: Vec<String>,
    /// Channels with no snapshot at or below the fork height. Their local
    /// state is unknown and must be re-read from chain.
    pub unresolved: Vec<String>,
    /// Snapshots above the fork height that were discarded.
    pub dropped_snapshots: usize,
}

impl ReorgReport {
    /// Whether the reorg was fully reconciled without a chain resync.
    pub fn is_clean(&self) -> bool {
        self.unresolved.is_empty()
    }
}

/// Local channel state plus the per-channel snapshot history needed to unwind
/// it when the ledger it was built on disappears.
struct TrackedChannel {
    state: LocalChannelState,
    history: ReorgLog,
}

/// Channel manager for handling all channel operations
pub struct ChannelManager {
    /// Local channel states, each with its reorg history
    channels: RwLock<HashMap<String, TrackedChannel>>,
    /// Signer for creating signatures
    signer: Box<dyn SignatureSigner>,
    /// Highest ledger height applied so far, used by the height-agnostic
    /// [`ChannelManager::execute_payment`] entry point.
    ledger_height: AtomicU32,
    /// How many past heights to retain per channel.
    history_depth: u32,
}

/// Signature signer trait
pub trait SignatureSigner: Send + Sync {
    /// Sign a message
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PaymentChannelError>;

    /// Verify a signature
    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, PaymentChannelError>;

    /// Get the public key
    fn public_key(&self) -> Vec<u8>;
}

impl ChannelManager {
    /// Create a new channel manager with the default reorg history depth
    pub fn new(signer: Box<dyn SignatureSigner>) -> Self {
        Self::with_history_depth(signer, reorg::DEFAULT_REORG_HISTORY_DEPTH)
    }

    /// Create a new channel manager that retains `history_depth` ledgers of
    /// channel state for reorg rollback.
    pub fn with_history_depth(signer: Box<dyn SignatureSigner>, history_depth: u32) -> Self {
        ChannelManager {
            channels: RwLock::new(HashMap::new()),
            signer,
            ledger_height: AtomicU32::new(0),
            history_depth,
        }
    }

    /// Create a new payment channel
    pub async fn create_channel(
        &self,
        our_address: String,
        their_address: String,
        our_initial_balance: i128,
        their_initial_balance: i128,
        timeout: u32,
        fee_percentage: u32,
    ) -> Result<LocalChannelState, PaymentChannelError> {
        // Generate channel ID
        let channel_id = Self::generate_channel_id(&our_address, &their_address);

        // Create local state
        let state = LocalChannelState {
            channel_id: channel_id.clone(),
            our_address: our_address.clone(),
            their_address: their_address.clone(),
            our_balance: our_initial_balance,
            their_balance: their_initial_balance,
            status: ChannelStatus::Open,
            sequence_number: 0,
            funding_tx_hash: None,
            closing_tx_hash: None,
            timeout,
            fee_percentage,
            pending_htlcs: Vec::new(),
            local_secret: self.signer.public_key(),
            remote_public_key: Vec::new(), // Will be set during handshake
        };

        // Store the channel, anchored with a genesis snapshot so that a reorg
        // below every applied update still has something to restore. Height 0
        // also matches the funding height the channel is created at.
        let mut history = ReorgLog::new(self.history_depth);
        history
            .record(0, state.clone())
            .expect("an empty history log accepts any height");

        self.channels.write().insert(
            channel_id,
            TrackedChannel {
                state: state.clone(),
                history,
            },
        );

        Ok(state)
    }

    /// Execute an off-chain payment at the next inferred ledger height.
    ///
    /// Prefer [`ChannelManager::execute_payment_at`] when the caller knows the
    /// real ledger height: a reorg can only be reconciled against heights that
    /// come from the chain.
    pub fn execute_payment(
        &self,
        channel_id: &str,
        amount: i128,
        direction: PaymentDirection,
    ) -> Result<LocalChannelState, PaymentChannelError> {
        let ledger_height = self.next_ledger_height();
        self.execute_payment_at(channel_id, amount, direction, ledger_height)
    }

    /// Execute an off-chain payment observed at `ledger_height`.
    ///
    /// The resulting state is recorded against that height so a later
    /// [`ChannelManager::handle_reorg`] can unwind it.
    pub fn execute_payment_at(
        &self,
        channel_id: &str,
        amount: i128,
        direction: PaymentDirection,
        ledger_height: u32,
    ) -> Result<LocalChannelState, PaymentChannelError> {
        let mut channels = self.channels.write();
        let channel = channels
            .get_mut(channel_id)
            .ok_or_else(|| PaymentChannelError::ChannelNotFound(channel_id.to_string()))?;

        // Check if channel is open
        if channel.state.status != ChannelStatus::Open {
            return Err(PaymentChannelError::ChannelClosed(
                channel.state.status.to_string(),
            ));
        }

        // Validate the height before touching the balances: a rejected update
        // must leave the channel exactly as it was.
        check_height(channel_id, &channel.history, ledger_height)?;

        // Update balances
        match direction {
            PaymentDirection::ToThem => {
                if channel.state.our_balance < amount {
                    return Err(PaymentChannelError::InsufficientBalance {
                        have: channel.state.our_balance,
                        need: amount,
                    });
                }
                channel.state.our_balance -= amount;
                channel.state.their_balance += amount;
            }
            PaymentDirection::ToUs => {
                if channel.state.their_balance < amount {
                    return Err(PaymentChannelError::InsufficientBalance {
                        have: channel.state.their_balance,
                        need: amount,
                    });
                }
                channel.state.their_balance -= amount;
                channel.state.our_balance += amount;
            }
        }

        channel.state.sequence_number += 1;

        record_state(channel_id, channel, ledger_height)?;

        Ok(channel.state.clone())
    }

    /// Set or update the remote participant's public key for authorization verification.
    pub fn set_remote_public_key(
        &self,
        channel_id: &str,
        remote_public_key: Vec<u8>,
    ) -> Result<(), PaymentChannelError> {
        let mut channels = self.channels.write();
        let channel = channels
            .get_mut(channel_id)
            .ok_or_else(|| PaymentChannelError::ChannelNotFound(channel_id.to_string()))?;
        channel.state.remote_public_key = remote_public_key;
        Ok(())
    }

    /// Sign the channel's current state update for exchange with the counterparty.
    pub fn sign_state_update(
        &self,
        channel_id: &str,
        ledger_height: u32,
    ) -> Result<Vec<u8>, PaymentChannelError> {
        let channels = self.channels.read();
        let channel = channels
            .get(channel_id)
            .ok_or_else(|| PaymentChannelError::ChannelNotFound(channel_id.to_string()))?;

        let digest = compute_state_digest(
            channel_id,
            channel.state.sequence_number,
            &channel.state.our_address,
            channel.state.our_balance,
            &channel.state.their_address,
            channel.state.their_balance,
            ledger_height,
        );

        self.signer.sign(&digest)
    }

    /// Sign a proposed state update commitment.
    pub fn sign_proposed_state(
        &self,
        channel_id: &str,
        sequence_number: u32,
        our_balance: i128,
        their_balance: i128,
        ledger_height: u32,
    ) -> Result<Vec<u8>, PaymentChannelError> {
        let channels = self.channels.read();
        let channel = channels
            .get(channel_id)
            .ok_or_else(|| PaymentChannelError::ChannelNotFound(channel_id.to_string()))?;

        let digest = compute_state_digest(
            channel_id,
            sequence_number,
            &channel.state.our_address,
            our_balance,
            &channel.state.their_address,
            their_balance,
            ledger_height,
        );

        self.signer.sign(&digest)
    }

    /// Apply a state update proposed by the counterparty after validating participant authorization.
    ///
    /// Validates:
    /// 1. Channel exists and is currently Open.
    /// 2. Ledger height is monotonic (reorg safety).
    /// 3. Balance conservation and non-negativity.
    /// 4. Cryptographic signature of the remote participant against `remote_public_key`.
    ///
    /// If verification fails, returns an actionable error and leaves the channel completely untouched.
    pub fn apply_signed_state_update(
        &self,
        channel_id: &str,
        new_our_balance: i128,
        new_their_balance: i128,
        remote_signature: &[u8],
        ledger_height: u32,
    ) -> Result<LocalChannelState, PaymentChannelError> {
        let mut channels = self.channels.write();
        let channel = channels
            .get_mut(channel_id)
            .ok_or_else(|| PaymentChannelError::ChannelNotFound(channel_id.to_string()))?;

        if channel.state.status != ChannelStatus::Open {
            return Err(PaymentChannelError::ChannelClosed(
                channel.state.status.to_string(),
            ));
        }

        if new_our_balance < 0 || new_their_balance < 0 {
            return Err(PaymentChannelError::InvalidState(
                "Balances cannot be negative".to_string(),
            ));
        }

        let expected_total = channel.state.our_balance + channel.state.their_balance;
        if new_our_balance + new_their_balance != expected_total {
            return Err(PaymentChannelError::InvalidState(format!(
                "Total balance mismatch: expected {}, got {}",
                expected_total,
                new_our_balance + new_their_balance
            )));
        }

        check_height(channel_id, &channel.history, ledger_height)?;

        if channel.state.remote_public_key.is_empty() {
            return Err(PaymentChannelError::SignatureError(
                "Remote public key not set for channel".to_string(),
            ));
        }

        let next_sequence = channel.state.sequence_number + 1;
        let digest = compute_state_digest(
            channel_id,
            next_sequence,
            &channel.state.our_address,
            new_our_balance,
            &channel.state.their_address,
            new_their_balance,
            ledger_height,
        );

        let valid = self.signer.verify(
            &digest,
            remote_signature,
            &channel.state.remote_public_key,
        )?;

        if !valid {
            return Err(PaymentChannelError::SignatureError(
                "Invalid participant authorization signature".to_string(),
            ));
        }

        channel.state.our_balance = new_our_balance;
        channel.state.their_balance = new_their_balance;
        channel.state.sequence_number = next_sequence;

        record_state(channel_id, channel, ledger_height)?;

        Ok(channel.state.clone())
    }

    /// Execute an off-chain payment while validating counterparty authorization.
    pub fn execute_authorized_payment_at(
        &self,
        channel_id: &str,
        amount: i128,
        direction: PaymentDirection,
        remote_signature: &[u8],
        ledger_height: u32,
    ) -> Result<LocalChannelState, PaymentChannelError> {
        let (new_our, new_their) = {
            let channels = self.channels.read();
            let channel = channels
                .get(channel_id)
                .ok_or_else(|| PaymentChannelError::ChannelNotFound(channel_id.to_string()))?;

            match direction {
                PaymentDirection::ToThem => {
                    if channel.state.our_balance < amount {
                        return Err(PaymentChannelError::InsufficientBalance {
                            have: channel.state.our_balance,
                            need: amount,
                        });
                    }
                    (
                        channel.state.our_balance - amount,
                        channel.state.their_balance + amount,
                    )
                }
                PaymentDirection::ToUs => {
                    if channel.state.their_balance < amount {
                        return Err(PaymentChannelError::InsufficientBalance {
                            have: channel.state.their_balance,
                            need: amount,
                        });
                    }
                    (
                        channel.state.our_balance + amount,
                        channel.state.their_balance - amount,
                    )
                }
            }
        };

        self.apply_signed_state_update(
            channel_id,
            new_our,
            new_their,
            remote_signature,
            ledger_height,
        )
    }

    /// Anchor the channel's current state at `ledger_height` without changing
    /// it, for updates applied outside this manager (a handshake, an on-chain
    /// confirmation, an imported channel state).
    pub fn record_channel_state(
        &self,
        channel_id: &str,
        ledger_height: u32,
    ) -> Result<(), PaymentChannelError> {
        let mut channels = self.channels.write();
        let channel = channels
            .get_mut(channel_id)
            .ok_or_else(|| PaymentChannelError::ChannelNotFound(channel_id.to_string()))?;

        check_height(channel_id, &channel.history, ledger_height)?;
        record_state(channel_id, channel, ledger_height)
    }

    /// Unwind every channel to the given fork height after a ledger reorg.
    ///
    /// Channels with a snapshot at or below `fork_height` are restored to their
    /// newest such state and all later snapshots are discarded. Channels
    /// without one are reported as unresolved: their local state cannot be
    /// trusted and must be re-read from chain.
    pub fn handle_reorg(&self, fork_height: u32) -> ReorgReport {
        let mut channels = self.channels.write();
        let mut report = ReorgReport {
            fork_height,
            ..Default::default()
        };

        for (channel_id, channel) in channels.iter_mut() {
            let (restored, dropped) = channel.history.rollback_to(fork_height);
            report.dropped_snapshots += dropped;

            match restored {
                Some(state) => {
                    channel.state = state;
                    report.rolled_back.push(channel_id.clone());
                }
                None => report.unresolved.push(channel_id.clone()),
            }
        }

        // `HashMap` iteration order is unspecified; sort the report so callers
        // can diff two reorg events without spurious changes.
        report.rolled_back.sort();
        report.unresolved.sort();

        report
    }

    /// Recorded ledger heights for a channel, oldest first.
    pub fn recorded_heights(&self, channel_id: &str) -> Option<Vec<u32>> {
        self.channels
            .read()
            .get(channel_id)
            .map(|channel| channel.history.heights())
    }

    /// Get a channel by ID
    pub fn get_channel(&self, channel_id: &str) -> Option<LocalChannelState> {
        self.channels
            .read()
            .get(channel_id)
            .map(|channel| channel.state.clone())
    }

    /// Get all channels
    pub fn get_all_channels(&self) -> Vec<LocalChannelState> {
        self.channels
            .read()
            .values()
            .map(|channel| channel.state.clone())
            .collect()
    }

    /// The height a height-agnostic update is attributed to.
    fn next_ledger_height(&self) -> u32 {
        self.ledger_height.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Close a channel cooperatively
    pub fn cooperative_close(
        &self,
        channel_id: &str,
    ) -> Result<LocalChannelState, PaymentChannelError> {
        let mut channels = self.channels.write();
        let state = channels
            .get_mut(channel_id)
            .ok_or_else(|| PaymentChannelError::ChannelNotFound(channel_id.to_string()))?;

        if state.state.status != ChannelStatus::Open {
            return Err(PaymentChannelError::InvalidState(format!(
                "Cannot close channel in state {:?}",
                state.state.status
            )));
        }

        let ledger_height = self.next_ledger_height();
        check_height(channel_id, &state.history, ledger_height)?;
        state.state.status = ChannelStatus::Closing;
        record_state(channel_id, state, ledger_height)?;

        Ok(state.state.clone())
    }

    /// Initiate a unilateral close
    pub fn initiate_unilateral_close(
        &self,
        channel_id: &str,
    ) -> Result<LocalChannelState, PaymentChannelError> {
        let mut channels = self.channels.write();
        let state = channels
            .get_mut(channel_id)
            .ok_or_else(|| PaymentChannelError::ChannelNotFound(channel_id.to_string()))?;

        let ledger_height = self.next_ledger_height();
        check_height(channel_id, &state.history, ledger_height)?;
        state.state.status = ChannelStatus::ForceClosed;
        record_state(channel_id, state, ledger_height)?;

        Ok(state.state.clone())
    }

    /// Rebalance a channel
    pub fn rebalance(
        &self,
        channel_id: &str,
        amount: i128,
    ) -> Result<LocalChannelState, PaymentChannelError> {
        let mut channels = self.channels.write();
        let state = channels
            .get_mut(channel_id)
            .ok_or_else(|| PaymentChannelError::ChannelNotFound(channel_id.to_string()))?;

        if state.state.status != ChannelStatus::Open {
            return Err(PaymentChannelError::InvalidState(
                "Channel not open".to_string(),
            ));
        }

        let ledger_height = self.next_ledger_height();
        check_height(channel_id, &state.history, ledger_height)?;

        // Add funds to both sides (requires on-chain transaction)
        state.state.our_balance += amount;
        state.state.their_balance += amount;
        state.state.sequence_number += 1;
        record_state(channel_id, state, ledger_height)?;

        Ok(state.state.clone())
    }

    /// Generate a deterministic channel ID
    fn generate_channel_id(a: &str, b: &str) -> String {
        use sha2::{Digest, Sha256};

        let mut sorted = [a, b].to_vec();
        sorted.sort();

        let mut hasher = Sha256::new();
        hasher.update(sorted[0].as_bytes());
        hasher.update(sorted[1].as_bytes());
        let result = hasher.finalize();

        hex::encode(result)
    }
}

/// Deterministically compute the SHA-256 digest of a state update commitment.
///
/// Binds channel ID, sequence number, balances, and ledger height under a distinct domain tag.
/// Address ordering is canonicalized so all participants compute the identical digest regardless
/// of local point-of-view.
pub fn compute_state_digest(
    channel_id: &str,
    sequence_number: u32,
    our_address: &str,
    our_balance: i128,
    their_address: &str,
    their_balance: i128,
    ledger_height: u32,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"STELLAR_PAYMENT_CHANNEL_STATE_UPDATE:");
    hasher.update(channel_id.as_bytes());
    hasher.update(&sequence_number.to_be_bytes());
    if our_address <= their_address {
        hasher.update(our_address.as_bytes());
        hasher.update(&our_balance.to_be_bytes());
        hasher.update(their_address.as_bytes());
        hasher.update(&their_balance.to_be_bytes());
    } else {
        hasher.update(their_address.as_bytes());
        hasher.update(&their_balance.to_be_bytes());
        hasher.update(our_address.as_bytes());
        hasher.update(&our_balance.to_be_bytes());
    }
    hasher.update(&ledger_height.to_be_bytes());
    let res = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&res);
    digest
}

/// Reject an update that claims a height the channel has already passed.
///
/// This is the reorg signal at the update level: the chain the earlier state
/// was built on has been replaced, so applying a lower height would silently
/// build two divergent histories into one channel.
fn check_height(
    channel_id: &str,
    history: &ReorgLog,
    ledger_height: u32,
) -> Result<(), PaymentChannelError> {
    match history.last_height() {
        Some(recorded) if ledger_height <= recorded => Err(PaymentChannelError::ReorgDetected {
            channel_id: channel_id.to_string(),
            recorded,
            incoming: ledger_height,
        }),
        _ => Ok(()),
    }
}

/// Anchor the channel's current state at `ledger_height`.
///
/// Callers must run [`check_height`] first so that a rejected height never
/// leaves the channel mutated but unrecorded.
fn record_state(
    channel_id: &str,
    channel: &mut TrackedChannel,
    ledger_height: u32,
) -> Result<(), PaymentChannelError> {
    channel
        .history
        .record(ledger_height, channel.state.clone())
        .map_err(|e| match e {
            ReorgError::NonMonotonicHeight { last, height } => PaymentChannelError::ReorgDetected {
                channel_id: channel_id.to_string(),
                recorded: last,
                incoming: height,
            },
            other => PaymentChannelError::InvalidState(other.to_string()),
        })?;

    Ok(())
}

/// Payment direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentDirection {
    /// Payment to the other party
    ToThem,
    /// Payment from the other party
    ToUs,
}

/// Convert channel status to string
impl std::fmt::Display for ChannelStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelStatus::Open => write!(f, "Open"),
            ChannelStatus::Closing => write!(f, "Closing"),
            ChannelStatus::Closed => write!(f, "Closed"),
            ChannelStatus::ForceClosed => write!(f, "ForceClosed"),
            ChannelStatus::Dispute => write!(f, "Dispute"),
        }
    }
}

/// Hex encoding helper
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(data: impl AsRef<[u8]>) -> String {
        let bytes = data.as_ref();
        let mut result = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            result.push(HEX_CHARS[(b >> 4) as usize] as char);
            result.push(HEX_CHARS[(b & 0xf) as usize] as char);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Signer that accepts anything, so the tests can focus on state handling.
    struct TestSigner;

    impl SignatureSigner for TestSigner {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PaymentChannelError> {
            Ok(message.to_vec())
        }

        fn verify(
            &self,
            _message: &[u8],
            _signature: &[u8],
            _public_key: &[u8],
        ) -> Result<bool, PaymentChannelError> {
            Ok(true)
        }

        fn public_key(&self) -> Vec<u8> {
            vec![7u8; 32]
        }
    }

    async fn manager_with_channel(depth: u32) -> (ChannelManager, String) {
        let manager = ChannelManager::with_history_depth(Box::new(TestSigner), depth);
        let state = manager
            .create_channel("alice".to_string(), "bob".to_string(), 1_000, 1_000, 100, 0)
            .await
            .unwrap();
        (manager, state.channel_id)
    }

    #[tokio::test]
    async fn reorg_rolls_back_payments_above_the_fork_height() {
        let (manager, channel_id) = manager_with_channel(8).await;

        manager
            .execute_payment_at(&channel_id, 100, PaymentDirection::ToThem, 10)
            .unwrap();
        manager
            .execute_payment_at(&channel_id, 100, PaymentDirection::ToThem, 11)
            .unwrap();
        assert_eq!(manager.get_channel(&channel_id).unwrap().our_balance, 800);

        let report = manager.handle_reorg(10);
        assert!(report.is_clean());
        assert_eq!(report.rolled_back, vec![channel_id.clone()]);
        assert_eq!(report.dropped_snapshots, 1);

        let state = manager.get_channel(&channel_id).unwrap();
        assert_eq!(state.our_balance, 900);
        assert_eq!(state.their_balance, 1_100);
        assert_eq!(state.sequence_number, 1);
        assert_eq!(manager.recorded_heights(&channel_id).unwrap(), vec![0, 10]);
    }

    #[tokio::test]
    async fn reorg_to_the_funding_height_restores_the_opening_state() {
        let (manager, channel_id) = manager_with_channel(8).await;

        for height in [10, 11, 12] {
            manager
                .execute_payment_at(&channel_id, 100, PaymentDirection::ToThem, height)
                .unwrap();
        }

        let report = manager.handle_reorg(0);
        assert_eq!(report.rolled_back.len(), 1);

        let state = manager.get_channel(&channel_id).unwrap();
        assert_eq!(state.our_balance, 1_000);
        assert_eq!(state.their_balance, 1_000);
        assert_eq!(state.sequence_number, 0);
    }

    #[tokio::test]
    async fn an_update_at_a_discarded_height_is_rejected() {
        let (manager, channel_id) = manager_with_channel(8).await;

        manager
            .execute_payment_at(&channel_id, 100, PaymentDirection::ToThem, 10)
            .unwrap();
        manager.handle_reorg(10);

        // The same height was already applied on the discarded branch.
        let err = manager
            .execute_payment_at(&channel_id, 100, PaymentDirection::ToThem, 10)
            .unwrap_err();
        assert_eq!(
            err,
            PaymentChannelError::ReorgDetected {
                channel_id: channel_id.clone(),
                recorded: 10,
                incoming: 10,
            }
        );

        // A rejected update leaves the channel untouched.
        assert_eq!(manager.get_channel(&channel_id).unwrap().our_balance, 900);

        // The next height on the new chain is accepted.
        manager
            .execute_payment_at(&channel_id, 100, PaymentDirection::ToThem, 11)
            .unwrap();
        assert_eq!(manager.get_channel(&channel_id).unwrap().our_balance, 800);
    }

    #[tokio::test]
    async fn a_reorg_below_the_retained_history_is_unresolved() {
        let (manager, channel_id) = manager_with_channel(2).await;

        for height in [10, 11, 12] {
            manager
                .execute_payment_at(&channel_id, 10, PaymentDirection::ToThem, height)
                .unwrap();
        }

        // Depth 2 keeps only heights 11 and 12, so a fork at 5 has nothing to
        // fall back on and must be reported for a chain resync.
        let report = manager.handle_reorg(5);
        assert!(!report.is_clean());
        assert_eq!(report.unresolved, vec![channel_id.clone()]);
        assert!(report.rolled_back.is_empty());
    }

    #[tokio::test]
    async fn reorg_report_covers_every_channel_deterministically() {
        let manager = ChannelManager::with_history_depth(Box::new(TestSigner), 8);
        let mut channel_ids = Vec::new();

        for (a, b) in [("alice", "bob"), ("carol", "dave")] {
            let state = manager
                .create_channel(a.to_string(), b.to_string(), 1_000, 1_000, 100, 0)
                .await
                .unwrap();
            manager
                .execute_payment_at(&state.channel_id, 10, PaymentDirection::ToThem, 10)
                .unwrap();
            channel_ids.push(state.channel_id);
        }

        let report = manager.handle_reorg(10);
        channel_ids.sort();
        assert_eq!(report.rolled_back, channel_ids);
        assert!(report.is_clean());
    }

    #[tokio::test]
    async fn height_agnostic_payments_are_recorded_on_increasing_heights() {
        let (manager, channel_id) = manager_with_channel(8).await;

        manager
            .execute_payment(&channel_id, 10, PaymentDirection::ToThem)
            .unwrap();
        manager
            .execute_payment(&channel_id, 10, PaymentDirection::ToThem)
            .unwrap();

        let heights = manager.recorded_heights(&channel_id).unwrap();
        assert_eq!(heights, vec![0, 1, 2]);

        // Rolling back to the funding height undoes both payments.
        manager.handle_reorg(0);
        assert_eq!(manager.get_channel(&channel_id).unwrap().our_balance, 1_000);
    }

    #[tokio::test]
    async fn close_and_rebalance_are_also_recorded() {
        let (manager, channel_id) = manager_with_channel(8).await;

        manager.rebalance(&channel_id, 500).unwrap();
        assert_eq!(manager.get_channel(&channel_id).unwrap().our_balance, 1_500);
        assert_eq!(manager.recorded_heights(&channel_id).unwrap().len(), 2);

        let report = manager.handle_reorg(0);
        assert_eq!(report.rolled_back.len(), 1);
        assert_eq!(manager.get_channel(&channel_id).unwrap().our_balance, 1_000);
    }

    #[tokio::test]
    async fn record_channel_state_anchors_without_mutating() {
        let (manager, channel_id) = manager_with_channel(8).await;
        let before = manager.get_channel(&channel_id).unwrap();

        manager.record_channel_state(&channel_id, 7).unwrap();

        assert_eq!(manager.get_channel(&channel_id).unwrap(), before);
        assert_eq!(manager.recorded_heights(&channel_id).unwrap(), vec![0, 7]);

        // Re-anchoring an old height is the same reorg signal as a payment.
        assert!(matches!(
            manager.record_channel_state(&channel_id, 7),
            Err(PaymentChannelError::ReorgDetected { .. })
        ));
    }

    #[test]
    fn test_channel_id_generation() {
        let id1 = ChannelManager::generate_channel_id("alice", "bob");
        let id2 = ChannelManager::generate_channel_id("bob", "alice");

        // Should be the same regardless of order
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_hex_encoding() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!(hex::encode(data), "deadbeef");
    }

    struct StrictTestSigner {
        pubkey: Vec<u8>,
    }

    impl StrictTestSigner {
        fn new(pubkey: Vec<u8>) -> Self {
            StrictTestSigner { pubkey }
        }
    }

    impl SignatureSigner for StrictTestSigner {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PaymentChannelError> {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(message);
            hasher.update(&self.pubkey);
            Ok(hasher.finalize().to_vec())
        }

        fn verify(
            &self,
            message: &[u8],
            signature: &[u8],
            public_key: &[u8],
        ) -> Result<bool, PaymentChannelError> {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(message);
            hasher.update(public_key);
            let expected = hasher.finalize().to_vec();
            Ok(signature == expected)
        }

        fn public_key(&self) -> Vec<u8> {
            self.pubkey.clone()
        }
    }

    #[tokio::test]
    async fn apply_signed_state_update_accepts_valid_signature() {
        let manager = ChannelManager::with_history_depth(Box::new(StrictTestSigner::new(vec![1; 32])), 8);
        let remote_signer = StrictTestSigner::new(vec![2; 32]);
        let state = manager
            .create_channel("alice".to_string(), "bob".to_string(), 1_000, 1_000, 100, 0)
            .await
            .unwrap();

        manager.set_remote_public_key(&state.channel_id, remote_signer.public_key()).unwrap();

        // Remote party (Bob) signs an update: Alice 800, Bob 1200 at sequence 1, height 5
        let digest = compute_state_digest(&state.channel_id, 1, "alice", 800, "bob", 1200, 5);
        let signature = remote_signer.sign(&digest).unwrap();

        let updated = manager
            .apply_signed_state_update(&state.channel_id, 800, 1200, &signature, 5)
            .unwrap();

        assert_eq!(updated.our_balance, 800);
        assert_eq!(updated.their_balance, 1200);
        assert_eq!(updated.sequence_number, 1);
        assert_eq!(manager.recorded_heights(&state.channel_id).unwrap(), vec![0, 5]);
    }

    #[tokio::test]
    async fn apply_signed_state_update_rejects_corrupted_signature_without_mutation() {
        let manager = ChannelManager::with_history_depth(Box::new(StrictTestSigner::new(vec![1; 32])), 8);
        let remote_signer = StrictTestSigner::new(vec![2; 32]);
        let state = manager
            .create_channel("alice".to_string(), "bob".to_string(), 1_000, 1_000, 100, 0)
            .await
            .unwrap();

        manager.set_remote_public_key(&state.channel_id, remote_signer.public_key()).unwrap();

        // Sign with wrong/foreign key
        let wrong_signer = StrictTestSigner::new(vec![99; 32]);
        let digest = compute_state_digest(&state.channel_id, 1, "alice", 800, "bob", 1200, 5);
        let bad_signature = wrong_signer.sign(&digest).unwrap();

        let err = manager
            .apply_signed_state_update(&state.channel_id, 800, 1200, &bad_signature, 5)
            .unwrap_err();

        assert!(matches!(err, PaymentChannelError::SignatureError(_)));

        // Channel state must remain pristine
        let untouched = manager.get_channel(&state.channel_id).unwrap();
        assert_eq!(untouched.our_balance, 1_000);
        assert_eq!(untouched.their_balance, 1_000);
        assert_eq!(untouched.sequence_number, 0);
        assert_eq!(manager.recorded_heights(&state.channel_id).unwrap(), vec![0]);
    }

    #[tokio::test]
    async fn apply_signed_state_update_rejects_balance_mismatch() {
        let manager = ChannelManager::with_history_depth(Box::new(StrictTestSigner::new(vec![1; 32])), 8);
        let remote_signer = StrictTestSigner::new(vec![2; 32]);
        let state = manager
            .create_channel("alice".to_string(), "bob".to_string(), 1_000, 1_000, 100, 0)
            .await
            .unwrap();

        manager.set_remote_public_key(&state.channel_id, remote_signer.public_key()).unwrap();

        let digest = compute_state_digest(&state.channel_id, 1, "alice", 1_500, "bob", 1_500, 5);
        let sig = remote_signer.sign(&digest).unwrap();

        let err = manager
            .apply_signed_state_update(&state.channel_id, 1_500, 1_500, &sig, 5)
            .unwrap_err();

        assert!(matches!(err, PaymentChannelError::InvalidState(_)));
    }

    #[tokio::test]
    async fn execute_authorized_payment_verifies_signature() {
        let manager = ChannelManager::with_history_depth(Box::new(StrictTestSigner::new(vec![1; 32])), 8);
        let remote_signer = StrictTestSigner::new(vec![2; 32]);
        let state = manager
            .create_channel("alice".to_string(), "bob".to_string(), 1_000, 1_000, 100, 0)
            .await
            .unwrap();

        manager.set_remote_public_key(&state.channel_id, remote_signer.public_key()).unwrap();

        // Payment of 200 to them produces our 800, their 1200
        let digest = compute_state_digest(&state.channel_id, 1, "alice", 800, "bob", 1200, 10);
        let valid_sig = remote_signer.sign(&digest).unwrap();

        let updated = manager
            .execute_authorized_payment_at(&state.channel_id, 200, PaymentDirection::ToThem, &valid_sig, 10)
            .unwrap();

        assert_eq!(updated.our_balance, 800);
        assert_eq!(updated.their_balance, 1200);
        assert_eq!(updated.sequence_number, 1);
    }

    #[tokio::test]
    async fn integration_two_party_reciprocal_authorization_exchange() {
        let alice_signer = StrictTestSigner::new(vec![10; 32]);
        let bob_signer = StrictTestSigner::new(vec![20; 32]);

        let alice_manager = ChannelManager::with_history_depth(Box::new(StrictTestSigner::new(vec![10; 32])), 8);
        let bob_manager = ChannelManager::with_history_depth(Box::new(StrictTestSigner::new(vec![20; 32])), 8);

        let ch_alice = alice_manager
            .create_channel("alice".to_string(), "bob".to_string(), 1_000, 1_000, 100, 0)
            .await
            .unwrap();
        let ch_bob = bob_manager
            .create_channel("bob".to_string(), "alice".to_string(), 1_000, 1_000, 100, 0)
            .await
            .unwrap();

        assert_eq!(ch_alice.channel_id, ch_bob.channel_id);
        let ch_id = ch_alice.channel_id.clone();

        alice_manager.set_remote_public_key(&ch_id, bob_signer.public_key()).unwrap();
        bob_manager.set_remote_public_key(&ch_id, alice_signer.public_key()).unwrap();

        // Alice pays 150 to Bob at height 1.
        // Proposed new balances: Alice 850, Bob 1150.
        // Bob authorizes the proposed state:
        let bob_sig = bob_manager
            .sign_proposed_state(&ch_id, 1, 1150, 850, 1)
            .unwrap();

        // Alice applies Bob's authorization:
        let alice_state = alice_manager
            .apply_signed_state_update(&ch_id, 850, 1150, &bob_sig, 1)
            .unwrap();

        // Alice signs her updated state and gives it to Bob:
        let alice_sig = alice_manager.sign_state_update(&ch_id, 1).unwrap();

        // Bob applies Alice's authorization:
        let bob_state = bob_manager
            .apply_signed_state_update(&ch_id, 1150, 850, &alice_sig, 1)
            .unwrap();

        assert_eq!(alice_state.our_balance, 850);
        assert_eq!(alice_state.their_balance, 1150);
        assert_eq!(bob_state.our_balance, 1150);
        assert_eq!(bob_state.their_balance, 850);
        assert_eq!(alice_state.sequence_number, bob_state.sequence_number);
    }
}

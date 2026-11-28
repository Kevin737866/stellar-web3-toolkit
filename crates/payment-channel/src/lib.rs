//! # Payment Channel Library
//!
//! High-level library for managing Stellar payment channels.
//! This library provides a Rust API for creating, managing, and closing
//! payment channels, as well as executing off-chain payments.

pub mod reorg;
pub mod signed;

use parking_lot::RwLock;
use reorg::{ReorgError, ReorgLog};
use serde::{Deserialize, Serialize};
use signed::SignedChannelState;
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

    /// A settlement presented a state the channel has already superseded (#352).
    ///
    /// Carries both numbers so an operator can tell a stale copy from a
    /// deliberately replayed one without reading the payload again.
    #[error(
        "Stale state for channel {channel_id}: presented sequence {presented} is not newer than the recorded sequence {recorded}"
    )]
    StaleState {
        channel_id: String,
        recorded: u32,
        presented: u32,
    },

    /// A payment or state update would drop a participant's balance below the
    /// channel's configured reserve requirement (#356).
    #[error(
        "Channel reserve not met for channel {channel_id}: balance {remaining} is below required reserve {reserve}"
    )]
    ReserveNotMet {
        channel_id: String,
        remaining: i128,
        reserve: i128,
    },
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
    /// Minimum balance each participant must maintain during off-chain payments (#356).
    ///
    /// Defaults to `0` for channels created via [`ChannelManager::create_channel`]
    /// to preserve backward compatibility with callers that do not configure a reserve.
    #[serde(default)]
    pub channel_reserve: i128,
    /// Pending HTLCs
    pub pending_htlcs: Vec<HtlcState>,
    /// Local secret for signing
    pub local_secret: Vec<u8>,
    /// Remote public key
    pub remote_public_key: Vec<u8>,
}

/// Summary of a channel's status including pending HTLC count and capacity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelStatusInfo {
    /// Channel ID
    pub channel_id: String,
    /// Current lifecycle status
    pub status: ChannelStatus,
    /// Our current balance
    pub our_balance: i128,
    /// Counterparty's current balance
    pub their_balance: i128,
    /// Number of active (unclaimed and unrefunded) pending HTLCs
    pub pending_htlc_count: usize,
    /// Total amount locked across active pending HTLCs
    pub pending_htlc_amount: i128,
    /// Total channel capacity (`our_balance + their_balance`)
    pub capacity: i128,
    /// Available capacity after subtracting `pending_htlc_amount`
    pub available_capacity: i128,
}

impl LocalChannelState {
    /// Compute a [`ChannelStatusInfo`] snapshot for this channel, validating
    /// balance and pending HTLC invariants.
    pub fn status_info(&self) -> Result<ChannelStatusInfo, PaymentChannelError> {
        if self.our_balance < 0 || self.their_balance < 0 {
            return Err(PaymentChannelError::InvalidState(
                "Channel balances cannot be negative".to_string(),
            ));
        }

        let capacity = self.our_balance.checked_add(self.their_balance).ok_or_else(|| {
            PaymentChannelError::InvalidState("Channel capacity overflow".to_string())
        })?;

        let mut pending_htlc_count = 0usize;
        let mut pending_htlc_amount = 0i128;
        for htlc in &self.pending_htlcs {
            if !htlc.is_claimed && !htlc.is_refunded {
                if htlc.amount < 0 {
                    return Err(PaymentChannelError::InvalidState(format!(
                        "Pending HTLC '{}' has negative amount {}",
                        htlc.htlc_id, htlc.amount
                    )));
                }
                pending_htlc_count += 1;
                pending_htlc_amount =
                    pending_htlc_amount.checked_add(htlc.amount).ok_or_else(|| {
                        PaymentChannelError::InvalidState(
                            "Pending HTLC amount overflow".to_string(),
                        )
                    })?;
            }
        }

        let available_capacity = capacity.saturating_sub(pending_htlc_amount);

        Ok(ChannelStatusInfo {
            channel_id: self.channel_id.clone(),
            status: self.status,
            our_balance: self.our_balance,
            their_balance: self.their_balance,
            pending_htlc_count,
            pending_htlc_amount,
            capacity,
            available_capacity,
        })
    }
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

    /// Create a new payment channel with a default `channel_reserve` of `0`.
    ///
    /// Preserves existing behavior for callers that do not configure a reserve.
    /// Use [`ChannelManager::create_channel_with_reserve`] to enforce a non-zero
    /// minimum balance per participant during off-chain payments.
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)] // public API; funding will need an RPC round trip
    pub async fn create_channel(
        &self,
        our_address: String,
        their_address: String,
        our_initial_balance: i128,
        their_initial_balance: i128,
        timeout: u32,
        fee_percentage: u32,
    ) -> Result<LocalChannelState, PaymentChannelError> {
        self.create_channel_with_reserve(
            our_address,
            their_address,
            our_initial_balance,
            their_initial_balance,
            timeout,
            fee_percentage,
            0,
        )
        .await
    }

    /// Create a new payment channel with an explicit per-participant reserve requirement (#356).
    ///
    /// Both `our_initial_balance` and `their_initial_balance` must be non-negative and at
    /// least `channel_reserve`, and `channel_reserve` must be non-negative.
    #[allow(
        clippy::too_many_arguments,
        clippy::unused_async,
        clippy::unused_async_trait_impl
    )]
    pub async fn create_channel_with_reserve(
        &self,
        our_address: String,
        their_address: String,
        our_initial_balance: i128,
        their_initial_balance: i128,
        timeout: u32,
        fee_percentage: u32,
        channel_reserve: i128,
    ) -> Result<LocalChannelState, PaymentChannelError> {
        if our_initial_balance < 0 || their_initial_balance < 0 {
            return Err(PaymentChannelError::InvalidState(
                "Initial balances cannot be negative".to_string(),
            ));
        }
        if channel_reserve < 0 {
            return Err(PaymentChannelError::InvalidState(
                "Channel reserve cannot be negative".to_string(),
            ));
        }

        // Generate channel ID
        let channel_id = Self::generate_channel_id(&our_address, &their_address);

        if our_initial_balance < channel_reserve {
            return Err(PaymentChannelError::ReserveNotMet {
                channel_id,
                remaining: our_initial_balance,
                reserve: channel_reserve,
            });
        }
        if their_initial_balance < channel_reserve {
            return Err(PaymentChannelError::ReserveNotMet {
                channel_id,
                remaining: their_initial_balance,
                reserve: channel_reserve,
            });
        }

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
            channel_reserve,
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

    /// Configure or update the minimum per-participant reserve on an open channel (#356).
    ///
    /// Rejects negative reserves, closed channels, or reserves exceeding either
    /// participant's current balance without mutating channel state.
    pub fn set_channel_reserve(
        &self,
        channel_id: &str,
        channel_reserve: i128,
    ) -> Result<(), PaymentChannelError> {
        if channel_reserve < 0 {
            return Err(PaymentChannelError::InvalidState(
                "Channel reserve cannot be negative".to_string(),
            ));
        }

        let mut channels = self.channels.write();
        let channel = channels
            .get_mut(channel_id)
            .ok_or_else(|| PaymentChannelError::ChannelNotFound(channel_id.to_string()))?;

        if channel.state.status != ChannelStatus::Open {
            return Err(PaymentChannelError::ChannelClosed(
                channel.state.status.to_string(),
            ));
        }

        if channel.state.our_balance < channel_reserve {
            return Err(PaymentChannelError::ReserveNotMet {
                channel_id: channel_id.to_string(),
                remaining: channel.state.our_balance,
                reserve: channel_reserve,
            });
        }
        if channel.state.their_balance < channel_reserve {
            return Err(PaymentChannelError::ReserveNotMet {
                channel_id: channel_id.to_string(),
                remaining: channel.state.their_balance,
                reserve: channel_reserve,
            });
        }

        channel.state.channel_reserve = channel_reserve;
        Ok(())
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

        let (new_our, new_their) =
            compute_post_payment_balances(channel_id, &channel.state, amount, direction)?;

        channel.state.our_balance = new_our;
        channel.state.their_balance = new_their;
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

        let expected_total = channel
            .state
            .our_balance
            .checked_add(channel.state.their_balance)
            .ok_or_else(|| PaymentChannelError::InvalidState("Channel balance overflow".to_string()))?;
        let new_total = new_our_balance
            .checked_add(new_their_balance)
            .ok_or_else(|| PaymentChannelError::InvalidState("Proposed balance overflow".to_string()))?;
        if new_total != expected_total {
            return Err(PaymentChannelError::InvalidState(format!(
                "Total balance mismatch: expected {}, got {}",
                expected_total, new_total
            )));
        }

        if new_our_balance < channel.state.channel_reserve {
            return Err(PaymentChannelError::ReserveNotMet {
                channel_id: channel_id.to_string(),
                remaining: new_our_balance,
                reserve: channel.state.channel_reserve,
            });
        }
        if new_their_balance < channel.state.channel_reserve {
            return Err(PaymentChannelError::ReserveNotMet {
                channel_id: channel_id.to_string(),
                remaining: new_their_balance,
                reserve: channel.state.channel_reserve,
            });
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

            if channel.state.status != ChannelStatus::Open {
                return Err(PaymentChannelError::ChannelClosed(
                    channel.state.status.to_string(),
                ));
            }

            compute_post_payment_balances(channel_id, &channel.state, amount, direction)?
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

    /// Get a channel's status snapshot including pending HTLC count and capacity.
    pub fn get_channel_status(
        &self,
        channel_id: &str,
    ) -> Result<ChannelStatusInfo, PaymentChannelError> {
        let channels = self.channels.read();
        let channel = channels
            .get(channel_id)
            .ok_or_else(|| PaymentChannelError::ChannelNotFound(channel_id.to_string()))?;
        channel.state.status_info()
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

    /// Close a channel cooperatively.
    ///
    /// Idempotent (#351): the first call moves the channel to
    /// [`ChannelStatus::Closing`]. Calling it again — the retry a client makes
    /// when the response to the first call was lost — returns that same state
    /// without recording another snapshot, advancing the sequence number, or
    /// consuming a ledger height.
    ///
    /// A channel that is not open and not already closing cooperatively (a
    /// force close, a dispute) is refused with [`PaymentChannelError::InvalidState`].
    pub fn cooperative_close(
        &self,
        channel_id: &str,
    ) -> Result<LocalChannelState, PaymentChannelError> {
        self.close_cooperatively(channel_id, None)
    }

    /// Close a channel cooperatively at a known ledger height.
    ///
    /// The height-aware twin of [`ChannelManager::cooperative_close`], for
    /// callers that observed the close on chain. A retry of an already-applied
    /// close is still idempotent and ignores `ledger_height`, because there is
    /// no state left to record.
    pub fn cooperative_close_at(
        &self,
        channel_id: &str,
        ledger_height: u32,
    ) -> Result<LocalChannelState, PaymentChannelError> {
        self.close_cooperatively(channel_id, Some(ledger_height))
    }

    fn close_cooperatively(
        &self,
        channel_id: &str,
        ledger_height: Option<u32>,
    ) -> Result<LocalChannelState, PaymentChannelError> {
        let mut channels = self.channels.write();
        let channel = channels
            .get_mut(channel_id)
            .ok_or_else(|| PaymentChannelError::ChannelNotFound(channel_id.to_string()))?;

        match channel.state.status {
            // Already closed (or closing) cooperatively: the retry's intent is
            // satisfied. Return the state the first call produced, untouched.
            ChannelStatus::Closing | ChannelStatus::Closed => {
                return Ok(channel.state.clone());
            }
            ChannelStatus::Open => {}
            other => {
                return Err(PaymentChannelError::InvalidState(format!(
                    "Cannot close channel in state {other}"
                )));
            }
        }

        // Only allocate a height for a close that will actually be applied, so a
        // retry does not leave a gap in the recorded heights.
        let ledger_height = ledger_height.unwrap_or_else(|| self.next_ledger_height());
        check_height(channel_id, &channel.history, ledger_height)?;
        channel.state.status = ChannelStatus::Closing;
        record_state(channel_id, channel, ledger_height)?;

        Ok(channel.state.clone())
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

    /// Register the counterparty's public key for this channel.
    ///
    /// Settlement ([`ChannelManager::settle_signed_state`]) verifies the
    /// presented signature against this key, so it must be registered after the
    /// handshake. Re-registering replaces the key, which is what a key rotation
    /// looks like; settlement itself never changes it.
    pub fn set_remote_public_key(
        &self,
        channel_id: &str,
        public_key: Vec<u8>,
    ) -> Result<(), PaymentChannelError> {
        let mut channels = self.channels.write();
        let channel = channels
            .get_mut(channel_id)
            .ok_or_else(|| PaymentChannelError::ChannelNotFound(channel_id.to_string()))?;

        if public_key.is_empty() {
            return Err(PaymentChannelError::InvalidState(
                "the counterparty public key must not be empty".to_string(),
            ));
        }

        channel.state.remote_public_key = public_key;
        Ok(())
    }

    /// Settle the channel on a signed state, refusing anything the channel has
    /// already superseded (#352).
    ///
    /// The counterparty presents the newest split both parties signed. The
    /// call succeeds only when all of the following hold, and nothing is
    /// written unless they do:
    ///
    /// * the channel exists and is [`ChannelStatus::Open`];
    /// * `signed.channel_id` names this channel;
    /// * `signature` verifies over [`SignedChannelState::digest`] against the
    ///   channel's registered `remote_public_key` (so
    ///   [`ChannelManager::set_remote_public_key`] must have run);
    /// * both balances are non-negative and sum to the channel total;
    /// * `signed.sequence_number` is **strictly newer** than the channel's
    ///   recorded sequence — an equal or lower number is
    ///   [`PaymentChannelError::StaleState`];
    /// * `ledger_height` is newer than the channel's last recorded height
    ///   ([`PaymentChannelError::ReorgDetected`] otherwise).
    ///
    /// On success the balances are applied, the channel's sequence number is
    /// advanced to the signed one (gaps are allowed: a party may have missed
    /// intermediate updates) and the channel moves to
    /// [`ChannelStatus::Closing`], because a settled split is a terminal state
    /// that is waiting on the on-chain confirmation.
    pub fn settle_signed_state(
        &self,
        signed: &SignedChannelState,
        signature: &[u8],
        ledger_height: u32,
    ) -> Result<LocalChannelState, PaymentChannelError> {
        let mut channels = self.channels.write();
        let channel = channels
            .get_mut(&signed.channel_id)
            .ok_or_else(|| PaymentChannelError::ChannelNotFound(signed.channel_id.clone()))?;

        if channel.state.status != ChannelStatus::Open {
            return Err(PaymentChannelError::ChannelClosed(
                channel.state.status.to_string(),
            ));
        }

        if channel.state.remote_public_key.is_empty() {
            return Err(PaymentChannelError::InvalidState(format!(
                "channel {} has no registered counterparty key; call set_remote_public_key first",
                signed.channel_id
            )));
        }

        // Authenticate before anything else: an unsigned state must not be able
        // to learn the recorded sequence number from the error it gets back.
        let verified = self.signer.verify(
            &signed.digest(),
            signature,
            &channel.state.remote_public_key,
        )?;
        if !verified {
            return Err(PaymentChannelError::SignatureError(format!(
                "settlement for channel {} is not signed by the counterparty",
                signed.channel_id
            )));
        }

        let total = signed.total()?;
        if total != channel.state.our_balance + channel.state.their_balance {
            return Err(PaymentChannelError::InvalidState(format!(
                "settlement for {} does not conserve the channel total: {total} != {}",
                signed.channel_id,
                channel.state.our_balance + channel.state.their_balance
            )));
        }

        // The staleness rule: only a strictly newer state may settle. This is
        // what stops a party from settling on an older, more favourable split
        // after the channel has moved on.
        if signed.sequence_number <= channel.state.sequence_number {
            return Err(PaymentChannelError::StaleState {
                channel_id: signed.channel_id.clone(),
                recorded: channel.state.sequence_number,
                presented: signed.sequence_number,
            });
        }

        // A rejected height must leave the channel exactly as it was, so the
        // height is validated before any mutation.
        check_height(&signed.channel_id, &channel.history, ledger_height)?;

        channel.state.our_balance = signed.balance_a;
        channel.state.their_balance = signed.balance_b;
        channel.state.sequence_number = signed.sequence_number;
        channel.state.status = ChannelStatus::Closing;

        record_state(&signed.channel_id, channel, ledger_height)?;

        Ok(channel.state.clone())
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
        sorted.sort_unstable();

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

/// Compute post-payment balances after validating positive amount, sufficient
/// funds, and the channel's reserve requirement.
fn compute_post_payment_balances(
    channel_id: &str,
    state: &LocalChannelState,
    amount: i128,
    direction: PaymentDirection,
) -> Result<(i128, i128), PaymentChannelError> {
    if amount <= 0 {
        return Err(PaymentChannelError::InvalidState(
            "Payment amount must be positive".to_string(),
        ));
    }

    let (sender_balance, receiver_balance) = match direction {
        PaymentDirection::ToThem => (state.our_balance, state.their_balance),
        PaymentDirection::ToUs => (state.their_balance, state.our_balance),
    };

    if sender_balance < amount {
        return Err(PaymentChannelError::InsufficientBalance {
            have: sender_balance,
            need: amount,
        });
    }

    let new_sender = sender_balance - amount;
    if new_sender < state.channel_reserve {
        return Err(PaymentChannelError::ReserveNotMet {
            channel_id: channel_id.to_string(),
            remaining: new_sender,
            reserve: state.channel_reserve,
        });
    }

    let new_receiver = receiver_balance
        .checked_add(amount)
        .ok_or_else(|| PaymentChannelError::InvalidState("Balance overflow".to_string()))?;

    match direction {
        PaymentDirection::ToThem => Ok((new_sender, new_receiver)),
        PaymentDirection::ToUs => Ok((new_receiver, new_sender)),
    }
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
            other @ ReorgError::NoSnapshotAtOrBelow { .. } => {
                PaymentChannelError::InvalidState(other.to_string())
            }
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

    #[tokio::test]
    async fn cooperative_close_is_idempotent_on_retry() {
        let (manager, channel_id) = manager_with_channel(8).await;

        let first = manager.cooperative_close(&channel_id).unwrap();
        assert_eq!(first.status, ChannelStatus::Closing);
        let heights = manager.recorded_heights(&channel_id).unwrap();
        assert_eq!(heights.len(), 2, "the close records one snapshot");

        for _ in 0..3 {
            let again = manager
                .cooperative_close(&channel_id)
                .expect("a retry of the same close must succeed");
            assert_eq!(again, first, "a retry must not change the state");
        }

        assert_eq!(
            manager.recorded_heights(&channel_id).unwrap(),
            heights,
            "a retry must not record another snapshot"
        );
    }

    #[tokio::test]
    async fn a_retry_at_a_known_height_is_also_idempotent() {
        let (manager, channel_id) = manager_with_channel(8).await;

        manager.cooperative_close_at(&channel_id, 10).unwrap();
        assert_eq!(manager.recorded_heights(&channel_id).unwrap(), vec![0, 10]);

        // The retry carries a height that was never applied; it must still be a
        // no-op rather than a second close or a reorg rejection.
        manager.cooperative_close_at(&channel_id, 11).unwrap();
        assert_eq!(manager.recorded_heights(&channel_id).unwrap(), vec![0, 10]);
    }

    #[tokio::test]
    async fn a_closed_channel_accepts_a_cooperative_close_retry() {
        let (manager, channel_id) = manager_with_channel(8).await;

        manager.cooperative_close(&channel_id).unwrap();
        // Simulate the on-chain confirmation that moves the channel on.
        {
            let mut channels = manager.channels.write();
            channels.get_mut(&channel_id).unwrap().state.status = ChannelStatus::Closed;
        }

        let state = manager.cooperative_close(&channel_id).unwrap();
        assert_eq!(state.status, ChannelStatus::Closed);
    }

    #[tokio::test]
    async fn a_force_closed_channel_refuses_a_cooperative_close() {
        let (manager, channel_id) = manager_with_channel(8).await;

        manager.initiate_unilateral_close(&channel_id).unwrap();

        let err = manager.cooperative_close(&channel_id).unwrap_err();
        assert!(matches!(err, PaymentChannelError::InvalidState(_)));
        assert_eq!(
            manager.get_channel(&channel_id).unwrap().status,
            ChannelStatus::ForceClosed,
            "a rejected close must not change the state"
        );
    }

    #[tokio::test]
    async fn closing_an_unknown_channel_reports_not_found() {
        let (manager, _) = manager_with_channel(8).await;

        assert!(matches!(
            manager.cooperative_close("missing"),
            Err(PaymentChannelError::ChannelNotFound(_))
        ));
    }

    #[tokio::test]
    async fn a_retried_close_still_participates_in_reorg_rollback() {
        let (manager, channel_id) = manager_with_channel(8).await;

        manager.cooperative_close_at(&channel_id, 10).unwrap();
        manager.cooperative_close_at(&channel_id, 10).unwrap();
        assert_eq!(
            manager.get_channel(&channel_id).unwrap().status,
            ChannelStatus::Closing
        );

        // The fork is below the close, so the rollback reopens the channel.
        let report = manager.handle_reorg(0);
        assert!(report.is_clean());
        assert_eq!(
            manager.get_channel(&channel_id).unwrap().status,
            ChannelStatus::Open
        );
    }

    /// Signer that signs by echoing the message, and verifies by comparing the
    /// signature to the message. Unlike [`TestSigner`] it can reject a
    /// signature, which is what the settlement tests need.
    struct EchoSigner;

    impl SignatureSigner for EchoSigner {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PaymentChannelError> {
            Ok(message.to_vec())
        }

        fn verify(
            &self,
            message: &[u8],
            signature: &[u8],
            _public_key: &[u8],
        ) -> Result<bool, PaymentChannelError> {
            Ok(message == signature)
        }

        fn public_key(&self) -> Vec<u8> {
            vec![9u8; 32]
        }
    }

    /// A manager whose channel has a registered counterparty key, ready to
    /// settle.
    async fn manager_ready_to_settle() -> (ChannelManager, String) {
        let manager = ChannelManager::with_history_depth(Box::new(EchoSigner), 8);
        let state = manager
            .create_channel("alice".to_string(), "bob".to_string(), 1_000, 1_000, 100, 0)
            .await
            .unwrap();
        manager
            .set_remote_public_key(&state.channel_id, vec![5u8; 32])
            .unwrap();
        (manager, state.channel_id)
    }

    fn signed(channel_id: &str, sequence_number: u32, a: i128, b: i128) -> SignedChannelState {
        SignedChannelState::new(channel_id, sequence_number, a, b)
    }

    #[tokio::test]
    async fn a_newer_signed_state_settles_the_channel() {
        let (manager, channel_id) = manager_ready_to_settle().await;
        let state = signed(&channel_id, 3, 1_200, 800);

        let settled = manager
            .settle_signed_state(&state, &state.digest(), 10)
            .expect("a newer state must settle");

        assert_eq!(settled.our_balance, 1_200);
        assert_eq!(settled.their_balance, 800);
        assert_eq!(settled.sequence_number, 3);
        assert_eq!(settled.status, ChannelStatus::Closing);
        assert_eq!(manager.recorded_heights(&channel_id).unwrap(), vec![0, 10]);
    }

    #[tokio::test]
    async fn a_stale_signed_state_is_refused_and_changes_nothing() {
        let (manager, channel_id) = manager_ready_to_settle().await;

        // Move the channel on to sequence 5 through a normal payment.
        for height in [10, 11, 12, 13, 14] {
            manager
                .execute_payment_at(&channel_id, 10, PaymentDirection::ToThem, height)
                .unwrap();
        }
        let before = manager.get_channel(&channel_id).unwrap();
        assert_eq!(before.sequence_number, 5);

        // An old, more favourable split the counterparty kept from sequence 2.
        let stale = signed(&channel_id, 2, 1_500, 500);
        let error = manager
            .settle_signed_state(&stale, &stale.digest(), 20)
            .expect_err("a superseded state must not settle");
        assert_eq!(
            error,
            PaymentChannelError::StaleState {
                channel_id: channel_id.clone(),
                recorded: 5,
                presented: 2,
            }
        );

        assert_eq!(
            manager.get_channel(&channel_id).unwrap(),
            before,
            "a rejected settlement must leave the channel untouched"
        );
        assert_eq!(
            manager.recorded_heights(&channel_id).unwrap().last(),
            Some(&14),
            "a rejected settlement must not record a snapshot"
        );
    }

    #[tokio::test]
    async fn the_recorded_sequence_itself_is_stale() {
        let (manager, channel_id) = manager_ready_to_settle().await;
        manager
            .execute_payment_at(&channel_id, 10, PaymentDirection::ToThem, 10)
            .unwrap();

        // Re-presenting the state the channel is already on is not progress.
        let same = signed(&channel_id, 1, 990, 1_010);
        let error = manager
            .settle_signed_state(&same, &same.digest(), 11)
            .expect_err("an equal sequence is not newer");
        assert!(matches!(
            error,
            PaymentChannelError::StaleState {
                recorded: 1,
                presented: 1,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn a_sequence_gap_is_accepted() {
        let (manager, channel_id) = manager_ready_to_settle().await;

        // The counterparty may have missed intermediate updates, so the signed
        // sequence only has to be newer, not exactly one more.
        let state = signed(&channel_id, 9, 1_100, 900);
        let settled = manager
            .settle_signed_state(&state, &state.digest(), 10)
            .unwrap();
        assert_eq!(settled.sequence_number, 9);
    }

    #[tokio::test]
    async fn an_unsigned_settlement_is_refused() {
        let (manager, channel_id) = manager_ready_to_settle().await;
        let state = signed(&channel_id, 3, 1_200, 800);
        let before = manager.get_channel(&channel_id).unwrap();

        let error = manager
            .settle_signed_state(&state, &[0u8; 32], 10)
            .expect_err("a bad signature must not settle");
        assert!(matches!(error, PaymentChannelError::SignatureError(_)));
        assert_eq!(manager.get_channel(&channel_id).unwrap(), before);
    }

    #[tokio::test]
    async fn settlement_requires_a_registered_counterparty_key() {
        let manager = ChannelManager::with_history_depth(Box::new(EchoSigner), 8);
        let state = manager
            .create_channel("alice".to_string(), "bob".to_string(), 1_000, 1_000, 100, 0)
            .await
            .unwrap();

        let settlement = signed(&state.channel_id, 3, 1_200, 800);
        let error = manager
            .settle_signed_state(&settlement, &settlement.digest(), 10)
            .expect_err("without a counterparty key nothing can be verified");
        assert!(matches!(error, PaymentChannelError::InvalidState(_)));
    }

    #[tokio::test]
    async fn a_settlement_that_does_not_conserve_the_total_is_refused() {
        let (manager, channel_id) = manager_ready_to_settle().await;

        let state = signed(&channel_id, 3, 1_500, 900);
        let error = manager
            .settle_signed_state(&state, &state.digest(), 10)
            .expect_err("the total must be conserved");
        assert!(matches!(error, PaymentChannelError::InvalidState(_)));
        assert_eq!(manager.get_channel(&channel_id).unwrap().sequence_number, 0);
    }

    #[tokio::test]
    async fn a_settlement_for_another_channel_is_refused() {
        let (manager, _) = manager_ready_to_settle().await;

        let state = signed("someone-elses-channel", 3, 1_200, 800);
        let error = manager
            .settle_signed_state(&state, &state.digest(), 10)
            .expect_err("a settlement is bound to its channel");
        assert!(matches!(error, PaymentChannelError::ChannelNotFound(_)));
    }

    #[tokio::test]
    async fn a_settlement_at_a_stale_height_is_refused() {
        let (manager, channel_id) = manager_ready_to_settle().await;
        manager
            .execute_payment_at(&channel_id, 10, PaymentDirection::ToThem, 10)
            .unwrap();

        let state = signed(&channel_id, 3, 1_100, 900);
        let error = manager
            .settle_signed_state(&state, &state.digest(), 10)
            .expect_err("the height must be newer than the last recorded one");
        assert!(matches!(error, PaymentChannelError::ReorgDetected { .. }));
        assert_eq!(manager.get_channel(&channel_id).unwrap().sequence_number, 1);
    }

    #[tokio::test]
    async fn a_settled_channel_refuses_further_settlement() {
        let (manager, channel_id) = manager_ready_to_settle().await;

        let first = signed(&channel_id, 3, 1_200, 800);
        manager
            .settle_signed_state(&first, &first.digest(), 10)
            .unwrap();

        let second = signed(&channel_id, 4, 900, 1_100);
        let error = manager
            .settle_signed_state(&second, &second.digest(), 11)
            .expect_err("settlement is terminal");
        assert!(matches!(error, PaymentChannelError::ChannelClosed(_)));
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

        let alice_manager = ChannelManager::with_history_depth(
            Box::new(StrictTestSigner::new(vec![10; 32])),
            8,
        );
        let bob_manager = ChannelManager::with_history_depth(
            Box::new(StrictTestSigner::new(vec![20; 32])),
            8,
        );

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

    #[test]
    fn channel_status_exposes_pending_htlc_count_and_capacity() {
        let mut state = LocalChannelState {
            channel_id: "ch-status".to_string(),
            our_address: "GA".to_string(),
            their_address: "GB".to_string(),
            our_balance: 700,
            their_balance: 300,
            status: ChannelStatus::Open,
            sequence_number: 1,
            funding_tx_hash: None,
            closing_tx_hash: None,
            timeout: 100,
            fee_percentage: 10,
            pending_htlcs: vec![
                HtlcState {
                    htlc_id: "h1".to_string(),
                    amount: 150,
                    hashlock: vec![1; 32],
                    timelock: 500,
                    is_claimed: false,
                    is_refunded: false,
                    preimage: None,
                    direction: HtlcDirection::Outgoing,
                },
                HtlcState {
                    htlc_id: "h2".to_string(),
                    amount: 250,
                    hashlock: vec![2; 32],
                    timelock: 600,
                    is_claimed: false,
                    is_refunded: false,
                    preimage: None,
                    direction: HtlcDirection::Incoming,
                },
                HtlcState {
                    htlc_id: "h3-claimed".to_string(),
                    amount: 999,
                    hashlock: vec![3; 32],
                    timelock: 700,
                    is_claimed: true,
                    is_refunded: false,
                    preimage: Some(vec![9; 32]),
                    direction: HtlcDirection::Outgoing,
                },
                HtlcState {
                    htlc_id: "h4-refunded".to_string(),
                    amount: 888,
                    hashlock: vec![4; 32],
                    timelock: 800,
                    is_claimed: false,
                    is_refunded: true,
                    preimage: None,
                    direction: HtlcDirection::Outgoing,
                },
            ],
            local_secret: vec![],
            remote_public_key: vec![],
        };

        let info = state.status_info().unwrap();
        assert_eq!(info.status, ChannelStatus::Open);
        assert_eq!(info.pending_htlc_count, 2);
        assert_eq!(info.pending_htlc_amount, 400);
        assert_eq!(info.capacity, 1_000);
        assert_eq!(info.available_capacity, 600);

        // Negative HTLC amount is rejected explicitly.
        state.pending_htlcs[0].amount = -10;
        assert!(matches!(
            state.status_info(),
            Err(PaymentChannelError::InvalidState(_))
        ));
    }

    #[test]
    fn get_channel_status_returns_not_found_for_missing_channel() {
        let manager = PaymentChannelManager::new(Arc::new(Ed25519Signer::generate()));
        let err = manager.get_channel_status("missing").unwrap_err();
        assert!(matches!(err, PaymentChannelError::ChannelNotFound(_)));
    }
}

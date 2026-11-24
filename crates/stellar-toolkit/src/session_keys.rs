//! Account Abstraction & Session Key Management
//!
//! Provides lightweight, secure session keys and account abstraction UX primitives
//! for interacting with Soroban contracts. Features include:
//! - Session key generation with customizable expiration, spending limits, and method whitelist
//! - Non-blocking policy validation for transactions
//! - Transaction signing delegation using active session keys
//! - Session key revocation and auditing
//! - Multi-guardian recovery UX for account recovery
//! - A veto guardian set that can block an in-flight recovery before it executes

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents an error in session key or account abstraction operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum SessionError {
    #[error("Session key {0} not found")]
    SessionNotFound(String),
    #[error("Session key {0} has expired at timestamp {1}")]
    SessionExpired(String, u64),
    #[error("Session key {0} has been revoked")]
    SessionRevoked(String),
    /// Returned when the caller supplies an `account_id` that does not match
    /// the account that owns the session key (issue #334).
    ///
    /// We deliberately use the same message text as `SessionNotFound` to avoid
    /// leaking cross-account existence information to the caller.
    #[error("Session key {0} not found")]
    SessionNotOwned(String),
    #[error("Contract {0} is not authorized for session {1}")]
    ContractNotAllowed(String, String),
    #[error("Method {0} on contract {1} is not authorized for session {2}")]
    MethodNotAllowed(String, String, String),
    #[error("Spend limit exceeded for session {0}: requested {1}, remaining {2}")]
    SpendLimitExceeded(String, u64, u64),
    #[error("Recovery threshold not met: required {0}, received {1}")]
    RecoveryThresholdNotMet(usize, usize),
    #[error("Invalid recovery signature from guardian {0}")]
    InvalidGuardianSignature(String),
    #[error("Recovery {0} is blocked by veto: {1} of {2} vetoes required")]
    RecoveryVetoed(String, usize, usize),
    #[error("Recovery {0} has already been executed")]
    RecoveryAlreadyExecuted(String),
    #[error("No veto from {0} to clear on this recovery")]
    VetoNotFound(String),
    #[error("Invalid account identifier: {0}")]
    InvalidAccountId(String),
}

pub type Result<T> = std::result::Result<T, SessionError>;

/// Permissions and policies bound to a session key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPolicy {
    /// Maximum Unix timestamp when the session expires.
    pub expires_at: u64,
    /// Whitelisted contract IDs that the session key can invoke.
    pub allowed_contracts: HashSet<String>,
    /// Whitelisted methods per contract ID (`contract_id` -> set of method names).
    pub allowed_methods: HashMap<String, HashSet<String>>,
    /// Optional maximum cumulative spend limit in stroops/stroop equivalent.
    pub max_spend_limit: Option<u64>,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            expires_at: current_unix_timestamp() + 3600, // Default 1 hour TTL
            allowed_contracts: HashSet::new(),
            allowed_methods: HashMap::new(),
            max_spend_limit: None,
        }
    }
}

/// Represents an active or revoked session key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKey {
    /// Unique identifier for the session key.
    pub session_id: String,
    /// Account address (G-address) owning this session key.
    pub account_id: String,
    /// Public key string of the ephemeral session key pair.
    pub session_public_key: String,
    /// Policy and restrictions.
    pub policy: SessionPolicy,
    /// Total cumulative amount spent by this session key so far.
    pub total_spent: u64,
    /// Whether the session key has been explicitly revoked.
    pub is_revoked: bool,
    /// Unix timestamp when the session key was created.
    pub created_at: u64,
}

impl SessionKey {
    /// Creates a new active session key.
    pub fn new(
        session_id: impl Into<String>,
        account_id: impl Into<String>,
        session_public_key: impl Into<String>,
        policy: SessionPolicy,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            account_id: account_id.into(),
            session_public_key: session_public_key.into(),
            policy,
            total_spent: 0,
            is_revoked: false,
            created_at: current_unix_timestamp(),
        }
    }

    /// Checks whether the session key is currently valid (unexpired and unrevoked).
    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        !self.is_revoked && self.policy.expires_at > now
    }

    /// Builds a deterministic [`SessionKeySummary`] if this session key is active
    /// (unrevoked and unexpired) at Unix timestamp `now`.
    ///
    /// Returns `None` when the session is revoked or `now >= policy.expires_at`.
    #[must_use]
    pub fn summary_at(&self, now: u64) -> Option<SessionKeySummary> {
        if !self.is_valid_at(now) {
            return None;
        }

        let mut allowed_contracts: Vec<String> =
            self.policy.allowed_contracts.iter().cloned().collect();
        allowed_contracts.sort();

        let mut allowed_methods: Vec<(String, Vec<String>)> = self
            .policy
            .allowed_methods
            .iter()
            .map(|(contract, methods)| {
                let mut sorted: Vec<String> = methods.iter().cloned().collect();
                sorted.sort();
                (contract.clone(), sorted)
            })
            .collect();
        allowed_methods.sort_by(|a, b| a.0.cmp(&b.0));

        let remaining_spend = self
            .policy
            .max_spend_limit
            .map(|limit| limit.saturating_sub(self.total_spent));

        Some(SessionKeySummary {
            session_id: self.session_id.clone(),
            account_id: self.account_id.clone(),
            session_public_key: self.session_public_key.clone(),
            allowed_contracts,
            allowed_methods,
            max_spend_limit: self.policy.max_spend_limit,
            total_spent: self.total_spent,
            remaining_spend,
            created_at: self.created_at,
            expires_at: self.policy.expires_at,
            expires_in_secs: self.policy.expires_at - now,
        })
    }
}

/// Human- and machine-readable summary of an active session key's scopes and
/// expiry timestamp.
///
/// Returned by [`AccountAbstractionManager::active_session_summaries`] and
/// [`AccountAbstractionManager::get_active_session_summary`]. All collections
/// are sorted deterministically so display output and snapshots are stable.
/// Only public metadata is included; secret key material is never stored or
/// displayed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKeySummary {
    /// Unique identifier for the session key.
    pub session_id: String,
    /// Account address (G-address) owning this session key.
    pub account_id: String,
    /// Public key of the ephemeral session key pair.
    pub session_public_key: String,
    /// Sorted list of whitelisted contract IDs (empty means any contract).
    pub allowed_contracts: Vec<String>,
    /// Sorted list of `(contract_id, sorted_methods)` scope entries.
    pub allowed_methods: Vec<(String, Vec<String>)>,
    /// Optional maximum cumulative spend limit in stroops.
    pub max_spend_limit: Option<u64>,
    /// Cumulative amount already spent by this session key.
    pub total_spent: u64,
    /// Remaining spend allowance if `max_spend_limit` is set.
    pub remaining_spend: Option<u64>,
    /// Unix timestamp when the session key was created.
    pub created_at: u64,
    /// Unix timestamp when the session key expires.
    pub expires_at: u64,
    /// Seconds remaining until expiry relative to the query timestamp.
    pub expires_in_secs: u64,
}

impl fmt::Display for SessionKeySummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Session: {}", self.session_id)?;
        writeln!(f, "  Public Key : {}", self.session_public_key)?;
        writeln!(
            f,
            "  Expires At : {} (unix: {}, in {}s)",
            format_unix_timestamp_utc(self.expires_at),
            self.expires_at,
            self.expires_in_secs
        )?;

        if self.allowed_contracts.is_empty() {
            writeln!(f, "  Contracts  : any")?;
        } else {
            writeln!(f, "  Contracts  : {}", self.allowed_contracts.join(", "))?;
        }

        if self.allowed_methods.is_empty() {
            writeln!(f, "  Methods    : any")?;
        } else {
            let formatted: Vec<String> = self
                .allowed_methods
                .iter()
                .map(|(contract, methods)| {
                    if methods.is_empty() {
                        format!("{contract}: any")
                    } else {
                        format!("{contract}: [{}]", methods.join(", "))
                    }
                })
                .collect();
            writeln!(f, "  Methods    : {}", formatted.join("; "))?;
        }

        match (self.max_spend_limit, self.remaining_spend) {
            (Some(limit), Some(remaining)) => write!(
                f,
                "  Spend Limit: {remaining}/{limit} stroops remaining (spent: {})",
                self.total_spent
            ),
            _ => write!(f, "  Spend Limit: unlimited (spent: {})", self.total_spent),
        }
    }
}

/// Formats a list of active [`SessionKeySummary`] records for `account_id` into
/// a human-readable display string.
#[must_use]
pub fn format_active_session_summaries(
    account_id: &str,
    summaries: &[SessionKeySummary],
) -> String {
    if summaries.is_empty() {
        return format!("No active session keys for account `{account_id}`.");
    }

    let mut out = format!(
        "Active session keys for account `{account_id}` ({}):\n",
        summaries.len()
    );
    for (idx, summary) in summaries.iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(&summary.to_string());
        out.push('\n');
    }
    out
}

/// Formats a Unix timestamp (seconds since 1970-01-01T00:00:00Z) as an ISO-8601
/// UTC string (`YYYY-MM-DDTHH:MM:SSZ`), or `"overflow"` if the timestamp cannot
/// be represented as a signed 64-bit day count.
#[must_use]
pub fn format_unix_timestamp_utc(ts: u64) -> String {
    let secs_of_day = ts % 86_400;
    let Ok(days) = i64::try_from(ts / 86_400) else {
        return "overflow".to_string();
    };
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;

    // Howard Hinnant's civil-from-days algorithm (UTC proleptic Gregorian).
    let Some(z) = days.checked_add(719_468) else {
        return "overflow".to_string();
    };
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = y + i64::from(m <= 2);

    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Validates that `account_id` is non-empty and does not look like a Stellar
/// secret seed (`S...` of length 56), preventing accidental secret leakage in
/// output or logs.
fn validate_account_id(account_id: &str) -> Result<()> {
    if account_id.trim().is_empty() {
        return Err(SessionError::InvalidAccountId(
            "account_id must not be empty".to_string(),
        ));
    }
    if account_id.len() == 56 && account_id.starts_with('S') {
        return Err(SessionError::InvalidAccountId(
            "account_id must be a public account identifier, not a secret key".to_string(),
        ));
    }
    Ok(())
}

/// Guardian details for Account Abstraction social recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Guardian {
    pub guardian_id: String,
    pub public_key: String,
    pub is_active: bool,
}

/// A member of the account's **veto guardian set**.
///
/// This is deliberately a distinct role from [`Guardian`], not a flag on it.
/// See [`AccountAbstractionManager::veto_recovery`] for why the separation of
/// duties matters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VetoGuardian {
    pub guardian_id: String,
    pub public_key: String,
    pub is_active: bool,
}

/// A single veto cast by a veto guardian against an in-flight recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryVeto {
    pub veto_guardian_id: String,
    pub reason: String,
    pub cast_at: u64,
}

/// State of an in-flight account recovery process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRequest {
    pub recovery_id: String,
    pub account_id: String,
    pub proposed_new_owner_key: String,
    pub threshold: usize,
    pub confirmed_guardians: HashSet<String>,
    pub is_executed: bool,
    pub created_at: u64,
    /// Number of distinct vetoes required to block execution. `1` means a
    /// single veto guardian can stop the recovery on its own.
    pub veto_threshold: usize,
    /// Outstanding vetoes, keyed by veto guardian id. Never expires and is
    /// only removed by [`AccountAbstractionManager::clear_veto`].
    pub vetoes: HashMap<String, RecoveryVeto>,
}

impl RecoveryRequest {
    /// Number of distinct vetoes currently outstanding.
    #[must_use]
    pub fn veto_count(&self) -> usize {
        self.vetoes.len()
    }

    /// Whether enough distinct vetoes have accumulated to block execution.
    #[must_use]
    pub fn is_vetoed(&self) -> bool {
        self.vetoes.len() >= self.veto_threshold
    }
}

/// Account Abstraction Manager handling session keys and guardian recovery UX.
#[derive(Debug, Default)]
pub struct AccountAbstractionManager {
    sessions: HashMap<String, SessionKey>,
    guardians: HashMap<String, Vec<Guardian>>, // account_id -> list of guardians
    veto_guardians: HashMap<String, Vec<VetoGuardian>>, // account_id -> veto guardian set
    recovery_requests: HashMap<String, RecoveryRequest>,
}

impl AccountAbstractionManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            guardians: HashMap::new(),
            veto_guardians: HashMap::new(),
            recovery_requests: HashMap::new(),
        }
    }

    /// Register a new session key for an account.
    pub fn register_session(&mut self, session: SessionKey) {
        self.sessions.insert(session.session_id.clone(), session);
    }

    /// Retrieve a reference to a session key.
    #[must_use]
    pub fn get_session(&self, session_id: &str) -> Option<&SessionKey> {
        self.sessions.get(session_id)
    }

    /// Revokes an existing session key immediately.
    pub fn revoke_session(&mut self, session_id: &str) -> Result<()> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| SessionError::SessionNotFound(session_id.to_string()))?;
        session.is_revoked = true;
        Ok(())
    }

    /// Revokes a single session key identified by `session_id`, verifying that
    /// it belongs to `account_id` before flipping the revocation flag (issue #334).
    ///
    /// This is the preferred revocation entry point: it confirms ownership so
    /// one account cannot revoke another account's session key. The account key
    /// itself is **never touched** — this operation only marks the specified
    /// session key as revoked.
    ///
    /// # Errors
    ///
    /// * [`SessionError::SessionNotFound`] — no session with `session_id` exists.
    /// * [`SessionError::SessionNotOwned`] — the session exists but its
    ///   `account_id` does not match the supplied `account_id`. The error
    ///   message is intentionally identical to `SessionNotFound` to prevent
    ///   leaking cross-account existence information.
    /// * [`SessionError::SessionRevoked`] — the session is already revoked.
    pub fn revoke_session_authorized(&mut self, account_id: &str, session_id: &str) -> Result<()> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| SessionError::SessionNotFound(session_id.to_string()))?;

        // Ownership check: prevent cross-account revocation.
        if session.account_id != account_id {
            return Err(SessionError::SessionNotOwned(session_id.to_string()));
        }

        // Reject double-revocation so the caller gets an explicit signal.
        if session.is_revoked {
            return Err(SessionError::SessionRevoked(session_id.to_string()));
        }

        session.is_revoked = true;
        Ok(())
    }

    /// Revokes the session key whose **public key** matches `session_public_key`,
    /// within the given `account_id` (issue #334).
    ///
    /// A session may be identified by its ephemeral public key when the caller
    /// knows the key but not the internal session ID (e.g. from a hardware
    /// wallet flow or an on-chain event). Like [`revoke_session_authorized`],
    /// this only revokes the matching session and does not rotate the account
    /// key.
    ///
    /// # Errors
    ///
    /// * [`SessionError::SessionNotFound`] — no session with the given
    ///   `session_public_key` and `account_id` exists. The same error is
    ///   returned when a matching public key exists under a *different*
    ///   account, to avoid leaking cross-account existence information.
    /// * [`SessionError::SessionRevoked`] — the session is already revoked.
    ///
    /// [`revoke_session_authorized`]: Self::revoke_session_authorized
    pub fn revoke_session_by_public_key(
        &mut self,
        account_id: &str,
        session_public_key: &str,
    ) -> Result<()> {
        // Scan for a session that matches BOTH the public key AND the account.
        // We do not expose a session that belongs to a different account, even
        // if its public key matches — the error is SessionNotFound in both
        // cases.
        let session = self
            .sessions
            .values_mut()
            .find(|s| s.session_public_key == session_public_key && s.account_id == account_id)
            .ok_or_else(|| SessionError::SessionNotFound(session_public_key.to_string()))?;

        if session.is_revoked {
            return Err(SessionError::SessionRevoked(session.session_id.clone()));
        }

        session.is_revoked = true;
        Ok(())
    }

    /// List all session key IDs registered for `account_id`, regardless of
    /// revocation or expiry status.
    #[must_use]
    pub fn list_sessions(&self, account_id: &str) -> Vec<&SessionKey> {
        self.sessions
            .values()
            .filter(|s| s.account_id == account_id)
            .collect()
    }

    /// Returns deterministic summaries of all **active** (unrevoked and
    /// unexpired at `now`) session keys owned by `account_id`, including their
    /// contract/method/spend scopes and expiry timestamps.
    ///
    /// Results are ordered by soonest expiry first, then by `session_id`.
    /// Sessions belonging to other accounts, revoked sessions, and sessions
    /// where `now >= policy.expires_at` are excluded.
    ///
    /// # Errors
    ///
    /// * [`SessionError::InvalidAccountId`] — `account_id` is empty,
    ///   whitespace-only, or looks like a Stellar secret key (`S...`).
    pub fn active_session_summaries(
        &self,
        account_id: &str,
        now: u64,
    ) -> Result<Vec<SessionKeySummary>> {
        validate_account_id(account_id)?;

        let mut summaries: Vec<SessionKeySummary> = self
            .sessions
            .values()
            .filter(|s| s.account_id == account_id)
            .filter_map(|s| s.summary_at(now))
            .collect();

        summaries.sort_by(|a, b| {
            a.expires_at
                .cmp(&b.expires_at)
                .then_with(|| a.session_id.cmp(&b.session_id))
        });

        Ok(summaries)
    }

    /// Returns the [`SessionKeySummary`] for a single active session key
    /// identified by `session_id`, verifying that it belongs to `account_id`
    /// and is neither revoked nor expired at `now`.
    ///
    /// # Errors
    ///
    /// * [`SessionError::InvalidAccountId`] — `account_id` is empty,
    ///   whitespace-only, or looks like a Stellar secret key (`S...`).
    /// * [`SessionError::SessionNotFound`] — no session with `session_id` exists.
    /// * [`SessionError::SessionNotOwned`] — the session belongs to a different
    ///   account (error message intentionally matches `SessionNotFound`).
    /// * [`SessionError::SessionRevoked`] — the session has been revoked.
    /// * [`SessionError::SessionExpired`] — `now >= policy.expires_at`.
    pub fn get_active_session_summary(
        &self,
        account_id: &str,
        session_id: &str,
        now: u64,
    ) -> Result<SessionKeySummary> {
        validate_account_id(account_id)?;

        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| SessionError::SessionNotFound(session_id.to_string()))?;

        if session.account_id != account_id {
            return Err(SessionError::SessionNotOwned(session_id.to_string()));
        }

        if session.is_revoked {
            return Err(SessionError::SessionRevoked(session_id.to_string()));
        }

        if now >= session.policy.expires_at {
            return Err(SessionError::SessionExpired(
                session_id.to_string(),
                session.policy.expires_at,
            ));
        }

        Ok(session
            .summary_at(now)
            .expect("session was just validated as unrevoked and unexpired"))
    }

    /// Formats all active session keys for `account_id` at timestamp `now`
    /// into a human-readable display string showing each key's scopes and
    /// expiry timestamp.
    ///
    /// # Errors
    ///
    /// * [`SessionError::InvalidAccountId`] — `account_id` is empty,
    ///   whitespace-only, or looks like a Stellar secret key (`S...`).
    pub fn format_active_sessions(&self, account_id: &str, now: u64) -> Result<String> {
        let summaries = self.active_session_summaries(account_id, now)?;
        Ok(format_active_session_summaries(account_id, &summaries))
    }

    /// Validates an intended contract call against session key policies.
    pub fn validate_and_record_call(
        &mut self,
        session_id: &str,
        contract_id: &str,
        method: &str,
        amount: u64,
        now: u64,
    ) -> Result<()> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| SessionError::SessionNotFound(session_id.to_string()))?;

        if session.is_revoked {
            return Err(SessionError::SessionRevoked(session_id.to_string()));
        }

        if now >= session.policy.expires_at {
            return Err(SessionError::SessionExpired(
                session_id.to_string(),
                session.policy.expires_at,
            ));
        }

        if !session.policy.allowed_contracts.is_empty()
            && !session.policy.allowed_contracts.contains(contract_id)
        {
            return Err(SessionError::ContractNotAllowed(
                contract_id.to_string(),
                session_id.to_string(),
            ));
        }

        if let Some(methods) = session.policy.allowed_methods.get(contract_id) {
            if !methods.is_empty() && !methods.contains(method) {
                return Err(SessionError::MethodNotAllowed(
                    method.to_string(),
                    contract_id.to_string(),
                    session_id.to_string(),
                ));
            }
        }

        if let Some(max_limit) = session.policy.max_spend_limit {
            let remaining = max_limit.saturating_sub(session.total_spent);
            if amount > remaining {
                return Err(SessionError::SpendLimitExceeded(
                    session_id.to_string(),
                    amount,
                    remaining,
                ));
            }
            session.total_spent += amount;
        }

        Ok(())
    }

    /// Simulates signing a payload using a validated session key.
    pub fn sign_with_session(&self, session_id: &str, payload: &[u8], now: u64) -> Result<Vec<u8>> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| SessionError::SessionNotFound(session_id.to_string()))?;

        if !session.is_valid_at(now) {
            if session.is_revoked {
                return Err(SessionError::SessionRevoked(session_id.to_string()));
            }
            return Err(SessionError::SessionExpired(
                session_id.to_string(),
                session.policy.expires_at,
            ));
        }

        // Mock signature for abstraction layer testability
        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(session.session_public_key.as_bytes());
        signature.extend_from_slice(payload);
        signature.truncate(64);
        Ok(signature)
    }

    /// Configures guardians for account social recovery.
    pub fn set_guardians(&mut self, account_id: impl Into<String>, guardians: Vec<Guardian>) {
        self.guardians.insert(account_id.into(), guardians);
    }

    /// Configures the account's **veto guardian set**.
    ///
    /// Members of this set can block an in-flight recovery but cannot advance
    /// one. See [`AccountAbstractionManager::veto_recovery`] for the rationale
    /// behind keeping the two roles separate.
    pub fn set_veto_guardians(
        &mut self,
        account_id: impl Into<String>,
        veto_guardians: Vec<VetoGuardian>,
    ) {
        self.veto_guardians
            .insert(account_id.into(), veto_guardians);
    }

    /// Initiate an account recovery request with the default veto threshold of 1
    /// (any single veto guardian may block it).
    pub fn initiate_recovery(
        &mut self,
        recovery_id: impl Into<String>,
        account_id: impl Into<String>,
        proposed_new_owner_key: impl Into<String>,
        threshold: usize,
    ) -> String {
        self.initiate_recovery_with_veto(
            recovery_id,
            account_id,
            proposed_new_owner_key,
            threshold,
            1,
        )
    }

    /// Initiate an account recovery request with an explicit veto threshold.
    ///
    /// `veto_threshold` is the number of distinct vetoes needed to block
    /// execution. `1` gives the veto set a unilateral circuit-breaker; higher
    /// values trade that for resistance to a single compromised veto guardian.
    pub fn initiate_recovery_with_veto(
        &mut self,
        recovery_id: impl Into<String>,
        account_id: impl Into<String>,
        proposed_new_owner_key: impl Into<String>,
        threshold: usize,
        veto_threshold: usize,
    ) -> String {
        let rec_id = recovery_id.into();
        let request = RecoveryRequest {
            recovery_id: rec_id.clone(),
            account_id: account_id.into(),
            proposed_new_owner_key: proposed_new_owner_key.into(),
            threshold,
            confirmed_guardians: HashSet::new(),
            is_executed: false,
            created_at: current_unix_timestamp(),
            veto_threshold,
            vetoes: HashMap::new(),
        };
        self.recovery_requests.insert(rec_id.clone(), request);
        rec_id
    }

    /// Retrieve a reference to an in-flight (or completed) recovery request.
    #[must_use]
    pub fn get_recovery(&self, recovery_id: &str) -> Option<&RecoveryRequest> {
        self.recovery_requests.get(recovery_id)
    }

    /// Submit a guardian confirmation for an in-flight recovery request.
    ///
    /// The confirmation is always recorded. When it pushes the request over
    /// `threshold`, execution is attempted — and refused with
    /// [`SessionError::RecoveryVetoed`] if the veto threshold is currently met.
    /// That check is the single enforcement point for vetoes: quorum alone is
    /// never sufficient to take over an account.
    pub fn confirm_recovery(&mut self, recovery_id: &str, guardian_id: &str) -> Result<bool> {
        let request = self
            .recovery_requests
            .get_mut(recovery_id)
            .ok_or_else(|| SessionError::SessionNotFound(recovery_id.to_string()))?;

        if request.is_executed {
            return Err(SessionError::RecoveryAlreadyExecuted(
                recovery_id.to_string(),
            ));
        }

        // Verify guardian is registered for account
        let guardians = self
            .guardians
            .get(&request.account_id)
            .ok_or_else(|| SessionError::InvalidGuardianSignature(guardian_id.to_string()))?;

        let is_valid = guardians
            .iter()
            .any(|g| g.guardian_id == guardian_id && g.is_active);

        if !is_valid {
            return Err(SessionError::InvalidGuardianSignature(
                guardian_id.to_string(),
            ));
        }

        request.confirmed_guardians.insert(guardian_id.to_string());

        if request.confirmed_guardians.len() >= request.threshold {
            if request.is_vetoed() {
                // Quorum reached, but the veto set is holding execution.
                return Err(SessionError::RecoveryVetoed(
                    recovery_id.to_string(),
                    request.veto_count(),
                    request.veto_threshold,
                ));
            }
            request.is_executed = true;
            Ok(true) // Recovery threshold met, not vetoed, and executed
        } else {
            Ok(false)
        }
    }

    /// Attempt to execute a recovery whose threshold is already met.
    ///
    /// This is the step a veto actually holds up: after a veto is cast against
    /// a request that has already reached quorum, clearing the veto and calling
    /// this completes the recovery without needing another confirmation.
    pub fn try_execute_recovery(&mut self, recovery_id: &str) -> Result<bool> {
        let request = self
            .recovery_requests
            .get_mut(recovery_id)
            .ok_or_else(|| SessionError::SessionNotFound(recovery_id.to_string()))?;

        if request.is_executed {
            return Ok(true);
        }

        let confirmed = request.confirmed_guardians.len();
        if confirmed < request.threshold {
            return Err(SessionError::RecoveryThresholdNotMet(
                request.threshold,
                confirmed,
            ));
        }

        if request.is_vetoed() {
            return Err(SessionError::RecoveryVetoed(
                recovery_id.to_string(),
                request.veto_count(),
                request.veto_threshold,
            ));
        }

        request.is_executed = true;
        Ok(true)
    }

    /// Record a veto against an in-flight recovery, returning the veto count.
    ///
    /// Only an **active member of the account's veto guardian set** may veto.
    /// Recovery guardians cannot veto, and veto guardians cannot confirm —
    /// the roles are disjoint, so a quorum that is compromised or coerced
    /// cannot authorise a takeover and then veto its own attempt into a
    /// permanent denial of service. Unregistered and inactive veto guardians
    /// are rejected with [`SessionError::InvalidGuardianSignature`], matching
    /// how [`AccountAbstractionManager::confirm_recovery`] treats bad
    /// recovery confirmations.
    ///
    /// Re-vetoing an already-vetoed recovery is idempotent: the original
    /// record and its timestamp are preserved and the count is unchanged.
    pub fn veto_recovery(
        &mut self,
        recovery_id: &str,
        veto_guardian_id: &str,
        reason: impl Into<String>,
        now: u64,
    ) -> Result<usize> {
        let request = self
            .recovery_requests
            .get(recovery_id)
            .ok_or_else(|| SessionError::SessionNotFound(recovery_id.to_string()))?;

        if request.is_executed {
            // Too late — the ownership change already happened. Reporting this
            // rather than silently succeeding is what makes a late veto visible.
            return Err(SessionError::RecoveryAlreadyExecuted(
                recovery_id.to_string(),
            ));
        }

        let veto_guardians = self
            .veto_guardians
            .get(&request.account_id)
            .ok_or_else(|| SessionError::InvalidGuardianSignature(veto_guardian_id.to_string()))?;

        let is_valid = veto_guardians
            .iter()
            .any(|g| g.guardian_id == veto_guardian_id && g.is_active);

        if !is_valid {
            return Err(SessionError::InvalidGuardianSignature(
                veto_guardian_id.to_string(),
            ));
        }

        let request = self
            .recovery_requests
            .get_mut(recovery_id)
            .expect("request was just read and nothing else was borrowed");

        request
            .vetoes
            .entry(veto_guardian_id.to_string())
            .or_insert(RecoveryVeto {
                veto_guardian_id: veto_guardian_id.to_string(),
                reason: reason.into(),
                cast_at: now,
            });

        Ok(request.veto_count())
    }

    /// Retract a previously cast veto.
    ///
    /// Only the veto guardian that cast the veto may retract it, and only
    /// while the recovery has not executed. This is the deliberate escape
    /// valve against a permanent denial of service: a mistaken or coerced
    /// veto can be walked back by the party that made it. The broader escape
    /// is that a *new* recovery request is a new object with a clean veto
    /// set, so no amount of standing vetoes can permanently lock an account.
    pub fn clear_veto(&mut self, recovery_id: &str, veto_guardian_id: &str) -> Result<usize> {
        let request = self
            .recovery_requests
            .get_mut(recovery_id)
            .ok_or_else(|| SessionError::SessionNotFound(recovery_id.to_string()))?;

        if request.is_executed {
            return Err(SessionError::RecoveryAlreadyExecuted(
                recovery_id.to_string(),
            ));
        }

        request
            .vetoes
            .remove(veto_guardian_id)
            .ok_or_else(|| SessionError::VetoNotFound(veto_guardian_id.to_string()))?;

        Ok(request.veto_count())
    }

    /// Whether an in-flight recovery is currently blocked by its veto set.
    pub fn is_recovery_vetoed(&self, recovery_id: &str) -> Result<bool> {
        self.recovery_requests
            .get(recovery_id)
            .map(RecoveryRequest::is_vetoed)
            .ok_or_else(|| SessionError::SessionNotFound(recovery_id.to_string()))
    }
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_key_lifecycle_and_validation() {
        let mut manager = AccountAbstractionManager::new();

        let policy = SessionPolicy {
            expires_at: 1000,
            allowed_contracts: HashSet::from(["contract_amm".to_string()]),
            allowed_methods: HashMap::from([(
                "contract_amm".to_string(),
                HashSet::from(["swap".to_string()]),
            )]),
            max_spend_limit: Some(500),
        };

        let session = SessionKey::new("sess_1", "acc_g1", "pub_sess_1", policy.clone());
        manager.register_session(session);

        // Valid call before expiry
        assert!(manager
            .validate_and_record_call("sess_1", "contract_amm", "swap", 200, 500)
            .is_ok());

        // Check spend limit tracking
        assert_eq!(manager.get_session("sess_1").unwrap().total_spent, 200);

        // Call exceeding remaining spend limit (200 + 400 > 500)
        let res = manager.validate_and_record_call("sess_1", "contract_amm", "swap", 400, 500);
        assert!(matches!(
            res,
            Err(SessionError::SpendLimitExceeded(_, 400, 300))
        ));

        // Unallowed method
        let res =
            manager.validate_and_record_call("sess_1", "contract_amm", "admin_drain", 10, 500);
        assert!(matches!(res, Err(SessionError::MethodNotAllowed(_, _, _))));

        // Expired session
        let res = manager.validate_and_record_call("sess_1", "contract_amm", "swap", 100, 1001);
        assert!(matches!(res, Err(SessionError::SessionExpired(_, 1000))));

        // Revocation
        assert!(manager.revoke_session("sess_1").is_ok());
        let res = manager.validate_and_record_call("sess_1", "contract_amm", "swap", 10, 500);
        assert!(matches!(res, Err(SessionError::SessionRevoked(_))));
    }

    #[test]
    fn test_account_abstraction_guardian_recovery() {
        let mut manager = AccountAbstractionManager::new();

        manager.set_guardians(
            "user_account_1",
            vec![
                Guardian {
                    guardian_id: "g1".to_string(),
                    public_key: "pub_g1".to_string(),
                    is_active: true,
                },
                Guardian {
                    guardian_id: "g2".to_string(),
                    public_key: "pub_g2".to_string(),
                    is_active: true,
                },
                Guardian {
                    guardian_id: "g3".to_string(),
                    public_key: "pub_g3".to_string(),
                    is_active: true,
                },
            ],
        );

        let rec_id = manager.initiate_recovery("rec_100", "user_account_1", "new_owner_pubkey", 2);

        // First guardian confirms (1/2 threshold)
        let executed = manager.confirm_recovery(&rec_id, "g1").unwrap();
        assert!(!executed);

        // Second guardian confirms (2/2 threshold)
        let executed = manager.confirm_recovery(&rec_id, "g2").unwrap();
        assert!(executed);
    }

    /// A manager wired with 3 active recovery guardians and 2 active veto
    /// guardians (`v1`, `v2`) on account `acct_1`.
    fn manager_with_veto_set() -> AccountAbstractionManager {
        let mut manager = AccountAbstractionManager::new();
        manager.set_guardians(
            "acct_1",
            vec![
                Guardian {
                    guardian_id: "g1".into(),
                    public_key: "pub_g1".into(),
                    is_active: true,
                },
                Guardian {
                    guardian_id: "g2".into(),
                    public_key: "pub_g2".into(),
                    is_active: true,
                },
                Guardian {
                    guardian_id: "g3".into(),
                    public_key: "pub_g3".into(),
                    is_active: true,
                },
            ],
        );
        manager.set_veto_guardians(
            "acct_1",
            vec![
                VetoGuardian {
                    guardian_id: "v1".into(),
                    public_key: "pub_v1".into(),
                    is_active: true,
                },
                VetoGuardian {
                    guardian_id: "v2".into(),
                    public_key: "pub_v2".into(),
                    is_active: true,
                },
                VetoGuardian {
                    guardian_id: "v3".into(),
                    public_key: "pub_v3".into(),
                    is_active: false,
                },
            ],
        );
        manager
    }

    #[test]
    fn test_veto_before_threshold_blocks_execution() {
        let mut manager = manager_with_veto_set();
        let rec = manager.initiate_recovery("rec_a", "acct_1", "new_owner", 2);

        // Veto lands while the request is still short of quorum.
        assert_eq!(
            manager
                .veto_recovery(&rec, "v1", "coerced signer", 1000)
                .unwrap(),
            1
        );
        assert!(manager.is_recovery_vetoed(&rec).unwrap());

        // One confirmation is still fine and returns false.
        assert!(!manager.confirm_recovery(&rec, "g1").unwrap());

        // The confirmation that crosses the threshold is REFUSED, not executed.
        let err = manager.confirm_recovery(&rec, "g2").unwrap_err();
        assert!(matches!(err, SessionError::RecoveryVetoed(ref id, 1, 1) if id == &rec));

        let request = manager.get_recovery(&rec).unwrap();
        assert!(!request.is_executed, "veto must prevent execution");
        // The confirmation itself is still recorded, so quorum is not lost.
        assert_eq!(request.confirmed_guardians.len(), 2);
    }

    #[test]
    fn test_veto_after_threshold_but_before_execution() {
        let mut manager = manager_with_veto_set();
        let rec = manager.initiate_recovery_with_veto("rec_b", "acct_1", "new_owner", 2, 1);

        // Reach quorum, but hold execution back by requiring an explicit step.
        // `veto_recovery` is refused once execution has happened, so the veto
        // has to be cast in the same window the quorum is reached.
        assert_eq!(
            manager
                .veto_recovery(&rec, "v1", "late objection", 1000)
                .unwrap(),
            1
        );
        assert!(!manager.confirm_recovery(&rec, "g1").unwrap());
        assert!(matches!(
            manager.confirm_recovery(&rec, "g2").unwrap_err(),
            SessionError::RecoveryVetoed(_, 1, 1)
        ));

        // Clearing the veto unblocks the already-reached quorum.
        assert_eq!(manager.clear_veto(&rec, "v1").unwrap(), 0);
        assert!(!manager.is_recovery_vetoed(&rec).unwrap());
        assert!(manager.try_execute_recovery(&rec).unwrap());
        assert!(manager.get_recovery(&rec).unwrap().is_executed);
    }

    #[test]
    fn test_clearing_a_veto_allows_recovery_to_proceed() {
        let mut manager = manager_with_veto_set();
        let rec = manager.initiate_recovery("rec_c", "acct_1", "new_owner", 2);

        manager
            .veto_recovery(&rec, "v1", "misunderstanding", 1000)
            .unwrap();
        assert!(!manager.confirm_recovery(&rec, "g1").unwrap());
        assert!(manager.confirm_recovery(&rec, "g2").is_err());

        manager.clear_veto(&rec, "v1").unwrap();

        // A fresh confirmation now carries the request over the line.
        assert!(manager.confirm_recovery(&rec, "g3").unwrap());
        assert!(manager.get_recovery(&rec).unwrap().is_executed);
    }

    #[test]
    fn test_veto_from_unregistered_or_inactive_guardian_is_rejected() {
        let mut manager = manager_with_veto_set();
        let rec = manager.initiate_recovery("rec_d", "acct_1", "new_owner", 2);

        // Not a member of the veto set at all.
        assert!(matches!(
            manager.veto_recovery(&rec, "stranger", "nope", 1000).unwrap_err(),
            SessionError::InvalidGuardianSignature(ref id) if id == "stranger"
        ));

        // Registered but inactive.
        assert!(matches!(
            manager.veto_recovery(&rec, "v3", "nope", 1000).unwrap_err(),
            SessionError::InvalidGuardianSignature(ref id) if id == "v3"
        ));

        // A recovery guardian is NOT implicitly a veto guardian.
        assert!(matches!(
            manager.veto_recovery(&rec, "g1", "nope", 1000).unwrap_err(),
            SessionError::InvalidGuardianSignature(ref id) if id == "g1"
        ));

        // No veto landed, so recovery proceeds normally.
        assert!(!manager.confirm_recovery(&rec, "g1").unwrap());
        assert!(manager.confirm_recovery(&rec, "g2").unwrap());
    }

    #[test]
    fn test_double_veto_is_idempotent() {
        let mut manager = manager_with_veto_set();
        let rec = manager.initiate_recovery("rec_e", "acct_1", "new_owner", 2);

        assert_eq!(
            manager
                .veto_recovery(&rec, "v1", "first reason", 1000)
                .unwrap(),
            1
        );
        // Same guardian vetoing again must not inflate the count, and must not
        // clobber the original reason/timestamp.
        assert_eq!(
            manager
                .veto_recovery(&rec, "v1", "second reason", 2000)
                .unwrap(),
            1
        );

        let request = manager.get_recovery(&rec).unwrap();
        assert_eq!(request.veto_count(), 1);
        assert_eq!(request.vetoes["v1"].reason, "first reason");
        assert_eq!(request.vetoes["v1"].cast_at, 1000);

        // Clearing once fully clears it; clearing again is a clear error.
        assert_eq!(manager.clear_veto(&rec, "v1").unwrap(), 0);
        assert!(matches!(
            manager.clear_veto(&rec, "v1").unwrap_err(),
            SessionError::VetoNotFound(ref id) if id == "v1"
        ));
    }

    #[test]
    fn test_veto_threshold_greater_than_one() {
        let mut manager = manager_with_veto_set();
        let rec = manager.initiate_recovery_with_veto("rec_f", "acct_1", "new_owner", 2, 2);

        // One veto is recorded but not yet enough to block.
        assert_eq!(manager.veto_recovery(&rec, "v1", "one", 1000).unwrap(), 1);
        assert!(!manager.is_recovery_vetoed(&rec).unwrap());

        assert!(!manager.confirm_recovery(&rec, "g1").unwrap());
        // Still not blocked at one veto out of two.
        assert!(manager.confirm_recovery(&rec, "g2").unwrap());

        // Vetoing an already-executed recovery is refused, not silently ignored.
        assert!(matches!(
            manager.veto_recovery(&rec, "v2", "too late", 2000).unwrap_err(),
            SessionError::RecoveryAlreadyExecuted(ref id) if id == &rec
        ));
    }

    #[test]
    fn test_two_vetoes_block_at_threshold_of_two() {
        let mut manager = manager_with_veto_set();
        let rec = manager.initiate_recovery_with_veto("rec_g", "acct_1", "new_owner", 2, 2);

        assert_eq!(manager.veto_recovery(&rec, "v1", "one", 1000).unwrap(), 1);
        assert_eq!(manager.veto_recovery(&rec, "v2", "two", 1000).unwrap(), 2);
        assert!(manager.is_recovery_vetoed(&rec).unwrap());

        assert!(!manager.confirm_recovery(&rec, "g1").unwrap());
        // The second confirmation reaches quorum but is refused by the veto set.
        assert!(matches!(
            manager.confirm_recovery(&rec, "g2").unwrap_err(),
            SessionError::RecoveryVetoed(_, 2, 2)
        ));
        // Quorum is recorded, so the only thing standing in the way is the veto.
        assert_eq!(
            manager
                .get_recovery(&rec)
                .unwrap()
                .confirmed_guardians
                .len(),
            2
        );
        assert!(matches!(
            manager.try_execute_recovery(&rec).unwrap_err(),
            SessionError::RecoveryVetoed(_, 2, 2)
        ));
        assert!(!manager.get_recovery(&rec).unwrap().is_executed);
    }

    #[test]
    fn test_veto_does_not_survive_into_a_new_recovery_request() {
        let mut manager = manager_with_veto_set();
        let stale = manager.initiate_recovery("rec_old", "acct_1", "attacker", 2);
        manager.veto_recovery(&stale, "v1", "attack", 1000).unwrap();
        assert!(manager.is_recovery_vetoed(&stale).unwrap());

        // A new request id is a new object with a clean veto set — this is the
        // anti-denial-of-service property that lets vetoes be non-expiring.
        let fresh = manager.initiate_recovery("rec_new", "acct_1", "legit_owner", 2);
        assert!(!manager.is_recovery_vetoed(&fresh).unwrap());
        assert!(!manager.confirm_recovery(&fresh, "g1").unwrap());
        assert!(manager.confirm_recovery(&fresh, "g2").unwrap());
    }

    #[test]
    fn test_operations_on_unknown_recovery_report_not_found() {
        let mut manager = manager_with_veto_set();
        assert!(matches!(
            manager.veto_recovery("nope", "v1", "x", 0).unwrap_err(),
            SessionError::SessionNotFound(_)
        ));
        assert!(matches!(
            manager.clear_veto("nope", "v1").unwrap_err(),
            SessionError::SessionNotFound(_)
        ));
        assert!(matches!(
            manager.try_execute_recovery("nope").unwrap_err(),
            SessionError::SessionNotFound(_)
        ));
        assert!(matches!(
            manager.is_recovery_vetoed("nope").unwrap_err(),
            SessionError::SessionNotFound(_)
        ));
    }

    #[test]
    fn test_try_execute_recovery_requires_threshold() {
        let mut manager = manager_with_veto_set();
        let rec = manager.initiate_recovery("rec_h", "acct_1", "new_owner", 2);

        assert!(matches!(
            manager.try_execute_recovery(&rec).unwrap_err(),
            SessionError::RecoveryThresholdNotMet(2, 0)
        ));

        assert!(!manager.confirm_recovery(&rec, "g1").unwrap());
        assert!(matches!(
            manager.try_execute_recovery(&rec).unwrap_err(),
            SessionError::RecoveryThresholdNotMet(2, 1)
        ));

        assert!(manager.confirm_recovery(&rec, "g2").unwrap());
        // Already executed: idempotent, not an error.
        assert!(manager.try_execute_recovery(&rec).unwrap());
        // And confirming a completed recovery is refused.
        assert!(matches!(
            manager.confirm_recovery(&rec, "g3").unwrap_err(),
            SessionError::RecoveryAlreadyExecuted(_)
        ));
    }

    #[test]
    fn test_recovery_request_roundtrips_through_serde_with_vetoes() {
        let mut manager = manager_with_veto_set();
        let rec = manager.initiate_recovery_with_veto("rec_i", "acct_1", "new_owner", 2, 1);
        manager
            .veto_recovery(&rec, "v1", "compelled", 12345)
            .unwrap();

        let encoded = serde_json::to_string(manager.get_recovery(&rec).unwrap()).unwrap();
        let decoded: RecoveryRequest = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded.recovery_id, rec);
        assert_eq!(decoded.veto_threshold, 1);
        assert!(decoded.is_vetoed());
        assert_eq!(decoded.vetoes["v1"].reason, "compelled");
        assert_eq!(decoded.vetoes["v1"].cast_at, 12345);
    }

    // ── revoke_session_authorized (issue #334) ────────────────────────────────

    fn session_for(
        session_id: &str,
        account_id: &str,
        public_key: &str,
        expires_at: u64,
    ) -> SessionKey {
        SessionKey::new(
            session_id,
            account_id,
            public_key,
            SessionPolicy {
                expires_at,
                ..SessionPolicy::default()
            },
        )
    }

    #[test]
    fn revoke_authorized_succeeds_for_correct_owner() {
        let mut mgr = AccountAbstractionManager::new();
        mgr.register_session(session_for("s1", "acct_A", "pubkey_A1", 9999));

        assert!(mgr.revoke_session_authorized("acct_A", "s1").is_ok());

        // The key is now rejected by validate_and_record_call.
        let res = mgr.validate_and_record_call("s1", "contract", "fn", 0, 500);
        assert!(
            matches!(res, Err(SessionError::SessionRevoked(_))),
            "revoked key must be rejected: {res:?}"
        );
    }

    #[test]
    fn revoke_authorized_fails_for_unknown_session_id() {
        let mut mgr = AccountAbstractionManager::new();
        let err = mgr
            .revoke_session_authorized("acct_A", "no-such-session")
            .unwrap_err();
        assert!(matches!(err, SessionError::SessionNotFound(_)));
    }

    #[test]
    fn revoke_authorized_fails_when_account_does_not_own_session() {
        let mut mgr = AccountAbstractionManager::new();
        mgr.register_session(session_for("s1", "acct_A", "pubkey_A1", 9999));

        let err = mgr.revoke_session_authorized("acct_B", "s1").unwrap_err();
        // Returns SessionNotOwned (same display as SessionNotFound — no
        // cross-account existence leak).
        assert!(
            matches!(err, SessionError::SessionNotOwned(_)),
            "wrong account must be rejected: {err:?}"
        );

        // The session must remain valid after the failed revocation.
        let session = mgr.get_session("s1").unwrap();
        assert!(
            !session.is_revoked,
            "session must not be revoked after failed attempt"
        );
    }

    #[test]
    fn revoke_authorized_fails_when_session_is_already_revoked() {
        let mut mgr = AccountAbstractionManager::new();
        mgr.register_session(session_for("s1", "acct_A", "pubkey_A1", 9999));

        mgr.revoke_session_authorized("acct_A", "s1").unwrap();
        let err = mgr.revoke_session_authorized("acct_A", "s1").unwrap_err();
        assert!(
            matches!(err, SessionError::SessionRevoked(_)),
            "double-revoke must be rejected: {err:?}"
        );
    }

    #[test]
    fn revoke_authorized_does_not_affect_other_sessions_on_same_account() {
        let mut mgr = AccountAbstractionManager::new();
        mgr.register_session(session_for("s1", "acct_A", "pubkey_A1", 9999));
        mgr.register_session(session_for("s2", "acct_A", "pubkey_A2", 9999));

        mgr.revoke_session_authorized("acct_A", "s1").unwrap();

        // s2 must still be active.
        let s2 = mgr.get_session("s2").unwrap();
        assert!(!s2.is_revoked, "s2 must remain active after revoking s1");
    }

    #[test]
    fn revoke_authorized_does_not_rotate_or_modify_account_key() {
        // wallet.rs has no account-key rotation and session_keys.rs has no
        // reference to wallet.rs — confirm that after revocation the account_id
        // stored on the remaining session key is unchanged.
        let mut mgr = AccountAbstractionManager::new();
        mgr.register_session(session_for("s1", "acct_A", "pubkey_A1", 9999));
        mgr.register_session(session_for("s2", "acct_A", "pubkey_A2", 9999));

        mgr.revoke_session_authorized("acct_A", "s1").unwrap();

        // The account_id on s2 is still what was registered.
        assert_eq!(
            mgr.get_session("s2").unwrap().account_id,
            "acct_A",
            "account_id must be unchanged after session revocation"
        );
    }

    // ── revoke_session_by_public_key (issue #334) ─────────────────────────────

    #[test]
    fn revoke_by_public_key_succeeds_for_correct_owner() {
        let mut mgr = AccountAbstractionManager::new();
        mgr.register_session(session_for("s1", "acct_A", "pubkey_A1", 9999));

        assert!(mgr
            .revoke_session_by_public_key("acct_A", "pubkey_A1")
            .is_ok());

        assert!(mgr.get_session("s1").unwrap().is_revoked);
    }

    #[test]
    fn revoke_by_public_key_fails_for_unknown_key() {
        let mut mgr = AccountAbstractionManager::new();
        let err = mgr
            .revoke_session_by_public_key("acct_A", "nonexistent_pubkey")
            .unwrap_err();
        assert!(matches!(err, SessionError::SessionNotFound(_)));
    }

    #[test]
    fn revoke_by_public_key_does_not_reveal_cross_account_existence() {
        // A key registered under acct_B must not be revocable by acct_A, and
        // the error must be SessionNotFound (not SessionNotOwned) to avoid
        // leaking that the key exists under a different account.
        let mut mgr = AccountAbstractionManager::new();
        mgr.register_session(session_for("s1", "acct_B", "shared_pubkey", 9999));

        let err = mgr
            .revoke_session_by_public_key("acct_A", "shared_pubkey")
            .unwrap_err();
        assert!(
            matches!(err, SessionError::SessionNotFound(_)),
            "cross-account key must return SessionNotFound, got: {err:?}"
        );

        // The key on acct_B must be untouched.
        assert!(!mgr.get_session("s1").unwrap().is_revoked);
    }

    #[test]
    fn revoke_by_public_key_fails_when_already_revoked() {
        let mut mgr = AccountAbstractionManager::new();
        mgr.register_session(session_for("s1", "acct_A", "pubkey_A1", 9999));

        mgr.revoke_session_by_public_key("acct_A", "pubkey_A1")
            .unwrap();
        let err = mgr
            .revoke_session_by_public_key("acct_A", "pubkey_A1")
            .unwrap_err();
        assert!(matches!(err, SessionError::SessionRevoked(_)));
    }

    // ── list_sessions ─────────────────────────────────────────────────────────

    #[test]
    fn list_sessions_returns_only_sessions_for_the_given_account() {
        let mut mgr = AccountAbstractionManager::new();
        mgr.register_session(session_for("s1", "acct_A", "pk1", 9999));
        mgr.register_session(session_for("s2", "acct_A", "pk2", 9999));
        mgr.register_session(session_for("s3", "acct_B", "pk3", 9999));

        let sessions_a = mgr.list_sessions("acct_A");
        assert_eq!(sessions_a.len(), 2);

        let sessions_b = mgr.list_sessions("acct_B");
        assert_eq!(sessions_b.len(), 1);

        let sessions_c = mgr.list_sessions("acct_C");
        assert!(sessions_c.is_empty());
    }

    // ── active session summaries & display ───────────────────────────────────

    #[test]
    fn active_session_summaries_filters_revoked_expired_and_other_accounts() {
        let mut mgr = AccountAbstractionManager::new();

        // Active session expiring later
        mgr.register_session(SessionKey::new(
            "sess_late",
            "GACCT1",
            "GPUB_LATE",
            SessionPolicy {
                expires_at: 2_000,
                allowed_contracts: HashSet::from(["C_DEX".to_string(), "C_AMM".to_string()]),
                allowed_methods: HashMap::from([(
                    "C_AMM".to_string(),
                    HashSet::from(["swap".to_string(), "deposit".to_string()]),
                )]),
                max_spend_limit: Some(1_000),
            },
        ));
        // Active session expiring sooner
        mgr.register_session(session_for("sess_soon", "GACCT1", "GPUB_SOON", 1_500));
        // Expired at boundary (expires_at == now)
        mgr.register_session(session_for("sess_boundary", "GACCT1", "GPUB_BOUND", 1_000));
        // Revoked session
        mgr.register_session(session_for("sess_revoked", "GACCT1", "GPUB_REV", 5_000));
        mgr.revoke_session_authorized("GACCT1", "sess_revoked")
            .unwrap();
        // Other account's active session
        mgr.register_session(session_for("sess_other", "GACCT2", "GPUB_OTHER", 5_000));

        let summaries = mgr.active_session_summaries("GACCT1", 1_000).unwrap();
        assert_eq!(summaries.len(), 2);
        // Ordered soonest expiry first
        assert_eq!(summaries[0].session_id, "sess_soon");
        assert_eq!(summaries[0].expires_in_secs, 500);
        assert_eq!(summaries[1].session_id, "sess_late");
        assert_eq!(summaries[1].expires_in_secs, 1_000);
        // Deterministic sorting of contracts and methods
        assert_eq!(summaries[1].allowed_contracts, vec!["C_AMM", "C_DEX"]);
        assert_eq!(
            summaries[1].allowed_methods,
            vec![(
                "C_AMM".to_string(),
                vec!["deposit".to_string(), "swap".to_string()]
            )]
        );
        assert_eq!(summaries[1].remaining_spend, Some(1_000));
    }

    #[test]
    fn active_session_summary_boundary_one_second_before_and_at_expiry() {
        let mut mgr = AccountAbstractionManager::new();
        mgr.register_session(session_for("s1", "GACCT1", "GPUB1", 1_700_000_000));

        // 1 second before expiry: active
        let summary = mgr
            .get_active_session_summary("GACCT1", "s1", 1_699_999_999)
            .unwrap();
        assert_eq!(summary.expires_in_secs, 1);

        // Exactly at expiry: rejected with SessionExpired
        let err = mgr
            .get_active_session_summary("GACCT1", "s1", 1_700_000_000)
            .unwrap_err();
        assert_eq!(
            err,
            SessionError::SessionExpired("s1".to_string(), 1_700_000_000)
        );
    }

    #[test]
    fn active_session_summary_rejects_invalid_account_and_secret_keys() {
        let mgr = AccountAbstractionManager::new();

        // Empty and whitespace-only account_id
        assert!(matches!(
            mgr.active_session_summaries("", 100),
            Err(SessionError::InvalidAccountId(_))
        ));
        assert!(matches!(
            mgr.active_session_summaries("   ", 100),
            Err(SessionError::InvalidAccountId(_))
        ));

        // Secret key (S... of length 56) must be rejected without echoing the secret
        let fake_secret = format!("S{}", "A".repeat(55));
        let err = mgr.active_session_summaries(&fake_secret, 100).unwrap_err();
        assert!(matches!(err, SessionError::InvalidAccountId(_)));
        assert!(!err.to_string().contains(&fake_secret));
    }

    #[test]
    fn get_active_session_summary_enforces_ownership_and_revocation() {
        let mut mgr = AccountAbstractionManager::new();
        mgr.register_session(session_for("s1", "GACCT1", "GPUB1", 5_000));

        // Wrong account -> SessionNotOwned (same message as SessionNotFound)
        let err = mgr
            .get_active_session_summary("GACCT2", "s1", 1_000)
            .unwrap_err();
        assert!(matches!(err, SessionError::SessionNotOwned(_)));
        assert_eq!(err.to_string(), "Session key s1 not found");

        // Revoked -> SessionRevoked
        mgr.revoke_session_authorized("GACCT1", "s1").unwrap();
        let err = mgr
            .get_active_session_summary("GACCT1", "s1", 1_000)
            .unwrap_err();
        assert!(matches!(err, SessionError::SessionRevoked(_)));
    }

    #[test]
    fn format_unix_timestamp_utc_known_dates_and_overflow() {
        assert_eq!(format_unix_timestamp_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(
            format_unix_timestamp_utc(1_700_000_000),
            "2023-11-14T22:13:20Z"
        );
        // Leap day 2024-02-29T12:34:56Z
        assert_eq!(
            format_unix_timestamp_utc(1_709_210_096),
            "2024-02-29T12:34:56Z"
        );
        // u64::MAX does not panic
        assert_eq!(format_unix_timestamp_utc(u64::MAX), "overflow");
    }

    #[test]
    fn format_active_sessions_renders_scopes_expiry_and_empty_state() {
        let mut mgr = AccountAbstractionManager::new();
        assert_eq!(
            mgr.format_active_sessions("GACCT1", 1_000).unwrap(),
            "No active session keys for account `GACCT1`."
        );

        mgr.register_session(SessionKey::new(
            "sess_1",
            "GACCT1",
            "GPUB1",
            SessionPolicy {
                expires_at: 1_700_000_000,
                allowed_contracts: HashSet::from(["C_TOKEN".to_string()]),
                allowed_methods: HashMap::from([(
                    "C_TOKEN".to_string(),
                    HashSet::from(["transfer".to_string()]),
                )]),
                max_spend_limit: Some(500),
            },
        ));
        mgr.validate_and_record_call("sess_1", "C_TOKEN", "transfer", 125, 1_699_999_000)
            .unwrap();

        let rendered = mgr.format_active_sessions("GACCT1", 1_699_999_000).unwrap();
        assert!(rendered.contains("Session: sess_1"));
        assert!(rendered.contains("Public Key : GPUB1"));
        assert!(rendered.contains("2023-11-14T22:13:20Z (unix: 1700000000, in 1000s)"));
        assert!(rendered.contains("Contracts  : C_TOKEN"));
        assert!(rendered.contains("Methods    : C_TOKEN: [transfer]"));
        assert!(rendered.contains("Spend Limit: 375/500 stroops remaining (spent: 125)"));
    }
}

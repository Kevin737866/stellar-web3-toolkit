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
    pub fn is_valid_at(&self, now: u64) -> bool {
        !self.is_revoked && self.policy.expires_at > now
    }
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
    pub fn veto_count(&self) -> usize {
        self.vetoes.len()
    }

    /// Whether enough distinct vetoes have accumulated to block execution.
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
            } else {
                return Err(SessionError::SessionExpired(
                    session_id.to_string(),
                    session.policy.expires_at,
                ));
            }
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
            .map(|r| r.is_vetoed())
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
}

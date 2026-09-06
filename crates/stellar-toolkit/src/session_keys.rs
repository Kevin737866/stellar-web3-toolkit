//! Account Abstraction & Session Key Management
//!
//! Provides lightweight, secure session keys and account abstraction UX primitives
//! for interacting with Soroban contracts. Features include:
//! - Session key generation with customizable expiration, spending limits, and method whitelist
//! - Non-blocking policy validation for transactions
//! - Transaction signing delegation using active session keys
//! - Session key revocation and auditing
//! - Multi-guardian recovery UX for account recovery

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
}

/// Account Abstraction Manager handling session keys and guardian recovery UX.
#[derive(Debug, Default)]
pub struct AccountAbstractionManager {
    sessions: HashMap<String, SessionKey>,
    guardians: HashMap<String, Vec<Guardian>>, // account_id -> list of guardians
    recovery_requests: HashMap<String, RecoveryRequest>,
}

impl AccountAbstractionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            guardians: HashMap::new(),
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

    /// Initiate an account recovery request.
    pub fn initiate_recovery(
        &mut self,
        recovery_id: impl Into<String>,
        account_id: impl Into<String>,
        proposed_new_owner_key: impl Into<String>,
        threshold: usize,
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
        };
        self.recovery_requests.insert(rec_id.clone(), request);
        rec_id
    }

    /// Submit a guardian confirmation for an in-flight recovery request.
    pub fn confirm_recovery(
        &mut self,
        recovery_id: &str,
        guardian_id: &str,
    ) -> Result<bool> {
        let request = self
            .recovery_requests
            .get_mut(recovery_id)
            .ok_or_else(|| SessionError::SessionNotFound(recovery_id.to_string()))?;

        // Verify guardian is registered for account
        let guardians = self
            .guardians
            .get(&request.account_id)
            .ok_or_else(|| SessionError::InvalidGuardianSignature(guardian_id.to_string()))?;

        let is_valid = guardians
            .iter()
            .any(|g| g.guardian_id == guardian_id && g.is_active);

        if !is_valid {
            return Err(SessionError::InvalidGuardianSignature(guardian_id.to_string()));
        }

        request.confirmed_guardians.insert(guardian_id.to_string());

        if request.confirmed_guardians.len() >= request.threshold {
            request.is_executed = true;
            Ok(true) // Recovery threshold met and executed
        } else {
            Ok(false)
        }
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
        assert!(matches!(res, Err(SessionError::SpendLimitExceeded(_, 400, 300))));

        // Unallowed method
        let res = manager.validate_and_record_call("sess_1", "contract_amm", "admin_drain", 10, 500);
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
}

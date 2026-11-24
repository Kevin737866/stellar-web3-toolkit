//! Integration tests for scoped expiry metadata on session keys (issue #333).

use stellar_toolkit::{
    AccountAbstractionManager, ScopedExpiry, SessionError, SessionKey, SessionPolicy,
};

#[test]
fn scoped_expiry_workflow_serialization_and_enforcement() {
    let mut mgr = AccountAbstractionManager::new();
    let policy = SessionPolicy {
        expires_at: 10_000,
        max_spend_limit: Some(500),
        ..SessionPolicy::default()
    }
    .with_scoped_expiry(ScopedExpiry::for_method(
        "C_AMM_POOL",
        "swap",
        5_000,
        Some("short-lived swap permission".to_string()),
    ))
    .expect("valid scoped expiry");

    let session = SessionKey::new("sess-scoped-1", "GACCT1", "GPUB1", policy);

    // Round-trip through JSON to verify serde compatibility.
    let json = serde_json::to_string(&session).expect("serialize session");
    let restored: SessionKey = serde_json::from_str(&json).expect("deserialize session");
    assert_eq!(restored.policy.scoped_expiries.len(), 1);

    mgr.register_session_checked(restored)
        .expect("register validated session");

    // Before scoped expiry: succeeds and records spend.
    mgr.validate_and_record_call("sess-scoped-1", "C_AMM_POOL", "swap", 200, 4_999)
        .expect("call before scoped expiry must succeed");
    assert_eq!(mgr.get_session("sess-scoped-1").unwrap().total_spent, 200);

    // At scoped expiry boundary: fails without incrementing total_spent.
    let err = mgr
        .validate_and_record_call("sess-scoped-1", "C_AMM_POOL", "swap", 100, 5_000)
        .expect_err("call at scoped expiry must fail");
    assert!(matches!(
        err,
        SessionError::ScopeExpired {
            expires_at: 5_000,
            ..
        }
    ));
    assert_eq!(mgr.get_session("sess-scoped-1").unwrap().total_spent, 200);

    // Unscoped method on same contract still works until global expires_at.
    mgr.validate_and_record_call("sess-scoped-1", "C_AMM_POOL", "get_reserves", 0, 5_000)
        .expect("unscoped method remains valid until global expiry");
}

#[test]
fn legacy_session_policy_json_without_scoped_expiries_deserializes_cleanly() {
    let legacy_json = r#"{
        "expires_at": 9000,
        "allowed_contracts": [],
        "allowed_methods": {},
        "max_spend_limit": null
    }"#;
    let policy: SessionPolicy =
        serde_json::from_str(legacy_json).expect("legacy JSON must deserialize");
    assert!(policy.scoped_expiries.is_empty());
    assert_eq!(policy.effective_expiry_for("C_ANY", Some("fn")), 9000);
}

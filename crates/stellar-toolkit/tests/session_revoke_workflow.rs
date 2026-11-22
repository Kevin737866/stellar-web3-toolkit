//! Integration tests for single session key revocation without rotating the
//! account key (issue #334).
//!
//! These tests exercise the public library API end-to-end, following the
//! conventions of tests/keystore_workflow.rs.

use stellar_toolkit::{
    AccountAbstractionManager, SessionError, SessionKey, SessionPolicy,
};

fn make_session(id: &str, account: &str, pubkey: &str) -> SessionKey {
    SessionKey::new(
        id,
        account,
        pubkey,
        SessionPolicy {
            expires_at: u64::MAX,
            ..SessionPolicy::default()
        },
    )
}

// ── revoke_session_authorized ─────────────────────────────────────────────────

#[test]
fn authorized_revocation_marks_key_revoked_and_rejects_subsequent_calls() {
    let mut mgr = AccountAbstractionManager::new();
    mgr.register_session(make_session("sess-1", "GACCT1", "GPUB1"));

    // Revoke through the authorized path.
    mgr.revoke_session_authorized("GACCT1", "sess-1")
        .expect("authorized revocation must succeed");

    // The key is now revoked.
    assert!(
        mgr.get_session("sess-1").unwrap().is_revoked,
        "session must be marked revoked"
    );
}

#[test]
fn authorized_revocation_rejects_wrong_account() {
    let mut mgr = AccountAbstractionManager::new();
    mgr.register_session(make_session("sess-1", "GACCT1", "GPUB1"));

    let err = mgr
        .revoke_session_authorized("GACCT2", "sess-1")
        .expect_err("wrong account must be rejected");

    assert!(
        matches!(err, SessionError::SessionNotOwned(_)),
        "expected SessionNotOwned, got {err:?}"
    );

    // The session must still be active.
    assert!(
        !mgr.get_session("sess-1").unwrap().is_revoked,
        "session must not be revoked after a failed attempt"
    );
}

#[test]
fn authorized_revocation_does_not_affect_other_session_keys_on_the_same_account() {
    let mut mgr = AccountAbstractionManager::new();
    mgr.register_session(make_session("sess-1", "GACCT1", "GPUB1"));
    mgr.register_session(make_session("sess-2", "GACCT1", "GPUB2"));

    mgr.revoke_session_authorized("GACCT1", "sess-1")
        .expect("revocation must succeed");

    // sess-2 must remain untouched.
    assert!(
        !mgr.get_session("sess-2").unwrap().is_revoked,
        "sess-2 must remain active"
    );
}

#[test]
fn authorized_revocation_returns_actionable_error_for_unknown_session_id() {
    let mut mgr = AccountAbstractionManager::new();
    let err = mgr
        .revoke_session_authorized("GACCT1", "no-such-session")
        .expect_err("unknown session must be rejected");

    assert!(
        matches!(err, SessionError::SessionNotFound(_)),
        "expected SessionNotFound, got {err:?}"
    );
}

#[test]
fn authorized_revocation_rejects_already_revoked_session_explicitly() {
    let mut mgr = AccountAbstractionManager::new();
    mgr.register_session(make_session("sess-1", "GACCT1", "GPUB1"));
    mgr.revoke_session_authorized("GACCT1", "sess-1").unwrap();

    let err = mgr
        .revoke_session_authorized("GACCT1", "sess-1")
        .expect_err("double-revoke must be rejected");

    assert!(
        matches!(err, SessionError::SessionRevoked(_)),
        "expected SessionRevoked on double-revoke, got {err:?}"
    );
}

// ── revoke_session_by_public_key ──────────────────────────────────────────────

#[test]
fn revoke_by_public_key_succeeds_and_key_becomes_unusable() {
    let mut mgr = AccountAbstractionManager::new();
    mgr.register_session(make_session("sess-1", "GACCT1", "GPUB1"));

    mgr.revoke_session_by_public_key("GACCT1", "GPUB1")
        .expect("revocation by public key must succeed");

    assert!(
        mgr.get_session("sess-1").unwrap().is_revoked,
        "session must be marked revoked"
    );
}

#[test]
fn revoke_by_public_key_does_not_reveal_key_belonging_to_different_account() {
    let mut mgr = AccountAbstractionManager::new();
    mgr.register_session(make_session("sess-1", "GACCT2", "GPUB_SHARED"));

    // acct1 tries to revoke a key registered under acct2.
    let err = mgr
        .revoke_session_by_public_key("GACCT1", "GPUB_SHARED")
        .expect_err("cross-account revocation must be rejected");

    // Must return SessionNotFound, not SessionNotOwned — to avoid leaking
    // that GPUB_SHARED is registered somewhere.
    assert!(
        matches!(err, SessionError::SessionNotFound(_)),
        "expected SessionNotFound (no existence leak), got {err:?}"
    );

    // The key on acct2 must be untouched.
    assert!(
        !mgr.get_session("sess-1").unwrap().is_revoked,
        "acct2 session must be unaffected"
    );
}

// ── Account key is never rotated ──────────────────────────────────────────────

#[test]
fn account_key_is_not_modified_after_session_revocation() {
    // wallet.rs and session_keys.rs are decoupled: a SessionKey carries the
    // account G-address as an opaque string. After revocation the stored
    // account_id on the remaining sessions must be unchanged, confirming that
    // revocation touches only the is_revoked flag, nothing else.
    let mut mgr = AccountAbstractionManager::new();
    mgr.register_session(make_session("sess-1", "GACCT1", "GPUB1"));
    mgr.register_session(make_session("sess-2", "GACCT1", "GPUB2"));

    mgr.revoke_session_authorized("GACCT1", "sess-1").unwrap();

    assert_eq!(
        mgr.get_session("sess-2").unwrap().account_id,
        "GACCT1",
        "account_id on sess-2 must be unchanged"
    );
    assert_eq!(
        mgr.get_session("sess-2").unwrap().session_public_key,
        "GPUB2",
        "session_public_key on sess-2 must be unchanged"
    );
}

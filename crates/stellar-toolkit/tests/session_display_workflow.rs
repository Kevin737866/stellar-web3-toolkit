//! Integration tests for displaying active session-key scopes and expiry
//! timestamps end-to-end through the public library API and CLI.

use std::collections::{HashMap, HashSet};
use stellar_toolkit::{
    format_active_session_summaries, format_unix_timestamp_utc, AccountAbstractionManager,
    SessionError, SessionKey, SessionPolicy,
};

#[test]
fn end_to_end_active_session_display_tracks_spend_expiry_and_revocation() {
    let mut mgr = AccountAbstractionManager::new();

    let policy_amm = SessionPolicy {
        expires_at: 1_700_003_600,
        allowed_contracts: HashSet::from(["C_AMM".to_string()]),
        allowed_methods: HashMap::from([(
            "C_AMM".to_string(),
            HashSet::from(["swap".to_string(), "quote".to_string()]),
        )]),
        max_spend_limit: Some(1_000),
    };
    let policy_open = SessionPolicy {
        expires_at: 1_700_001_800,
        allowed_contracts: HashSet::new(),
        allowed_methods: HashMap::new(),
        max_spend_limit: None,
    };

    mgr.register_session(SessionKey::new(
        "sess-amm", "GACCT1", "GPUB_AMM", policy_amm,
    ));
    mgr.register_session(SessionKey::new(
        "sess-open",
        "GACCT1",
        "GPUB_OPEN",
        policy_open,
    ));
    mgr.register_session(SessionKey::new(
        "sess-other",
        "GACCT2",
        "GPUB_OTHER",
        SessionPolicy {
            expires_at: 1_700_009_999,
            ..SessionPolicy::default()
        },
    ));

    // Record a spend on sess-amm before inspecting active sessions.
    let now = 1_700_000_000;
    mgr.validate_and_record_call("sess-amm", "C_AMM", "swap", 250, now)
        .expect("call within policy must succeed");

    let summaries = mgr
        .active_session_summaries("GACCT1", now)
        .expect("listing active sessions must succeed");
    assert_eq!(summaries.len(), 2);
    assert_eq!(summaries[0].session_id, "sess-open");
    assert_eq!(summaries[1].session_id, "sess-amm");
    assert_eq!(summaries[1].remaining_spend, Some(750));

    let rendered = format_active_session_summaries("GACCT1", &summaries);
    assert!(rendered.contains("Active session keys for account `GACCT1` (2):"));
    assert!(rendered.contains("Contracts  : any"));
    assert!(rendered.contains("Contracts  : C_AMM"));
    assert!(rendered.contains("Methods    : C_AMM: [quote, swap]"));
    assert!(rendered.contains("Spend Limit: 750/1000 stroops remaining (spent: 250)"));
    assert!(rendered.contains(&format_unix_timestamp_utc(1_700_001_800)));
    assert!(!rendered.contains("sess-other"));

    // Advance time past sess-open's expiry: only sess-amm remains active.
    let after_first_expiry = 1_700_001_800;
    let remaining = mgr
        .active_session_summaries("GACCT1", after_first_expiry)
        .expect("listing active sessions must succeed");
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].session_id, "sess-amm");

    // Revoke sess-amm: no active sessions remain.
    mgr.revoke_session_authorized("GACCT1", "sess-amm")
        .expect("revocation must succeed");
    let empty = mgr
        .active_session_summaries("GACCT1", after_first_expiry)
        .expect("listing active sessions must succeed");
    assert!(empty.is_empty());

    // Direct lookup of revoked session returns SessionRevoked.
    let err = mgr
        .get_active_session_summary("GACCT1", "sess-amm", after_first_expiry)
        .expect_err("revoked session must be rejected");
    assert!(matches!(err, SessionError::SessionRevoked(_)));
}

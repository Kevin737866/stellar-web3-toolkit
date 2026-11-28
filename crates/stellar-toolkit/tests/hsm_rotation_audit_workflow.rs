//! Integration tests for HSM key rotation audit records (issue #336).
//!
//! These tests exercise the full rotation workflow end-to-end through the
//! public library API, following the conventions of the other `tests/`
//! integration tests in this crate.

use stellar_toolkit::{ColdSigner, HsmError, RotationAudit, RotationRecord, SignRequest, StubHsm};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn seed(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn req(sequence: u64) -> SignRequest {
    SignRequest::new(
        "pubnet",
        "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        [0xdeu8; 32],
        sequence,
    )
}

fn unlocked_signer(byte: u8) -> StubHsm {
    let mut s = StubHsm::from_seed("prod-deploy-key", &seed(byte));
    s.unlock();
    s
}

// ── Normal path ───────────────────────────────────────────────────────────────

#[test]
fn rotation_appends_one_record_with_correct_public_keys() {
    let mut signer = unlocked_signer(1);
    let old_pub = hex::encode(signer.public_key());

    signer
        .rotate_key_at(&seed(2), Some("scheduled 90-day rotation"), 1_700_000_000)
        .expect("rotation must succeed");

    let audit = signer.rotation_audit();
    assert_eq!(audit.len(), 1, "exactly one record after one rotation");

    let record = audit.last().expect("record is present");
    assert_eq!(record.handle, "prod-deploy-key");
    assert_eq!(record.previous_public_key_hex, old_pub);
    assert_eq!(
        record.new_public_key_hex,
        hex::encode(signer.public_key()),
        "new public key in record matches the signer's current key"
    );
    assert_ne!(
        record.previous_public_key_hex, record.new_public_key_hex,
        "old and new public keys must differ"
    );
    assert_eq!(record.rotated_at, 1_700_000_000);
    assert_eq!(record.reason.as_deref(), Some("scheduled 90-day rotation"));
}

#[test]
fn rotation_records_last_sequence_before_rotation() {
    let mut signer = unlocked_signer(1);

    // Sign a request so the sequence counter is non-zero.
    let first = req(7);
    signer.approve(&first);
    signer.sign(&first).expect("sign");

    signer
        .rotate_key_at(&seed(2), None::<&str>, 1_700_000_001)
        .expect("rotation");

    let record = signer.rotation_audit().last().unwrap();
    assert_eq!(
        record.last_sequence_before_rotation,
        Some(7),
        "last sequence before rotation must be captured"
    );
}

#[test]
fn rotation_records_none_for_sequence_when_slot_never_signed() {
    let mut signer = unlocked_signer(1);

    signer
        .rotate_key_at(&seed(2), None::<&str>, 1_700_000_002)
        .expect("rotation");

    let record = signer.rotation_audit().last().unwrap();
    assert_eq!(
        record.last_sequence_before_rotation, None,
        "sequence must be None when no signature was produced before rotation"
    );
}

#[test]
fn multiple_rotations_chain_correctly_and_accumulate() {
    let mut signer = unlocked_signer(1);

    signer
        .rotate_key_at(&seed(2), Some("first"), 1_000)
        .unwrap();
    // Sign one request between rotations.
    let r = req(1);
    signer.approve(&r);
    signer.sign(&r).unwrap();

    signer
        .rotate_key_at(&seed(3), Some("second"), 2_000)
        .unwrap();
    signer
        .rotate_key_at(&seed(4), Some("third"), 3_000)
        .unwrap();

    let audit = signer.rotation_audit();
    assert_eq!(audit.len(), 3);

    // Records are in insertion order.
    assert_eq!(audit.records()[0].rotated_at, 1_000);
    assert_eq!(audit.records()[1].rotated_at, 2_000);
    assert_eq!(audit.records()[2].rotated_at, 3_000);

    // Forward linkage: each record's new key is the next record's previous key.
    assert_eq!(
        audit.records()[0].new_public_key_hex,
        audit.records()[1].previous_public_key_hex,
        "chain[0→1] broken"
    );
    assert_eq!(
        audit.records()[1].new_public_key_hex,
        audit.records()[2].previous_public_key_hex,
        "chain[1→2] broken"
    );

    // The second rotation recorded the sequence signed between rotations.
    assert_eq!(audit.records()[1].last_sequence_before_rotation, Some(1));
}

// ── Post-rotation signing ─────────────────────────────────────────────────────

#[test]
fn signer_signs_with_new_key_and_old_signature_does_not_verify() {
    let mut signer = unlocked_signer(1);

    // Sign a request with the original key.
    let old_req = req(1);
    signer.approve(&old_req);
    let old_sig = signer.sign(&old_req).expect("sign with old key");

    // Rotate to a new key.
    signer
        .rotate_key_at(&seed(2), None::<&str>, 1_700_000_003)
        .expect("rotation");
    signer.unlock();

    // Sign a new request with the rotated key.
    let new_req = req(2);
    signer.approve(&new_req);
    let new_sig = signer.sign(&new_req).expect("sign with new key");

    assert!(
        signer.verify(&new_req, &new_sig),
        "new signature must verify with the new key"
    );
    assert!(
        !signer.verify(&old_req, &old_sig),
        "old signature must NOT verify with the new key"
    );
}

#[test]
fn rotation_clears_pending_approvals_so_old_digest_cannot_sign() {
    let mut signer = unlocked_signer(1);

    // Approve a request but do not sign it.
    let pending = req(3);
    signer.approve(&pending);
    assert!(signer.is_approved(&pending));

    // Rotate the key.
    signer
        .rotate_key_at(&seed(2), None::<&str>, 1_700_000_004)
        .expect("rotation");
    signer.unlock();

    // The pending approval was cleared: signing must now be refused.
    assert!(
        !signer.is_approved(&pending),
        "pending approval must be cleared by rotation"
    );
    assert!(
        matches!(
            signer.sign(&pending),
            Err(HsmError::ArtifactNotReviewed { .. })
        ),
        "signing with a stale approval must be refused after rotation"
    );
}

// ── Failure paths ─────────────────────────────────────────────────────────────

#[test]
fn rotation_is_refused_when_signer_is_locked() {
    let mut signer = StubHsm::from_seed("prod-deploy-key", &seed(1));
    // Deliberately do not call unlock().

    let err = signer
        .rotate_key_at(&seed(2), Some("attempted rotation"), 1_700_000_005)
        .expect_err("locked signer must refuse rotation");

    assert!(
        matches!(err, HsmError::Locked { .. }),
        "expected HsmError::Locked, got {err:?}"
    );
    assert!(
        signer.rotation_audit().is_empty(),
        "no audit record must be written for a refused rotation"
    );
}

#[test]
fn rotation_to_the_same_key_is_refused_and_produces_no_record() {
    let mut signer = unlocked_signer(5);

    let err = signer
        .rotate_key_at(&seed(5), Some("no-op attempt"), 1_700_000_006)
        .expect_err("same-key rotation must be refused");

    assert!(
        matches!(err, HsmError::RotationIdentical),
        "expected HsmError::RotationIdentical, got {err:?}"
    );
    assert!(
        signer.rotation_audit().is_empty(),
        "no audit record must be written for an identical-key rotation"
    );
}

// ── Audit log immutability ─────────────────────────────────────────────────────

#[test]
fn audit_records_are_immutable_after_append() {
    let mut audit = RotationAudit::new();
    let record = RotationRecord {
        handle: "slot-0".to_string(),
        previous_public_key_hex: "aa".repeat(32),
        new_public_key_hex: "bb".repeat(32),
        last_sequence_before_rotation: Some(42),
        rotated_at: 9_999,
        reason: Some("test".to_string()),
    };
    audit.append(record.clone());

    // The only view is a shared slice — no &mut access to individual records.
    let slice = audit.records();
    assert_eq!(slice.len(), 1);
    assert_eq!(slice[0], record);
}

#[test]
fn rotation_without_reason_records_none() {
    let mut signer = unlocked_signer(1);
    signer
        .rotate_key_at(&seed(2), None::<&str>, 1_700_000_007)
        .unwrap();
    assert_eq!(signer.rotation_audit().last().unwrap().reason, None);
}

//! Cold-storage signer boundary (issue #201).
//!
//! `docs/KEY_MANAGEMENT.md` describes the deployment flow the toolkit assumes:
//! the machine that holds the deploy key is offline, and it only ever signs an
//! artifact whose hashes were reviewed and carried over on removable media. That
//! flow is a *protocol between two machines*, and until now it existed only as
//! prose. This module gives it a type: the request the online side builds, the
//! review the offline side records, and the signer that produces at most one
//! signature per review.
//!
//! [`StubHsm`] is deliberately a stub. It keeps its key in process memory, which
//! is exactly what a hardware module exists to avoid, so it is **not** a
//! hardware-backed signer and must not be described as one. What it does have is
//! the part that is worth testing before the hardware lands:
//!
//! * an artifact is signed only if its [`SignRequest::digest`] was approved
//!   first, so a compromised online host cannot turn "sign this deployment" into
//!   "sign anything";
//! * an approval is spent by the signature it authorises, so replaying the same
//!   request does not produce a second signature;
//! * sequences are strictly increasing, so an older request cannot be replayed
//!   even with a new approval;
//! * the secret never leaves the signer — there is no accessor for it, and the
//!   [`Debug`] rendering contains only public material.
//!
//! The [`ColdSigner`] trait is the seam for a real HSM: production code depends
//! on the trait, the stub implements it, and swapping in a PKCS#11 / cloud-KMS
//! backend changes no caller.
//!
//! # Key rotation audit
//!
//! Rotating the signing key on an HSM slot is an irreversible change whose
//! operator trail must be preserved. [`RotationRecord`] captures everything an
//! auditor needs: the old public key, the new public key, the slot handle, the
//! last sequence signed before the rotation, the wall-clock timestamp, and an
//! optional free-text reason. [`RotationAudit`] is an append-only log of those
//! records. Past entries cannot be overwritten or deleted; a fresh log is the
//! only way to start over.
//!
//! [`StubHsm::rotate_key`] enforces the write path:
//!
//! * the signer must be unlocked (rotating a locked key is refused, just as
//!   signing is);
//! * the caller supplies the new 32-byte seed in a `[u8; 32]` — no raw
//!   `SigningKey`, so key material never crosses the API boundary;
//! * after a successful rotation the signer holds the new key, all prior
//!   approvals are cleared (they were issued for a digest signed by the old
//!   key, so they are meaningless now), and a [`RotationRecord`] is appended
//!   to the audit log;
//! * rotating to the same seed as the current key is refused — a no-op
//!   rotation would produce a misleading audit entry.

use ed25519_dalek::{Signature as Ed25519Signature, Signer as _, SigningKey, VerifyingKey};
use std::collections::BTreeSet;
use std::fmt;

// ── Rotation audit ────────────────────────────────────────────────────────────

/// A single key-rotation event on an HSM slot.
///
/// Every field is immutable after creation; the [`RotationAudit`] log that
/// owns these records is append-only, so a past rotation cannot be rewritten.
///
/// Both public keys are stored as hex strings so the record is self-contained
/// when serialised (no dependency on the `ed25519-dalek` types at the
/// deserialization site).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationRecord {
    /// Identifying label of the slot that was rotated.
    pub handle: String,
    /// Ed25519 public key that was active **before** the rotation, hex-encoded.
    pub previous_public_key_hex: String,
    /// Ed25519 public key that became active **after** the rotation, hex-encoded.
    pub new_public_key_hex: String,
    /// The last sequence this slot signed **before** the rotation, or `None`
    /// if the slot had never produced a signature.
    pub last_sequence_before_rotation: Option<u64>,
    /// Unix timestamp (seconds since epoch) when the rotation was recorded.
    ///
    /// For the stub this is taken from [`std::time::SystemTime`]. In a real
    /// HSM the hardware clock is authoritative; callers can override via
    /// [`StubHsm::rotate_key_at`].
    pub rotated_at: u64,
    /// Optional free-text reason supplied by the operator (e.g.
    /// "scheduled 90-day rotation" or "emergency: key exposure suspected").
    pub reason: Option<String>,
}

/// Append-only log of key-rotation events for an HSM slot.
///
/// Records accumulate in insertion order. The only mutation the log permits
/// is appending a new record; existing records cannot be removed or changed.
///
/// # Compatibility
///
/// The log is an in-memory structure. Persistence and replay are the
/// responsibility of the calling application; the log provides no I/O.
#[derive(Debug, Default, Clone)]
pub struct RotationAudit {
    records: Vec<RotationRecord>,
}

impl RotationAudit {
    /// Create a new, empty audit log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a rotation record to the log.
    ///
    /// This is the only way to add an entry; there is no way to remove or
    /// modify an existing one.
    pub fn append(&mut self, record: RotationRecord) {
        self.records.push(record);
    }

    /// All records in insertion order. The returned slice is immutable.
    #[must_use]
    pub fn records(&self) -> &[RotationRecord] {
        &self.records
    }

    /// Number of rotations recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the log contains no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The most recently appended record, or `None` if the log is empty.
    #[must_use]
    pub fn last(&self) -> Option<&RotationRecord> {
        self.records.last()
    }
}

// ── Error variants for rotation ───────────────────────────────────────────────

/// Domain separator mixed into every request digest.
///
/// Two deployments that happen to share a wasm hash on different networks still
/// produce different digests, and a digest can never be confused with a plain
/// sha256 of the artifact.
const DIGEST_DOMAIN: &[u8] = b"stellar-toolkit/cold-sign/v1";

/// What the offline signer is being asked to authorise.
///
/// Every field is part of the digest: the network and contract id name *where*
/// the deployment lands, `wasm_sha256` names *what* is being deployed, and
/// `sequence` gives the review a position in time so an old approval cannot be
/// replayed after the operator has moved on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    /// Network the artifact will be submitted to (`testnet`, `pubnet`, …).
    pub network: String,
    /// Contract id the deployment writes to.
    pub contract_id: String,
    /// sha256 of the wasm the deployment will upload.
    pub wasm_sha256: [u8; 32],
    /// Monotonically increasing position of this request in the deploy log.
    pub sequence: u64,
}

impl SignRequest {
    pub fn new(
        network: impl Into<String>,
        contract_id: impl Into<String>,
        wasm_sha256: [u8; 32],
        sequence: u64,
    ) -> Self {
        Self {
            network: network.into(),
            contract_id: contract_id.into(),
            wasm_sha256,
            sequence,
        }
    }

    /// The 32-byte digest of everything this request authorises.
    ///
    /// Variable-length fields are length-prefixed, so `network = "ab",
    /// contract_id = "c"` cannot collide with `network = "a", contract_id =
    /// "bc"`. The fields are fixed-width beyond that, so the encoding is
    /// unambiguous without relying on a separator byte that a field could
    /// contain.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        for field in [self.network.as_bytes(), self.contract_id.as_bytes()] {
            hasher.update((field.len() as u32).to_be_bytes());
            hasher.update(field);
        }
        hasher.update(self.wasm_sha256);
        hasher.update(self.sequence.to_be_bytes());

        let out = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&out);
        digest
    }

    /// Hex rendering of [`SignRequest::digest`], the value an operator compares
    /// against the one computed on the online machine.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        hex::encode(self.digest())
    }
}

/// Why a signer refused a request.
///
/// Each variant is a distinct operator action, so they are not collapsed into
/// one "signing failed": a locked signer needs an unlock, an unapproved digest
/// needs a review, and a replayed sequence means the deploy log is inconsistent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HsmError {
    #[error("cold signer {handle} is locked")]
    Locked { handle: String },
    #[error("artifact {digest} was never approved on this signer")]
    ArtifactNotReviewed { digest: String },
    #[error("the review of {digest} has already been spent on a signature")]
    ReviewAlreadySpent { digest: String },
    #[error("sequence {sequence} was already signed (last signed sequence {last_signed})")]
    ReplayedSequence { sequence: u64, last_signed: u64 },
    /// The caller attempted to rotate the key to a seed that produces the
    /// same public key as the current key. A no-op rotation would create a
    /// misleading audit entry and is refused.
    #[error("key rotation refused: the new seed produces the same public key as the current key")]
    RotationIdentical,
}

/// The seam a real hardware signer implements.
pub trait ColdSigner {
    /// Identifying label for the key slot, used in errors and the deploy log.
    fn handle(&self) -> &str;

    /// Public key of the slot, so the online side can check it is talking to the
    /// key it expects before it builds a request.
    fn public_key(&self) -> [u8; 32];

    /// Sign `request` if — and only if — it was reviewed on this signer and its
    /// sequence has not been used.
    fn sign(&mut self, request: &SignRequest) -> Result<[u8; 64], HsmError>;
}

/// A software stand-in for a hardware signing module.
///
/// See the module docs: this is a stub. The behaviour it *does* guarantee is the
/// review/replay protocol, which is the part that has to be right before a real
/// HSM is wired in.
pub struct StubHsm {
    handle: String,
    signing_key: SigningKey,
    /// Digests approved by the offline review step.
    reviewed: BTreeSet<[u8; 32]>,
    /// Digests whose approval has already produced a signature.
    spent: BTreeSet<[u8; 32]>,
    last_signed: Option<u64>,
    unlocked: bool,
    /// Append-only record of every key rotation on this slot.
    audit: RotationAudit,
}

impl StubHsm {
    /// Create a signer from a 32-byte Ed25519 seed.
    ///
    /// The signer starts **locked**, mirroring a module that needs an operator
    /// PIN: approving a digest is an offline review and does not require
    /// unlocking, but signing does.
    pub fn from_seed(handle: impl Into<String>, seed: &[u8; 32]) -> Self {
        Self {
            handle: handle.into(),
            signing_key: SigningKey::from_bytes(seed),
            reviewed: BTreeSet::new(),
            spent: BTreeSet::new(),
            last_signed: None,
            unlocked: false,
            audit: RotationAudit::new(),
        }
    }

    #[must_use]
    pub fn handle(&self) -> &str {
        &self.handle
    }

    #[must_use]
    pub fn is_locked(&self) -> bool {
        !self.unlocked
    }

    /// Unlock the key slot. In a real HSM this is the PIN entry.
    pub fn unlock(&mut self) {
        self.unlocked = true;
    }

    /// Lock the key slot again, keeping reviews and sequence bookkeeping.
    pub fn lock(&mut self) {
        self.unlocked = false;
    }

    /// Record the offline review of `request`, returning its digest.
    ///
    /// Approving twice is idempotent: the second call does not create a second
    /// signature's worth of authority.
    pub fn approve(&mut self, request: &SignRequest) -> [u8; 32] {
        let digest = request.digest();
        self.approve_digest(digest);
        digest
    }

    /// Record a review that happened on another machine, by digest.
    ///
    /// This is the path an operator uses after carrying `digest_hex` across on
    /// removable media: the online host cannot approve anything for itself, it
    /// can only be handed a digest a human already checked.
    pub fn approve_digest(&mut self, digest: [u8; 32]) -> [u8; 32] {
        if !self.spent.contains(&digest) {
            self.reviewed.insert(digest);
        }
        digest
    }

    /// Whether `request` has been reviewed and not yet spent.
    #[must_use]
    pub fn is_approved(&self, request: &SignRequest) -> bool {
        let digest = request.digest();
        self.reviewed.contains(&digest) && !self.spent.contains(&digest)
    }

    /// The last sequence this signer produced a signature for.
    #[must_use]
    pub fn last_signed_sequence(&self) -> Option<u64> {
        self.last_signed
    }

    /// Verify a signature against the request it claims to authorise.
    ///
    /// This is what the online machine does before submitting: it recomputes the
    /// digest it reviewed and checks the signature is over that digest, not over
    /// something else the signer was tricked into signing.
    #[must_use]
    pub fn verify(&self, request: &SignRequest, signature: &[u8; 64]) -> bool {
        let signature = Ed25519Signature::from_bytes(signature);
        self.verifying_key()
            .verify_strict(&request.digest(), &signature)
            .is_ok()
    }

    // ── Key rotation ──────────────────────────────────────────────────────────

    /// Replace the signing key with the key derived from `new_seed` and append
    /// a [`RotationRecord`] to the slot's audit log.
    ///
    /// Uses the wall clock ([`std::time::SystemTime`]) for the `rotated_at`
    /// timestamp. If you need a deterministic timestamp in tests, use
    /// [`rotate_key_at`] instead.
    ///
    /// # Errors
    ///
    /// * [`HsmError::Locked`] — the signer must be unlocked before rotating.
    ///   This mirrors the sign path: a PIN is required for any key-material
    ///   change.
    /// * [`HsmError::RotationIdentical`] — `new_seed` produces the same public
    ///   key as the current key. A no-op rotation is refused because it would
    ///   emit a misleading audit record.
    ///
    /// [`rotate_key_at`]: Self::rotate_key_at
    pub fn rotate_key(
        &mut self,
        new_seed: &[u8; 32],
        reason: Option<impl Into<String>>,
    ) -> Result<&RotationRecord, HsmError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.rotate_key_at(new_seed, reason, now)
    }

    /// Replace the signing key with the key derived from `new_seed`, recording
    /// `rotated_at` as the event timestamp.
    ///
    /// This variant is intended for tests and deterministic replay scenarios
    /// where wall-clock non-determinism is undesirable. All invariants from
    /// [`rotate_key`] apply.
    ///
    /// [`rotate_key`]: Self::rotate_key
    pub fn rotate_key_at(
        &mut self,
        new_seed: &[u8; 32],
        reason: Option<impl Into<String>>,
        rotated_at: u64,
    ) -> Result<&RotationRecord, HsmError> {
        if !self.unlocked {
            return Err(HsmError::Locked {
                handle: self.handle.clone(),
            });
        }

        let new_key = SigningKey::from_bytes(new_seed);
        let new_pub = new_key.verifying_key().to_bytes();
        let old_pub = self.verifying_key().to_bytes();

        if new_pub == old_pub {
            return Err(HsmError::RotationIdentical);
        }

        let record = RotationRecord {
            handle: self.handle.clone(),
            previous_public_key_hex: hex::encode(old_pub),
            new_public_key_hex: hex::encode(new_pub),
            last_sequence_before_rotation: self.last_signed,
            rotated_at,
            reason: reason.map(Into::into),
        };

        // Install the new key and clear per-key state: approvals from the old
        // key are meaningless for the new one, so they must not carry over.
        // The sequence counter and the audit log are retained because they
        // belong to the slot, not to the key.
        self.signing_key = new_key;
        self.reviewed.clear();
        self.spent.clear();

        self.audit.append(record);

        // Safety: we just pushed a record, so `last()` is always `Some`.
        Ok(self.audit.last().expect("record just appended"))
    }

    /// Read-only reference to the rotation audit log for this slot.
    ///
    /// The log is append-only: the caller can read all records but cannot
    /// modify or remove any entry.
    #[must_use]
    pub fn rotation_audit(&self) -> &RotationAudit {
        &self.audit
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl ColdSigner for StubHsm {
    fn handle(&self) -> &str {
        &self.handle
    }

    fn public_key(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }

    fn sign(&mut self, request: &SignRequest) -> Result<[u8; 64], HsmError> {
        if !self.unlocked {
            return Err(HsmError::Locked {
                handle: self.handle.clone(),
            });
        }

        let digest = request.digest();

        if self.spent.contains(&digest) {
            return Err(HsmError::ReviewAlreadySpent {
                digest: hex::encode(digest),
            });
        }
        if !self.reviewed.contains(&digest) {
            return Err(HsmError::ArtifactNotReviewed {
                digest: hex::encode(digest),
            });
        }
        // Strictly increasing, not merely "different": an older request signed
        // again out of order is exactly the replay this guards against.
        if let Some(last_signed) = self.last_signed {
            if request.sequence <= last_signed {
                return Err(HsmError::ReplayedSequence {
                    sequence: request.sequence,
                    last_signed,
                });
            }
        }

        let signature = self.signing_key.sign(&digest);
        self.spent.insert(digest);
        self.last_signed = Some(request.sequence);

        Ok(signature.to_bytes())
    }
}

impl fmt::Debug for StubHsm {
    /// Renders public material only; the secret seed is never formatted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StubHsm")
            .field("handle", &self.handle)
            .field("public_key", &hex::encode(self.verifying_key().to_bytes()))
            .field("unlocked", &self.unlocked)
            .field("approved", &self.reviewed.len())
            .field("last_signed", &self.last_signed)
            .field("rotation_count", &self.audit.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn req(sequence: u64) -> SignRequest {
        SignRequest::new(
            "testnet",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            [7u8; 32],
            sequence,
        )
    }

    fn unlocked(byte: u8) -> StubHsm {
        let mut signer = StubHsm::from_seed("deploy-key", &seed(byte));
        signer.unlock();
        signer
    }

    #[test]
    fn approved_request_signs_and_verifies() {
        let mut signer = unlocked(1);
        let request = req(1);
        signer.approve(&request);

        let signature = signer.sign(&request).expect("approved request signs");
        assert!(signer.verify(&request, &signature));
    }

    #[test]
    fn signature_is_over_the_reviewed_digest() {
        let mut signer = unlocked(2);
        let request = req(3);
        signer.approve(&request);
        let signature = signer.sign(&request).unwrap();

        // Verify with dalek directly, so this does not just agree with our own
        // `verify` wrapper.
        let verifying_key = VerifyingKey::from_bytes(&signer.public_key()).unwrap();
        verifying_key
            .verify_strict(&request.digest(), &Ed25519Signature::from_bytes(&signature))
            .expect("signature is a valid Ed25519 signature over the digest");

        // And a different request must not verify with the same signature.
        let other = req(4);
        assert!(!signer.verify(&other, &signature));
    }

    #[test]
    fn unapproved_request_is_refused_and_nothing_is_signed() {
        let mut signer = unlocked(3);
        let request = req(1);

        assert_eq!(
            signer.sign(&request),
            Err(HsmError::ArtifactNotReviewed {
                digest: request.digest_hex()
            })
        );
        assert_eq!(signer.last_signed_sequence(), None);
    }

    #[test]
    fn an_approval_authorises_exactly_one_signature() {
        let mut signer = unlocked(4);
        let request = req(1);
        signer.approve(&request);
        assert!(signer.is_approved(&request));

        signer.sign(&request).unwrap();
        assert!(!signer.is_approved(&request));
        assert_eq!(
            signer.sign(&request),
            Err(HsmError::ReviewAlreadySpent {
                digest: request.digest_hex()
            })
        );

        // Re-approving a spent digest does not resurrect it.
        signer.approve(&request);
        assert!(matches!(
            signer.sign(&request),
            Err(HsmError::ReviewAlreadySpent { .. })
        ));
    }

    #[test]
    fn out_of_order_sequence_is_refused() {
        let mut signer = unlocked(5);

        let newer = req(10);
        signer.approve(&newer);
        signer.sign(&newer).unwrap();

        // An older request, freshly approved, would undo work the operator has
        // already done: it must not sign.
        let older = req(9);
        signer.approve(&older);
        assert_eq!(
            signer.sign(&older),
            Err(HsmError::ReplayedSequence {
                sequence: 9,
                last_signed: 10
            })
        );

        // A different artifact at an already-used sequence is refused by the
        // sequence rule, not merely by the spent review.
        let mut repeated = req(10);
        repeated.wasm_sha256 = [9u8; 32];
        assert_ne!(repeated.digest(), newer.digest());
        signer.approve(&repeated);
        assert_eq!(
            signer.sign(&repeated),
            Err(HsmError::ReplayedSequence {
                sequence: 10,
                last_signed: 10
            })
        );
    }

    #[test]
    fn locked_signer_refuses_even_an_approved_request() {
        let mut signer = StubHsm::from_seed("deploy-key", &seed(6));
        let request = req(1);
        signer.approve(&request);

        assert!(signer.is_locked());
        assert_eq!(
            signer.sign(&request),
            Err(HsmError::Locked {
                handle: "deploy-key".to_string()
            })
        );

        signer.unlock();
        assert!(signer.sign(&request).is_ok());
    }

    #[test]
    fn locking_keeps_reviews_and_sequence() {
        let mut signer = unlocked(7);
        let first = req(1);
        signer.approve(&first);
        signer.sign(&first).unwrap();

        let second = req(2);
        signer.approve(&second);
        signer.lock();
        signer.unlock();

        assert!(signer.is_approved(&second));
        signer.sign(&second).unwrap();
        assert_eq!(signer.last_signed_sequence(), Some(2));
    }

    #[test]
    fn digest_distinguishes_every_field() {
        let base = req(1);

        let mut other_network = base.clone();
        other_network.network = "pubnet".into();
        let mut other_contract = base.clone();
        other_contract.contract_id =
            "CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB2KM".into();
        let mut other_wasm = base.clone();
        other_wasm.wasm_sha256 = [8u8; 32];
        let mut other_sequence = base.clone();
        other_sequence.sequence = 2;

        let digest = base.digest();
        for other in [
            other_network.digest(),
            other_contract.digest(),
            other_wasm.digest(),
            other_sequence.digest(),
        ] {
            assert_ne!(digest, other);
        }

        // Field boundaries are length-prefixed, so shifting a character from one
        // field into the next is a different request, not the same preimage.
        let shifted = SignRequest::new("testne", "tCAAAA", [7u8; 32], 1);
        assert_ne!(digest, shifted.digest());
    }

    #[test]
    fn debug_output_never_contains_the_seed() {
        let signer = StubHsm::from_seed("deploy-key", &seed(0xAB));
        let rendered = format!("{signer:?}");
        assert!(rendered.contains("deploy-key"));
        assert!(!rendered.contains("abababab"));
        assert!(!rendered.contains("171171171"));
    }

    #[test]
    fn two_signers_hold_different_keys() {
        let mut first = unlocked(10);
        let second = unlocked(11);
        assert_ne!(first.public_key(), second.public_key());

        let request = req(1);
        first.approve(&request);
        let signature = first.sign(&request).unwrap();

        assert!(first.verify(&request, &signature));
        assert!(!second.verify(&request, &signature));
    }

    // ── Rotation audit tests ─────────────────────────────────────────────────

    #[test]
    fn rotation_records_old_and_new_public_keys() {
        let mut signer = unlocked(1);
        let old_pub = hex::encode(signer.public_key());
        let new_seed = seed(2);

        let record = signer
            .rotate_key_at(&new_seed, Some("test rotation"), 1_700_000_000)
            .expect("rotation must succeed");

        assert_eq!(record.handle, "deploy-key");
        assert_eq!(record.previous_public_key_hex, old_pub);
        assert_eq!(record.new_public_key_hex, hex::encode(signer.public_key()));
        assert_ne!(record.previous_public_key_hex, record.new_public_key_hex);
        assert_eq!(record.rotated_at, 1_700_000_000);
        assert_eq!(record.reason.as_deref(), Some("test rotation"));
        assert_eq!(record.last_sequence_before_rotation, None);
    }

    #[test]
    fn rotation_records_last_signed_sequence_before_rotation() {
        let mut signer = unlocked(1);
        let req = req(5);
        signer.approve(&req);
        signer.sign(&req).unwrap();

        signer
            .rotate_key_at(&seed(2), None::<&str>, 1_700_000_001)
            .expect("rotation must succeed");

        let record = signer.rotation_audit().last().unwrap();
        assert_eq!(record.last_sequence_before_rotation, Some(5));
    }

    #[test]
    fn rotation_clears_pending_approvals_but_keeps_sequence_counter() {
        let mut signer = unlocked(1);

        // Sign something to advance the sequence counter.
        let first = req(1);
        signer.approve(&first);
        signer.sign(&first).unwrap();

        // Approve a second request but don't sign it yet.
        let second = req(2);
        signer.approve(&second);
        assert!(signer.is_approved(&second));

        // Rotate the key.
        signer
            .rotate_key_at(&seed(2), Some("scheduled"), 1_700_000_002)
            .expect("rotation");

        // The pending approval was cleared by the rotation.
        assert!(!signer.is_approved(&second));

        // The sequence counter is unaffected: the new key still refuses a
        // request at or below the last signed sequence.
        let third = req(1); // sequence <= last_signed
        signer.approve(&third);
        signer.unlock();
        assert!(matches!(
            signer.sign(&third),
            Err(HsmError::ReplayedSequence { .. })
        ));
        assert_eq!(signer.last_signed_sequence(), Some(1));
    }

    #[test]
    fn rotation_is_refused_while_locked() {
        let mut signer = StubHsm::from_seed("deploy-key", &seed(1));
        assert!(signer.is_locked());

        let err = signer
            .rotate_key_at(&seed(2), None::<&str>, 1_700_000_003)
            .expect_err("locked signer must refuse rotation");

        assert!(
            matches!(err, HsmError::Locked { .. }),
            "expected Locked, got {err:?}"
        );
        assert!(signer.rotation_audit().is_empty());
    }

    #[test]
    fn rotation_to_the_same_key_is_refused() {
        let mut signer = unlocked(5);
        let same_seed = seed(5);

        let err = signer
            .rotate_key_at(&same_seed, Some("no-op attempt"), 1_700_000_004)
            .expect_err("same-key rotation must be refused");

        assert!(
            matches!(err, HsmError::RotationIdentical),
            "expected RotationIdentical, got {err:?}"
        );
        // No spurious record was written.
        assert!(signer.rotation_audit().is_empty());
    }

    #[test]
    fn multiple_rotations_accumulate_in_insertion_order() {
        let mut signer = unlocked(1);

        signer
            .rotate_key_at(&seed(2), Some("first rotation"), 1_000)
            .unwrap();
        signer
            .rotate_key_at(&seed(3), Some("second rotation"), 2_000)
            .unwrap();
        signer
            .rotate_key_at(&seed(4), Some("third rotation"), 3_000)
            .unwrap();

        let audit = signer.rotation_audit();
        assert_eq!(audit.len(), 3);
        assert_eq!(audit.records()[0].rotated_at, 1_000);
        assert_eq!(audit.records()[1].rotated_at, 2_000);
        assert_eq!(audit.records()[2].rotated_at, 3_000);

        // Verify forward linkage: each record's new key is the next record's
        // previous key.
        assert_eq!(
            audit.records()[0].new_public_key_hex,
            audit.records()[1].previous_public_key_hex
        );
        assert_eq!(
            audit.records()[1].new_public_key_hex,
            audit.records()[2].previous_public_key_hex
        );
    }

    #[test]
    fn signer_signs_with_new_key_after_rotation_and_old_signature_does_not_verify() {
        let mut signer = unlocked(1);

        let request = req(1);
        signer.approve(&request);
        let old_sig = signer.sign(&request).unwrap();

        // Rotate to a fresh key.
        signer
            .rotate_key_at(&seed(2), None::<&str>, 1_700_000_005)
            .expect("rotation");
        signer.unlock();

        // A new request signed by the new key.
        let new_request = req(2);
        signer.approve(&new_request);
        let new_sig = signer.sign(&new_request).unwrap();

        // The new signature verifies with the current key.
        assert!(signer.verify(&new_request, &new_sig));
        // The old signature does NOT verify with the new key.
        assert!(!signer.verify(&request, &old_sig));
    }

    #[test]
    fn rotation_without_reason_records_none() {
        let mut signer = unlocked(1);
        signer
            .rotate_key_at(&seed(2), None::<&str>, 1_700_000_006)
            .unwrap();
        let record = signer.rotation_audit().last().unwrap();
        assert_eq!(record.reason, None);
    }

    #[test]
    fn rotation_audit_is_included_in_debug_output() {
        let mut signer = unlocked(1);
        let rendered_before = format!("{signer:?}");
        assert!(rendered_before.contains("rotation_count: 0"));

        signer
            .rotate_key_at(&seed(2), None::<&str>, 1_700_000_007)
            .unwrap();
        let rendered_after = format!("{signer:?}");
        assert!(rendered_after.contains("rotation_count: 1"));
    }
}

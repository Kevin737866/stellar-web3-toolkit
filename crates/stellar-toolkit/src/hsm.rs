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

use ed25519_dalek::{Signature as Ed25519Signature, Signer as _, SigningKey, VerifyingKey};
use std::collections::BTreeSet;
use std::fmt;

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
        }
    }

    pub fn handle(&self) -> &str {
        &self.handle
    }

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
    pub fn is_approved(&self, request: &SignRequest) -> bool {
        let digest = request.digest();
        self.reviewed.contains(&digest) && !self.spent.contains(&digest)
    }

    /// The last sequence this signer produced a signature for.
    pub fn last_signed_sequence(&self) -> Option<u64> {
        self.last_signed
    }

    /// Verify a signature against the request it claims to authorise.
    ///
    /// This is what the online machine does before submitting: it recomputes the
    /// digest it reviewed and checks the signature is over that digest, not over
    /// something else the signer was tricked into signing.
    pub fn verify(&self, request: &SignRequest, signature: &[u8; 64]) -> bool {
        let signature = Ed25519Signature::from_bytes(signature);
        self.verifying_key()
            .verify_strict(&request.digest(), &signature)
            .is_ok()
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
}

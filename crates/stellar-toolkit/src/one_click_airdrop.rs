//! One-Click Claim Airdrop UX Module (#129)
//!
//! Provides single-click transaction building, eligibility verification,
//! claim status tracking, and error recovery for Soroban airdrop distributions.
//!
//! Eligibility is **Merkle-rooted**: a distributor publishes the root of a
//! [`MerkleTree`] over the allocation list plus the number of leaves, and each
//! recipient proves membership with a sibling path. A request is eligible only
//! when its `(address, amount)` leaf hashes up to the published root at the
//! published depth. The proof therefore authenticates the *amount* as well as
//! the address — see [`crate::merkle`] for the tree's design decisions.
//!
//! The previous behaviour — a hardcoded [`AMOUNT_PER_CLAIM`] returned for any
//! syntactically non-empty address, with the request's `proof` field carried
//! through the payload but checked by nothing — granted every address in
//! existence a fixed allocation. That was the whole security model of the
//! module, so it is replaced rather than extended.

use crate::error::{Result, ToolkitError};
use crate::merkle::{self, Hash, MerkleTree};
use serde::{Deserialize, Serialize};

/// Fallback allocation size, kept only as the default used when building a
/// distribution for a recipient. It is **not** used for eligibility: no value
/// here can make an address claimable without a valid proof.
pub const AMOUNT_PER_CLAIM: u64 = 5_000_000;

/// Claim status for an airdrop recipient
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClaimStatus {
    Eligible { amount: u64 },
    Ineligible { reason: String },
    Claiming { tx_hash: String },
    Claimed { tx_hash: String, timestamp: u64 },
    Failed { reason: String, retryable: bool },
}

/// Request parameters for a single-click claim
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirdropClaimRequest {
    pub claimant_address: String,
    pub airdrop_id: String,
    /// Sibling path from the claimant's leaf to the distribution root, hex
    /// encoded, leaf sibling first. Verified against the distribution root and
    /// depth by [`OneClickAirdropClaimer::check_eligibility`].
    pub proof: Vec<String>,
    /// The amount the claimant believes it was allocated. It is part of the
    /// leaf preimage, so a mismatched value invalidates the proof rather than
    /// being paid out.
    pub expected_amount: u64,
}

/// The published, immutable description of one airdrop.
///
/// This is the only trust anchor a claim needs: the root authenticates the
/// allocation set, `leaf_count` determines the tree depth that every proof
/// must have, and `airdrop_id` binds the root to a named distribution so a
/// proof cannot be replayed against a different airdrop.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AirdropDistribution {
    pub airdrop_id: String,
    pub root: Hash,
    /// Total number of allocations in the tree. Determines the required proof
    /// length; a mismatched value makes every proof fail.
    pub leaf_count: usize,
    /// Addresses (or address prefixes) that are refused regardless of proof.
    /// Defaults to empty — the denylist is a policy input, never a hardcoded
    /// constant in the verification path.
    pub denylist: Vec<String>,
}

impl AirdropDistribution {
    /// Create a distribution from an already-computed root.
    pub fn new(airdrop_id: &str, root: Hash, leaf_count: usize) -> Result<Self> {
        if airdrop_id.trim().is_empty() {
            return Err(ToolkitError::Session(
                "airdrop_id must not be empty".to_string(),
            ));
        }
        if leaf_count == 0 {
            return Err(ToolkitError::Session(format!(
                "airdrop `{airdrop_id}` has an empty allocation list, so it has no root to publish"
            )));
        }
        Ok(Self {
            airdrop_id: airdrop_id.to_string(),
            root,
            leaf_count,
            denylist: Vec::new(),
        })
    }

    /// Convenience constructor: publish the root of an in-memory tree.
    pub fn from_tree(airdrop_id: &str, tree: &MerkleTree) -> Result<Self> {
        let root = tree.root().ok_or_else(|| {
            ToolkitError::Session(format!("airdrop `{airdrop_id}` has no allocations"))
        })?;
        Self::new(airdrop_id, root, tree.len())
    }

    /// Attach a denylist of refused address prefixes.
    pub fn with_denylist(mut self, entries: Vec<String>) -> Self {
        self.denylist = entries.into_iter().filter(|e| !e.is_empty()).collect();
        self
    }

    /// The tree depth every proof for this distribution must have.
    pub fn depth(&self) -> usize {
        merkle::depth_for(self.leaf_count)
    }
}

/// One-click airdrop claim execution manager
pub struct OneClickAirdropClaimer;

impl OneClickAirdropClaimer {
    /// Checks eligibility of a claim request against a published distribution.
    ///
    /// A request is [`ClaimStatus::Eligible`] only when all of the following
    /// hold:
    ///
    /// 1. the claimant address is non-empty;
    /// 2. the request's `airdrop_id` names this distribution;
    /// 3. the address is not on the distribution's denylist;
    /// 4. every proof element is valid 32-byte hex;
    /// 5. `SHA256(leaf(address, expected_amount))` folded bottom-up with the
    ///    proof hashes to `distribution.root` **at exactly
    ///    `distribution.depth()` siblings**.
    ///
    /// Otherwise the result is [`ClaimStatus::Ineligible`] with a reason —
    /// ineligibility is an expected outcome of an untrusted request, not an
    /// error, so it does not consume the `Result` error channel.
    pub fn check_eligibility(
        request: &AirdropClaimRequest,
        distribution: &AirdropDistribution,
    ) -> Result<ClaimStatus> {
        let address = &request.claimant_address;
        if address.trim().is_empty() {
            return Ok(ClaimStatus::Ineligible {
                reason: "Empty claimant address".to_string(),
            });
        }

        if request.airdrop_id != distribution.airdrop_id {
            return Ok(ClaimStatus::Ineligible {
                reason: format!(
                    "Request names airdrop `{}` but the published distribution is `{}`",
                    request.airdrop_id, distribution.airdrop_id
                ),
            });
        }

        if distribution
            .denylist
            .iter()
            .any(|denied| address.starts_with(denied.as_str()))
        {
            return Ok(ClaimStatus::Ineligible {
                reason: format!(
                    "Address is on the denylist for airdrop `{}`",
                    distribution.airdrop_id
                ),
            });
        }

        let proof = match parse_proof(&request.proof) {
            Some(proof) => proof,
            None => {
                return Ok(ClaimStatus::Ineligible {
                    reason: format!(
                        "Proof is malformed: expected hex-encoded 32-byte nodes for airdrop `{}`",
                        distribution.airdrop_id
                    ),
                })
            }
        };

        let expected_depth = distribution.depth();
        let leaf = merkle::leaf_hash(address, request.expected_amount);
        if !merkle::verify_proof(&leaf, &proof, &distribution.root, expected_depth) {
            return Ok(ClaimStatus::Ineligible {
                reason: format!(
                    "Merkle proof does not verify against the root of airdrop `{}` \
                     (expected depth {expected_depth}, proof has {} node(s))",
                    distribution.airdrop_id,
                    proof.len()
                ),
            });
        }

        Ok(ClaimStatus::Eligible {
            amount: request.expected_amount,
        })
    }

    /// Builds a single-click airdrop claim transaction payload
    pub fn build_claim_transaction(
        request: &AirdropClaimRequest,
        distribution: &AirdropDistribution,
    ) -> Result<String> {
        let status = Self::check_eligibility(request, distribution)?;

        match status {
            ClaimStatus::Eligible { amount } => {
                let tx_payload = serde_json::json!({
                    "action": "claim_airdrop",
                    "airdrop_id": request.airdrop_id,
                    "claimant": request.claimant_address,
                    "proof": request.proof,
                    "amount": amount,
                    "fee": 100,
                    "built_at": 1700000000
                });
                Ok(tx_payload.to_string())
            }
            ClaimStatus::Ineligible { reason } => Err(ToolkitError::Session(format!(
                "Cannot build claim transaction: {}",
                reason
            ))),
            _ => Err(ToolkitError::Session(
                "Airdrop claim transaction build failed".to_string(),
            )),
        }
    }

    /// Executes single-click claim flow and returns resulting status
    pub fn execute_one_click_claim(
        request: &AirdropClaimRequest,
        distribution: &AirdropDistribution,
    ) -> Result<ClaimStatus> {
        let _tx_payload = Self::build_claim_transaction(request, distribution)?;
        // Derived from the (already proof-verified) leaf, so it is well defined
        // for any address length. The previous implementation sliced
        // `claimant_address.as_bytes()[..8]` and panicked on any address shorter
        // than eight bytes.
        let leaf = merkle::leaf_hash(&request.claimant_address, request.expected_amount);
        let mock_hash = format!("0x{}", hex::encode(&leaf[..8]));

        Ok(ClaimStatus::Claimed {
            tx_hash: mock_hash,
            timestamp: 1700000050,
        })
    }

    /// Attempts automated recovery for a failed claim
    pub fn recover_claim(
        request: &AirdropClaimRequest,
        distribution: &AirdropDistribution,
        failure_reason: &str,
    ) -> Result<ClaimStatus> {
        if failure_reason.contains("sequence_number") || failure_reason.contains("fee_bump") {
            Self::execute_one_click_claim(request, distribution)
        } else {
            Ok(ClaimStatus::Failed {
                reason: format!("Non-retryable failure: {}", failure_reason),
                retryable: false,
            })
        }
    }
}

/// Decode a request's hex-encoded proof into 32-byte nodes.
fn parse_proof(proof: &[String]) -> Option<Vec<Hash>> {
    proof
        .iter()
        .map(|node| {
            let bytes = hex::decode(node.trim()).ok()?;
            <[u8; 32]>::try_from(bytes.as_slice()).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::AirdropLeaf;

    const AIRDROP_ID: &str = "winter-airdrop-2026";

    fn distribution() -> AirdropDistribution {
        let tree = tree();
        AirdropDistribution::from_tree(AIRDROP_ID, &tree).expect("distribution")
    }

    /// 5 leaves: depth 3, with odd-level duplication exercised.
    fn tree() -> MerkleTree {
        MerkleTree::new(&[
            AirdropLeaf::new("GAAA", 1_000),
            AirdropLeaf::new("GBBB", AMOUNT_PER_CLAIM),
            AirdropLeaf::new("GCCC", 3_000),
            AirdropLeaf::new("GDDD", 4_000),
            AirdropLeaf::new("GEEE", 5_000),
        ])
    }

    fn request(address: &str, amount: u64, t: &MerkleTree) -> AirdropClaimRequest {
        let proof = t
            .proof_for(address, amount)
            .expect("allocation present in tree");
        AirdropClaimRequest {
            claimant_address: address.to_string(),
            airdrop_id: AIRDROP_ID.to_string(),
            proof: proof.iter().copied().map(hex::encode).collect(),
            expected_amount: amount,
        }
    }

    fn reason_of(status: &ClaimStatus) -> &str {
        match status {
            ClaimStatus::Ineligible { reason } => reason,
            other => panic!("expected Ineligible, got {other:?}"),
        }
    }

    #[test]
    fn eligible_claimant_gets_its_proven_amount() {
        let t = tree();
        let d = AirdropDistribution::from_tree(AIRDROP_ID, &t).unwrap();
        let status =
            OneClickAirdropClaimer::check_eligibility(&request("GBBB", AMOUNT_PER_CLAIM, &t), &d)
                .unwrap();
        assert_eq!(
            status,
            ClaimStatus::Eligible {
                amount: AMOUNT_PER_CLAIM
            }
        );
    }

    #[test]
    fn empty_address_is_ineligible() {
        let d = distribution();
        let mut req = request("GBBB", AMOUNT_PER_CLAIM, &tree());
        req.claimant_address = "   ".to_string();
        let status = OneClickAirdropClaimer::check_eligibility(&req, &d).unwrap();
        assert_eq!(reason_of(&status), "Empty claimant address");
    }

    #[test]
    fn proof_wrong_depth_is_rejected() {
        let t = tree();
        let d = AirdropDistribution::from_tree(AIRDROP_ID, &t).unwrap();
        assert_eq!(d.depth(), 3);

        // Truncate the proof: it is now the wrong length for a depth-3 tree.
        let mut req = request("GBBB", AMOUNT_PER_CLAIM, &t);
        req.proof.pop();
        let status = OneClickAirdropClaimer::check_eligibility(&req, &d).unwrap();
        assert!(reason_of(&status).contains("expected depth 3, proof has 2"));

        // Publishing a shallower leaf_count than the tree really has must not
        // help the claimant either.
        let lying = AirdropDistribution::new(AIRDROP_ID, d.root, 4).unwrap();
        let status = OneClickAirdropClaimer::check_eligibility(&req, &lying).unwrap();
        assert!(reason_of(&status).contains("expected depth 2"));
    }

    #[test]
    fn proof_built_for_a_shallower_tree_is_rejected() {
        // A 2-leaf tree is a prefix of the 5-leaf tree: a 1-element proof
        // really does hash to a real root, but not to *this* distribution's.
        let shallow = MerkleTree::new(&[
            AirdropLeaf::new("GAAA", 1_000),
            AirdropLeaf::new("GBBB", AMOUNT_PER_CLAIM),
        ]);
        let d = AirdropDistribution::from_tree(AIRDROP_ID, &tree()).unwrap();
        let req = request("GBBB", AMOUNT_PER_CLAIM, &shallow);
        assert_eq!(req.proof.len(), 1);
        // Sanity: that proof is valid for its own tree at its own depth.
        assert_eq!(shallow.depth(), 1);
        let shallow_d = AirdropDistribution::from_tree(AIRDROP_ID, &shallow).unwrap();
        assert!(matches!(
            OneClickAirdropClaimer::check_eligibility(&req, &shallow_d).unwrap(),
            ClaimStatus::Eligible { .. }
        ));
        // ...but not for the deeper distribution.
        let status = OneClickAirdropClaimer::check_eligibility(&req, &d).unwrap();
        assert!(reason_of(&status).contains("Merkle proof does not verify"));
    }

    #[test]
    fn wrong_leaf_index_is_rejected() {
        let t = tree();
        let d = AirdropDistribution::from_tree(AIRDROP_ID, &t).unwrap();
        // Valid proof path, wrong leaf.
        let mut req = request("GBBB", AMOUNT_PER_CLAIM, &t);
        req.claimant_address = "GAAA".to_string();
        let status = OneClickAirdropClaimer::check_eligibility(&req, &d).unwrap();
        assert!(reason_of(&status).contains("Merkle proof does not verify"));
    }

    #[test]
    fn wrong_amount_is_rejected() {
        let t = tree();
        let d = AirdropDistribution::from_tree(AIRDROP_ID, &t).unwrap();
        // Proof is valid for (GBBB, AMOUNT_PER_CLAIM) but the request claims more.
        let mut req = request("GBBB", AMOUNT_PER_CLAIM, &t);
        req.expected_amount = AMOUNT_PER_CLAIM + 1;
        let status = OneClickAirdropClaimer::check_eligibility(&req, &d).unwrap();
        assert!(reason_of(&status).contains("Merkle proof does not verify"));
    }

    #[test]
    fn tampered_leaf_is_rejected() {
        let t = tree();
        let d = AirdropDistribution::from_tree(AIRDROP_ID, &t).unwrap();
        let mut req = request("GBBB", AMOUNT_PER_CLAIM, &t);
        req.claimant_address = "GBBX".to_string();
        let status = OneClickAirdropClaimer::check_eligibility(&req, &d).unwrap();
        assert!(reason_of(&status).contains("Merkle proof does not verify"));
    }

    #[test]
    fn tampered_sibling_is_rejected() {
        let t = tree();
        let d = AirdropDistribution::from_tree(AIRDROP_ID, &t).unwrap();
        let mut req = request("GBBB", AMOUNT_PER_CLAIM, &t);
        let mut bytes = hex::decode(&req.proof[1]).unwrap();
        bytes[0] ^= 0x01;
        req.proof[1] = hex::encode(bytes);
        let status = OneClickAirdropClaimer::check_eligibility(&req, &d).unwrap();
        assert!(reason_of(&status).contains("Merkle proof does not verify"));
    }

    #[test]
    fn wrong_root_is_rejected() {
        let a = tree();
        let b = MerkleTree::new(&[AirdropLeaf::new("GAAA", 1_000)]);
        let d = AirdropDistribution::from_tree(AIRDROP_ID, &b).unwrap();
        let status =
            OneClickAirdropClaimer::check_eligibility(&request("GBBB", AMOUNT_PER_CLAIM, &a), &d)
                .unwrap();
        assert!(reason_of(&status).contains("Merkle proof does not verify"));
    }

    #[test]
    fn proof_from_another_tree_is_rejected() {
        let a = tree();
        let b = MerkleTree::new(&[
            AirdropLeaf::new("GAAA", 1_000),
            AirdropLeaf::new("GBBB", AMOUNT_PER_CLAIM),
            AirdropLeaf::new("GCCC", 3_000),
            AirdropLeaf::new("GDDD", 4_000),
            AirdropLeaf::new("GZZZ", 5_000),
        ]);
        let d = AirdropDistribution::from_tree(AIRDROP_ID, &a).unwrap();
        let status =
            OneClickAirdropClaimer::check_eligibility(&request("GBBB", AMOUNT_PER_CLAIM, &b), &d)
                .unwrap();
        assert!(reason_of(&status).contains("Merkle proof does not verify"));
    }

    #[test]
    fn single_leaf_tree_claims_with_an_empty_proof() {
        let t = MerkleTree::new(&[AirdropLeaf::new("GAAA", 7)]);
        let d = AirdropDistribution::from_tree(AIRDROP_ID, &t).unwrap();
        assert_eq!(d.depth(), 0);
        let status =
            OneClickAirdropClaimer::check_eligibility(&request("GAAA", 7, &t), &d).unwrap();
        assert_eq!(status, ClaimStatus::Eligible { amount: 7 });
    }

    #[test]
    fn malformed_proof_nodes_are_ineligible() {
        let t = tree();
        let d = AirdropDistribution::from_tree(AIRDROP_ID, &t).unwrap();
        let mut req = request("GBBB", AMOUNT_PER_CLAIM, &t);
        req.proof[0] = "not-hex".to_string();
        let status = OneClickAirdropClaimer::check_eligibility(&req, &d).unwrap();
        assert!(reason_of(&status).contains("Proof is malformed"));

        // Right hex, wrong length.
        let mut req = request("GBBB", AMOUNT_PER_CLAIM, &t);
        req.proof[0] = hex::encode([0u8; 16]);
        let status = OneClickAirdropClaimer::check_eligibility(&req, &d).unwrap();
        assert!(reason_of(&status).contains("Proof is malformed"));
    }

    #[test]
    fn foreign_airdrop_id_is_rejected() {
        let t = tree();
        let d = AirdropDistribution::from_tree(AIRDROP_ID, &t).unwrap();
        let mut req = request("GBBB", AMOUNT_PER_CLAIM, &t);
        req.airdrop_id = "some-other-airdrop".to_string();
        let status = OneClickAirdropClaimer::check_eligibility(&req, &d).unwrap();
        assert!(reason_of(&status).contains("Request names airdrop"));
    }

    #[test]
    fn denylisted_address_is_rejected_even_with_a_valid_proof() {
        let t = tree();
        let d = AirdropDistribution::from_tree(AIRDROP_ID, &t)
            .unwrap()
            .with_denylist(vec!["GDDD".to_string()]);
        let status =
            OneClickAirdropClaimer::check_eligibility(&request("GDDD", 4_000, &t), &d).unwrap();
        assert!(reason_of(&status).contains("denylist"));
    }

    #[test]
    fn arbitrary_address_is_not_eligible() {
        // The pre-fix behaviour: any non-empty, non-blacklisted address was
        // Eligible for a hardcoded amount with no proof at all.
        let d = distribution();
        let req = AirdropClaimRequest {
            claimant_address: "GTOTALLYNOTONTHELIST".to_string(),
            airdrop_id: AIRDROP_ID.to_string(),
            proof: vec![],
            expected_amount: AMOUNT_PER_CLAIM,
        };
        let status = OneClickAirdropClaimer::check_eligibility(&req, &d).unwrap();
        assert!(reason_of(&status).contains("Merkle proof does not verify"));
    }

    #[test]
    fn one_click_claim_flow_and_recovery() {
        let t = tree();
        let d = AirdropDistribution::from_tree(AIRDROP_ID, &t).unwrap();
        let req = request("GBBB", AMOUNT_PER_CLAIM, &t);

        let result = OneClickAirdropClaimer::execute_one_click_claim(&req, &d).unwrap();
        assert!(matches!(result, ClaimStatus::Claimed { .. }));

        let recovered =
            OneClickAirdropClaimer::recover_claim(&req, &d, "sequence_number_out_of_sync").unwrap();
        assert!(matches!(recovered, ClaimStatus::Claimed { .. }));

        let not_retryable =
            OneClickAirdropClaimer::recover_claim(&req, &d, "insufficient_balance").unwrap();
        assert!(matches!(
            not_retryable,
            ClaimStatus::Failed {
                retryable: false,
                ..
            }
        ));
    }

    #[test]
    fn claim_refused_for_ineligible_request() {
        let d = distribution();
        let req = AirdropClaimRequest {
            claimant_address: "G".to_string(),
            airdrop_id: AIRDROP_ID.to_string(),
            proof: vec![],
            expected_amount: 1,
        };
        assert!(OneClickAirdropClaimer::build_claim_transaction(&req, &d).is_err());
    }

    #[test]
    fn short_address_does_not_panic() {
        // The tx-hash derivation used to slice [..8] of the address bytes.
        let t = MerkleTree::new(&[AirdropLeaf::new("G", 42)]);
        let d = AirdropDistribution::from_tree(AIRDROP_ID, &t).unwrap();
        let req = request("G", 42, &t);
        let claimed = OneClickAirdropClaimer::execute_one_click_claim(&req, &d).unwrap();
        assert!(matches!(claimed, ClaimStatus::Claimed { .. }));
    }

    #[test]
    fn distribution_constructor_validates_inputs() {
        assert!(AirdropDistribution::new("", [0u8; 32], 1).is_err());
        assert!(AirdropDistribution::new("  ", [0u8; 32], 1).is_err());
        assert!(AirdropDistribution::new(AIRDROP_ID, [0u8; 32], 0).is_err());
        assert!(AirdropDistribution::from_tree(AIRDROP_ID, &MerkleTree::new(&[])).is_err());
        assert!(AirdropDistribution::new(AIRDROP_ID, [0u8; 32], 8)
            .unwrap()
            .with_denylist(vec![String::new()])
            .denylist
            .is_empty());
    }
}

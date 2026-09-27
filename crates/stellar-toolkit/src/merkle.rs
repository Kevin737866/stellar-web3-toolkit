//! Merkle tree utilities for airdrop distribution proofs.
//!
//! The airdrop module publishes a *Merkle root* and hands each recipient a
//! *path* from their leaf to that root. A recipient can prove membership — and
//! therefore prove the exact amount they were allocated — without the
//! distributor having to publish the full allocation list, and without any
//! on-chain state for "already claimed" addresses.
//!
//! # Design decisions (and why)
//!
//! ## Hash
//!
//! SHA-256, producing a 32-byte [`Hash`]. Airdrop allocation lists are
//! public data that must be reproducible on-chain and off-chain, so the tree
//! has to be computable with nothing but a standard hash; SHA-256 is the
//! cheapest such primitive that is also collision resistant.
//!
//! ## Leaf preimage
//!
//! A leaf hashes **the address and the amount**, never the address alone,
//! because the amount *is* part of what is being proven. A proof that only
//! committed to the address would let a claimant redirect their allocation to
//! an address of their choosing or claim it twice under two addresses.
//!
//! The preimage is domain separated and unambiguously encoded:
//!
//! ```text
//! leaf = SHA256( LEAF_DOMAIN || 0x00 || amount_be_u64 || len_be_u64(address) || address_bytes )
//! node = SHA256( NODE_DOMAIN   || left_32 || right_32 )
//! ```
//!
//! * `LEAF_DOMAIN` and `NODE_DOMAIN` are distinct, fixed-length tags and the
//!   leaf preimage additionally starts with a `0x00` byte. Because no node
//!   preimage can begin with a leaf preimage (and vice versa), a second
//!   preimage cannot be manufactured by presenting an internal node where a
//!   leaf is expected. This is the classic second-preimage footgun of naive
//!   `SHA256(concat(a, b))` trees.
//! * The amount is a fixed-width big-endian `u64`, so no two `(amount)`
//!   values share an encoding.
//! * The address is **length-prefixed**. Without the length prefix,
//!   `("GAB", 7)` and `("GAB7", ...)`-style shifts could produce the same
//!   preimage byte string for two different logical leaves.
//!
//! ## Odd nodes
//!
//! When a level has an odd number of nodes the **last node is paired with
//! itself** ("duplicate the last node"). The alternative — padding with a zero
//! hash — is also defensible, but duplication keeps every level's node count
//! exactly `ceil(n/2)` and makes the odd case indistinguishable from the
//! ordinary case, so there is no "which value fills the hole?" ambiguity for a
//! verifier to get wrong. It is also the Bitcoin/OpenZeppelin convention.
//!
//! ## Sorting
//!
//! The tree is **pairwise sorted**: a parent is always
//! `SHA256(NODE_DOMAIN || min(l, r) || max(l, r))`, and leaves are first sorted
//! by `(address, amount)`. Sorting at every level means the root depends only
//! on the *set* of leaves, not on the order they were inserted in or listed —
//! so a distributor who loads the same allocation CSV twice cannot accidentally
//! publish two different roots, and a verifier cannot be fed a differently
//! ordered tree. It also removes the ordering-ambiguity class of second
//! preimage attacks, where the same multiset of leaves arranged in a different
//! order produces a different internal node.
//!
//! ## Depth is checked explicitly
//!
//! [`verify_proof`] requires the caller to pass the tree's **expected depth**
//! and rejects any proof whose length differs. This is load-bearing, not
//! defensive decoration: the first `k` levels of a 8-leaf tree are byte-for-byte
//! the same nodes as the whole of some 4-leaf tree, so a 2-element proof
//! genuinely can hash to a real root of a *shallower* tree. Binding the depth
//! into the API makes "which tree shape is this proof for" a first-class,
//! checkable fact instead of an implicit assumption.
//!
//! ## Root comparison
//!
//! The final root comparison is constant time ([`ct_eq`]). The root is public
//! data, so a timing oracle on this particular comparison is not realistically
//! exploitable — but a constant-time compare costs a few nanoseconds and
//! removes the need to re-argue that for every future caller, so it is the
//! default rather than a comment.
//!
//! # Example
//!
//! ```
//! use stellar_toolkit::merkle::{depth_for, leaf_hash, verify_proof, AirdropLeaf, MerkleTree};
//!
//! let tree = MerkleTree::new(&[
//!     AirdropLeaf { address: "GAAA".into(), amount: 10 },
//!     AirdropLeaf { address: "GBBB".into(), amount: 20 },
//!     AirdropLeaf { address: "GCCC".into(), amount: 30 },
//! ]);
//! let root = tree.root().unwrap();
//! assert_eq!(tree.depth(), depth_for(tree.len()));
//!
//! let proof = tree.proof_for("GBBB", 20).unwrap();
//! assert!(verify_proof(&leaf_hash("GBBB", 20), &proof, &root, tree.depth()));
//! ```

use sha2::{Digest, Sha256};

/// A 32-byte SHA-256 digest.
pub type Hash = [u8; 32];

/// Domain tag prefixed to every leaf preimage.
pub const LEAF_DOMAIN: &[u8] = b"swt-merkle-leaf-v1";

/// Domain tag prefixed to every internal-node preimage.
pub const NODE_DOMAIN: &[u8] = b"swt-merkle-node-v1";

/// A single allocation: the address entitled to claim, and how much.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AirdropLeaf {
    pub address: String,
    pub amount: u64,
}

impl AirdropLeaf {
    pub fn new(address: impl Into<String>, amount: u64) -> Self {
        Self {
            address: address.into(),
            amount,
        }
    }
}

/// Hash of a single `(address, amount)` allocation.
///
/// See the module docs for the exact preimage layout.
pub fn leaf_hash(address: &str, amount: u64) -> Hash {
    let address = address.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(LEAF_DOMAIN);
    hasher.update([0u8]);
    hasher.update(amount.to_be_bytes());
    hasher.update((address.len() as u64).to_be_bytes());
    hasher.update(address);
    hasher.finalize().into()
}

/// Hash of an internal node, sorting the two children.
///
/// Sorting is what makes the root a function of the leaf *set*.
pub fn node_hash(left: Hash, right: Hash) -> Hash {
    let (l, r) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    let mut hasher = Sha256::new();
    hasher.update(NODE_DOMAIN);
    hasher.update(l);
    hasher.update(r);
    hasher.finalize().into()
}

/// The number of levels below the leaf level for a tree with `leaf_count`
/// leaves, i.e. `ceil(log2(leaf_count))` computed without floating point.
///
/// `depth_for(0)` and `depth_for(1)` are both `0`: a single-leaf tree's root
/// *is* its leaf and its proof is empty.
pub fn depth_for(leaf_count: usize) -> usize {
    let mut depth = 0usize;
    let mut capacity = 1usize;
    while capacity < leaf_count {
        capacity = capacity.saturating_mul(2);
        depth += 1;
    }
    depth
}

/// Constant-time equality for 32-byte digests.
///
/// The comparison does not short-circuit on the first differing byte.
pub fn ct_eq(a: &Hash, b: &Hash) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// A pairwise-sorted Merkle tree over a set of [`AirdropLeaf`] values.
///
/// `levels[0]` are the leaf hashes in sorted order; `levels[i + 1]` are the
/// parents of `levels[i]`.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    sorted_leaves: Vec<AirdropLeaf>,
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Build a tree from an unordered allocation list.
    ///
    /// Leaves are sorted by `(address, amount)`, so the resulting root does not
    /// depend on the input order. Duplicate `(address, amount)` pairs are the
    /// distributor's error: they occupy two leaves but a single
    /// [`MerkleTree::proof`] lookup resolves to the first of them.
    pub fn new(leaves: &[AirdropLeaf]) -> Self {
        let mut sorted = leaves.to_vec();
        sorted.sort();
        let level0: Vec<Hash> = sorted
            .iter()
            .map(|l| leaf_hash(&l.address, l.amount))
            .collect();
        Self::from_leaf_hashes(sorted, level0)
    }

    fn from_leaf_hashes(sorted_leaves: Vec<AirdropLeaf>, level0: Vec<Hash>) -> Self {
        let mut levels = vec![level0.clone()];
        let mut current = level0;
        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            let mut i = 0;
            while i < current.len() {
                let left = current[i];
                // Odd node: pair the last node with itself.
                let right = if i + 1 < current.len() {
                    current[i + 1]
                } else {
                    current[i]
                };
                next.push(node_hash(left, right));
                i += 2;
            }
            levels.push(next.clone());
            current = next;
        }
        Self {
            sorted_leaves,
            levels,
        }
    }

    /// Number of leaves.
    pub fn len(&self) -> usize {
        self.levels[0].len()
    }

    /// True when the tree was built from an empty allocation list.
    pub fn is_empty(&self) -> bool {
        self.levels[0].is_empty()
    }

    /// Number of sibling hashes a valid proof contains.
    ///
    /// Equal to [`depth_for`] of [`MerkleTree::len`].
    pub fn depth(&self) -> usize {
        self.levels.len().saturating_sub(1)
    }

    /// The Merkle root, or `None` for an empty tree (which has no root).
    pub fn root(&self) -> Option<Hash> {
        self.levels.last().and_then(|level| level.first().copied())
    }

    /// Position of an allocation in the sorted leaf order, if it is present.
    pub fn index_of(&self, address: &str, amount: u64) -> Option<usize> {
        self.sorted_leaves
            .iter()
            .position(|l| l.address == address && l.amount == amount)
    }

    /// Build the sibling path for the leaf at `index` in sorted order.
    pub fn proof(&self, index: usize) -> Option<Vec<Hash>> {
        if index >= self.len() {
            return None;
        }
        let mut index = index;
        let mut proof = Vec::with_capacity(self.depth());
        for level in 0..self.depth() {
            let nodes = &self.levels[level];
            // Mirrors construction: pairs are (2i, 2i+1), or (2i, 2i) when the
            // level has an odd number of nodes, so the partner of an even index
            // is the next node and the partner of an odd index is the previous
            // one — except for a trailing even index, whose partner is itself.
            let partner = index ^ 1;
            let sibling = if partner < nodes.len() {
                nodes[partner]
            } else {
                nodes[index]
            };
            proof.push(sibling);
            index /= 2;
        }
        Some(proof)
    }

    /// Build the sibling path for a specific `(address, amount)` allocation.
    pub fn proof_for(&self, address: &str, amount: u64) -> Option<Vec<Hash>> {
        self.proof(self.index_of(address, amount)?)
    }
}

/// Verify a leaf-to-root proof.
///
/// `proof` is consumed bottom-up: `proof[0]` is the leaf's sibling,
/// `proof[proof.len() - 1]` is the node just below the root. The length of
/// `proof` **must** equal `expected_depth` — a proof of the wrong length is
/// rejected outright rather than being allowed to hash to some other root.
pub fn verify_proof(
    leaf: &Hash,
    proof: &[Hash],
    expected_root: &Hash,
    expected_depth: usize,
) -> bool {
    if proof.len() != expected_depth {
        return false;
    }
    let mut acc = *leaf;
    for sibling in proof {
        acc = node_hash(acc, *sibling);
    }
    ct_eq(&acc, expected_root)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper: build a tree from `(address, amount)` pairs.
    fn tree(entries: &[(&str, u64)]) -> MerkleTree {
        let leaves: Vec<AirdropLeaf> = entries
            .iter()
            .map(|(a, amt)| AirdropLeaf::new(*a, *amt))
            .collect();
        MerkleTree::new(&leaves)
    }

    fn proof_for(t: &MerkleTree, address: &str, amount: u64) -> Vec<Hash> {
        t.proof_for(address, amount).expect("leaf present")
    }

    #[test]
    fn leaf_hash_binds_both_address_and_amount() {
        assert_ne!(leaf_hash("GAAA", 10), leaf_hash("GAAA", 11));
        assert_ne!(leaf_hash("GAAA", 10), leaf_hash("GAAB", 10));
        assert_eq!(leaf_hash("GAAA", 10), leaf_hash("GAAA", 10));
    }

    #[test]
    fn leaf_preimage_is_length_prefixed() {
        // Without a length prefix the two allocations below would share a
        // preimage; with it they cannot.
        assert_ne!(leaf_hash("GAB", 7), leaf_hash("GAB7", 0));
    }

    #[test]
    fn leaf_and_node_domains_are_separated() {
        // A 32-byte "leaf hash" must not be usable as an internal node.
        let a = leaf_hash("GAAA", 1);
        let b = leaf_hash("GBBB", 2);
        assert_ne!(node_hash(a, b), a);
        assert_ne!(node_hash(a, b), b);
    }

    #[test]
    fn root_is_independent_of_insertion_order() {
        let a = tree(&[("GAAA", 10), ("GBBB", 20), ("GCCC", 30)]);
        let b = tree(&[("GCCC", 30), ("GAAA", 10), ("GBBB", 20)]);
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn correct_proof_verifies() {
        let t = tree(&[("GAAA", 10), ("GBBB", 20), ("GCCC", 30)]);
        let root = t.root().unwrap();
        let proof = proof_for(&t, "GBBB", 20);
        assert_eq!(proof.len(), t.depth());
        assert!(verify_proof(
            &leaf_hash("GBBB", 20),
            &proof,
            &root,
            t.depth()
        ));
    }

    #[test]
    fn every_leaf_of_a_non_power_of_two_tree_verifies() {
        let t = tree(&[("GAAA", 10), ("GBBB", 20), ("GCCC", 30)]);
        let root = t.root().unwrap();
        for (addr, amt) in [("GAAA", 10u64), ("GBBB", 20), ("GCCC", 30)] {
            assert!(
                verify_proof(
                    &leaf_hash(addr, amt),
                    &proof_for(&t, addr, amt),
                    &root,
                    t.depth()
                ),
                "leaf {addr} must verify"
            );
        }
    }

    #[test]
    fn single_leaf_tree_has_depth_zero_and_empty_proof() {
        let t = tree(&[("GAAA", 10)]);
        assert_eq!(t.len(), 1);
        assert_eq!(t.depth(), 0);
        assert_eq!(t.root(), Some(leaf_hash("GAAA", 10)));
        let proof = proof_for(&t, "GAAA", 10);
        assert!(proof.is_empty());
        assert!(verify_proof(
            &leaf_hash("GAAA", 10),
            &proof,
            &t.root().unwrap(),
            0
        ));
    }

    #[test]
    fn empty_tree_has_no_root() {
        let t = tree(&[]);
        assert!(t.is_empty());
        assert_eq!(t.root(), None);
        assert_eq!(t.depth(), 0);
    }

    #[test]
    fn depth_for_matches_constructed_depth() {
        for n in 0..=64usize {
            let leaves: Vec<AirdropLeaf> = (0..n)
                .map(|i| AirdropLeaf::new(format!("G{i:04}"), i as u64))
                .collect();
            let t = MerkleTree::new(&leaves);
            assert_eq!(t.len(), n);
            assert_eq!(t.depth(), depth_for(n), "depth mismatch for {n} leaves");
        }
    }

    #[test]
    fn deeper_tree_rejects_proof_built_for_a_shallower_tree() {
        // 4 leaves => depth 2. Its proof has 2 elements, and it verifies
        // against its own root at expected_depth 2.
        let shallow = tree(&[("GAAA", 1), ("GBBB", 2), ("GCCC", 3), ("GDDD", 4)]);
        let shallow_proof = proof_for(&shallow, "GAAA", 1);
        assert_eq!(shallow_proof.len(), 2);
        assert!(verify_proof(
            &leaf_hash("GAAA", 1),
            &shallow_proof,
            &shallow.root().unwrap(),
            2
        ));

        // 8 leaves => depth 3. The same leaf's proof is 3 elements and lands
        // on a different root. Presenting the *truncated* (2-element) proof
        // with the deep tree's depth must be rejected on the length check.
        let deep = tree(&[
            ("GAAA", 1),
            ("GBBB", 2),
            ("GCCC", 3),
            ("GDDD", 4),
            ("GEEE", 5),
            ("GFFF", 6),
            ("GGGG", 7),
            ("GHHH", 8),
        ]);
        let deep_proof = proof_for(&deep, "GAAA", 1);
        assert_eq!(deep_proof.len(), 3);
        let mut truncated = deep_proof.clone();
        truncated.pop();
        assert_eq!(truncated.len(), 2);
        assert_ne!(shallow.root(), deep.root());
        assert!(
            !verify_proof(&leaf_hash("GAAA", 1), &truncated, &deep.root().unwrap(), 3),
            "a truncated proof for a deeper tree must be rejected"
        );
        // ...and the full proof still verifies.
        assert!(verify_proof(
            &leaf_hash("GAAA", 1),
            &deep_proof,
            &deep.root().unwrap(),
            3
        ));
    }

    #[test]
    fn proof_longer_than_expected_depth_is_rejected() {
        let t = tree(&[("GAAA", 1), ("GBBB", 2)]);
        let mut proof = proof_for(&t, "GAAA", 1);
        proof.push([0u8; 32]);
        assert!(!verify_proof(
            &leaf_hash("GAAA", 1),
            &proof,
            &t.root().unwrap(),
            1
        ));
    }

    #[test]
    fn wrong_leaf_index_is_rejected() {
        let t = tree(&[("GAAA", 10), ("GBBB", 20), ("GCCC", 30), ("GDDD", 40)]);
        let root = t.root().unwrap();
        // Proof for "GAAA" presented with the leaf hash of a different leaf.
        let wrong = proof_for(&t, "GBBB", 20);
        assert!(!verify_proof(
            &leaf_hash("GAAA", 10),
            &wrong,
            &root,
            t.depth()
        ));
    }

    #[test]
    fn wrong_amount_is_rejected() {
        let t = tree(&[("GAAA", 10), ("GBBB", 20)]);
        let root = t.root().unwrap();
        let proof = proof_for(&t, "GAAA", 10);
        assert!(verify_proof(
            &leaf_hash("GAAA", 10),
            &proof,
            &root,
            t.depth()
        ));
        // Same address, inflated amount: the leaf preimage differs.
        assert!(!verify_proof(
            &leaf_hash("GAAA", 11),
            &proof,
            &root,
            t.depth()
        ));
    }

    #[test]
    fn tampered_leaf_is_rejected() {
        let t = tree(&[("GAAA", 10), ("GBBB", 20)]);
        let proof = proof_for(&t, "GAAA", 10);
        let mut leaf = leaf_hash("GAAA", 10);
        leaf[0] ^= 0x01;
        assert!(!verify_proof(&leaf, &proof, &t.root().unwrap(), t.depth()));
    }

    #[test]
    fn tampered_sibling_is_rejected() {
        let t = tree(&[("GAAA", 10), ("GBBB", 20)]);
        let mut proof = proof_for(&t, "GAAA", 10);
        proof[0][31] ^= 0x80;
        assert!(!verify_proof(
            &leaf_hash("GAAA", 10),
            &proof,
            &t.root().unwrap(),
            t.depth()
        ));
    }

    #[test]
    fn wrong_root_is_rejected() {
        let a = tree(&[("GAAA", 10), ("GBBB", 20)]);
        let b = tree(&[("GAAA", 10), ("GCCC", 20)]);
        let proof = proof_for(&a, "GAAA", 10);
        assert!(!verify_proof(
            &leaf_hash("GAAA", 10),
            &proof,
            &b.root().unwrap(),
            a.depth()
        ));
    }

    #[test]
    fn proof_from_tree_a_is_rejected_against_tree_b_root() {
        let a = tree(&[
            ("GAAA", 1),
            ("GBBB", 2),
            ("GCCC", 3),
            ("GDDD", 4),
            ("GEEE", 5),
            ("GFFF", 6),
            ("GGGG", 7),
            ("GHHH", 8),
        ]);
        let b = tree(&[("GAAA", 1), ("GBBB", 2), ("GCCC", 3), ("GDDD", 4)]);
        let proof = proof_for(&a, "GAAA", 1);
        // Right depth for A, wrong tree.
        assert!(!verify_proof(
            &leaf_hash("GAAA", 1),
            &proof,
            &b.root().unwrap(),
            a.depth()
        ));
        // Right tree, wrong depth.
        assert!(!verify_proof(
            &leaf_hash("GAAA", 1),
            &proof,
            &b.root().unwrap(),
            b.depth()
        ));
    }

    #[test]
    fn unknown_allocation_has_no_proof() {
        let t = tree(&[("GAAA", 10)]);
        assert!(t.proof_for("GZZZ", 10).is_none());
        assert!(t.proof_for("GAAA", 11).is_none());
        assert!(t.proof(5).is_none());
    }

    #[test]
    fn ct_eq_compares_all_bytes() {
        let a = [7u8; 32];
        assert!(ct_eq(&a, &a));
        let mut b = a;
        b[31] = 8;
        assert!(!ct_eq(&a, &b));
    }
}

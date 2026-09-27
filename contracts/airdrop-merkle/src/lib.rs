//! Airdrops that scale to many thousands of recipients.
//!
//! Storing one on-chain entry per recipient makes a large airdrop prohibitively
//! expensive. Instead the admin commits to a Merkle root off-chain and stores
//! only that root. Recipients prove membership with a sibling path, and the
//! contract releases their allocation. One claim costs a constant number of
//! hashes regardless of how many people the campaign targets.
//!
//! # Leaf and node encoding
//!
//! Everything is hashed with SHA-256, exposed by the host as
//! [`Env::crypto`], so the tree can be rebuilt in any language.
//!
//! * leaf — `SHA256(LEAF_DOMAIN || account_sc_address_xdr || amount_i128_xdr)`
//! * internal node — `SHA256(0x01 || sorted(left, right))`
//!
//! Sibling halves are ordered lexicographically, and an unpaired node at any
//! level is promoted to the next level unchanged. `LEAF_DOMAIN` is
//! `soroban-merkle-claim-v1`. The `0x01` prefix keeps internal nodes in a
//! different domain than leaves, so a leaf can never be replayed as a subtree.

#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short,
    token::{StellarAssetClient, TokenClient},
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, Vec,
};

/// Domain separator mixed into every leaf pre-image.
pub const LEAF_DOMAIN: &[u8] = b"soroban-merkle-claim-v1";

/// First byte of an internal-node pre-image, keeping it out of the leaf domain.
const INTERNAL_NODE_TAG: u8 = 0x01;

#[contracttype]
#[derive(Clone)]
pub struct Config {
    pub admin: Address,
    pub token: Address,
    pub merkle_root: BytesN<32>,
    pub total_amount: i128,
    pub claimed_amount: i128,
    pub claim_count: u32,
    /// `0` means the campaign never expires.
    pub expiry_ledger: u32,
    pub root_set: bool,
    pub paused: bool,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Config,
    /// Marks the `(account, amount)` pair behind `leaf` as already used.
    Claimed(BytesN<32>),
}

#[contract]
pub struct AirdropMerkle;

fn config(env: &Env) -> Config {
    env.storage()
        .instance()
        .get(&DataKey::Config)
        .expect("not initialized")
}

fn set_config(env: &Env, cfg: &Config) {
    env.storage().instance().set(&DataKey::Config, cfg);
}

// ---------------------------------------------------------------------------
// Merkle helpers
// ---------------------------------------------------------------------------

fn sha256(env: &Env, bytes: &Bytes) -> BytesN<32> {
    env.crypto().sha256(bytes).to_bytes()
}

/// `SHA256(LEAF_DOMAIN || account.to_xdr() || amount.to_xdr())`.
pub fn claim_leaf(env: &Env, account: &Address, amount: i128) -> BytesN<32> {
    let mut preimage = Bytes::from_slice(env, LEAF_DOMAIN);
    preimage.append(&account.to_xdr(env));
    preimage.append(&amount.to_xdr(env));
    sha256(env, &preimage)
}

/// `SHA256(0x01 || min(left, right) || max(left, right))`.
///
/// Halves are compared as raw 32-byte payloads rather than through
/// [`BytesN`]'s ordering, which is defined over the underlying host object and
/// would not match the lexicographic ordering a tree builder uses off-chain.
fn hash_node(env: &Env, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
    let (low, high) = if left.to_array() <= right.to_array() {
        (left, right)
    } else {
        (right, left)
    };
    let mut preimage = Bytes::from_slice(env, &[INTERNAL_NODE_TAG]);
    preimage.append(&Bytes::from_slice(env, &low.to_array()));
    preimage.append(&Bytes::from_slice(env, &high.to_array()));
    sha256(env, &preimage)
}

/// Walks a sibling path and reports whether it lands on `root`.
///
/// The same sorted-halves rule used to build the tree is applied here, so a
/// recipient only needs the siblings along their own branch.
fn verify_proof(env: &Env, root: &BytesN<32>, leaf: &BytesN<32>, proof: &Vec<BytesN<32>>) -> bool {
    let mut computed = leaf.clone();
    for sibling in proof.iter() {
        computed = hash_node(env, &computed, &sibling);
    }
    computed == *root
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contractimpl]
impl AirdropMerkle {
    /// One-time setup. `expiry_ledger` of `0` disables expiry; otherwise claims
    /// close once the current ledger passes it.
    pub fn initialize(env: Env, admin: Address, token: Address, expiry_ledger: u32) {
        assert!(
            !env.storage().instance().has(&DataKey::Config),
            "already initialized"
        );
        admin.require_auth();
        set_config(
            &env,
            &Config {
                admin,
                token,
                merkle_root: BytesN::from_array(&env, &[0u8; 32]),
                total_amount: 0,
                claimed_amount: 0,
                claim_count: 0,
                expiry_ledger,
                root_set: false,
                paused: false,
            },
        );
    }

    pub fn admin(env: Env) -> Address {
        config(&env).admin
    }

    pub fn set_admin(env: Env, new_admin: Address) {
        let mut cfg = config(&env);
        cfg.admin.require_auth();
        cfg.admin = new_admin.clone();
        set_config(&env, &cfg);
        env.events()
            .publish((symbol_short!("set_admin"),), new_admin);
    }

    pub fn token(env: Env) -> Address {
        config(&env).token
    }

    pub fn merkle_root(env: Env) -> BytesN<32> {
        config(&env).merkle_root
    }

    /// Total allocation encoded in the committed tree.
    pub fn total_amount(env: Env) -> i128 {
        config(&env).total_amount
    }

    pub fn claimed_amount(env: Env) -> i128 {
        config(&env).claimed_amount
    }

    pub fn claim_count(env: Env) -> u32 {
        config(&env).claim_count
    }

    pub fn expiry_ledger(env: Env) -> u32 {
        config(&env).expiry_ledger
    }

    pub fn expired(env: Env) -> bool {
        let cfg = config(&env);
        cfg.expiry_ledger != 0 && env.ledger().sequence() > cfg.expiry_ledger
    }

    pub fn paused(env: Env) -> bool {
        config(&env).paused
    }

    /// Whether `(account, amount)` has already been claimed.
    pub fn is_claimed(env: Env, account: Address, amount: i128) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::Claimed(claim_leaf(&env, &account, amount)))
    }

    /// Commits the campaign. Only accepted before the first claim, so a
    /// published root can never be swapped out from under recipients.
    pub fn set_merkle_root(env: Env, merkle_root: BytesN<32>, total_amount: i128) {
        let mut cfg = config(&env);
        cfg.admin.require_auth();
        assert!(!cfg.root_set, "merkle root already set");
        assert!(total_amount > 0, "total amount must be positive");

        cfg.merkle_root = merkle_root.clone();
        cfg.total_amount = total_amount;
        cfg.root_set = true;
        set_config(&env, &cfg);

        env.events()
            .publish((symbol_short!("set_root"),), merkle_root);
    }

    /// Tops up the contract so claims can be paid out.
    pub fn fund(env: Env, funder: Address, amount: i128) {
        funder.require_auth();
        assert!(amount > 0, "amount must be positive");
        TokenClient::new(&env, &config(&env).token).transfer(
            &funder,
            &env.current_contract_address(),
            &amount,
        );
    }

    /// Releases `amount` to `claimer` if `proof` shows their leaf is in the
    /// committed tree. Each `(account, amount)` pair can be claimed only once.
    pub fn claim(env: Env, claimer: Address, amount: i128, proof: Vec<BytesN<32>>) -> i128 {
        claimer.require_auth();
        let mut cfg = config(&env);

        assert!(cfg.root_set, "merkle root not set");
        assert!(!cfg.paused, "campaign is paused");
        assert!(!expired_at(&env, &cfg), "campaign has expired");
        assert!(amount > 0, "amount must be positive");

        let leaf = claim_leaf(&env, &claimer, amount);
        assert!(
            !env.storage()
                .persistent()
                .has(&DataKey::Claimed(leaf.clone())),
            "already claimed"
        );
        assert!(
            verify_proof(&env, &cfg.merkle_root, &leaf, &proof),
            "invalid merkle proof"
        );

        // The escrow must always cover the whole unclaimed liability, otherwise
        // an early claimant could consume funds earmarked for later ones. This
        // also surfaces a campaign that was never funded in full.
        let token = cfg.token.clone();
        let contract = env.current_contract_address();
        let available = TokenClient::new(&env, &token).balance(&contract);
        assert!(
            available + cfg.claimed_amount >= cfg.total_amount,
            "campaign is underfunded"
        );

        env.storage()
            .persistent()
            .set(&DataKey::Claimed(leaf), &true);
        cfg.claimed_amount += amount;
        cfg.claim_count += 1;
        set_config(&env, &cfg);

        TokenClient::new(&env, &token).transfer(&contract, &claimer, &amount);

        env.events()
            .publish((symbol_short!("claim"), claimer), amount);
        amount
    }

    /// Pauses new claims without changing the committed root.
    pub fn set_paused(env: Env, paused: bool) {
        let mut cfg = config(&env);
        cfg.admin.require_auth();
        cfg.paused = paused;
        set_config(&env, &cfg);
    }

    /// Returns whatever is left to `to` once the campaign has expired.
    pub fn sweep_unclaimed(env: Env, to: Address) -> i128 {
        let cfg = config(&env);
        cfg.admin.require_auth();
        assert!(expired_at(&env, &cfg), "campaign has not expired");

        let contract = env.current_contract_address();
        let remaining = TokenClient::new(&env, &cfg.token).balance(&contract);
        if remaining > 0 {
            TokenClient::new(&env, &cfg.token).transfer(&contract, &to, &remaining);
        }
        env.events()
            .publish((symbol_short!("sweep"),), (to, remaining));
        remaining
    }
}

fn expired_at(env: &Env, cfg: &Config) -> bool {
    cfg.expiry_ledger != 0 && env.ledger().sequence() > cfg.expiry_ledger
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
    use soroban_sdk::{Symbol, TryFromVal};

    /// Builds the same tree the contract verifies against, returning the root
    /// and the sibling path for each leaf, in the caller's original order.
    ///
    /// Leaves are paired in lexicographic order and an unpaired node is promoted
    /// to the next level unchanged, mirroring `hash_node` and `verify_proof`.
    /// Each level appends to the path of every original leaf a node covers, so
    /// the paths come out ordered leaf-to-root exactly as the verifier walks
    /// them.
    fn build_tree(
        env: &Env,
        leaves: &[BytesN<32>],
    ) -> (BytesN<32>, std::vec::Vec<std::vec::Vec<BytesN<32>>>) {
        assert!(!leaves.is_empty(), "empty tree");
        if leaves.len() == 1 {
            return (leaves[0].clone(), std::vec![std::vec::Vec::new()]);
        }

        // Pair leaves in the same lexicographic order `hash_node` uses.
        let mut order: std::vec::Vec<usize> = (0..leaves.len()).collect();
        order.sort_by(|a, b| leaves[*a].to_array().cmp(&leaves[*b].to_array()));

        // Each level entry is a node plus the original leaf indices it covers.
        let mut level: std::vec::Vec<(BytesN<32>, std::vec::Vec<usize>)> = order
            .iter()
            .map(|&i| (leaves[i].clone(), std::vec![i]))
            .collect();
        let mut paths: std::vec::Vec<std::vec::Vec<BytesN<32>>> =
            std::vec![std::vec::Vec::new(); leaves.len()];

        while level.len() > 1 {
            let mut next: std::vec::Vec<(BytesN<32>, std::vec::Vec<usize>)> = std::vec::Vec::new();
            let mut j = 0;
            while j < level.len() {
                if j + 1 < level.len() {
                    let (left, left_leaves) = level[j].clone();
                    let (right, right_leaves) = level[j + 1].clone();
                    for idx in &left_leaves {
                        paths[*idx].push(right.clone());
                    }
                    for idx in &right_leaves {
                        paths[*idx].push(left.clone());
                    }
                    let mut merged = left_leaves;
                    merged.extend(right_leaves);
                    next.push((hash_node(env, &left, &right), merged));
                    j += 2;
                } else {
                    // Promote the unpaired node; its path is unchanged.
                    next.push(level[j].clone());
                    j += 1;
                }
            }
            level = next;
        }

        (level[0].0.clone(), paths)
    }

    fn setup(expiry_ledger: u32) -> (Env, Address, Address, AirdropMerkleClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let id = env.register_contract(None, AirdropMerkle);
        let client = AirdropMerkleClient::new(&env, &id);
        client.initialize(&admin, &token, &expiry_ledger);
        (env, admin, token, client)
    }

    fn to_proof(env: &Env, path: &[BytesN<32>]) -> Vec<BytesN<32>> {
        Vec::from_slice(env, path)
    }

    /// Pins the leaf pre-image so off-chain tree builders cannot silently
    /// drift from the on-chain verifier.
    ///
    /// `Address::generate` yields a contract address with id `1`, so the leaf
    /// below is fully reproducible. Independently checkable with:
    ///
    /// ```text
    /// sha256(b"soroban-merkle-claim-v1"
    ///        + uint32be(0x12)          # ScVal::ScAddress
    ///        + uint32be(0x01)          # ScAddressType::Contract
    ///        + uint32be(1)             # contract id, 32 bytes
    ///        + uint32be(0x0A)          # ScVal::I128
    ///        + int128be(1000))         # amount, 16 bytes
    /// = a5429068f242de7668e5b645ddeb99499adda821ee2b368151d21b2a069b9e01
    /// ```
    #[test]
    fn leaf_digest_matches_the_documented_preimage() {
        let env = Env::default();
        let account = Address::generate(&env);
        let amount = 1_000i128;

        // Rebuild the documented pre-image by hand.
        let mut spec = Bytes::from_slice(&env, LEAF_DOMAIN);
        spec.append(&Bytes::from_slice(&env, &0x0000_0012u32.to_be_bytes()));
        spec.append(&Bytes::from_slice(&env, &0x0000_0001u32.to_be_bytes()));
        for _ in 0..31 {
            spec.push_back(0);
        }
        spec.push_back(1);
        spec.append(&Bytes::from_slice(&env, &0x0000_000Au32.to_be_bytes()));
        spec.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));

        let leaf = claim_leaf(&env, &account, amount);
        assert_eq!(leaf, env.crypto().sha256(&spec).to_bytes());

        let hex: std::string::String = leaf
            .to_array()
            .iter()
            .map(|b| std::format!("{:02x}", b))
            .collect();
        assert_eq!(
            hex,
            "a5429068f242de7668e5b645ddeb99499adda821ee2b368151d21b2a069b9e01"
        );
    }

    /// The documented internal-node layout, checked against a two-leaf tree.
    #[test]
    fn internal_node_digest_matches_the_documented_preimage() {
        let env = Env::default();
        let left = BytesN::from_array(&env, &[0x11u8; 32]);
        let right = BytesN::from_array(&env, &[0x22u8; 32]);

        let mut spec = Bytes::from_slice(&env, &[INTERNAL_NODE_TAG]);
        spec.append(&Bytes::from_slice(&env, &left.to_array()));
        spec.append(&Bytes::from_slice(&env, &right.to_array()));

        assert_eq!(
            hash_node(&env, &left, &right),
            env.crypto().sha256(&spec).to_bytes()
        );
    }

    /// Halves are ordered, so both sibling orders produce the same node.
    #[test]
    fn node_hashing_is_order_independent() {
        let env = Env::default();
        let low = BytesN::from_array(&env, &[0x01u8; 32]);
        let high = BytesN::from_array(&env, &[0xFEu8; 32]);
        assert_eq!(hash_node(&env, &low, &high), hash_node(&env, &high, &low));
    }

    #[test]
    fn single_recipient_tree_has_an_empty_proof() {
        let (env, _, token, client) = setup(0);
        let alice = Address::generate(&env);
        let amount = 500i128;

        let leaf = claim_leaf(&env, &alice, amount);
        let (root, paths) = build_tree(&env, &[leaf.clone()]);
        assert_eq!(paths[0].len(), 0);

        client.set_merkle_root(&root, &amount);
        fund(&env, &token, &client, &alice, amount);

        assert_eq!(
            client.claim(&alice, &amount, &to_proof(&env, &paths[0])),
            amount
        );
        assert_eq!(TokenClient::new(&env, &token).balance(&alice), amount);
    }

    fn fund(
        env: &Env,
        token: &Address,
        client: &AirdropMerkleClient,
        from: &Address,
        amount: i128,
    ) {
        StellarAssetClient::new(env, token).mint(from, &amount);
        client.fund(from, &amount);
        assert_eq!(
            TokenClient::new(env, token).balance(&client.address),
            amount
        );
    }

    #[test]
    fn multi_recipient_tree_pays_every_proven_claim() {
        let (env, _, token, client) = setup(0);
        let allocations = [
            (Address::generate(&env), 100i128),
            (Address::generate(&env), 250i128),
            (Address::generate(&env), 375i128),
            (Address::generate(&env), 500i128),
            (Address::generate(&env), 625i128),
        ];

        let leaves: std::vec::Vec<BytesN<32>> = allocations
            .iter()
            .map(|(account, amount)| claim_leaf(&env, account, *amount))
            .collect();
        let total: i128 = allocations.iter().map(|(_, amount)| amount).sum();
        let (root, paths) = build_tree(&env, &leaves);

        client.set_merkle_root(&root, &total);
        let funder = Address::generate(&env);
        StellarAssetClient::new(&env, &token).mint(&funder, &total);
        client.fund(&funder, &total);
        assert_eq!(
            TokenClient::new(&env, &token).balance(&client.address),
            total
        );

        for (i, (account, amount)) in allocations.iter().enumerate() {
            let claimed = client.claim(account, amount, &to_proof(&env, &paths[i]));
            assert_eq!(claimed, *amount);
            assert_eq!(TokenClient::new(&env, &token).balance(account), *amount);
        }

        assert_eq!(client.claim_count(), 5);
        assert_eq!(client.claimed_amount(), total);
    }

    #[test]
    fn odd_sized_tree_promotes_the_unpaired_node() {
        let env = Env::default();
        let allocations: std::vec::Vec<(Address, i128)> = (0..5)
            .map(|i| (Address::generate(&env), 10 * (i as i128 + 1)))
            .collect();
        let leaves: std::vec::Vec<BytesN<32>> = allocations
            .iter()
            .map(|(account, amount)| claim_leaf(&env, account, *amount))
            .collect();
        let (root, paths) = build_tree(&env, &leaves);

        for (i, (account, amount)) in allocations.iter().enumerate() {
            assert!(verify_proof(
                &env,
                &root,
                &claim_leaf(&env, account, *amount),
                &to_proof(&env, &paths[i])
            ));
        }
    }

    #[test]
    fn a_claim_cannot_be_replayed() {
        let (env, _, token, client) = setup(0);
        let alice = Address::generate(&env);
        let amount = 700i128;
        let leaf = claim_leaf(&env, &alice, amount);
        let (root, paths) = build_tree(&env, &[leaf]);

        client.set_merkle_root(&root, &amount);
        fund(&env, &token, &client, &alice, amount);
        client.claim(&alice, &amount, &to_proof(&env, &paths[0]));

        assert!(client.is_claimed(&alice, &amount));
        assert!(client
            .try_claim(&alice, &amount, &to_proof(&env, &paths[0]))
            .is_err());
        assert_eq!(client.claim_count(), 1);
    }

    #[test]
    fn a_different_amount_fails_against_the_same_proof() {
        let (env, _, token, client) = setup(0);
        let alice = Address::generate(&env);
        let amount = 700i128;
        let leaf = claim_leaf(&env, &alice, amount);
        let (root, paths) = build_tree(&env, &[leaf]);

        client.set_merkle_root(&root, &amount);
        fund(&env, &token, &client, &alice, amount);

        // The amount is part of the leaf, so inflating it breaks the proof.
        assert!(client
            .try_claim(&alice, &7000, &to_proof(&env, &paths[0]))
            .is_err());
        assert_eq!(client.claim_count(), 0);
    }

    #[test]
    fn a_proof_from_another_account_is_rejected() {
        let (env, _, token, client) = setup(0);
        let alice = Address::generate(&env);
        let mallory = Address::generate(&env);
        let amount = 700i128;

        let (root, paths) = build_tree(&env, &[claim_leaf(&env, &alice, amount)]);
        client.set_merkle_root(&root, &amount);
        fund(&env, &token, &client, &alice, amount);

        assert!(client
            .try_claim(&mallory, &amount, &to_proof(&env, &paths[0]))
            .is_err());
    }

    #[test]
    fn claims_are_rejected_before_the_root_is_set() {
        let (env, _, token, client) = setup(0);
        let alice = Address::generate(&env);
        let amount = 700i128;
        let (_root, paths) = build_tree(&env, &[claim_leaf(&env, &alice, amount)]);
        fund(&env, &token, &client, &alice, amount);

        assert!(client
            .try_claim(&alice, &amount, &to_proof(&env, &paths[0]))
            .is_err());
    }

    #[test]
    fn merkle_root_is_immutable_after_the_first_claim() {
        let (env, _, token, client) = setup(0);
        let alice = Address::generate(&env);
        let amount = 700i128;
        let (root, paths) = build_tree(&env, &[claim_leaf(&env, &alice, amount)]);
        client.set_merkle_root(&root, &amount);
        fund(&env, &token, &client, &alice, amount);
        client.claim(&alice, &amount, &to_proof(&env, &paths[0]));

        let (other_root, _) = build_tree(&env, &[claim_leaf(&env, &alice, 1_000i128)]);
        assert!(client.try_set_merkle_root(&other_root, &1_000).is_err());
    }

    #[test]
    fn expiry_blocks_claims_and_allows_sweeping() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let treasury = Address::generate(&env);
        let id = env.register_contract(None, AirdropMerkle);
        let client = AirdropMerkleClient::new(&env, &id);

        let expiry = env.ledger().sequence() + 10;
        client.initialize(&admin, &token, &expiry);

        let alice = Address::generate(&env);
        let amount = 400i128;
        let (root, paths) = build_tree(&env, &[claim_leaf(&env, &alice, amount)]);
        client.set_merkle_root(&root, &amount);

        // Fund three allocations but only one recipient exists in the tree.
        StellarAssetClient::new(&env, &token).mint(&treasury, &1_200);
        client.fund(&treasury, &1_200);

        client.claim(&alice, &amount, &to_proof(&env, &paths[0]));
        assert_eq!(client.claimed_amount(), amount);
        assert!(!client.expired());

        // Sweeping before expiry is rejected.
        assert!(client.try_sweep_unclaimed(&treasury).is_err());

        env.ledger().set_sequence_number(expiry + 1);
        assert!(client.expired());
        assert!(client
            .try_claim(&alice, &amount, &to_proof(&env, &paths[0]))
            .is_err());

        let swept = client.sweep_unclaimed(&treasury);
        assert_eq!(swept, 800);
        assert_eq!(TokenClient::new(&env, &token).balance(&treasury), 800);
        assert_eq!(TokenClient::new(&env, &token).balance(&client.address), 0);
    }

    #[test]
    fn zero_expiry_never_closes_the_campaign() {
        // Raise the TTL ceiling so the ledger can jump far ahead of any
        // plausible campaign length without archiving state.
        let (env, _, token, client) = {
            let env = Env::default();
            env.mock_all_auths();
            env.ledger().set_min_persistent_entry_ttl(1_000_000);
            env.ledger().set_max_entry_ttl(1_000_000);
            let admin = Address::generate(&env);
            let token = env
                .register_stellar_asset_contract_v2(admin.clone())
                .address();
            let id = env.register_contract(None, AirdropMerkle);
            let client = AirdropMerkleClient::new(&env, &id);
            client.initialize(&admin, &token, &0);
            (env, (), token, client)
        };

        let alice = Address::generate(&env);
        let amount = 900i128;
        let (root, paths) = build_tree(&env, &[claim_leaf(&env, &alice, amount)]);
        client.set_merkle_root(&root, &amount);
        fund(&env, &token, &client, &alice, amount);

        env.ledger().set_sequence_number(500_000);
        assert!(!client.expired());
        client.claim(&alice, &amount, &to_proof(&env, &paths[0]));
    }

    #[test]
    fn paused_campaign_rejects_claims_and_resumes() {
        let (env, _, token, client) = setup(0);
        let alice = Address::generate(&env);
        let amount = 900i128;
        let (root, paths) = build_tree(&env, &[claim_leaf(&env, &alice, amount)]);
        client.set_merkle_root(&root, &amount);
        fund(&env, &token, &client, &alice, amount);

        client.set_paused(&true);
        assert!(client.paused());
        assert!(client
            .try_claim(&alice, &amount, &to_proof(&env, &paths[0]))
            .is_err());

        client.set_paused(&false);
        client.claim(&alice, &amount, &to_proof(&env, &paths[0]));
    }

    #[test]
    fn underfunded_campaigns_fail_loudly() {
        let (env, _, token, client) = setup(0);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let allocations = [(alice.clone(), 500i128), (bob.clone(), 500i128)];

        let leaves: std::vec::Vec<BytesN<32>> = allocations
            .iter()
            .map(|(account, amount)| claim_leaf(&env, account, *amount))
            .collect();
        let (root, paths) = build_tree(&env, &leaves);
        client.set_merkle_root(&root, &1_000);

        // Only the first allocation is funded, so the escrow cannot cover the
        // whole liability. Nobody may claim, otherwise an early claimant would
        // consume funds earmarked for someone else.
        StellarAssetClient::new(&env, &token).mint(&alice, &500);
        client.fund(&alice, &500);

        assert!(client
            .try_claim(&alice, &500, &to_proof(&env, &paths[0]))
            .is_err());
        assert!(client
            .try_claim(&bob, &500, &to_proof(&env, &paths[1]))
            .is_err());
        assert_eq!(client.claim_count(), 0);
        assert_eq!(TokenClient::new(&env, &token).balance(&alice), 0);
        assert_eq!(TokenClient::new(&env, &token).balance(&client.address), 500);

        // Topping the escrow up unblocks both claims.
        StellarAssetClient::new(&env, &token).mint(&bob, &500);
        client.fund(&bob, &500);
        client.claim(&alice, &500, &to_proof(&env, &paths[0]));
        client.claim(&bob, &500, &to_proof(&env, &paths[1]));
        assert_eq!(client.claim_count(), 2);
    }

    #[test]
    fn claim_emits_an_event() {
        let (env, _, token, client) = setup(0);
        let alice = Address::generate(&env);
        let amount = 300i128;
        let (root, paths) = build_tree(&env, &[claim_leaf(&env, &alice, amount)]);
        client.set_merkle_root(&root, &amount);
        fund(&env, &token, &client, &alice, amount);
        client.claim(&alice, &amount, &to_proof(&env, &paths[0]));

        let mut names: std::vec::Vec<Symbol> = std::vec::Vec::new();
        for (_, topics, _) in env.events().all() {
            for i in 0..topics.len() {
                if let Ok(sym) = Symbol::try_from_val(&env, &topics.get(i).unwrap()) {
                    names.push(sym);
                }
            }
        }
        assert!(names.contains(&symbol_short!("claim")));
    }
}

//! Idempotent swap initiation (issue #212).
//!
//! # The problem
//!
//! [`AtomicSwapCoordinator::initiate_swap`](crate::AtomicSwapCoordinator::initiate_swap)
//! is not safe to retry. Every call generates a fresh preimage, hashes it into a
//! new hash lock and stores a new swap, so a client that times out waiting for the
//! response and retries ends up with *two* swaps funded against the same intent
//! and only one of them ever settles. The client cannot even tell which response
//! was the real one, because both look valid.
//!
//! # The mechanism
//!
//! A caller-chosen [`IdempotencyKey`] is bound to the first successful
//! initiation it is used with. Re-presenting the same key:
//!
//! * with the same initiator and the same [`SwapRequest`] returns the response
//!   recorded by the original call — same swap id, same hash lock, same preimage
//!   — without creating a second swap;
//! * with a different initiator or a different request is refused with
//!   [`AtomicSwapError::IdempotencyConflict`], so a key can never be used to
//!   observe or hijack someone else's swap.
//!
//! Failed initiations do **not** consume the key. A request that was rejected
//! (bad timeout, unsupported asset, replayed nonce, ...) created nothing, so
//! retrying the same key with a corrected request must be allowed to proceed.
//!
//! # Scope
//!
//! This is exactly-once initiation *within one coordinator process*, which is
//! where the duplicate-swap bug lives. It is not a durable distributed lock:
//! two coordinator instances still have separate stores. Settlement is already
//! idempotent on chain (a completed swap cannot be completed twice), so the
//! record is only needed for the initiation window and is deliberately held in
//! memory rather than persisted with the swaps.
//!
//! Keys are compared byte-for-byte. They are not trimmed or lower-cased: two
//! callers that send `swap-1` and `Swap-1` hold different keys, and silently
//! treating them as equal would be a surprising source of accidental replay.

use crate::coordinator::{SwapRequest, SwapResponse};
use crate::error::{AtomicSwapError, Result};
use std::collections::HashMap;
use std::fmt;

/// Longest accepted idempotency key, in bytes.
///
/// Keys are caller-controlled, so the length is bounded: the store is in
/// memory and every entry is retained for the coordinator's lifetime.
pub const MAX_IDEMPOTENCY_KEY_LEN: usize = 128;

/// A caller-chosen key identifying one logical initiation attempt.
///
/// Construct with [`IdempotencyKey::new`], which rejects keys that cannot be
/// used safely (empty, over-long, or containing control characters).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Validate and wrap `key`.
    ///
    /// Rejects:
    ///
    /// * an empty key — it would make every anonymous retry collide;
    /// * a key longer than [`MAX_IDEMPOTENCY_KEY_LEN`] bytes — unbounded input
    ///   into an in-memory map;
    /// * a key containing control characters — those do not survive logging or
    ///   a round trip through a header cleanly, so the key a client sent and
    ///   the key an operator reads could differ.
    pub fn new(key: impl Into<String>) -> Result<Self> {
        let key = key.into();
        if key.is_empty() {
            return Err(AtomicSwapError::InvalidIdempotencyKey {
                reason: "key must not be empty".to_string(),
            });
        }
        if key.len() > MAX_IDEMPOTENCY_KEY_LEN {
            return Err(AtomicSwapError::InvalidIdempotencyKey {
                reason: format!(
                    "key is {} bytes, the maximum is {MAX_IDEMPOTENCY_KEY_LEN}",
                    key.len()
                ),
            });
        }
        if key.chars().any(char::is_control) {
            return Err(AtomicSwapError::InvalidIdempotencyKey {
                reason: "key must not contain control characters".to_string(),
            });
        }
        Ok(Self(key))
    }

    /// The key exactly as it was supplied.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a key was first used for, and the response that call produced.
#[derive(Debug, Clone)]
struct Record {
    initiator: String,
    request: SwapRequest,
    response: SwapResponse,
}

/// Key -> original initiation, held for the coordinator's lifetime.
///
/// The store never evicts on its own. That is deliberate for a process-scoped
/// guarantee, and it is also why keys are length-bounded. [`IdempotencyStore::forget`]
/// exists for the case where a caller has independently learned that the
/// original swap will never be used; it is not part of normal operation.
#[derive(Debug, Default)]
pub struct IdempotencyStore {
    records: HashMap<String, Record>,
}

impl IdempotencyStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of keys bound to an initiation.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether no key has been used yet.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Look up `key`.
    ///
    /// Returns `None` when the key is unused. When it is used, returns the
    /// recorded response if `initiator` and `request` match the original call,
    /// and [`AtomicSwapError::IdempotencyConflict`] otherwise. A mismatch is an
    /// error rather than a fresh initiation: reusing a key for a different
    /// intent is a caller bug, and quietly doing the second thing would defeat
    /// the guarantee for the first.
    pub fn lookup(
        &self,
        key: &IdempotencyKey,
        initiator: &str,
        request: &SwapRequest,
    ) -> Option<Result<SwapResponse>> {
        self.records.get(key.as_str()).map(|record| {
            if record.initiator == initiator && record.request == *request {
                Ok(record.response.clone())
            } else {
                Err(AtomicSwapError::IdempotencyConflict {
                    key: key.as_str().to_string(),
                })
            }
        })
    }

    /// Bind `key` to a successful initiation.
    ///
    /// The first binding wins: if the key is already present the existing
    /// record is left untouched, which keeps the store consistent even if a
    /// caller bypasses [`IdempotencyStore::lookup`].
    pub fn record(
        &mut self,
        key: &IdempotencyKey,
        initiator: String,
        request: SwapRequest,
        response: SwapResponse,
    ) {
        self.records
            .entry(key.as_str().to_string())
            .or_insert(Record {
                initiator,
                request,
                response,
            });
    }

    /// Remove a binding, returning whether it existed.
    pub fn forget(&mut self, key: &IdempotencyKey) -> bool {
        self.records.remove(key.as_str()).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::Asset;
    use std::collections::HashMap;

    fn request(amount: i128) -> SwapRequest {
        SwapRequest {
            participant: "participant".to_string(),
            initiator_asset: Asset::XLM,
            participant_asset: Asset::Custom("USDC".to_string()),
            initiator_amount: amount,
            participant_amount: 500,
            timeout_hours: 24,
            origin_chain: None,
            nonce: None,
            metadata: HashMap::new(),
        }
    }

    fn response(swap_id: &str) -> SwapResponse {
        SwapResponse {
            swap_id: swap_id.to_string(),
            hash_lock: "hash".to_string(),
            preimage: Some("preimage".to_string()),
            timeout_ledger: 100,
            contract_address: None,
        }
    }

    fn key(value: &str) -> IdempotencyKey {
        IdempotencyKey::new(value).expect("test key should be valid")
    }

    #[test]
    fn accepts_keys_at_and_below_the_length_bound() {
        let boundary = "k".repeat(MAX_IDEMPOTENCY_KEY_LEN);
        assert_eq!(
            IdempotencyKey::new(boundary.clone()).unwrap().as_str(),
            boundary
        );
        assert_eq!(IdempotencyKey::new("swap-1").unwrap().as_str(), "swap-1");
    }

    #[test]
    fn rejects_an_empty_key() {
        let error = IdempotencyKey::new("").expect_err("empty keys would collide");
        assert!(matches!(
            error,
            AtomicSwapError::InvalidIdempotencyKey { .. }
        ));
    }

    #[test]
    fn rejects_an_over_long_key() {
        let too_long = "k".repeat(MAX_IDEMPOTENCY_KEY_LEN + 1);
        let error = IdempotencyKey::new(too_long).expect_err("keys are length-bounded");
        assert!(matches!(
            error,
            AtomicSwapError::InvalidIdempotencyKey { .. }
        ));
    }

    #[test]
    fn rejects_control_characters() {
        for bad in ["swap\n1", "swap\t1", "swap\u{0}1"] {
            let error = IdempotencyKey::new(bad).expect_err("control characters are ambiguous");
            assert!(
                matches!(error, AtomicSwapError::InvalidIdempotencyKey { .. }),
                "expected a key validation error for {bad:?}"
            );
        }
    }

    #[test]
    fn keys_are_not_normalised() {
        // `Swap-1` is a different key from `swap-1`; treating them as equal
        // would let a case change replay a previous swap by accident.
        let lower = key("swap-1");
        let mixed = key("Swap-1");
        let store = IdempotencyStore::new();
        assert!(store.lookup(&lower, "initiator", &request(1_000)).is_none());
        assert!(store.lookup(&mixed, "initiator", &request(1_000)).is_none());
        assert_ne!(lower, mixed);
    }

    #[test]
    fn a_recorded_key_replays_the_original_response() {
        let mut store = IdempotencyStore::new();
        let key = key("swap-1");
        let original = request(1_000);
        store.record(
            &key,
            "initiator".to_string(),
            original.clone(),
            response("swap-a"),
        );

        let replayed = store
            .lookup(&key, "initiator", &original)
            .expect("the key is bound")
            .expect("an identical request replays");
        assert_eq!(replayed.swap_id, "swap-a");
        assert_eq!(replayed.preimage.as_deref(), Some("preimage"));
    }

    #[test]
    fn the_same_key_with_a_different_amount_conflicts() {
        let mut store = IdempotencyStore::new();
        let key = key("swap-1");
        store.record(
            &key,
            "initiator".to_string(),
            request(1_000),
            response("swap-a"),
        );

        let error = store
            .lookup(&key, "initiator", &request(2_000))
            .expect("the key is bound")
            .expect_err("a different intent must not replay the old swap");
        assert!(matches!(error, AtomicSwapError::IdempotencyConflict { .. }));
    }

    #[test]
    fn the_same_key_for_a_different_initiator_conflicts() {
        let mut store = IdempotencyStore::new();
        let key = key("swap-1");
        let original = request(1_000);
        store.record(
            &key,
            "initiator".to_string(),
            original.clone(),
            response("swap-a"),
        );

        // Otherwise anyone who guessed or observed a key could read the
        // preimage of someone else's swap.
        let error = store
            .lookup(&key, "someone-else", &original)
            .expect("the key is bound")
            .expect_err("keys are scoped to the initiator");
        assert!(matches!(error, AtomicSwapError::IdempotencyConflict { .. }));
    }

    #[test]
    fn the_first_binding_wins() {
        let mut store = IdempotencyStore::new();
        let key = key("swap-1");
        store.record(
            &key,
            "initiator".to_string(),
            request(1_000),
            response("first"),
        );
        store.record(
            &key,
            "initiator".to_string(),
            request(2_000),
            response("second"),
        );

        let replayed = store
            .lookup(&key, "initiator", &request(1_000))
            .unwrap()
            .unwrap();
        assert_eq!(replayed.swap_id, "first");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn forgetting_a_key_frees_it() {
        let mut store = IdempotencyStore::new();
        let key = key("swap-1");
        store.record(
            &key,
            "initiator".to_string(),
            request(1_000),
            response("swap-a"),
        );
        assert_eq!(store.len(), 1);

        assert!(store.forget(&key));
        assert!(store.is_empty());
        assert!(!store.forget(&key));
        assert!(store.lookup(&key, "initiator", &request(1_000)).is_none());
    }
}

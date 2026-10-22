//! Off-chain signal snapshot sync (issue #206).
//!
//! Governance discussion happens off-chain — a forum, a mailing list, a Signal
//! group export — but a vote has to name *something* both sides agree on. This
//! module is the mirror: it takes a feed of [`Signal`]s, folds it into a
//! deterministic [`SignalSnapshot`], and reports exactly what changed.
//!
//! The rules exist because a mirror is only useful if it fails loudly:
//!
//! * **Addressed by hash.** Each signal carries `body_sha256`, not the body. A
//!   vote can commit to `(id, hash)`, and the snapshot never becomes a copy of
//!   the forum with all its retention and moderation problems.
//! * **Deterministic.** The digest is computed over id-sorted, length-prefixed
//!   fields, so two mirrors that received the same signals in different orders
//!   produce the same digest — and one that received *different* content cannot
//!   produce the same digest by shifting bytes between fields.
//! * **No silent rollback.** A feed entry older than the stored one is refused
//!   rather than applied, and an empty feed is refused while the snapshot holds
//!   signals. A transient outage must not erase the mirror or rewind an edit.
//! * **All-or-nothing.** A sync either applies completely or leaves the snapshot
//!   byte-for-byte unchanged; there is no half-applied state for a retry to
//!   build on.
//!
//! `updated_at` is the feed's own ordering, not wall-clock time — the toolkit
//! does not trust the local clock to sequence a remote feed.

use crate::monitoring_dashboard::sha256_hex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Bumped when the on-disk shape of a snapshot changes incompatibly.
pub const SNAPSHOT_VERSION: u32 = 1;

/// Domain separator for the snapshot digest.
const DIGEST_DOMAIN: &[u8] = b"stellar-toolkit/signal-snapshot/v1";

/// One off-chain signal, reduced to what a snapshot needs to name it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    /// Stable feed id, e.g. `forum:proposal/42`.
    pub id: String,
    /// Author handle as the feed reports it.
    pub author: String,
    pub title: String,
    /// sha256 of the body, lowercase hex. The body itself is not mirrored.
    pub body_sha256: String,
    /// Feed-assigned revision time; only ever compared, never generated locally.
    pub updated_at: u64,
}

impl Signal {
    /// Build a signal from a body, hashing it so the body is never retained.
    pub fn new(
        id: impl Into<String>,
        author: impl Into<String>,
        title: impl Into<String>,
        body: &[u8],
        updated_at: u64,
    ) -> Self {
        Self {
            id: id.into(),
            author: author.into(),
            title: title.into(),
            body_sha256: sha256_hex(body),
            updated_at,
        }
    }

    fn validate(&self) -> Result<(), SyncError> {
        if self.id.trim().is_empty() {
            return Err(SyncError::InvalidSignal {
                id: self.id.clone(),
                reason: "id must not be empty".to_string(),
            });
        }
        if self.author.trim().is_empty() {
            return Err(SyncError::InvalidSignal {
                id: self.id.clone(),
                reason: "author must not be empty".to_string(),
            });
        }
        if self.title.trim().is_empty() {
            return Err(SyncError::InvalidSignal {
                id: self.id.clone(),
                reason: "title must not be empty".to_string(),
            });
        }
        if self.body_sha256.len() != 64
            || !self
                .body_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(SyncError::InvalidSignal {
                id: self.id.clone(),
                reason: "body_sha256 must be 64 lowercase hex characters".to_string(),
            });
        }
        Ok(())
    }
}

/// Why a sync was refused. Every variant leaves the snapshot untouched.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SyncError {
    #[error("signal {id} is invalid: {reason}")]
    InvalidSignal { id: String, reason: String },
    #[error("signal {0} appears more than once in the feed")]
    DuplicateSignal(String),
    #[error(
        "signal {id} is stale: feed says {incoming} but the snapshot is at {stored}; refusing to rewind"
    )]
    StaleSignal {
        id: String,
        stored: u64,
        incoming: u64,
    },
    #[error("signal {id} changed at unchanged timestamp {at}; the feed is ambiguous")]
    ConflictingUpdate { id: String, at: u64 },
    #[error(
        "the feed is empty but the snapshot holds {stored} signal(s); refusing to erase the mirror"
    )]
    EmptyFeed { stored: usize },
}

/// What a successful sync did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncReport {
    /// Ids present in the feed but not in the snapshot.
    pub added: Vec<String>,
    /// Ids whose content changed at a newer feed timestamp.
    pub updated: Vec<String>,
    /// Ids present in the snapshot but no longer in the feed.
    pub removed: Vec<String>,
    /// Ids whose content and timestamp both matched.
    pub unchanged: usize,
    /// Digest of the snapshot after the sync.
    pub digest: String,
}

impl SyncReport {
    /// True when the feed matched the snapshot exactly.
    pub fn is_noop(&self) -> bool {
        self.added.is_empty() && self.updated.is_empty() && self.removed.is_empty()
    }

    /// One-line summary for a deploy log.
    pub fn render(&self) -> String {
        format!(
            "signals: {} added, {} updated, {} removed, {} unchanged (digest {})",
            self.added.len(),
            self.updated.len(),
            self.removed.len(),
            self.unchanged,
            self.digest
        )
    }
}

/// A deterministic mirror of a signal feed.
///
/// Iteration order is `BTreeMap` order, so the digest and every report are
/// reproducible without sorting at each call site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalSnapshot {
    pub version: u32,
    signals: BTreeMap<String, Signal>,
}

impl Default for SignalSnapshot {
    fn default() -> Self {
        Self::empty()
    }
}

impl SignalSnapshot {
    pub fn empty() -> Self {
        Self {
            version: SNAPSHOT_VERSION,
            signals: BTreeMap::new(),
        }
    }

    /// Build a snapshot from a feed, rejecting duplicates and invalid entries.
    pub fn from_signals<I>(signals: I) -> Result<Self, SyncError>
    where
        I: IntoIterator<Item = Signal>,
    {
        let mut snapshot = Self::empty();
        let mut seen = BTreeMap::new();
        for signal in signals {
            signal.validate()?;
            if seen.insert(signal.id.clone(), ()).is_some() {
                return Err(SyncError::DuplicateSignal(signal.id));
            }
            snapshot.signals.insert(signal.id.clone(), signal);
        }
        Ok(snapshot)
    }

    pub fn len(&self) -> usize {
        self.signals.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signals.is_empty()
    }

    pub fn get(&self, id: &str) -> Option<&Signal> {
        self.signals.get(id)
    }

    /// Ids in deterministic (lexicographic) order.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.signals.keys().map(String::as_str)
    }

    /// Digest committing to every signal and its content.
    ///
    /// Length prefixes keep the encoding injective; the domain separator keeps
    /// it from colliding with any other sha256 this toolkit produces.
    pub fn digest(&self) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(DIGEST_DOMAIN);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&(self.signals.len() as u32).to_be_bytes());

        for signal in self.signals.values() {
            for field in [
                signal.id.as_bytes(),
                signal.author.as_bytes(),
                signal.title.as_bytes(),
                signal.body_sha256.as_bytes(),
            ] {
                bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
                bytes.extend_from_slice(field);
            }
            bytes.extend_from_slice(&signal.updated_at.to_be_bytes());
        }

        sha256_hex(&bytes)
    }

    /// Apply an authoritative feed read.
    ///
    /// On any error the snapshot is left exactly as it was: the new map is built
    /// first and only swapped in once every check has passed.
    pub fn sync<I>(&mut self, feed: I) -> Result<SyncReport, SyncError>
    where
        I: IntoIterator<Item = Signal>,
    {
        let mut incoming: BTreeMap<String, Signal> = BTreeMap::new();
        for signal in feed {
            signal.validate()?;
            let id = signal.id.clone();
            if incoming.insert(id.clone(), signal).is_some() {
                return Err(SyncError::DuplicateSignal(id));
            }
        }

        if incoming.is_empty() && !self.signals.is_empty() {
            return Err(SyncError::EmptyFeed {
                stored: self.signals.len(),
            });
        }

        let mut added = Vec::new();
        let mut updated = Vec::new();
        let mut unchanged = 0usize;

        for (id, signal) in &incoming {
            match self.signals.get(id) {
                None => added.push(id.clone()),
                Some(stored) => {
                    if signal.updated_at < stored.updated_at {
                        return Err(SyncError::StaleSignal {
                            id: id.clone(),
                            stored: stored.updated_at,
                            incoming: signal.updated_at,
                        });
                    }
                    if signal.updated_at == stored.updated_at {
                        if signal.body_sha256 != stored.body_sha256
                            || signal.author != stored.author
                            || signal.title != stored.title
                        {
                            return Err(SyncError::ConflictingUpdate {
                                id: id.clone(),
                                at: signal.updated_at,
                            });
                        }
                        unchanged += 1;
                    } else {
                        updated.push(id.clone());
                    }
                }
            }
        }

        let removed: Vec<String> = self
            .signals
            .keys()
            .filter(|id| !incoming.contains_key(*id))
            .cloned()
            .collect();

        self.signals = incoming;
        Ok(SyncReport {
            added,
            updated,
            removed,
            unchanged,
            digest: self.digest(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(id: &str, body: &[u8], updated_at: u64) -> Signal {
        Signal::new(id, "alice", format!("title for {id}"), body, updated_at)
    }

    fn snapshot() -> SignalSnapshot {
        SignalSnapshot::from_signals([
            signal("forum/1", b"first proposal", 100),
            signal("forum/2", b"second proposal", 200),
        ])
        .unwrap()
    }

    #[test]
    fn first_sync_adds_everything_and_matches_a_fresh_snapshot() {
        let feed = vec![signal("forum/2", b"two", 2), signal("forum/1", b"one", 1)];
        let mut snapshot = SignalSnapshot::empty();
        let report = snapshot.sync(feed.clone()).unwrap();

        assert_eq!(report.added, vec!["forum/1", "forum/2"]);
        assert!(report.updated.is_empty());
        assert!(report.removed.is_empty());
        assert_eq!(report.unchanged, 0);
        assert_eq!(
            report.digest,
            SignalSnapshot::from_signals(feed).unwrap().digest()
        );
    }

    #[test]
    fn syncing_the_same_feed_twice_is_a_noop() {
        let mut snapshot = SignalSnapshot::empty();
        let feed: Vec<Signal> = vec![signal("forum/1", b"one", 1), signal("forum/2", b"two", 2)];

        snapshot.sync(feed.clone()).unwrap();
        let digest_before = snapshot.digest();
        let report = snapshot.sync(feed).unwrap();

        assert!(report.is_noop());
        assert_eq!(report.unchanged, 2);
        assert_eq!(report.digest, digest_before);
        assert_eq!(snapshot.digest(), digest_before);
    }

    #[test]
    fn newer_revision_updates_and_disappearance_removes() {
        let mut snapshot = snapshot();

        let report = snapshot
            .sync([
                signal("forum/1", b"first proposal, amended", 300),
                // forum/2 is gone from the feed
            ])
            .unwrap();

        assert_eq!(report.updated, vec!["forum/1"]);
        assert_eq!(report.removed, vec!["forum/2"]);
        assert_eq!(report.unchanged, 0);
        assert_eq!(snapshot.len(), 1);
        assert_eq!(
            snapshot.get("forum/1").unwrap().body_sha256,
            sha256_hex(b"first proposal, amended")
        );
    }

    #[test]
    fn a_stale_feed_entry_is_refused_and_changes_nothing() {
        let mut snapshot = snapshot();
        let before = snapshot.clone();

        let error = snapshot
            .sync([signal("forum/1", b"older text", 99)])
            .unwrap_err();

        assert_eq!(
            error,
            SyncError::StaleSignal {
                id: "forum/1".to_string(),
                stored: 100,
                incoming: 99
            }
        );
        assert_eq!(snapshot, before);
    }

    #[test]
    fn an_ambiguous_edit_at_the_same_timestamp_is_refused() {
        let mut snapshot = snapshot();
        let before = snapshot.clone();

        let error = snapshot
            .sync([signal("forum/1", b"different text, same clock", 100)])
            .unwrap_err();

        assert_eq!(
            error,
            SyncError::ConflictingUpdate {
                id: "forum/1".to_string(),
                at: 100
            }
        );
        assert_eq!(snapshot, before);
    }

    #[test]
    fn duplicate_ids_in_one_feed_are_refused() {
        let error = SignalSnapshot::from_signals([
            signal("forum/1", b"one", 1),
            signal("forum/1", b"two", 2),
        ])
        .unwrap_err();

        assert_eq!(error, SyncError::DuplicateSignal("forum/1".to_string()));
    }

    #[test]
    fn invalid_signals_are_refused() {
        let mut empty_title = signal("forum/1", b"body", 1);
        empty_title.title = "  ".into();
        assert!(matches!(
            SignalSnapshot::from_signals([empty_title]),
            Err(SyncError::InvalidSignal { ref id, .. }) if id == "forum/1"
        ));

        let mut bad_hash = signal("forum/2", b"body", 1);
        bad_hash.body_sha256 = "not-a-hash".into();
        assert!(matches!(
            SignalSnapshot::from_signals([bad_hash]),
            Err(SyncError::InvalidSignal { ref id, .. }) if id == "forum/2"
        ));

        let mut uppercase = signal("forum/3", b"body", 1);
        uppercase.body_sha256 = sha256_hex(b"body").to_uppercase();
        assert!(SignalSnapshot::from_signals([uppercase]).is_err());
    }

    #[test]
    fn an_empty_feed_cannot_erase_a_populated_snapshot() {
        let mut snapshot = snapshot();
        let before = snapshot.digest();

        let error = snapshot.sync(Vec::new()).unwrap_err();
        assert_eq!(error, SyncError::EmptyFeed { stored: 2 });
        assert_eq!(snapshot.digest(), before);

        // An empty snapshot syncing an empty feed is a no-op, not an error.
        let mut empty = SignalSnapshot::empty();
        let report = empty.sync(Vec::new()).unwrap();
        assert!(report.is_noop());
    }

    #[test]
    fn the_digest_is_order_independent_and_content_sensitive() {
        let a = SignalSnapshot::from_signals([
            signal("forum/1", b"one", 1),
            signal("forum/2", b"two", 2),
        ])
        .unwrap();
        let b = SignalSnapshot::from_signals([
            signal("forum/2", b"two", 2),
            signal("forum/1", b"one", 1),
        ])
        .unwrap();
        assert_eq!(a.digest(), b.digest());

        let mut edited = a.clone();
        edited
            .sync([
                signal("forum/1", b"one!", 1 + 1),
                signal("forum/2", b"two", 2),
            ])
            .unwrap();
        assert_ne!(a.digest(), edited.digest());

        // Field boundaries are length-prefixed: moving a character between the
        // author and the title is a different snapshot, not the same preimage.
        let shifted_author = Signal::new("forum/9", "ab", "c", b"", 1);
        let shifted_title = Signal::new("forum/9", "a", "bc", b"", 1);
        assert_ne!(
            SignalSnapshot::from_signals([shifted_author])
                .unwrap()
                .digest(),
            SignalSnapshot::from_signals([shifted_title])
                .unwrap()
                .digest()
        );
    }

    #[test]
    fn a_snapshot_round_trips_through_json_without_losing_its_digest() {
        let snapshot = snapshot();
        let encoded = serde_json::to_string_pretty(&snapshot).unwrap();
        let decoded: SignalSnapshot = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded, snapshot);
        assert_eq!(decoded.digest(), snapshot.digest());
        assert_eq!(decoded.version, SNAPSHOT_VERSION);
    }

    #[test]
    fn the_body_is_hashed_not_stored() {
        let body = b"a proposal with a distinctive phrase";
        let signal = Signal::new("forum/1", "alice", "title", body, 1);
        let encoded = serde_json::to_string(&signal).unwrap();

        assert!(!encoded.contains("distinctive phrase"));
        assert!(encoded.contains(&sha256_hex(body)));
    }
}

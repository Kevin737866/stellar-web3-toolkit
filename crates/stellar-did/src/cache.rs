//! Bounded DID document cache with explicit freshness (issue #340).
//!
//! Resolving a `did:stellar` document from the network on every verification
//! adds latency and external dependency coupling, while an unbounded or
//! indefinitely stale cache can serve revoked keys or exhaust memory.
//!
//! This module provides:
//! - [`CacheConfig`]: explicit capacity (`max_entries > 0`) and TTL (`ttl > 0`).
//! - [`DidCache`]: a bounded LRU cache that tracks insertion timestamps and
//!   never silently substitutes defaults for invalid configuration or inputs.
//! - [`FreshnessPolicy`] & [`ResolvedDidDocument`]: explicit caller control
//!   over cache freshness (`PreferCache`, `MaxAge`, `BypassCache`, `CacheOnly`)
//!   and observable provenance (`CacheHit` vs `OriginFetch`, `age`,
//!   `remaining_ttl`).
//! - [`CachedDidResolver`]: integrates [`DidCache`] with a [`DidSource`]
//!   backend, ensuring failed fetches never leave partial cache updates.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::service::DidDocument;

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors returned by [`CacheConfig`], [`DidCache`], and [`CachedDidResolver`].
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CacheError {
    /// Cache capacity must be at least 1.
    #[error("cache max_entries must be greater than 0, got {max_entries}")]
    InvalidCapacity { max_entries: usize },

    /// Cache TTL must be strictly positive.
    #[error("cache ttl must be greater than zero")]
    InvalidTtl,

    /// The DID string is empty, contains whitespace, or lacks the `did:` prefix.
    #[error("invalid DID `{did}`: {reason}")]
    InvalidDid { did: String, reason: String },

    /// The resolved document's `id` does not match the requested DID.
    #[error("resolved document id `{actual}` does not match requested DID `{expected}`")]
    DocumentIdMismatch { expected: String, actual: String },

    /// No entry was found in the cache when [`FreshnessPolicy::CacheOnly`] was used.
    #[error("DID `{did}` is not present in cache")]
    CacheMiss { did: String },

    /// A cached entry exists but exceeded the allowed freshness bound.
    #[error("cached DID `{did}` is stale (age {age:?} exceeds max age {max_age:?})")]
    StaleEntry {
        did: String,
        age: Duration,
        max_age: Duration,
    },

    /// The underlying [`DidSource`] failed to resolve the DID document.
    #[error("failed to resolve DID `{did}` from source: {reason}")]
    SourceFailed { did: String, reason: String },
}

// ── Configuration & Freshness ────────────────────────────────────────────────

/// Configuration for [`DidCache`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheConfig {
    /// Maximum number of DID documents retained in the cache.
    pub max_entries: usize,
    /// Maximum time a cached document remains fresh after insertion.
    pub ttl: Duration,
}

impl CacheConfig {
    /// Construct a validated [`CacheConfig`].
    ///
    /// # Errors
    ///
    /// * [`CacheError::InvalidCapacity`] when `max_entries == 0`.
    /// * [`CacheError::InvalidTtl`] when `ttl.is_zero()`.
    pub fn new(max_entries: usize, ttl: Duration) -> Result<Self, CacheError> {
        if max_entries == 0 {
            return Err(CacheError::InvalidCapacity { max_entries });
        }
        if ttl.is_zero() {
            return Err(CacheError::InvalidTtl);
        }
        Ok(Self { max_entries, ttl })
    }
}

/// Explicit freshness policy for DID resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessPolicy {
    /// Return a cached document if present and within the cache's configured TTL;
    /// otherwise fetch from the source and update the cache.
    PreferCache,
    /// Return a cached document only if its age is at most the given duration
    /// (and within the cache's configured TTL); otherwise fetch from the source.
    MaxAge(Duration),
    /// Always fetch a fresh document from the source and update the cache.
    BypassCache,
    /// Resolve exclusively from the cache, failing with [`CacheError::CacheMiss`]
    /// or [`CacheError::StaleEntry`] if no fresh entry is available.
    CacheOnly,
}

/// Provenance of a resolved DID document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionSource {
    /// Served from the local [`DidCache`].
    CacheHit,
    /// Fetched from the upstream [`DidSource`].
    OriginFetch,
}

/// A resolved DID document paired with explicit freshness metadata.
#[derive(Debug, Clone)]
pub struct ResolvedDidDocument {
    /// The resolved DID document.
    pub document: DidDocument,
    /// Whether the document was served from cache or fetched from the origin.
    pub source: ResolutionSource,
    /// Elapsed time since the entry was cached (`Duration::ZERO` for origin fetches).
    pub age: Duration,
    /// Remaining time before the cached entry expires.
    pub remaining_ttl: Duration,
}

// ── DidSource ────────────────────────────────────────────────────────────────

/// Upstream source used by [`CachedDidResolver`] on cache misses or bypasses.
pub trait DidSource {
    /// Fetch the authoritative [`DidDocument`] for `did`.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError::SourceFailed`] (or another [`CacheError`]) if the
    /// DID cannot be resolved.
    fn fetch(&self, did: &str) -> Result<DidDocument, CacheError>;
}

// ── DidCache ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CacheEntry {
    document: DidDocument,
    inserted_at: Instant,
}

/// Bounded LRU cache for [`DidDocument`]s with explicit TTL freshness.
#[derive(Debug)]
pub struct DidCache {
    config: CacheConfig,
    entries: HashMap<String, CacheEntry>,
    /// LRU order: front is least-recently-used, back is most-recently-used.
    lru: VecDeque<String>,
}

impl DidCache {
    /// Create a new bounded [`DidCache`] with the given validated configuration.
    #[must_use]
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config,
            entries: HashMap::with_capacity(config.max_entries),
            lru: VecDeque::with_capacity(config.max_entries),
        }
    }

    /// Configured maximum number of entries.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.config.max_entries
    }

    /// Configured time-to-live for cached entries.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.config.ttl
    }

    /// Current number of stored entries (including any not yet purged).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when the cache contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Insert or refresh a [`DidDocument`] for `did` at timestamp `now`.
    ///
    /// If `did` is already present, its document and timestamp are updated and
    /// it is moved to the most-recently-used position. If the cache is at
    /// capacity, the least-recently-used entry is evicted first.
    ///
    /// # Errors
    ///
    /// * [`CacheError::InvalidDid`] if `did` is malformed.
    /// * [`CacheError::DocumentIdMismatch`] if `document.id != did`.
    pub fn insert_at(
        &mut self,
        did: impl Into<String>,
        document: DidDocument,
        now: Instant,
    ) -> Result<(), CacheError> {
        let did = did.into();
        validate_did(&did)?;
        if document.id != did {
            return Err(CacheError::DocumentIdMismatch {
                expected: did,
                actual: document.id,
            });
        }

        if self.entries.contains_key(&did) {
            self.touch_lru(&did);
            self.entries.insert(
                did,
                CacheEntry {
                    document,
                    inserted_at: now,
                },
            );
            return Ok(());
        }

        if self.entries.len() >= self.config.max_entries {
            if let Some(evicted_key) = self.lru.pop_front() {
                self.entries.remove(&evicted_key);
            }
        }

        self.lru.push_back(did.clone());
        self.entries.insert(
            did,
            CacheEntry {
                document,
                inserted_at: now,
            },
        );
        Ok(())
    }

    /// Insert or refresh a [`DidDocument`] using [`Instant::now()`].
    pub fn insert(
        &mut self,
        did: impl Into<String>,
        document: DidDocument,
    ) -> Result<(), CacheError> {
        self.insert_at(did, document, Instant::now())
    }

    /// Look up `did` at timestamp `now`, enforcing `max_age` (capped by the
    /// cache's configured TTL).
    ///
    /// Expired or over-age entries are evicted on lookup when they exceed the
    /// cache's own TTL, and [`CacheError::StaleEntry`] is returned.
    ///
    /// # Errors
    ///
    /// * [`CacheError::InvalidDid`] if `did` is malformed.
    /// * [`CacheError::CacheMiss`] if `did` is not in the cache.
    /// * [`CacheError::StaleEntry`] if the entry's age exceeds `effective_max_age`.
    pub fn get_fresh_at(
        &mut self,
        did: &str,
        max_age: Option<Duration>,
        now: Instant,
    ) -> Result<ResolvedDidDocument, CacheError> {
        validate_did(did)?;

        let Some(entry) = self.entries.get(did) else {
            return Err(CacheError::CacheMiss {
                did: did.to_string(),
            });
        };

        let age = now.saturating_duration_since(entry.inserted_at);
        let effective_limit = match max_age {
            Some(limit) => limit.min(self.config.ttl),
            None => self.config.ttl,
        };

        if age >= self.config.ttl {
            // Entry is past the cache's own TTL; evict it so it cannot linger.
            self.remove_entry(did);
            return Err(CacheError::StaleEntry {
                did: did.to_string(),
                age,
                max_age: effective_limit,
            });
        }

        if let Some(limit) = max_age {
            if age > limit || limit.is_zero() {
                return Err(CacheError::StaleEntry {
                    did: did.to_string(),
                    age,
                    max_age: limit,
                });
            }
        }

        let document = entry.document.clone();
        let remaining_ttl = self.config.ttl.saturating_sub(age);
        self.touch_lru(did);

        Ok(ResolvedDidDocument {
            document,
            source: ResolutionSource::CacheHit,
            age,
            remaining_ttl,
        })
    }

    /// Remove a specific DID from the cache, returning `true` if it was present.
    pub fn invalidate(&mut self, did: &str) -> bool {
        self.remove_entry(did)
    }

    /// Remove all entries from the cache.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.lru.clear();
    }

    /// Purge all entries whose age at `now` has reached or exceeded the cache TTL.
    pub fn purge_expired_at(&mut self, now: Instant) -> usize {
        let ttl = self.config.ttl;
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter_map(|(k, v)| {
                if now.saturating_duration_since(v.inserted_at) >= ttl {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();

        let count = expired.len();
        for key in expired {
            self.remove_entry(&key);
        }
        count
    }

    /// Purge all expired entries using [`Instant::now()`].
    pub fn purge_expired(&mut self) -> usize {
        self.purge_expired_at(Instant::now())
    }

    fn touch_lru(&mut self, did: &str) {
        if let Some(pos) = self.lru.iter().position(|k| k == did) {
            self.lru.remove(pos);
        }
        self.lru.push_back(did.to_string());
    }

    fn remove_entry(&mut self, did: &str) -> bool {
        if self.entries.remove(did).is_some() {
            if let Some(pos) = self.lru.iter().position(|k| k == did) {
                self.lru.remove(pos);
            }
            true
        } else {
            false
        }
    }
}

// ── CachedDidResolver ────────────────────────────────────────────────────────

/// Resolves DID documents using a bounded [`DidCache`] backed by a [`DidSource`].
#[derive(Debug)]
pub struct CachedDidResolver<S> {
    source: S,
    cache: DidCache,
}

impl<S: DidSource> CachedDidResolver<S> {
    /// Construct a new [`CachedDidResolver`] with the given `source` and `config`.
    #[must_use]
    pub fn new(source: S, config: CacheConfig) -> Self {
        Self {
            source,
            cache: DidCache::new(config),
        }
    }

    /// Resolve `did` according to `freshness` using [`Instant::now()`].
    ///
    /// # Errors
    ///
    /// Propagates [`CacheError`] on invalid DIDs, cache-only misses/staleness,
    /// or upstream [`DidSource`] failures.
    pub fn resolve(
        &mut self,
        did: &str,
        freshness: FreshnessPolicy,
    ) -> Result<ResolvedDidDocument, CacheError> {
        self.resolve_at(did, freshness, Instant::now())
    }

    /// Resolve `did` according to `freshness` at an explicit timestamp `now`.
    ///
    /// On upstream fetch failure, the cache is not updated with partial or
    /// invalid state.
    pub fn resolve_at(
        &mut self,
        did: &str,
        freshness: FreshnessPolicy,
        now: Instant,
    ) -> Result<ResolvedDidDocument, CacheError> {
        validate_did(did)?;

        match freshness {
            FreshnessPolicy::PreferCache => match self.cache.get_fresh_at(did, None, now) {
                Ok(hit) => Ok(hit),
                Err(CacheError::CacheMiss { .. } | CacheError::StaleEntry { .. }) => {
                    self.fetch_and_cache(did, now)
                }
                Err(e) => Err(e),
            },
            FreshnessPolicy::MaxAge(max_age) => {
                match self.cache.get_fresh_at(did, Some(max_age), now) {
                    Ok(hit) => Ok(hit),
                    Err(CacheError::CacheMiss { .. } | CacheError::StaleEntry { .. }) => {
                        self.fetch_and_cache(did, now)
                    }
                    Err(e) => Err(e),
                }
            }
            FreshnessPolicy::BypassCache => self.fetch_and_cache(did, now),
            FreshnessPolicy::CacheOnly => self.cache.get_fresh_at(did, None, now),
        }
    }

    /// Invalidate a cached DID document, returning `true` if one was removed.
    pub fn invalidate(&mut self, did: &str) -> bool {
        self.cache.invalidate(did)
    }

    /// Borrow the underlying [`DidCache`].
    #[must_use]
    pub fn cache(&self) -> &DidCache {
        &self.cache
    }

    /// Mutably borrow the underlying [`DidCache`].
    pub fn cache_mut(&mut self) -> &mut DidCache {
        &mut self.cache
    }

    fn fetch_and_cache(
        &mut self,
        did: &str,
        now: Instant,
    ) -> Result<ResolvedDidDocument, CacheError> {
        let document = self.source.fetch(did)?;
        self.cache.insert_at(did, document.clone(), now)?;
        Ok(ResolvedDidDocument {
            document,
            source: ResolutionSource::OriginFetch,
            age: Duration::ZERO,
            remaining_ttl: self.cache.ttl(),
        })
    }
}

fn validate_did(did: &str) -> Result<(), CacheError> {
    if did.is_empty() {
        return Err(CacheError::InvalidDid {
            did: did.to_string(),
            reason: "DID must not be empty".to_string(),
        });
    }
    if did.chars().any(char::is_whitespace) {
        return Err(CacheError::InvalidDid {
            did: did.to_string(),
            reason: "DID must not contain whitespace".to_string(),
        });
    }
    if !did.starts_with("did:") || did.len() <= 4 {
        return Err(CacheError::InvalidDid {
            did: did.to_string(),
            reason: "DID must start with `did:` followed by method-specific identifier".to_string(),
        });
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct StubSource {
        calls: Cell<usize>,
        fail: bool,
    }

    impl StubSource {
        fn new() -> Self {
            Self {
                calls: Cell::new(0),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                calls: Cell::new(0),
                fail: true,
            }
        }
    }

    impl DidSource for StubSource {
        fn fetch(&self, did: &str) -> Result<DidDocument, CacheError> {
            self.calls.set(self.calls.get() + 1);
            if self.fail {
                return Err(CacheError::SourceFailed {
                    did: did.to_string(),
                    reason: "network timeout".to_string(),
                });
            }
            Ok(DidDocument::new(did))
        }
    }

    #[test]
    fn config_rejects_zero_capacity_and_zero_ttl() {
        assert!(matches!(
            CacheConfig::new(0, Duration::from_secs(60)),
            Err(CacheError::InvalidCapacity { max_entries: 0 })
        ));
        assert!(matches!(
            CacheConfig::new(10, Duration::ZERO),
            Err(CacheError::InvalidTtl)
        ));
    }

    #[test]
    fn cache_evicts_least_recently_used_at_capacity() {
        let cfg = CacheConfig::new(2, Duration::from_secs(60)).unwrap();
        let mut cache = DidCache::new(cfg);
        let t0 = Instant::now();

        let d1 = "did:stellar:testnet:G1";
        let d2 = "did:stellar:testnet:G2";
        let d3 = "did:stellar:testnet:G3";

        cache.insert_at(d1, DidDocument::new(d1), t0).unwrap();
        cache.insert_at(d2, DidDocument::new(d2), t0).unwrap();

        // Access d1 so d2 becomes the least recently used entry.
        assert!(cache.get_fresh_at(d1, None, t0).is_ok());

        // Inserting d3 must evict d2, keeping d1 and d3.
        cache.insert_at(d3, DidDocument::new(d3), t0).unwrap();
        assert_eq!(cache.len(), 2);
        assert!(cache.get_fresh_at(d1, None, t0).is_ok());
        assert!(cache.get_fresh_at(d3, None, t0).is_ok());
        assert!(matches!(
            cache.get_fresh_at(d2, None, t0),
            Err(CacheError::CacheMiss { .. })
        ));
    }

    #[test]
    fn cache_rejects_mismatched_document_id_and_invalid_did() {
        let cfg = CacheConfig::new(2, Duration::from_secs(60)).unwrap();
        let mut cache = DidCache::new(cfg);
        let t0 = Instant::now();

        assert!(matches!(
            cache.insert_at("not-a-did", DidDocument::new("not-a-did"), t0),
            Err(CacheError::InvalidDid { .. })
        ));
        assert!(matches!(
            cache.insert_at("did:stellar:testnet:G1", DidDocument::new("did:stellar:testnet:G2"), t0),
            Err(CacheError::DocumentIdMismatch { .. })
        ));
        assert!(cache.is_empty());
    }

    #[test]
    fn resolver_serves_cache_hit_within_ttl_and_refetches_when_expired() {
        let cfg = CacheConfig::new(4, Duration::from_secs(30)).unwrap();
        let mut resolver = CachedDidResolver::new(StubSource::new(), cfg);
        let t0 = Instant::now();
        let did = "did:stellar:testnet:GABC";

        let first = resolver
            .resolve_at(did, FreshnessPolicy::PreferCache, t0)
            .unwrap();
        assert_eq!(first.source, ResolutionSource::OriginFetch);
        assert_eq!(first.age, Duration::ZERO);
        assert_eq!(resolver.source.calls.get(), 1);

        // 10s later: still fresh.
        let second = resolver
            .resolve_at(did, FreshnessPolicy::PreferCache, t0 + Duration::from_secs(10))
            .unwrap();
        assert_eq!(second.source, ResolutionSource::CacheHit);
        assert_eq!(second.age, Duration::from_secs(10));
        assert_eq!(second.remaining_ttl, Duration::from_secs(20));
        assert_eq!(resolver.source.calls.get(), 1);

        // 30s later: expired -> refetched.
        let third = resolver
            .resolve_at(did, FreshnessPolicy::PreferCache, t0 + Duration::from_secs(30))
            .unwrap();
        assert_eq!(third.source, ResolutionSource::OriginFetch);
        assert_eq!(resolver.source.calls.get(), 2);
    }

    #[test]
    fn resolver_respects_max_age_bypass_and_cache_only() {
        let cfg = CacheConfig::new(4, Duration::from_secs(60)).unwrap();
        let mut resolver = CachedDidResolver::new(StubSource::new(), cfg);
        let t0 = Instant::now();
        let did = "did:stellar:testnet:GABC";

        // CacheOnly on cold cache returns CacheMiss without calling source.
        assert!(matches!(
            resolver.resolve_at(did, FreshnessPolicy::CacheOnly, t0),
            Err(CacheError::CacheMiss { .. })
        ));
        assert_eq!(resolver.source.calls.get(), 0);

        // Populate cache.
        resolver
            .resolve_at(did, FreshnessPolicy::PreferCache, t0)
            .unwrap();
        assert_eq!(resolver.source.calls.get(), 1);

        // MaxAge(5s) at t0 + 10s forces origin refetch even though TTL is 60s.
        let res = resolver
            .resolve_at(
                did,
                FreshnessPolicy::MaxAge(Duration::from_secs(5)),
                t0 + Duration::from_secs(10),
            )
            .unwrap();
        assert_eq!(res.source, ResolutionSource::OriginFetch);
        assert_eq!(resolver.source.calls.get(), 2);

        // BypassCache always fetches from origin.
        let bypass = resolver
            .resolve_at(did, FreshnessPolicy::BypassCache, t0 + Duration::from_secs(11))
            .unwrap();
        assert_eq!(bypass.source, ResolutionSource::OriginFetch);
        assert_eq!(resolver.source.calls.get(), 3);
    }

    #[test]
    fn failed_source_fetch_does_not_populate_cache() {
        let cfg = CacheConfig::new(2, Duration::from_secs(60)).unwrap();
        let mut resolver = CachedDidResolver::new(StubSource::failing(), cfg);
        let t0 = Instant::now();

        let err = resolver
            .resolve_at("did:stellar:testnet:GFAIL", FreshnessPolicy::PreferCache, t0)
            .unwrap_err();
        assert!(matches!(err, CacheError::SourceFailed { .. }));
        assert!(resolver.cache().is_empty());
    }
}

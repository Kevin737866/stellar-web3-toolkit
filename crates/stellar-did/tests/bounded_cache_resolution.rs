//! Integration tests for bounded DID document caching with explicit freshness
//! (issue #340).

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use stellar_did::{
    CacheConfig, CacheError, CachedDidResolver, DidDocument, DidSource, FreshnessPolicy,
    ResolutionSource, Service, ServiceEndpoint,
};

struct InMemoryRegistry {
    docs: RefCell<HashMap<String, DidDocument>>,
}

impl InMemoryRegistry {
    fn new() -> Self {
        Self {
            docs: RefCell::new(HashMap::new()),
        }
    }

    fn publish(&self, doc: DidDocument) {
        self.docs.borrow_mut().insert(doc.id.clone(), doc);
    }
}

impl DidSource for InMemoryRegistry {
    fn fetch(&self, did: &str) -> Result<DidDocument, CacheError> {
        self.docs
            .borrow()
            .get(did)
            .cloned()
            .ok_or_else(|| CacheError::SourceFailed {
                did: did.to_string(),
                reason: "DID not registered".to_string(),
            })
    }
}

#[test]
fn bounded_cache_resolution_workflow_with_explicit_freshness() {
    let registry = InMemoryRegistry::new();
    let d1 = "did:stellar:testnet:G1";
    let d2 = "did:stellar:testnet:G2";
    let d3 = "did:stellar:testnet:G3";

    let mut doc1 = DidDocument::new(d1);
    doc1.add_service(
        Service::new(
            format!("{d1}#hub"),
            "IdentityHub",
            ServiceEndpoint::uri("https://hub1.example.com").unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    registry.publish(doc1);
    registry.publish(DidDocument::new(d2));
    registry.publish(DidDocument::new(d3));

    let config = CacheConfig::new(2, Duration::from_secs(60)).unwrap();
    let mut resolver = CachedDidResolver::new(registry, config);
    let t0 = Instant::now();

    // Cold fetch for d1 and d2.
    let r1 = resolver
        .resolve_at(d1, FreshnessPolicy::PreferCache, t0)
        .unwrap();
    assert_eq!(r1.source, ResolutionSource::OriginFetch);
    assert_eq!(r1.document.service.len(), 1);

    let r2 = resolver
        .resolve_at(d2, FreshnessPolicy::PreferCache, t0 + Duration::from_secs(1))
        .unwrap();
    assert_eq!(r2.source, ResolutionSource::OriginFetch);

    // Cache hit for d1 keeps d1 as most-recently-used.
    let r1_hit = resolver
        .resolve_at(d1, FreshnessPolicy::CacheOnly, t0 + Duration::from_secs(5))
        .unwrap();
    assert_eq!(r1_hit.source, ResolutionSource::CacheHit);
    assert_eq!(r1_hit.age, Duration::from_secs(5));
    assert_eq!(r1_hit.remaining_ttl, Duration::from_secs(55));

    // Resolving d3 evicts d2 (LRU) because capacity is 2.
    let r3 = resolver
        .resolve_at(d3, FreshnessPolicy::PreferCache, t0 + Duration::from_secs(6))
        .unwrap();
    assert_eq!(r3.source, ResolutionSource::OriginFetch);
    assert_eq!(resolver.cache().len(), 2);

    // d2 is no longer in cache under CacheOnly.
    assert!(matches!(
        resolver.resolve_at(d2, FreshnessPolicy::CacheOnly, t0 + Duration::from_secs(7)),
        Err(CacheError::CacheMiss { .. })
    ));

    // d1 is still cached, but MaxAge(1s) at t0 + 10s forces a fresh origin fetch.
    let r1_refreshed = resolver
        .resolve_at(
            d1,
            FreshnessPolicy::MaxAge(Duration::from_secs(1)),
            t0 + Duration::from_secs(10),
        )
        .unwrap();
    assert_eq!(r1_refreshed.source, ResolutionSource::OriginFetch);
    assert_eq!(r1_refreshed.age, Duration::ZERO);
}

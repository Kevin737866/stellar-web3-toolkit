//! Cross-chain nonce replay protection (issue #238).
//!
//! A cross-chain transfer is authorised by a signature over one intent: *this
//! sender*, *this nonce*, *on this chain*, for *this payload*. Once a second
//! chain exists, a signature alone stops being enough, because the same bytes
//! can be presented twice in two different ways:
//!
//! * **Same chain, twice.** The relayer (or anyone who saw the envelope)
//!   submits the transfer again after it settled. The signature still verifies;
//!   without a nonce the recipient is paid twice.
//! * **A different chain.** A transfer signed for `testnet` is presented to
//!   `mainnet` — or to a fork of the same chain. If the digest does not name the
//!   chain, the verifier on the other side accepts it, and value moves that the
//!   signer never authorised.
//!
//! The two failure modes need different fixes, and this module implements both:
//!
//! 1. [`ReplayGuard::verify_and_record`] recomputes the intent digest with the
//!    *local* chain id and rejects a digest that was produced for another chain
//!    ([`ReplayError::ChainMismatch`]). The chain id is length-prefixed inside
//!    the digest, so `("ab", "c")` and `("a", "bc")` cannot collide.
//! 2. It then consumes the `(chain, sender, nonce)` triple exactly once. A
//!    second presentation of the same nonce is [`ReplayError::Replayed`].
//!
//! Tracking the nonce per domain is what makes the first fix usable: an
//! operator's nonce sequence on `mainnet` and on `testnet` are independent, so
//! a shared counter would reject legitimate traffic.
//!
//! # Replay windows, not a growing set
//!
//! A naive "seen nonces" set grows forever. Instead each domain keeps the
//! highest nonce it has accepted plus a 64-bit sliding window of the ones just
//! below it ([`NonceWindow`]). Nonces that fall out of the window are
//! [`ReplayError::StaleNonce`]: they cannot be distinguished from a replay, so
//! they are refused rather than accepted. A nonce far ahead of the window is
//! refused too, so one forged envelope cannot wedge the domain by pushing the
//! window past every nonce the sender will legitimately use next.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;

/// Width of the accepted nonce window, in nonces below the highest accepted.
pub const NONCE_WINDOW: u64 = 64;

/// How far ahead of the highest accepted nonce a nonce may be. A sender that
/// opens its sequence at `1_000_000` is a configuration mistake, and accepting
/// it would make every earlier nonce stale.
pub const DEFAULT_MAX_AHEAD: u64 = 4_096;

/// Upper bound on the domains tracked at once, so a peer cannot make the
/// registry grow without limit by inventing senders.
pub const DEFAULT_MAX_DOMAINS: usize = 4_096;

/// Domain separator mixed into every intent digest. Changing it invalidates
/// every previously signed intent, which is the point: it versions the scheme.
const DIGEST_DOMAIN: &[u8] = b"stellar-web3-toolkit/cross-chain-intent/v1";

/// Why a cross-chain intent was refused.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// The nonce was already consumed for this domain.
    #[error("nonce {nonce} was already consumed for {domain}")]
    Replayed { domain: String, nonce: u64 },

    /// The nonce is older than the window this domain still remembers.
    #[error("nonce {nonce} is older than the window starting at {lowest} for {domain}")]
    StaleNonce {
        domain: String,
        nonce: u64,
        lowest: u64,
    },

    /// The nonce is implausibly far ahead of the last accepted one.
    #[error("nonce {nonce} is more than {max_ahead} ahead of {highest} for {domain}")]
    TooFarAhead {
        domain: String,
        nonce: u64,
        highest: u64,
        max_ahead: u64,
    },

    /// The digest was produced for a different chain than the one verifying.
    #[error("intent was signed for chain \"{signed_for}\" but presented to \"{local}\"")]
    ChainMismatch { signed_for: String, local: String },

    /// A cross-chain intent was presented without one half of its identity.
    #[error("cross-chain intent is missing its {missing}")]
    IncompleteIntent { missing: &'static str },

    /// The registry is at capacity and refusing to track a new domain.
    #[error("nonce registry is already tracking its maximum of {max_domains} domains")]
    RegistryFull { max_domains: usize },
}

/// The `(chain, sender)` pair a nonce sequence belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReplayDomain {
    pub chain: String,
    pub sender: String,
}

impl ReplayDomain {
    pub fn new(chain: impl Into<String>, sender: impl Into<String>) -> Self {
        Self {
            chain: chain.into(),
            sender: sender.into(),
        }
    }

    /// Human-readable `chain:sender` label used in errors and reports.
    pub fn label(&self) -> String {
        format!("{}:{}", self.chain, self.sender)
    }
}

/// One cross-chain transfer, as the signer described it.
///
/// `payload` is the digest of whatever is being moved (amount, recipient,
/// asset, contract id — the caller decides); it is bound into the digest so a
/// signature cannot be repointed at different value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossChainIntent {
    /// Chain the intent was signed for. A verifier only accepts its own.
    pub chain: String,
    pub sender: String,
    pub nonce: u64,
    pub payload: [u8; 32],
}

impl CrossChainIntent {
    pub fn new(chain: impl Into<String>, sender: impl Into<String>, nonce: u64) -> Self {
        Self {
            chain: chain.into(),
            sender: sender.into(),
            nonce,
            payload: [0u8; 32],
        }
    }

    /// Bind the value being moved into the intent.
    pub fn with_payload(mut self, payload: [u8; 32]) -> Self {
        self.payload = payload;
        self
    }

    /// The digest the signer approved. Every field that a replayer could change
    /// is inside it, including the chain id.
    pub fn digest(&self) -> [u8; 32] {
        domain_separated_digest(&self.chain, &self.sender, self.nonce, &self.payload)
    }

    pub fn domain(&self) -> ReplayDomain {
        ReplayDomain::new(self.chain.clone(), self.sender.clone())
    }
}

/// `H(domain ‖ |chain| ‖ chain ‖ |sender| ‖ sender ‖ nonce ‖ payload)`.
///
/// The lengths are hashed in so that no split of the same bytes can produce the
/// digest of a different `(chain, sender)` pair: without them
/// `("stellar", "mainnet")` and `("stellar-mainnet", "")` would collide.
pub fn domain_separated_digest(
    chain: &str,
    sender: &str,
    nonce: u64,
    payload: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update((chain.len() as u64).to_be_bytes());
    hasher.update(chain.as_bytes());
    hasher.update((sender.len() as u64).to_be_bytes());
    hasher.update(sender.as_bytes());
    hasher.update(nonce.to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

/// Constant-time equality for two digests, so verification does not leak how
/// many leading bytes of a guess were right.
pub fn digests_match(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// What a domain remembers about the nonces it has accepted: the highest one,
/// and a bit per nonce in the [`NONCE_WINDOW`] below it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceWindow {
    highest: u64,
    /// Bit `i` is set when `highest - i` has been consumed.
    seen: u64,
    initialised: bool,
}

impl Default for NonceWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceWindow {
    pub fn new() -> Self {
        Self {
            highest: 0,
            seen: 0,
            initialised: false,
        }
    }

    /// Highest nonce this window has accepted, if any.
    pub fn highest(&self) -> Option<u64> {
        self.initialised.then_some(self.highest)
    }

    /// Oldest nonce this window still recognises.
    pub fn lowest(&self) -> Option<u64> {
        self.highest()
            .map(|highest| highest.saturating_sub(NONCE_WINDOW - 1))
    }

    pub fn is_consumed(&self, nonce: u64) -> bool {
        match self.highest() {
            Some(highest) if nonce > highest => false,
            Some(highest) => {
                let offset = highest - nonce;
                offset < NONCE_WINDOW && self.seen & (1u64 << offset) != 0
            }
            None => false,
        }
    }

    /// Consume `nonce`, returning `Err` with the reason when it is not usable.
    fn accept(&mut self, nonce: u64, max_ahead: u64) -> std::result::Result<(), WindowRejection> {
        self.check(nonce, max_ahead)?;

        match self.highest() {
            None => {
                self.highest = nonce;
                self.seen = 1;
                self.initialised = true;
            }
            Some(highest) => {
                if nonce > highest {
                    let advance = nonce - highest;
                    self.seen = if advance >= NONCE_WINDOW {
                        0
                    } else {
                        self.seen << advance
                    };
                    self.seen |= 1; // bit 0 == the new highest nonce
                    self.highest = nonce;
                } else {
                    let offset = highest - nonce;
                    self.seen |= 1u64 << offset;
                }
            }
        }

        Ok(())
    }

    /// Decide whether `nonce` is usable without consuming it.
    ///
    /// The single source of truth for [`NonceWindow::accept`], so a caller can
    /// preflight an intent (see [`ReplayGuard::preflight`]) and get exactly the
    /// answer the consuming call will give.
    fn check(&self, nonce: u64, max_ahead: u64) -> std::result::Result<(), WindowRejection> {
        match self.highest() {
            None => Ok(()),
            Some(highest) => {
                if nonce > highest {
                    let advance = nonce - highest;
                    if advance > max_ahead {
                        return Err(WindowRejection::TooFarAhead { highest, max_ahead });
                    }
                    return Ok(());
                }

                let offset = highest - nonce;
                if offset >= NONCE_WINDOW {
                    return Err(WindowRejection::Stale {
                        lowest: highest - (NONCE_WINDOW - 1),
                    });
                }
                if self.seen & (1u64 << offset) != 0 {
                    return Err(WindowRejection::Duplicate);
                }
                Ok(())
            }
        }
    }
}

/// Local view of why [`NonceWindow::accept`] said no; the guard adds the domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowRejection {
    Duplicate,
    Stale { lowest: u64 },
    TooFarAhead { highest: u64, max_ahead: u64 },
}

/// Counters an operator can scrape: how much traffic the guard accepted and how
/// much it refused, split by reason.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayStats {
    pub accepted: u64,
    pub replayed: u64,
    pub stale: u64,
    pub too_far_ahead: u64,
    pub chain_mismatch: u64,
    pub domains_tracked: usize,
}

/// Consumes `(chain, sender, nonce)` once, for every chain the toolkit talks to.
#[derive(Debug, Clone)]
pub struct ReplayGuard {
    domains: HashMap<ReplayDomain, NonceWindow>,
    max_ahead: u64,
    max_domains: usize,
    stats: ReplayStats,
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_AHEAD, DEFAULT_MAX_DOMAINS)
    }

    pub fn with_limits(max_ahead: u64, max_domains: usize) -> Self {
        Self {
            domains: HashMap::new(),
            max_ahead,
            max_domains,
            stats: ReplayStats::default(),
        }
    }

    /// Verify a signed intent against `local_chain`, then consume its nonce.
    ///
    /// The digest is recomputed here rather than trusted from the envelope: an
    /// envelope signed for one chain cannot be re-presented to another, because
    /// the chain id is an input to the digest and the verifier substitutes its
    /// own.
    pub fn verify_and_record(
        &mut self,
        local_chain: &str,
        intent: &CrossChainIntent,
        digest: &[u8; 32],
    ) -> std::result::Result<(), ReplayError> {
        if intent.chain != local_chain {
            self.stats.chain_mismatch += 1;
            return Err(ReplayError::ChainMismatch {
                signed_for: intent.chain.clone(),
                local: local_chain.to_string(),
            });
        }
        let expected =
            domain_separated_digest(local_chain, &intent.sender, intent.nonce, &intent.payload);
        if !digests_match(&expected, digest) {
            self.stats.chain_mismatch += 1;
            return Err(ReplayError::ChainMismatch {
                signed_for: intent.chain.clone(),
                local: local_chain.to_string(),
            });
        }
        self.check_and_record(local_chain, &intent.sender, intent.nonce)
    }

    /// Consume one nonce for `(chain, sender)`.
    pub fn check_and_record(
        &mut self,
        chain: &str,
        sender: &str,
        nonce: u64,
    ) -> std::result::Result<(), ReplayError> {
        let domain = ReplayDomain::new(chain, sender);

        if !self.domains.contains_key(&domain) && self.domains.len() >= self.max_domains {
            return Err(ReplayError::RegistryFull {
                max_domains: self.max_domains,
            });
        }

        let window = self.domains.entry(domain).or_default();
        match window.accept(nonce, self.max_ahead) {
            Ok(()) => {
                self.stats.accepted += 1;
                Ok(())
            }
            Err(rejection) => Err(self.record_rejection(chain, sender, nonce, rejection)),
        }
    }

    /// Report whether `nonce` could be consumed for `(chain, sender)`, without
    /// consuming it.
    ///
    /// Used to reject a replayed intent *before* any side effect, so a caller
    /// that fails later does not leave the nonce burned. The answer is
    /// identical to what [`ReplayGuard::check_and_record`] would return at the
    /// same moment, because both go through [`NonceWindow::check`].
    ///
    /// A refusal here is still counted in [`ReplayGuard::stats`]: a replayed
    /// intent is exactly the signal an operator needs to see, and it must not
    /// disappear just because the caller preflighted.
    pub fn preflight(
        &mut self,
        chain: &str,
        sender: &str,
        nonce: u64,
    ) -> std::result::Result<(), ReplayError> {
        let domain = ReplayDomain::new(chain, sender);

        if !self.domains.contains_key(&domain) && self.domains.len() >= self.max_domains {
            return Err(ReplayError::RegistryFull {
                max_domains: self.max_domains,
            });
        }

        let Some(window) = self.domains.get(&domain) else {
            return Ok(());
        };

        match window.check(nonce, self.max_ahead) {
            Ok(()) => Ok(()),
            Err(rejection) => Err(self.record_rejection(chain, sender, nonce, rejection)),
        }
    }

    /// Give a consumed nonce back, so a later attempt can use it again.
    ///
    /// Only valid for a nonce that was consumed by an initiation which then
    /// failed before producing a swap. If `nonce` was the highest in the
    /// window, the window is rewound to the highest nonce still marked
    /// consumed; otherwise just its bit is cleared. Returns whether anything
    /// changed.
    ///
    /// A nonce that fell out of the window cannot be released: it is
    /// indistinguishable from one consumed long ago, and treating it as free
    /// would reopen the replay hole the window exists to close.
    pub fn release(&mut self, chain: &str, sender: &str, nonce: u64) -> bool {
        let domain = ReplayDomain::new(chain, sender);
        let Some(window) = self.domains.get_mut(&domain) else {
            return false;
        };

        match window.highest() {
            Some(highest) if nonce > highest => false,
            Some(highest) => {
                let offset = highest - nonce;
                if offset >= NONCE_WINDOW {
                    return false;
                }
                let bit = 1u64 << offset;
                if window.seen & bit == 0 {
                    return false;
                }
                window.seen &= !bit;

                if nonce == highest {
                    // Rewind to the highest nonce still marked consumed.
                    if let Some(offset) =
                        (0..NONCE_WINDOW).find(|offset| window.seen & (1u64 << offset) != 0)
                    {
                        window.highest = highest - offset;
                    } else {
                        window.highest = 0;
                        window.seen = 0;
                        window.initialised = false;
                    }
                }
                true
            }
            None => false,
        }
    }

    /// Count a rejection and map it to the public error.
    fn record_rejection(
        &mut self,
        chain: &str,
        sender: &str,
        nonce: u64,
        rejection: WindowRejection,
    ) -> ReplayError {
        match rejection {
            WindowRejection::Duplicate => self.stats.replayed += 1,
            WindowRejection::Stale { .. } => self.stats.stale += 1,
            WindowRejection::TooFarAhead { .. } => self.stats.too_far_ahead += 1,
        }
        self.stats.domains_tracked = self.domains.len();
        let label = ReplayDomain::new(chain, sender).label();
        match rejection {
            WindowRejection::Duplicate => ReplayError::Replayed {
                domain: label,
                nonce,
            },
            WindowRejection::Stale { lowest } => ReplayError::StaleNonce {
                domain: label,
                nonce,
                lowest,
            },
            WindowRejection::TooFarAhead { highest, max_ahead } => ReplayError::TooFarAhead {
                domain: label,
                nonce,
                highest,
                max_ahead,
            },
        }
    }

    /// True when the nonce has already been consumed for this domain.
    pub fn is_recorded(&self, chain: &str, sender: &str, nonce: u64) -> bool {
        self.domains
            .get(&ReplayDomain::new(chain, sender))
            .is_some_and(|window| window.is_consumed(nonce))
    }

    /// Highest nonce accepted for a domain, if the domain is known.
    pub fn highest_nonce(&self, chain: &str, sender: &str) -> Option<u64> {
        self.domains
            .get(&ReplayDomain::new(chain, sender))
            .and_then(NonceWindow::highest)
    }

    /// Stop tracking a domain. Only safe once nothing will ever replay an
    /// unconsumed nonce of it — i.e. after that sequence is closed on every
    /// chain it can reach.
    pub fn forget(&mut self, chain: &str, sender: &str) -> bool {
        let dropped = self
            .domains
            .remove(&ReplayDomain::new(chain, sender))
            .is_some();
        self.stats.domains_tracked = self.domains.len();
        dropped
    }

    /// Drop every domain whose highest accepted nonce is below `watermark`, for
    /// callers whose sequences are known to be closed past that point.
    pub fn forget_domains_below(&mut self, watermark: u64) -> usize {
        let before = self.domains.len();
        self.domains.retain(|_, window| match window.highest() {
            Some(highest) => highest >= watermark,
            None => true,
        });
        let removed = before - self.domains.len();
        self.stats.domains_tracked = self.domains.len();
        removed
    }

    pub fn stats(&self) -> ReplayStats {
        let mut stats = self.stats.clone();
        stats.domains_tracked = self.domains.len();
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(chain: &str, sender: &str, nonce: u64) -> CrossChainIntent {
        CrossChainIntent::new(chain, sender, nonce).with_payload([7u8; 32])
    }

    #[test]
    fn accepts_a_monotonic_sequence() {
        let mut guard = ReplayGuard::new();
        for nonce in 0..256 {
            guard
                .check_and_record("testnet", "GALICE", nonce)
                .unwrap_or_else(|e| panic!("nonce {nonce} rejected: {e}"));
        }
        assert_eq!(guard.highest_nonce("testnet", "GALICE"), Some(255));
        assert_eq!(guard.stats().accepted, 256);
        assert_eq!(guard.stats().replayed, 0);
    }

    #[test]
    fn rejects_a_replayed_nonce() {
        let mut guard = ReplayGuard::new();
        guard.check_and_record("testnet", "GALICE", 1).unwrap();
        let error = guard
            .check_and_record("testnet", "GALICE", 1)
            .expect_err("second use of the same nonce must be refused");
        assert!(matches!(error, ReplayError::Replayed { .. }));
        assert_eq!(guard.stats().replayed, 1);
        assert!(guard.is_recorded("testnet", "GALICE", 1));
    }

    #[test]
    fn out_of_order_nonces_inside_the_window_are_accepted_once_each() {
        let mut guard = ReplayGuard::new();
        // A relayer may deliver these out of order; all of them are legitimate.
        for nonce in [5, 3, 9, 4, 6, 7, 8] {
            guard.check_and_record("testnet", "GALICE", nonce).unwrap();
        }
        for nonce in [3, 4, 5, 6, 7, 8, 9] {
            assert!(guard.is_recorded("testnet", "GALICE", nonce));
            assert!(matches!(
                guard.check_and_record("testnet", "GALICE", nonce),
                Err(ReplayError::Replayed { .. })
            ));
        }
    }

    #[test]
    fn nonces_below_the_window_are_stale_not_accepted() {
        let mut guard = ReplayGuard::new();
        guard.check_and_record("testnet", "GALICE", 1_000).unwrap();
        let error = guard
            .check_and_record("testnet", "GALICE", 1_000 - NONCE_WINDOW - 1)
            .expect_err("a nonce that fell out of the window cannot be trusted");
        match error {
            ReplayError::StaleNonce { lowest, nonce, .. } => {
                assert_eq!(lowest, 1_000 - (NONCE_WINDOW - 1));
                assert_eq!(nonce, 1_000 - NONCE_WINDOW - 1);
            }
            other => panic!("expected StaleNonce, got {other}"),
        }
        assert_eq!(guard.stats().stale, 1);
    }

    #[test]
    fn the_window_edge_is_still_recognised() {
        let mut guard = ReplayGuard::new();
        guard.check_and_record("testnet", "GALICE", 100).unwrap();
        // Exactly NONCE_WINDOW - 1 below the highest: the oldest nonce the
        // window still covers.
        guard
            .check_and_record("testnet", "GALICE", 100 - 63)
            .unwrap();
        assert!(matches!(
            guard.check_and_record("testnet", "GALICE", 100 - 63),
            Err(ReplayError::Replayed { .. })
        ));
    }

    #[test]
    fn a_nonce_far_ahead_is_refused_and_does_not_move_the_window() {
        let mut guard = ReplayGuard::with_limits(16, 4);
        guard.check_and_record("testnet", "GALICE", 5).unwrap();
        let error = guard
            .check_and_record("testnet", "GALICE", 5 + 17)
            .expect_err("a nonce beyond the lookahead bound must be refused");
        assert!(matches!(error, ReplayError::TooFarAhead { .. }));
        // The forged envelope must not have wedged the domain.
        assert_eq!(guard.highest_nonce("testnet", "GALICE"), Some(5));
        guard.check_and_record("testnet", "GALICE", 6).unwrap();
        assert_eq!(guard.stats().too_far_ahead, 1);
    }

    #[test]
    fn domains_do_not_share_a_nonce_sequence() {
        let mut guard = ReplayGuard::new();
        guard.check_and_record("testnet", "GALICE", 1).unwrap();
        // The same nonce for another sender, and for another chain, is a
        // different sequence and must be accepted.
        guard.check_and_record("testnet", "GBOB", 1).unwrap();
        guard.check_and_record("mainnet", "GALICE", 1).unwrap();
        assert_eq!(guard.stats().accepted, 3);
        assert_eq!(guard.stats().domains_tracked, 3);
    }

    #[test]
    fn a_digest_is_bound_to_its_chain() {
        let signed_for_testnet = intent("testnet", "GALICE", 1);
        let digest = signed_for_testnet.digest();

        let mut guard = ReplayGuard::new();
        // Presenting the testnet envelope to mainnet is refused before the
        // nonce is touched.
        let error = guard
            .verify_and_record("mainnet", &signed_for_testnet, &digest)
            .expect_err("a testnet intent must not be accepted on mainnet");
        assert!(matches!(error, ReplayError::ChainMismatch { .. }));
        assert!(!guard.is_recorded("mainnet", "GALICE", 1));

        // The same envelope on the chain it names is accepted exactly once.
        guard
            .verify_and_record("testnet", &signed_for_testnet, &digest)
            .unwrap();
        assert!(matches!(
            guard.verify_and_record("testnet", &signed_for_testnet, &digest),
            Err(ReplayError::Replayed { .. })
        ));
        assert_eq!(guard.stats().chain_mismatch, 1);
    }

    #[test]
    fn a_digest_is_bound_to_sender_nonce_and_payload() {
        let base = intent("testnet", "GALICE", 1).digest();
        assert_ne!(base, intent("testnet", "GBOB", 1).digest());
        assert_ne!(base, intent("testnet", "GALICE", 2).digest());
        assert_ne!(
            base,
            CrossChainIntent::new("testnet", "GALICE", 1)
                .with_payload([8u8; 32])
                .digest()
        );
        assert_eq!(base, intent("testnet", "GALICE", 1).digest());
    }

    #[test]
    fn digest_domain_separation_is_unambiguous() {
        // "ab" + "c" must not hash the same as "a" + "bc": that is exactly the
        // ambiguity a naive concatenation would have.
        assert_ne!(
            domain_separated_digest("ab", "c", 1, &[0u8; 32]),
            domain_separated_digest("a", "bc", 1, &[0u8; 32])
        );
    }

    #[test]
    fn a_forged_digest_is_refused_without_consuming_the_nonce() {
        let real = intent("testnet", "GALICE", 4);
        let mut forged = real.digest();
        forged[0] ^= 0x01;
        let mut guard = ReplayGuard::new();
        assert!(matches!(
            guard.verify_and_record("testnet", &real, &forged),
            Err(ReplayError::ChainMismatch { .. })
        ));
        assert!(!guard.is_recorded("testnet", "GALICE", 4));
        guard
            .verify_and_record("testnet", &real, &real.digest())
            .unwrap();
    }

    #[test]
    fn registry_refuses_new_domains_at_capacity_but_keeps_serving_known_ones() {
        let mut guard = ReplayGuard::with_limits(DEFAULT_MAX_AHEAD, 2);
        guard.check_and_record("testnet", "GALICE", 1).unwrap();
        guard.check_and_record("testnet", "GBOB", 1).unwrap();
        assert!(matches!(
            guard.check_and_record("testnet", "GCAROL", 1),
            Err(ReplayError::RegistryFull { max_domains: 2 })
        ));
        // Known domains keep working, and a replay is still a replay.
        guard.check_and_record("testnet", "GALICE", 2).unwrap();
        assert!(matches!(
            guard.check_and_record("testnet", "GALICE", 1),
            Err(ReplayError::Replayed { .. })
        ));
    }

    #[test]
    fn forgetting_a_domain_lets_its_sequence_start_again() {
        let mut guard = ReplayGuard::new();
        guard.check_and_record("testnet", "GALICE", 1).unwrap();
        assert!(guard.forget("testnet", "GALICE"));
        assert!(!guard.is_recorded("testnet", "GALICE", 1));
        guard.check_and_record("testnet", "GALICE", 1).unwrap();
        assert!(!guard.forget("testnet", "GALICE-NOT-TRACKED"));
    }

    #[test]
    fn forgetting_below_a_watermark_prunes_closed_sequences() {
        let mut guard = ReplayGuard::new();
        guard.check_and_record("testnet", "GALICE", 10).unwrap();
        guard.check_and_record("testnet", "GBOB", 500).unwrap();
        assert_eq!(guard.forget_domains_below(100), 1);
        assert_eq!(guard.stats().domains_tracked, 1);
        assert_eq!(guard.highest_nonce("testnet", "GBOB"), Some(500));
    }

    #[test]
    fn preflight_agrees_with_consume_without_consuming() {
        let mut guard = ReplayGuard::new();
        guard.check_and_record("testnet", "GALICE", 5).unwrap();

        // A fresh nonce preflights cleanly and stays unconsumed.
        assert!(guard.preflight("testnet", "GALICE", 6).is_ok());
        assert!(!guard.is_recorded("testnet", "GALICE", 6));
        assert_eq!(guard.stats().accepted, 1, "a preflight consumes nothing");
        assert_eq!(guard.stats().replayed, 0);

        // A used nonce is reported exactly as the consuming call would report it.
        let preflight_error = guard
            .preflight("testnet", "GALICE", 5)
            .expect_err("a used nonce cannot be preflighted");
        assert!(matches!(preflight_error, ReplayError::Replayed { .. }));
        assert_eq!(
            guard.stats().replayed,
            1,
            "a refused preflight is still counted, so an operator sees the replay"
        );

        // The consuming call reports the same error for the same reason.
        let consume_error = guard
            .check_and_record("testnet", "GALICE", 5)
            .expect_err("a used nonce cannot be consumed");
        assert_eq!(preflight_error, consume_error);
    }

    #[test]
    fn releasing_the_highest_nonce_rewinds_the_window() {
        let mut guard = ReplayGuard::new();
        guard.check_and_record("testnet", "GALICE", 10).unwrap();
        guard.check_and_record("testnet", "GALICE", 11).unwrap();
        assert_eq!(guard.highest_nonce("testnet", "GALICE"), Some(11));

        // Releasing the highest rewinds to the newest still-consumed nonce.
        assert!(guard.release("testnet", "GALICE", 11));
        assert!(!guard.is_recorded("testnet", "GALICE", 11));
        assert_eq!(guard.highest_nonce("testnet", "GALICE"), Some(10));

        // ...and it can be consumed again.
        guard.check_and_record("testnet", "GALICE", 11).unwrap();
        assert!(guard.is_recorded("testnet", "GALICE", 11));
    }

    #[test]
    fn releasing_a_middle_nonce_only_clears_its_bit() {
        let mut guard = ReplayGuard::new();
        for nonce in [10, 11, 12] {
            guard.check_and_record("testnet", "GALICE", nonce).unwrap();
        }

        assert!(guard.release("testnet", "GALICE", 11));
        assert!(!guard.is_recorded("testnet", "GALICE", 11));
        assert_eq!(
            guard.highest_nonce("testnet", "GALICE"),
            Some(12),
            "releasing a middle nonce does not move the top"
        );
        assert!(guard.is_recorded("testnet", "GALICE", 10));
        assert!(guard.is_recorded("testnet", "GALICE", 12));
    }

    #[test]
    fn releasing_the_only_nonce_clears_the_domain() {
        let mut guard = ReplayGuard::new();
        guard.check_and_record("testnet", "GALICE", 4).unwrap();
        assert!(guard.release("testnet", "GALICE", 4));
        assert_eq!(guard.highest_nonce("testnet", "GALICE"), None);
        // The domain starts from scratch, so a much lower nonce is accepted.
        guard.check_and_record("testnet", "GALICE", 1).unwrap();
        assert_eq!(guard.highest_nonce("testnet", "GALICE"), Some(1));
    }

    #[test]
    fn releasing_an_unconsumed_or_unknown_nonce_changes_nothing() {
        let mut guard = ReplayGuard::new();
        guard.check_and_record("testnet", "GALICE", 5).unwrap();

        assert!(!guard.release("testnet", "GALICE", 9), "never consumed");
        assert!(
            !guard.release("testnet", "GALICE", 1),
            "inside the window but unset"
        );
        assert!(!guard.release("mainnet", "GALICE", 5), "unknown domain");
        assert!(guard.is_recorded("testnet", "GALICE", 5));
    }

    #[test]
    fn a_nonce_outside_the_window_cannot_be_released() {
        let mut guard = ReplayGuard::new();
        for nonce in 0..(NONCE_WINDOW + 5) {
            guard
                .check_and_record("testnet", "GALICE", nonce)
                .unwrap_or_else(|e| panic!("nonce {nonce} rejected: {e}"));
        }
        // Nonce 0 fell out of the window; treating it as free would reopen the
        // replay hole the window exists to close.
        assert!(!guard.release("testnet", "GALICE", 0));
        assert_eq!(
            guard.highest_nonce("testnet", "GALICE"),
            Some(NONCE_WINDOW + 4)
        );
    }

    #[test]
    fn stats_report_the_engagement_and_the_domain_count() {
        let mut guard = ReplayGuard::new();
        guard.check_and_record("testnet", "GALICE", 1).unwrap();
        let _ = guard.check_and_record("testnet", "GALICE", 1);
        let stats = guard.stats();
        assert_eq!(stats.accepted, 1);
        assert_eq!(stats.replayed, 1);
        assert_eq!(stats.domains_tracked, 1);
        // A fresh guard starts at zero on every counter.
        let fresh = ReplayGuard::new().stats();
        assert_eq!(fresh.accepted, 0);
        assert_eq!(fresh.domains_tracked, 0);
    }
}

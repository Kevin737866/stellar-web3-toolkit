#![no_std]
//! Reusable Soroban storage TTL (time-to-live) auto-extension.
//!
//! Soroban storage entries do not live forever. Persistent and temporary entries
//! expire once their remaining lifespan runs out, and instance storage is tied to
//! the lifetime of the contract instance itself. When an entry is archived it can
//! only be recovered through a paid restore transaction, which is both expensive
//! and a poor user experience.
//!
//! The mitigation is to periodically extend the TTL of any entry that is still in
//! active use. This module centralises that logic so every contract in the toolkit
//! applies the same policy instead of re-deriving magic numbers at each call site.
//!
//! # How it works
//!
//! Every helper here delegates to Soroban's `extend_ttl`, which takes a
//! **threshold** and an **extend-to** value:
//!
//! * if the entry's remaining TTL is **greater than** the threshold, nothing
//!   happens (so the cheap path stays cheap);
//! * if it is **at or below** the threshold, the TTL is pushed out to
//!   `extend_to` ledgers.
//!
//! That makes the correct placement obvious: call these helpers on the paths that
//! prove an entry is still in use — typically every state-mutating call, plus the
//! read paths a user depends on. Doing so keeps hot state alive without paying rent
//! on entries nobody touches.
//!
//! # Example
//!
//! ```ignore
//! use soroban_sdk::Env;
//! use soroban_ttl::{extend_instance, TtlPolicy};
//!
//! pub fn record_deposit(env: &Env) {
//!     // ... write state ...
//!     extend_instance(env, TtlPolicy::BALANCE);
//! }
//! ```
//!
//! The `BALANCE` preset intentionally mirrors the `BALANCE_TTL_THRESHOLD` /
//! `BALANCE_TTL_BUMP` pair documented in
//! `docs/SOROBAN_STORAGE_BEST_PRACTICES.md`, so the code and the guide stay in
//! agreement.

use soroban_sdk::{Env, IntoVal, Val};

/// Number of ledgers closed per hour on Stellar public networks (~5s per ledger).
pub const LEDGERS_PER_HOUR: u32 = 720;

/// Number of ledgers closed per day on Stellar public networks.
pub const LEDGERS_PER_DAY: u32 = LEDGERS_PER_HOUR * 24;

/// A `(threshold, extend_to)` pair describing when an entry's TTL should be pushed
/// out, and how far.
///
/// Both values are denominated in ledgers. Use [`TtlPolicy::hours`] to build one
/// from wall-clock estimates, or the associated constants for the policies already
/// agreed on across the toolkit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TtlPolicy {
    /// If the remaining TTL is at or below this many ledgers, extend the entry.
    pub threshold: u32,
    /// The number of ledgers the entry's TTL is extended to when triggered.
    pub extend_to: u32,
}

impl TtlPolicy {
    /// Build a policy directly from ledger counts.
    pub const fn new(threshold: u32, extend_to: u32) -> Self {
        Self {
            threshold,
            extend_to,
        }
    }

    /// Build a policy from wall-clock estimates expressed in hours.
    ///
    /// Rounding happens once, here, so that policies stay easy to reason about in
    /// review rather than being littered with unexplained ledger counts.
    pub const fn hours(threshold_hours: u32, extend_to_hours: u32) -> Self {
        Self {
            threshold: threshold_hours.saturating_mul(LEDGERS_PER_HOUR),
            extend_to: extend_to_hours.saturating_mul(LEDGERS_PER_HOUR),
        }
    }

    /// Build a policy from wall-clock estimates expressed in days.
    pub const fn days(threshold_days: u32, extend_to_days: u32) -> Self {
        Self {
            threshold: threshold_days.saturating_mul(LEDGERS_PER_DAY),
            extend_to: extend_to_days.saturating_mul(LEDGERS_PER_DAY),
        }
    }

    /// Policy for short-lived scratch state that only matters within a transaction
    /// or two (nonces, replay guards, in-flight routing state).
    pub const TRANSIENT: Self = Self::hours(6, 24);

    /// Policy for user balances and allowances.
    ///
    /// Matches `BALANCE_TTL_THRESHOLD` / `BALANCE_TTL_BUMP` from
    /// `docs/SOROBAN_STORAGE_BEST_PRACTICES.md`.
    pub const BALANCE: Self = Self::new(2_000, 100_000);

    /// Policy for state that must outlive long periods of inactivity, such as an
    /// atomic swap that a counterparty may only claim well after it was opened.
    pub const LONG_LIVED: Self = Self::days(3, 180);
}

/// Extend the TTL of the contract's **instance** storage (and, with it, the
/// contract instance/code entry).
///
/// Instance storage is the storage tier used by most contracts in this toolkit,
/// so this is the helper to reach for unless an entry is deliberately kept in
/// persistent or temporary storage.
pub fn extend_instance(env: &Env, policy: TtlPolicy) {
    env.storage()
        .instance()
        .extend_ttl(policy.threshold, policy.extend_to);
}

/// Extend the TTL of a single **persistent** storage entry.
pub fn extend_persistent<K>(env: &Env, key: &K, policy: TtlPolicy)
where
    K: IntoVal<Env, Val>,
{
    env.storage()
        .persistent()
        .extend_ttl(key, policy.threshold, policy.extend_to);
}

/// Extend the TTL of a single **temporary** storage entry.
pub fn extend_temporary<K>(env: &Env, key: &K, policy: TtlPolicy)
where
    K: IntoVal<Env, Val>,
{
    env.storage()
        .temporary()
        .extend_ttl(key, policy.threshold, policy.extend_to);
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::storage::{Instance as _, Persistent as _, Temporary as _};
    use soroban_sdk::testutils::Ledger as _;
    use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

    /// Threshold/extend-to pair used across the behavioural tests.
    ///
    /// The threshold is deliberately set above the test ledger's default
    /// `min_persistent_entry_ttl` (4096) so that a freshly written entry is
    /// *already* due for extension and the bump is observable.
    const TEST_THRESHOLD: u32 = 10_000;
    const TEST_EXTEND_TO: u32 = 100_000;

    /// `extend_ttl` reports the ledger at which the entry dies, so the value read
    /// back can be one ledger below the requested figure.
    fn at_least_extend_to(ttl: u32, extend_to: u32) -> bool {
        ttl >= extend_to.saturating_sub(1)
    }

    #[contracttype]
    #[derive(Clone)]
    pub enum ProbeKey {
        Persistent(u32),
        Temporary(u32),
    }

    /// Minimal contract that exposes each helper so the behaviour can be observed
    /// from outside the contract boundary.
    #[contract]
    pub struct TtlProbe;

    #[contractimpl]
    impl TtlProbe {
        pub fn init(env: Env) {
            env.storage().instance().set(&0u32, &1u32);
        }

        pub fn touch_instance(env: Env, threshold: u32, extend_to: u32) {
            extend_instance(&env, TtlPolicy::new(threshold, extend_to));
        }

        pub fn touch_persistent(env: Env, id: u32, threshold: u32, extend_to: u32) {
            let key = ProbeKey::Persistent(id);
            env.storage().persistent().set(&key, &id);
            extend_persistent(&env, &key, TtlPolicy::new(threshold, extend_to));
        }

        pub fn touch_temporary(env: Env, id: u32, threshold: u32, extend_to: u32) {
            let key = ProbeKey::Temporary(id);
            env.storage().temporary().set(&key, &id);
            extend_temporary(&env, &key, TtlPolicy::new(threshold, extend_to));
        }
    }

    fn setup() -> (Env, Address) {
        let env = Env::default();
        let id = env.register_contract(None, TtlProbe);
        TtlProbeClient::new(&env, &id).init();
        (env, id)
    }

    /// Remaining instance TTL, read from inside the contract's own frame.
    fn instance_ttl(env: &Env, id: &Address) -> u32 {
        env.as_contract(id, || env.storage().instance().get_ttl())
    }

    fn persistent_ttl(env: &Env, id: &Address, key: &ProbeKey) -> u32 {
        env.as_contract(id, || env.storage().persistent().get_ttl(key))
    }

    fn temporary_ttl(env: &Env, id: &Address, key: &ProbeKey) -> u32 {
        env.as_contract(id, || env.storage().temporary().get_ttl(key))
    }

    fn advance(env: &Env, ledgers: u32) {
        env.ledger().with_mut(|li| {
            li.sequence_number = li.sequence_number.saturating_add(ledgers);
        });
    }

    #[test]
    fn ledger_constants_match_stellar_network_cadence() {
        assert_eq!(LEDGERS_PER_HOUR, 720);
        assert_eq!(LEDGERS_PER_DAY, 17_280);
    }

    #[test]
    fn policies_derive_from_hours_and_days() {
        let p = TtlPolicy::hours(2, 24);
        assert_eq!(p.threshold, 1_440);
        assert_eq!(p.extend_to, 17_280);

        let d = TtlPolicy::days(1, 2);
        assert_eq!(d.threshold, 17_280);
        assert_eq!(d.extend_to, 34_560);
    }

    #[test]
    fn documented_presets_match_the_storage_guide() {
        // Guards against the code drifting away from
        // docs/SOROBAN_STORAGE_BEST_PRACTICES.md.
        assert_eq!(TtlPolicy::BALANCE.threshold, 2_000);
        assert_eq!(TtlPolicy::BALANCE.extend_to, 100_000);
    }

    #[test]
    fn every_preset_extends_further_than_its_threshold() {
        for policy in [
            TtlPolicy::TRANSIENT,
            TtlPolicy::BALANCE,
            TtlPolicy::LONG_LIVED,
        ] {
            assert!(
                policy.extend_to > policy.threshold,
                "policy {policy:?} would never extend anything"
            );
        }
    }

    #[test]
    fn instance_ttl_is_extended_when_below_threshold() {
        let (env, id) = setup();
        let before = instance_ttl(&env, &id);

        TtlProbeClient::new(&env, &id).touch_instance(&TEST_THRESHOLD, &TEST_EXTEND_TO);

        let after = instance_ttl(&env, &id);
        assert!(
            at_least_extend_to(after, TEST_EXTEND_TO),
            "expected instance ttl near {TEST_EXTEND_TO}, got {after}"
        );
        assert!(
            after > before,
            "instance ttl should have grown: {before} -> {after}"
        );
    }

    #[test]
    fn extension_is_a_no_op_while_ttl_is_above_the_threshold() {
        let (env, id) = setup();
        let client = TtlProbeClient::new(&env, &id);

        client.touch_instance(&TEST_THRESHOLD, &TEST_EXTEND_TO);
        let after_first = instance_ttl(&env, &id);

        // One ledger later the entry still comfortably outlives the threshold, so
        // the second call must not move the TTL and must not cost any rent.
        advance(&env, 1);
        client.touch_instance(&TEST_THRESHOLD, &TEST_EXTEND_TO);

        assert_eq!(
            after_first - 1,
            instance_ttl(&env, &id),
            "ttl should be untouched while remaining lifespan exceeds the threshold"
        );
    }

    #[test]
    fn extension_resumes_once_ttl_drops_to_the_threshold() {
        let (env, id) = setup();
        let client = TtlProbeClient::new(&env, &id);
        client.touch_instance(&TEST_THRESHOLD, &TEST_EXTEND_TO);

        // Age the entry down to exactly the threshold, which is the boundary at
        // which `extend_ttl` starts paying rent again.
        let target = TEST_THRESHOLD;
        let full = instance_ttl(&env, &id);
        advance(&env, full - target);
        assert_eq!(target, instance_ttl(&env, &id));

        client.touch_instance(&TEST_THRESHOLD, &TEST_EXTEND_TO);

        let after = instance_ttl(&env, &id);
        assert!(
            at_least_extend_to(after, TEST_EXTEND_TO),
            "entry should have been pushed back out, got {after}"
        );
    }

    #[test]
    fn a_fresh_entry_is_left_alone_by_a_policy_with_a_low_threshold() {
        // The documented BALANCE threshold (2000) sits below the network's default
        // entry TTL, so brand-new entries are intentionally not bumped: the rent is
        // not yet worth paying. This is the behaviour that keeps the cheap path cheap.
        let (env, id) = setup();
        let before = instance_ttl(&env, &id);

        TtlProbeClient::new(&env, &id)
            .touch_instance(&TtlPolicy::BALANCE.threshold, &TtlPolicy::BALANCE.extend_to);

        assert_eq!(
            before,
            instance_ttl(&env, &id),
            "a fresh entry above the threshold must not be extended"
        );
    }

    #[test]
    fn persistent_entry_ttl_is_extended() {
        let (env, id) = setup();
        TtlProbeClient::new(&env, &id).touch_persistent(&7, &TEST_THRESHOLD, &TEST_EXTEND_TO);

        let ttl = persistent_ttl(&env, &id, &ProbeKey::Persistent(7));
        assert!(
            at_least_extend_to(ttl, TEST_EXTEND_TO),
            "persistent ttl near {TEST_EXTEND_TO} expected, got {ttl}"
        );
    }

    #[test]
    fn temporary_entry_ttl_is_extended() {
        let (env, id) = setup();
        TtlProbeClient::new(&env, &id).touch_temporary(&9, &TEST_THRESHOLD, &TEST_EXTEND_TO);

        let ttl = temporary_ttl(&env, &id, &ProbeKey::Temporary(9));
        assert!(
            at_least_extend_to(ttl, TEST_EXTEND_TO),
            "temporary ttl near {TEST_EXTEND_TO} expected, got {ttl}"
        );
    }
}

//! Bridge pause timelock (issue #239).
//!
//! A bridge needs a way to stop outflows *now* when something is draining it,
//! and it also needs that stop to be impossible to use quietly. Those two goals
//! pull in opposite directions, and this contract keeps both by separating the
//! two halves of a pause:
//!
//! * **Asking** is cheap, public and logged. Any guardian can
//!   [`request_pause`](BridgePauseGuard::request_pause) at any time, and the
//!   request is an on-chain event carrying its reason and the ledger it becomes
//!   effective on. A second guardian asking again does not extend the countdown,
//!   so a request cannot be held open indefinitely and a guardian cannot reset
//!   the clock to stall a rival's request.
//! * **Landing** is timelocked. [`activate_pause`](BridgePauseGuard::activate_pause)
//!   is permissionless but refuses to do anything before
//!   `requested_ledger + pause_delay`, so a pause is always announced for
//!   `pause_delay` ledgers before it takes effect. Anyone watching the chain
//!   sees it coming.
//!
//! Resuming is timelocked for the same reason in the other direction: a
//! compromised guardian key must not be able to lift a pause and drain in the
//! same ledger. [`request_unpause`](BridgePauseGuard::request_unpause) is the
//! admin's, waits `unpause_delay`, and the delay is never allowed to be shorter
//! than `pause_delay` — otherwise a pause would be easier to announce than to
//! keep.
//!
//! # What the contract guarantees
//!
//! * A pause can never take effect in the ledger it is requested in
//!   (`pause_delay >= MIN_PAUSE_DELAY`), and the admin can
//!   [`cancel_pending`](BridgePauseGuard::cancel_pending) a request that has not
//!   landed yet.
//! * While `paused` is true, [`assert_unpaused`](BridgePauseGuard::assert_unpaused)
//!   aborts, which is the gate any bridge operation calls before moving value.
//! * Unpausing cannot be requested by a guardian, and cannot land before
//!   `unpause_delay` ledgers have passed.
//! * At least one guardian always exists, so a bridge can never be left with no
//!   one able to raise a pause.
//! * The reason string is emitted in the event and never stored: a free-text
//!   field in instance storage would let any guardian grow the contract's state
//!   without bound.

#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, String, Vec};

/// Shortest pause that is still a timelock: a pause must be announced for at
/// least one ledger before it can land, so it can never be silent.
pub const MIN_PAUSE_DELAY: u32 = 1;

/// Longest pause or unpause delay the contract accepts: 17_280 ledgers is about
/// a day at five-second ledgers. Past that the timelock stops being an emergency
/// tool and starts being a way to freeze the bridge.
pub const MAX_PAUSE_DELAY: u32 = 17_280;

/// Most guardians a bridge may have. Each one is a pause authority, so the set
/// stays small enough to name.
pub const MAX_GUARDIANS: u32 = 10;

/// Instance entries are bumped once their remaining TTL drops below the
/// threshold, so a long-pending change is never archived out from under the
/// bridge.
const TTL_THRESHOLD: u32 = 100_000;
const TTL_BUMP: u32 = 200_000;

/// Who the bridge trusts and how long its two timelocks are.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub admin: Address,
    /// Ledgers between requesting a pause and it becoming effective.
    pub pause_delay: u32,
    /// Ledgers between requesting an unpause and it becoming effective. Never
    /// shorter than `pause_delay`.
    pub unpause_delay: u32,
    /// True while the bridge must refuse value-moving operations.
    pub paused: bool,
}

/// Which way the bridge is moving.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Change {
    Pause,
    Unpause,
}

/// A change that has been requested but cannot land yet.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pending {
    pub change: Change,
    /// Who asked. A guardian for a pause, the admin for an unpause.
    pub requested_by: Address,
    pub requested_ledger: u32,
    /// `requested_ledger + delay` for the change's direction.
    pub effective_ledger: u32,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Config,
    Guardians,
    Pending,
}

#[contract]
pub struct BridgePauseGuard;

#[contractimpl]
impl BridgePauseGuard {
    /// Install the admin, the initial guardian set and both delays.
    ///
    /// `pause_delay` and `unpause_delay` must both be within
    /// `[MIN_PAUSE_DELAY, MAX_PAUSE_DELAY]`, and `unpause_delay` must be at
    /// least `pause_delay`: a bridge that resumes faster than it pauses is a
    /// bridge whose pause is decoration.
    pub fn initialize(
        env: Env,
        admin: Address,
        guardians: Vec<Address>,
        pause_delay: u32,
        unpause_delay: u32,
    ) {
        admin.require_auth();
        assert!(
            !env.storage().instance().has(&DataKey::Config),
            "contract already initialized"
        );
        assert!(!guardians.is_empty(), "at least one guardian is required");
        assert!(
            guardians.len() <= MAX_GUARDIANS,
            "too many guardians for the set limit"
        );
        assert!(
            (MIN_PAUSE_DELAY..=MAX_PAUSE_DELAY).contains(&pause_delay),
            "pause delay is out of range"
        );
        assert!(
            (pause_delay..=MAX_PAUSE_DELAY).contains(&unpause_delay),
            "unpause delay must be at least the pause delay and within range"
        );

        // A duplicated guardian would let the same key count twice and would
        // make `remove_guardian` ambiguous.
        let mut seen = Vec::new(&env);
        for guardian in guardians.iter() {
            assert!(!seen.contains(&guardian), "duplicate guardian");
            seen.push_back(guardian);
        }

        let config = Config {
            admin,
            pause_delay,
            unpause_delay,
            paused: false,
        };
        write_config(&env, &config);
        env.storage()
            .instance()
            .set(&DataKey::Guardians, &guardians);
        env.storage().instance().remove(&DataKey::Pending);

        env.events()
            .publish((symbol_short!("init"),), (pause_delay, unpause_delay));
    }

    // ---------------------------------------------------------------- queries

    pub fn config(env: Env) -> Config {
        read_config(&env)
    }

    pub fn admin(env: Env) -> Address {
        read_config(&env).admin
    }

    pub fn guardians(env: Env) -> Vec<Address> {
        read_guardians(&env)
    }

    pub fn is_guardian(env: Env, who: Address) -> bool {
        read_guardians(&env).contains(&who)
    }

    pub fn is_paused(env: Env) -> bool {
        read_config(&env).paused
    }

    pub fn pause_delay(env: Env) -> u32 {
        read_config(&env).pause_delay
    }

    pub fn unpause_delay(env: Env) -> u32 {
        read_config(&env).unpause_delay
    }

    /// The change waiting on its timelock, if any.
    pub fn pending_change(env: Env) -> Option<Pending> {
        env.storage().instance().get(&DataKey::Pending)
    }

    /// The gate a bridge operation calls before moving value.
    ///
    /// Aborting here is the whole point of the contract: a bridged transfer that
    /// cannot be stopped is a transfer that will be drained.
    pub fn assert_unpaused(env: Env) {
        assert!(!read_config(&env).paused, "bridge is paused");
    }

    // ----------------------------------------------------------------- pauses

    /// Announce a pause (`reason` is logged, never stored).
    ///
    /// Returns the ledger the pause can land in. Asking again while a pause is
    /// already pending returns that same ledger: the countdown belongs to the
    /// bridge, not to the guardian who started it.
    pub fn request_pause(env: Env, guardian: Address, reason: String) -> u32 {
        guardian.require_auth();
        assert!(reason.len() > 0, "reason must not be empty");
        assert!(
            read_guardians(&env).contains(&guardian),
            "not a pause guardian"
        );

        let config = read_config(&env);
        assert!(!config.paused, "bridge is already paused");

        if let Some(pending) = read_pending(&env) {
            match pending.change {
                // Idempotent: a second name on the same request must not push
                // the effective ledger out, or one guardian could stall the
                // bridge by re-requesting forever.
                Change::Pause => return pending.effective_ledger,
                Change::Unpause => panic!("a pending unpause must be resolved first"),
            }
        }

        let requested_ledger = env.ledger().sequence();
        let effective_ledger = requested_ledger + config.pause_delay;
        write_pending(
            &env,
            &Pending {
                change: Change::Pause,
                requested_by: guardian.clone(),
                requested_ledger,
                effective_ledger,
            },
            &config,
        );

        env.events().publish(
            (symbol_short!("pause"), symbol_short!("request")),
            (guardian, effective_ledger, reason),
        );
        effective_ledger
    }

    /// Land a requested pause once its timelock has elapsed.
    ///
    /// Permissionless: anyone may settle the state change, which means a bridge
    /// cannot be left unpaused simply because the guardians stopped
    /// transacting.
    pub fn activate_pause(env: Env) -> bool {
        let mut config = read_config(&env);
        let pending = read_pending(&env).unwrap_or_else(|| panic!("no pending change"));
        assert!(
            pending.change == Change::Pause,
            "pending change is not a pause"
        );
        assert!(
            env.ledger().sequence() >= pending.effective_ledger,
            "pause timelock has not elapsed"
        );

        config.paused = true;
        write_config(&env, &config);
        clear_pending(&env);

        env.events().publish(
            (symbol_short!("pause"), symbol_short!("activate")),
            (pending.requested_by, pending.effective_ledger),
        );
        true
    }

    // --------------------------------------------------------------- unpauses

    /// Ask to resume, as the admin. Returns the ledger the unpause can land in.
    pub fn request_unpause(env: Env, admin: Address) -> u32 {
        admin.require_auth();
        let config = read_config(&env);
        assert!(
            admin == config.admin,
            "only the admin may resume the bridge"
        );
        assert!(config.paused, "bridge is not paused");

        if let Some(pending) = read_pending(&env) {
            match pending.change {
                Change::Unpause => return pending.effective_ledger,
                Change::Pause => panic!("a pending pause must be resolved first"),
            }
        }

        let requested_ledger = env.ledger().sequence();
        let effective_ledger = requested_ledger + config.unpause_delay;
        write_pending(
            &env,
            &Pending {
                change: Change::Unpause,
                requested_by: admin.clone(),
                requested_ledger,
                effective_ledger,
            },
            &config,
        );

        env.events().publish(
            (symbol_short!("unpause"), symbol_short!("request")),
            (admin, effective_ledger),
        );
        effective_ledger
    }

    /// Land a requested unpause once its timelock has elapsed.
    pub fn activate_unpause(env: Env) -> bool {
        let mut config = read_config(&env);
        let pending = read_pending(&env).unwrap_or_else(|| panic!("no pending change"));
        assert!(
            pending.change == Change::Unpause,
            "pending change is not an unpause"
        );
        assert!(
            env.ledger().sequence() >= pending.effective_ledger,
            "unpause timelock has not elapsed"
        );

        config.paused = false;
        write_config(&env, &config);
        clear_pending(&env);

        env.events().publish(
            (symbol_short!("unpause"), symbol_short!("activate")),
            (pending.requested_by, pending.effective_ledger),
        );
        true
    }

    /// Drop a pending change before it lands, as the admin.
    ///
    /// This is the escape hatch for a rogue guardian's pause request: the whole
    /// timelock is there to give the admin time to use it.
    pub fn cancel_pending(env: Env, admin: Address) {
        admin.require_auth();
        let config = read_config(&env);
        assert!(admin == config.admin, "only the admin may cancel");
        let pending = read_pending(&env).unwrap_or_else(|| panic!("no pending change"));

        clear_pending(&env);
        env.events().publish(
            (symbol_short!("pause"), symbol_short!("cancel")),
            (pending.requested_by, pending.effective_ledger),
        );
    }

    // --------------------------------------------------------------- guardians

    /// Add a pause guardian, as the admin.
    pub fn add_guardian(env: Env, admin: Address, guardian: Address) {
        admin.require_auth();
        let config = read_config(&env);
        assert!(
            admin == config.admin,
            "only the admin may change the guardians"
        );
        let mut guardians = read_guardians(&env);
        assert!(
            !guardians.contains(&guardian),
            "guardian is already in the set"
        );
        assert!(guardians.len() < MAX_GUARDIANS, "guardian set is full");

        guardians.push_back(guardian.clone());
        write_guardians(&env, &guardians);
        env.events()
            .publish((symbol_short!("guardian"), symbol_short!("add")), guardian);
    }

    /// Remove a pause guardian, as the admin.
    ///
    /// The last guardian cannot be removed: a bridge with no guardian has no one
    /// who can raise a pause, which is the state this contract exists to prevent.
    pub fn remove_guardian(env: Env, admin: Address, guardian: Address) {
        admin.require_auth();
        let config = read_config(&env);
        assert!(
            admin == config.admin,
            "only the admin may change the guardians"
        );
        let guardians = read_guardians(&env);
        let index = guardians
            .first_index_of(&guardian)
            .unwrap_or_else(|| panic!("not a guardian")) as usize;
        assert!(guardians.len() > 1, "the last guardian cannot be removed");

        let mut remaining = Vec::new(&env);
        for (i, existing) in guardians.iter().enumerate() {
            if i != index {
                remaining.push_back(existing);
            }
        }
        write_guardians(&env, &remaining);
        env.events().publish(
            (symbol_short!("guardian"), symbol_short!("remove")),
            guardian,
        );
    }
}

// ------------------------------------------------------------------ storage

fn read_config(env: &Env) -> Config {
    env.storage()
        .instance()
        .get(&DataKey::Config)
        .unwrap_or_else(|| panic!("contract is not initialized"))
}

fn write_config(env: &Env, config: &Config) {
    env.storage().instance().set(&DataKey::Config, config);
    bump_instance_ttl(env);
}

fn read_guardians(env: &Env) -> Vec<Address> {
    env.storage()
        .instance()
        .get(&DataKey::Guardians)
        .unwrap_or_else(|| panic!("contract is not initialized"))
}

fn write_guardians(env: &Env, guardians: &Vec<Address>) {
    env.storage().instance().set(&DataKey::Guardians, guardians);
    bump_instance_ttl(env);
}

fn read_pending(env: &Env) -> Option<Pending> {
    env.storage().instance().get(&DataKey::Pending)
}

fn write_pending(env: &Env, pending: &Pending, _config: &Config) {
    env.storage().instance().set(&DataKey::Pending, pending);
    bump_instance_ttl(env);
}

fn clear_pending(env: &Env) {
    env.storage().instance().remove(&DataKey::Pending);
    bump_instance_ttl(env);
}

/// Keep the instance (config, guardians and any pending change) alive. A pending
/// change is the state that matters most here: archiving it would silently drop
/// a pause the bridge is counting on.
fn bump_instance_ttl(env: &Env) {
    env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_BUMP);
}

#[cfg(test)]
mod test {
    extern crate std;
    use super::*;
    use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
    use soroban_sdk::{Symbol, TryFromVal};

    /// A deployed guard with an admin and two guardians, 10 ledgers to pause and
    /// 20 to resume.
    struct Fixture {
        env: Env,
        admin: Address,
        guardian_a: Address,
        guardian_b: Address,
        client: BridgePauseGuardClient<'static>,
    }

    impl Fixture {
        fn new() -> Self {
            let env = Env::default();
            env.mock_all_auths();
            env.ledger().set_min_persistent_entry_ttl(1_000_000);
            env.ledger().set_max_entry_ttl(1_000_000);
            env.ledger().set_sequence_number(1_000);

            let admin = Address::generate(&env);
            let guardian_a = Address::generate(&env);
            let guardian_b = Address::generate(&env);

            let id = env.register_contract(None, BridgePauseGuard);
            let client = BridgePauseGuardClient::new(&env, &id);
            client.initialize(
                &admin,
                &soroban_sdk::vec![&env, guardian_a.clone(), guardian_b.clone()],
                &10,
                &20,
            );

            Fixture {
                env,
                admin,
                guardian_a,
                guardian_b,
                client,
            }
        }

        fn at(&self, ledger: u32) {
            self.env.ledger().set_sequence_number(ledger);
        }

        fn now(&self) -> u32 {
            self.env.ledger().sequence()
        }

        /// Requests a pause and runs it out to the effective ledger.
        fn paused(&self) -> u32 {
            let effective = self
                .client
                .request_pause(&self.guardian_a, &String::from_str(&self.env, "drain"));
            self.at(effective);
            self.client.activate_pause();
            effective
        }

        /// Requests an unpause and runs it out to the effective ledger.
        fn unpaused(&self) {
            let effective = self.client.request_unpause(&self.admin);
            self.at(effective);
            self.client.activate_unpause();
        }
    }

    #[test]
    fn initialize_sets_the_guardian_set_and_delays() {
        let f = Fixture::new();
        let config = f.client.config();
        assert_eq!(config.admin, f.admin);
        assert_eq!(config.pause_delay, 10);
        assert_eq!(config.unpause_delay, 20);
        assert!(!config.paused);
        assert!(f.client.is_guardian(&f.guardian_a));
        assert!(f.client.is_guardian(&f.guardian_b));
        assert!(!f.client.is_paused());
        assert!(f.client.pending_change().is_none());
    }

    #[test]
    fn initialize_is_write_once() {
        let f = Fixture::new();
        let again = soroban_sdk::vec![&f.env, f.guardian_a.clone()];
        assert!(f.client.try_initialize(&f.admin, &again, &10, &20).is_err());
    }

    #[test]
    fn initialize_rejects_delays_that_are_not_a_timelock() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let guardian = Address::generate(&env);
        let set = soroban_sdk::vec![&env, guardian];
        let id = env.register_contract(None, BridgePauseGuard);
        let client = BridgePauseGuardClient::new(&env, &id);

        // A zero pause delay is a silent pause, which is the thing this
        // contract exists to prevent.
        assert!(client.try_initialize(&admin, &set, &0, &20).is_err());
        assert!(client
            .try_initialize(&admin, &set, &MIN_PAUSE_DELAY, &(MAX_PAUSE_DELAY + 1))
            .is_err());
        // Resuming must not be quicker than pausing.
        assert!(client.try_initialize(&admin, &set, &50, &49).is_err());
        assert!(client.try_initialize(&admin, &set, &10, &10).is_ok());
    }

    #[test]
    fn initialize_requires_a_non_empty_guardian_set() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let empty: Vec<Address> = Vec::new(&env);
        let id = env.register_contract(None, BridgePauseGuard);
        let client = BridgePauseGuardClient::new(&env, &id);
        assert!(client.try_initialize(&admin, &empty, &10, &20).is_err());
    }

    #[test]
    fn initialize_rejects_a_duplicated_guardian() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let guardian = Address::generate(&env);
        let duplicated = soroban_sdk::vec![&env, guardian.clone(), guardian.clone()];
        let id = env.register_contract(None, BridgePauseGuard);
        let client = BridgePauseGuardClient::new(&env, &id);
        assert!(client
            .try_initialize(&admin, &duplicated, &10, &20)
            .is_err());
    }

    #[test]
    fn only_a_guardian_can_request_a_pause() {
        let f = Fixture::new();
        let outsider = Address::generate(&f.env);
        assert!(f
            .client
            .try_request_pause(&outsider, &String::from_str(&f.env, "hi"))
            .is_err());
        assert!(f.client.pending_change().is_none());

        // A guardian that was removed has no authority either.
        f.client.remove_guardian(&f.admin, &f.guardian_b);
        assert!(f
            .client
            .try_request_pause(&f.guardian_b, &String::from_str(&f.env, "hi"))
            .is_err());
    }

    #[test]
    fn a_request_does_not_pause_anything_until_its_timelock_elapses() {
        let f = Fixture::new();
        let now = f.now();
        let effective = f
            .client
            .request_pause(&f.guardian_a, &String::from_str(&f.env, "drain"));

        assert_eq!(effective, now + 10);
        assert!(!f.client.is_paused());
        let pending = f.client.pending_change().unwrap();
        assert_eq!(pending.change, Change::Pause);
        assert_eq!(pending.requested_by, f.guardian_a);
        assert_eq!(pending.requested_ledger, now);
        assert_eq!(pending.effective_ledger, now + 10);

        // Still a ledger early.
        f.at(effective - 1);
        assert!(f.client.try_activate_pause().is_err());
        assert!(!f.client.is_paused());

        // And now it lands.
        f.at(effective);
        assert!(f.client.try_activate_pause().is_ok());
        assert!(f.client.is_paused());
        assert!(f.client.pending_change().is_none());
    }

    #[test]
    fn a_second_request_does_not_extend_the_countdown() {
        let f = Fixture::new();
        let first = f
            .client
            .request_pause(&f.guardian_a, &String::from_str(&f.env, "drain"));
        f.at(f.now() + 4);
        let second = f
            .client
            .request_pause(&f.guardian_b, &String::from_str(&f.env, "me too"));

        // The clock belongs to the bridge, not to the guardian who started it:
        // otherwise one guardian could stall the pause forever.
        assert_eq!(first, second);
        assert_eq!(f.client.pending_change().unwrap().effective_ledger, first);
        assert_eq!(
            f.client.pending_change().unwrap().requested_by,
            f.guardian_a
        );
    }

    #[test]
    fn activate_pause_needs_a_pending_request() {
        let f = Fixture::new();
        assert!(f.client.try_activate_pause().is_err());
    }

    #[test]
    fn the_gate_aborts_while_paused_and_clears_after_resuming() {
        let f = Fixture::new();
        // Open, so the gate passes.
        assert!(f.client.try_assert_unpaused().is_ok());

        f.paused();
        assert!(f.client.is_paused());
        assert!(f.client.try_assert_unpaused().is_err());

        f.unpaused();
        assert!(!f.client.is_paused());
        assert!(f.client.try_assert_unpaused().is_ok());
        assert!(f.client.pending_change().is_none());
    }

    #[test]
    fn a_pause_cannot_be_requested_while_paused() {
        let f = Fixture::new();
        f.paused();
        assert!(f
            .client
            .try_request_pause(&f.guardian_b, &String::from_str(&f.env, "again"))
            .is_err());
    }

    #[test]
    fn a_guardian_cannot_request_an_unpause() {
        let f = Fixture::new();
        f.paused();
        // `request_unpause` demands the admin's auth; with every auth mocked,
        // the identity check is what has to hold.
        assert!(f.client.try_request_unpause(&f.guardian_a).is_err());
    }

    #[test]
    fn unpausing_is_timelocked_and_only_the_admin_can_start_it() {
        let f = Fixture::new();
        f.paused();
        let now = f.now();

        assert!(
            f.client.try_activate_unpause().is_err(),
            "nothing requested yet"
        );

        let effective = f.client.request_unpause(&f.admin);
        assert_eq!(effective, now + 20);
        assert!(
            f.client.is_paused(),
            "still paused until the timelock runs out"
        );

        f.at(effective - 1);
        assert!(f.client.try_activate_unpause().is_err());
        assert!(f.client.is_paused());

        // Permissionless: anyone may settle it once the delay has passed.
        f.at(effective);
        assert!(f.client.try_activate_unpause().is_ok());
        assert!(!f.client.is_paused());
    }

    #[test]
    fn an_unpause_request_is_idempotent_and_blocks_a_competing_pause() {
        let f = Fixture::new();
        f.paused();
        let first = f.client.request_unpause(&f.admin);
        f.at(f.now() + 5);
        assert_eq!(f.client.request_unpause(&f.admin), first);
        // A guardian cannot park a pause in front of a resume that is under way.
        assert!(f
            .client
            .try_request_pause(&f.guardian_a, &String::from_str(&f.env, "block it"))
            .is_err());
    }

    #[test]
    fn the_admin_can_cancel_a_pending_pause_before_it_lands() {
        let f = Fixture::new();
        let effective = f
            .client
            .request_pause(&f.guardian_a, &String::from_str(&f.env, "drain"));

        let outsider = Address::generate(&f.env);
        assert!(f.client.try_cancel_pending(&outsider).is_err());

        f.client.cancel_pending(&f.admin);
        assert!(f.client.pending_change().is_none());
        assert!(!f.client.is_paused());
        // The cancelled request is gone, so activation has nothing to land.
        f.at(effective);
        assert!(f.client.try_activate_pause().is_err());
        assert!(!f.client.is_paused());
    }

    #[test]
    fn the_admin_can_cancel_a_pending_unpause() {
        let f = Fixture::new();
        f.paused();
        f.client.request_unpause(&f.admin);
        assert!(f.client.pending_change().is_some());
        f.client.cancel_pending(&f.admin);
        assert!(f.client.pending_change().is_none());
        // Still paused, and the paused bridge refuses value movement.
        assert!(f.client.try_assert_unpaused().is_err());
    }

    #[test]
    fn cancelling_with_nothing_pending_is_refused() {
        let f = Fixture::new();
        assert!(f.client.try_cancel_pending(&f.admin).is_err());
    }

    #[test]
    fn the_admin_manages_the_guardian_set() {
        let f = Fixture::new();
        let newcomer = Address::generate(&f.env);
        f.client.add_guardian(&f.admin, &newcomer);
        assert!(f.client.is_guardian(&newcomer));
        assert_eq!(f.client.guardians().len(), 3);

        // No duplicates, and only the admin may change the set.
        assert!(f.client.try_add_guardian(&f.admin, &newcomer).is_err());
        assert!(f.client.try_add_guardian(&newcomer, &f.guardian_a).is_err());

        f.client.remove_guardian(&f.admin, &newcomer);
        assert!(!f.client.is_guardian(&newcomer));
        assert!(f.client.try_remove_guardian(&f.admin, &newcomer).is_err());
    }

    #[test]
    fn the_last_guardian_cannot_be_removed() {
        let f = Fixture::new();
        f.client.remove_guardian(&f.admin, &f.guardian_b);
        assert_eq!(f.client.guardians().len(), 1);
        assert!(f
            .client
            .try_remove_guardian(&f.admin, &f.guardian_a)
            .is_err());
        assert_eq!(f.client.guardians().len(), 1);
    }

    #[test]
    fn the_guardian_set_is_capped() {
        let f = Fixture::new();
        for _ in 0..(MAX_GUARDIANS - 2) {
            f.client.add_guardian(&f.admin, &Address::generate(&f.env));
        }
        assert_eq!(f.client.guardians().len(), MAX_GUARDIANS);
        assert!(f
            .client
            .try_add_guardian(&f.admin, &Address::generate(&f.env))
            .is_err());
    }

    #[test]
    fn a_pause_can_be_raised_again_after_a_resume() {
        let f = Fixture::new();
        f.paused();
        f.unpaused();
        assert!(!f.client.is_paused());

        let effective = f
            .client
            .request_pause(&f.guardian_b, &String::from_str(&f.env, "second drain"));
        assert_eq!(effective, f.now() + 10);
        f.at(effective);
        f.client.activate_pause();
        assert!(f.client.is_paused());
    }

    #[test]
    fn the_request_event_carries_the_reason_and_the_effective_ledger() {
        let f = Fixture::new();
        let reason = String::from_str(&f.env, "unauthorised outflow");
        let effective = f.client.request_pause(&f.guardian_a, &reason);

        let mut announced = false;
        for (_, topics, data) in f.env.events().all() {
            let names: std::vec::Vec<Symbol> = (0..topics.len())
                .filter_map(|i| Symbol::try_from_val(&f.env, &topics.get(i).unwrap()).ok())
                .collect();
            if !(names.contains(&symbol_short!("pause"))
                && names.contains(&symbol_short!("request")))
            {
                continue;
            }
            announced = true;
            let (who, ledger, why) =
                <(Address, u32, String)>::try_from_val(&f.env, &data).expect("event payload");
            assert_eq!(who, f.guardian_a);
            assert_eq!(ledger, effective);
            assert_eq!(why, reason);
        }
        assert!(announced, "the pause request was not announced");

        // The reason is logged, never stored: instance state must not grow with
        // free text a guardian controls. The request is still only a request.
        assert!(f.client.try_assert_unpaused().is_ok());
        assert!(f.client.pending_change().is_some());
    }

    #[test]
    #[should_panic(expected = "reason must not be empty")]
    fn request_pause_requires_non_empty_reason() {
        let f = Fixture::new();
        f.client
            .request_pause(&f.guardian_a, &String::from_str(&f.env, ""));
    }

    #[test]
    fn guardian_rotation_and_lost_key_recovery() {
        let f = Fixture::new();
        let replacement = Address::generate(&f.env);

        // Step 1: Add new guardian
        f.client.add_guardian(&f.admin, &replacement);
        assert!(f.client.is_guardian(&replacement));
        assert_eq!(f.client.guardians().len(), 3);

        // Step 2: Remove old / compromised guardian
        f.client.remove_guardian(&f.admin, &f.guardian_a);
        assert!(!f.client.is_guardian(&f.guardian_a));
        assert_eq!(f.client.guardians().len(), 2);
    }
}

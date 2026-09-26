//! # State Management Module
//!
//! Instance storage for payment channel state on Soroban.

// Some of the accessors below are not called by a contract entrypoint yet. They
// are part of a coherent storage API and are exercised by this module's tests, so
// they are kept rather than deleted; the allow is scoped to this module instead of
// the whole crate.
#![allow(dead_code)]

use soroban_sdk::{contracttype, Address, BytesN, Env, Map, TryFromVal, Val, Vec};
use soroban_ttl::{extend_instance, TtlPolicy};

use crate::error::PaymentChannelError;
use crate::types::{ChannelState, ChannelStats, HTLCInfo};

/// Storage key enum for all stored data
#[contracttype]
#[derive(Clone)]
pub enum StorageKey {
    Channel(BytesN<32>),
    ParticipantChannels(Address),
    ChannelStats(BytesN<32>),
}

/// Keep channel state alive.
///
/// A channel is a long-lived bilateral relationship: it can sit idle for weeks and
/// still be closed or challenged afterwards. Channel state therefore gets the
/// generous policy, and every read or write below keeps the entry alive so a
/// dormant channel is never silently archived out from under its participants.
fn touch(env: &Env) {
    extend_instance(env, TtlPolicy::LONG_LIVED);
}

/// Store channel state
///
/// `StorageKey` is a `#[contracttype]`, so it already converts into a storage key.
/// Passing it directly (rather than round-tripping through `Val`) is what lets
/// `soroban-sdk` infer both the key and the value type.
pub fn store_channel_state(env: &Env, channel_id: &BytesN<32>, state: &ChannelState) {
    env.storage()
        .instance()
        .set(&StorageKey::Channel(channel_id.clone()), state);
    touch(env);
}

/// Retrieve channel state from storage
pub fn get_channel_state(
    env: &Env,
    channel_id: &BytesN<32>,
) -> Result<ChannelState, PaymentChannelError> {
    let state = env
        .storage()
        .instance()
        .get(&StorageKey::Channel(channel_id.clone()))
        .ok_or(PaymentChannelError::ChannelNotFound)?;
    touch(env);
    Ok(state)
}

/// Delete channel state from storage
pub fn delete_channel_state(env: &Env, channel_id: &BytesN<32>) {
    env.storage()
        .instance()
        .remove(&StorageKey::Channel(channel_id.clone()));
}

/// Store list of channels for a participant
pub fn store_participant_channels(env: &Env, participant: &Address, channels: &Vec<BytesN<32>>) {
    env.storage().instance().set(
        &StorageKey::ParticipantChannels(participant.clone()),
        channels,
    );
    touch(env);
}

/// Get list of channels for a participant
pub fn get_participant_channels(env: &Env, participant: &Address) -> Vec<BytesN<32>> {
    let channels = env
        .storage()
        .instance()
        .get(&StorageKey::ParticipantChannels(participant.clone()))
        .unwrap_or_else(|| Vec::new(env));
    touch(env);
    channels
}

/// Store channel statistics
pub fn store_channel_stats(env: &Env, channel_id: &BytesN<32>, stats: &ChannelStats) {
    env.storage()
        .instance()
        .set(&StorageKey::ChannelStats(channel_id.clone()), stats);
    touch(env);
}

/// Get channel statistics
pub fn get_channel_stats(env: &Env, channel_id: &BytesN<32>) -> ChannelStats {
    let stats = env
        .storage()
        .instance()
        .get(&StorageKey::ChannelStats(channel_id.clone()))
        .unwrap_or_default();
    touch(env);
    stats
}

/// Check if a channel exists
pub fn channel_exists(env: &Env, channel_id: &BytesN<32>) -> bool {
    let exists = env
        .storage()
        .instance()
        .has(&StorageKey::Channel(channel_id.clone()));
    touch(env);
    exists
}

/// Check if a participant exists
pub fn participant_exists(env: &Env, participant: &Address) -> bool {
    let exists = env
        .storage()
        .instance()
        .has(&StorageKey::ParticipantChannels(participant.clone()));
    touch(env);
    exists
}

/// Get all channel IDs (for iteration - limited in Soroban)
pub fn get_all_channels(env: &Env) -> Vec<BytesN<32>> {
    Vec::new(env)
}

/// Check if there are any active HTLCs in a channel's HTLC map
pub fn has_active_htlcs(env: &Env, htlcs: &Map<Val, Val>) -> Result<bool, PaymentChannelError> {
    for (_, val) in htlcs.iter() {
        if let Ok(htlc) = HTLCInfo::try_from_val(env, &val) {
            if !htlc.is_claimed && !htlc.is_refunded {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Get count of active HTLCs
pub fn count_active_htlcs(env: &Env, htlcs: &Map<Val, Val>) -> u32 {
    let mut count = 0u32;
    for (_, val) in htlcs.iter() {
        if let Ok(htlc) = HTLCInfo::try_from_val(env, &val) {
            if !htlc.is_claimed && !htlc.is_refunded {
                count += 1;
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    /// Storage can only be touched from inside a contract frame, so every
    /// assertion here runs through `as_contract` against a registered contract.
    fn in_contract<T>(env: &Env, id: &Address, f: impl FnOnce() -> T) -> T {
        env.as_contract(id, f)
    }

    fn deploy(env: &Env) -> Address {
        env.register_contract(None, crate::PaymentChannel)
    }

    fn channel_id(env: &Env) -> BytesN<32> {
        BytesN::from_array(env, &[7u8; 32])
    }

    /// `ChannelState` has no `Default` (it holds addresses and a key), so tests
    /// build one through the real constructor.
    fn sample_state(env: &Env, id: &BytesN<32>) -> ChannelState {
        ChannelState::new(
            env,
            id.clone(),
            Address::generate(env),
            Address::generate(env),
            1_000,
            1_000,
            3_600,
            0,
        )
    }

    #[test]
    fn channel_state_round_trips_through_storage() {
        let env = Env::default();
        let contract = deploy(&env);
        let id = channel_id(&env);
        let state = sample_state(&env, &id);

        in_contract(&env, &contract, || {
            assert!(!channel_exists(&env, &id));
            store_channel_state(&env, &id, &state);
            assert!(channel_exists(&env, &id));

            let loaded = get_channel_state(&env, &id).expect("channel should load");
            assert_eq!(loaded, state);
        });
    }

    #[test]
    fn missing_channel_reports_not_found() {
        let env = Env::default();
        let contract = deploy(&env);
        let id = channel_id(&env);

        in_contract(&env, &contract, || {
            assert_eq!(
                get_channel_state(&env, &id).unwrap_err(),
                PaymentChannelError::ChannelNotFound
            );
        });
    }

    #[test]
    fn delete_removes_the_entry() {
        let env = Env::default();
        let contract = deploy(&env);
        let id = channel_id(&env);
        let state = sample_state(&env, &id);

        in_contract(&env, &contract, || {
            store_channel_state(&env, &id, &state);
            delete_channel_state(&env, &id);

            assert!(!channel_exists(&env, &id));
            assert!(get_channel_state(&env, &id).is_err());
        });
    }

    #[test]
    fn participant_channels_round_trip() {
        let env = Env::default();
        let contract = deploy(&env);
        let id = channel_id(&env);
        let participant = Address::generate(&env);

        in_contract(&env, &contract, || {
            assert!(!participant_exists(&env, &participant));
            assert!(get_participant_channels(&env, &participant).is_empty());

            let mut channels = Vec::new(&env);
            channels.push_back(id.clone());
            store_participant_channels(&env, &participant, &channels);

            assert!(participant_exists(&env, &participant));
            let loaded = get_participant_channels(&env, &participant);
            assert_eq!(loaded.len(), 1);
            assert_eq!(loaded.get(0), Some(id));
        });
    }

    #[test]
    fn channel_stats_default_when_absent() {
        let env = Env::default();
        let contract = deploy(&env);
        let id = channel_id(&env);

        in_contract(&env, &contract, || {
            assert_eq!(get_channel_stats(&env, &id), ChannelStats::default());

            let stored = ChannelStats::default();
            store_channel_stats(&env, &id, &stored);
            assert_eq!(get_channel_stats(&env, &id), stored);
        });
    }

    #[test]
    fn participant_channels_do_not_bleed_across_participants() {
        let env = Env::default();
        let contract = deploy(&env);
        let id = channel_id(&env);
        let a = Address::generate(&env);
        let b = Address::generate(&env);

        in_contract(&env, &contract, || {
            let mut channels = Vec::new(&env);
            channels.push_back(id);
            store_participant_channels(&env, &a, &channels);

            assert!(participant_exists(&env, &a));
            assert!(!participant_exists(&env, &b));
            assert!(get_participant_channels(&env, &b).is_empty());
        });
    }
}

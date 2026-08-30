//! # State Management Module
//!
//! Persistent storage for payment channel state on Soroban.

use soroban_sdk::{
    contracttype, Env, BytesN, Address, Vec, Map, Val,
    IntoVal, TryFromVal,
};

use crate::types::{ChannelState, ChannelStats, HTLCInfo};
use crate::error::PaymentChannelError;

/// Storage key enum for all stored data
#[contracttype]
#[derive(Clone)]
pub enum StorageKey {
    Channel(BytesN<32>),
    ParticipantChannels(Address),
    ChannelStats(BytesN<32>),
}

/// Store channel state persistently
pub fn store_channel_state(env: &Env, channel_id: &BytesN<32>, state: &ChannelState) {
    let key = StorageKey::Channel(channel_id.clone());
    let val = state.clone().into_val(env);
    env.storage().instance().set(&key.into_val(env), &val);
}

/// Retrieve channel state from storage
pub fn get_channel_state(env: &Env, channel_id: &BytesN<32>) -> Result<ChannelState, PaymentChannelError> {
    let key = StorageKey::Channel(channel_id.clone());
    let val: Val = env.storage().instance().get(&key.into_val(env))
        .ok_or(PaymentChannelError::ChannelNotFound)?;
    ChannelState::try_from_val(env, &val)
        .map_err(|_| PaymentChannelError::InvalidChannelState)
}

/// Delete channel state from storage
pub fn delete_channel_state(env: &Env, channel_id: &BytesN<32>) {
    let key = StorageKey::Channel(channel_id.clone());
    env.storage().instance().remove(&key.into_val(env));
}

/// Store list of channels for a participant
pub fn store_participant_channels(env: &Env, participant: &Address, channels: &Vec<BytesN<32>>) {
    let key = StorageKey::ParticipantChannels(participant.clone());
    let val = channels.clone().into_val(env);
    env.storage().instance().set(&key.into_val(env), &val);
}

/// Get list of channels for a participant
pub fn get_participant_channels(env: &Env, participant: &Address) -> Vec<BytesN<32>> {
    let key = StorageKey::ParticipantChannels(participant.clone());
    env.storage().instance()
        .get::<Val, Val>(&key.into_val(env))
        .map(|val| Vec::<BytesN<32>>::try_from_val(env, &val).unwrap_or_else(|_| Vec::new(env)))
        .unwrap_or_else(|| Vec::new(env))
}

/// Store channel statistics
pub fn store_channel_stats(env: &Env, channel_id: &BytesN<32>, stats: &ChannelStats) {
    let key = StorageKey::ChannelStats(channel_id.clone());
    let val = stats.clone().into_val(env);
    env.storage().instance().set(&key.into_val(env), &val);
}

/// Get channel statistics
pub fn get_channel_stats(env: &Env, channel_id: &BytesN<32>) -> ChannelStats {
    let key = StorageKey::ChannelStats(channel_id.clone());
    env.storage().instance()
        .get::<Val, Val>(&key.into_val(env))
        .and_then(|val| ChannelStats::try_from_val(env, &val).ok())
        .unwrap_or_else(|| ChannelStats::default())
}

/// Check if a channel exists
pub fn channel_exists(env: &Env, channel_id: &BytesN<32>) -> bool {
    let key = StorageKey::Channel(channel_id.clone());
    env.storage().instance().has(&key.into_val(env))
}

/// Check if a participant exists
pub fn participant_exists(env: &Env, participant: &Address) -> bool {
    let key = StorageKey::ParticipantChannels(participant.clone());
    env.storage().instance().has(&key.into_val(env))
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

    #[test]
    fn test_channel_storage() {
        // Placeholder for proper Soroban tests
    }
}

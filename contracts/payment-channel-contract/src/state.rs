//! # State Management Module
//! 
//! Persistent storage for payment channel state on Soroban.

use soroban_sdk::{
    Env, BytesN, Address, Vec, Map, Val,
    StorageInstance, InstanceStorage,
};

use crate::types::{ChannelState, ChannelStats, HTLCInfo};
use crate::error::PaymentChannelError;

/// Storage keys for channel data
const CHANNEL_PREFIX: &str = "channel_";
const PARTICIPANT_PREFIX: &str = "participant_";
const STATS_PREFIX: &str = "stats_";

/// Store channel state persistently
pub fn store_channel_state(env: &Env, channel_id: &BytesN<32>, state: &ChannelState) {
    let key = format!("{}{}", CHANNEL_PREFIX, hex::encode(channel_id.to_vec()));
    let storage = env.storage().instance();
    storage.set::<_, Val>(&key.into_val(env), &state.clone().into_val(env));
}

/// Retrieve channel state from storage
pub fn get_channel_state(env: &Env, channel_id: &BytesN<32>) -> Result<ChannelState, PaymentChannelError> {
    let key = format!("{}{}", CHANNEL_PREFIX, hex::encode(channel_id.to_vec()));
    let storage = env.storage().instance();
    
    storage.get::<_, Val>(&key.into_val(env))
        .ok_or(PaymentChannelError::ChannelNotFound)
        .and_then(|val| {
            Ok(ChannelState::from_val(env, &val))
        })
}

/// Delete channel state from storage
pub fn delete_channel_state(env: &Env, channel_id: &BytesN<32>) {
    let key = format!("{}{}", CHANNEL_PREFIX, hex::encode(channel_id.to_vec()));
    let storage = env.storage().instance();
    storage.remove::<_, Val>(&key.into_val(env));
}

/// Store list of channels for a participant
pub fn store_participant_channels(env: &Env, participant: &Address, channels: &Vec<BytesN<32>>) {
    let key = format!("{}{}", PARTICIPANT_PREFIX, participant.as_val().to_string());
    let storage = env.storage().instance();
    storage.set::<_, Val>(&key.into_val(env), &channels.clone().into_val(env));
}

/// Get list of channels for a participant
pub fn get_participant_channels(env: &Env, participant: &Address) -> Vec<BytesN<32>> {
    let key = format!("{}{}", PARTICIPANT_PREFIX, participant.as_val().to_string());
    let storage = env.storage().instance();
    
    storage.get::<_, Val>(&key.into_val(env))
        .map(|val| Vec::<BytesN<32>>::from_val(env, &val))
        .unwrap_or_else(|| Vec::new(env))
}

/// Store channel statistics
pub fn store_channel_stats(env: &Env, channel_id: &BytesN<32>, stats: &ChannelStats) {
    let key = format!("{}{}", STATS_PREFIX, hex::encode(channel_id.to_vec()));
    let storage = env.storage().instance();
    storage.set::<_, Val>(&key.into_val(env), &stats.clone().into_val(env));
}

/// Get channel statistics
pub fn get_channel_stats(env: &Env, channel_id: &BytesN<32>) -> ChannelStats {
    let key = format!("{}{}", STATS_PREFIX, hex::encode(channel_id.to_vec()));
    let storage = env.storage().instance();
    
    storage.get::<_, Val>(&key.into_val(env))
        .map(|val| ChannelStats::from_val(env, &val))
        .unwrap_or_else(|_| ChannelStats::default())
}

/// Check if a channel exists
pub fn channel_exists(env: &Env, channel_id: &BytesN<32>) -> bool {
    let key = format!("{}{}", CHANNEL_PREFIX, hex::encode(channel_id.to_vec()));
    let storage = env.storage().instance();
    storage.has::<_, Val>(&key.into_val(env))
}

/// Check if a participant exists
pub fn participant_exists(env: &Env, participant: &Address) -> bool {
    let key = format!("{}{}", PARTICIPANT_PREFIX, participant.as_val().to_string());
    let storage = env.storage().instance();
    storage.has::<_, Val>(&key.into_val(env))
}

/// Get all channel IDs (for iteration - limited in Soroban)
pub fn get_all_channels(env: &Env) -> Vec<BytesN<32>> {
    // In production, this would use a more efficient method
    // Soroban doesn't have efficient iteration, so this is a placeholder
    Vec::new(env)
}

/// Check if there are any active HTLCs in a channel's HTLC map
pub fn has_active_htlcs(env: &Env, htlcs: &Map<Val, Val>) -> Result<bool, PaymentChannelError> {
    for (_, val) in htlcs.iter() {
        let htlc: HTLCInfo = HTLCInfo::from_val(env, &val);
        if !htlc.is_claimed && !htlc.is_refunded {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Get count of active HTLCs
pub fn count_active_htlcs(env: &Env, htlcs: &Map<Val, Val>) -> u32 {
    let mut count = 0u32;
    for (_, val) in htlcs.iter() {
        let htlc: HTLCInfo = HTLCInfo::from_val(env, &val);
        if !htlc.is_claimed && !htlc.is_refunded {
            count += 1;
        }
    }
    count
}

/// Helper to convert bytes to hex string
mod hex {
    pub fn encode(data: Vec<u8>) -> String {
        let mut result = String::new();
        for i in 0..data.len() {
            result.push_str(&format!("{:02x}", data.get(i).unwrap_or(0)));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_channel_storage() {
        // This would be a proper test in a full test suite
        // Soroban tests require the SDK testutils
    }
}

//! # Storage Module
//! 
//! Persistent storage backends for the watchtower.

use crate::{Alert, WatchtowerConfig};
use crate::monitor::{ChannelMonitorState, ChannelUpdate};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Storage backend trait
pub trait StorageBackend: Send + Sync {
    /// Store a channel state
    fn store_channel_state(&self, channel_id: &str, state: &ChannelMonitorState) -> Result<(), StorageError>;
    
    /// Get a channel state
    fn get_channel_state(&self, channel_id: &str) -> Result<Option<ChannelMonitorState>, StorageError>;
    
    /// Store an alert
    fn store_alert(&self, alert: &Alert) -> Result<(), StorageError>;
    
    /// Get alerts
    fn get_alerts(&self, limit: usize) -> Result<Vec<Alert>, StorageError>;
    
    /// Store a cached channel update
    fn store_channel_update(&self, update: &ChannelUpdate) -> Result<(), StorageError>;
    
    /// Get cached channel update
    fn get_channel_update(&self, channel_id: &str) -> Result<Option<ChannelUpdate>, StorageError>;
    
    /// Store a channel we're subscribed to
    fn store_subscription(&self, channel_id: &str) -> Result<(), StorageError>;
    
    /// Get all subscriptions
    fn get_subscriptions(&self) -> Result<Vec<String>, StorageError>;
    
    /// Remove a subscription
    fn remove_subscription(&self, channel_id: &str) -> Result<(), StorageError>;
}

/// In-memory storage backend
pub struct InMemoryStorage {
    channel_states: parking_lot::RwLock<HashMap<String, ChannelMonitorState>>,
    channel_updates: parking_lot::RwLock<HashMap<String, ChannelUpdate>>,
    alerts: parking_lot::RwLock<Vec<Alert>>,
    subscriptions: parking_lot::RwLock<Vec<String>>,
}

impl InMemoryStorage {
    /// Create a new in-memory storage
    pub fn new() -> Self {
        InMemoryStorage {
            channel_states: parking_lot::RwLock::new(HashMap::new()),
            channel_updates: parking_lot::RwLock::new(HashMap::new()),
            alerts: parking_lot::RwLock::new(Vec::new()),
            subscriptions: parking_lot::RwLock::new(Vec::new()),
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for InMemoryStorage {
    fn store_channel_state(&self, channel_id: &str, state: &ChannelMonitorState) -> Result<(), StorageError> {
        let mut states = self.channel_states.write();
        states.insert(channel_id.to_string(), state.clone());
        Ok(())
    }
    
    fn get_channel_state(&self, channel_id: &str) -> Result<Option<ChannelMonitorState>, StorageError> {
        let states = self.channel_states.read();
        Ok(states.get(channel_id).cloned())
    }
    
    fn store_alert(&self, alert: &Alert) -> Result<(), StorageError> {
        let mut alerts = self.alerts.write();
        alerts.push(alert.clone());
        
        // Keep only last 1000
        if alerts.len() > 1000 {
            alerts.drain(0..500);
        }
        
        Ok(())
    }
    
    fn get_alerts(&self, limit: usize) -> Result<Vec<Alert>, StorageError> {
        let alerts = self.alerts.read();
        Ok(alerts.iter().rev().take(limit).cloned().collect())
    }
    
    fn store_channel_update(&self, update: &ChannelUpdate) -> Result<(), StorageError> {
        let mut updates = self.channel_updates.write();
        updates.insert(update.channel_id.clone(), update.clone());
        Ok(())
    }
    
    fn get_channel_update(&self, channel_id: &str) -> Result<Option<ChannelUpdate>, StorageError> {
        let updates = self.channel_updates.read();
        Ok(updates.get(channel_id).cloned())
    }
    
    fn store_subscription(&self, channel_id: &str) -> Result<(), StorageError> {
        let mut subs = self.subscriptions.write();
        if !subs.contains(&channel_id.to_string()) {
            subs.push(channel_id.to_string());
        }
        Ok(())
    }
    
    fn get_subscriptions(&self) -> Result<Vec<String>, StorageError> {
        let subs = self.subscriptions.read();
        Ok(subs.clone())
    }
    
    fn remove_subscription(&self, channel_id: &str) -> Result<(), StorageError> {
        let mut subs = self.subscriptions.write();
        subs.retain(|s| s != channel_id);
        Ok(())
    }
}

/// SQLite storage backend (placeholder implementation)
pub struct SqliteStorage {
    path: String,
}

impl SqliteStorage {
    /// Create a new SQLite storage backend
    pub fn new(path: &str) -> Result<Self, StorageError> {
        // In production, this would initialize SQLite connection
        Ok(SqliteStorage {
            path: path.to_string(),
        })
    }
}

impl StorageBackend for SqliteStorage {
    fn store_channel_state(&self, channel_id: &str, state: &ChannelMonitorState) -> Result<(), StorageError> {
        // In production: INSERT INTO channel_states VALUES (?, ?)
        info!("SQLite: storing channel state for {}", channel_id);
        Ok(())
    }
    
    fn get_channel_state(&self, channel_id: &str) -> Result<Option<ChannelMonitorState>, StorageError> {
        // In production: SELECT * FROM channel_states WHERE channel_id = ?
        info!("SQLite: getting channel state for {}", channel_id);
        Ok(None)
    }
    
    fn store_alert(&self, alert: &Alert) -> Result<(), StorageError> {
        // In production: INSERT INTO alerts VALUES (?, ?)
        info!("SQLite: storing alert {}", alert.id);
        Ok(())
    }
    
    fn get_alerts(&self, limit: usize) -> Result<Vec<Alert>, StorageError> {
        // In production: SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?
        info!("SQLite: getting {} alerts", limit);
        Ok(Vec::new())
    }
    
    fn store_channel_update(&self, update: &ChannelUpdate) -> Result<(), StorageError> {
        // In production: INSERT OR REPLACE INTO channel_updates VALUES (?, ?)
        info!("SQLite: storing channel update for {}", update.channel_id);
        Ok(())
    }
    
    fn get_channel_update(&self, channel_id: &str) -> Result<Option<ChannelUpdate>, StorageError> {
        // In production: SELECT * FROM channel_updates WHERE channel_id = ?
        info!("SQLite: getting channel update for {}", channel_id);
        Ok(None)
    }
    
    fn store_subscription(&self, channel_id: &str) -> Result<(), StorageError> {
        // In production: INSERT OR IGNORE INTO subscriptions VALUES (?)
        info!("SQLite: storing subscription for {}", channel_id);
        Ok(())
    }
    
    fn get_subscriptions(&self) -> Result<Vec<String>, StorageError> {
        // In production: SELECT channel_id FROM subscriptions
        info!("SQLite: getting all subscriptions");
        Ok(Vec::new())
    }
    
    fn remove_subscription(&self, channel_id: &str) -> Result<(), StorageError> {
        // In production: DELETE FROM subscriptions WHERE channel_id = ?
        info!("SQLite: removing subscription for {}", channel_id);
        Ok(())
    }
}

/// Storage errors
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Query error: {0}")]
    QueryError(String),
}

/// Import the info! macro
fn info(msg: &str) {
    // Placeholder - in production would use tracing
    let _ = msg;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_storage() {
        let storage = InMemoryStorage::new();
        
        // Test subscription
        storage.store_subscription("channel1").unwrap();
        let subs = storage.get_subscriptions().unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0], "channel1");
        
        // Test alert
        let alert = Alert::breach_attempt("channel1".to_string(), 1, 5);
        storage.store_alert(&alert).unwrap();
        let alerts = storage.get_alerts(10).unwrap();
        assert_eq!(alerts.len(), 1);
    }
}

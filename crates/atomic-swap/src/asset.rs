use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Asset {
    XLM,
    Custom(String), // Asset code
}

impl fmt::Display for Asset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Asset::XLM => write!(f, "XLM"),
            Asset::Custom(code) => write!(f, "{}", code),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetInfo {
    pub asset: Asset,
    pub issuer: Option<String>, // For custom assets
    pub decimals: u8,
    pub is_native: bool,
    pub minimum_balance: i128,
}

impl AssetInfo {
    pub fn xlm() -> Self {
        Self {
            asset: Asset::XLM,
            issuer: None,
            decimals: 7,
            is_native: true,
            minimum_balance: 1_000_0000, // 1 XLM in stroops
        }
    }

    pub fn custom(code: String, issuer: String, decimals: u8) -> Self {
        Self {
            asset: Asset::Custom(code),
            issuer: Some(issuer),
            decimals,
            is_native: false,
            minimum_balance: 0,
        }
    }

    pub fn to_string(&self) -> String {
        match &self.asset {
            Asset::XLM => "XLM".to_string(),
            Asset::Custom(code) => {
                if let Some(issuer) = &self.issuer {
                    format!("{}:{}", code, issuer)
                } else {
                    code.clone()
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct AssetRegistry {
    assets: HashMap<String, AssetInfo>,
}

impl AssetRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            assets: HashMap::new(),
        };
        
        // Register XLM by default
        registry.register(AssetInfo::xlm());
        registry
    }

    pub fn register(&mut self, asset_info: AssetInfo) {
        let key = asset_info.to_string();
        self.assets.insert(key, asset_info);
    }

    pub fn get(&self, asset: &Asset) -> Option<&AssetInfo> {
        let key = match asset {
            Asset::XLM => "XLM".to_string(),
            Asset::Custom(code) => code.clone(),
        };
        self.assets.get(&key)
    }

    pub fn get_by_string(&self, asset_str: &str) -> Option<&AssetInfo> {
        self.assets.get(asset_str)
    }

    pub fn list_all(&self) -> Vec<&AssetInfo> {
        self.assets.values().collect()
    }

    pub fn is_supported(&self, asset: &Asset) -> bool {
        self.get(asset).is_some()
    }
}

impl Default for AssetRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_registry() {
        let mut registry = AssetRegistry::new();
        
        // Test XLM is registered by default
        assert!(registry.is_supported(&Asset::XLM));
        
        // Test custom asset registration
        let usdc = AssetInfo::custom(
            "USDC".to_string(),
            "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_string(),
            7,
        );
        registry.register(usdc.clone());
        
        assert!(registry.is_supported(&Asset::Custom("USDC".to_string())));
        
        // Test retrieval
        let retrieved = registry.get(&Asset::Custom("USDC".to_string()));
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().decimals, 7);
    }
}

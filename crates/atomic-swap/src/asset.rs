use crate::error::{AtomicSwapError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Longest asset code Stellar accepts (the classic 4-character codes are a
/// subset; up to 12 alphanumeric characters are valid).
pub const MAX_ASSET_CODE_LEN: usize = 12;

/// Length of an encoded Stellar account id (`G...` `StrKey`).
pub const STELLAR_ACCOUNT_ID_LEN: usize = 56;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Asset {
    XLM,
    Custom(String), // Asset code
}

impl fmt::Display for Asset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Asset::XLM => write!(f, "XLM"),
            Asset::Custom(code) => write!(f, "{code}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
            minimum_balance: 10_000_000, // 1 XLM in stroops
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

    /// Check that this value identifies a real Stellar asset (#388).
    ///
    /// Two things are enforced, because neither is checked anywhere else on the
    /// offer path:
    ///
    /// * a custom code is 1-12 ASCII alphanumeric characters, and
    /// * a custom asset names an issuer that has the shape of a Stellar account
    ///   id: 56 characters, a leading `G`, and the `base32` alphabet for the rest.
    ///
    /// The issuer check is structural, not a `StrKey` checksum verification: it
    /// rejects empty, truncated, wrong-prefix and non-base32 values here, while
    /// the checksum is verified where the key is actually used to authorise a
    /// transfer. XLM must not carry an issuer.
    pub fn validate_identifier(&self) -> Result<()> {
        match (&self.asset, &self.issuer) {
            (Asset::XLM, None) => Ok(()),
            (Asset::XLM, Some(issuer)) => Err(AtomicSwapError::InvalidAssetIdentifier {
                asset: self.display_key(),
                reason: format!("native XLM must not carry an issuer (got `{issuer}`)"),
            }),
            (Asset::Custom(code), issuer) => {
                if code.is_empty() {
                    return Err(AtomicSwapError::InvalidAssetIdentifier {
                        asset: self.display_key(),
                        reason: "asset code must not be empty".to_string(),
                    });
                }
                if code.chars().count() > MAX_ASSET_CODE_LEN {
                    return Err(AtomicSwapError::InvalidAssetIdentifier {
                        asset: self.display_key(),
                        reason: format!(
                            "asset code is longer than {MAX_ASSET_CODE_LEN} characters"
                        ),
                    });
                }
                if !code.chars().all(|c| c.is_ascii_alphanumeric()) {
                    return Err(AtomicSwapError::InvalidAssetIdentifier {
                        asset: self.display_key(),
                        reason: "asset code must be ASCII alphanumeric".to_string(),
                    });
                }
                let Some(issuer) = issuer else {
                    return Err(AtomicSwapError::InvalidAssetIdentifier {
                        asset: self.display_key(),
                        reason: "custom asset must name an issuer".to_string(),
                    });
                };
                if !is_valid_account_id(issuer) {
                    return Err(AtomicSwapError::InvalidAssetIdentifier {
                        asset: self.display_key(),
                        reason: format!(
                            "issuer `{issuer}` is not a valid Stellar account id (expected {STELLAR_ACCOUNT_ID_LEN} base32 characters starting with `G`)"
                        ),
                    });
                }
                Ok(())
            }
        }
    }

    /// Human-readable identifier including the issuer, when there is one.
    ///
    /// Note this is an inherent method that shadows `ToString`, and it is *not* a
    /// valid [`AssetRegistry`] key -- see [`AssetRegistry::key`].
    pub fn display_key(&self) -> String {
        match &self.asset {
            Asset::XLM => "XLM".to_string(),
            Asset::Custom(code) => {
                if let Some(issuer) = &self.issuer {
                    format!("{code}:{issuer}")
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

    /// The key an asset is stored under.
    ///
    /// Deliberately the bare asset code. `Asset::Custom` carries only a code, so a
    /// key that also included the issuer could never be reconstructed by a lookup:
    /// that mismatch meant every custom asset *with* an issuer was registered under
    /// `"CODE:ISSUER"` and then never found again, so swaps against such assets
    /// failed with `UnsupportedAsset`. Deriving the key in one place keeps
    /// registration and lookup from drifting apart again.
    fn key(asset: &Asset) -> String {
        match asset {
            Asset::XLM => "XLM".to_string(),
            Asset::Custom(code) => code.clone(),
        }
    }

    pub fn register(&mut self, asset_info: AssetInfo) {
        let key = Self::key(&asset_info.asset);
        self.assets.insert(key, asset_info);
    }

    pub fn get(&self, asset: &Asset) -> Option<&AssetInfo> {
        self.assets.get(&Self::key(asset))
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

/// Structural check for a Stellar account id (`StrKey` `G...` form).
///
/// Length, prefix and alphabet only; the `StrKey` checksum is verified by the
/// code that actually signs for the account.
fn is_valid_account_id(value: &str) -> bool {
    value.len() == STELLAR_ACCOUNT_ID_LEN
        && value.starts_with('G')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
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

    // ---- Asset identifier validation (#388) ----

    const ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

    fn custom(code: &str, issuer: Option<&str>) -> AssetInfo {
        AssetInfo {
            asset: Asset::Custom(code.to_string()),
            issuer: issuer.map(str::to_string),
            decimals: 7,
            is_native: false,
            minimum_balance: 0,
        }
    }

    #[test]
    fn native_and_well_formed_custom_identifiers_are_accepted() {
        assert!(AssetInfo::xlm().validate_identifier().is_ok());
        assert!(custom("USDC", Some(ISSUER)).validate_identifier().is_ok());
        // Four-character classic code and the full 12-character maximum.
        assert!(custom("USDC", Some(ISSUER)).validate_identifier().is_ok());
        assert!(custom("ABCDEFGHIJKL", Some(ISSUER))
            .validate_identifier()
            .is_ok());
    }

    #[test]
    fn native_xlm_must_not_name_an_issuer() {
        let mut xlm = AssetInfo::xlm();
        xlm.issuer = Some(ISSUER.to_string());
        let error = xlm.validate_identifier().unwrap_err();
        assert!(matches!(
            error,
            AtomicSwapError::InvalidAssetIdentifier { .. }
        ));
        assert!(error.to_string().contains("must not carry an issuer"));
    }

    #[test]
    fn malformed_asset_codes_are_rejected() {
        let cases = [
            ("", "must not be empty"),
            ("TOOLONGCODE123", "longer than 12"),
            ("USD C", "ASCII alphanumeric"),
            ("USDC!", "ASCII alphanumeric"),
            ("ÜSDC", "ASCII alphanumeric"),
        ];

        for (code, expected_reason) in cases {
            let error = custom(code, Some(ISSUER))
                .validate_identifier()
                .expect_err("malformed code should be refused");
            assert!(
                error.to_string().contains(expected_reason),
                "code {code:?} produced unexpected error: {error}"
            );
        }
    }

    #[test]
    fn custom_assets_must_name_a_structurally_valid_issuer() {
        let missing = custom("USDC", None)
            .validate_identifier()
            .expect_err("a custom asset needs an issuer");
        assert!(missing.to_string().contains("must name an issuer"));

        let malformed = [
            "",
            "GSHORT",
            "SBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA0",
            "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFL-",
        ];
        for issuer in malformed {
            let error = custom("USDC", Some(issuer))
                .validate_identifier()
                .expect_err("malformed issuer should be refused");
            assert!(
                error.to_string().contains("not a valid Stellar account id"),
                "issuer {issuer:?} produced unexpected error: {error}"
            );
        }
    }
}

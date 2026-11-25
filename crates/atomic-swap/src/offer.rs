//! # Swap Offers
//!
//! An offer is the advertisement that precedes a swap: a maker states which
//! asset it gives, which asset it wants, the two amounts and the ledger by
//! which a taker must respond. Offers are exchanged before either side funds a
//! leg, so every validation that can be done off-chain has to happen here.
//!
//! [`SwapOffer::new`] validates both asset identifiers before an offer exists.
//! That ordering is the point: a malformed code or issuer is rejected at
//! creation, not discovered by a counterparty after committing to the trade.
//! Because creation either returns an offer or an error, there is no partial
//! offer to clean up.
//!
//! Expiry handling (refusing to sign an offer whose deadline has passed) lives
//! in the signing path built on top of this type.

use crate::asset::AssetInfo;
use crate::error::{AtomicSwapError, Result};
use serde::{Deserialize, Serialize};

/// A maker's advertised swap terms.
///
/// Construct one with [`SwapOffer::new`], which is the only way to get a value
/// whose asset identifiers have been validated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapOffer {
    /// Caller-chosen identifier for this offer.
    pub id: String,
    /// Account advertising the offer.
    pub maker: String,
    /// Asset the maker gives.
    pub maker_asset: AssetInfo,
    /// Asset the maker wants in return.
    pub taker_asset: AssetInfo,
    /// Amount of `maker_asset` the maker gives.
    pub maker_amount: i128,
    /// Amount of `taker_asset` the maker wants.
    pub taker_amount: i128,
    /// Ledger the offer was created at.
    pub created_at_ledger: u32,
    /// First ledger at which the offer is no longer valid (exclusive deadline).
    pub expires_at_ledger: u32,
}

impl SwapOffer {
    /// Create an offer, validating every field that can be checked off-chain.
    ///
    /// Asset identifiers are validated first, so an invalid asset is reported
    /// even when the amounts or the expiry window are also wrong. Amounts must
    /// be strictly positive, and the expiry ledger must be strictly later than
    /// the creation ledger; a zero-length window could never be accepted by a
    /// counterparty and is rejected rather than silently widened.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        maker: String,
        maker_asset: AssetInfo,
        taker_asset: AssetInfo,
        maker_amount: i128,
        taker_amount: i128,
        created_at_ledger: u32,
        expires_at_ledger: u32,
    ) -> Result<Self> {
        maker_asset.validate_identifier()?;
        taker_asset.validate_identifier()?;

        if maker_amount <= 0 {
            return Err(AtomicSwapError::InvalidAmount {
                amount: maker_amount,
            });
        }
        if taker_amount <= 0 {
            return Err(AtomicSwapError::InvalidAmount {
                amount: taker_amount,
            });
        }
        if expires_at_ledger <= created_at_ledger {
            return Err(AtomicSwapError::InvalidOfferExpiry {
                created_at_ledger,
                expires_at_ledger,
            });
        }

        Ok(Self {
            id,
            maker,
            maker_asset,
            taker_asset,
            maker_amount,
            taker_amount,
            created_at_ledger,
            expires_at_ledger,
        })
    }

    /// `(maker_asset, taker_asset)` identifiers in `CODE:ISSUER` form, for logs
    /// and UI that do not want to reach into [`AssetInfo`].
    pub fn asset_pair(&self) -> (String, String) {
        (
            self.maker_asset.display_key(),
            self.taker_asset.display_key(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USDC_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

    fn usdc() -> AssetInfo {
        AssetInfo::custom("USDC".to_string(), USDC_ISSUER.to_string(), 7)
    }

    fn offer(maker_asset: AssetInfo, taker_asset: AssetInfo) -> Result<SwapOffer> {
        SwapOffer::new(
            "offer-1".to_string(),
            "GMAKER".to_string(),
            maker_asset,
            taker_asset,
            1_000,
            500,
            100,
            200,
        )
    }

    #[test]
    fn a_valid_offer_is_created_with_both_identifiers() {
        let offer = offer(usdc(), AssetInfo::xlm()).expect("valid assets should be accepted");

        assert_eq!(
            offer.asset_pair(),
            (
                "USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_string(),
                "XLM".to_string()
            )
        );
        assert_eq!(offer.maker_amount, 1_000);
        assert_eq!(offer.taker_amount, 500);
        assert_eq!(offer.expires_at_ledger, 200);
    }

    #[test]
    fn the_maker_asset_identifier_is_validated_before_creation() {
        let mut bad = usdc();
        bad.asset = crate::asset::Asset::Custom("USDC!".to_string());

        let error = offer(bad, AssetInfo::xlm()).expect_err("invalid maker asset is refused");
        assert!(matches!(
            error,
            AtomicSwapError::InvalidAssetIdentifier { .. }
        ));
    }

    #[test]
    fn the_taker_asset_identifier_is_validated_before_creation() {
        let mut bad = usdc();
        bad.issuer = Some("GSHORT".to_string());

        let error = offer(usdc(), bad).expect_err("invalid taker issuer is refused");
        assert!(matches!(
            error,
            AtomicSwapError::InvalidAssetIdentifier { .. }
        ));
    }

    #[test]
    fn amounts_must_be_strictly_positive() {
        let zero = SwapOffer::new(
            "offer-1".to_string(),
            "GMAKER".to_string(),
            usdc(),
            AssetInfo::xlm(),
            0,
            500,
            100,
            200,
        );
        assert!(matches!(
            zero,
            Err(AtomicSwapError::InvalidAmount { amount: 0 })
        ));

        let negative = SwapOffer::new(
            "offer-1".to_string(),
            "GMAKER".to_string(),
            usdc(),
            AssetInfo::xlm(),
            1_000,
            -1,
            100,
            200,
        );
        assert!(matches!(
            negative,
            Err(AtomicSwapError::InvalidAmount { amount: -1 })
        ));
    }

    #[test]
    fn the_expiry_window_must_be_positive() {
        for expires_at in [100, 99] {
            let error = SwapOffer::new(
                "offer-1".to_string(),
                "GMAKER".to_string(),
                usdc(),
                AssetInfo::xlm(),
                1_000,
                500,
                100,
                expires_at,
            )
            .expect_err("a non-positive window is refused");
            assert!(matches!(
                error,
                AtomicSwapError::InvalidOfferExpiry {
                    created_at_ledger: 100,
                    expires_at_ledger: _
                }
            ));
        }

        // One ledger of validity is the smallest valid window.
        assert!(SwapOffer::new(
            "offer-1".to_string(),
            "GMAKER".to_string(),
            usdc(),
            AssetInfo::xlm(),
            1_000,
            500,
            100,
            101,
        )
        .is_ok());
    }

    #[test]
    fn offers_round_trip_through_json() {
        let offer = offer(usdc(), AssetInfo::xlm()).unwrap();
        let json = serde_json::to_string(&offer).unwrap();
        let restored: SwapOffer = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, offer);
    }
}

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
//! Offers also have a deadline. [`SwapOffer::sign`] refuses to produce signing
//! material for an offer whose deadline has passed, so an expired offer cannot
//! be handed to a wallet and signed by accident. The crate holds no signer
//! keys: `sign` produces the canonical SHA-256 commitment that a wallet or HSM
//! signs, and [`OfferSignature`] records it with the ledger it was authorised
//! at.

use crate::asset::AssetInfo;
use crate::error::{AtomicSwapError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain tag that separates offer digests from every other digest this crate
/// computes (swap digests, preimage hashes).
pub const OFFER_DIGEST_DOMAIN_TAG: &[u8] = b"STELLAR_SWAP_OFFER_V1";

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

    /// True once `current_ledger` has reached the offer's deadline.
    ///
    /// `expires_at_ledger` is the *first* ledger at which the offer is no
    /// longer valid: [`sign`](Self::sign) at `expires_at_ledger - 1` succeeds,
    /// and at `expires_at_ledger` (or later) it is refused. This is the offer
    /// analogue of an exclusive deadline, and is the opposite convention to a
    /// swap's timeout ledger, where the timeout ledger is still the last
    /// settleable ledger.
    pub fn is_expired(&self, current_ledger: u32) -> bool {
        current_ledger >= self.expires_at_ledger
    }

    /// Canonical SHA-256 commitment over every field a signer authorises.
    ///
    /// Fields are length-prefixed and big-endian, with a domain tag, so two
    /// different offers cannot encode to the same bytes by shifting a field
    /// boundary. Amounts and ledgers are included: a signer that approved 100
    /// units for 10,000 ledgers has not approved any other combination.
    ///
    /// The digest does not depend on wall-clock time or process state, so it
    /// can be recomputed after a restart from the same offer fields.
    pub fn signing_digest(&self) -> Result<[u8; 32]> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(OFFER_DIGEST_DOMAIN_TAG);
        write_length_prefixed(&mut encoded, self.id.as_bytes(), "offer id")?;
        write_length_prefixed(&mut encoded, self.maker.as_bytes(), "maker")?;
        write_length_prefixed(
            &mut encoded,
            self.maker_asset.display_key().as_bytes(),
            "maker asset",
        )?;
        write_length_prefixed(
            &mut encoded,
            self.taker_asset.display_key().as_bytes(),
            "taker asset",
        )?;
        encoded.extend_from_slice(&self.maker_amount.to_be_bytes());
        encoded.extend_from_slice(&self.taker_amount.to_be_bytes());
        encoded.extend_from_slice(&self.created_at_ledger.to_be_bytes());
        encoded.extend_from_slice(&self.expires_at_ledger.to_be_bytes());

        let digest = Sha256::digest(&encoded);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }

    /// Produce the signing commitment for this offer at `current_ledger`.
    ///
    /// An expired offer is refused with [`AtomicSwapError::OfferExpired`]
    /// *before* any digest is computed, so no signing material exists for an
    /// offer a counterparty can no longer act on. The check reads `&self` and
    /// writes nothing, so a refusal leaves the offer untouched and it can be
    /// re-signed while still live.
    pub fn sign(&self, current_ledger: u32) -> Result<OfferSignature> {
        if self.is_expired(current_ledger) {
            return Err(AtomicSwapError::OfferExpired {
                offer_id: self.id.clone(),
                expires_at_ledger: self.expires_at_ledger,
                current_ledger,
            });
        }

        Ok(OfferSignature {
            offer_id: self.id.clone(),
            digest: hex::encode(self.signing_digest()?),
            signed_at_ledger: current_ledger,
        })
    }
}

/// The commitment a signer authorises for an offer.
///
/// `digest` is the hex-encoded [`SwapOffer::signing_digest`] value. The offer id
/// and ledger are carried alongside it so a signature can be tied back to the
/// offer after a restart without guessing which offer it belonged to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferSignature {
    /// Offer this commitment authorises.
    pub offer_id: String,
    /// Hex-encoded SHA-256 commitment over the offer fields.
    pub digest: String,
    /// Ledger at which signing was authorised (strictly before expiry).
    pub signed_at_ledger: u32,
}

/// Write a `u16` big-endian length followed by the field bytes.
///
/// Lengths are checked rather than truncated: two different values that both
/// truncated to the same prefix would produce the same digest.
fn write_length_prefixed(buffer: &mut Vec<u8>, bytes: &[u8], field: &'static str) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| {
        AtomicSwapError::HashComputationError(format!(
            "offer {field} is {} bytes, longer than the u16 length prefix allows",
            bytes.len()
        ))
    })?;
    buffer.extend_from_slice(&len.to_be_bytes());
    buffer.extend_from_slice(bytes);
    Ok(())
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

    // ---- Expiry at signing time (#389) ----

    #[test]
    fn signing_is_refused_from_the_deadline_onwards() {
        let offer = offer(usdc(), AssetInfo::xlm()).unwrap(); // expires at 200

        // Last ledger before the deadline: still signable.
        let signature = offer
            .sign(199)
            .expect("an offer inside its window must be signable");
        assert_eq!(signature.offer_id, "offer-1");
        assert_eq!(signature.signed_at_ledger, 199);
        assert_eq!(signature.digest.len(), 64);

        // Exactly at the deadline: expired.
        let error = offer
            .sign(200)
            .expect_err("an offer at its deadline must be refused");
        assert!(matches!(
            error,
            AtomicSwapError::OfferExpired {
                ref offer_id,
                expires_at_ledger: 200,
                current_ledger: 200,
            } if offer_id == "offer-1"
        ));

        // After the deadline: still refused, and the offer is untouched.
        assert!(offer.sign(201).is_err());
        assert_eq!(offer.expires_at_ledger, 200);
        assert!(!offer.is_expired(199));
        assert!(offer.is_expired(200));
    }

    #[test]
    fn the_signing_digest_is_deterministic_and_field_sensitive() {
        let offer = offer(usdc(), AssetInfo::xlm()).unwrap();
        let base = offer.signing_digest().unwrap();

        // Same fields, same digest -- including across a clone (restart-safe).
        assert_eq!(offer.signing_digest().unwrap(), base);
        assert_eq!(offer.clone().signing_digest().unwrap(), base);

        // Signing at different live ledgers commits to the same offer terms.
        assert_eq!(
            offer.sign(100).unwrap().digest,
            offer.sign(199).unwrap().digest
        );

        let mut changed_amount = offer.clone();
        changed_amount.maker_amount += 1;
        assert_ne!(changed_amount.signing_digest().unwrap(), base);

        let mut changed_expiry = offer.clone();
        changed_expiry.expires_at_ledger += 1;
        assert_ne!(changed_expiry.signing_digest().unwrap(), base);

        let mut changed_maker = offer.clone();
        changed_maker.maker = "GOTHER".to_string();
        assert_ne!(changed_maker.signing_digest().unwrap(), base);

        let mut changed_asset = offer.clone();
        changed_asset.taker_asset =
            AssetInfo::custom("EURC".to_string(), USDC_ISSUER.to_string(), 7);
        assert_ne!(changed_asset.signing_digest().unwrap(), base);
    }

    #[test]
    fn field_boundaries_cannot_be_shifted_between_offers() {
        let mut a = offer(usdc(), AssetInfo::xlm()).unwrap();
        a.id = "AB".to_string();
        a.maker = "GMAKER".to_string();

        let mut b = offer(usdc(), AssetInfo::xlm()).unwrap();
        b.id = "A".to_string();
        b.maker = "BGMAKER".to_string();

        assert_ne!(
            a.signing_digest().unwrap(),
            b.signing_digest().unwrap(),
            "length-prefixed fields must not be ambiguous"
        );
    }
}

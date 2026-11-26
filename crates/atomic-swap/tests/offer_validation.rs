//! Integration coverage for offer creation and asset identifier validation
//! (#388).

use atomic_swap::{
    Asset, AssetInfo, AtomicSwapError, SwapOffer, MAX_ASSET_CODE_LEN, STELLAR_ACCOUNT_ID_LEN,
};

const USDC_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

fn usdc() -> AssetInfo {
    AssetInfo::custom("USDC".to_string(), USDC_ISSUER.to_string(), 7)
}

fn build(maker_asset: AssetInfo, taker_asset: AssetInfo) -> Result<SwapOffer, AtomicSwapError> {
    SwapOffer::new(
        "offer-integration".to_string(),
        "GMAKER".to_string(),
        maker_asset,
        taker_asset,
        10_000,
        5_000,
        1_000,
        1_720,
    )
}

#[test]
fn an_offer_between_two_well_formed_assets_is_created() {
    let offer = build(usdc(), AssetInfo::xlm()).expect("valid assets must be accepted");

    assert_eq!(offer.asset_pair().0, format!("USDC:{USDC_ISSUER}"));
    assert_eq!(offer.asset_pair().1, "XLM");
    assert_eq!(offer.maker, "GMAKER");
    assert_eq!(offer.maker_amount, 10_000);
    assert_eq!(offer.taker_amount, 5_000);
}

#[test]
fn an_invalid_maker_or_taker_identifier_creates_nothing() {
    let mut bad_code = usdc();
    bad_code.asset = Asset::Custom("USDC!".to_string());
    let error = build(bad_code, AssetInfo::xlm()).expect_err("invalid maker code is refused");
    assert!(matches!(
        error,
        AtomicSwapError::InvalidAssetIdentifier { .. }
    ));
    assert!(error.to_string().contains("USDC!"));

    let mut bad_issuer = usdc();
    bad_issuer.issuer = Some("not-an-account".to_string());
    let error = build(usdc(), bad_issuer).expect_err("invalid taker issuer is refused");
    assert!(matches!(
        error,
        AtomicSwapError::InvalidAssetIdentifier { .. }
    ));
    assert!(error.to_string().contains("not a valid Stellar account id"));

    // Neither call produced an offer, so there is no partial state to clean up.
    assert!(build(usdc(), AssetInfo::xlm()).is_ok());
}

#[test]
fn asset_identifier_boundaries_follow_stellar_rules() {
    // Exactly the maximum code length is valid; one more character is not.
    let max_code = "A".repeat(MAX_ASSET_CODE_LEN);
    assert!(
        AssetInfo::custom(max_code.clone(), USDC_ISSUER.to_string(), 7)
            .validate_identifier()
            .is_ok()
    );
    assert!(
        AssetInfo::custom(format!("{max_code}A"), USDC_ISSUER.to_string(), 7)
            .validate_identifier()
            .is_err()
    );

    // Exactly the account-id length with the right prefix and alphabet is valid.
    let exact_issuer = format!("G{}", "A".repeat(STELLAR_ACCOUNT_ID_LEN - 1));
    assert!(
        AssetInfo::custom("USDC".to_string(), exact_issuer.clone(), 7)
            .validate_identifier()
            .is_ok()
    );
    assert!(
        AssetInfo::custom("USDC".to_string(), format!("{exact_issuer}A"), 7)
            .validate_identifier()
            .is_err()
    );
    assert!(
        AssetInfo::custom("USDC".to_string(), format!("H{}", &exact_issuer[1..]), 7)
            .validate_identifier()
            .is_err()
    );
}

//! Integration coverage for rejecting expired offers before signing (#389).

use atomic_swap::{AssetInfo, AtomicSwapError, SwapOffer};

const USDC_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

fn live_offer() -> SwapOffer {
    SwapOffer::new(
        "offer-signing".to_string(),
        "GMAKER".to_string(),
        AssetInfo::custom("USDC".to_string(), USDC_ISSUER.to_string(), 7),
        AssetInfo::xlm(),
        10_000,
        5_000,
        1_000,
        1_720,
    )
    .expect("valid offer")
}

#[test]
fn an_offer_is_signable_until_the_ledger_before_its_deadline() {
    let offer = live_offer();

    let signature = offer.sign(1_000).expect("fresh offer must sign");
    assert_eq!(signature.offer_id, "offer-signing");
    assert_eq!(signature.signed_at_ledger, 1_000);
    assert_eq!(signature.digest.len(), 64);

    // Signing does not mutate the offer; it can be re-signed while live.
    assert_eq!(offer.sign(1_719).unwrap().digest, signature.digest);
    assert_eq!(offer.expires_at_ledger, 1_720);
}

#[test]
fn signing_at_or_after_the_deadline_is_refused_with_an_actionable_error() {
    let offer = live_offer();

    let error = offer
        .sign(1_720)
        .expect_err("an expired offer must not produce signing material");
    match error {
        AtomicSwapError::OfferExpired {
            offer_id,
            expires_at_ledger,
            current_ledger,
        } => {
            assert_eq!(offer_id, "offer-signing");
            assert_eq!(expires_at_ledger, 1_720);
            assert_eq!(current_ledger, 1_720);
        }
        other => panic!("expected OfferExpired, got {other:?}"),
    }

    let message = offer.sign(1_900).unwrap_err().to_string();
    assert!(message.contains("offer-signing"));
    assert!(message.contains("1720"));
    assert!(message.contains("1900"));
}

#[test]
fn an_expired_offer_is_still_retained_and_reports_expiry() {
    let offer = live_offer();

    // The rejected signing attempt must leave the offer exactly as it was,
    // including its original deadline, so an operator can inspect and replace
    // it rather than debugging a mutated record.
    let _ = offer.sign(5_000).unwrap_err();
    assert!(offer.is_expired(5_000));
    assert!(!offer.is_expired(1_719));
    assert_eq!(offer.expires_at_ledger, 1_720);
    assert_eq!(offer.maker_amount, 10_000);
    assert_eq!(offer.taker_amount, 5_000);
}

#[test]
fn the_signing_commitment_covers_every_term_of_the_offer() {
    let base = live_offer().sign(1_500).unwrap().digest;

    let mut cheaper = live_offer();
    cheaper.taker_amount -= 1;
    assert_ne!(cheaper.sign(1_500).unwrap().digest, base);

    let mut longer = live_offer();
    longer.expires_at_ledger += 1;
    assert_ne!(longer.sign(1_500).unwrap().digest, base);

    let mut different_pair = live_offer();
    different_pair.taker_asset = AssetInfo::custom("EURC".to_string(), USDC_ISSUER.to_string(), 7);
    assert_ne!(different_pair.sign(1_500).unwrap().digest, base);
}

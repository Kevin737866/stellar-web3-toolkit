//! End-to-end example integration for the NFT drop + collection access control.
//!
//! This walks through a real drop where privileged drop operations are
//! delegated to the collection's role registry (issue #148):
//!   1. the access-control contract is deployed and the collection registered,
//!   2. a curator is granted `PERM_ADMIN` for the collection,
//!   3. the curator — not the drop admin — opens the public sale phase,
//!   4. a collector blind mints, and the curator later reveals the metadata.
//!
//! Run with: `cargo test -p nft-drop --test integration`

use collection_access_control::{
    CollectionAccessControl, CollectionAccessControlClient, PERM_ADMIN,
};
use nft_drop::{NftDropContract, NftDropContractClient, SalePhase};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::token::{StellarAssetClient, TokenClient};
use soroban_sdk::{Address, Env, String};

#[test]
fn access_control_delegates_drop_administration() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let curator = Address::generate(&env);
    let collector = Address::generate(&env);
    let stranger = Address::generate(&env);

    let payment = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();

    // 1. Deploy the collection access-control registry.
    let acl_id = env.register_contract(None, CollectionAccessControl);
    let acl = CollectionAccessControlClient::new(&env, &acl_id);
    acl.initialize(&admin);

    // 2. Deploy the drop and point it at the registry.
    let drop_id = env.register_contract(None, NftDropContract);
    let drop = NftDropContractClient::new(&env, &drop_id);
    drop.configure(
        &admin,
        &payment,
        &0,
        &100,
        &3,
        &0,
        &0_u64,
        &10_000_u64,
        &0_u64,
        &Some(acl_id.clone()),
    );

    // Register this drop as a collection owned by the admin...
    acl.register_collection(&admin, &drop_id, &admin);
    // ...and grant the curator admin rights over it.
    acl.grant_permissions(&admin, &drop_id, &curator, &PERM_ADMIN);
    assert!(acl.has_permission(&drop_id, &curator, &PERM_ADMIN));
    assert!(!acl.has_permission(&drop_id, &stranger, &PERM_ADMIN));

    // 3. The curator opens the sale; a stranger cannot.
    assert!(drop.try_set_phase(&stranger, &SalePhase::Public).is_err());
    drop.set_phase(&curator, &SalePhase::Public);
    assert_eq!(drop.phase(), SalePhase::Public);

    // 4. A collector blind mints; metadata is hidden until revealed.
    StellarAssetClient::new(&env, &payment).mint(&collector, &500);
    let token_id = drop.blind_mint(&collector);
    assert_eq!(drop.owner_of(&token_id), collector);
    assert!(!drop.is_revealed(&token_id));

    let payment_token = TokenClient::new(&env, &payment);
    assert_eq!(payment_token.balance(&collector), 400);
    assert_eq!(payment_token.balance(&drop_id), 100);

    // The curator reveals the metadata through the registry-granted permission.
    let uri = String::from_str(&env, "ipfs://nft-drop/0");
    drop.reveal(&curator, &token_id, &uri);
    assert!(drop.is_revealed(&token_id));
    assert_eq!(drop.token_uri(&token_id), uri);

    // Revoking the curator's rights takes drop administration away again.
    acl.revoke_permissions(&admin, &drop_id, &curator, &PERM_ADMIN);
    assert!(!acl.has_permission(&drop_id, &curator, &PERM_ADMIN));
    assert!(drop.try_reveal(&curator, &token_id, &uri).is_err());
}

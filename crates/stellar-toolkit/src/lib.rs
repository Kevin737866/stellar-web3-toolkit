//! Stellar Web3 Toolkit Library
//!
//! Provides CLI utilities, build management, and account abstraction session key primitives.

pub mod api_reference_gen;
pub mod cli;
pub mod error;
pub mod example_gallery;
pub mod merkle;
pub mod monitoring_dashboard;
pub mod one_click_airdrop;
pub mod p2p_qr_payment;
pub mod session_keys;
pub mod theme;
pub mod wallet;

pub use api_reference_gen::{ApiFunctionDoc, ApiReferenceGenerator};
pub use cli::ToolkitCommand;
pub use error::{Result, ToolkitError};
pub use example_gallery::{ContractExample, ExampleGalleryRegistry};
pub use merkle::{AirdropLeaf, Hash, MerkleTree};
pub use one_click_airdrop::{
    AirdropClaimRequest, AirdropDistribution, ClaimStatus, OneClickAirdropClaimer,
};
pub use p2p_qr_payment::{P2PQRPaymentFlow, PaymentStatus, QRPaymentRequest};
pub use session_keys::{
    AccountAbstractionManager, Guardian, RecoveryRequest, SessionError, SessionKey, SessionPolicy,
};
pub use theme::{Style, Theme, ThemeEnv, ThemeMode};
pub use wallet::GeneratedWallet;

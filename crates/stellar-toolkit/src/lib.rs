//! Stellar Web3 Toolkit Library
//!
//! Provides CLI utilities, build management, and account abstraction session key primitives.

pub mod api_reference_gen;
pub mod cli;
pub mod error;
pub mod example_gallery;
pub mod glossary;
pub mod migration_diff;
pub mod monitoring_dashboard;
pub mod one_click_airdrop;
pub mod p2p_qr_payment;
pub mod session_keys;
pub mod treasury_stream;
pub mod wallet;

pub use api_reference_gen::{ApiFunctionDoc, ApiReferenceGenerator};
pub use cli::ToolkitCommand;
pub use error::{Result, ToolkitError};
pub use example_gallery::{ContractExample, ExampleGalleryRegistry};
pub use glossary::{Glossary, GlossaryEntry, Lookup, MatchKind};
pub use migration_diff::{
    diff_specs, ArgumentChange, ContractSpec, EventSpec, FunctionSpec, SpecDiff,
};
pub use one_click_airdrop::{AirdropClaimRequest, ClaimStatus, OneClickAirdropClaimer};
pub use p2p_qr_payment::{P2PQRPaymentFlow, PaymentStatus, QRPaymentRequest};
pub use session_keys::{
    AccountAbstractionManager, Guardian, RecoveryRequest, RecoveryVeto, SessionError, SessionKey,
    SessionPolicy, VetoGuardian,
};
pub use treasury_stream::{
    StreamCancellation, StreamRelease, StreamStatus, Treasury, TreasuryStream,
};

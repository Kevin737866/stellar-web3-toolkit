//! Stellar Web3 Toolkit Library
//!
//! Provides CLI utilities, build management, and account abstraction session key primitives.

pub mod api_reference_gen;
pub mod cli;
pub mod error;
pub mod example_gallery;
pub mod gas_simulator;
pub mod help_text;
pub mod monitoring_dashboard;
pub mod one_click_airdrop;
pub mod p2p_qr_payment;
pub mod scaffolder;
pub mod session_keys;
pub mod state_inspector;
pub mod wallet;

pub use api_reference_gen::{ApiFunctionDoc, ApiReferenceGenerator};
pub use cli::{App, ToolkitCommand};
pub use error::{Result, ToolkitError};
pub use example_gallery::{ContractExample, ExampleGalleryRegistry};
pub use gas_simulator::{FeeBump, FeeEstimate, FeeSchedule, GasSimulator, TransactionProfile};
pub use help_text::{help_width, render_command_help, wrap, HelpEntry};
pub use one_click_airdrop::{AirdropClaimRequest, ClaimStatus, OneClickAirdropClaimer};
pub use p2p_qr_payment::{P2PQRPaymentFlow, PaymentStatus, QRPaymentRequest};
pub use scaffolder::{LintFinding, LintReport, LintSeverity, ScaffoldOptions, Scaffolder};
pub use session_keys::{
    AccountAbstractionManager, Guardian, RecoveryRequest, SessionError, SessionKey, SessionPolicy,
};
pub use state_inspector::{Durability, StateEntry, StateInspector, StatePage, StateQuery};

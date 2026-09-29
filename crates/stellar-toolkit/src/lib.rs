//! Stellar Web3 Toolkit Library
//!
//! Provides CLI utilities, build management, and account abstraction session key primitives.

pub mod api_reference_gen;
pub mod cli;
pub mod env_config;
pub mod error;
pub mod example_gallery;
pub mod gas_simulator;
pub mod glossary;
pub mod help_text;
pub mod invariants;
pub mod key_hygiene;
pub mod merkle;
pub mod migration_diff;
pub mod monitoring_dashboard;
pub mod one_click_airdrop;
pub mod p2p_qr_payment;
pub mod scaffolder;
pub mod session_keys;
pub mod state_inspector;
pub mod theme;
pub mod treasury_stream;
pub mod ts_codegen;
pub mod wallet;

pub use api_reference_gen::{ApiFunctionDoc, ApiReferenceGenerator};
pub use cli::{App, ToolkitCommand};
pub use env_config::{
    validate_directory, EnvConfig, EnvValidation, EnvValidationReport, Finding as EnvFinding,
    Severity as EnvSeverity, ENVIRONMENTS,
};
pub use error::{Result, ToolkitError};
pub use example_gallery::{ContractExample, ExampleGalleryRegistry};
pub use gas_simulator::{FeeBump, FeeEstimate, FeeSchedule, GasSimulator, TransactionProfile};
pub use help_text::{help_width, render_command_help, wrap, HelpEntry};
pub use invariants::{run_suite, InvariantReport, Prng, SuiteReport};
pub use key_hygiene::{scan_paths, scan_text, Finding as SecretFinding, ScanReport, SecretKind};
pub use one_click_airdrop::{AirdropClaimRequest, ClaimStatus, OneClickAirdropClaimer};
pub use p2p_qr_payment::{P2PQRPaymentFlow, PaymentStatus, QRPaymentRequest};
pub use scaffolder::{LintFinding, LintReport, LintSeverity, ScaffoldOptions, Scaffolder};
pub use session_keys::{
    AccountAbstractionManager, Guardian, RecoveryRequest, RecoveryVeto, SessionError, SessionKey,
    SessionPolicy, VetoGuardian,
};
pub use state_inspector::{Durability, StateEntry, StateInspector, StatePage, StateQuery};
pub use treasury_stream::{
    StreamCancellation, StreamRelease, StreamStatus, Treasury, TreasuryStream,
};

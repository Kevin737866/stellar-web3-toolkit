//! Stellar Web3 Toolkit Library
//!
//! Provides CLI utilities, build management, and account abstraction session key primitives.

pub mod anomaly;
pub mod api_reference_gen;
pub mod audit_allowlist;
pub mod bridge_oracle;
pub mod cli;
pub mod compliance;
pub mod conviction;
pub mod env_config;
pub mod error;
pub mod example_gallery;
pub mod gas_simulator;
pub mod glossary;
pub mod help_text;
pub mod horizon;
pub mod hsm;
pub mod invariants;
pub mod keeper;
pub mod key_hygiene;
pub mod merkle;
pub mod migration_diff;
pub mod monitoring_dashboard;
pub mod onboarding;
pub mod one_click_airdrop;
pub mod oracle_resilience;
pub mod p2p_qr_payment;
pub mod presigned_deploy;
pub mod scaffolder;
pub mod session_keys;
pub mod signal_sync;
pub mod state_inspector;
pub mod theme;
pub mod timelock;
pub mod treasury_stream;
pub mod ts_codegen;
pub mod wallet;
pub mod wasm_provenance;

pub use wallet::{AllowedNetwork, fund_account_on};

pub use anomaly::{
    catalog as anomaly_catalog, AnomalyDetector, AnomalyReport, AnomalyRule, Baseline, Direction,
    MetricVerdict, Series,
};
pub use api_reference_gen::{ApiFunctionDoc, ApiReferenceGenerator};
pub use bridge_oracle::{
    OracleConfirmation, OracleQuorumError, OracleSet, QuorumReport, QuorumVerdict, MAX_ORACLES,
};
pub use cli::{App, ToolkitCommand};
pub use compliance::{
    ComplianceCategory, ComplianceChecklist, ComplianceItem, VerificationHarness,
    VerificationHarnessReport, VerificationStep,
};
pub use conviction::{
    conviction_weight, decayed_weight, isqrt, ProposalMetadata, ProposalValidationError,
    MAX_LOCK_LEDGERS, MAX_PROPOSAL_DESCRIPTION_LEN, MAX_PROPOSAL_TITLE_LEN, WEIGHT_SCALE,
};
pub use env_config::{
    validate_directory, EnvConfig, EnvValidation, EnvValidationReport, Finding as EnvFinding,
    Severity as EnvSeverity, ENVIRONMENTS,
};
pub use error::{Result, ToolkitError};
pub use example_gallery::{ContractExample, ExampleGalleryRegistry};
pub use gas_simulator::{FeeBump, FeeBreakdown, FeeBreakdownPercents, FeeEstimate, FeeEstimateReport, FeeSchedule, GasSimulator, TransactionProfile};
pub use help_text::{help_width, render_command_help, wrap, HelpEntry};
pub use horizon::{
    page_path, paginate, Cursor, HorizonPage, HorizonPaginationError, DEFAULT_LIMIT, MAX_LIMIT,
};
pub use hsm::{ColdSigner, HsmError, RotationAudit, RotationRecord, SignRequest, StubHsm};
pub use invariants::{run_suite, InvariantReport, Prng, SuiteReport};
pub use keeper::{
    BudgetedKeeper, ExecutionBudget, ExecutionReport, KeeperBudgetConfig, KeeperBudgetError,
    KeeperOperation, KeeperStrategy,
};
pub use key_hygiene::{
    scan_paths, scan_text, Finding as SecretFinding, SarifLog, SarifResult, SarifRule, SarifRun,
    ScanReport, SecretKind,
};
pub use one_click_airdrop::{AirdropClaimRequest, ClaimStatus, OneClickAirdropClaimer};
pub use oracle_resilience::{assess_quorum_liveness, LivenessError, QuorumLiveness};
pub use p2p_qr_payment::{P2PQRPaymentFlow, PaymentStatus, QRPaymentRequest};
pub use presigned_deploy::{
    submit_presigned_deployment, PresignedDeployError, PresignedDeployReceipt,
    PresignedDeployRequest, RpcHttpResponse, RpcTransport, SubmissionStatus, TransportError,
    UreqRpcTransport, WasmArtifactCheck, DEFAULT_MAX_RETRIES, DEFAULT_TIMEOUT_SECS,
    MAX_ALLOWED_RETRIES, MAX_ENVELOPE_XDR_BYTES, MAX_TIMEOUT_SECS,
};
pub use scaffolder::{LintFinding, LintReport, LintSeverity, ScaffoldOptions, Scaffolder};
pub use session_keys::{
    format_active_session_summaries, format_unix_timestamp_utc, AccountAbstractionManager,
    Guardian, RecoveryRequest, RecoveryVeto, SessionError, SessionKey, SessionKeySummary,
    SessionPolicy, VetoGuardian,
};
pub use signal_sync::{Signal, SignalSnapshot, SyncError, SyncReport, SNAPSHOT_VERSION};
pub use state_inspector::{Durability, StateEntry, StateInspector, StatePage, StateQuery};
pub use timelock::{
    authorize_governance_action, DelayKind, GovernanceAction, GovernanceRole,
    ProposalQuorumProgress, TimelockError, TimelockPolicy, MAX_PAUSE_DELAY, MIN_PAUSE_DELAY,
};
pub use treasury_stream::{
    StreamCancellation, StreamRelease, StreamStatus, Treasury, TreasuryStream,
};
pub use wasm_provenance::{
    verify as verify_wasm_provenance, ArtifactProvenance, ArtifactStatus, ArtifactVerdict,
    BuildInputs, ManifestError, ProvenanceManifest, ProvenanceReport, DEFAULT_MANIFEST,
    DEFAULT_WASM_DIR, PROVENANCE_FILE, PROVENANCE_SCHEMA_VERSION,
};

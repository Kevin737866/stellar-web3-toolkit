//! Pre-signed deployment transaction submission via Soroban RPC.
//!
//! This module implements offline-signed / pre-signed deployment transaction
//! submission against a Soroban RPC `sendTransaction` JSON-RPC 2.0 endpoint.
//!
//! # Design & Invariants
//!
//! 1. **Build reproducibility**: When a [`WasmArtifactCheck`] is supplied, the
//!    local `.wasm` artifact's SHA-256 digest is computed and compared against
//!    the expected 64-character hex digest *before* any network request is sent.
//!    A mismatch aborts submission immediately.
//! 2. **Explicit validation (no silent defaults)**: The caller must provide a
//!    valid `http://` or `https://` RPC URL and a syntactically valid base64
//!    transaction envelope XDR within [`MAX_ENVELOPE_XDR_BYTES`]. Invalid retry
//!    counts, timeouts, or blank network passphrases are rejected explicitly.
//! 3. **Network errors & recoverable submission**:
//!    - Soroban RPC `DUPLICATE` responses are treated as recoverable idempotent
//!      outcomes ([`SubmissionStatus::Duplicate`]) returning the transaction hash.
//!    - Soroban RPC `TRY_AGAIN_LATER` responses and transient transport/5xx/429
//!      errors are retried up to `max_retries` times.
//!    - Non-retryable 4xx errors, JSON-RPC error objects, and `ERROR`
//!      transaction rejections fail immediately with actionable diagnostics.
//! 4. **No partial state updates on failure**: All inputs and optional WASM
//!    digests are validated before network I/O. If a `receipt_path` is
//!    configured, the JSON receipt is written atomically (write-then-rename)
//!    only after submission succeeds.
//!
//! # Compatibility
//!
//! Only the standard Soroban RPC `sendTransaction` response fields (`status`,
//! `hash`, `latestLedger`, `latestLedgerCloseTime`, `errorResultXdr`) are
//! inspected; unknown fields added by newer RPC releases are ignored.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

/// Maximum accepted length of a base64-encoded transaction envelope XDR (256 KiB).
pub const MAX_ENVELOPE_XDR_BYTES: usize = 256 * 1024;
/// Default number of retries on transient network or `TRY_AGAIN_LATER` responses.
pub const DEFAULT_MAX_RETRIES: u32 = 2;
/// Upper bound on `max_retries` to prevent unbounded retry loops.
pub const MAX_ALLOWED_RETRIES: u32 = 10;
/// Default per-attempt HTTP timeout in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Upper bound on per-attempt HTTP timeout in seconds.
pub const MAX_TIMEOUT_SECS: u64 = 300;

/// Errors returned when validating or submitting a pre-signed deployment transaction.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PresignedDeployError {
    #[error("invalid RPC URL: {0}")]
    InvalidRpcUrl(String),
    #[error("invalid transaction envelope XDR: {0}")]
    InvalidEnvelope(String),
    #[error("invalid network passphrase: {0}")]
    InvalidNetworkPassphrase(String),
    #[error("invalid expected WASM SHA-256 hash: {0}")]
    InvalidExpectedWasmHash(String),
    #[error("invalid submission configuration: {0}")]
    InvalidConfig(String),
    #[error("failed to read WASM artifact `{path}`: {reason}")]
    WasmReadFailed { path: String, reason: String },
    #[error("WASM artifact `{path}` SHA-256 mismatch: expected {expected}, got {actual}")]
    WasmHashMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error(
        "network error contacting `{url}` (status={status:?}, retryable={retryable}): {message}"
    )]
    Network {
        url: String,
        status: Option<u16>,
        message: String,
        retryable: bool,
    },
    #[error("Soroban RPC error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("invalid Soroban RPC response: {0}")]
    InvalidRpcResponse(String),
    #[error("deployment transaction rejected by RPC (hash={hash:?}): {message}")]
    TransactionRejected {
        hash: Option<String>,
        error_result_xdr: Option<String>,
        message: String,
    },
    #[error(
        "submission remained retryable (`{last_status}`) after {attempts} attempt(s) (hash={hash:?})"
    )]
    RetryableSubmissionExhausted {
        attempts: u32,
        last_status: String,
        hash: Option<String>,
    },
    #[error("failed to write deployment receipt `{path}`: {reason}")]
    ReceiptWriteFailed { path: String, reason: String },
}

/// Optional build-reproducibility check for the `.wasm` artifact being deployed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmArtifactCheck {
    /// Path to the compiled `.wasm` artifact on disk.
    pub wasm_path: PathBuf,
    /// Expected 64-character hexadecimal SHA-256 digest of the artifact.
    pub expected_sha256: String,
}

impl WasmArtifactCheck {
    /// Validate the expected digest format, read the `.wasm` file, and verify
    /// that its SHA-256 matches `expected_sha256`.
    ///
    /// Returns the verified lowercase hex digest on success.
    pub fn verify(&self) -> std::result::Result<String, PresignedDeployError> {
        let expected = self.expected_sha256.trim().to_ascii_lowercase();
        if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(PresignedDeployError::InvalidExpectedWasmHash(format!(
                "expected 64 hexadecimal characters, got `{}`",
                self.expected_sha256
            )));
        }

        let bytes =
            std::fs::read(&self.wasm_path).map_err(|e| PresignedDeployError::WasmReadFailed {
                path: self.wasm_path.display().to_string(),
                reason: e.to_string(),
            })?;
        if bytes.is_empty() {
            return Err(PresignedDeployError::WasmReadFailed {
                path: self.wasm_path.display().to_string(),
                reason: "WASM artifact file is empty".to_string(),
            });
        }

        let actual = hex::encode(Sha256::digest(&bytes));
        if actual != expected {
            return Err(PresignedDeployError::WasmHashMismatch {
                path: self.wasm_path.display().to_string(),
                expected,
                actual,
            });
        }
        Ok(actual)
    }
}

/// Request parameters for submitting a pre-signed deployment transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresignedDeployRequest {
    /// Soroban RPC endpoint URL (`http://` or `https://`).
    pub rpc_url: String,
    /// Base64-encoded signed Stellar transaction envelope XDR.
    pub envelope_xdr: String,
    /// Optional network passphrase metadata recorded in the receipt.
    pub network_passphrase: Option<String>,
    /// Optional local WASM artifact SHA-256 check enforced before submission.
    pub wasm_check: Option<WasmArtifactCheck>,
    /// Maximum retries for `TRY_AGAIN_LATER` or transient network failures.
    pub max_retries: u32,
    /// Per-attempt HTTP request timeout in seconds.
    pub timeout_secs: u64,
    /// Optional path where a JSON receipt is atomically written on success.
    pub receipt_path: Option<PathBuf>,
}

impl PresignedDeployRequest {
    /// Construct a request with explicit `rpc_url` and `envelope_xdr` and
    /// conservative retry/timeout bounds.
    pub fn new(rpc_url: impl Into<String>, envelope_xdr: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            envelope_xdr: envelope_xdr.into(),
            network_passphrase: None,
            wasm_check: None,
            max_retries: DEFAULT_MAX_RETRIES,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            receipt_path: None,
        }
    }
}

/// Normalized, validated submission inputs ready for RPC transmission.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedRequest {
    rpc_url: String,
    envelope_xdr: String,
    network_passphrase: Option<String>,
    verified_wasm_sha256: Option<String>,
    max_retries: u32,
    timeout_secs: u64,
    receipt_path: Option<PathBuf>,
}

/// Outcome status of an accepted pre-signed deployment submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SubmissionStatus {
    /// Accepted by Soroban RPC into the mempool.
    Pending,
    /// Already present on the network (recoverable/idempotent).
    Duplicate,
}

/// Structured receipt returned (and optionally persisted) after submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresignedDeployReceipt {
    pub rpc_url: String,
    pub tx_hash: String,
    pub status: SubmissionStatus,
    pub latest_ledger: Option<u64>,
    pub latest_ledger_close_time: Option<String>,
    pub network_passphrase: Option<String>,
    pub verified_wasm_sha256: Option<String>,
    pub attempts: u32,
}

impl PresignedDeployReceipt {
    /// Serialize the receipt as pretty-printed JSON.
    pub fn to_json(&self) -> std::result::Result<String, PresignedDeployError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| PresignedDeployError::InvalidRpcResponse(e.to_string()))
    }
}

/// Raw HTTP response returned by an [`RpcTransport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcHttpResponse {
    pub status: u16,
    pub body: String,
}

/// Transport-level failure (DNS, TCP, TLS, timeout) before receiving an HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportError {
    pub message: String,
    pub retryable: bool,
}

/// Pluggable HTTP transport for Soroban JSON-RPC 2.0 requests.
pub trait RpcTransport {
    fn send_json_rpc(
        &self,
        url: &str,
        body: &str,
        timeout_secs: u64,
    ) -> std::result::Result<RpcHttpResponse, TransportError>;
}

/// Default blocking HTTP transport backed by `ureq`.
#[derive(Debug, Default, Clone, Copy)]
pub struct UreqRpcTransport;

impl RpcTransport for UreqRpcTransport {
    fn send_json_rpc(
        &self,
        url: &str,
        body: &str,
        timeout_secs: u64,
    ) -> std::result::Result<RpcHttpResponse, TransportError> {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(timeout_secs))
            .build();

        match agent
            .post(url)
            .set("Content-Type", "application/json")
            .send_string(body)
        {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.into_string().map_err(|e| TransportError {
                    message: format!("failed to read RPC response body: {e}"),
                    retryable: true,
                })?;
                Ok(RpcHttpResponse { status, body })
            }
            Err(ureq::Error::Status(status, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                Ok(RpcHttpResponse { status, body })
            }
            Err(ureq::Error::Transport(err)) => Err(TransportError {
                message: err.to_string(),
                retryable: true,
            }),
        }
    }
}

/// Validate and submit a pre-signed deployment transaction using `transport`.
///
/// All inputs (RPC URL, base64 envelope XDR, retry/timeout bounds, and optional
/// WASM SHA-256 check) are validated before any network call is made.
pub fn submit_presigned_deployment(
    request: &PresignedDeployRequest,
    transport: &dyn RpcTransport,
) -> std::result::Result<PresignedDeployReceipt, PresignedDeployError> {
    let validated = validate_request(request)?;
    let rpc_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sendTransaction",
        "params": {
            "transaction": validated.envelope_xdr,
        }
    })
    .to_string();

    let total_attempts = validated.max_retries + 1;
    let mut last_retryable_status: Option<String> = None;
    let mut last_hash: Option<String> = None;

    for attempt in 1..=total_attempts {
        let response =
            match transport.send_json_rpc(&validated.rpc_url, &rpc_body, validated.timeout_secs) {
                Ok(resp) => resp,
                Err(err) => {
                    if err.retryable && attempt < total_attempts {
                        continue;
                    }
                    return Err(PresignedDeployError::Network {
                        url: validated.rpc_url,
                        status: None,
                        message: err.message,
                        retryable: err.retryable,
                    });
                }
            };

        if response.status == 429 || response.status >= 500 {
            if attempt < total_attempts {
                continue;
            }
            return Err(PresignedDeployError::Network {
                url: validated.rpc_url,
                status: Some(response.status),
                message: summarize_body(&response.body),
                retryable: true,
            });
        }

        if !(200..300).contains(&response.status) {
            return Err(PresignedDeployError::Network {
                url: validated.rpc_url,
                status: Some(response.status),
                message: summarize_body(&response.body),
                retryable: false,
            });
        }

        match parse_send_transaction_response(&response.body)? {
            ParsedRpcOutcome::Accepted {
                status,
                tx_hash,
                latest_ledger,
                latest_ledger_close_time,
            } => {
                let receipt = PresignedDeployReceipt {
                    rpc_url: validated.rpc_url,
                    tx_hash,
                    status,
                    latest_ledger,
                    latest_ledger_close_time,
                    network_passphrase: validated.network_passphrase,
                    verified_wasm_sha256: validated.verified_wasm_sha256,
                    attempts: attempt,
                };
                if let Some(path) = &validated.receipt_path {
                    write_receipt_atomic(path, &receipt)?;
                }
                return Ok(receipt);
            }
            ParsedRpcOutcome::TryAgainLater { hash } => {
                last_retryable_status = Some("TRY_AGAIN_LATER".to_string());
                last_hash = hash;
                if attempt < total_attempts {
                    continue;
                }
            }
        }
    }

    Err(PresignedDeployError::RetryableSubmissionExhausted {
        attempts: total_attempts,
        last_status: last_retryable_status.unwrap_or_else(|| "TRY_AGAIN_LATER".to_string()),
        hash: last_hash,
    })
}

enum ParsedRpcOutcome {
    Accepted {
        status: SubmissionStatus,
        tx_hash: String,
        latest_ledger: Option<u64>,
        latest_ledger_close_time: Option<String>,
    },
    TryAgainLater {
        hash: Option<String>,
    },
}

fn validate_request(
    request: &PresignedDeployRequest,
) -> std::result::Result<ValidatedRequest, PresignedDeployError> {
    let rpc_url = validate_rpc_url(&request.rpc_url)?;
    let envelope_xdr = validate_envelope_xdr(&request.envelope_xdr)?;

    let network_passphrase = match &request.network_passphrase {
        None => None,
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(PresignedDeployError::InvalidNetworkPassphrase(
                    "network passphrase must not be empty when provided".to_string(),
                ));
            }
            Some(trimmed.to_string())
        }
    };

    if request.max_retries > MAX_ALLOWED_RETRIES {
        return Err(PresignedDeployError::InvalidConfig(format!(
            "max_retries ({}) exceeds maximum allowed ({MAX_ALLOWED_RETRIES})",
            request.max_retries
        )));
    }

    if request.timeout_secs == 0 || request.timeout_secs > MAX_TIMEOUT_SECS {
        return Err(PresignedDeployError::InvalidConfig(format!(
            "timeout_secs ({}) must be between 1 and {MAX_TIMEOUT_SECS}",
            request.timeout_secs
        )));
    }

    let verified_wasm_sha256 = match &request.wasm_check {
        Some(check) => Some(check.verify()?),
        None => None,
    };

    Ok(ValidatedRequest {
        rpc_url,
        envelope_xdr,
        network_passphrase,
        verified_wasm_sha256,
        max_retries: request.max_retries,
        timeout_secs: request.timeout_secs,
        receipt_path: request.receipt_path.clone(),
    })
}

fn validate_rpc_url(raw: &str) -> std::result::Result<String, PresignedDeployError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(PresignedDeployError::InvalidRpcUrl(
            "RPC URL must not be empty".to_string(),
        ));
    }
    let parsed = url::Url::parse(trimmed).map_err(|e| {
        PresignedDeployError::InvalidRpcUrl(format!("malformed URL `{trimmed}`: {e}"))
    })?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(PresignedDeployError::InvalidRpcUrl(format!(
                "unsupported URL scheme `{other}`; expected `http` or `https`"
            )));
        }
    }
    if parsed.host_str().is_none() {
        return Err(PresignedDeployError::InvalidRpcUrl(format!(
            "RPC URL `{trimmed}` is missing a host"
        )));
    }
    Ok(trimmed.to_string())
}

fn validate_envelope_xdr(raw: &str) -> std::result::Result<String, PresignedDeployError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(PresignedDeployError::InvalidEnvelope(
            "envelope XDR must not be empty".to_string(),
        ));
    }
    if trimmed.len() > MAX_ENVELOPE_XDR_BYTES {
        return Err(PresignedDeployError::InvalidEnvelope(format!(
            "envelope XDR size ({} bytes) exceeds limit ({MAX_ENVELOPE_XDR_BYTES} bytes)",
            trimmed.len()
        )));
    }
    if !is_valid_base64(trimmed) {
        return Err(PresignedDeployError::InvalidEnvelope(
            "envelope XDR must be valid standard base64 without embedded whitespace".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

fn is_valid_base64(input: &str) -> bool {
    let bytes = input.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return false;
    }
    let pad = bytes.iter().rev().take_while(|&&b| b == b'=').count();
    if pad > 2 {
        return false;
    }
    let body_len = bytes.len() - pad;
    if body_len == 0 {
        return false;
    }
    bytes[..body_len]
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

fn parse_send_transaction_response(
    body: &str,
) -> std::result::Result<ParsedRpcOutcome, PresignedDeployError> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| PresignedDeployError::InvalidRpcResponse(format!("invalid JSON: {e}")))?;

    if let Some(error) = value.get("error") {
        let code = error
            .get("code")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(-32000);
        let message = error
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown JSON-RPC error")
            .to_string();
        return Err(PresignedDeployError::Rpc { code, message });
    }

    let result = value.get("result").ok_or_else(|| {
        PresignedDeployError::InvalidRpcResponse("response is missing `result` object".to_string())
    })?;

    let status = result
        .get("status")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            PresignedDeployError::InvalidRpcResponse("`result.status` must be a string".to_string())
        })?;

    let hash = result
        .get("hash")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let latest_ledger = result
        .get("latestLedger")
        .and_then(serde_json::Value::as_u64);

    let latest_ledger_close_time = result.get("latestLedgerCloseTime").and_then(|v| {
        v.as_str()
            .map(ToOwned::to_owned)
            .or_else(|| v.as_u64().map(|n| n.to_string()))
    });

    match status {
        "PENDING" => {
            let tx_hash = hash.ok_or_else(|| {
                PresignedDeployError::InvalidRpcResponse(
                    "`PENDING` response is missing a non-empty `hash`".to_string(),
                )
            })?;
            Ok(ParsedRpcOutcome::Accepted {
                status: SubmissionStatus::Pending,
                tx_hash,
                latest_ledger,
                latest_ledger_close_time,
            })
        }
        "DUPLICATE" => {
            let tx_hash = hash.ok_or_else(|| {
                PresignedDeployError::InvalidRpcResponse(
                    "`DUPLICATE` response is missing a non-empty `hash`".to_string(),
                )
            })?;
            Ok(ParsedRpcOutcome::Accepted {
                status: SubmissionStatus::Duplicate,
                tx_hash,
                latest_ledger,
                latest_ledger_close_time,
            })
        }
        "TRY_AGAIN_LATER" => Ok(ParsedRpcOutcome::TryAgainLater { hash }),
        "ERROR" => {
            let error_result_xdr = result
                .get("errorResultXdr")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned);
            let message = match &error_result_xdr {
                Some(xdr) => format!("RPC returned status ERROR (errorResultXdr={xdr})"),
                None => "RPC returned status ERROR".to_string(),
            };
            Err(PresignedDeployError::TransactionRejected {
                hash,
                error_result_xdr,
                message,
            })
        }
        other => Err(PresignedDeployError::InvalidRpcResponse(format!(
            "unrecognized `sendTransaction` status `{other}`"
        ))),
    }
}

fn summarize_body(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return "empty response body".to_string();
    }
    const MAX_LEN: usize = 200;
    if trimmed.chars().count() > MAX_LEN {
        let prefix: String = trimmed.chars().take(MAX_LEN).collect();
        format!("{prefix}...")
    } else {
        trimmed.to_string()
    }
}

fn write_receipt_atomic(
    path: &Path,
    receipt: &PresignedDeployReceipt,
) -> std::result::Result<(), PresignedDeployError> {
    let json = receipt.to_json()?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                PresignedDeployError::ReceiptWriteFailed {
                    path: path.display().to_string(),
                    reason: e.to_string(),
                }
            })?;
        }
    }

    let tmp_name = format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("presigned-deploy-receipt")
    );
    let tmp_path = path.with_file_name(tmp_name);

    std::fs::write(&tmp_path, json).map_err(|e| PresignedDeployError::ReceiptWriteFailed {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(PresignedDeployError::ReceiptWriteFailed {
            path: path.display().to_string(),
            reason: e.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    struct MockTransport {
        responses: RefCell<VecDeque<std::result::Result<RpcHttpResponse, TransportError>>>,
        calls: RefCell<Vec<(String, String)>>,
    }

    impl MockTransport {
        fn new(responses: Vec<std::result::Result<RpcHttpResponse, TransportError>>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
                calls: RefCell::new(Vec::new()),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.borrow().len()
        }
    }

    impl RpcTransport for MockTransport {
        fn send_json_rpc(
            &self,
            url: &str,
            body: &str,
            _timeout_secs: u64,
        ) -> std::result::Result<RpcHttpResponse, TransportError> {
            self.calls
                .borrow_mut()
                .push((url.to_string(), body.to_string()));
            self.responses
                .borrow_mut()
                .pop_front()
                .expect("mock transport ran out of scripted responses")
        }
    }

    fn ok_response(body: &str) -> std::result::Result<RpcHttpResponse, TransportError> {
        Ok(RpcHttpResponse {
            status: 200,
            body: body.to_string(),
        })
    }

    #[test]
    fn submits_pending_transaction_and_returns_receipt() {
        let transport = MockTransport::new(vec![ok_response(
            r#"{"jsonrpc":"2.0","id":1,"result":{"status":"PENDING","hash":"abc123","latestLedger":42,"latestLedgerCloseTime":"1700000000"}}"#,
        )]);
        let mut req = PresignedDeployRequest::new("https://soroban-testnet.stellar.org", "AAAA==");
        req.network_passphrase = Some("Test SDF Network ; September 2015".to_string());

        let receipt = submit_presigned_deployment(&req, &transport).expect("submission succeeds");
        assert_eq!(receipt.status, SubmissionStatus::Pending);
        assert_eq!(receipt.tx_hash, "abc123");
        assert_eq!(receipt.latest_ledger, Some(42));
        assert_eq!(receipt.attempts, 1);
        assert_eq!(transport.call_count(), 1);
    }

    #[test]
    fn treats_duplicate_status_as_recoverable_success() {
        let transport = MockTransport::new(vec![ok_response(
            r#"{"jsonrpc":"2.0","id":1,"result":{"status":"DUPLICATE","hash":"dup999","latestLedger":99}}"#,
        )]);
        let req = PresignedDeployRequest::new("https://soroban-testnet.stellar.org", "AAAA==");

        let receipt = submit_presigned_deployment(&req, &transport).expect("duplicate succeeds");
        assert_eq!(receipt.status, SubmissionStatus::Duplicate);
        assert_eq!(receipt.tx_hash, "dup999");
        assert_eq!(receipt.attempts, 1);
    }

    #[test]
    fn retries_on_try_again_later_and_transient_http_503() {
        let transport = MockTransport::new(vec![
            Ok(RpcHttpResponse {
                status: 503,
                body: "service unavailable".to_string(),
            }),
            ok_response(
                r#"{"jsonrpc":"2.0","id":1,"result":{"status":"TRY_AGAIN_LATER","hash":"retry1"}}"#,
            ),
            ok_response(
                r#"{"jsonrpc":"2.0","id":1,"result":{"status":"PENDING","hash":"retry1","latestLedger":105}}"#,
            ),
        ]);
        let mut req = PresignedDeployRequest::new("https://soroban-testnet.stellar.org", "AAAA==");
        req.max_retries = 2;

        let receipt = submit_presigned_deployment(&req, &transport).expect("retries succeed");
        assert_eq!(receipt.status, SubmissionStatus::Pending);
        assert_eq!(receipt.tx_hash, "retry1");
        assert_eq!(receipt.attempts, 3);
        assert_eq!(transport.call_count(), 3);
    }

    #[test]
    fn rejects_invalid_inputs_before_calling_transport() {
        let transport = MockTransport::new(vec![]);

        let bad_url = PresignedDeployRequest::new("ftp://example.com", "AAAA==");
        assert!(matches!(
            submit_presigned_deployment(&bad_url, &transport),
            Err(PresignedDeployError::InvalidRpcUrl(_))
        ));

        let bad_xdr = PresignedDeployRequest::new("https://rpc.example.com", "not valid base64!");
        assert!(matches!(
            submit_presigned_deployment(&bad_xdr, &transport),
            Err(PresignedDeployError::InvalidEnvelope(_))
        ));

        let mut bad_retries = PresignedDeployRequest::new("https://rpc.example.com", "AAAA==");
        bad_retries.max_retries = MAX_ALLOWED_RETRIES + 1;
        assert!(matches!(
            submit_presigned_deployment(&bad_retries, &transport),
            Err(PresignedDeployError::InvalidConfig(_))
        ));

        let mut bad_timeout = PresignedDeployRequest::new("https://rpc.example.com", "AAAA==");
        bad_timeout.timeout_secs = 0;
        assert!(matches!(
            submit_presigned_deployment(&bad_timeout, &transport),
            Err(PresignedDeployError::InvalidConfig(_))
        ));

        assert_eq!(transport.call_count(), 0);
    }

    #[test]
    fn enforces_envelope_size_boundary() {
        let transport = MockTransport::new(vec![ok_response(
            r#"{"jsonrpc":"2.0","id":1,"result":{"status":"PENDING","hash":"bigok"}}"#,
        )]);
        let exact = "A".repeat(MAX_ENVELOPE_XDR_BYTES);
        let req_ok = PresignedDeployRequest::new("https://rpc.example.com", exact);
        assert!(submit_presigned_deployment(&req_ok, &transport).is_ok());

        let too_big = "A".repeat(MAX_ENVELOPE_XDR_BYTES + 4);
        let req_err = PresignedDeployRequest::new("https://rpc.example.com", too_big);
        assert!(matches!(
            submit_presigned_deployment(&req_err, &transport),
            Err(PresignedDeployError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn does_not_retry_http_400_or_rpc_error_or_tx_rejection() {
        let t_400 = MockTransport::new(vec![Ok(RpcHttpResponse {
            status: 400,
            body: "bad request".to_string(),
        })]);
        let req = PresignedDeployRequest::new("https://rpc.example.com", "AAAA==");
        let err = submit_presigned_deployment(&req, &t_400).unwrap_err();
        assert!(matches!(
            err,
            PresignedDeployError::Network {
                status: Some(400),
                retryable: false,
                ..
            }
        ));
        assert_eq!(t_400.call_count(), 1);

        let t_rpc = MockTransport::new(vec![ok_response(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid params"}}"#,
        )]);
        assert!(matches!(
            submit_presigned_deployment(&req, &t_rpc),
            Err(PresignedDeployError::Rpc { code: -32602, .. })
        ));
        assert_eq!(t_rpc.call_count(), 1);

        let t_rej = MockTransport::new(vec![ok_response(
            r#"{"jsonrpc":"2.0","id":1,"result":{"status":"ERROR","hash":"badtx","errorResultXdr":"AAAA"}}"#,
        )]);
        assert!(matches!(
            submit_presigned_deployment(&req, &t_rej),
            Err(PresignedDeployError::TransactionRejected {
                hash: Some(_),
                error_result_xdr: Some(_),
                ..
            })
        ));
        assert_eq!(t_rej.call_count(), 1);
    }

    #[test]
    fn wasm_hash_mismatch_aborts_before_network_and_without_writing_receipt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wasm_path = dir.path().join("contract.wasm");
        std::fs::write(&wasm_path, b"\0asm\x01\x00\x00\x00").expect("write wasm");
        let receipt_path = dir.path().join("receipt.json");

        let transport = MockTransport::new(vec![]);
        let mut req = PresignedDeployRequest::new("https://rpc.example.com", "AAAA==");
        req.wasm_check = Some(WasmArtifactCheck {
            wasm_path,
            expected_sha256: "0".repeat(64),
        });
        req.receipt_path = Some(receipt_path.clone());

        let err = submit_presigned_deployment(&req, &transport).unwrap_err();
        assert!(matches!(err, PresignedDeployError::WasmHashMismatch { .. }));
        assert_eq!(transport.call_count(), 0);
        assert!(
            !receipt_path.exists(),
            "receipt must not be written when validation fails"
        );
    }
}

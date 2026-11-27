//! Soroban RPC transaction status polling (issue #324).
//!
//! Submitting a Soroban transaction only enqueues it into the network's
//! mempool; the transaction is not finalized until a ledger closes and
//! `getTransaction` reports a terminal status (`SUCCESS` or `FAILED`). While
//! pending, `getTransaction` returns `NOT_FOUND`.
//!
//! This module provides:
//!
//! * [`validate_tx_hash`] and [`PollConfig`] — explicit input and configuration
//!   validation (empty hashes, non-hex hashes, zero intervals, or zero attempt
//!   limits are rejected rather than silently replaced with defaults);
//! * [`TransactionStatusResponse`] — typed parser for Soroban RPC JSON-RPC 2.0
//!   `getTransaction` responses (unknown fields ignored for forward
//!   compatibility);
//! * [`SorobanRpcTransport`] and [`HttpSorobanRpcClient`] — transport
//!   abstraction so workflows can run against a live Soroban RPC endpoint or a
//!   deterministic mock in tests;
//! * [`poll_transaction`] and [`poll_transaction_with_sleep`] — bounded
//!   polling loops with capped exponential backoff and bounded recovery from
//!   transient network errors (`5xx`, `429`, or transport timeouts).

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use thiserror::Error;
use url::Url;

/// Expected length in hex characters of a 32-byte Soroban transaction hash.
pub const TX_HASH_HEX_LEN: usize = 64;

/// Default initial polling interval between `getTransaction` requests.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Default maximum polling interval when exponential backoff is applied.
pub const DEFAULT_MAX_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Default overall timeout for polling a transaction to a terminal state.
pub const DEFAULT_POLL_TIMEOUT: Duration = Duration::from_secs(30);

/// Default maximum number of polling attempts.
pub const DEFAULT_MAX_ATTEMPTS: usize = 30;

/// Default number of consecutive transient network/RPC errors tolerated.
pub const DEFAULT_MAX_TRANSIENT_ERRORS: usize = 3;

/// Default HTTP request timeout for a single `getTransaction` call.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Errors returned while validating inputs, querying Soroban RPC, or polling
/// a transaction to a terminal result.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PollError {
    #[error("invalid transaction hash `{hash}`: {reason}")]
    InvalidTxHash { hash: String, reason: String },

    #[error("invalid Soroban RPC URL `{url}`: {reason}")]
    InvalidRpcUrl { url: String, reason: String },

    #[error("invalid poll configuration: {0}")]
    InvalidConfig(String),

    #[error("transient Soroban RPC error: {0}")]
    TransientRpc(String),

    #[error("Soroban RPC request failed: {0}")]
    RpcProtocol(String),

    #[error("unexpected transaction status `{0}` from getTransaction")]
    UnexpectedStatus(String),

    #[error(
        "transaction `{tx_hash}` did not reach a terminal status after {attempts} attempt(s) ({elapsed_ms}ms)"
    )]
    Timeout {
        tx_hash: String,
        attempts: usize,
        elapsed_ms: u128,
    },

    #[error(
        "transaction `{tx_hash}` failed on-chain at ledger {ledger:?}: result_xdr={result_xdr:?}"
    )]
    TransactionFailed {
        tx_hash: String,
        ledger: Option<u64>,
        result_xdr: Option<String>,
    },
}

impl PollError {
    /// Returns `true` when the error is transient and safe to retry within the
    /// configured `max_transient_errors` budget.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::TransientRpc(_))
    }
}

/// Validates that `tx_hash` is a 64-character hexadecimal string (32 bytes).
///
/// Leading/trailing whitespace is not trimmed silently — callers must pass the
/// exact hash string.
pub fn validate_tx_hash(tx_hash: &str) -> std::result::Result<(), PollError> {
    if tx_hash.is_empty() {
        return Err(PollError::InvalidTxHash {
            hash: tx_hash.to_string(),
            reason: "transaction hash must not be empty".to_string(),
        });
    }
    if tx_hash.len() != TX_HASH_HEX_LEN {
        return Err(PollError::InvalidTxHash {
            hash: tx_hash.to_string(),
            reason: format!(
                "expected {TX_HASH_HEX_LEN} hex characters, got {}",
                tx_hash.len()
            ),
        });
    }
    if !tx_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PollError::InvalidTxHash {
            hash: tx_hash.to_string(),
            reason: "transaction hash must contain only hexadecimal characters [0-9a-fA-F]"
                .to_string(),
        });
    }
    Ok(())
}

/// Validates that `rpc_url` is a well-formed `http` or `https` URL.
pub fn validate_rpc_url(rpc_url: &str) -> std::result::Result<Url, PollError> {
    let trimmed = rpc_url.trim();
    if trimmed.is_empty() || trimmed != rpc_url {
        return Err(PollError::InvalidRpcUrl {
            url: rpc_url.to_string(),
            reason: "URL must be non-empty without leading or trailing whitespace".to_string(),
        });
    }
    let parsed = Url::parse(rpc_url).map_err(|e| PollError::InvalidRpcUrl {
        url: rpc_url.to_string(),
        reason: e.to_string(),
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(PollError::InvalidRpcUrl {
            url: rpc_url.to_string(),
            reason: format!("unsupported scheme `{}`; expected http or https", parsed.scheme()),
        });
    }
    if parsed.host_str().is_none() {
        return Err(PollError::InvalidRpcUrl {
            url: rpc_url.to_string(),
            reason: "URL must include a host".to_string(),
        });
    }
    Ok(parsed)
}

/// Configuration for [`poll_transaction`] and [`poll_transaction_with_sleep`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollConfig {
    /// Initial delay between `getTransaction` calls. Must be greater than zero.
    pub poll_interval: Duration,
    /// Upper bound for exponential backoff between polls. Must be `>= poll_interval`.
    pub max_interval: Duration,
    /// Maximum wall-clock (or simulated) duration before returning [`PollError::Timeout`].
    pub timeout: Duration,
    /// Maximum number of `getTransaction` attempts before returning [`PollError::Timeout`].
    pub max_attempts: usize,
    /// Maximum number of consecutive transient RPC errors before aborting.
    pub max_transient_errors: usize,
}

impl Default for PollConfig {
    fn default() -> Self {
        Self {
            poll_interval: DEFAULT_POLL_INTERVAL,
            max_interval: DEFAULT_MAX_POLL_INTERVAL,
            timeout: DEFAULT_POLL_TIMEOUT,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            max_transient_errors: DEFAULT_MAX_TRANSIENT_ERRORS,
        }
    }
}

impl PollConfig {
    /// Validates all polling bounds, rejecting zero or inconsistent values.
    pub fn validate(&self) -> std::result::Result<(), PollError> {
        if self.poll_interval.is_zero() {
            return Err(PollError::InvalidConfig(
                "poll_interval must be greater than zero".to_string(),
            ));
        }
        if self.max_interval < self.poll_interval {
            return Err(PollError::InvalidConfig(
                "max_interval must be greater than or equal to poll_interval".to_string(),
            ));
        }
        if self.timeout.is_zero() {
            return Err(PollError::InvalidConfig(
                "timeout must be greater than zero".to_string(),
            ));
        }
        if self.max_attempts == 0 {
            return Err(PollError::InvalidConfig(
                "max_attempts must be at least 1".to_string(),
            ));
        }
        Ok(())
    }
}

/// Raw `result` payload returned by Soroban RPC's `getTransaction` method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionStatusResponse {
    pub status: String,
    #[serde(default)]
    pub latest_ledger: Option<u64>,
    #[serde(default)]
    pub latest_ledger_close_time: Option<String>,
    #[serde(default)]
    pub oldest_ledger: Option<u64>,
    #[serde(default)]
    pub oldest_ledger_close_time: Option<String>,
    #[serde(default)]
    pub ledger: Option<u64>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub application_order: Option<u32>,
    #[serde(default)]
    pub fee_bump: Option<bool>,
    #[serde(default)]
    pub envelope_xdr: Option<String>,
    #[serde(default)]
    pub result_xdr: Option<String>,
    #[serde(default)]
    pub result_meta_xdr: Option<String>,
    #[serde(default)]
    pub diagnostic_events_xdr: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcEnvelope {
    #[serde(default)]
    result: Option<TransactionStatusResponse>,
    #[serde(default)]
    error: Option<JsonRpcErrorObject>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcErrorObject {
    code: i64,
    message: String,
}

impl TransactionStatusResponse {
    /// Parses a full JSON-RPC 2.0 `getTransaction` response body.
    pub fn from_json_rpc_str(body: &str) -> std::result::Result<Self, PollError> {
        let envelope: JsonRpcEnvelope = serde_json::from_str(body)
            .map_err(|e| PollError::RpcProtocol(format!("invalid JSON-RPC response: {e}")))?;

        if let Some(err) = envelope.error {
            // JSON-RPC -32000..-32099 are server-defined errors that may be transient
            // (e.g. overloaded/rate-limited); standard invalid-request/method errors are permanent.
            if (-32099..=-32000).contains(&err.code) {
                return Err(PollError::TransientRpc(format!(
                    "JSON-RPC error {}: {}",
                    err.code, err.message
                )));
            }
            return Err(PollError::RpcProtocol(format!(
                "JSON-RPC error {}: {}",
                err.code, err.message
            )));
        }

        envelope.result.ok_or_else(|| {
            PollError::RpcProtocol("JSON-RPC response contained neither `result` nor `error`".to_string())
        })
    }
}

/// Details captured from a terminal `getTransaction` response (`SUCCESS` or `FAILED`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub tx_hash: String,
    pub ledger: Option<u64>,
    pub created_at: Option<String>,
    pub application_order: Option<u32>,
    pub fee_bump: Option<bool>,
    pub envelope_xdr: Option<String>,
    pub result_xdr: Option<String>,
    pub result_meta_xdr: Option<String>,
    pub diagnostic_events_xdr: Option<Vec<String>>,
}

impl TransactionReceipt {
    fn from_response(tx_hash: &str, resp: TransactionStatusResponse) -> Self {
        Self {
            tx_hash: tx_hash.to_string(),
            ledger: resp.ledger,
            created_at: resp.created_at,
            application_order: resp.application_order,
            fee_bump: resp.fee_bump,
            envelope_xdr: resp.envelope_xdr,
            result_xdr: resp.result_xdr,
            result_meta_xdr: resp.result_meta_xdr,
            diagnostic_events_xdr: resp.diagnostic_events_xdr,
        }
    }
}

/// Terminal outcome of a polled Soroban transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminalTransactionResult {
    Success(TransactionReceipt),
    Failed(TransactionReceipt),
}

impl TerminalTransactionResult {
    /// Returns `true` if the transaction succeeded on-chain.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success(_))
    }

    /// Returns a reference to the underlying [`TransactionReceipt`].
    #[must_use]
    pub fn receipt(&self) -> &TransactionReceipt {
        match self {
            Self::Success(r) | Self::Failed(r) => r,
        }
    }

    /// Converts a terminal result into `Ok(receipt)` on `SUCCESS`, or
    /// `Err(PollError::TransactionFailed)` on `FAILED`.
    pub fn into_result(self) -> std::result::Result<TransactionReceipt, PollError> {
        match self {
            Self::Success(r) => Ok(r),
            Self::Failed(r) => Err(PollError::TransactionFailed {
                tx_hash: r.tx_hash,
                ledger: r.ledger,
                result_xdr: r.result_xdr,
            }),
        }
    }
}

/// Summary returned when [`poll_transaction`] reaches a terminal result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollOutcome {
    pub result: TerminalTransactionResult,
    pub attempts: usize,
    pub transient_errors_recovered: usize,
}

/// Transport abstraction for Soroban RPC `getTransaction` calls.
pub trait SorobanRpcTransport {
    /// Queries the status of `tx_hash`.
    fn get_transaction(
        &mut self,
        tx_hash: &str,
    ) -> std::result::Result<TransactionStatusResponse, PollError>;
}

/// HTTP JSON-RPC 2.0 client for Soroban RPC using `ureq`.
#[derive(Debug, Clone)]
pub struct HttpSorobanRpcClient {
    rpc_url: String,
    request_timeout: Duration,
}

impl HttpSorobanRpcClient {
    /// Creates a new client after validating `rpc_url`.
    pub fn new(rpc_url: impl Into<String>) -> std::result::Result<Self, PollError> {
        let rpc_url = rpc_url.into();
        validate_rpc_url(&rpc_url)?;
        Ok(Self {
            rpc_url,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        })
    }

    /// Overrides the per-request HTTP timeout (must be greater than zero).
    pub fn with_request_timeout(
        mut self,
        timeout: Duration,
    ) -> std::result::Result<Self, PollError> {
        if timeout.is_zero() {
            return Err(PollError::InvalidConfig(
                "request_timeout must be greater than zero".to_string(),
            ));
        }
        self.request_timeout = timeout;
        Ok(self)
    }

    /// Returns the configured RPC endpoint URL.
    #[must_use]
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }
}

impl SorobanRpcTransport for HttpSorobanRpcClient {
    fn get_transaction(
        &mut self,
        tx_hash: &str,
    ) -> std::result::Result<TransactionStatusResponse, PollError> {
        validate_tx_hash(tx_hash)?;
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": { "hash": tx_hash },
        });

        match ureq::post(&self.rpc_url)
            .timeout(self.request_timeout)
            .send_json(payload)
        {
            Ok(response) => {
                let body = response.into_string().map_err(|e| {
                    PollError::TransientRpc(format!("failed reading RPC response body: {e}"))
                })?;
                TransactionStatusResponse::from_json_rpc_str(&body)
            }
            Err(ureq::Error::Status(code, _)) => {
                let msg = format!("HTTP {code} from Soroban RPC `{}`", self.rpc_url);
                if code == 429 || (500..=599).contains(&code) {
                    Err(PollError::TransientRpc(msg))
                } else {
                    Err(PollError::RpcProtocol(msg))
                }
            }
            Err(ureq::Error::Transport(transport)) => Err(PollError::TransientRpc(format!(
                "transport error contacting `{}`: {transport}",
                self.rpc_url
            ))),
        }
    }
}

/// Polls `transport` for `tx_hash` until `SUCCESS` or `FAILED`, using
/// `std::thread::sleep` between attempts.
pub fn poll_transaction<T: SorobanRpcTransport>(
    transport: &mut T,
    tx_hash: &str,
    config: &PollConfig,
) -> std::result::Result<PollOutcome, PollError> {
    poll_transaction_with_sleep(transport, tx_hash, config, std::thread::sleep)
}

/// Polls `transport` for `tx_hash` until `SUCCESS` or `FAILED`, invoking
/// `sleep_fn` for backoff delays.
///
/// Using an injectable `sleep_fn` allows deterministic unit and integration
/// tests without wall-clock sleeps.
pub fn poll_transaction_with_sleep<T, F>(
    transport: &mut T,
    tx_hash: &str,
    config: &PollConfig,
    mut sleep_fn: F,
) -> std::result::Result<PollOutcome, PollError>
where
    T: SorobanRpcTransport,
    F: FnMut(Duration),
{
    validate_tx_hash(tx_hash)?;
    config.validate()?;

    let start = Instant::now();
    let mut simulated_elapsed = Duration::ZERO;
    let mut current_interval = config.poll_interval;
    let mut consecutive_transient_errors: usize = 0;
    let mut total_transient_errors_recovered: usize = 0;

    for attempt in 1..=config.max_attempts {
        match transport.get_transaction(tx_hash) {
            Ok(resp) => {
                consecutive_transient_errors = 0;
                match resp.status.as_str() {
                    "SUCCESS" => {
                        return Ok(PollOutcome {
                            result: TerminalTransactionResult::Success(
                                TransactionReceipt::from_response(tx_hash, resp),
                            ),
                            attempts: attempt,
                            transient_errors_recovered: total_transient_errors_recovered,
                        });
                    }
                    "FAILED" => {
                        return Ok(PollOutcome {
                            result: TerminalTransactionResult::Failed(
                                TransactionReceipt::from_response(tx_hash, resp),
                            ),
                            attempts: attempt,
                            transient_errors_recovered: total_transient_errors_recovered,
                        });
                    }
                    "NOT_FOUND" => {
                        // Transaction is still pending; continue polling if budget remains.
                    }
                    other => {
                        return Err(PollError::UnexpectedStatus(other.to_string()));
                    }
                }
            }
            Err(err) if err.is_retryable() => {
                consecutive_transient_errors += 1;
                total_transient_errors_recovered += 1;
                if consecutive_transient_errors > config.max_transient_errors {
                    return Err(err);
                }
            }
            Err(err) => return Err(err),
        }

        let elapsed = start.elapsed().max(simulated_elapsed);
        if attempt == config.max_attempts || elapsed >= config.timeout {
            return Err(PollError::Timeout {
                tx_hash: tx_hash.to_string(),
                attempts: attempt,
                elapsed_ms: elapsed.as_millis(),
            });
        }

        let remaining_timeout = config.timeout.saturating_sub(elapsed);
        let delay = current_interval.min(remaining_timeout);
        sleep_fn(delay);
        simulated_elapsed = simulated_elapsed.saturating_add(delay);
        current_interval = current_interval
            .saturating_mul(2)
            .min(config.max_interval);
    }

    let elapsed = start.elapsed().max(simulated_elapsed);
    Err(PollError::Timeout {
        tx_hash: tx_hash.to_string(),
        attempts: config.max_attempts,
        elapsed_ms: elapsed.as_millis(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const VALID_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    struct MockTransport {
        responses: VecDeque<std::result::Result<TransactionStatusResponse, PollError>>,
    }

    impl MockTransport {
        fn new(responses: Vec<std::result::Result<TransactionStatusResponse, PollError>>) -> Self {
            Self {
                responses: responses.into(),
            }
        }
    }

    impl SorobanRpcTransport for MockTransport {
        fn get_transaction(
            &mut self,
            _tx_hash: &str,
        ) -> std::result::Result<TransactionStatusResponse, PollError> {
            self.responses
                .pop_front()
                .unwrap_or_else(|| Ok(status_resp("NOT_FOUND", None, None)))
        }
    }

    fn status_resp(
        status: &str,
        ledger: Option<u64>,
        result_xdr: Option<&str>,
    ) -> TransactionStatusResponse {
        TransactionStatusResponse {
            status: status.to_string(),
            latest_ledger: Some(100),
            latest_ledger_close_time: None,
            oldest_ledger: None,
            oldest_ledger_close_time: None,
            ledger,
            created_at: None,
            application_order: Some(1),
            fee_bump: Some(false),
            envelope_xdr: None,
            result_xdr: result_xdr.map(str::to_string),
            result_meta_xdr: None,
            diagnostic_events_xdr: None,
        }
    }

    fn fast_config() -> PollConfig {
        PollConfig {
            poll_interval: Duration::from_millis(100),
            max_interval: Duration::from_millis(400),
            timeout: Duration::from_secs(5),
            max_attempts: 10,
            max_transient_errors: 2,
        }
    }

    #[test]
    fn poll_succeeds_after_not_found_polls() {
        let mut transport = MockTransport::new(vec![
            Ok(status_resp("NOT_FOUND", None, None)),
            Ok(status_resp("NOT_FOUND", None, None)),
            Ok(status_resp("SUCCESS", Some(42), Some("AAAA"))),
        ]);
        let mut sleeps = Vec::new();

        let outcome = poll_transaction_with_sleep(&mut transport, VALID_HASH, &fast_config(), |d| {
            sleeps.push(d);
        })
        .expect("should succeed");

        assert_eq!(outcome.attempts, 3);
        assert_eq!(outcome.transient_errors_recovered, 0);
        assert!(outcome.result.is_success());
        assert_eq!(outcome.result.receipt().ledger, Some(42));
        assert_eq!(outcome.result.receipt().result_xdr.as_deref(), Some("AAAA"));
        assert_eq!(
            sleeps,
            vec![Duration::from_millis(100), Duration::from_millis(200)]
        );
    }

    #[test]
    fn poll_returns_terminal_failed_without_erroring_and_into_result_errors() {
        let mut transport = MockTransport::new(vec![
            Ok(status_resp("NOT_FOUND", None, None)),
            Ok(status_resp("FAILED", Some(99), Some("ERR_XDR"))),
        ]);

        let outcome =
            poll_transaction_with_sleep(&mut transport, VALID_HASH, &fast_config(), |_| {})
                .expect("FAILED is a terminal result");

        assert_eq!(outcome.attempts, 2);
        assert!(!outcome.result.is_success());
        let err = outcome.result.into_result().expect_err("must convert to error");
        assert!(matches!(
            err,
            PollError::TransactionFailed {
                ledger: Some(99),
                ..
            }
        ));
    }

    #[test]
    fn poll_recovers_from_bounded_transient_errors() {
        let mut transport = MockTransport::new(vec![
            Err(PollError::TransientRpc("HTTP 503".to_string())),
            Err(PollError::TransientRpc("timeout".to_string())),
            Ok(status_resp("SUCCESS", Some(50), Some("OK"))),
        ]);

        let outcome =
            poll_transaction_with_sleep(&mut transport, VALID_HASH, &fast_config(), |_| {})
                .expect("should recover within transient error budget");

        assert_eq!(outcome.attempts, 3);
        assert_eq!(outcome.transient_errors_recovered, 2);
        assert!(outcome.result.is_success());
    }

    #[test]
    fn poll_aborts_when_transient_errors_exceed_budget() {
        let mut transport = MockTransport::new(vec![
            Err(PollError::TransientRpc("err 1".to_string())),
            Err(PollError::TransientRpc("err 2".to_string())),
            Err(PollError::TransientRpc("err 3".to_string())),
        ]);

        let err =
            poll_transaction_with_sleep(&mut transport, VALID_HASH, &fast_config(), |_| {})
                .expect_err("must abort after exceeding max_transient_errors");

        assert!(matches!(err, PollError::TransientRpc(_)));
    }

    #[test]
    fn poll_times_out_when_max_attempts_exhausted() {
        let mut transport = MockTransport::new(vec![
            Ok(status_resp("NOT_FOUND", None, None)),
            Ok(status_resp("NOT_FOUND", None, None)),
            Ok(status_resp("NOT_FOUND", None, None)),
        ]);
        let cfg = PollConfig {
            max_attempts: 3,
            ..fast_config()
        };

        let err = poll_transaction_with_sleep(&mut transport, VALID_HASH, &cfg, |_| {})
            .expect_err("must time out");

        assert!(matches!(
            err,
            PollError::Timeout {
                attempts: 3,
                ..
            }
        ));
    }

    #[test]
    fn rejects_invalid_tx_hash_and_invalid_config() {
        let mut transport = MockTransport::new(vec![]);
        let cfg = fast_config();

        assert!(matches!(
            poll_transaction_with_sleep(&mut transport, "", &cfg, |_| {}),
            Err(PollError::InvalidTxHash { .. })
        ));
        assert!(matches!(
            poll_transaction_with_sleep(&mut transport, "abcd", &cfg, |_| {}),
            Err(PollError::InvalidTxHash { .. })
        ));
        assert!(matches!(
            poll_transaction_with_sleep(
                &mut transport,
                &"z".repeat(64),
                &cfg,
                |_| {}
            ),
            Err(PollError::InvalidTxHash { .. })
        ));

        let bad_interval = PollConfig {
            poll_interval: Duration::ZERO,
            ..cfg.clone()
        };
        assert!(matches!(
            poll_transaction_with_sleep(&mut transport, VALID_HASH, &bad_interval, |_| {}),
            Err(PollError::InvalidConfig(_))
        ));

        let bad_attempts = PollConfig {
            max_attempts: 0,
            ..cfg
        };
        assert!(matches!(
            poll_transaction_with_sleep(&mut transport, VALID_HASH, &bad_attempts, |_| {}),
            Err(PollError::InvalidConfig(_))
        ));
    }

    #[test]
    fn rejects_invalid_rpc_url_and_unexpected_status() {
        assert!(matches!(
            validate_rpc_url(""),
            Err(PollError::InvalidRpcUrl { .. })
        ));
        assert!(matches!(
            validate_rpc_url("ftp://soroban.example.com"),
            Err(PollError::InvalidRpcUrl { .. })
        ));
        assert!(validate_rpc_url("https://soroban-testnet.stellar.org").is_ok());

        let mut transport = MockTransport::new(vec![Ok(status_resp("UNKNOWN", None, None))]);
        let err = poll_transaction_with_sleep(&mut transport, VALID_HASH, &fast_config(), |_| {})
            .expect_err("unexpected status must fail");
        assert!(matches!(err, PollError::UnexpectedStatus(s) if s == "UNKNOWN"));
    }

    #[test]
    fn parses_json_rpc_success_and_error_responses() {
        let ok_body = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "status": "SUCCESS",
                "ledger": 12345,
                "resultXdr": "AAAAAQ=="
            }
        }"#;
        let parsed = TransactionStatusResponse::from_json_rpc_str(ok_body).expect("valid");
        assert_eq!(parsed.status, "SUCCESS");
        assert_eq!(parsed.ledger, Some(12345));

        let err_body = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": -32602, "message": "Invalid params" }
        }"#;
        let err = TransactionStatusResponse::from_json_rpc_str(err_body).expect_err("rpc error");
        assert!(matches!(err, PollError::RpcProtocol(_)));
    }
}

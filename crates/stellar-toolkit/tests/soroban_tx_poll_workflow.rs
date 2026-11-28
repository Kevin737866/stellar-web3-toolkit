//! Integration tests for polling Soroban transaction status until terminal
//! result (issue #324).

use std::collections::VecDeque;
use std::time::Duration;
use stellar_toolkit::{
    poll_transaction_with_sleep, HttpSorobanRpcClient, PollConfig, PollError, SorobanRpcTransport,
    TerminalTransactionResult, TransactionStatusResponse,
};

const SAMPLE_TX_HASH: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

struct ScriptedJsonRpcTransport {
    payloads: VecDeque<std::result::Result<String, PollError>>,
}

impl SorobanRpcTransport for ScriptedJsonRpcTransport {
    fn get_transaction(
        &mut self,
        _tx_hash: &str,
    ) -> std::result::Result<TransactionStatusResponse, PollError> {
        let next = self
            .payloads
            .pop_front()
            .expect("test scripted enough responses");
        let body = next?;
        TransactionStatusResponse::from_json_rpc_str(&body)
    }
}

#[test]
fn end_to_end_polling_handles_pending_transient_error_and_terminal_success() {
    let mut transport = ScriptedJsonRpcTransport {
        payloads: VecDeque::from([
            Ok(r#"{"jsonrpc":"2.0","id":1,"result":{"status":"NOT_FOUND","latestLedger":10}}"#
                .to_string()),
            Err(PollError::TransientRpc("HTTP 502 Bad Gateway".to_string())),
            Ok(r#"{"jsonrpc":"2.0","id":1,"result":{"status":"NOT_FOUND","latestLedger":11}}"#
                .to_string()),
            Ok(r#"{"jsonrpc":"2.0","id":1,"result":{"status":"SUCCESS","ledger":12,"resultXdr":"AAAA"}}"#
                .to_string()),
        ]),
    };

    let config = PollConfig {
        poll_interval: Duration::from_millis(50),
        max_interval: Duration::from_millis(200),
        timeout: Duration::from_secs(5),
        max_attempts: 10,
        max_transient_errors: 2,
    };

    let outcome = poll_transaction_with_sleep(&mut transport, SAMPLE_TX_HASH, &config, |_| {})
        .expect("workflow should reach terminal SUCCESS");

    assert_eq!(outcome.attempts, 4);
    assert_eq!(outcome.transient_errors_recovered, 1);
    match outcome.result {
        TerminalTransactionResult::Success(receipt) => {
            assert_eq!(receipt.tx_hash, SAMPLE_TX_HASH);
            assert_eq!(receipt.ledger, Some(12));
            assert_eq!(receipt.result_xdr.as_deref(), Some("AAAA"));
        }
        TerminalTransactionResult::Failed(_) => panic!("expected Success"),
    }
}

#[test]
fn http_client_rejects_invalid_rpc_url_and_zero_timeout() {
    assert!(HttpSorobanRpcClient::new("not-a-url").is_err());
    let client = HttpSorobanRpcClient::new("https://soroban-testnet.stellar.org")
        .expect("valid https url");
    assert!(client.with_request_timeout(Duration::ZERO).is_err());
}

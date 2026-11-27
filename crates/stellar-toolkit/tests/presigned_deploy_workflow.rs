//! Integration tests for submitting pre-signed deployment transactions over
//! real HTTP via [`UreqRpcTransport`].

use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use stellar_toolkit::{
    submit_presigned_deployment, PresignedDeployError, PresignedDeployReceipt,
    PresignedDeployRequest, SubmissionStatus, UreqRpcTransport, WasmArtifactCheck,
};

fn spawn_mock_rpc_server(
    responses: Vec<(u16, String)>,
) -> (String, Arc<AtomicUsize>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);

    let handle = thread::spawn(move || {
        for (status, body) in responses {
            let (mut stream, _) = listener.accept().expect("accept connection");
            hits_clone.fetch_add(1, Ordering::SeqCst);

            let mut buf = [0_u8; 4096];
            let _ = stream.read(&mut buf);

            let reason = match status {
                200 => "OK",
                503 => "Service Unavailable",
                _ => "Error",
            };
            let reply = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(reply.as_bytes()).expect("write response");
            stream.flush().expect("flush response");
        }
    });

    (format!("http://{addr}"), hits, handle)
}

#[test]
fn end_to_end_presigned_deploy_with_wasm_check_and_receipt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let wasm_path = dir.path().join("amm_pool.wasm");
    let wasm_bytes = b"\0asm\x01\x00\x00\x00presigned-deploy-test";
    std::fs::write(&wasm_path, wasm_bytes).expect("write wasm");
    let expected_sha256 = hex::encode(Sha256::digest(wasm_bytes));
    let receipt_path = dir.path().join("receipts").join("deploy.json");

    let (url, hits, handle) = spawn_mock_rpc_server(vec![
        (
            200,
            r#"{"jsonrpc":"2.0","id":1,"result":{"status":"TRY_AGAIN_LATER","hash":"txhash42"}}"#
                .to_string(),
        ),
        (
            200,
            r#"{"jsonrpc":"2.0","id":1,"result":{"status":"PENDING","hash":"txhash42","latestLedger":555,"latestLedgerCloseTime":"1700000100"}}"#
                .to_string(),
        ),
    ]);

    let mut req = PresignedDeployRequest::new(&url, "AAAA");
    req.network_passphrase = Some("Test SDF Network ; September 2015".to_string());
    req.wasm_check = Some(WasmArtifactCheck {
        wasm_path,
        expected_sha256: expected_sha256.clone(),
    });
    req.max_retries = 2;
    req.receipt_path = Some(receipt_path.clone());

    let receipt =
        submit_presigned_deployment(&req, &UreqRpcTransport).expect("submission succeeds");
    handle.join().expect("server thread");

    assert_eq!(hits.load(Ordering::SeqCst), 2);
    assert_eq!(receipt.status, SubmissionStatus::Pending);
    assert_eq!(receipt.tx_hash, "txhash42");
    assert_eq!(receipt.latest_ledger, Some(555));
    assert_eq!(receipt.attempts, 2);
    assert_eq!(
        receipt.verified_wasm_sha256.as_deref(),
        Some(expected_sha256.as_str())
    );

    let persisted: PresignedDeployReceipt =
        serde_json::from_str(&std::fs::read_to_string(&receipt_path).expect("read receipt"))
            .expect("valid receipt JSON");
    assert_eq!(persisted, receipt);
}

#[test]
fn end_to_end_duplicate_submission_is_recoverable() {
    let (url, hits, handle) = spawn_mock_rpc_server(vec![(
        200,
        r#"{"jsonrpc":"2.0","id":1,"result":{"status":"DUPLICATE","hash":"duptx77","latestLedger":800}}"#
            .to_string(),
    )]);

    let req = PresignedDeployRequest::new(&url, "AAAA");
    let receipt =
        submit_presigned_deployment(&req, &UreqRpcTransport).expect("duplicate is recoverable");
    handle.join().expect("server thread");

    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(receipt.status, SubmissionStatus::Duplicate);
    assert_eq!(receipt.tx_hash, "duptx77");
}

#[test]
fn wasm_mismatch_never_contacts_rpc_and_leaves_no_receipt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let wasm_path = dir.path().join("tampered.wasm");
    std::fs::write(&wasm_path, b"\0asm\x01\x00\x00\x00tampered").expect("write wasm");
    let receipt_path = dir.path().join("deploy.json");

    let mut req = PresignedDeployRequest::new("http://127.0.0.1:9", "AAAA");
    req.wasm_check = Some(WasmArtifactCheck {
        wasm_path,
        expected_sha256: "f".repeat(64),
    });
    req.receipt_path = Some(receipt_path.clone());

    let err = submit_presigned_deployment(&req, &UreqRpcTransport).unwrap_err();
    assert!(matches!(err, PresignedDeployError::WasmHashMismatch { .. }));
    assert!(!receipt_path.exists());
}

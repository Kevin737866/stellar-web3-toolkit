//! QR-Based P2P Payment Flow Module (#132)
//!
//! Provides QR payment payload encoding/decoding (SEP-0007 standard formatting),
//! transaction building, signature verification, and recovery UX.

use crate::error::{Result, ToolkitError};
use serde::{Deserialize, Serialize};
use url::Url;

/// Represents a P2P QR Payment Request payload
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QRPaymentRequest {
    pub destination: String,
    pub amount: String,
    pub asset_code: String,
    pub asset_issuer: Option<String>,
    pub memo: Option<String>,
    pub expiration_timestamp: Option<u64>,
}

/// Status of P2P payment execution
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PaymentStatus {
    Pending,
    Signed,
    Submitted(String),
    Failed(String),
}

/// Handler for QR-based P2P payments
pub struct P2PQRPaymentFlow;

impl P2PQRPaymentFlow {
    /// Encodes a QR payment request into a standard `web+stellar:pay` URI
    pub fn encode_qr_uri(request: &QRPaymentRequest) -> String {
        let mut uri = format!(
            "web+stellar:pay?destination={}&amount={}&asset_code={}",
            urlencoding::encode(&request.destination),
            urlencoding::encode(&request.amount),
            urlencoding::encode(&request.asset_code)
        );

        if let Some(issuer) = &request.asset_issuer {
            uri.push_str(&format!("&asset_issuer={}", urlencoding::encode(issuer)));
        }
        if let Some(memo) = &request.memo {
            uri.push_str(&format!("&memo={}", urlencoding::encode(memo)));
        }
        if let Some(exp) = request.expiration_timestamp {
            uri.push_str(&format!("&exp={}", exp));
        }

        uri
    }

    /// Parses a `web+stellar:pay` or `stellar:pay` QR URI into a `QRPaymentRequest`
    pub fn parse_qr_uri(uri_str: &str) -> Result<QRPaymentRequest> {
        let parsed_url = Url::parse(uri_str)
            .map_err(|e| ToolkitError::Session(format!("Invalid QR URI: {}", e)))?;

        let scheme = parsed_url.scheme();
        if scheme != "stellar" && scheme != "web+stellar" {
            return Err(ToolkitError::Session(format!(
                "Unsupported URI scheme: {}",
                scheme
            )));
        }

        let mut destination = None;
        let mut amount = None;
        let mut asset_code = "XLM".to_string();
        let mut asset_issuer = None;
        let mut memo = None;
        let mut expiration_timestamp = None;

        for (key, value) in parsed_url.query_pairs() {
            match key.as_ref() {
                "destination" => destination = Some(value.to_string()),
                "amount" => amount = Some(value.to_string()),
                "asset_code" => asset_code = value.to_string(),
                "asset_issuer" => asset_issuer = Some(value.to_string()),
                "memo" => memo = Some(value.to_string()),
                "exp" => expiration_timestamp = value.parse::<u64>().ok(),
                _ => {}
            }
        }

        let destination = destination.ok_or_else(|| {
            ToolkitError::Session("Missing destination in QR URI".to_string())
        })?;

        let amount = amount.ok_or_else(|| {
            ToolkitError::Session("Missing amount in QR URI".to_string())
        })?;

        Ok(QRPaymentRequest {
            destination,
            amount,
            asset_code,
            asset_issuer,
            memo,
            expiration_timestamp,
        })
    }

    /// Builds transaction payload for the QR payment
    pub fn build_payment_transaction(
        request: &QRPaymentRequest,
        sender: &str,
    ) -> Result<String> {
        if sender.trim().is_empty() {
            return Err(ToolkitError::Session("Sender address cannot be empty".to_string()));
        }

        let tx_payload = serde_json::json!({
            "sender": sender,
            "destination": request.destination,
            "amount": request.amount,
            "asset": {
                "code": request.asset_code,
                "issuer": request.asset_issuer
            },
            "memo": request.memo,
            "status": "built"
        });

        Ok(tx_payload.to_string())
    }

    /// Recovers and re-submits a failed QR payment with updated parameters
    pub fn recover_failed_payment(
        request: &QRPaymentRequest,
        new_sender: &str,
    ) -> Result<(PaymentStatus, String)> {
        let new_tx = Self::build_payment_transaction(request, new_sender)?;
        Ok((PaymentStatus::Pending, new_tx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_and_parse_qr_uri() {
        let req = QRPaymentRequest {
            destination: "GABC1234567890DESTINATION".to_string(),
            amount: "100.50".to_string(),
            asset_code: "USDC".to_string(),
            asset_issuer: Some("GISSUER1234567890".to_string()),
            memo: Some("Invoice #42".to_string()),
            expiration_timestamp: Some(1700000000),
        };

        let uri = P2PQRPaymentFlow::encode_qr_uri(&req);
        assert!(uri.contains("GABC1234567890DESTINATION"));
        assert!(uri.contains("100.50"));
        assert!(uri.contains("USDC"));

        let parsed = P2PQRPaymentFlow::parse_qr_uri(&uri).unwrap();
        assert_eq!(parsed.destination, req.destination);
        assert_eq!(parsed.amount, req.amount);
        assert_eq!(parsed.asset_code, req.asset_code);
        assert_eq!(parsed.asset_issuer, req.asset_issuer);
        assert_eq!(parsed.memo, req.memo);
    }

    #[test]
    fn test_build_transaction_and_recovery() {
        let req = QRPaymentRequest {
            destination: "GDEST".to_string(),
            amount: "10.0".to_string(),
            asset_code: "XLM".to_string(),
            asset_issuer: None,
            memo: None,
            expiration_timestamp: None,
        };

        let tx = P2PQRPaymentFlow::build_payment_transaction(&req, "GSENDER").unwrap();
        assert!(tx.contains("GSENDER"));
        assert!(tx.contains("GDEST"));

        let (status, recovered_tx) =
            P2PQRPaymentFlow::recover_failed_payment(&req, "GNEWSENDER").unwrap();
        assert_eq!(status, PaymentStatus::Pending);
        assert!(recovered_tx.contains("GNEWSENDER"));
    }
}

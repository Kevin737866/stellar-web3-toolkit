//! API Reference Site Generation Module (#137)
//!
//! Generates markdown & HTML API reference documentation for the Soroban smart contracts
//! and Rust SDK crates in the stellar-web3-toolkit workspace.

use crate::error::{Result, ToolkitError};
use serde::{Deserialize, Serialize};

/// Documented API Endpoint / Contract Function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiFunctionDoc {
    pub name: String,
    pub module_or_contract: String,
    pub description: String,
    pub parameters: Vec<(String, String)>,
    pub return_type: String,
    pub example_call: String,
}

/// Generator for workspace API reference documentation
pub struct ApiReferenceGenerator {
    pub site_title: String,
    pub version: String,
    pub functions: Vec<ApiFunctionDoc>,
}

impl Default for ApiReferenceGenerator {
    fn default() -> Self {
        let mut gen = Self::new("Stellar Web3 Toolkit API Reference", "v0.1.0");
        gen.populate_default_docs();
        gen
    }
}

impl ApiReferenceGenerator {
    pub fn new(site_title: &str, version: &str) -> Self {
        Self {
            site_title: site_title.to_string(),
            version: version.to_string(),
            functions: Vec::new(),
        }
    }

    /// Populates documentation items for contracts and SDK modules
    pub fn populate_default_docs(&mut self) {
        self.functions.push(ApiFunctionDoc {
            name: "P2PQRPaymentFlow::parse_qr_uri".to_string(),
            module_or_contract: "crates/stellar-toolkit (p2p_qr_payment)".to_string(),
            description: "Parses a standard SEP-0007 / web+stellar QR code URI into a payment request struct.".to_string(),
            parameters: vec![("uri_str".to_string(), "&str".to_string())],
            return_type: "Result<QRPaymentRequest>".to_string(),
            example_call: "P2PQRPaymentFlow::parse_qr_uri(\"web+stellar:pay?destination=GABC...\")".to_string(),
        });

        self.functions.push(ApiFunctionDoc {
            name: "OneClickAirdropClaimer::execute_one_click_claim".to_string(),
            module_or_contract: "crates/stellar-toolkit (one_click_airdrop)".to_string(),
            description: "Builds, signs, and executes an automated single-click token airdrop claim.".to_string(),
            parameters: vec![("request".to_string(), "&AirdropClaimRequest".to_string())],
            return_type: "Result<ClaimStatus>".to_string(),
            example_call: "OneClickAirdropClaimer::execute_one_click_claim(&request)".to_string(),
        });

        self.functions.push(ApiFunctionDoc {
            name: "AmmPool::swap".to_string(),
            module_or_contract: "contracts/amm-pool".to_string(),
            description: "Executes constant-product AMM token swap with slippage protection.".to_string(),
            parameters: vec![
                ("to".to_string(), "Address".to_string()),
                ("out_a".to_string(), "i128".to_string()),
                ("out_b".to_string(), "i128".to_string()),
            ],
            return_type: "()".to_string(),
            example_call: "amm_pool_client.swap(&user, &100_i128, &0_i128)".to_string(),
        });
    }

    /// Exports full API reference as a Markdown site file
    pub fn generate_markdown_site(&self) -> String {
        let mut md = format!("# {}\n\n", self.site_title);
        md.push_str(&format!("**Version**: {}\n\n", self.version));
        md.push_str("Complete API documentation reference for Soroban contracts and SDK crates.\n\n");
        md.push_str("## Table of Contents\n\n");

        for doc in &self.functions {
            md.push_str(&format!("- [{}]({}#user-content-{})\n", doc.name, "", doc.name.to_lowercase().replace("::", "-")));
        }

        md.push_str("\n---\n\n");

        for doc in &self.functions {
            md.push_str(&format!("### {}\n\n", doc.name));
            md.push_str(&format!("*Module/Contract*: `{}`\n\n", doc.module_or_contract));
            md.push_str(&format!("{}\n\n", doc.description));
            md.push_str("**Parameters:**\n");
            for (param, ptype) in &doc.parameters {
                md.push_str(&format!("- `{}`: `{}`\n", param, ptype));
            }
            md.push_str(&format!("\n**Return Type:** `{}`\n\n", doc.return_type));
            md.push_str("```rust\n");
            md.push_str(&doc.example_call);
            md.push_str("\n```\n\n---\n\n");
        }

        md
    }

    /// Saves API documentation file
    pub fn save_docs_to_file(&self, file_path: &str) -> Result<()> {
        let content = self.generate_markdown_site();
        std::fs::write(file_path, content)
            .map_err(|e| ToolkitError::Session(format!("Failed to write API docs: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_reference_generator() {
        let gen = ApiReferenceGenerator::default();
        let md = gen.generate_markdown_site();

        assert!(md.contains("Stellar Web3 Toolkit API Reference"));
        assert!(md.contains("P2PQRPaymentFlow::parse_qr_uri"));
        assert!(md.contains("OneClickAirdropClaimer::execute_one_click_claim"));
        assert!(md.contains("AmmPool::swap"));
    }
}

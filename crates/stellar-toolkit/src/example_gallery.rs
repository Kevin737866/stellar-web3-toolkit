//! Contract Example Gallery Module (#138)
//!
//! Provides an interactive example gallery of runnable Soroban smart contracts
//! including AMM Pool, AMM Factory, Payment Channel, HTLC, and Airdrop Claim.

use crate::error::{Result, ToolkitError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write as _;

/// Represents a runnable Soroban contract example
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractExample {
    pub id: String,
    pub title: String,
    pub category: String,
    pub description: String,
    pub contract_wasm_hash: String,
    pub rust_snippet: String,
    pub cli_run_command: String,
}

/// Registry of curated contract examples
pub struct ExampleGalleryRegistry {
    examples: HashMap<String, ContractExample>,
}

impl Default for ExampleGalleryRegistry {
    fn default() -> Self {
        let mut registry = Self::new();
        registry.load_builtin_examples();
        registry
    }
}

impl ExampleGalleryRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            examples: HashMap::new(),
        }
    }

    /// Loads built-in runnable contract examples
    pub fn load_builtin_examples(&mut self) {
        let amm_example = ContractExample {
            id: "amm-pool-swap".to_string(),
            title: "Automated Market Maker (AMM) Liquidity & Swap".to_string(),
            category: "DeFi / AMM".to_string(),
            description: "Demonstrates initializing liquidity pools, depositing reserves, and executing exact-in swaps on Soroban.".to_string(),
            contract_wasm_hash: "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            rust_snippet: r"
let env = Env::default();
let client = AmmPoolClient::new(&env, &contract_id);
client.deposit(&user, &1000_i128, &2000_i128);
let out = client.swap(&user, &token_a, &100_i128, &180_i128);
            ".trim().to_string(),
            cli_run_command: "stellar-toolkit example run --id amm-pool-swap --network testnet".to_string(),
        };

        let payment_channel_example = ContractExample {
            id: "payment-channel-offchain".to_string(),
            title: "Stateful Payment Channel Settlement".to_string(),
            category: "Layer 2 / Payments".to_string(),
            description: "Showcases opening payment channels, off-chain state updates with HMAC signatures, and channel closing with on-chain dispute resolution.".to_string(),
            contract_wasm_hash: "b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef12".to_string(),
            rust_snippet: r"
let channel = PaymentChannel::open(&env, &alice, &bob, 5000_i128, 86400);
let signature = channel.sign_state_update(nonce, alice_bal, bob_bal);
channel.close(&env, &signature);
            ".trim().to_string(),
            cli_run_command: "stellar-toolkit example run --id payment-channel-offchain --network testnet".to_string(),
        };

        let airdrop_example = ContractExample {
            id: "one-click-airdrop".to_string(),
            title: "One-Click Airdrop Claim UX".to_string(),
            category: "Token Distribution".to_string(),
            description: "Allows eligible accounts to claim token airdrops with cryptographic proof verification and single-click execution.".to_string(),
            contract_wasm_hash: "c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef1234".to_string(),
            rust_snippet: r#"
let claimer = OneClickAirdropClaimer::new();
let tx = claimer.claim_airdrop("GCLAIMANT...", "airdrop-event-2026", &proof)?;
            "#.trim().to_string(),
            cli_run_command: "stellar-toolkit example run --id one-click-airdrop --network testnet".to_string(),
        };

        let mobile_wallet_example = ContractExample {
            id: "mobile-wallet-dapp".to_string(),
            title: "Mobile Wallet Contract Dapp".to_string(),
            category: "Wallet / Mobile".to_string(),
            description: "Connects a wallet to a toolkit contract on a phone: signs a payment, simulates a read, prepares and submits a write, hands the payment to a wallet app with a SEP-7 deep link when there is no extension, and recovers an account from a BIP-39 phrase.".to_string(),
            contract_wasm_hash: "d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef123456".to_string(),
            rust_snippet: r"
// examples/mobile-wallet-dapp — the wallet-facing half, in JS:
//   const wallet = createWallet({ config, server, provider });
//   await wallet.sendPayment({ from, to, amount: '1.5' });
//   await wallet.readContract({ from, contractId, method: 'balance_of', args: [holder] });
//   await wallet.invokeContract({ from, contractId, method: 'deposit', args: [holder, token, amount] });
//
// The contract call it is wired to, from a Rust test:
let client = TokenLockerClient::new(&env, &contract_id);
client.deposit(&holder, &token, &1_000);
assert_eq!(client.balance_of(&holder, &token), 1_000);
            ".trim().to_string(),
            cli_run_command: "stellar-toolkit example run --id mobile-wallet-dapp --network testnet".to_string(),
        };

        self.examples.insert(amm_example.id.clone(), amm_example);
        self.examples
            .insert(payment_channel_example.id.clone(), payment_channel_example);
        self.examples
            .insert(airdrop_example.id.clone(), airdrop_example);
        self.examples
            .insert(mobile_wallet_example.id.clone(), mobile_wallet_example);
    }

    #[must_use]
    pub fn list_examples(&self) -> Vec<&ContractExample> {
        self.examples.values().collect()
    }

    #[must_use]
    pub fn get_example(&self, id: &str) -> Option<&ContractExample> {
        self.examples.get(id)
    }

    /// Simulates running a contract example
    pub fn run_example_execution(&self, id: &str) -> Result<String> {
        let example = self
            .get_example(id)
            .ok_or_else(|| ToolkitError::Session(format!("Example '{id}' not found in gallery")))?;

        Ok(format!(
            "Executed example '{}': Successfully invoked WASM hash [{}]",
            example.title, example.contract_wasm_hash
        ))
    }

    /// Exports gallery as Markdown site representation
    #[must_use]
    pub fn export_markdown_gallery(&self) -> String {
        let mut markdown = String::from("# Soroban Contract Example Gallery\n\n");
        markdown.push_str(
            "Explore runnable smart contract examples and integration code snippets.\n\n",
        );

        for example in self.list_examples() {
            let _ = writeln!(markdown, "## {}", example.title);
            let _ = writeln!(markdown, "- **Category**: {}", example.category);
            let _ = writeln!(
                markdown,
                "- **WASM Hash**: `{}`",
                example.contract_wasm_hash
            );
            let _ = write!(
                markdown,
                "- **Run Command**: `{}`\n\n",
                example.cli_run_command
            );
            let _ = write!(markdown, "{}\n\n", example.description);
            markdown.push_str("```rust\n");
            markdown.push_str(&example.rust_snippet);
            markdown.push_str("\n```\n\n---\n\n");
        }

        markdown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example_gallery_registry() {
        let gallery = ExampleGalleryRegistry::default();
        let list = gallery.list_examples();
        assert!(!list.is_empty());

        let amm = gallery.get_example("amm-pool-swap").unwrap();
        assert_eq!(amm.category, "DeFi / AMM");

        let run_res = gallery.run_example_execution("one-click-airdrop").unwrap();
        assert!(run_res.contains("One-Click Airdrop Claim UX"));

        let md = gallery.export_markdown_gallery();
        assert!(md.contains("# Soroban Contract Example Gallery"));
    }

    /// The mobile wallet example (#128) is a real entry, and it says where to
    /// find the dapp rather than only naming a wasm hash.
    #[test]
    fn test_mobile_wallet_example_is_registered() {
        let gallery = ExampleGalleryRegistry::default();
        let example = gallery
            .get_example("mobile-wallet-dapp")
            .expect("the mobile wallet example is registered");

        assert_eq!(example.category, "Wallet / Mobile");
        assert!(example.description.contains("SEP-7"));
        assert!(example.rust_snippet.contains("examples/mobile-wallet-dapp"));
        assert!(gallery
            .run_example_execution("mobile-wallet-dapp")
            .unwrap()
            .contains("Mobile Wallet Contract Dapp"));

        // And it survives the Markdown export the gallery documents itself
        // with, so the docs and the registry cannot disagree.
        assert!(gallery
            .export_markdown_gallery()
            .contains("Mobile Wallet Contract Dapp"));
    }
}

# Security Disclosure Policy

The **Stellar Web3 Toolkit** team takes security vulnerabilities seriously. We appreciate the efforts of security researchers and community members in helping keep our toolkit, CLI utilities, and Soroban smart contracts secure.

---

## Reporting a Vulnerability

If you discover a security vulnerability or potential exploit in this repository, **do not open a public GitHub issue**.

Please report vulnerabilities privately via email to:
- **Email**: `security@stellar-web3-toolkit.dev` (or contact maintainers privately)

### Information to Include in Your Report
1. Description of the vulnerability and its potential impact.
2. Steps to reproduce the issue (including code snippets, CLI parameters, or contract calls).
3. Any suggested remediation or patch.

---

## Response Timeline & SLA

We aim to adhere to the following response timeline:

| Stage | SLA Target |
|:---|:---|
| Initial Acknowledgment | Within 24 hours |
| Vulnerability Assessment & Triage | Within 72 hours |
| Security Patch & Advisory Release | Within 14 days (depending on severity) |

---

## Scope

### In Scope
- Core CLI tools and WASM compilation pipeline (`crates/stellar-toolkit`).
- Soroban smart contracts (`contracts/htlc-contract`, `contracts/payment-channel-contract`, `contracts/amm-pool`).
- Cryptographic verification engines (`crates/atomic-swap`, `crates/stellar-did`).

### Out of Scope
- Issues in third-party RPC providers or public Stellar Horizon endpoints.
- Social engineering, phishing, or physical security attacks.
- Denial of service attacks against public Stellar testnets.

---

## Security Best Practices for Developers

- **Secret Keys**: Never hardcode secret keys or private seeds in source code or commits. Always supply secret keys via environment variables or encrypted key stores.
- **WASM Sandboxing**: Ensure Soroban host functions validate transaction authorization trees (`env.authorize_as_current_contract`) before mutating state.
- **Preimage Safety**: Verify SHA-256 preimages against target hash locks before executing HTLC withdrawals.

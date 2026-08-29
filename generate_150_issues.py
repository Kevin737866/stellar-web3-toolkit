#!/usr/bin/env python3
"""
Generate and post 150 distinct feature/roadmap issues for the
Kevin737866/stellar-web3-toolkit repository via the gh CLI.

Each issue is a unique, meaningful development task around Stellar/Soroban/Web3.

Usage:
    export GITHUB_TOKEN=...   # gh will pick this up
    ./generate_150_issues.py
"""

import subprocess
import sys
import time

OWNER = "Kevin737866"
REPO = "stellar-web3-toolkit"

# Each tuple: (title, group_key). We derive body + labels from the group.
ISSUES = [
    # --- Core smart contracts / Soroban basics ---
    ("Create reusable base library for Soroban contract development", "contract-basics"),
    ("Add contract metadata registration helper for Soroban wasm", "contract-basics"),
    ("Implement upgradeable proxy pattern for Soroban contracts", "contract-basics"),
    ("Build a contract versioning and migration framework", "contract-basics"),
    ("Add contract authentication and signing helper module", "contract-basics"),
    ("Implement admin-only guarded administrative functions", "contract-basics"),
    ("Add pause/unpause capability to managed contracts", "contract-basics"),
    ("Create contract event logging conventions and macros", "contract-basics"),
    ("Implement fee handling utilities for Soroban calls", "contract-basics"),
    ("Add cross-contract call helper abstractions", "contract-basics"),
    ("Build a storage access layer over Soroban persistent storage", "contract-basics"),
    ("Add error handling best-practice guidance with typed errors", "contract-basics"),

    # --- DeFi / AMM / DEX ---
    ("Implement stableswap invariant AMM (Curve-style)", "defi-amm"),
    ("Build concentrated liquidity market-maker contract", "defi-amm"),
    ("Add slippage-protected multi-hop swap router", "defi-amm"),
    ("Implement limit order matching engine on Soroban", "defi-amm"),
    ("Add flash-loan support to liquidity pool contracts", "defi-amm"),
    ("Build a farming/rewards staking pool contract", "defi-amm"),
    ("Implement liquidation engine for under-collateralized positions", "defi-amm"),
    ("Add on-chain price oracle with cumulative TWAP", "defi-amm"),
    ("Build a lending/borrowing lending pool contract", "defi-amm"),
    ("Create a DEX aggregator contract and SDK", "defi-amm"),
    ("Implement veToken-style governance for DEX fees", "defi-amm"),
    ("Add dynamic fee model based on volatility", "defi-amm"),
    ("Build impermanent-loss insurance contract", "defi-amm"),
    ("Add batch swap and routing optimization", "defi-amm"),
    ("Implement rebasing token support in pools", "defi-amm"),

    # --- Payments / payment channels ---
    ("Design multi-asset payment batching contract", "payments"),
    ("Build scheduled/recurring payments contract", "payments"),
    ("Implement escrow-based milestone payments", "payments"),
    ("Create a payment splitter among multiple beneficiaries", "payments"),
    ("Add cross-border fiat ramp integration guide", "payments"),
    ("Build on-chain invoice issuance and QR utility", "payments"),
    ("Implement atomic swap with HTLC referencing protocol spec", "payments"),
    ("Create a donation/tip jar contract", "payments"),
    ("Add payment streaming (Superfluid-style) for Stellar", "payments"),
    ("Build pending-unlock time-locked token contract", "payments"),
    ("Implement multi-sig approval payments", "payments"),
    ("Add payment notifications via event subscription", "payments"),

    # --- Identity / DID / Web3 ---
    ("Implement W3C DID document builder and resolver in Rust", "identity"),
    ("Add DID key rotation and recovery mechanism", "identity"),
    ("Build verifiable credential issuance contract", "identity"),
    ("Add verifiable presentation verification modules", "identity"),
    ("Create decentralized reputation scoring contract", "identity"),
    ("Implement on-chain social identity anchoring", "identity"),
    ("Add ENS-style domain registry for .stellar names", "identity"),
    ("Build zero-knowledge proof issuance tooling", "identity"),
    ("Add identity wallet credential manager SDK", "identity"),
    ("Implement account abstraction for user onboarding", "identity"),
    ("Create keyless login via passkey/session keys", "identity"),

    # --- Tokens / standards ---
    ("Implement SEP-41 token standard conformance suite", "tokens"),
    ("Add multi-signature token (multisig gov) contract", "tokens"),
    ("Build a wrapped/native pegged asset mint-burn bridge contract", "tokens"),
    ("Create community token with vesting schedules", "tokens"),
    ("Implement dividend/rebate distribution for token holders", "tokens"),
    ("Add token metadata registry with on-chain URIs", "tokens"),
    ("Build an NFT/SFT asset contract with metadata", "tokens"),
    ("Implement fractionalization of real-world assets", "tokens"),
    ("Create airdrop contract with claim and merkle proofs", "tokens"),
    ("Add token lockers and delegates", "tokens"),

    # --- Oracles & data ---
    ("Build native Stellar/Virgo price feed integration", "oracles"),
    ("Implement decentralized median-price oracle contract", "oracles"),
    ("Add on-chain random numbers via VRF-like source", "oracles"),
    ("Create sports/weather data market oracle", "oracles"),
    ("Build timestamped data caching for off-chain feeds", "oracles"),
    ("Add reputation-weighted oracle evaluation", "oracles"),
    ("Implement oracle aggregation with deviation triggers", "oracles"),
    ("Create bridge confirmation oracle for cross-chain data", "oracles"),

    # --- Cross-chain / interoperability ---
    ("Design cross-chain transfer protocol using Stellar bridge", "crosschain"),
    ("Build a lightweight token burn-mint bridge contract", "crosschain"),
    ("Add bridging SDK with unified interface", "crosschain"),
    ("Implement message passing for cross-chain contracts", "crosschain"),
    ("Add relay monitoring and fraud detection for bridges", "crosschain"),
    ("Create cross-chain swap coordination service", "crosschain"),
    ("Add Wells/AssetTransfer federated transfer integration", "crosschain"),
    ("Build bridge security audit and pause mechanism", "crosschain"),

    # --- Tooling / CLI / SDK ---
    ("Build CLI for contract lifecycle management", "tooling"),
    ("Add REPL for interactive Soroban contract testing", "tooling"),
    ("Create daemon for local Stellar+contract network", "tooling"),
    ("Add SDK client helpers for common workflows", "tooling"),
    ("Build typed TypeScript client generated from contract wasm", "tooling"),
    ("Add codegen for contract interfaces from specs", "tooling"),
    ("Create deployment snapshot and rollback tool", "tooling"),
    ("Add state inspector CLI for on-chain contracts", "tooling"),
    ("Build a local gas/cost simulator", "tooling"),
    ("Add project scaffolding generator (template repo)", "tooling"),
    ("Create lint/styling config for Soroban projects", "tooling"),
    ("Add hot-reload development workflow", "tooling"),

    # --- Governance / DAO ---
    ("Implement snapshot-based proposal voting contract", "governance"),
    ("Add quadratic voting support", "governance"),
    ("Build timelock governance execution", "governance"),
    ("Create delegating voter proxy", "governance"),
    ("Add on-chain treasury management contract", "governance"),
    ("Implement proposal cancellation and veto", "governance"),
    ("Create quorum and vote power calculation engine", "governance"),
    ("Build quadratic-quadratic conviction voting", "governance"),
    ("Add off-chain signal/forum synchronizer", "governance"),

    # --- Security / audits ---
    ("Add automated vulnerability scanning pipeline", "security"),
    ("Create security checklist template for contracts", "security"),
    ("Add fuzzing harness for contract boundaries", "security"),
    ("Build reentrancy protection utility module", "security"),
    ("Add gas-limit and griefing protections", "security"),
    ("Create threat model documentation for core contracts", "security"),
    ("Add access-control audit tooling", "security"),
    ("Implement key management and cold-storage guidance", "security"),
    ("Add informal-verification test framework", "security"),

    # --- Infrastructure / deployment ---
    ("Build CI pipeline for automated contract builds", "infra"),
    ("Add multi-environment deploy (dev/test/prod) configs", "infra"),
    ("Create Dockerized build environment for reproducible wasm", "infra"),
    ("Add GitHub Actions workflow for release of contracts", "infra"),
    ("Build monitoring dashboard for testnet contracts", "infra"),
    ("Add backup/restore for contract state snapshots", "infra"),
    ("Create deployment audit log", "infra"),
    ("Add alerting for anomalous on-chain activity", "infra"),
    ("Build key-rotation automation for deploy accounts", "infra"),
    ("Add reproducible bytecode verification tool", "infra"),

    # --- Wallet & UX ---
    ("Build web wallet UI for interacting with contracts", "wallet"),
    ("Add mobile wallet dapp example", "wallet"),
    ("Implement one-click claim airdrop UX", "wallet"),
    ("Create transaction builder/simulator for end users", "wallet"),
    ("Add hardware wallet support", "wallet"),
    ("Build QR-based p2p payment flow", "wallet"),
    ("Add gas funding faucet integration", "wallet"),
    ("Implement session-based UX with account abstraction", "wallet"),
    ("Create onboarding flow with recovery phrase backup", "wallet"),

    # --- Documentation / education ---
    ("Write getting-started tutorial for contract devs", "docs"),
    ("Create API reference site generation", "docs"),
    ("Add example gallery with runnable contracts", "docs"),
    ("Write best-practices guide for Soroban storage", "docs"),
    ("Add troubleshooting and FAQ documentation", "docs"),
    ("Create architecture decision records (ADR) index", "docs"),
    ("Write migration guide across SDK versions", "docs"),
    ("Add glossary of protocol terms", "docs"),
    ("Create contributor onboarding documentation", "docs"),
    ("Write security disclosure policy", "docs"),

    # --- NFT / digital assets ---
    ("Build a marketplace listing contract for digital assets", "tokens"),
    ("Add royalty splitter for secondary asset sales", "tokens"),
    ("Create collection-level permission and access control", "tokens"),
    ("Add blind-mint and sale phases for an NFT drop", "tokens"),

    # --- Staking / yield ---
    ("Implement delegated staking contract with auto-compounding", "defi-amm"),
    ("Build yield-farm position tracking across pools", "defi-amm"),

    # --- Testing & quality ---
    ("Add property-based testing framework for contracts", "testing"),
    ("Build integration test suite across full flows", "testing"),
    ("Add coverage report tooling", "testing"),
    ("Create mutation testing to validate suites", "testing"),
    ("Add contract invariant testing harness", "testing"),
    ("Build scenario-based testing DSL", "testing"),
    ("Add regression golden-file tests for serialization", "testing"),
    ("Create benchmark harness for gas usage", "testing"),
    ("Add differential testing against reference impl", "testing"),
]


BODIES = {
    "contract-basics": "## Description\nA foundational piece of the Stellar Web3 toolkit's smart-contract layer.\nThis issue covers reusable infrastructure used across Soroban contracts.\n\n## Acceptance Criteria\n- [ ] Design and document the module API\n- [ ] Implement in Rust with the Soroban SDK\n- [ ] Add unit tests (>=90% coverage)\n- [ ] Wire into an example contract\n- [ ] Add usage documentation with code samples\n\n## Technical Requirements\n- Rust / Soroban SDK\n- Contract conventions used across the repo",
    "defi-amm": "## Description\nDeFi-related enhancement to the toolkit focused on automated market makers, liquidity, and on-chain financial primitives on Stellar/Soroban.\n\n## Acceptance Criteria\n- [ ] Define contract interface and state layout\n- [ ] Implement core logic in Rust\n- [ ] Handle precision with fixed-point math\n- [ ] Add slippage/edge-case protection\n- [ ] Comprehensive test suite\n- [ ] Document economic parameters\n\n## Technical Requirements\n- Soroban Rust smart contracts\n- SEP-41 token standard\n- Fixed-point arithmetic",
    "payments": "## Description\nPayments feature for moving value on Stellar. Focused on usability, batching, and trustless settlement.\n\n## Acceptance Criteria\n- [ ] Specify transaction flow\n- [ ] Implement contract logic in Rust\n- [ ] Add refund/failure handling\n- [ ] Write integration tests\n- [ ] Provide SDK helpers\n\n## Technical Requirements\n- Stellar SDK\n- Soroban contracts\n- Proper event logging",
    "identity": "## Description\nDecentralized identity related capability for the Web3 toolkit, building on DID/verifiable credentials on Stellar.\n\n## Acceptance Criteria\n- [ ] Implement core identity logic\n- [ ] Add key management\n- [ ] Provide resolver/indexing\n- [ ] Test against W3C DID specs\n- [ ] Document flows\n\n## Technical Requirements\n- Rust / Soroban\n- W3C DID Core\n- Ed25519 keys",
    "tokens": "## Description\nToken-related capability following Stellar asset/SEP standards, extending the toolkit's asset layer.\n\n## Acceptance Criteria\n- [ ] Conform to relevant SEP standard\n- [ ] Implement functionality in Rust\n- [ ] Add comprehensive tests\n- [ ] Include example integration\n- [ ] Document usage\n\n## Technical Requirements\n- SEP-41 + related standards\n- Soroban tokens\n- Rust",
    "oracles": "## Description\nData oracle capability so contracts can safely consume off-chain information.\n\n## Acceptance Criteria\n- [ ] Define data schema + update flow\n- [ ] Implement oracle contract in Rust\n- [ ] Add freshness/authority checks\n- [ ] Provide consumer SDK\n- [ ] Test aggregation logic\n\n## Technical Requirements\n- Soroban contracts\n- Off-chain data ingestion\n- Confidence/freshness handling",
    "crosschain": "## Description\nCross-chain interoperability capability to move assets and messages across networks via Stellar bridges.\n\n## Acceptance Criteria\n- [ ] Define bridge message format\n- [ ] Implement mint/burn or wrap logic\n- [ ] Add relay monitoring\n- [ ] Harden against relay failure/fraud\n- [ ] Write end-to-end tests\n\n## Technical Requirements\n- Bridge contracts in Rust\n- Merkle/proof verification\n- Monitoring service",
    "tooling": "## Description\nDeveloper tooling improvement that makes building, testing, and deploying contracts smoother.\n\n## Acceptance Criteria\n- [ ] Design UX/CLI flow\n- [ ] Implement functionality\n- [ ] Add documentation + examples\n- [ ] Automated tests\n- [ ] Integrate with existing scripts\n\n## Technical Requirements\n- CLI / SDK in project's stack\n- Soroban tooling integration",
    "governance": "## Description\nOn-chain governance capability for the toolkit so token holders can coordinate changes.\n\n## Acceptance Criteria\n- [ ] Specify voting + proposal lifecycle\n- [ ] Implement in Rust\n- [ ] Add quorum/threshold logic\n- [ ] Timelock execution\n- [ ] Comprehensive tests\n\n## Technical Requirements\n- Soroban contracts\n- Vote power calculations\n- Timelock pattern",
    "security": "## Description\nSecurity-hardening effort to keep contracts safe against common smart-contract vulnerabilities.\n\n## Acceptance Criteria\n- [ ] Identify attack surface\n- [ ] Implement mitigations\n- [ ] Add automated checks\n- [ ] Document threat model\n- [ ] Update audit guidance\n\n## Technical Requirements\n- Rust / Soroban\n- Security best practices\n- Audit tooling",
    "infra": "## Description\nInfrastructure and deployment improvement for reproducible, auditable contract releases.\n\n## Acceptance Criteria\n- [ ] Set up automation\n- [ ] Add reproducible builds\n- [ ] Environment configs\n- [ ] Monitoring/alerting\n- [ ] Document runbooks\n\n## Technical Requirements\n- CI/CD\n- Docker/reproducible wasm\n- Monitoring stack",
    "wallet": "## Description\nWallet/user-experience capability that lets end users interact with toolkit contracts.\n\n## Acceptance Criteria\n- [ ] Wire wallet to contracts\n- [ ] Handle tx building/signing\n- [ ] Add recovery UX\n- [ ] Test key flows\n- [ ] Document setup\n\n## Technical Requirements\n- Wallet SDK\n- Transaction building\n- UX best practices",
    "docs": "## Description\nDocumentation improvement to make the toolkit easier to adopt and contribute to.\n\n## Acceptance Criteria\n- [ ] Identify gaps\n- [ ] Write/update docs\n- [ ] Add examples\n- [ ] Link from README\n- [ ] Review for accuracy\n\n## Technical Requirements\n- Markdown/docs tooling\n- Consistent style",
    "testing": "## Description\nTesting and quality-capability improvement to raise confidence in the toolkit.\n\n## Acceptance Criteria\n- [ ] Design test strategy\n- [ ] Implement tests/harness\n- [ ] Integrate into CI\n- [ ] Add coverage reporting\n- [ ] Document how to run\n\n## Technical Requirements\n- Rust test tooling\n- Property-based testing\n- CI integration",
}


def post_issue(title, body, labels):
    cmd = [
        "gh", "issue", "create",
        "--repo", f"{OWNER}/{REPO}",
        "--title", title,
        "--body", body,
    ]
    for label in labels:
        cmd += ["--label", label]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=120)
        url = proc.stdout.strip()
        print(f"  -> {url}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  !! FAILED: {e.stderr.strip()}")
        return False


def main():
    if len(ISSUES) != 150:
        print(f"WARNING: defined {len(ISSUES)} issues, expected 150", file=sys.stderr)

    # Create labels in a first pass so issue creation succeeds.
    for key in dict.fromkeys(["stellar-web3-toolkit"] + [g for _, g in ISSUES]):
        try:
            subprocess.run(
                ["gh", "label", "create", key, "--repo", f"{OWNER}/{REPO}",
                 "--description", f"topic: {key}", "--force"],
                capture_output=True, text=True,
            )
        except subprocess.SubprocessError:
            pass

    ok = 0
    fail = 0
    for i, (title, group) in enumerate(ISSUES, start=1):
        body = BODIES[group]
        labels = [group, "stellar-web3-toolkit"]
        print(f"[{i}/150] {title}")
        if post_issue(title, body, labels):
            ok += 1
        else:
            fail += 1
            break  # stop if there's an auth/rate-limit failure
        time.sleep(1)  # gentle pacing to avoid rate limits

    print(f"\nDone. Created: {ok}, Failed: {fail}")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
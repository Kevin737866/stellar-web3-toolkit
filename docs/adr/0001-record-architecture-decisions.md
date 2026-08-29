# ADR-0001: Record Architecture Decisions

* **Status**: Accepted
* **Date**: 2026-08-29
* **Authors**: Stellar Web3 Toolkit Core Team

## Context

As the **Stellar Web3 Toolkit** expands with CLI tools, Soroban smart contract templates, HTLC atomic swap modules, and DID resolvers, architectural choices need clear documentation to ensure long-term maintainability, transparency, and contributor alignment.

## Decision

We will adopt **Architecture Decision Records (ADRs)** stored directly in version control under `docs/adr/` in Markdown format.

Each ADR will detail:
1. Architectural context and problem statement.
2. The specific decision reached.
3. Positive and negative consequences/trade-offs.
4. Verification and compliance rules.

## Consequences

### Positive
* Transparent history of major architectural trade-offs.
* Standardized onboarding resource for new maintainers and contributors.
* Prevents recurring debates on past architectural choices.

### Negative
* Requires discipline to create and update ADRs during significant design changes.

# Stellar Payment Channel Network Specification

## Abstract

This specification defines a Lightning Network-style payment channel system built on the Stellar blockchain using Soroban smart contracts. The system enables instant, low-cost off-chain transactions with on-chain settlement, supporting multi-hop payments through a network of payment channels.

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Architecture](#2-system-architecture)
3. [Multi-Sig Escrow Account Structure](#3-multi-sig-escrow-account-structure)
4. [Channel Lifecycle](#4-channel-lifecycle)
5. [Off-Chain Payment State](#5-off-chain-payment-state)
6. [Hashed Time-Locked Contracts (HTLC)](#6-hashed-time-locked-contracts-htlc)
7. [Multi-Hop Payment Routing](#7-multi-hop-payment-routing)
8. [Channel Closing Mechanisms](#8-channel-closing-mechanisms)
9. [Watchtower Service](#9-watchtower-service)
10. [Channel Rebalancing](#10-channel-rebalancing)
11. [Formal Verification](#11-formal-verification)
12. [Network Simulation](#12-network-simulation)
13. [Security Considerations](#13-security-considerations)
14. [Implementation Details](#14-implementation-details)

---

## 1. Introduction

### 1.1 Purpose

The Stellar Payment Channel Network enables:
- **Instant Payments**: Sub-second settlement between channel participants
- **Low Fees**: Minimal on-chain transaction costs
- **Scalability**: Millions of transactions without blockchain bloat
- **Privacy**: Off-chain transactions are not publicly visible
- **Trustless**: No need to trust intermediate nodes in multi-hop payments

### 1.2 Scope

This implementation covers:
- Payment channel creation and management
- Off-chain state updates with cryptographic proofs
- HTLC-based conditional payments
- Multi-hop routing through intermediate nodes
- Cooperative and unilateral channel closing
- Watchtower monitoring for breach protection
- Network simulation for testing

---

## 2. System Architecture

### 2.1 Component Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Stellar Payment Channel Network               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │   Node A    │    │   Node B    │    │   Node C    │          │
│  │             │    │             │    │             │          │
│  │ ┌─────────┐ │    │ ┌─────────┐ │    │ ┌─────────┐ │          │
│  │ │Channel  │ │◄──►│ │Channel  │ │◄──►│ │Channel  │ │          │
│  │ │Manager  │ │    │ │Manager  │ │    │ │Manager  │ │          │
│  │ └─────────┘ │    │ └─────────┘ │    │ └─────────┘ │          │
│  │ ┌─────────┐ │    │ ┌─────────┐ │    │ ┌─────────┐ │          │
│  │ │ Router  │ │    │ │ Router  │ │    │ │ Router  │ │          │
│  │ └─────────┘ │    │ └─────────┘ │    │ └─────────┘ │          │
│  └─────────────┘    └─────────────┘    └─────────────┘          │
│         │                 │                   │                  │
│         └─────────────────┴───────────────────┘                  │
│                           │                                      │
│                    ┌─────────────┐                               │
│                    │  Watchtower │                               │
│                    │   Service  │                               │
│                    └─────────────┘                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Components

| Component | Description |
|-----------|-------------|
| **PaymentChannelContract** | Soroban smart contract for channel state |
| **ChannelManager** | Rust library for channel operations |
| **ChannelRouter** | Multi-hop payment routing algorithm |
| **Watchtower** | Breach detection and justice service |
| **NetworkSimulator** | Testing environment with 100+ nodes |

---

## 3. Multi-Sig Escrow Account Structure

### 3.1 Account Design

Each payment channel uses a 2-of-2 multi-signature setup:

```
┌─────────────────────────────────────────┐
│         Escrow Account (on-chain)        │
├─────────────────────────────────────────┤
│  Threshold: 2                           │
│  Signers: [Party A, Party B]            │
│  Balance: Initial funding + top-ups     │
└─────────────────────────────────────────┘
```

### 3.2 Channel ID Generation

Channel IDs are deterministically generated using:
```
ChannelID = SHA256(sorted(PubKey_A) || sorted(PubKey_B) || nonce)
```

### 3.3 State Storage

On-chain contract stores:
- Channel ID
- Participant public keys
- Current sequence number
- Timeout value
- Fee percentage

Off-chain state (local to each participant):
- Current balances
- HTLC details
- Revocable state commitments

---

## 4. Channel Lifecycle

### 4.1 Channel Opening

```
Alice                 Bob
   │                    │
   │  create_channel()  │
   │───────────────────►│
   │                    │
   │  [Both fund escrow] │
   │───────────────────►│
   │                    │
   │◄─ Channel Ready ────│
```

**Steps:**
1. Participants agree on initial balances
2. Both parties sign funding transaction
3. Funds deposited to escrow account
4. Channel state initialized on contract
5. Local state synchronized

### 4.2 Channel States

```rust
enum ChannelState {
    Open,           // Ready for payments
    Closing,        // Cooperative close in progress
    Closed,          // Successfully closed
    ForceClosed,     // Unilateral close initiated
    Dispute,         // Contest period active
}
```

### 4.3 Channel Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | 1440 blocks (~24 hours) | Unilateral close timeout |
| `fee_percentage` | 0.01% | Routing fee |
| `max_htlcs` | 100 | Maximum concurrent HTLCs |
| `min_htlc_value` | 100 stroops | Dust limit |
| `channel_reserve` | 1000 stroops | Minimum balance per side |

---

## 5. Off-Chain Payment State

### 5.1 State Update Protocol

```
1. Alice prepares new state:
   - balance_a = 8000
   - balance_b = 2000
   - sequence = 1

2. Alice signs state with her key

3. Alice sends signed state to Bob

4. Bob verifies:
   - Signatures valid
   - Total balance preserved
   - Balances non-negative

5. Bob signs and acknowledges

6. Both parties store new state
```

### 5.2 State Commitment

Each state update is committed with:
- New balance values
- Sequence number (incrementing)
- Digital signatures from both parties

### 5.3 Revocable State

Previous states become revocable after update:
```
Previous State → Revocable (after 1 confirmation)
                → Revoked (after justice period)
```

---

## 6. Hashed Time-Locked Contracts (HTLC)

### 6.1 HTLC Structure

```rust
struct HTLCInfo {
    htlc_id: BytesN<32>,
    hashlock: BytesN<32>,     // SHA256(preimage)
    timelock: u32,            // Block number
    amount: i128,
    receiver: Address,
    sender: Address,
    is_claimed: bool,
    is_refunded: bool,
}
```

### 6.2 HTLC Flow

```
Alice (Sender) ──── HTLC ────► Bob (Receiver)
                              hashlock = H(preimage)
                              timelock = 1440 blocks

Receiver knows preimage:
    claim_htlc(preimage) → Funds released

Timeout expires:
    refund_htlc() → Funds returned to sender
```

### 6.3 HTLC Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `min_timelock` | 144 blocks | Minimum HTLC timeout |
| `max_timelock` | 2016 blocks | Maximum HTLC timeout |
| `hash_function` | SHA256 | Hash algorithm for preimage |

---

## 7. Multi-Hop Payment Routing

### 7.1 Routing Algorithm

The router implements Dijkstra's algorithm with weighted edges:

```
Weight(channel) = base_fee + (amount * fee_rate / 1,000,000) + time_lock_fee

Path Cost = Σ channel_weights
```

### 7.2 Route Selection Criteria

1. **Minimum Cost**: Cheapest route by total fees
2. **Path Length**: Maximum 20 hops
3. **Capacity**: Each channel must have sufficient balance
4. **Fee Budget**: Total fees < configurable maximum
5. **CLTV Delta**: Cumulative time-lock requirements

### 7.3 Path-Finding Algorithm

```rust
pub fn find_best_route(
    source: &str,
    destination: &str,
    amount: i128,
    max_hops: usize,
    max_fee: i128,
) -> Result<Route, RoutingError> {
    // Dijkstra's algorithm
    // Priority queue ordered by accumulated cost
    // Early termination when destination reached
}
```

### 7.4 Routing Policies

```rust
struct RoutingPolicy {
    max_hops: 20,
    max_fee_bps: 1000,        // 10% of amount
    max_base_fee: 1000,       // stroops
    max_fee_rate: 10000,      // ppm (1%)
    excluded_nodes: HashSet,
    prefer_low_cltv: true,
}
```

---

## 8. Channel Closing Mechanisms

### 8.1 Cooperative Close

Both parties agree on final state:
```
1. Negotiate final balances
2. Both sign close transaction
3. Submit to escrow account
4. Funds released according to final state
```

**Advantages:**
- Fast (single transaction)
- No timeout needed
- Exact final balances

### 8.2 Unilateral Close

One party initiates close without agreement:

```
1. Initiator publishes latest state
2. Dispute period begins (timeout)
3. Other party can contest within period
4. If no contest, funds released
```

**Timeline:**
```
T+0: Unilateral close initiated
T+0 to T+timeout: Dispute period
T+timeout: Funds released if uncontested
```

### 8.3 Dispute Resolution

If a breach is detected:
```
1. Non-breaching party contests
2. Provides older state with higher balance
3. Breaching party penalized
4. Justice transaction submitted
```

---

## 9. Watchtower Service

### 9.1 Purpose

The watchtower monitors channels on behalf of users who may be offline, detecting and responding to breach attempts.

### 9.2 Monitoring Functions

```rust
struct Watchtower {
    subscribed_channels: HashSet<String>,
    justice_service: JusticeService,
}

impl Watchtower {
    // Monitor channel state
    async fn check_channel(&self, channel_id: &str) -> Result<Option<ChannelUpdate>>;
    
    // Detect breach attempts
    fn detect_breach(&self, old_state: &ChannelState, new_state: &ChannelState) -> Option<BreachAttempt>;
    
    // Submit justice transactions
    async fn submit_justice(&self, breach: &BreachAttempt) -> Result<()>;
}
```

### 9.3 Alert System

```rust
enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

enum AlertType {
    BreachAttempt { channel_id, old_seq, new_seq },
    HtlcTimeoutWarning { channel_id, htlc_id, blocks_remaining },
    JusticeSubmitted { channel_id, tx_hash },
    UnexpectedClose { channel_id, reason },
}
```

---

## 10. Channel Rebalancing

### 10.1 Rebalancing Methods

1. **Circular Rebalancing**: Alice → Bob → Carol → Alice
2. **Submarine Swaps**: On-chain XLM for off-chain capacity
3. **Manual Top-up**: Both parties add funds

### 10.2 Circular Rebalancing

```
Before:                    After:
Alice ─1000─ Bob    →     Alice ─500─ Bob
  │                         │
  │                         ▼
Carol ─500─ Carol         Carol ─1000─ Carol
```

### 10.3 Rebalancing Algorithm

```rust
pub fn find_rebalance_path(
    source: &str,
    target: &str,
    amount: i128,
    graph: &NetworkGraph,
) -> Result<Route, RoutingError> {
    // Find circular path: source → ... → target → source
    // Negotiate fees with intermediate nodes
    // Execute as series of HTLCs
}
```

---

## 11. Formal Verification

### 11.1 Invariants

The payment channel system maintains these invariants:

1. **Balance Conservation**: `balance_a + balance_b = total_balance`
2. **Non-Negativity**: `balance_a >= 0 && balance_b >= 0`
3. **Sequence Monotonicity**: `sequence_number` always increases
4. **HTLC Fund Reservation**: HTLC amount reserved until resolved

### 11.2 Security Properties

| Property | Description |
|----------|-------------|
| **Balance Security** | No party can steal funds |
| **State Validity** | Invalid states rejected |
| **Timeout Safety** | HTLCs always resolve |
| **Breach Penalty** | Cheating is unprofitable |

### 11.3 Threat Model

- **Collusion**: Honest parties cannot be cheated
- **Eclipse**: Network views are not manipulated
- **Replay**: Old states cannot be replayed
- **Front-Running**: HTLC claims cannot be front-run

---

## 12. Network Simulation

### 12.1 Simulation Parameters

```rust
struct SimulatorConfig {
    num_nodes: 100,              // 100+ nodes
    avg_channels_per_node: 5.0,  // Average connectivity
    min_channel_capacity: 1000,  // stroops
    max_channel_capacity: 100_000_000,
    num_payments: 1000,          // Test payments
    max_payment_amount: 1_000_000,
}
```

### 12.2 Network Topologies

| Topology | Description |
|----------|-------------|
| Random | Erdős–Rényi random graph |
| Scale-Free | Barabási–Albert preferential attachment |
| Small-World | Watts–Strogatz model |
| Grid | Lattice topology |
| Star | Single hub with spokes |
| Ring | Linear chain with wrap-around |

### 12.3 Simulation Metrics

```
- Success Rate: Percentage of successful payments
- Average Path Length: Hops per payment
- Network Utilization: Capacity usage
- Routing Efficiency: Fees vs. amount
- Payment Latency: Time to route
```

---

## 13. Security Considerations

### 13.1 On-Chain Security

- **Multi-Sig Threshold**: Always 2-of-2
- **Timeout Values**: Sufficient dispute periods
- **State Validation**: Strict sequence checking
- **Signature Verification**: Ed25519 required

### 13.2 Off-Chain Security

- **Revocable Commitments**: Old states can be challenged
- **Key Rotation**: Per-channel keys prevent historical breaches
- **Watchtower Delegation**: Backup monitoring service

### 13.3 HTLC Security

- **Hash Preimage**: 32 bytes of cryptographic randomness
- **Timelock Delta**: Prevents griefing with minimal timeouts
- **Expiry Monitoring**: Watchtower tracks pending HTLCs

---

## 14. Implementation Details

### 14.1 Smart Contract

Located at: `contracts/payment-channel-contract/`

Key functions:
- `initialize()` - Create new channel
- `update_state()` - Process off-chain update
- `create_htlc()` - Create HTLC
- `claim_htlc()` - Claim HTLC with preimage
- `refund_htlc()` - Refund expired HTLC
- `cooperative_close()` - Mutual channel close
- `initiate_unilateral_close()` - Force close
- `contest_close()` - Dispute invalid close

### 14.2 Router Library

Located at: `crates/channel-router/`

Key modules:
- `pathfinder.rs` - Dijkstra/A*/BFS algorithms
- `graph.rs` - Network graph data structure
- `policy.rs` - Routing policies and fee estimation

### 14.3 Watchtower Service

Located at: `crates/watchtower/`

Key modules:
- `monitor.rs` - Channel state monitoring
- `justice.rs` - Breach response transactions
- `storage.rs` - Persistent state storage

### 14.4 Network Simulator

Located at: `crates/channel-simulator/`

Key modules:
- `network.rs` - Topology generation
- `statistics.rs` - Network analysis

---

## 15. Conclusion

This specification defines a complete Lightning Network-style payment channel system for Stellar. The implementation provides:

- **Trustless Payments**: No need to trust intermediaries
- **Instant Settlement**: Sub-second off-chain transactions
- **Low Costs**: Minimal on-chain fees
- **Scalability**: Support for 100+ node networks
- **Security**: Formal invariants and breach detection

The system is production-ready and has been validated through network simulation with 100+ nodes.

---

## Appendix A: Error Codes

| Code | Error | Description |
|------|-------|-------------|
| 1 | ChannelNotFound | Channel does not exist |
| 2 | InvalidBalance | Balance is invalid |
| 3 | BalanceMismatch | Balances don't sum correctly |
| 4 | InvalidTimeout | Timeout value invalid |
| 5 | InvalidFee | Fee percentage invalid |
| 6 | InsufficientBalance | Not enough funds |
| 7 | UnauthorizedParticipant | Not a channel participant |
| 8-16 | HTLC Errors | HTLC-related failures |
| 17 | ActiveHtlcsExist | Cannot close with active HTLCs |

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| Channel | Bi-directional payment pathway |
| HTLC | Hash Time-Locked Contract |
| Escrow | On-chain locked funds |
| State | Current balances and sequence |
| Commitment | Signed state update |
| Justice | Breach penalty transaction |
| Watchtower | Monitoring service |

---

*Specification Version: 1.0*
*Last Updated: 2024*

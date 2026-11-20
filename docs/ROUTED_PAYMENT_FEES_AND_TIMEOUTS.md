# Routed Payment Fee and Timeout Calculation Guide

This guide details the exact fee, timelock (CLTV), and policy calculation formulas used by `crates/channel-router` across multi-hop payment channels.

---

## 1. Hop Fee Calculation Formula

Each channel in a payment path specifies a fee policy composed of:
1. `base_fee`: Fixed fee per transaction forwarding (in stroops / channel integer units).
2. `fee_rate`: Proportional fee in parts-per-million (ppm), where $10\,000 \text{ ppm} = 1.0\%$.

For a payment forwarding amount $A$:
$$\text{fee} = \text{base\_fee} + \left\lfloor \frac{A \times \text{fee\_rate}}{1\,000\,000} \right\rfloor$$

### Protocol Fee Caps
To protect senders against fee-gouging intermediate nodes, the pathfinder enforces strict protocol limits:
* Protocol max channel fee rate: $10\,000 \text{ ppm}$ ($1\%$).
* Protocol max channel base fee: $1000$ base units.
* Any channel advertising fees exceeding these caps is pruned during Dijkstra and A* exploration.

---

## 2. Multi-Hop Reverse Calculation Example

In multi-hop routing, fees are calculated **backwards from destination to source**:

Suppose Alice ($N_0$) pays Dave ($N_3$) 1,000,000 units over the route:
$$N_0 \xrightarrow{C_1} N_1 \xrightarrow{C_2} N_2 \xrightarrow{C_3} N_3$$

Channel Parameters:
* Channel $C_1$ ($N_0 \to N_1$): `base_fee = 10`, `fee_rate = 500 ppm` (0.05%), `cltv_delta = 40`
* Channel $C_2$ ($N_1 \to N_2$): `base_fee = 5`, `fee_rate = 1000 ppm` (0.10%), `cltv_delta = 30`
* Channel $C_3$ ($N_2 \to N_3$): `base_fee = 1`, `fee_rate = 200 ppm` (0.02%), `cltv_delta = 20`

### Step 1: Destination receives
* $N_3$ receives: $1\,000\,000$

### Step 2: Intermediate node $N_2$ forwarding fee
* Forwarding amount to $N_3$: $1\,000\,000$
* $N_2$ fee: $1 + \lfloor \frac{1\,000\,000 \times 200}{1\,000\,000} \rfloor = 1 + 200 = 201$
* $N_1$ must send to $N_2$: $1\,000\,000 + 201 = 1\,000\,201$

### Step 3: Intermediate node $N_1$ forwarding fee
* Forwarding amount to $N_2$: $1\,000\,201$
* $N_1$ fee: $5 + \lfloor \frac{1\,000\,201 \times 1000}{1\,000\,000} \rfloor = 5 + 1000 = 1005$
* $N_0$ must send to $N_1$: $1\,000\,201 + 1005 = 1\,001\,206$

### Summary
* Amount Dave receives: $1\,000\,000$
* Total fees collected: $201 + 1005 = 1206$
* Total amount Alice debits: $1\,001\,206$

---

## 3. CLTV Expiry Delta and Timeout Safety

Every hop enforces a `cltv_delta` (CheckLockTimeVerify block/ledger interval). The upstream HTLC lock duration must exceed the downstream HTLC lock duration by at least the intermediate node's `cltv_delta`.

$$\text{expiry}_{i} = \text{expiry}_{i+1} + \Delta_{\text{cltv}, i}$$

Assuming the payment settles at final ledger $L_{\text{final}} = 1000$:
* Hop $N_2 \to N_3$: Expiry = $1000 + 20 = 1020$
* Hop $N_1 \to N_2$: Expiry = $1020 + 30 = 1050$
* Hop $N_0 \to N_1$: Expiry = $1050 + 40 = 1090$

This 40-block cushion ensures that if Dave claims the HTLC on-chain at ledger 1000, Bob ($N_1$) has 40 ledgers to extract the preimage and settle the upstream HTLC with Alice ($N_0$) before the upstream HTLC expires.

---

## 4. Policy Rejection Diagnostics (#365)

When a candidate route fails validation, `RoutingPolicy::evaluate_route` generates structured `PolicyViolation` records:
* `MaxHopsExceeded`: Path length exceeds configured limit.
* `FeeBpsExceeded`: Route fee exceeds percentage cap of payment amount.
* `ExcludedNode` / `ExcludedChannel`: Path contains blacklisted topology elements.
* `AmountBelowMinimum` / `AmountAboveMaximum`: Payment violates channel or policy liquidity thresholds.

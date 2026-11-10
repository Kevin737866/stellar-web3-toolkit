# Channel Simulator Scenario Testing & Operational Guide

This document describes the scenario testing, deterministic reproducibility, latency simulation, fault injection, and statistical export capabilities in `crates/channel-simulator`.

## 1. Deterministic Seeding for Scenario Testing (#378)

Reproducible scenario testing is essential for verifying payment routing, fee policies, and topological edge cases across runs.

### Usage
```rust
use channel_simulator::{Simulator, SimulatorConfig};

// Configure an explicit deterministic seed
let config = SimulatorConfig::default()
    .with_seed(123456789);

let simulator = Simulator::new(config);
simulator.initialize_network()?;

// The effective seed is inspectable
assert_eq!(simulator.seed(), 123456789);

let stats = simulator.run_simulation().await?;
```

When `seed` is provided, all stochastic decisions—including channel capacities, random routing payment pairs, amounts, and path jitter—are fully deterministic. Running two simulators with the exact same seed generates identical node graphs and execution outputs.

---

## 2. Configurable Message Latency (#379)

Real-world payment networks experience varying network latencies depending on geographic distribution and peer links.

### Configuration
`SimulatorConfig` supports defining hop-by-hop latency bounds:
* `min_latency_ms`: Minimum message propagation latency per hop (default: 5 ms).
* `max_latency_ms`: Maximum message propagation latency per hop (default: 25 ms).

### Custom Channel Overrides
```rust
// Set an explicit latency for a specific channel
simulator.set_channel_latency("ch_node1_node2", 75);

// Query configured latency
assert_eq!(simulator.get_channel_latency("ch_node1_node2"), Some(75));
```

During simulation execution, total end-to-end payment latency is accumulated over all traversed hops and recorded in `SimulationStats.latency_ms`.

---

## 3. Temporary Node Disconnection and Fault Recovery (#380)

To model unreliable networks, node maintenance, and partitions, nodes can be dynamically disconnected and subsequently reconnected.

### Fault Injection API
```rust
// Disconnect a node
simulator.disconnect_node("node_alpha")?;
assert!(!simulator.is_node_connected("node_alpha"));

// Payments attempting to originate from, terminate at, or route through node_alpha fail
let stats = simulator.run_simulation().await?;

// Reconnect the node
simulator.reconnect_node("node_alpha")?;
assert!(simulator.is_node_connected("node_alpha"));
```

When a node is disconnected, the router will reject payments attempting to traverse the offline node, allowing validation of alternative path exploration and failover policies.

---

## 4. Machine-Readable JSON Export (#381)

Both `SimulationStats` and `NetworkStats` implement `Serialize` and `Deserialize` alongside native JSON export methods:

```rust
// Export to compact or formatted JSON
let json_str = stats.to_json()?;
let pretty_json = stats.to_json_pretty()?;

// Deserialize from JSON
let restored_stats = SimulationStats::from_json(&json_str)?;

// Write directly to file
stats.export_json_file("artifacts/simulation_results.json")?;
```

Exported metrics include `total_payments`, `successful_payments`, `failed_payments`, `total_value_routed`, `total_fees_collected`, `avg_path_length`, `max_path_length`, `success_rate`, and `latency_ms` distribution.

---

## 5. Bounded Fuzz Runs & Failure Reporting (#382)

Topology fuzzing can be bounded by execution duration to prevent timeouts in CI/CD pipelines while recording actionable diagnostics on failure.

### Configuration
```rust
use channel_simulator::fuzz::{TopologyFuzzer, TopologyFuzzConfig};
use std::time::Duration;

let config = TopologyFuzzConfig::default()
    .with_max_duration(Duration::from_secs(30));

let fuzzer = TopologyFuzzer::new(config);
let report = fuzzer.run();

if report.duration_bounded {
    println!("Fuzz run gracefully bounded after {:?}", report.elapsed);
}

if !report.is_clean() {
    println!("Failing seed: {:?}", report.failure_seed());
    println!("Diagnostic: {}", report.failure_diagnostic.unwrap_or_default());
}
```

If an invariant fails during execution, the first failing iteration's exact random seed is captured in `report.seed_on_failure` and `report.failure_diagnostic`, enabling immediate single-iteration reproduction:
```rust
fuzzer.run_iteration(iteration, &mut replay_report);
```

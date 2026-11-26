# Per-Strategy Keeper Execution Budgets (Issue #486)

Keeper processes now execute plans under explicit, per-strategy budgets. A
budget bounds three things for one run: the number of operations, the total
Soroban instructions those operations may consume, and the span of ledgers they
may cover.

## Public interface

| Item | Purpose |
|------|---------|
| `KeeperStrategy` | `Rebalance`, `Harvest`, or `ExecuteGovernance`. |
| `ExecutionBudget::new` | Validated `(max_operations, max_instructions, max_ledgers)` limits. |
| `KeeperBudgetConfig` | Explicit strategy-to-budget mapping. |
| `KeeperOperation::new` | One labelled operation with instructions and a ledger. |
| `BudgetedKeeper::execute` | Validate the whole plan, then commit it. |
| `BudgetedKeeper::execute_governance_plan` | Check governance role permissions and then run under the governance budget. |
| `ExecutionReport` | Measured consumption of an accepted run. |
| `KeeperBudgetError` | Actionable error naming the strategy, limit, and observed value. |

All types are exported from `stellar_toolkit` and live in
`crates/stellar-toolkit/src/keeper.rs`.

## Default budgets

`KeeperBudgetConfig::default()` provides backward-compatible starting limits:

| Strategy | Max operations | Max instructions | Max ledger span |
|----------|----------------|------------------|-----------------|
| `Rebalance` | 16 | 12,000,000 | 32 |
| `Harvest` | 32 | 8,000,000 | 64 |
| `ExecuteGovernance` | 4 | 4,000,000 | 16 |

Operators can override one strategy while keeping the others:

```rust
use stellar_toolkit::{
    BudgetedKeeper, ExecutionBudget, KeeperBudgetConfig, KeeperStrategy,
};

let config = KeeperBudgetConfig::default()
    .with_budget(
        KeeperStrategy::Harvest,
        ExecutionBudget::new(8, 2_000_000, 10).expect("valid budget"),
    );
let keeper = BudgetedKeeper::new(config);
```

`KeeperBudgetConfig::empty()` starts with no strategies. Running a strategy
that was not configured returns `KeeperBudgetError::MissingBudget`; no default
is silently substituted for an explicit configuration.

## Normal, boundary, and failure behavior

* A plan is accepted when it has at least one operation and stays within all
  three limits **at equality**. Exact-limit plans are covered by unit tests.
* More operations, more instructions, or a wider ledger span than the budget
  rejects the plan with an error naming both the observed value and the limit.
* An empty plan is rejected explicitly rather than reported as a successful
  no-op.
* A zero budget limit is rejected at construction; an overflowing instruction
  total is rejected before execution.
* A blank operation label is rejected so reports and errors stay actionable.
* Governance execution checks
  `stellar_toolkit::timelock::authorize_governance_action` first. An
  unauthorized role never reaches the budget check and commits nothing.

## Failure atomicity and recovery

`BudgetedKeeper::execute` checks the full plan before touching keeper state.
On any error, `applied_labels()` is unchanged. The caller can therefore retry
with a smaller plan or an explicit budget override without compensating for
partially applied work. After a successful run, `ExecutionReport` records what
was budgeted so operators can reconcile it with on-chain events.

No state is persisted outside the keeper instance, so there is no migration to
run and no rollback file to clean up.

## Compatibility

This is an additive module. No existing CLI command, contract entry point, or
governance permission check changed. Callers that do not construct a
`BudgetedKeeper` keep their previous behavior. Governance execution keeps the
same role checks; the budget is an additional opt-in gate.

## Validation

```bash
cargo fmt --all -- --check
cargo test -p stellar-toolkit --test keeper_budget_workflow
cargo test -p stellar-toolkit keeper
```

The integration test
`crates/stellar-toolkit/tests/keeper_budget_workflow.rs` covers exact limits,
one-over-limit rejection with unchanged state, and the authorized versus
unauthorized governance path.

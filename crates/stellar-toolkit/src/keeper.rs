//! Per-strategy execution budgets for keeper processes (issue #486).
//!
//! A keeper run is a plan of operations. Each strategy has its own
//! [`ExecutionBudget`], so a slow treasury harvest cannot consume the budget
//! reserved for a time-sensitive governance execution. [`BudgetedKeeper`]
//! validates a whole plan against the strategy budget **before** committing
//! any operation, which makes a rejected run a no-op for keeper state.
//!
//! The module is additive: callers that never construct a [`BudgetedKeeper`]
//! keep their existing behaviour. Governance execution opts into the same gate
//! through [`BudgetedKeeper::execute_governance_plan`], which checks the
//! existing [`crate::timelock::authorize_governance_action`] permission first.

use crate::timelock::{
    authorize_governance_action, GovernanceAction, GovernanceRole, TimelockError,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Keeper strategies with independently configured budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum KeeperStrategy {
    /// Rebalance liquidity across pools.
    Rebalance,
    /// Harvest and compound rewards.
    Harvest,
    /// Execute a governance action after its timelock expires.
    ExecuteGovernance,
}

impl KeeperStrategy {
    /// Stable lowercase name used in reports and operator output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rebalance => "rebalance",
            Self::Harvest => "harvest",
            Self::ExecuteGovernance => "execute_governance",
        }
    }
}

impl std::fmt::Display for KeeperStrategy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One operation in a keeper plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeeperOperation {
    /// Operator-facing label, used in reports and error messages.
    pub label: String,
    /// Worst-case Soroban instructions the operation may consume.
    pub instructions: u64,
    /// Ledger in which the operation will be submitted.
    pub ledger: u32,
}

impl KeeperOperation {
    /// Construct an operation, rejecting a label that cannot identify it in a report.
    ///
    /// # Errors
    ///
    /// Returns [`KeeperBudgetError::EmptyOperationLabel`] when `label` is blank.
    pub fn new(
        label: impl Into<String>,
        instructions: u64,
        ledger: u32,
    ) -> Result<Self, KeeperBudgetError> {
        let label = label.into();
        if label.trim().is_empty() {
            return Err(KeeperBudgetError::EmptyOperationLabel);
        }
        Ok(Self {
            label,
            instructions,
            ledger,
        })
    }
}

/// Hard limits for a single keeper run of one strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionBudget {
    operations: u32,
    instructions: u64,
    ledgers: u32,
}

impl ExecutionBudget {
    /// Validate and construct a budget. Every limit must be greater than zero.
    ///
    /// # Errors
    ///
    /// Returns [`KeeperBudgetError::InvalidLimit`] naming the zero field. No
    /// default is substituted: an operator must supply an explicit value.
    pub fn new(
        max_operations: u32,
        max_instructions: u64,
        max_ledgers: u32,
    ) -> Result<Self, KeeperBudgetError> {
        if max_operations == 0 {
            return Err(KeeperBudgetError::InvalidLimit {
                field: "max_operations",
                value: 0,
            });
        }
        if max_instructions == 0 {
            return Err(KeeperBudgetError::InvalidLimit {
                field: "max_instructions",
                value: 0,
            });
        }
        if max_ledgers == 0 {
            return Err(KeeperBudgetError::InvalidLimit {
                field: "max_ledgers",
                value: 0,
            });
        }
        Ok(Self {
            operations: max_operations,
            instructions: max_instructions,
            ledgers: max_ledgers,
        })
    }

    /// Maximum number of operations the run may contain.
    #[must_use]
    pub fn max_operations(self) -> u32 {
        self.operations
    }

    /// Maximum total instructions the run may consume.
    #[must_use]
    pub fn max_instructions(self) -> u64 {
        self.instructions
    }

    /// Maximum ledger span (`last ledger - first ledger`) the run may cover.
    #[must_use]
    pub fn max_ledgers(self) -> u32 {
        self.ledgers
    }

    fn check(
        self,
        strategy: KeeperStrategy,
        plan: &[KeeperOperation],
    ) -> Result<ExecutionReport, KeeperBudgetError> {
        if plan.is_empty() {
            return Err(KeeperBudgetError::EmptyPlan { strategy });
        }

        let operations = u32::try_from(plan.len()).unwrap_or(u32::MAX);
        if operations > self.operations {
            return Err(KeeperBudgetError::TooManyOperations {
                strategy,
                actual: operations,
                max: self.operations,
            });
        }

        let instructions = plan.iter().try_fold(0u64, |total, operation| {
            total.checked_add(operation.instructions)
        });
        let Some(instructions) = instructions else {
            return Err(KeeperBudgetError::InstructionOverflow { strategy });
        };
        if instructions > self.instructions {
            return Err(KeeperBudgetError::InstructionsExceeded {
                strategy,
                actual: instructions,
                max: self.instructions,
            });
        }

        let first_ledger = plan
            .iter()
            .map(|operation| operation.ledger)
            .min()
            .unwrap_or(0);
        let last_ledger = plan
            .iter()
            .map(|operation| operation.ledger)
            .max()
            .unwrap_or(0);
        let ledger_span = last_ledger - first_ledger;
        if ledger_span > self.ledgers {
            return Err(KeeperBudgetError::LedgerSpanExceeded {
                strategy,
                actual: ledger_span,
                max: self.ledgers,
            });
        }

        Ok(ExecutionReport {
            strategy,
            operations,
            instructions,
            first_ledger,
            last_ledger,
        })
    }
}

/// Measured consumption of an accepted keeper plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReport {
    /// Strategy the plan was executed under.
    pub strategy: KeeperStrategy,
    /// Number of operations committed.
    pub operations: u32,
    /// Total instructions budgeted by the plan.
    pub instructions: u64,
    /// Earliest ledger in the plan.
    pub first_ledger: u32,
    /// Latest ledger in the plan.
    pub last_ledger: u32,
}

/// Explicit budget mapping for every strategy a keeper may run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeeperBudgetConfig {
    budgets: BTreeMap<KeeperStrategy, ExecutionBudget>,
}

impl Default for KeeperBudgetConfig {
    fn default() -> Self {
        let mut budgets = BTreeMap::new();
        let _ = budgets.insert(
            KeeperStrategy::Rebalance,
            ExecutionBudget::new(16, 12_000_000, 32).expect("valid default budget"),
        );
        let _ = budgets.insert(
            KeeperStrategy::Harvest,
            ExecutionBudget::new(32, 8_000_000, 64).expect("valid default budget"),
        );
        let _ = budgets.insert(
            KeeperStrategy::ExecuteGovernance,
            ExecutionBudget::new(4, 4_000_000, 16).expect("valid default budget"),
        );
        Self { budgets }
    }
}

impl KeeperBudgetConfig {
    /// A config with no strategies configured.
    ///
    /// Useful when an operator wants to supply every budget explicitly: any
    /// missing strategy is an error rather than an implicit default.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            budgets: BTreeMap::new(),
        }
    }

    /// Set or replace the budget for `strategy`.
    #[must_use]
    pub fn with_budget(mut self, strategy: KeeperStrategy, budget: ExecutionBudget) -> Self {
        let _ = self.budgets.insert(strategy, budget);
        self
    }

    /// Look up a configured budget.
    #[must_use]
    pub fn budget(&self, strategy: KeeperStrategy) -> Option<ExecutionBudget> {
        self.budgets.get(&strategy).copied()
    }

    /// Return the configured budget or an actionable error.
    ///
    /// # Errors
    ///
    /// Returns [`KeeperBudgetError::MissingBudget`] when `strategy` was not
    /// configured.
    pub fn require_budget(
        &self,
        strategy: KeeperStrategy,
    ) -> Result<ExecutionBudget, KeeperBudgetError> {
        self.budget(strategy)
            .ok_or(KeeperBudgetError::MissingBudget { strategy })
    }

    /// Strategies with an explicit budget.
    pub fn strategies(&self) -> impl Iterator<Item = KeeperStrategy> + '_ {
        self.budgets.keys().copied()
    }
}

/// A keeper process whose runs are bounded by per-strategy budgets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetedKeeper {
    config: KeeperBudgetConfig,
    applied_labels: Vec<String>,
}

impl BudgetedKeeper {
    /// Create a keeper with the given budget configuration.
    #[must_use]
    pub fn new(config: KeeperBudgetConfig) -> Self {
        Self {
            config,
            applied_labels: Vec::new(),
        }
    }

    /// The budget configuration in use.
    #[must_use]
    pub fn config(&self) -> &KeeperBudgetConfig {
        &self.config
    }

    /// Labels of operations committed by accepted runs, in execution order.
    #[must_use]
    pub fn applied_labels(&self) -> &[String] {
        &self.applied_labels
    }

    /// Validate and execute `plan` under `strategy`.
    ///
    /// # Errors
    ///
    /// Returns a [`KeeperBudgetError`] describing the first failed invariant.
    /// On failure the keeper's applied state is untouched.
    pub fn execute(
        &mut self,
        strategy: KeeperStrategy,
        plan: &[KeeperOperation],
    ) -> Result<ExecutionReport, KeeperBudgetError> {
        let budget = self.config.require_budget(strategy)?;
        let report = budget.check(strategy, plan)?;

        let mut next = self.applied_labels.clone();
        next.extend(plan.iter().map(|operation| operation.label.clone()));
        self.applied_labels = next;
        Ok(report)
    }

    /// Execute a governance plan after checking the existing role permissions.
    ///
    /// # Errors
    ///
    /// Returns [`KeeperBudgetError::GovernanceAuthorization`] when `role` may
    /// not perform `action`, or a budget error when the plan exceeds its limits.
    /// Neither failure commits any operation.
    pub fn execute_governance_plan(
        &mut self,
        role: GovernanceRole,
        action: GovernanceAction,
        plan: &[KeeperOperation],
    ) -> Result<ExecutionReport, KeeperBudgetError> {
        authorize_governance_action(role, action)
            .map_err(|source| KeeperBudgetError::GovernanceAuthorization { source })?;
        self.execute(KeeperStrategy::ExecuteGovernance, plan)
    }
}

/// A rejected keeper run, with enough context to fix the plan or configuration.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KeeperBudgetError {
    /// The strategy has no explicit budget.
    #[error("keeper budget for {strategy} is not configured")]
    MissingBudget {
        /// Strategy that could not run.
        strategy: KeeperStrategy,
    },
    /// A budget limit was zero.
    #[error("keeper budget limit {field} must be greater than zero, got {value}")]
    InvalidLimit {
        /// Name of the invalid field.
        field: &'static str,
        /// Rejected value.
        value: u64,
    },
    /// The plan contains no operations.
    #[error("{strategy} plan is empty; submit at least one operation")]
    EmptyPlan {
        /// Strategy that could not run.
        strategy: KeeperStrategy,
    },
    /// An operation label was blank.
    #[error("keeper operation label must not be empty")]
    EmptyOperationLabel,
    /// The plan had more operations than the budget allows.
    #[error("{strategy} plan has {actual} operations, budget allows {max}")]
    TooManyOperations {
        /// Strategy that could not run.
        strategy: KeeperStrategy,
        /// Operations in the submitted plan.
        actual: u32,
        /// Configured maximum.
        max: u32,
    },
    /// The plan consumed more instructions than the budget allows.
    #[error("{strategy} plan consumes {actual} instructions, budget allows {max}")]
    InstructionsExceeded {
        /// Strategy that could not run.
        strategy: KeeperStrategy,
        /// Instructions in the submitted plan.
        actual: u64,
        /// Configured maximum.
        max: u64,
    },
    /// The plan spanned more ledgers than the budget allows.
    #[error("{strategy} plan spans {actual} ledgers, budget allows {max}")]
    LedgerSpanExceeded {
        /// Strategy that could not run.
        strategy: KeeperStrategy,
        /// Ledger span of the submitted plan.
        actual: u32,
        /// Configured maximum.
        max: u32,
    },
    /// Instruction totals overflowed `u64`.
    #[error("{strategy} instruction total overflowed u64")]
    InstructionOverflow {
        /// Strategy that could not run.
        strategy: KeeperStrategy,
    },
    /// The governance role was not permitted to execute the action.
    #[error("governance execution is not authorized: {source}")]
    GovernanceAuthorization {
        /// Underlying role check error.
        #[source]
        source: TimelockError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn operation(label: impl Into<String>, instructions: u64, ledger: u32) -> KeeperOperation {
        KeeperOperation::new(label, instructions, ledger).expect("valid operation")
    }

    #[test]
    fn default_config_covers_every_strategy() {
        let config = KeeperBudgetConfig::default();
        let configured: BTreeSet<_> = config.strategies().collect();
        assert_eq!(
            configured,
            BTreeSet::from([
                KeeperStrategy::Rebalance,
                KeeperStrategy::Harvest,
                KeeperStrategy::ExecuteGovernance
            ])
        );
        for strategy in configured {
            let budget = config.require_budget(strategy).expect("default budget");
            assert!(budget.max_operations() > 0);
            assert!(budget.max_instructions() > 0);
            assert!(budget.max_ledgers() > 0);
        }
    }

    #[test]
    fn zero_limits_are_rejected_explicitly() {
        assert_eq!(
            ExecutionBudget::new(0, 10, 10),
            Err(KeeperBudgetError::InvalidLimit {
                field: "max_operations",
                value: 0
            })
        );
        assert_eq!(
            ExecutionBudget::new(1, 0, 10),
            Err(KeeperBudgetError::InvalidLimit {
                field: "max_instructions",
                value: 0
            })
        );
        assert_eq!(
            ExecutionBudget::new(1, 10, 0),
            Err(KeeperBudgetError::InvalidLimit {
                field: "max_ledgers",
                value: 0
            })
        );
    }

    #[test]
    fn blank_operation_labels_are_rejected() {
        assert_eq!(
            KeeperOperation::new("   ", 1, 1),
            Err(KeeperBudgetError::EmptyOperationLabel)
        );
    }

    #[test]
    fn exact_limits_are_accepted() {
        let budget = ExecutionBudget::new(2, 100, 5).expect("valid budget");
        let plan = [operation("first", 40, 10), operation("second", 60, 15)];
        let report = budget
            .check(KeeperStrategy::Harvest, &plan)
            .expect("exact budget is allowed");
        assert_eq!(report.operations, 2);
        assert_eq!(report.instructions, 100);
        assert_eq!(report.first_ledger, 10);
        assert_eq!(report.last_ledger, 15);
    }

    #[test]
    fn each_limit_failure_is_actionable() {
        let budget = ExecutionBudget::new(2, 100, 5).expect("valid budget");

        let error = budget
            .check(
                KeeperStrategy::Harvest,
                &[
                    operation("a", 1, 10),
                    operation("b", 1, 11),
                    operation("c", 1, 12),
                ],
            )
            .expect_err("too many operations");
        assert_eq!(
            error,
            KeeperBudgetError::TooManyOperations {
                strategy: KeeperStrategy::Harvest,
                actual: 3,
                max: 2
            }
        );

        let error = budget
            .check(
                KeeperStrategy::Harvest,
                &[operation("a", 60, 10), operation("b", 41, 10)],
            )
            .expect_err("too many instructions");
        assert_eq!(
            error,
            KeeperBudgetError::InstructionsExceeded {
                strategy: KeeperStrategy::Harvest,
                actual: 101,
                max: 100
            }
        );

        let error = budget
            .check(
                KeeperStrategy::Harvest,
                &[operation("a", 1, 10), operation("b", 1, 16)],
            )
            .expect_err("ledger span too long");
        assert_eq!(
            error,
            KeeperBudgetError::LedgerSpanExceeded {
                strategy: KeeperStrategy::Harvest,
                actual: 6,
                max: 5
            }
        );
    }

    #[test]
    fn empty_plan_and_instruction_overflow_are_rejected() {
        let budget = ExecutionBudget::new(2, 100, 5).expect("valid budget");
        assert_eq!(
            budget.check(KeeperStrategy::Rebalance, &[]),
            Err(KeeperBudgetError::EmptyPlan {
                strategy: KeeperStrategy::Rebalance
            })
        );

        let error = budget
            .check(
                KeeperStrategy::Rebalance,
                &[operation("a", u64::MAX, 10), operation("b", 1, 10)],
            )
            .expect_err("overflow");
        assert_eq!(
            error,
            KeeperBudgetError::InstructionOverflow {
                strategy: KeeperStrategy::Rebalance
            }
        );
    }

    #[test]
    fn missing_budget_is_not_replaced_with_a_default() {
        let keeper = BudgetedKeeper::new(KeeperBudgetConfig::empty());
        let error = keeper
            .config()
            .require_budget(KeeperStrategy::Rebalance)
            .expect_err("no implicit default");
        assert_eq!(
            error,
            KeeperBudgetError::MissingBudget {
                strategy: KeeperStrategy::Rebalance
            }
        );
    }

    #[test]
    fn failed_run_does_not_mutate_keeper_state() {
        let mut keeper = BudgetedKeeper::new(KeeperBudgetConfig::default());
        let plan = [
            operation("collect", 100, 10),
            operation("compound", 200, 11),
        ];
        keeper
            .execute(KeeperStrategy::Harvest, &plan)
            .expect("first run accepted");
        assert_eq!(keeper.applied_labels(), ["collect", "compound"]);

        let oversized: Vec<_> = (0..33)
            .map(|index| operation(format!("op-{index}"), 1, 10))
            .collect();
        let error = keeper
            .execute(KeeperStrategy::Harvest, &oversized)
            .expect_err("over budget");
        assert!(matches!(error, KeeperBudgetError::TooManyOperations { .. }));
        assert_eq!(keeper.applied_labels(), ["collect", "compound"]);
    }

    #[test]
    fn governance_runs_require_authorization_before_budgeting() {
        let mut keeper = BudgetedKeeper::new(KeeperBudgetConfig::default());
        let plan = [operation("upgrade", 1_000, 100)];

        let error = keeper
            .execute_governance_plan(
                GovernanceRole::Voter,
                GovernanceAction::ExecuteUpgrade,
                &plan,
            )
            .expect_err("voter may not execute");
        assert!(matches!(
            error,
            KeeperBudgetError::GovernanceAuthorization { .. }
        ));
        assert!(keeper.applied_labels().is_empty());

        let report = keeper
            .execute_governance_plan(
                GovernanceRole::TimelockAdmin,
                GovernanceAction::ExecuteUpgrade,
                &plan,
            )
            .expect("authorized run");
        assert_eq!(report.strategy, KeeperStrategy::ExecuteGovernance);
        assert_eq!(keeper.applied_labels(), ["upgrade"]);
    }

    #[test]
    fn strategy_names_are_stable() {
        assert_eq!(KeeperStrategy::Rebalance.as_str(), "rebalance");
        assert_eq!(KeeperStrategy::Harvest.as_str(), "harvest");
        assert_eq!(
            KeeperStrategy::ExecuteGovernance.as_str(),
            "execute_governance"
        );
    }
}

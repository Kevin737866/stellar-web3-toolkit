use stellar_toolkit::{
    BudgetedKeeper, ExecutionBudget, KeeperBudgetConfig, KeeperBudgetError, KeeperOperation,
    KeeperStrategy,
};
use stellar_toolkit::{GovernanceAction, GovernanceRole};

#[test]
fn keeper_budget_workflow_handles_normal_boundary_and_failure_cases() {
    let config = KeeperBudgetConfig::default().with_budget(
        KeeperStrategy::Harvest,
        ExecutionBudget::new(2, 200, 5).unwrap(),
    );
    let mut keeper = BudgetedKeeper::new(config);

    let exact_plan = [
        KeeperOperation::new("harvest-rewards", 100, 100).unwrap(),
        KeeperOperation::new("compound", 100, 105).unwrap(),
    ];
    let report = keeper
        .execute(KeeperStrategy::Harvest, &exact_plan)
        .unwrap();
    assert_eq!(report.operations, 2);
    assert_eq!(report.instructions, 200);
    assert_eq!(keeper.applied_labels(), ["harvest-rewards", "compound"]);

    let over_budget = [
        KeeperOperation::new("harvest-rewards", 100, 100).unwrap(),
        KeeperOperation::new("compound", 101, 105).unwrap(),
    ];
    let error = keeper
        .execute(KeeperStrategy::Harvest, &over_budget)
        .expect_err("one instruction over the boundary must fail");
    assert_eq!(
        error,
        KeeperBudgetError::InstructionsExceeded {
            strategy: KeeperStrategy::Harvest,
            actual: 201,
            max: 200
        }
    );
    assert_eq!(keeper.applied_labels(), ["harvest-rewards", "compound"]);
}

#[test]
fn governance_keeper_workflow_is_backward_compatible_and_atomic() {
    let mut keeper = BudgetedKeeper::new(KeeperBudgetConfig::default());
    let plan = [KeeperOperation::new("execute-upgrade", 1_000, 500).unwrap()];

    assert!(keeper
        .execute_governance_plan(
            GovernanceRole::Voter,
            GovernanceAction::ExecuteUpgrade,
            &plan,
        )
        .is_err());
    assert!(keeper.applied_labels().is_empty());

    let report = keeper
        .execute_governance_plan(
            GovernanceRole::TimelockAdmin,
            GovernanceAction::ExecuteUpgrade,
            &plan,
        )
        .unwrap();
    assert_eq!(report.strategy, KeeperStrategy::ExecuteGovernance);

    let previously_valid = keeper
        .config()
        .require_budget(KeeperStrategy::Rebalance)
        .unwrap();
    assert!(previously_valid.max_operations() > 0);
}

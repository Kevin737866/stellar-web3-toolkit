//! Verification harness stub (#202) and automated compliance checklist (#203).
//!
//! Provides a lightweight, deterministic verification harness for running
//! contract pre-deployment assertions alongside the property-based invariant
//! suite, plus a structured compliance checklist evaluator for Soroban
//! contracts and release artifacts.

use crate::invariants::{run_suite, SuiteReport, DEFAULT_SEED};
use serde::{Deserialize, Serialize};

/// A single assertion step executed by [`VerificationHarness`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationStep {
    pub id: String,
    pub description: String,
    pub passed: bool,
    pub details: Option<String>,
}

/// Aggregated report produced by [`VerificationHarness::run`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationHarnessReport {
    pub target: String,
    pub seed: u64,
    pub steps: Vec<VerificationStep>,
    pub invariant_suite: Option<SuiteReport>,
}

impl VerificationHarnessReport {
    /// True when every verification step and any attached invariant suite passed.
    pub fn passed(&self) -> bool {
        let steps_ok = self.steps.iter().all(|s| s.passed);
        let suite_ok = self
            .invariant_suite
            .as_ref()
            .map(SuiteReport::passed)
            .unwrap_or(true);
        steps_ok && suite_ok
    }

    /// Number of failed verification steps.
    pub fn failed_steps(&self) -> usize {
        self.steps.iter().filter(|s| !s.passed).count()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }

    pub fn render(&self) -> String {
        let mut out = format!(
            "verification harness: {} (seed {})\n",
            self.target, self.seed
        );
        for step in &self.steps {
            let status = if step.passed { "PASS" } else { "FAIL" };
            out.push_str(&format!(
                "  {status}  {:<28} {}\n",
                step.id, step.description
            ));
            if let Some(details) = &step.details {
                out.push_str(&format!("        {details}\n"));
            }
        }
        if let Some(suite) = &self.invariant_suite {
            out.push_str(&suite.render());
        }
        out
    }
}

type AssertionFn = Box<dyn Fn(u64) -> std::result::Result<(), String>>;

struct RegisteredAssertion {
    id: String,
    description: String,
    check: AssertionFn,
}

/// Deterministic verification harness for contract and toolkit checks (#202).
pub struct VerificationHarness {
    target: String,
    seed: u64,
    invariant_iterations: Option<u64>,
    assertions: Vec<RegisteredAssertion>,
}

impl VerificationHarness {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            seed: DEFAULT_SEED,
            invariant_iterations: None,
            assertions: Vec::new(),
        }
    }

    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    pub fn with_invariant_suite(mut self, iterations: u64) -> Self {
        self.invariant_iterations = Some(iterations.max(1));
        self
    }

    pub fn add_assertion<F>(
        mut self,
        id: impl Into<String>,
        description: impl Into<String>,
        check: F,
    ) -> Self
    where
        F: Fn(u64) -> std::result::Result<(), String> + 'static,
    {
        self.assertions.push(RegisteredAssertion {
            id: id.into(),
            description: description.into(),
            check: Box::new(check),
        });
        self
    }

    /// Standard pre-deployment verification stub with baseline sanity assertions.
    pub fn standard_stub(target: impl Into<String>) -> Self {
        Self::new(target)
            .add_assertion(
                "harness::seed_nonzero",
                "verification PRNG seed must be non-zero for deterministic replay",
                |seed| {
                    if seed == 0 {
                        Err("seed must not be zero".to_string())
                    } else {
                        Ok(())
                    }
                },
            )
            .add_assertion(
                "harness::arithmetic_checked",
                "checked i128 boundary arithmetic must reject overflow",
                |_| {
                    if i128::MAX.checked_add(1).is_none() && i128::MIN.checked_sub(1).is_none() {
                        Ok(())
                    } else {
                        Err("i128 boundary overflow was not trapped".to_string())
                    }
                },
            )
    }

    /// Execute all registered assertions and any configured invariant suite.
    pub fn run(&self) -> VerificationHarnessReport {
        let mut steps = Vec::with_capacity(self.assertions.len());
        for assertion in &self.assertions {
            match (assertion.check)(self.seed) {
                Ok(()) => steps.push(VerificationStep {
                    id: assertion.id.clone(),
                    description: assertion.description.clone(),
                    passed: true,
                    details: None,
                }),
                Err(reason) => steps.push(VerificationStep {
                    id: assertion.id.clone(),
                    description: assertion.description.clone(),
                    passed: false,
                    details: Some(reason),
                }),
            }
        }

        let invariant_suite = self
            .invariant_iterations
            .map(|iterations| run_suite(self.seed, iterations));

        VerificationHarnessReport {
            target: self.target.clone(),
            seed: self.seed,
            steps,
            invariant_suite,
        }
    }
}

// ---------------------------------------------------------------------------
// Compliance checklist (#203)
// ---------------------------------------------------------------------------

/// Domain category for a compliance requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceCategory {
    NoStdContract,
    AccessControl,
    StorageTtl,
    OverflowSafety,
    EmergencyPause,
    KeyHygiene,
}

impl ComplianceCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoStdContract => "no_std_contract",
            Self::AccessControl => "access_control",
            Self::StorageTtl => "storage_ttl",
            Self::OverflowSafety => "overflow_safety",
            Self::EmergencyPause => "emergency_pause",
            Self::KeyHygiene => "key_hygiene",
        }
    }
}

/// One item in a [`ComplianceChecklist`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceItem {
    pub id: String,
    pub category: ComplianceCategory,
    pub requirement: String,
    pub mandatory: bool,
    pub satisfied: bool,
    pub evidence: String,
}

/// Automated compliance checklist for Soroban contracts and releases (#203).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceChecklist {
    pub target: String,
    pub items: Vec<ComplianceItem>,
}

impl ComplianceChecklist {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            items: Vec::new(),
        }
    }

    pub fn add_item(&mut self, item: ComplianceItem) {
        self.items.push(item);
    }

    /// True when every mandatory item in the checklist is satisfied.
    pub fn passed(&self) -> bool {
        self.items
            .iter()
            .filter(|item| item.mandatory)
            .all(|item| item.satisfied)
    }

    /// All mandatory items that have not been satisfied.
    pub fn mandatory_failures(&self) -> Vec<&ComplianceItem> {
        self.items
            .iter()
            .filter(|item| item.mandatory && !item.satisfied)
            .collect()
    }

    /// Completion score in basis points (`0..=10_000`).
    pub fn score_bps(&self) -> u32 {
        if self.items.is_empty() {
            return 10_000;
        }
        let satisfied = self.items.iter().filter(|i| i.satisfied).count() as u64;
        ((satisfied * 10_000) / self.items.len() as u64) as u32
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }

    pub fn render(&self) -> String {
        let mut out = format!(
            "compliance checklist: {} (score {} bps, passed={})\n",
            self.target,
            self.score_bps(),
            self.passed()
        );
        for item in &self.items {
            let mark = if item.satisfied { "[x]" } else { "[ ]" };
            let req_tag = if item.mandatory {
                "mandatory"
            } else {
                "optional"
            };
            out.push_str(&format!(
                "  {mark} {:<24} ({:<9}) {}\n        evidence: {}\n",
                item.id, req_tag, item.requirement, item.evidence
            ));
        }
        out
    }

    /// Evaluate a Soroban contract source file against standard security and
    /// operational compliance checks.
    pub fn evaluate_contract_source(target: impl Into<String>, source: &str) -> Self {
        let mut checklist = Self::new(target);

        let has_no_std = source.contains("#![no_std]");
        checklist.add_item(ComplianceItem {
            id: "SOROBAN-001".to_string(),
            category: ComplianceCategory::NoStdContract,
            requirement: "Contract crate declares #![no_std]".to_string(),
            mandatory: true,
            satisfied: has_no_std,
            evidence: if has_no_std {
                "found #![no_std] attribute".to_string()
            } else {
                "missing #![no_std] attribute".to_string()
            },
        });

        let has_auth = source.contains("require_auth(");
        checklist.add_item(ComplianceItem {
            id: "SOROBAN-002".to_string(),
            category: ComplianceCategory::AccessControl,
            requirement: "State-mutating entrypoints enforce caller authorization".to_string(),
            mandatory: true,
            satisfied: has_auth,
            evidence: if has_auth {
                "found require_auth() guard".to_string()
            } else {
                "no require_auth() call detected".to_string()
            },
        });

        let has_ttl = source.contains("extend_ttl(");
        checklist.add_item(ComplianceItem {
            id: "SOROBAN-003".to_string(),
            category: ComplianceCategory::StorageTtl,
            requirement: "Persistent state records extend storage TTL".to_string(),
            mandatory: false,
            satisfied: has_ttl,
            evidence: if has_ttl {
                "found extend_ttl() call".to_string()
            } else {
                "no extend_ttl() call detected".to_string()
            },
        });

        let has_checked_math = source.contains("checked_add(")
            || source.contains("checked_sub(")
            || source.contains("checked_mul(")
            || source.contains("saturating_");
        checklist.add_item(ComplianceItem {
            id: "SOROBAN-004".to_string(),
            category: ComplianceCategory::OverflowSafety,
            requirement: "Token/accounting arithmetic uses checked or saturating operations"
                .to_string(),
            mandatory: true,
            satisfied: has_checked_math,
            evidence: if has_checked_math {
                "found checked/saturating arithmetic".to_string()
            } else {
                "no checked or saturating arithmetic detected".to_string()
            },
        });

        let secret_findings = crate::key_hygiene::scan_text(std::path::Path::new("contract.rs"), source);
        let clean_secrets = secret_findings.iter().all(|f| !f.is_error());
        checklist.add_item(ComplianceItem {
            id: "SOROBAN-005".to_string(),
            category: ComplianceCategory::KeyHygiene,
            requirement: "Source contains no hardcoded secret keys or mnemonics".to_string(),
            mandatory: true,
            satisfied: clean_secrets,
            evidence: if clean_secrets {
                "key hygiene scan passed with 0 errors".to_string()
            } else {
                format!("key hygiene flagged {} error(s)", secret_findings.len())
            },
        });

        checklist
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_verification_harness_stub_passes() {
        let harness = VerificationHarness::standard_stub("delegated-staking")
            .with_seed(42)
            .with_invariant_suite(16);
        let report = harness.run();
        assert!(report.passed(), "{}", report.render());
        assert_eq!(report.failed_steps(), 0);
        assert_eq!(report.steps.len(), 2);
        assert!(report.invariant_suite.is_some());
    }

    #[test]
    fn verification_harness_reports_failed_assertion() {
        let harness = VerificationHarness::standard_stub("broken-contract")
            .with_seed(0);
        let report = harness.run();
        assert!(!report.passed());
        assert_eq!(report.failed_steps(), 1);
        assert!(report.render().contains("FAIL"));
    }

    #[test]
    fn compliance_checklist_passes_valid_soroban_source() {
        let sample = r#"
            #![no_std]
            pub fn deposit(env: Env, user: Address, amount: i128) {
                user.require_auth();
                let next = amount.checked_add(1).unwrap();
                env.storage().persistent().extend_ttl(&user, 100, 200);
            }
        "#;
        let checklist = ComplianceChecklist::evaluate_contract_source("sample-pool", sample);
        assert!(checklist.passed(), "{}", checklist.render());
        assert_eq!(checklist.mandatory_failures().len(), 0);
        assert_eq!(checklist.score_bps(), 10_000);
    }

    #[test]
    fn compliance_checklist_flags_missing_mandatory_controls() {
        let sample = "pub fn insecure(amount: i128) -> i128 { amount + 1 }";
        let checklist = ComplianceChecklist::evaluate_contract_source("insecure", sample);
        assert!(!checklist.passed());
        let failures = checklist.mandatory_failures();
        assert!(failures.iter().any(|f| f.id == "SOROBAN-001"));
        assert!(failures.iter().any(|f| f.id == "SOROBAN-002"));
        assert!(failures.iter().any(|f| f.id == "SOROBAN-004"));
    }
}

//! Cargo audit allowlist checks (issue #185).
//!
//! `cargo audit` reports every advisory that matches something in
//! `Cargo.lock`. Some of them cannot be fixed on our schedule — an upstream
//! crate has not cut a release yet, or the vulnerable path is not reachable from
//! this workspace. Suppressing those is legitimate, but an allowlist that is
//! never re-examined quietly becomes a list of accepted vulnerabilities.
//!
//! This module makes the allowlist an artifact that is *checked*:
//!
//! * every entry must carry a reason (a bare `RUSTSEC-...` tells a reviewer
//!   nothing);
//! * every entry may carry an expiry, and an expired entry fails the check —
//!   the suppression has to be renewed deliberately, not by neglect;
//! * every advisory the audit actually reported must be suppressed, so a new
//!   advisory cannot slip in behind an allowlist that looks maintained;
//! * an entry for an advisory the audit no longer reports is called out as stale,
//!   because it is the residue that makes allowlists grow forever.
//!
//! The `cargo audit` invocation itself is the caller's job: this module takes the
//! audit output as input, so the rules are testable without the network or a
//! pinned advisory database.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Default location of the allowlist, relative to the workspace root.
pub const ALLOWLIST_PATH: &str = "audit-allowlist.toml";

/// An entry is only useful if a reviewer can act on it; shorter reasons are
/// treated as missing.
pub const MIN_REASON_LEN: usize = 12;

/// One suppressed advisory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowlistEntry {
    /// Advisory id, e.g. `RUSTSEC-2024-0001`.
    pub id: String,
    /// Why this workspace accepts the advisory.
    pub reason: String,
    /// `YYYY-MM-DD` after which the suppression must be re-justified.
    pub expires: Option<String>,
}

/// An advisory `cargo audit` reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    pub id: String,
    pub package: String,
}

/// What the check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// The entry has no usable reason.
    Unjustified { id: String },
    /// The entry's expiry is not a date.
    BadExpiry { id: String, expires: String },
    /// The suppression lapsed.
    Expired { id: String, expires: String },
    /// `cargo audit` reported this and nothing suppresses it.
    Unsuppressed { id: String, package: String },
    /// The allowlist suppresses an advisory the audit no longer reports.
    Stale { id: String },
}

impl Problem {
    /// Everything except `Stale` fails the check.
    ///
    /// A lapsed or missing justification is as much a gate failure as a live
    /// advisory: if it only warned, the allowlist would silently become a list of
    /// accepted vulnerabilities, which is the failure mode this check exists to
    /// prevent. `Stale` is the exception — an entry for an advisory that is gone
    /// is harmless residue, worth cleaning but not worth blocking a merge on.
    pub fn is_error(&self) -> bool {
        !matches!(self, Self::Stale { .. })
    }

    pub fn message(&self) -> String {
        match self {
            Self::Unjustified { id } => {
                format!("{id}: no reason recorded — say why this workspace accepts it")
            }
            Self::BadExpiry { id, expires } => {
                format!("{id}: expiry {expires} is not YYYY-MM-DD")
            }
            Self::Expired { id, expires } => format!(
                "{id}: suppression lapsed on {expires} — re-justify it or fix the dependency"
            ),
            Self::Unsuppressed { id, package } => {
                format!("{id} in {package} is not suppressed — fix it, or add a justified entry")
            }
            Self::Stale { id } => {
                format!("{id}: no longer reported by cargo audit — remove the entry")
            }
        }
    }
}

/// Outcome of a check run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditCheckReport {
    pub problems: Vec<Problem>,
    /// Entries that passed every rule, for the summary line.
    pub accepted: usize,
}

impl AuditCheckReport {
    pub fn errors(&self) -> usize {
        self.problems.iter().filter(|p| p.is_error()).count()
    }

    pub fn warnings(&self) -> usize {
        self.problems.iter().filter(|p| !p.is_error()).count()
    }

    pub fn passed(&self) -> bool {
        self.errors() == 0
    }

    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "audit allowlist: {} accepted, {} error(s), {} warning(s)",
            self.accepted,
            self.errors(),
            self.warnings()
        );
        for problem in &self.problems {
            let level = if problem.is_error() {
                "error"
            } else {
                "warning"
            };
            let _ = writeln!(out, "  {level}: {}", problem.message());
        }
        out
    }

    pub fn to_json(&self) -> String {
        let problems: Vec<serde_json::Value> = self
            .problems
            .iter()
            .map(|p| {
                serde_json::json!({
                    "severity": if p.is_error() { "error" } else { "warning" },
                    "message": p.message(),
                })
            })
            .collect();
        serde_json::json!({
            "accepted": self.accepted,
            "errors": self.errors(),
            "warnings": self.warnings(),
            "passed": self.passed(),
            "problems": problems,
        })
        .to_string()
    }
}

/// A calendar date, so expiry comparison does not need a date library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    pub year: i32,
    pub month: u32,
    pub day: u32,
}

impl Date {
    /// Parse `YYYY-MM-DD`, rejecting impossible days so a typo in the allowlist is
    /// reported rather than silently comparing as a small number.
    pub fn parse(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split('-').collect();
        if parts.len() != 3 {
            return None;
        }
        let year = parts[0].parse::<i32>().ok()?;
        let month = parts[1].parse::<u32>().ok()?;
        let day = parts[2].parse::<u32>().ok()?;
        if !(1..=12).contains(&month) {
            return None;
        }
        let max_day = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            _ => {
                let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
                if leap {
                    29
                } else {
                    28
                }
            }
        };
        if day == 0 || day > max_day {
            return None;
        }
        Some(Self { year, month, day })
    }

    /// Today, in UTC, from the system clock.
    pub fn today() -> Self {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Self::from_unix_secs(secs as i64)
    }

    /// Civil date from Unix seconds (Howard Hinnant's `civil_from_days`).
    pub fn from_unix_secs(secs: i64) -> Self {
        let days = secs.div_euclid(86_400);
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = if m <= 2 { y + 1 } else { y };
        Self {
            year: year as i32,
            month: m as u32,
            day: d as u32,
        }
    }
}

/// Parse the `[[deny.ignore]]` array from an `audit-allowlist.toml`.
///
/// A file with no `deny` table at all is an empty allowlist, not an error: a
/// workspace that has never suppressed anything should still be checkable.
pub fn parse_allowlist(text: &str) -> Result<Vec<AllowlistEntry>, String> {
    let parsed: AllowlistFile =
        toml::from_str(text).map_err(|e| format!("audit-allowlist.toml is not valid TOML: {e}"))?;
    Ok(parsed.deny.ignore)
}

#[derive(Debug, Deserialize)]
struct AllowlistFile {
    #[serde(default)]
    deny: DenyTable,
}

#[derive(Debug, Default, Deserialize)]
struct DenyTable {
    #[serde(default)]
    ignore: Vec<AllowlistEntry>,
}

/// Apply every allowlist rule.
///
/// `today` is a parameter rather than read from the clock so the rules can be
/// tested at a fixed date.
pub fn check(entries: &[AllowlistEntry], advisories: &[Advisory], today: Date) -> AuditCheckReport {
    let mut problems = Vec::new();
    let mut accepted = 0;

    for entry in entries {
        let mut ok = true;

        if entry.reason.trim().len() < MIN_REASON_LEN {
            problems.push(Problem::Unjustified {
                id: entry.id.clone(),
            });
            ok = false;
        }

        if let Some(expires) = &entry.expires {
            match Date::parse(expires) {
                Some(date) if date < today => {
                    problems.push(Problem::Expired {
                        id: entry.id.clone(),
                        expires: expires.clone(),
                    });
                    ok = false;
                }
                Some(_) => {}
                None => {
                    problems.push(Problem::BadExpiry {
                        id: entry.id.clone(),
                        expires: expires.clone(),
                    });
                    ok = false;
                }
            }
        }

        if ok {
            accepted += 1;
        }
    }

    let suppressed: HashSet<&str> = entries.iter().map(|e| e.id.as_str()).collect();

    for advisory in advisories {
        if !suppressed.contains(advisory.id.as_str()) {
            problems.push(Problem::Unsuppressed {
                id: advisory.id.clone(),
                package: advisory.package.clone(),
            });
        }
    }

    let reported: HashSet<&str> = advisories.iter().map(|a| a.id.as_str()).collect();
    for entry in entries {
        if !reported.contains(entry.id.as_str()) {
            problems.push(Problem::Stale {
                id: entry.id.clone(),
            });
        }
    }

    AuditCheckReport { problems, accepted }
}

/// Extract the advisories from `cargo audit --json` output.
///
/// The schema nests the id and package under `advisory`:
///
/// ```json
/// { "vulnerabilities": { "list": [ { "advisory": { "id": "RUSTSEC-...",
///                                                 "package": "time" } } ] } }
/// ```
///
/// Only the fields the check needs are read, and an entry without an id is
/// skipped rather than failing the whole run: the goal is to suppress what the
/// audit reports, not to re-implement its schema.
pub fn parse_audit_json(text: &str) -> Result<Vec<Advisory>, String> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("cargo audit output is not JSON: {e}"))?;
    let mut out = Vec::new();
    let Some(entries) = value
        .get("vulnerabilities")
        .and_then(|v| v.get("list"))
        .and_then(|v| v.as_array())
    else {
        return Ok(out);
    };
    for entry in entries {
        let Some(advisory) = entry.get("advisory") else {
            continue;
        };
        let Some(id) = advisory.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let package = advisory
            .get("package")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        out.push(Advisory {
            id: id.to_string(),
            package: package.to_string(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, reason: &str, expires: Option<&str>) -> AllowlistEntry {
        AllowlistEntry {
            id: id.to_string(),
            reason: reason.to_string(),
            expires: expires.map(ToString::to_string),
        }
    }

    fn advisory(id: &str, package: &str) -> Advisory {
        Advisory {
            id: id.to_string(),
            package: package.to_string(),
        }
    }

    fn today() -> Date {
        Date {
            year: 2026,
            month: 11,
            day: 20,
        }
    }

    const GOOD_REASON: &str = "not reachable from the wasm entry points";

    #[test]
    fn a_justified_live_entry_passes() {
        let entries = [entry("RUSTSEC-2024-0001", GOOD_REASON, Some("2027-01-01"))];
        let advisories = [advisory("RUSTSEC-2024-0001", "time")];
        let report = check(&entries, &advisories, today());
        assert!(report.passed(), "{:?}", report.problems);
        assert_eq!(report.accepted, 1);
        assert_eq!(report.warnings(), 0);
    }

    #[test]
    fn a_bare_entry_is_unjustified() {
        let entries = [entry("RUSTSEC-2024-0001", "", None)];
        let advisories = [advisory("RUSTSEC-2024-0001", "time")];
        let report = check(&entries, &advisories, today());
        assert!(!report.passed(), "an unjustified entry must fail the check");
        assert_eq!(report.errors(), 1);
        assert!(matches!(report.problems[0], Problem::Unjustified { .. }));
    }

    #[test]
    fn a_short_reason_counts_as_missing() {
        let entries = [entry("RUSTSEC-2024-0001", "todo", None)];
        let advisories = [advisory("RUSTSEC-2024-0001", "time")];
        let report = check(&entries, &advisories, today());
        assert_eq!(report.errors(), 1);
    }

    #[test]
    fn an_expired_suppression_is_reported() {
        let entries = [entry("RUSTSEC-2024-0001", GOOD_REASON, Some("2026-11-19"))];
        let advisories = [advisory("RUSTSEC-2024-0001", "time")];
        let report = check(&entries, &advisories, today());
        assert!(matches!(report.problems[0], Problem::Expired { .. }));
        assert_eq!(report.accepted, 0);
        assert!(
            !report.passed(),
            "a lapsed suppression must fail, not warn: that is the whole point"
        );
    }

    #[test]
    fn an_expiry_on_today_still_holds() {
        let entries = [entry("RUSTSEC-2024-0001", GOOD_REASON, Some("2026-11-20"))];
        let advisories = [advisory("RUSTSEC-2024-0001", "time")];
        assert!(check(&entries, &advisories, today()).passed());
    }

    #[test]
    fn a_malformed_expiry_is_reported_not_ignored() {
        let entries = [entry("RUSTSEC-2024-0001", GOOD_REASON, Some("next year"))];
        let advisories = [advisory("RUSTSEC-2024-0001", "time")];
        let report = check(&entries, &advisories, today());
        assert!(matches!(report.problems[0], Problem::BadExpiry { .. }));
        assert!(
            !report.passed(),
            "a typo must not silently disable the expiry"
        );
    }

    #[test]
    fn an_unsuppressed_advisory_fails_the_check() {
        let entries = [entry("RUSTSEC-2024-0001", GOOD_REASON, None)];
        let advisories = [
            advisory("RUSTSEC-2024-0001", "time"),
            advisory("RUSTSEC-2024-0002", "url"),
        ];
        let report = check(&entries, &advisories, today());
        assert!(!report.passed(), "a live advisory must fail the check");
        assert_eq!(report.errors(), 1);
        assert!(matches!(report.problems[0], Problem::Unsuppressed { .. }));
    }

    #[test]
    fn a_stale_entry_is_called_out() {
        let entries = [entry("RUSTSEC-2020-0009", GOOD_REASON, None)];
        let report = check(&entries, &[], today());
        assert!(report.passed(), "stale entries are warnings");
        assert!(matches!(report.problems[0], Problem::Stale { .. }));
    }

    #[test]
    fn an_empty_allowlist_with_a_clean_audit_passes() {
        let report = check(&[], &[], today());
        assert!(report.passed());
        assert_eq!(report.problems.len(), 0);
    }

    #[test]
    fn dates_compare_as_calendar_dates() {
        assert!(Date::parse("2026-11-20").unwrap() < Date::parse("2026-11-21").unwrap());
        assert!(Date::parse("2026-12-01").unwrap() > Date::parse("2026-11-30").unwrap());
        assert!(Date::parse("2027-01-01").unwrap() > Date::parse("2026-12-31").unwrap());
    }

    #[test]
    fn impossible_dates_are_rejected() {
        for bad in [
            "2026-13-01",
            "2026-00-01",
            "2026-11-31",
            "2026-02-30",
            "26-11",
            "x",
        ] {
            assert!(Date::parse(bad).is_none(), "{bad} should not parse");
        }
    }

    #[test]
    fn february_29_exists_only_in_leap_years() {
        assert!(Date::parse("2024-02-29").is_some());
        assert!(Date::parse("2026-02-29").is_none());
        assert!(Date::parse("2000-02-29").is_some());
        assert!(Date::parse("1900-02-29").is_none());
    }

    #[test]
    fn the_civil_conversion_matches_known_dates() {
        assert_eq!(
            Date::from_unix_secs(0),
            Date {
                year: 1970,
                month: 1,
                day: 1
            }
        );
        // 2026-11-20T00:00:00Z
        assert_eq!(
            Date::from_unix_secs(1_795_132_800),
            Date {
                year: 2026,
                month: 11,
                day: 20
            }
        );
    }

    #[test]
    fn the_allowlist_parses_from_toml() {
        let text = r#"
[[deny.ignore]]
id = "RUSTSEC-2024-0001"
reason = "not reachable from the wasm entry points"
expires = "2027-01-01"
"#;
        let entries = parse_allowlist(text).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "RUSTSEC-2024-0001");
    }

    #[test]
    fn an_allowlist_without_entries_is_empty_not_an_error() {
        let entries = parse_allowlist("").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn the_audit_json_yields_the_advisory_ids() {
        let json = r#"{
            "vulnerabilities": {
                "found": true,
                "count": 1,
                "list": [
                    { "advisory": { "id": "RUSTSEC-2024-0001", "package": "time" } }
                ]
            }
        }"#;
        let advisories = parse_audit_json(json).unwrap();
        assert_eq!(advisories.len(), 1);
    }
}

//! Integration tests for opaque page cursors in `inspect state` (issue #313).
//!
//! These exercise the CLI binary end to end: a token printed by one invocation
//! must resume the same walk in the next, while malformed, conflicting or stale
//! tokens must fail instead of silently returning a different page.

use assert_cmd::Command;
use serde_json::Value;
use std::process::Output;

fn run(args: &[&str]) -> Output {
    Command::cargo_bin("stellar-toolkit")
        .expect("the CLI binary is built by cargo")
        .args(["inspect", "state"])
        .args(args)
        .output()
        .expect("invoke the CLI")
}

fn json_page(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let start = stdout
        .find('{')
        .expect("a JSON page after the summary line");
    serde_json::from_str(&stdout[start..]).expect("the CLI prints valid JSON")
}

fn next_token(page: &Value) -> String {
    page["next_page_token"]
        .as_str()
        .expect("a token for the following page")
        .to_string()
}

fn keys(page: &Value) -> Vec<String> {
    page["entries"]
        .as_array()
        .expect("entries array")
        .iter()
        .map(|entry| entry["key"].as_str().unwrap().to_string())
        .collect()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn opaque_cursors_walk_the_export_without_repeats_or_skips() {
    let first = json_page(&run(&["--page-size", "2", "--json"]));
    assert_eq!(first["offset"], 0);
    assert_eq!(first["total"], 5);
    assert_eq!(keys(&first), vec!["Config", "Lp/Balance/GTRADER"], "page 1");

    let token = next_token(&first);
    assert!(
        token.starts_with("s1."),
        "tokens must be opaque and versioned"
    );
    let second = json_page(&run(&[
        "--page-size",
        "2",
        "--json",
        "--page-cursor",
        &token,
    ]));
    assert_eq!(second["offset"], 2);
    assert_eq!(second["page_index"], 1);
    assert_eq!(
        keys(&second),
        vec!["Pool/CDEMO7POOLCONTRC", "Reserves/A"],
        "page 2"
    );

    let token = next_token(&second);
    let third = json_page(&run(&[
        "--page-size",
        "2",
        "--json",
        "--page-cursor",
        &token,
    ]));
    assert_eq!(keys(&third), vec!["Reserves/B"], "page 3");
    assert!(third.get("next_page_token").is_none());
    assert_eq!(third["has_more"], false);

    // The legacy numeric cursor still addresses the same page and format.
    let legacy = json_page(&run(&["--page-size", "2", "--json", "--cursor", "2"]));
    assert_eq!(keys(&legacy), keys(&second));
    assert_eq!(legacy["next_cursor"], second["next_cursor"]);
}

#[test]
fn human_output_keeps_the_legacy_cursor_and_adds_a_page_token() {
    let output = run(&["--page-size", "2"]);
    assert!(output.status.success());
    let text = stdout(&output);
    assert!(text.contains("next cursor: 2"), "legacy line: {text}");
    assert!(
        text.contains("next page token: s1."),
        "opaque cursor line: {text}"
    );
}

#[test]
fn invalid_and_conflicting_cursor_inputs_fail_without_printing_a_page() {
    let first = json_page(&run(&["--page-size", "2", "--json"]));
    let token = next_token(&first);

    let bad = run(&[
        "--page-size",
        "2",
        "--json",
        "--page-cursor",
        "not-a-cursor",
    ]);
    assert!(!bad.status.success());
    assert!(stderr(&bad).contains("malformed"), "{}", stderr(&bad));
    assert!(
        !stdout(&bad).contains("filter matched"),
        "no page summary may be printed for a rejected cursor"
    );

    let changed = run(&["--page-size", "3", "--json", "--page-cursor", &token]);
    assert!(!changed.status.success());
    assert!(
        stderr(&changed).contains("page size"),
        "{}",
        stderr(&changed)
    );

    let both = run(&[
        "--page-size",
        "2",
        "--json",
        "--page-cursor",
        &token,
        "--cursor",
        "2",
    ]);
    assert!(!both.status.success());
    assert!(
        stderr(&both).contains("use either --cursor"),
        "{}",
        stderr(&both)
    );

    let all = run(&[
        "--page-size",
        "2",
        "--json",
        "--page-cursor",
        &token,
        "--all-pages",
    ]);
    assert!(!all.status.success());
    assert!(
        stderr(&all).contains("cannot be combined with --all-pages"),
        "{}",
        stderr(&all)
    );
}

#[test]
fn a_cursor_from_a_changed_export_is_rejected_explicitly() {
    let dir = tempfile::tempdir().expect("temporary export directory");
    let path = dir.path().join("state.json");
    std::fs::write(
        &path,
        r#"[
          {"contract_id":"CPOOL","durability":"persistent","key":"A","value":"1","ledger":7},
          {"contract_id":"CPOOL","durability":"persistent","key":"B","value":"2","ledger":7},
          {"contract_id":"CPOOL","durability":"persistent","key":"C","value":"3","ledger":7}
        ]"#,
    )
    .unwrap();
    let input = path.to_str().unwrap();

    let first = json_page(&run(&["--input", input, "--page-size", "1", "--json"]));
    assert_eq!(keys(&first), vec!["A".to_string()]);
    let second = json_page(&run(&[
        "--input",
        input,
        "--page-size",
        "1",
        "--json",
        "--page-cursor",
        &next_token(&first),
    ]));
    assert_eq!(keys(&second), vec!["B".to_string()]);
    let token = next_token(&second); // points at offset 2

    // The export shrinks between calls: the cursor now points past its end.
    std::fs::write(
        &path,
        r#"[{"contract_id":"CPOOL","durability":"persistent","key":"A","value":"1","ledger":7}]"#,
    )
    .unwrap();
    let stale = run(&[
        "--input",
        input,
        "--page-size",
        "1",
        "--json",
        "--page-cursor",
        &token,
    ]);
    assert!(!stale.status.success());
    let message = stderr(&stale);
    assert!(
        message.contains("past the 1 entries") && message.contains("state export may have changed"),
        "actionable stale-cursor error: {message}"
    );
    assert!(
        !stdout(&stale).contains("filter matched"),
        "no page may be printed for a stale cursor"
    );
}

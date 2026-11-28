//! Integration tests for exporting contract state inspection results as JSON
//! (issue #312).
//!
//! `inspect state --json` prints one page at a time. `--output <path>` writes the
//! complete filtered result to a single, self-describing JSON document that
//! `--input` can read back. These tests drive the real binary so both directions
//! of that round trip are covered end to end.

use assert_cmd::Command;
use std::path::Path;

fn toolkit() -> Command {
    Command::cargo_bin("stellar-toolkit").expect("binary builds")
}

fn stdout_of(args: &[&str]) -> String {
    let output = toolkit().args(args).assert().success().get_output().clone();
    String::from_utf8(output.stdout).expect("utf-8 stdout")
}

#[test]
fn exports_every_matching_entry_to_one_json_document() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let stdout = stdout_of(&[
        "inspect",
        "state",
        "--output",
        path.to_str().unwrap(),
        "--include-temporary",
    ]);
    assert!(
        stdout.contains("exported 7 entries"),
        "the summary must report the exported count: {stdout}"
    );

    let json = std::fs::read_to_string(&path).expect("export file exists");
    let value: serde_json::Value = serde_json::from_str(&json).expect("export is valid JSON");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["total"], 7);
    assert_eq!(value["include_temporary"], true);
    assert_eq!(value["contract_id"], serde_json::Value::Null);
    let entries = value["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 7);
    // Stable order, so a diff of two exports only shows real changes.
    assert_eq!(entries[0]["key"], "Config");
    assert_eq!(entries[6]["key"], "PendingInit/2");
    assert_eq!(entries[6]["durability"], "temporary");
    assert!(
        json.ends_with('\n'),
        "a text export should end in a newline"
    );
}

#[test]
fn export_is_complete_even_when_pagination_is_small() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    // `--page-size` shapes terminal output; it must not truncate an export.
    let stdout = stdout_of(&[
        "inspect",
        "state",
        "--output",
        path.to_str().unwrap(),
        "--page-size",
        "2",
    ]);
    assert!(stdout.contains("exported 5 entries"), "{stdout}");

    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(value["total"], 5);
    assert_eq!(value["entries"].as_array().unwrap().len(), 5);
    // Temporary entries are excluded by default, and the document records that.
    assert_eq!(value["include_temporary"], false);
}

#[test]
fn exported_document_can_be_inspected_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pool-state.json");

    stdout_of(&[
        "inspect",
        "state",
        "--output",
        path.to_str().unwrap(),
        "--contract",
        "CDEMO7POOLCONTRACTID",
    ]);

    let stdout = stdout_of(&[
        "inspect",
        "state",
        "--input",
        path.to_str().unwrap(),
        "--contract",
        "CDEMO7POOLCONTRACTID",
        "--json",
    ]);
    let json = stdout
        .split_once('{')
        .map(|(_, rest)| format!("{{{rest}"))
        .expect("the page is printed as a JSON object");
    let value: serde_json::Value = serde_json::from_str(&json).expect("page JSON parses");
    assert_eq!(value["contract_id"], "CDEMO7POOLCONTRACTID");
    assert_eq!(value["total"], 4);
    assert_eq!(value["entries"].as_array().unwrap().len(), 4);
}

#[test]
fn export_creates_missing_directories() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reports/2026/state.json");
    assert!(!path.parent().unwrap().exists());

    stdout_of(&["inspect", "state", "--output", path.to_str().unwrap()]);
    assert!(path.exists(), "the export must be written through new dirs");
    assert!(Path::new(&path).is_file());
}

#[test]
fn without_output_the_command_still_renders_a_page() {
    let stdout = stdout_of(&["inspect", "state", "--page-size", "2"]);
    assert!(stdout.contains("next cursor: 2"), "{stdout}");
    assert!(stdout.contains("pass --cursor 2 to continue"), "{stdout}");
}

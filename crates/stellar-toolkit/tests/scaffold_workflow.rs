//! Integration tests for scaffold template name validation (issue #315).

use stellar_toolkit::scaffolder::lint_directory;
use stellar_toolkit::{validate_template_name, ScaffoldOptions, Scaffolder};

#[test]
fn scaffold_workflow_accepts_valid_kebab_case_name_and_lints_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    validate_template_name("my-token").expect("valid template name");

    let scaffolder = Scaffolder::new(ScaffoldOptions::new("my-token"));
    let written = scaffolder.write(dir.path(), false).unwrap();
    assert_eq!(written.len(), 5);

    let report = lint_directory(dir.path()).unwrap();
    assert!(report.passed(), "unexpected findings: {report:?}");
}

#[test]
fn scaffold_workflow_rejects_unsafe_or_invalid_names_with_no_files_created() {
    for invalid in ["", "../escape", "nested/name", "UpperCase", "bad_name"] {
        let dir = tempfile::tempdir().unwrap();
        let scaffolder = Scaffolder::new(ScaffoldOptions::new(invalid));
        let err = scaffolder.write(dir.path(), false).unwrap_err();
        assert!(
            err.to_string().contains("invalid template name"),
            "unexpected error for '{invalid}': {err}"
        );
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "no files should be created when '{invalid}' fails validation"
        );
    }
}

#[test]
fn scaffold_workflow_boundary_length_validation() {
    let dir = tempfile::tempdir().unwrap();
    let max_valid = "a".repeat(64);
    let scaffolder = Scaffolder::new(ScaffoldOptions::new(max_valid));
    assert!(scaffolder.write(dir.path(), false).is_ok());

    let too_long_dir = tempfile::tempdir().unwrap();
    let too_long = "a".repeat(65);
    let err = Scaffolder::new(ScaffoldOptions::new(too_long))
        .write(too_long_dir.path(), false)
        .unwrap_err();
    assert!(err.to_string().contains("exceeds maximum"));
    assert_eq!(std::fs::read_dir(too_long_dir.path()).unwrap().count(), 0);
}

//! Integration tests for the pre-execution verifier. Drives
//! `aegis_host::verifier::verify` directly. These tests assert the
//! same word-boundary and string/comment-stripping behavior that the
//! original inline unit tests covered, but routed through the public
//! entry point so the verifier's internal helpers stay private.

use std::path::PathBuf;

use aegis_host::verifier::verify;
use aegis_policy::{Policy, PolicyFile};

fn empty_policy() -> Policy {
    // Policy that allows nothing: any capability use should be flagged.
    let toml = r#"
[functions]
allow = []
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    Policy::from_file(file, PathBuf::from("/tmp")).unwrap()
}

#[test]
fn flags_underscored_capability_call() {
    // Direct use of the registered global is detected and rejected.
    let src = r#"_aegis_fs_read("x")"#;
    let err = verify(src, &empty_policy()).unwrap_err();
    assert_eq!(err.capability, "fs.read");
}

#[test]
fn ignores_substring_match_with_extra_prefix_or_suffix() {
    // Word-boundary discipline: `my_aegis_fs_read` and
    // `_aegis_fs_read_safe` are not the global the host registers.
    let safe_sources = [
        r#"x = my_aegis_fs_read("x")"#,
        r#"x = _aegis_fs_read_safe("x")"#,
    ];
    for src in safe_sources {
        verify(src, &empty_policy())
            .unwrap_or_else(|e| panic!("false positive on {src:?}: {e}"));
    }
}

#[test]
fn flags_dotted_capability_call() {
    let src = r#"x = fs.read("x")"#;
    let err = verify(src, &empty_policy()).unwrap_err();
    assert_eq!(err.capability, "fs.read");
}

#[test]
fn ignores_attribute_access_that_only_ends_in_capability_name() {
    // `obj.fs.read(...)` is not a top-level fs.read call: the leading
    // `.` extends the identifier context, so the boundary check rejects.
    let src = r#"x = obj.fs.read("x")"#;
    verify(src, &empty_policy())
        .unwrap_or_else(|e| panic!("false positive on attribute access: {e}"));

    // `fs.readme(...)` is similarly not fs.read.
    let src = r#"x = fs.readme("x")"#;
    verify(src, &empty_policy())
        .unwrap_or_else(|e| panic!("false positive on extended name: {e}"));
}

#[test]
fn ignores_capability_name_inside_string_literal() {
    // The verifier strips strings before scanning, so a capability
    // name quoted as data must NOT be flagged.
    let src = r#"x = "fs.read"
y = "_aegis_fs_read"
"#;
    verify(src, &empty_policy())
        .unwrap_or_else(|e| panic!("false positive on string literal: {e}"));
}

#[test]
fn ignores_capability_name_inside_line_comment() {
    let src = "# fs.read is dangerous\nx = 1\n";
    verify(src, &empty_policy())
        .unwrap_or_else(|e| panic!("false positive on line comment: {e}"));
}

#[test]
fn ignores_capability_name_inside_triple_quoted_string() {
    let src = r#"x = """
this docstring mentions fs.read and _aegis_fs_read
"""
y = 1
"#;
    verify(src, &empty_policy())
        .unwrap_or_else(|e| panic!("false positive on triple-quoted string: {e}"));
}

#[test]
fn allowed_capability_passes_verifier() {
    // Capabilities are now derived from populated resource sections.
    // Populating `read_allow` enables `fs.read`.
    let toml = r#"
[filesystem]
read_allow = ["**"]
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let policy = Policy::from_file(file, PathBuf::from("/tmp")).unwrap();
    let src = r#"x = fs.read("x")"#;
    verify(src, &policy).expect("allowed capability must pass");
}

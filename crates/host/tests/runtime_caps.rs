//! Tests for [runtime] caps: wall-time deadline and call-stack limit.

use std::path::PathBuf;

use aegis_host::{AegisError, Runner};
use aegis_policy::{Policy, PolicyFile};

fn runner_for(toml: &str) -> Runner {
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let policy = Policy::from_file(file, std::env::temp_dir()).unwrap();
    Runner::new(policy)
}

#[test]
fn deadline_zero_aborts_first_capability_call() {
    // max_seconds = 0 means "any time at all is too much" — the
    // first effecting call after eval starts is past the deadline.
    let toml = r#"
[runtime]
max_seconds = 0

[filesystem]
read_allow = ["/tmp/**"]
"#;
    let runner = runner_for(toml);
    let src = r#"x = fs.read("/tmp/whatever_does_not_matter")
print(x)
"#;
    let err = runner.run("t", src, "test.star").unwrap_err();
    match err {
        AegisError::RuntimeLimit(msg) => {
            assert!(msg.contains("deadline"), "{msg}");
            assert!(msg.contains("fs.read"), "{msg}");
        }
        other => panic!("expected RuntimeLimit, got: {other:?}"),
    }
}

#[test]
fn deadline_unset_means_unlimited() {
    // No [runtime] block at all: the script runs to completion
    // regardless of how long it takes (subject to other caps).
    let toml = r#"
[filesystem]
read_allow = ["/tmp/**"]
"#;
    let runner = runner_for(toml);
    // Pure computation only — no capability call. Should succeed.
    let outcome = runner
        .run("t", "print('hello')", "test.star")
        .unwrap();
    assert_eq!(outcome.printed, vec!["hello".to_string()]);
}

#[test]
fn pure_computation_not_caught_by_deadline_documented_limitation() {
    // Pure computation (no capability calls) is NOT caught by the
    // wall-time deadline — Starlark has no public abort hook. This
    // is documented honestly in the policy docs.
    //
    // The script does pure work then prints. With a 0-second
    // deadline it still completes, because the deadline is only
    // checked at capability-call entry and there are no capability
    // calls.
    let toml = r#"
[runtime]
max_seconds = 0
"#;
    let runner = runner_for(toml);
    let src = r#"def add(a, b):
    return a + b
print(add(1, 2))
"#;
    let outcome = runner.run("t", src, "test.star").unwrap();
    assert_eq!(outcome.printed, vec!["3".to_string()]);
}

#[test]
fn deadline_audit_event_emitted_before_capability_runs() {
    // When the deadline triggers, an audit event with
    // status="denied" and capability="<the cap>" must fire — even
    // though the actual fs/net/exec work didn't happen.
    use aegis_host::{AuditEvent, AuditSink};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Capture(Mutex<Vec<AuditEvent>>);
    impl AuditSink for Capture {
        fn emit(&self, event: AuditEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    let toml = r#"
[runtime]
max_seconds = 0

[environment]
allow_vars = ["PATH"]
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let policy = Policy::from_file(file, std::env::temp_dir()).unwrap();
    let cap = Arc::new(Capture::default());
    let runner = Runner::new(policy).with_audit(cap.clone());

    let _ = runner.run("t", r#"env.read("PATH")"#, "test.star");
    let events = cap.0.lock().unwrap();
    let found = events.iter().any(|e| {
        e.capability == "env.read"
            && matches!(e.status, aegis_host::audit::AuditStatus::Denied)
    });
    assert!(found, "expected denied env.read audit event, got: {events:?}");
}

#[test]
fn callstack_limit_catches_recursion_bomb() {
    // A small max_callstack_size aborts deep recursion before it
    // crashes the host stack.
    let toml = r#"
[runtime]
max_callstack_size = 30
"#;
    let runner = runner_for(toml);
    // Mutual recursion that would otherwise blow the stack.
    let src = r#"def deep(n):
    return deep(n + 1)
deep(0)
"#;
    let err = runner.run("t", src, "test.star").unwrap_err();
    // Starlark surfaces the cap as an eval error (not a typed
    // RuntimeLimit) because Starlark itself enforces it. Either way
    // the script does NOT succeed.
    assert!(matches!(err, AegisError::Starlark(_) | AegisError::RuntimeLimit(_)));
}

#[test]
fn pure_policy_runtime_accessors() {
    let toml = r#"
[runtime]
max_seconds = 30
max_callstack_size = 200
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let p = Policy::from_file(file, PathBuf::from("/")).unwrap();
    assert_eq!(p.runtime_max_seconds(), Some(30));
    assert_eq!(p.runtime_max_callstack_size(), Some(200));

    // No section at all → both None.
    let empty = PolicyFile::from_toml_str("").unwrap();
    let p2 = Policy::from_file(empty, PathBuf::from("/")).unwrap();
    assert_eq!(p2.runtime_max_seconds(), None);
    assert_eq!(p2.runtime_max_callstack_size(), None);
}

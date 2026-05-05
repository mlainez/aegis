//! Integration tests for local-only-read taint propagation.
//!
//! Each test exercises one of the four taint sources (filesystem,
//! environment, subprocess, network) end-to-end through `Runner::run`.
//! The script reads a tainted value, prints it (sometimes embedded in
//! a larger string), and the test asserts that the printed line that
//! comes back from the runtime contains `[REDACTED]` instead of the
//! raw value.
//!
//! These tests pin the contract: a value flagged local-only is
//! readable to the script but cannot bubble up to the calling host
//! through any output boundary.

use std::path::PathBuf;

use aegis_host::Runner;
use aegis_policy::{Policy, PolicyFile};

fn runner_for(toml: &str, root: PathBuf) -> Runner {
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let policy = Policy::from_file(file, root).unwrap();
    Runner::new(policy)
}

#[test]
fn fs_local_only_read_redacts_in_printed_output() {
    let tmp = std::env::temp_dir();
    let secret_path = tmp.join(format!("aegis_taint_secret_{}.txt", std::process::id()));
    let secret_value = "supersecret-fs-token-abc123-XYZ789";
    std::fs::write(&secret_path, secret_value).unwrap();

    let toml = format!(
        r#"
[filesystem]
local_only_read = ["{path}"]

[functions]
allow = ["fs.read"]
"#,
        path = secret_path.to_string_lossy().replace('\\', "/")
    );
    let runner = runner_for(&toml, tmp);
    let path_lit = secret_path.to_string_lossy().replace('\\', "/");
    let src = format!(
        r#"x = fs.read("{path_lit}")
print("got:", x)
print("len:", len(x))
"#
    );
    let outcome = runner.run("t-fs", &src, "test.star").unwrap();
    let joined = outcome.printed.join("\n");
    assert!(
        !joined.contains(secret_value),
        "raw secret leaked into printed output: {joined}"
    );
    assert!(
        joined.contains("[REDACTED]"),
        "expected [REDACTED] sentinel in output: {joined}"
    );
    // Length is a derived quantity (not a substring of the secret) and
    // should pass through unredacted.
    assert!(joined.contains("len:"));

    let _ = std::fs::remove_file(&secret_path);
}

#[test]
fn env_local_only_var_redacts_in_printed_output() {
    let var = "AEGIS_TAINT_TEST_VAR";
    let secret_value = "ek-zzz-zzz-this-is-the-key-do-not-leak";
    std::env::set_var(var, secret_value);

    let toml = format!(
        r#"
[environment]
local_only_vars = ["{var}"]

[functions]
allow = ["env.read"]
"#
    );
    let runner = runner_for(&toml, std::env::temp_dir());
    let src = format!(
        r#"k = env.read("{var}")
print("auth=Bearer", k)
"#
    );
    let outcome = runner.run("t-env", &src, "test.star").unwrap();
    let joined = outcome.printed.join("\n");
    assert!(
        !joined.contains(secret_value),
        "env secret leaked: {joined}"
    );
    assert!(joined.contains("[REDACTED]"), "got: {joined}");
    assert!(joined.contains("auth=Bearer"), "preamble preserved");

    std::env::remove_var(var);
}

#[test]
fn env_local_only_var_redacts_after_string_concat() {
    // Even when the script tries to wrap or interpolate the value, the
    // substring check on the final printed line catches it because the
    // raw secret is still present as a substring.
    let var = "AEGIS_TAINT_TEST_CONCAT";
    let secret_value = "raw-concat-secret-value-xyz0123";
    std::env::set_var(var, secret_value);

    let toml = format!(
        r#"
[environment]
local_only_vars = ["{var}"]

[functions]
allow = ["env.read"]
"#
    );
    let runner = runner_for(&toml, std::env::temp_dir());
    let src = format!(
        r#"k = env.read("{var}")
print("PREFIX[" + k + "]SUFFIX")
"#
    );
    let outcome = runner.run("t-concat", &src, "test.star").unwrap();
    let joined = outcome.printed.join("\n");
    assert!(!joined.contains(secret_value), "leaked via concat: {joined}");
    assert!(joined.contains("PREFIX["));
    assert!(joined.contains("]SUFFIX"));
    assert!(joined.contains("[REDACTED]"));

    std::env::remove_var(var);
}

#[test]
fn env_local_only_var_redacts_after_fs_write_then_read() {
    // Round-trip: write the secret to a file under a local-only-read
    // path, read it back, print. The substring scan still catches the
    // value because it's preserved on disk and read back identically.
    let var = "AEGIS_TAINT_TEST_ROUNDTRIP";
    let secret_value = "roundtrip-secret-value-9999-abcdef";
    std::env::set_var(var, secret_value);
    let tmp = std::env::temp_dir();
    let scratch = tmp.join(format!("aegis_taint_rt_{}.txt", std::process::id()));

    let toml = format!(
        r#"
[environment]
local_only_vars = ["{var}"]

[filesystem]
read_allow = ["{path}"]
write_allow = ["{path}"]

[functions]
allow = ["env.read", "fs.read", "fs.write"]
"#,
        path = scratch.to_string_lossy().replace('\\', "/")
    );
    let runner = runner_for(&toml, tmp);
    let path_lit = scratch.to_string_lossy().replace('\\', "/");
    let src = format!(
        r#"k = env.read("{var}")
fs.write("{path_lit}", k)
back = fs.read("{path_lit}")
print("readback:", back)
"#
    );
    let outcome = runner.run("t-rt", &src, "test.star").unwrap();
    let joined = outcome.printed.join("\n");
    assert!(
        !joined.contains(secret_value),
        "secret leaked via fs round-trip: {joined}"
    );
    assert!(joined.contains("[REDACTED]"));

    let _ = std::fs::remove_file(&scratch);
    std::env::remove_var(var);
}

#[test]
fn subprocess_local_only_command_redacts_stdout() {
    // `printf` is a portable subprocess. We mark it local-only and
    // assert its stdout is redacted in the printed output.
    let secret_value = "subproc-stdout-secret-token-MNOP4321";
    let toml = format!(
        r#"
[subprocess]
local_only_commands = ["printf"]

[functions]
allow = ["subprocess.exec"]
"#
    );
    let runner = runner_for(&toml, std::env::temp_dir());
    // printf "%s" "<secret>" — bare printf doesn't add a trailing
    // newline, so stdout is exactly the secret.
    let src = format!(
        r#"out = subprocess.exec(["printf", "%s", "{secret}"])
print("captured:", out)
"#,
        secret = secret_value
    );
    let outcome = runner.run("t-sp", &src, "test.star").unwrap();
    let joined = outcome.printed.join("\n");
    assert!(
        !joined.contains(secret_value),
        "subprocess stdout leaked: {joined}"
    );
    assert!(joined.contains("[REDACTED]"));
}

#[test]
fn plain_allow_does_not_redact() {
    // Sanity check: a regular allow_vars var is NOT tainted, so its
    // value passes through to the printed output unchanged.
    let var = "AEGIS_TAINT_TEST_PLAIN";
    let value = "plain-not-secret-value-AAAA";
    std::env::set_var(var, value);

    let toml = format!(
        r#"
[environment]
allow_vars = ["{var}"]

[functions]
allow = ["env.read"]
"#
    );
    let runner = runner_for(&toml, std::env::temp_dir());
    let src = format!(
        r#"k = env.read("{var}")
print("v=", k)
"#
    );
    let outcome = runner.run("t-plain", &src, "test.star").unwrap();
    let joined = outcome.printed.join(" ");
    assert!(joined.contains(value), "plain value should pass through: {joined}");
    assert!(!joined.contains("[REDACTED]"));

    std::env::remove_var(var);
}

#[test]
fn audit_event_payload_is_also_redacted() {
    // The audit log is one of the output boundaries. Even if a script
    // never `print`s, an audit-event field that happens to contain the
    // secret must be redacted before it reaches the sink.
    use aegis_host::{AuditEvent, AuditSink};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Capture(Mutex<Vec<AuditEvent>>);
    impl AuditSink for Capture {
        fn emit(&self, event: AuditEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    let var = "AEGIS_TAINT_AUDIT";
    let secret = "audit-secret-do-not-leak-ABCD";
    std::env::set_var(var, secret);

    let toml = format!(
        r#"
[environment]
local_only_vars = ["{var}"]

[subprocess]
allow_commands = ["printf"]

[functions]
allow = ["env.read", "subprocess.exec"]
"#
    );
    let file = PolicyFile::from_toml_str(&toml).unwrap();
    let policy = Policy::from_file(file, std::env::temp_dir()).unwrap();
    let cap = Arc::new(Capture::default());
    let runner = Runner::new(policy).with_audit(cap.clone());

    // Read the secret first so taint is registered, THEN exec a
    // subprocess that includes the secret literal in argv. The audit
    // event for the subprocess will record argv — must be redacted.
    let src = format!(
        r#"k = env.read("{var}")
out = subprocess.exec(["printf", "%s", k])
"#
    );
    runner.run("t-audit", &src, "test.star").unwrap();
    let events = cap.0.lock().unwrap();
    let serialized = serde_json::to_string(&*events).unwrap();
    assert!(
        !serialized.contains(secret),
        "audit log leaked secret: {serialized}"
    );

    std::env::remove_var(var);
}

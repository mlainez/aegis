//! Integration tests for `aegis_host`. Exercises the public `Runner`
//! surface end-to-end against synthetic policies: each test loads a
//! TOML policy, runs a small Starlark script, and asserts on the
//! outcome (printed output, or one of the typed `AegisError` variants).

use std::path::PathBuf;

use aegis_host::{AegisError, Runner};
use aegis_policy::{Policy, PolicyFile};

fn runner_for(toml: &str, root: PathBuf) -> Runner {
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let policy = Policy::from_file(file, root).unwrap();
    Runner::new(policy)
}

#[test]
fn allowed_read_succeeds() {
    let tmp = std::env::temp_dir();
    let f = tmp.join("aegis_test_input.txt");
    std::fs::write(&f, "hello aegis").unwrap();

    let toml = r#"
[filesystem]
read_allow = ["/tmp/**", "/var/tmp/**"]

[functions]
allow = ["fs.read"]
"#;
    let runner = runner_for(toml, tmp);
    let path_lit = f.to_string_lossy().replace('\\', "/");
    let src = format!(
        r#"x = fs.read("{path_lit}")
print(x)"#
    );
    let outcome = runner.run("t1", &src, "test.star").unwrap();
    assert_eq!(outcome.printed, vec!["hello aegis".to_string()]);
}

#[test]
fn write_outside_allow_is_denied() {
    let toml = r#"
[filesystem]
write_allow = ["/tmp/**"]
deny = ["~/.aws/**"]

[functions]
allow = ["fs.write"]
"#;
    let runner = runner_for(toml, PathBuf::from("/work"));
    let src = r#"fs.write("/etc/passwd", "x")"#;
    let err = runner.run("t1", src, "test.star").unwrap_err();
    assert!(
        matches!(err, AegisError::Policy(_)),
        "expected policy violation, got: {err:?}"
    );
}

#[test]
fn function_not_in_allowlist_rejected_pre_execution() {
    let toml = r#"
[functions]
allow = ["fs.read"]
"#;
    let runner = runner_for(toml, PathBuf::from("/tmp"));
    let src = r#"subprocess.exec(["echo", "hi"])"#;
    let err = runner.run("t1", src, "test.star").unwrap_err();
    assert!(
        matches!(err, AegisError::Verifier(_)),
        "expected pre-execution verifier rejection, got: {err:?}"
    );
}

#[test]
fn subprocess_deny_args_blocks_force_push() {
    let toml = r#"
[subprocess]
allow_commands = ["git"]

[subprocess.deny_args]
git = ["push --force"]

[functions]
allow = ["subprocess.exec"]
"#;
    let runner = runner_for(toml, PathBuf::from("/tmp"));
    let src = r#"subprocess.exec(["git", "push", "--force", "origin", "main"])"#;
    let err = runner.run("t1", src, "test.star").unwrap_err();
    assert!(
        matches!(err, AegisError::Policy(_)),
        "expected policy violation for forbidden args, got: {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("push --force"),
        "expected the matched pattern in the error, got: {msg}"
    );
}

#[test]
fn subprocess_command_allowlist_blocks_unknown_command() {
    let toml = r#"
[subprocess]
allow_commands = ["git"]

[functions]
allow = ["subprocess.exec"]
"#;
    let runner = runner_for(toml, PathBuf::from("/tmp"));
    let src = r#"subprocess.exec(["rm", "-rf", "/tmp"])"#;
    let err = runner.run("t1", src, "test.star").unwrap_err();
    assert!(
        matches!(err, AegisError::Policy(_)),
        "expected policy violation for unknown command, got: {err:?}"
    );
}

#[test]
fn dns_resolves_hostname_through_deny_cidr() {
    // `localhost` reliably resolves to 127.0.0.1 / ::1 on every POSIX
    // system. Combined with the loopback CIDR, this exercises the full
    // DNS-then-policy path without a real network round-trip.
    let toml = r#"
[network]
http_get_allow = ["localhost"]
deny_ips = ["127.0.0.0/8", "::1/128"]

[functions]
allow = ["net.http_get"]
"#;
    let runner = runner_for(toml, PathBuf::from("/tmp"));
    let src = r#"net.http_get("http://localhost:1/")"#;
    let err = runner.run("t1", src, "test.star").unwrap_err();
    assert!(
        matches!(err, AegisError::Policy(_)),
        "expected policy violation from DNS-resolved deny, got: {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("127.") || msg.contains("::1"),
        "expected resolved-IP diagnostic, got: {msg}"
    );
}

#[test]
fn env_read_allowlist() {
    let toml = r#"
[environment]
allow_vars = ["PATH"]
deny_vars = ["AWS_SECRET_ACCESS_KEY"]

[functions]
allow = ["env.read"]
"#;
    let runner = runner_for(toml, PathBuf::from("/tmp"));
    let src = r#"
p = env.read("PATH")
print("path-prefix:", p[:1])
"#;
    runner.run("t1", src, "test.star").unwrap();
    let denied_src = r#"env.read("AWS_SECRET_ACCESS_KEY")"#;
    let err = runner.run("t1", denied_src, "test.star").unwrap_err();
    assert!(matches!(err, AegisError::Policy(_)));
}

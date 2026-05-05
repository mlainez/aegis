//! Tests for subprocess env filtering. The child process must see
//! ONLY env vars the policy enables — never the parent's full env.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use aegis_host::Runner;
use aegis_policy::{Policy, PolicyFile};

fn runner_for(toml: &str) -> Runner {
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let policy = Policy::from_file(file, std::env::temp_dir()).unwrap();
    Runner::new(policy)
}

/// Generate a unique env-var name per test invocation so concurrent
/// test runs don't race on shared state.
fn unique_var(prefix: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "AEGIS_SUBPROC_TEST_{}_{}_{}",
        prefix,
        std::process::id(),
        n
    )
}

#[test]
fn child_sees_only_allow_vars_not_full_parent_env() {
    let allowed = unique_var("ALLOWED");
    let forbidden = unique_var("FORBIDDEN");
    std::env::set_var(&allowed, "yes-allowed");
    std::env::set_var(&forbidden, "should-not-leak");

    let toml = format!(
        r#"
[environment]
allow_vars = ["PATH", "{allowed}"]

[subprocess]
allow_commands = ["env"]
"#
    );
    let runner = runner_for(&toml);
    let src = r#"out = subprocess.exec(["env"])
print(out)
"#;
    let outcome = runner.run("t", src, "test.star").unwrap();
    let joined = outcome.printed.join("\n");

    assert!(
        joined.contains(&format!("{allowed}=yes-allowed")),
        "allowed var must reach the child: {joined}"
    );
    assert!(
        !joined.contains(&forbidden),
        "forbidden parent-env var leaked into child: {joined}"
    );

    std::env::remove_var(&allowed);
    std::env::remove_var(&forbidden);
}

#[test]
fn child_does_not_see_local_only_vars_for_plain_command() {
    // Var is `local_only_vars` (so the script could `env.read` it
    // and get a tainted value), but the subprocess command is NOT
    // `local_only_commands` — so the var must NOT be in the child's
    // env, otherwise the child could echo it via stdout and the
    // taint registry has nothing to scrub against.
    let secret = unique_var("LOCAL_ONLY");
    std::env::set_var(&secret, "raw-secret-do-not-leak");

    let toml = format!(
        r#"
[environment]
allow_vars      = ["PATH"]
local_only_vars = ["{secret}"]

[subprocess]
allow_commands = ["env"]
"#
    );
    let runner = runner_for(&toml);
    let outcome = runner
        .run("t", r#"print(subprocess.exec(["env"]))"#, "test.star")
        .unwrap();
    let joined = outcome.printed.join("\n");
    assert!(
        !joined.contains(&secret),
        "local-only var must not be passed to a non-local-only subprocess: {joined}"
    );
    assert!(
        !joined.contains("raw-secret-do-not-leak"),
        "raw value must not leak via child env: {joined}"
    );

    std::env::remove_var(&secret);
}

#[test]
fn child_sees_local_only_vars_for_local_only_command_but_output_is_tainted() {
    // The whole point of `local_only_commands`: the child can use
    // the secret (e.g. for an authenticated CLI call), but its
    // stdout/stderr is tainted at the runtime boundary, so the value
    // cannot bubble up to the caller.
    let secret = unique_var("LOCAL_ONLY_PASSED");
    let secret_value = "auth-token-passed-but-redacted-9876543210";
    std::env::set_var(&secret, secret_value);

    let toml = format!(
        r#"
[environment]
allow_vars      = ["PATH"]
local_only_vars = ["{secret}"]

[subprocess]
allow_commands      = ["env"]
local_only_commands = ["env"]
"#
    );
    let runner = runner_for(&toml);
    let outcome = runner
        .run("t", r#"print(subprocess.exec(["env"]))"#, "test.star")
        .unwrap();
    let joined = outcome.printed.join("\n");

    // The raw value MUST be redacted in the printed output (taint
    // boundary). The var name itself appearing is fine.
    assert!(
        !joined.contains(secret_value),
        "raw secret value leaked through subprocess stdout: {joined}"
    );
    assert!(
        joined.contains("[REDACTED]"),
        "expected redaction sentinel in output: {joined}"
    );

    std::env::remove_var(&secret);
}

#[test]
fn deny_vars_excluded_even_if_listed_in_allow() {
    // Belt-and-suspenders: if a user accidentally lists the same
    // var in both allow_vars and deny_vars, deny wins both for
    // env.read AND for subprocess env passing.
    let var = unique_var("DENY_WINS");
    std::env::set_var(&var, "must-not-be-passed");

    let toml = format!(
        r#"
[environment]
allow_vars = ["PATH", "{var}"]
deny_vars  = ["{var}"]

[subprocess]
allow_commands = ["env"]
"#
    );
    let runner = runner_for(&toml);
    let outcome = runner
        .run("t", r#"print(subprocess.exec(["env"]))"#, "test.star")
        .unwrap();
    let joined = outcome.printed.join("\n");
    assert!(
        !joined.contains(&var) && !joined.contains("must-not-be-passed"),
        "deny_vars should win even when same name appears in allow_vars: {joined}"
    );

    std::env::remove_var(&var);
}

#[test]
fn empty_allow_vars_means_empty_child_env() {
    // The subprocess must be runnable when its argv[0] is an
    // absolute path (so PATH lookup isn't needed), even with NO
    // allow_vars — which produces a fully empty child env.
    let toml = r#"
[subprocess]
allow_commands = ["/bin/sh"]
"#;
    let runner = runner_for(toml);
    // /bin/sh -c "echo HOME=$HOME" — HOME isn't in allow_vars so it
    // should be absent (hence "HOME=" with nothing after).
    let src = r#"out = subprocess.exec(["/bin/sh", "-c", "echo HOME=$HOME"])
print(out)
"#;
    let outcome = runner.run("t", src, "test.star").unwrap();
    let joined = outcome.printed.join("\n");
    // HOME would have a real value if the parent's env leaked
    // through; it should be empty.
    assert!(
        joined.contains("HOME=\n") || joined.contains("HOME= ") || joined.trim_end().ends_with("HOME="),
        "HOME should be unset in the child (empty allow_vars), got: {joined:?}"
    );
}

#[test]
fn pure_policy_subprocess_env_method() {
    // Direct test of Policy::subprocess_env without spawning a
    // process. Pins the inclusion logic in isolation.
    let var_a = unique_var("PURE_A");
    let var_b = unique_var("PURE_B");
    let var_lo = unique_var("PURE_LO");
    let var_deny = unique_var("PURE_DENY");
    std::env::set_var(&var_a, "a-val");
    std::env::set_var(&var_b, "b-val");
    std::env::set_var(&var_lo, "lo-val");
    std::env::set_var(&var_deny, "deny-val");

    let toml = format!(
        r#"
[environment]
allow_vars      = ["{var_a}", "{var_b}", "{var_deny}"]
local_only_vars = ["{var_lo}"]
deny_vars       = ["{var_deny}"]

[subprocess]
allow_commands      = ["regular"]
local_only_commands = ["secret-tool"]
"#
    );
    let file = PolicyFile::from_toml_str(&toml).unwrap();
    let p = Policy::from_file(file, std::env::temp_dir()).unwrap();

    // Plain command: gets allow_vars minus deny_vars; no local-only vars.
    let regular: std::collections::HashMap<_, _> =
        p.subprocess_env("regular").into_iter().collect();
    assert!(regular.contains_key(&var_a));
    assert!(regular.contains_key(&var_b));
    assert!(!regular.contains_key(&var_lo));
    assert!(!regular.contains_key(&var_deny));

    // Local-only command: also gets local_only_vars.
    let secret: std::collections::HashMap<_, _> =
        p.subprocess_env("secret-tool").into_iter().collect();
    assert!(secret.contains_key(&var_a));
    assert!(secret.contains_key(&var_lo));
    assert!(!secret.contains_key(&var_deny));

    // basename match works for absolute paths too.
    let secret_abs: std::collections::HashMap<_, _> =
        p.subprocess_env("/usr/local/bin/secret-tool")
            .into_iter()
            .collect();
    assert!(secret_abs.contains_key(&var_lo));

    for v in [&var_a, &var_b, &var_lo, &var_deny] {
        std::env::remove_var(v);
    }
    let _ = PathBuf::from(""); // silence unused warning if any
}

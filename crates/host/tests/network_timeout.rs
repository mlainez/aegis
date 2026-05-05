//! Tests for `[network].timeout_seconds`. The hard one boots a
//! local TCP listener that accepts connections but never responds,
//! points the policy at it with a 1-second timeout, and asserts the
//! HTTP builtin fails within a few seconds — proving an unhealthy
//! backend cannot hang the agent indefinitely.

use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use aegis_host::Runner;
use aegis_policy::{Policy, PolicyFile};

fn runner_for(toml: &str) -> Runner {
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let policy = Policy::from_file(file, std::env::temp_dir()).unwrap();
    Runner::new(policy)
}

#[test]
fn pure_policy_default_timeout_is_thirty_seconds() {
    // No [network].timeout_seconds → 30s default.
    let p = Policy::from_file(PolicyFile::default(), PathBuf::from("/")).unwrap();
    assert_eq!(p.network_timeout(), Duration::from_secs(30));
}

#[test]
fn pure_policy_explicit_timeout_honored() {
    let toml = r#"
[network]
timeout_seconds = 5
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let p = Policy::from_file(file, PathBuf::from("/")).unwrap();
    assert_eq!(p.network_timeout(), Duration::from_secs(5));
}

#[test]
fn http_get_aborts_within_timeout_against_unresponsive_backend() {
    // Bind to an ephemeral port; accept connections but never write
    // anything back. The HTTP builtin will block on read until the
    // policy's timeout fires.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    let _bg = std::thread::spawn(move || {
        // Hold accepted connections forever (until process exit).
        let mut held = Vec::new();
        for conn in listener.incoming().flatten() {
            held.push(conn);
        }
    });

    let toml = format!(
        r#"
[network]
http_get_allow  = ["127.0.0.1"]
timeout_seconds = 1
"#
    );
    let runner = runner_for(&toml);
    let src = format!(
        r#"net.http_get("http://127.0.0.1:{port}/never-responds")
print("should not reach here")
"#
    );
    let started = Instant::now();
    let err = runner.run("t", &src, "test.star").unwrap_err();
    let elapsed = started.elapsed();

    // Allow generous slack for CI variability; the point is to
    // prove the call DOESN'T run forever.
    assert!(
        elapsed < Duration::from_secs(5),
        "timeout should fire within ~1s; took {elapsed:?}"
    );
    let msg = err.to_string();
    // ureq surfaces timeouts via std::io::Error variants; the
    // human-readable forms we've seen are "timed out" /
    // "operation timed out". Be lenient on the exact phrase, just
    // confirm an error fired.
    assert!(
        !msg.is_empty(),
        "expected an error message, got empty: {err:?}"
    );
}

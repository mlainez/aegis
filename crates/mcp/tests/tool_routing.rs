//! Integration tests for the `aegis_tool_routing` MCP tool.
//!
//! Spawns the compiled `aegis-mcp` binary against a policy that
//! declares two `[tools.X]` entries — one allowed (its required
//! capability has a populated resource section), one not — and
//! confirms the read-only oracle surfaces both records, with
//! correct `allowed` flags and routing fields, both for the
//! single-name lookup and the all-tools enumeration.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_aegis-mcp");

fn write_policy(body: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aegis_mcp_routing_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("aegis.toml");
    std::fs::write(&path, body).unwrap();
    path
}

fn drive_call(policy: &PathBuf, args: serde_json::Value) -> serde_json::Value {
    let mut child = Command::new(BIN)
        .arg("--policy")
        .arg(policy)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn aegis-mcp");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    let init = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion":"2024-11-05","capabilities":{}},
    });
    writeln!(stdin, "{init}").unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    line.clear();

    let init_done = serde_json::json!({
        "jsonrpc":"2.0","method":"notifications/initialized","params":{}
    });
    writeln!(stdin, "{init_done}").unwrap();
    reader.read_line(&mut line).unwrap();
    line.clear();

    let call = serde_json::json!({
        "jsonrpc":"2.0","id":2,"method":"tools/call",
        "params":{"name":"aegis_tool_routing","arguments": args},
    });
    writeln!(stdin, "{call}").unwrap();
    reader.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).expect("parse response");
    drop(stdin);
    let _ = child.wait();
    resp
}

const POLICY_BODY: &str = r#"
[filesystem]
read_allow = ["src/**"]

[network]
http_get_allow = ["api.github.com"]

[tools.WebSearch]
capabilities  = ["net.http_get"]
backend_url   = "https://duckduckgo.com/?q="
backend_method = "GET"
description   = "DuckDuckGo HTML endpoint."

[tools.Bash]
capabilities = ["subprocess.exec"]
"#;

#[test]
fn named_lookup_returns_record_and_allowed_flag() {
    let policy = write_policy(POLICY_BODY);
    let resp = drive_call(&policy, serde_json::json!({ "name": "WebSearch" }));
    let result = &resp["result"];
    assert_eq!(result["isError"], false);
    let body = &result["structuredContent"]["tool"];
    assert_eq!(body["name"], "WebSearch");
    assert_eq!(body["allowed"], true);
    assert_eq!(body["backend_url"], "https://duckduckgo.com/?q=");
    assert_eq!(body["backend_method"], "GET");
    assert_eq!(body["capabilities"][0], "net.http_get");

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_dir(policy.parent().unwrap());
}

#[test]
fn named_lookup_marks_disallowed_tool_when_capability_missing() {
    // Bash needs subprocess.exec; the policy doesn't populate
    // [subprocess], so the capability is not derived → not allowed.
    let policy = write_policy(POLICY_BODY);
    let resp = drive_call(&policy, serde_json::json!({ "name": "Bash" }));
    let body = &resp["result"]["structuredContent"]["tool"];
    assert_eq!(body["name"], "Bash");
    assert_eq!(body["allowed"], false);
    assert_eq!(body["capabilities"][0], "subprocess.exec");

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_dir(policy.parent().unwrap());
}

#[test]
fn unknown_tool_returns_error_field() {
    let policy = write_policy(POLICY_BODY);
    let resp = drive_call(&policy, serde_json::json!({ "name": "DefinitelyNotDeclared" }));
    let body = &resp["result"]["structuredContent"];
    assert!(body["tool"].is_null());
    let err = body["error"].as_str().unwrap_or("");
    assert!(err.contains("DefinitelyNotDeclared"), "error text: {err}");

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_dir(policy.parent().unwrap());
}

#[test]
fn no_name_returns_all_tools() {
    let policy = write_policy(POLICY_BODY);
    let resp = drive_call(&policy, serde_json::json!({}));
    let tools = resp["result"]["structuredContent"]["tools"]
        .as_array()
        .expect("tools array");
    let names: Vec<String> = tools
        .iter()
        .map(|t| t["name"].as_str().unwrap_or("").to_string())
        .collect();
    assert!(names.contains(&"WebSearch".to_string()), "got: {names:?}");
    assert!(names.contains(&"Bash".to_string()), "got: {names:?}");

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_dir(policy.parent().unwrap());
}

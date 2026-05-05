//! `aegis-mcp` — Aegis MCP server.
//!
//! Speaks newline-delimited JSON-RPC 2.0 on stdio (one JSON message per
//! line). Implements the subset of MCP needed to expose Aegis as a
//! policy-gated tool surface: `initialize`, `tools/list`, `tools/call`.
//!
//! Tools exposed:
//!
//! - `aegis_run(script, task_id?)` — primary surface. The caller hands
//!   over a Starlark program; the server runs it through the host's
//!   `Runner` under the configured policy. Output is the script's
//!   printed lines.
//! - `aegis_fs_read(path)`, `aegis_fs_write(path, content)`,
//!   `aegis_fs_delete(path)` — sugar over `aegis_run` for hosts that
//!   prefer one MCP call per action.
//! - `aegis_subprocess_exec(argv)` — same.
//! - `aegis_net_http_get(url)`, `aegis_net_http_post(url, body)` — same.
//! - `aegis_env_read(name)` — same.
//! - `aegis_tool_routing(name?)` — read-only oracle. Returns the
//!   `[tools.X]` routing hints (capabilities, backend_url,
//!   backend_method, description, allowed flag) for a named tool,
//!   or all declared tools if no name is given. Lets a calling host
//!   like Claude Code consult the policy's tool surface without
//!   re-parsing the TOML itself.
//!
//! Each tool call goes through the same enforcement path the CLI uses:
//! pre-execution verifier, policy checks at every capability builtin,
//! audit log entry per attempt, confirm-per-call hook (in MCP MVP this
//! is wired to `AllowAllConfirm` — Claude Code / opencode hosts that
//! want interactive confirms should embed `aegis-host` in-process where
//! they can plug their own UI in).

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;

use aegis_host::{
    AegisError, AllowAllConfirm, AuditSink, ConfirmHook, DenyAllConfirm, JsonlAuditSink, Runner,
};
use aegis_policy::Policy;
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "aegis-mcp";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug)]
#[command(name = "aegis-mcp", version, about = "MCP server exposing the Aegis policy-gated runtime over stdio")]
struct Cli {
    /// Path to the policy TOML file. If omitted, falls back to the
    /// built-in `secure-defaults` baseline (denies every effecting
    /// capability) and prints a banner on stderr.
    #[arg(short, long)]
    policy: Option<PathBuf>,

    /// Append audit events to this file (JSON Lines). Default: stderr.
    #[arg(long)]
    audit_log: Option<PathBuf>,

    /// How `confirm_per_call`-listed capabilities behave when invoked
    /// through this MCP server.
    ///
    /// - `auto-allow` (default, backward-compatible): the
    ///   confirm hook always allows. Same as before this flag
    ///   existed. `confirm_per_call` is effectively ignored.
    /// - `auto-deny`: the confirm hook always denies. Any call to a
    ///   capability listed in `confirm_per_call` returns a tool
    ///   result with `isError: true` and a `ConfirmDenied` message
    ///   naming the capability. The orchestrator (Claude Code,
    ///   opencode, ...) can interpret that error, present a prompt
    ///   to the user, and re-issue the call from a sibling MCP
    ///   server / tool that's NOT confirm-gated, or instruct the
    ///   user to remove the entry from `confirm_per_call` for that
    ///   session.
    #[arg(long, default_value = "auto-allow")]
    confirm_mode: ConfirmMode,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
enum ConfirmMode {
    AutoAllow,
    AutoDeny,
}

impl ConfirmMode {
    fn into_hook(self) -> Arc<dyn ConfirmHook> {
        match self {
            ConfirmMode::AutoAllow => Arc::new(AllowAllConfirm),
            ConfirmMode::AutoDeny => Arc::new(DenyAllConfirm),
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let policy = match cli.policy.as_deref() {
        Some(path) => Policy::load(path)
            .map_err(|e| anyhow::anyhow!("load policy {path:?}: {e}"))?,
        None => {
            eprintln!(
                "aegis-mcp: no --policy provided; using built-in `secure-defaults` baseline. \
This denies every fs/net/subprocess/env capability — every tool call will fail \
until you launch with --policy <project.toml>. See examples/policies/ for templates."
            );
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            Policy::secure_defaults_at(cwd)?
        }
    };
    let audit: Arc<dyn AuditSink> = match &cli.audit_log {
        Some(path) => {
            // Refuse to start if the audit log path is reachable
            // to the agent. See guard_audit_log doc.
            let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
            policy.guard_audit_log(&canon).map_err(|e| {
                anyhow::anyhow!("audit-log path is reachable to the agent: {e}")
            })?;
            Arc::new(JsonlAuditSink::file(path)?)
        }
        None => Arc::new(JsonlAuditSink::stderr()),
    };
    // The confirm-mode flag chooses between auto-allow (default,
    // backward-compatible) and auto-deny. Interactive hosts that
    // want real prompt UI should embed aegis-host in-process and
    // plug in their own ConfirmHook implementation; auto-deny is
    // the closest-to-interactive option for MCP today (the
    // orchestrator interprets the structured error and decides
    // whether to prompt the user out-of-band).
    let runner = Runner::new(policy)
        .with_audit(audit)
        .with_confirm_hook(cli.confirm_mode.into_hook());

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut counter: u64 = 0;
    let mut buf = String::new();

    loop {
        buf.clear();
        let n = stdin.lock().read_line(&mut buf)?;
        if n == 0 {
            break;
        }
        let trimmed = buf.trim();
        if trimmed.is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(trimmed) {
            Ok(req) => handle(&runner, &mut counter, req),
            Err(e) => Response::error(Value::Null, -32700, format!("parse error: {e}"), None),
        };
        let line = serde_json::to_string(&resp)?;
        writeln!(stdout, "{line}")?;
        stdout.flush()?;
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct Request {
    #[serde(default)]
    jsonrpc: String,
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct Response {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

impl Response {
    fn ok(id: Value, result: Value) -> Self {
        Self { jsonrpc: "2.0", id, result: Some(result), error: None }
    }
    fn error(id: Value, code: i32, message: String, data: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(RpcError { code, message, data }),
        }
    }
}

fn handle(runner: &Runner, counter: &mut u64, req: Request) -> Response {
    let _ = req.jsonrpc; // not validated for MVP
    let id = req.id.clone();
    match req.method.as_str() {
        "initialize" => Response::ok(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
            }),
        ),
        "initialized" | "notifications/initialized" => {
            // No response for notifications, but the loop still expects
            // a line. Returning an empty success keeps the stream
            // simple; clients ignore responses to notifications.
            Response::ok(id, json!({}))
        }
        "tools/list" => Response::ok(id, json!({ "tools": tool_definitions() })),
        "tools/call" => handle_tools_call(runner, counter, id, req.params),
        "ping" => Response::ok(id, json!({})),
        other => Response::error(
            id,
            -32601,
            format!("method not found: {other}"),
            None,
        ),
    }
}

fn handle_tools_call(runner: &Runner, counter: &mut u64, id: Value, params: Value) -> Response {
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let args = params.get("arguments").cloned().unwrap_or(Value::Null);

    *counter += 1;
    let task_id = format!("mcp-{counter}");

    // `aegis_tool_routing` is a read-only oracle that consults the
    // policy without invoking the runner. It does not allocate a
    // task ID, audit, or evaluate Starlark.
    if name == "aegis_tool_routing" {
        return handle_tool_routing(runner, id, &args);
    }

    let script_result = match dispatch(&name, &args, &task_id) {
        Ok(s) => s,
        Err(msg) => {
            return tool_error_response(id, &AegisError::Other(msg));
        }
    };

    match runner.run(&task_id, &script_result.script, &script_result.script_name) {
        Ok(outcome) => Response::ok(
            id,
            json!({
                "content": [
                    { "type": "text", "text": outcome.printed.join("\n") }
                ],
                "isError": false,
            }),
        ),
        Err(e) => tool_error_response(id, &e),
    }
}

/// Tag the error with a stable `aegis_error_kind` string so the
/// orchestrator can branch on it programmatically without scraping
/// the human-readable message. ConfirmDenied is the meaningful one
/// for the confirm-mode plumbing: an orchestrator that sees
/// `aegis_error_kind == "confirm_denied"` can prompt the user
/// out-of-band and re-issue from a different code path.
fn tool_error_response(id: Value, err: &AegisError) -> Response {
    let kind = match err {
        AegisError::ConfirmDenied(_) => "confirm_denied",
        AegisError::Policy(_) => "policy_violation",
        AegisError::Verifier(_) => "verifier_rejection",
        AegisError::RuntimeLimit(_) => "runtime_limit",
        AegisError::Starlark(_) => "starlark_error",
        AegisError::Io(_) => "io_error",
        AegisError::Other(_) => "other",
    };
    Response::ok(
        id,
        json!({
            "content": [
                { "type": "text", "text": err.to_string() }
            ],
            "isError": true,
            "aegis_error_kind": kind,
        }),
    )
}

/// Handle the `aegis_tool_routing` MCP tool. Read-only: consults the
/// policy and returns either one named record or all of them, with an
/// `allowed` flag computed from the same `Policy::check_tool` path
/// the runner uses. No script is evaluated, no audit event written.
fn handle_tool_routing(runner: &Runner, id: Value, args: &Value) -> Response {
    let policy = runner.policy();
    let name = args.get("name").and_then(|v| v.as_str());

    fn record_to_json(
        policy: &aegis_policy::Policy,
        name: &str,
        record: &aegis_policy::ToolRecord,
    ) -> Value {
        let allowed = policy.check_tool(name).is_ok();
        json!({
            "name": name,
            "allowed": allowed,
            "capabilities": record.capabilities,
            "backend_url": record.backend_url,
            "backend_method": record.method(),
            "description": record.description,
        })
    }

    let body = match name {
        Some(n) => match policy.tool_routing(n) {
            Some(record) => json!({ "tool": record_to_json(policy, n, record) }),
            None => json!({
                "tool": null,
                "error": format!("tool {n:?} not declared in [tools]"),
            }),
        },
        None => {
            let tools: Vec<Value> = policy
                .tools_iter()
                .map(|(n, r)| record_to_json(policy, n, r))
                .collect();
            json!({ "tools": tools })
        }
    };

    Response::ok(
        id,
        json!({
            "content": [
                { "type": "text", "text": serde_json::to_string(&body).unwrap_or_default() }
            ],
            "isError": false,
            "structuredContent": body,
        }),
    )
}

struct ScriptCall {
    script: String,
    script_name: String,
}

/// Build the Starlark program that the runner will execute for a given
/// MCP tool call. For `aegis_run`, the agent's script is forwarded
/// verbatim. For sugar tools, a small synthesized program calls the
/// corresponding namespaced builtin and prints the result so the
/// runner's `printed` capture surfaces it back to the caller.
fn dispatch(name: &str, args: &Value, task_id: &str) -> Result<ScriptCall, String> {
    match name {
        "aegis_run" => {
            let script = args
                .get("script")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "aegis_run: missing 'script' argument".to_string())?
                .to_string();
            Ok(ScriptCall {
                script,
                script_name: format!("{task_id}.star"),
            })
        }
        "aegis_fs_read" => {
            let path = require_str(args, "path")?;
            Ok(synth(format!(
                "_r = fs.read({})\nprint(_r)",
                starlark_str(path)
            )))
        }
        "aegis_fs_write" => {
            let path = require_str(args, "path")?;
            let content = require_str(args, "content")?;
            Ok(synth(format!(
                "fs.write({}, {})\nprint(\"ok\")",
                starlark_str(path),
                starlark_str(content)
            )))
        }
        "aegis_fs_delete" => {
            let path = require_str(args, "path")?;
            Ok(synth(format!(
                "fs.delete({})\nprint(\"ok\")",
                starlark_str(path)
            )))
        }
        "aegis_subprocess_exec" => {
            let argv = require_argv(args)?;
            Ok(synth(format!(
                "_r = subprocess.exec({})\nprint(_r)",
                starlark_list(&argv)
            )))
        }
        "aegis_net_http_get" => {
            let url = require_str(args, "url")?;
            Ok(synth(format!(
                "_r = net.http_get({})\nprint(_r)",
                starlark_str(url)
            )))
        }
        "aegis_net_http_post" => {
            let url = require_str(args, "url")?;
            let body = require_str(args, "body")?;
            Ok(synth(format!(
                "_r = net.http_post({}, {})\nprint(_r)",
                starlark_str(url),
                starlark_str(body)
            )))
        }
        "aegis_env_read" => {
            let name = require_str(args, "name")?;
            Ok(synth(format!(
                "_r = env.read({})\nprint(_r)",
                starlark_str(name)
            )))
        }
        other => Err(format!("unknown tool: {other}")),
    }
}

fn synth(body: String) -> ScriptCall {
    ScriptCall {
        script: body,
        script_name: "mcp_call.star".into(),
    }
}

fn require_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing '{key}' argument (must be a string)"))
}

fn require_argv(args: &Value) -> Result<Vec<String>, String> {
    let arr = args
        .get("argv")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing 'argv' argument (must be an array of strings)".to_string())?;
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        out.push(
            v.as_str()
                .ok_or_else(|| "argv entries must all be strings".to_string())?
                .to_string(),
        );
    }
    Ok(out)
}

/// Render a Rust string as a Starlark string literal. Starlark string
/// literals are Python-compatible, so Rust's Debug formatter produces
/// a valid Starlark literal (escaping `"`, `\`, control characters,
/// and non-printables).
fn starlark_str(s: &str) -> String {
    format!("{:?}", s)
}

fn starlark_list(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|s| starlark_str(s)).collect();
    format!("[{}]", inner.join(", "))
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "aegis_run",
            "description": "Run a Starlark program under the configured Aegis policy. The program has access to the policy-gated namespaced builtins (fs.read, fs.write, fs.delete, net.http_get, net.http_post, net.http_put, net.http_patch, net.http_delete, subprocess.exec, env.read). Returns the program's printed output. This is the most flexible surface; agents that compose multi-step actions should prefer this over the per-capability tools.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "script": { "type": "string", "description": "Starlark source. May reference fs.*, net.*, subprocess.*, env.*." },
                    "task_id": { "type": "string", "description": "Optional caller-supplied identifier; lands in audit events." }
                },
                "required": ["script"]
            }
        },
        {
            "name": "aegis_fs_read",
            "description": "Read a file under the policy's filesystem read_allow.",
            "inputSchema": {
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"]
            }
        },
        {
            "name": "aegis_fs_write",
            "description": "Write a file under the policy's filesystem write_allow.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "content": { "type": "string" }
                },
                "required": ["path", "content"]
            }
        },
        {
            "name": "aegis_fs_delete",
            "description": "Delete a file under the policy's filesystem delete_allow.",
            "inputSchema": {
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"]
            }
        },
        {
            "name": "aegis_subprocess_exec",
            "description": "Spawn a child process. argv[0] is matched against the policy's subprocess.allow_commands and the joined argv against subprocess.deny_args.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "argv": {
                        "type": "array",
                        "items": { "type": "string" },
                        "minItems": 1
                    }
                },
                "required": ["argv"]
            }
        },
        {
            "name": "aegis_net_http_get",
            "description": "HTTP GET. URL host is matched against http_get_allow; resolved IPs go through deny_ips.",
            "inputSchema": {
                "type": "object",
                "properties": { "url": { "type": "string" } },
                "required": ["url"]
            }
        },
        {
            "name": "aegis_net_http_post",
            "description": "HTTP POST with a string body.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": { "type": "string" },
                    "body": { "type": "string" }
                },
                "required": ["url", "body"]
            }
        },
        {
            "name": "aegis_env_read",
            "description": "Read a named environment variable. Subject to environment.allow_vars / deny_vars.",
            "inputSchema": {
                "type": "object",
                "properties": { "name": { "type": "string" } },
                "required": ["name"]
            }
        },
        {
            "name": "aegis_tool_routing",
            "description": "Read-only policy oracle. Returns the [tools.X] routing record for a given external tool name (e.g. WebSearch, Bash, Read), or every declared tool if no name is provided. The record contains: capabilities (Aegis caps the tool requires), backend_url and backend_method (where the policy expects the call to land), description, and an allowed flag (true iff every required capability is permitted). Bridges and hosts use this to surface the policy's tool surface to a calling agent without re-parsing the TOML.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Optional tool name. Omit to receive every declared [tools.X] record."
                    }
                }
            }
        }
    ])
}

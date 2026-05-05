# Architecture

> ← [Back to docs README](README.md)

Aegis is a Rust workspace with four crates and three deliverables. The
implementation strategy is the same idea the README opens with — a
**safe-by-design local tooling layer for agentic AI**. Concretely
that's three independent runtime gates plus an output-boundary scrub,
all in Rust, none of them depending on prompting. The policy file is
the single source of truth, and the policy file itself is protected
against agent-mediated modification.

The deliverables are:

- **`aegis`** — a CLI binary. `aegis run --policy <toml> <script.star>`
  evaluates a Starlark script under policy enforcement.
  `aegis init --lang <python|node|ruby|rust|go>` generates a starter
  policy.
- **`aegis-host`** — an embeddable Rust crate. Anything that wants
  policy-gated Starlark evaluation in-process pulls this in and calls
  `Runner::new(policy).run(...)`.
- **`aegis-mcp`** — an MCP server. Speaks newline-delimited JSON-RPC 2.0
  on stdio. Exposes the host runtime as a tool surface that Claude Code,
  opencode, or any MCP-aware orchestrator can wire in.

## The three lines of defense

Every effecting capability — `fs.read`, `fs.write`, `fs.delete`,
`net.http_get/post/put/patch/delete`, `subprocess.exec`, `env.read` — has
to clear three independent gates before it runs:

```
       Starlark source
              │
              ▼
   ┌───────────────────────┐
   │   pre-execution       │   1. verifier.rs:
   │   verifier            │      walks the source, rejects the script
   │                       │      if it references any capability not
   └───────────────────────┘      derived from a populated resource
                                  section.
              │
              ▼  pass
   ┌───────────────────────┐
   │   embedded Starlark   │   2. evaluator runs the script with
   │   evaluator           │      capability-typed builtins registered
   │                       │      as globals.
   └───────────────────────┘
              │
              ▼  call e.g. fs.read("/etc/passwd")
   ┌───────────────────────┐
   │   runtime gate +      │   3. each builtin re-checks the policy
   │   audit emit          │      via Policy::check_*; on success emits
   │                       │      an AuditEvent; on failure raises a
   └───────────────────────┘      typed PolicyError that surfaces as a
                                  non-zero exit code.
```

The verifier and the runtime gate must **both** agree before any effect
fires. A script that obfuscates the capability name (e.g. by aliasing
`r = fs.read` and calling `r(...)`) trips the runtime check; a script
that emits a literal capability name in dead code trips the verifier.
Together, they make it hard to construct an "almost-allowed" agent
script.

## Capabilities

A capability is a `(dotted-name, raw-builtin-name)` pair. The dotted name
(`fs.read`) is what the policy file and audit events use. The raw name
(`_aegis_fs_read`) is what the host actually registers as a Starlark
global. A small **prelude** evaluated before the user script binds the
dotted form onto the underscored builtins via `struct(...)` values:

```starlark
# Aegis prelude (auto-injected, not part of user code)
fs = struct(
    read = _aegis_fs_read,
    write = _aegis_fs_write,
    delete = _aegis_fs_delete,
)
net = struct(
    http_get = _aegis_net_http_get,
    http_post = _aegis_net_http_post,
    http_put = _aegis_net_http_put,
    http_patch = _aegis_net_http_patch,
    http_delete = _aegis_net_http_delete,
)
subprocess = struct(exec = _aegis_subprocess_exec)
env = struct(read = _aegis_env_read)
```

The full capability list, in `crates/host/src/lib.rs`:

| Dotted name        | Effect                               |
|--------------------|--------------------------------------|
| `fs.read`          | Read a file, return contents         |
| `fs.write`         | Write a file (creates if needed)     |
| `fs.delete`        | Remove a file                        |
| `net.http_get`     | HTTP GET, return body                |
| `net.http_post`    | HTTP POST with body, return body     |
| `net.http_put`     | HTTP PUT with body, return body      |
| `net.http_patch`   | HTTP PATCH with body, return body    |
| `net.http_delete`  | HTTP DELETE, return body             |
| `subprocess.exec`  | Run argv (no shell), return stdout   |
| `env.read`         | Read an env var, return value        |

Pure computation (string ops, arithmetic, list/dict, function definitions)
needs no capability and is always permitted, even in the empty default
policy.

## The policy crate

`crates/policy/src/lib.rs` defines:

- `PolicyFile` — the parsed TOML schema (filesystem, network, environment,
  subprocess, functions, tools, confirm-per-call sections).
- `Policy` — a loaded policy plus precompiled matchers. `check_*` methods
  return `Result<T, PolicyError>` per capability.
- `presets::SECURE_DEFAULTS` — the universal-deny baseline embedded as a
  TOML string. Loaded via `inherits = "secure-defaults"` or via
  `Policy::secure_defaults_at(root)` for the no-policy CLI fallback.
- `merge_policy_files` (`PolicyFile::merge_with`) — concat-with-dedup
  and gitignore-style negation (`"!X"` strips an inherited entry).
- `Policy::guard_self_writable(path)` — load-time guard that refuses
  any policy whose `write_allow` or `delete_allow` matches the policy
  file's own path. Called automatically by `Policy::load`.

Relative patterns in a policy file anchor at the policy file's own
parent directory (the portable default). This means policies travel
with the project they govern; `read_allow = ["src/**"]` works whether
the operator runs `aegis` from the project root, a subdirectory, or
CI, and the policy never has to spell out user-specific absolute
paths. Both relative and absolute patterns work.

Path matching uses the `globset` crate (gitignore-style). Network host
matching uses the same matcher over hostnames. CIDR ranges in
`[network].deny_ips` are parsed into `IpNet` (the `ipnet` crate); literal
IPs become `/32` or `/128` host networks. DNS resolution is done at HTTP-
call time via `std::net::ToSocketAddrs`, and each resolved IP is run
through `check_resolved_ip` before the request fires (defends SSRF where
a hostname resolves to an internal IP).

## The host crate

`crates/host/src/lib.rs` is the Starlark embedding. Three things to know:

1. **`HostCtx`** — per-evaluation state. Holds the policy, audit sink,
   confirm hook, captured-error stash, the printed-line buffer, and the
   taint registry.
2. **`Runner`** — top-level entry. `Runner::new(policy).with_audit(sink)
   .with_confirm_hook(hook).run(task_id, source, script_name)` does the
   full verifier → eval → outcome dance. Returns a `RunOutcome` whose
   `printed` lines have already been scrubbed through the taint registry.
3. **`verifier`** — pre-execution scanner. Strips comments and string
   literals (so `# fs.read` in a comment doesn't false-positive), then
   word-boundary scans for any registered capability name. Rejects the
   whole run before evaluation starts if the script references a
   capability not derived from a populated resource section (see
   [04-policy-file.md](04-policy-file.md#capabilities-are-derived-not-declared)).

### Audit log

Every effecting builtin emits exactly one `AuditEvent` per call —
`Allowed` on success, `Errored` on a runtime failure, `Denied` on a
policy rejection. The default sink is `JsonlAuditSink::stderr()`; the CLI
can be pointed at a file via `--audit-log path.jsonl`. Audit-event
payloads (path, url, argv, env-var name, error message, denial reason)
go through the same taint redaction as `printed` lines before reaching
the sink. **The audit log will never contain a tainted value.**

**Tamper-evidence.** Every line written to the file sink is
SHA-256-chained. Each entry carries `aegis_seq` (monotonic from 1)
and `aegis_prev_hash` (hex SHA-256 of the previous line, or
`GENESIS_PREV_HASH = "0".repeat(64)` for the first). On open of an
existing log, the sink reads the tail to recover the resume point;
the chain continues across runs. `aegis audit verify <path>`
replays the chain and reports any line whose hash doesn't match or
whose seq isn't `prev + 1`, with line numbers and a reason —
useful as a CI lint or a one-shot integrity check after a run.

**Audit-log protected-path guard.** At policy-load time (when the
CLI or MCP server is launched with `--audit-log`), the runtime
refuses to start if the policy grants the agent ANY access (read,
write, or delete) to the audit-log path. Write/delete would let
the agent fabricate or erase history; read would let the agent
compute valid `aegis_prev_hash` values for forged appends. Same
shape as the policy file's self-writable guard, applied to the
log.

**What the chain does NOT catch.** Wholesale replacement with a
fresh, internally-consistent chain (the attacker writes a brand-
new log starting from seq=1, then replaces the file) is not
detectable from the chain alone. Defense: forward the log to
syslog or an immutable sink, OR keep an external reference for
the expected last seq. Both are operator-side mitigations
documented in `docs/SECURITY_AUDIT.md`.

### Confirm hook

The `ConfirmHook` trait lets a host plug in interactive approval for
capabilities listed in `[confirm_per_call]`. The CLI uses a TTY prompt
when `aegis run` runs interactively, `AllowAllConfirm` when `--yes` is
passed, and `DenyAllConfirm` when stdin/stderr aren't a TTY. The MCP
server selects between `AllowAllConfirm` and `DenyAllConfirm` via the
`--confirm-mode {auto-allow,auto-deny}` flag (default `auto-allow`).
In `auto-deny`, a confirm-gated call returns a tool result with
`isError: true` and `aegis_error_kind: "confirm_denied"`, naming the
capability — the orchestrator can interpret that and prompt the user
out-of-band before reissuing. In-process embedders that want real
prompt UI should plug their own `ConfirmHook` implementation.

### Local-only reads (taint)

`crates/host/src/taint.rs` implements the runtime-boundary redaction:

- `TaintRegistry` lives on `HostCtx`. It accumulates values returned by
  any read the policy classified as local-only (`fs.read` of
  `local_only_read` paths, `env.read` of `local_only_vars`,
  `subprocess.exec` of `local_only_commands`, HTTP responses from
  `local_only_hosts`).
- `redact(input, taints)` is a longest-first substring replace. Every
  occurrence of every registered tainted value is replaced with
  `[REDACTED]` before the string crosses the runtime boundary.
- `redact_json(value, taints)` walks `serde_json::Value` and applies the
  same redaction to every string leaf — used for audit-event payloads.

The boundary points where redaction fires:

- `RunOutcome::printed` — captured `print()` lines, scrubbed before being
  returned from `Runner::run`.
- `HostCtx::emit` — every `AuditEvent` is scrubbed before reaching the
  sink (whether file, stderr, or a custom sink).
- `aegis-mcp` tool results — already protected because they consist of
  the `outcome.printed` lines.

The redaction is substring-based and conservative: it catches the common
accidental and naive-extraction leaks. It does *not* defend against a
deliberately adversarial script that XORs the secret or chunks it across
multiple outputs — that requires real information-flow tracking, beyond
the MVP's scope. The threat model is *prompt engineering can't bypass it*
— a malicious prompt cannot, because the rule is enforced in Rust.

## The CLI crate

`crates/cli/src/main.rs` is a clap-based subcommand dispatcher:

- `aegis run [--policy PATH] [--audit-log PATH] [--task-id ID] [--yes]
  <script>` — load policy, run script, exit with a typed exit code:
  - `0` ok
  - `1` Starlark eval error
  - `2` policy violation at runtime
  - `3` pre-execution verifier rejection
  - `4` confirm hook denied
  - `5` i/o or configuration error
- `aegis init --lang <LANG> [--output PATH] [--force]` — emit a starter
  policy. See [04-policy-file.md](04-policy-file.md#the-init-generator).
- `aegis policy validate <PATH>` — parse + resolve inheritance + run
  the load-time guards (including the self-writable check) without
  running any script. Exits 0 on OK; non-zero with a clear error
  otherwise. Useful as a CI lint step.
- `aegis policy show <PATH>` — print a human-readable summary of
  the resolved policy: derived capabilities, every populated rule
  section, declared tools (with routing hints), runtime caps,
  confirm-gated capabilities. Useful for "what is my agent
  actually allowed to do?".

If `--policy` is omitted on `aegis run`, the runtime falls back to the
built-in `secure-defaults` baseline and prints a loud-and-safe banner on
stderr: every effecting capability is denied; pure computation works.

## The MCP crate

`crates/mcp/src/main.rs` is a stdio JSON-RPC 2.0 server speaking the MCP
protocol. It exposes eight tools that all funnel through the host
runtime:

- `aegis_run(script, task_id?)` — primary surface. Caller hands over a
  Starlark program; server runs it under the configured policy. Returns
  the printed lines (already taint-scrubbed).
- `aegis_fs_read`, `aegis_fs_write`, `aegis_fs_delete` — sugar over
  `aegis_run`. Each synthesizes a one-line Starlark program for the
  action. Useful for hosts that prefer one MCP call per action.
- `aegis_subprocess_exec(argv)` — same.
- `aegis_net_http_get(url)`, `aegis_net_http_post(url, body)` — same.
- `aegis_env_read(name)` — same.

Like the CLI, `aegis-mcp` accepts `--policy <toml>` and falls back to
`secure-defaults` (with a stderr banner) if absent. Audit events stream
to stderr by default or to a file via `--audit-log`.

See [07-claude-code.md](07-claude-code.md) and [08-opencode.md](08-opencode.md)
for the host-side wiring.

## Layout

```
crates/
  policy/    — types, matchers, presets, inheritance, ~500 lines
    src/lib.rs        public API
    src/presets.rs    secure-defaults baseline (TOML const)
    tests/policy.rs   34 integration tests
  host/      — Starlark embedding, builtins, audit, verifier, taint
    src/lib.rs        Runner, HostCtx, capability builtins
    src/audit.rs      AuditEvent, JsonlAuditSink
    src/confirm.rs    ConfirmHook + DenyAll/AllowAll
    src/verifier.rs   pre-execution scanner
    src/taint.rs      TaintRegistry + redact / redact_json
    tests/host.rs       7 integration tests
    tests/verifier.rs   8 integration tests
    tests/taint.rs      7 integration tests
  cli/       — `aegis` binary
    src/main.rs       run + init subcommands
    src/init.rs       per-language policy templates
    tests/init.rs     10 integration tests
  mcp/       — `aegis-mcp` MCP server
    src/main.rs       JSON-RPC dispatch + 8 tools
```

Tests are all in `tests/` directories — Cargo integration tests against
the public API only.

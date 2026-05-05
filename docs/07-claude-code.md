# Using Aegis with Claude Code

> ← [Back to docs README](README.md)

[Claude Code](https://claude.com/claude-code) is Anthropic's official CLI
for Claude. It supports MCP — the [Model Context Protocol](https://modelcontextprotocol.io)
— which is exactly the integration shape Aegis is designed for. This
guide covers the two ways to wire Aegis in:

1. **As a policy-gated tool surface** — Claude Code calls Aegis tools
   through an MCP server, and only Aegis-permitted operations succeed.
2. **As a remote-orchestrator → local-executor relay** — Sonnet/Opus in
   Claude Code delegates tasks to a local 7B model that runs the actual
   code through Aegis. This is the architecture the project's evaluation
   harness measures (see [09-local-executor.md](09-local-executor.md)).

## Prerequisites

- `aegis` and `aegis-mcp` built and on `$PATH` (see
  [05-install.md](05-install.md)).
- `claude` CLI installed and authenticated.
- A policy file. `aegis init --lang <lang>` is the fastest start — see
  [04-policy-file.md](04-policy-file.md#the-aegis-init-generator).

## Approach 1: Aegis as a policy-gated tool surface

Wire `aegis-mcp` into Claude Code as a project-level MCP server.

### Configure the MCP server

Claude Code reads MCP server configuration from your settings (per-user
or per-project; see Claude Code's docs for the exact location on your
platform). Add an `aegis` server entry:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "aegis-mcp",
      "args": ["--policy", "/absolute/path/to/your/aegis.toml"]
    }
  }
}
```

Use absolute paths — the MCP server's working directory may not match
your project root.

### Available tools

Once configured, Claude Code sees these tools (all prefixed
`mcp__aegis__` by Claude Code's MCP namespacing):

- `mcp__aegis__aegis_run` — primary surface. Pass a Starlark program;
  the server runs it under the policy. Result is the printed lines,
  already taint-scrubbed.
- `mcp__aegis__aegis_fs_read`, `mcp__aegis__aegis_fs_write`,
  `mcp__aegis__aegis_fs_delete` — sugar tools that synthesize a
  one-statement Starlark program. Useful for hosts that prefer one
  call per action.
- `mcp__aegis__aegis_subprocess_exec` — same.
- `mcp__aegis__aegis_net_http_get`, `mcp__aegis__aegis_net_http_post`
  — same.
- `mcp__aegis__aegis_env_read` — same.

### Restrict Claude Code to only the Aegis tools

If you want a hardened setup where Claude Code can *only* affect the
system through Aegis (no built-in `Bash`, no built-in `Edit`), launch it
with `--tools` cleared and `--allowedTools` restricted:

```sh
claude \
  --mcp-config '{"mcpServers":{"aegis":{"command":"aegis-mcp","args":["--policy","/path/to/aegis.toml"]}}}' \
  --tools "" \
  --allowedTools "mcp__aegis__aegis_run,mcp__aegis__aegis_fs_read,mcp__aegis__aegis_fs_write,mcp__aegis__aegis_subprocess_exec,mcp__aegis__aegis_net_http_get,mcp__aegis__aegis_env_read"
```

Now Claude Code's *only* path to side-effects is through Aegis. Every
fs/net/subprocess/env call goes through the policy gate and lands in the
audit log.

### Audit log

To collect audit events to a file:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "aegis-mcp",
      "args": [
        "--policy", "/path/to/aegis.toml",
        "--audit-log", "/path/to/audit.jsonl"
      ]
    }
  }
}
```

Each tool call produces one JSON Lines record per effecting action.

### Confirm-gated capabilities

If your policy has `confirm_per_call = ["fs.delete", "subprocess.exec"]`,
the MCP server's `--confirm-mode` flag picks how those calls are
treated:

- **`--confirm-mode auto-allow`** (default): the confirm hook
  always allows. Same as not having `confirm_per_call` at all from
  the MCP path's perspective. Use this when you trust the agent
  surface and just want the audit log entry.
- **`--confirm-mode auto-deny`**: the confirm hook always denies.
  Each confirm-gated call returns a tool result with
  `isError: true` and `aegis_error_kind: "confirm_denied"`,
  naming the capability. Sonnet/Opus can read that error and
  decide whether to prompt the human (out-of-band) before
  reissuing — it's the closest thing to interactive confirm that
  works through MCP today.

Real round-trip prompting through MCP (server-initiated user
interaction) requires bidirectional protocol support that's not
yet implemented in Aegis. For interactive prompts today, use
the `aegis run` CLI directly instead of the MCP server.

```json
{
  "mcpServers": {
    "aegis": {
      "command": "aegis-mcp",
      "args": [
        "--policy", "/path/to/aegis.toml",
        "--confirm-mode", "auto-deny"
      ]
    }
  }
}
```

### What "policy-gated" actually buys you

A few examples of what Claude Code can no longer do, when wired this
way, regardless of how the model is prompted:

- Read `~/.aws/credentials` — `secure-defaults` blocks the path.
- Run `git push --force` — generated policies put it in
  `[subprocess.deny_args].git`.
- Curl an internal IP — `[network].deny_ips` includes RFC1918 + cloud
  metadata, applied after DNS resolution.
- Read `OPENAI_API_KEY` and ship it back in chat — if marked
  `local_only_vars`, the key bytes are scrubbed before crossing the MCP
  boundary.

## Approach 2: Sonnet → local-executor → Aegis

This is the architecture from
[09-local-executor.md](09-local-executor.md). It's worth a quick
overview here because it's the stack the project evaluation actually
measures.

The shape:

```
   Sonnet/Opus (in Claude Code, via `claude -p`)
        │  delegate_to_local("step description")
        ▼
   examples/local_executor/local_mcp.py  (an MCP server you launch)
        │  prompts the local 7B model
        ▼
   qwen2.5-coder:7b  (via Ollama)
        │  emits a Starlark program
        ▼
   aegis-mcp  (subprocess of local_mcp.py)
        │  runs the program under your policy
        ▼
   The actual side effects (fs/net/subprocess/env)
```

The bridge piece — `local_mcp.py` — is in `examples/local_executor/`. It
exposes a single MCP tool, `delegate_to_local(step)`. The cloud
orchestrator decomposes the task into atomic steps and delegates each
one; the local executor synthesizes Starlark for that step and runs it
through `aegis-mcp`.

To launch this from Claude Code:

```sh
claude -p "Refactor src/foo.py to remove duplication" \
  --model sonnet \
  --mcp-config '{
    "mcpServers": {
      "local-executor": {
        "command": "python3",
        "args": [
          "/path/to/aegis/examples/local_executor/local_mcp.py",
          "--policy", "/path/to/aegis.toml"
        ]
      }
    }
  }' \
  --tools "" \
  --allowedTools "mcp__local-executor__delegate_to_local" \
  --append-system-prompt "$(cat ORCHESTRATOR_PROMPT.txt)"
```

Sonnet sees only one tool: `delegate_to_local`. It cannot directly
write files, run shells, or fetch URLs — every side effect has to flow
through the local model and Aegis.

The `examples/local_executor/run_orchestrated.py` harness automates this
pattern across a 36-task evaluation suite, so you can reproduce the
project's measurement runs with `python3 run_orchestrated.py --models
sonnet opus --all`.

### Why this shape

- **The cloud orchestrator never sees raw secrets.** The local model
  reads the user's `OPENAI_API_KEY` (marked `local_only_vars`); Aegis
  scrubs it before the MCP response reaches Sonnet.
- **The cloud orchestrator never sees the file contents.** Whatever the
  local model does with `fs.read` results stays local; only the
  printed summary it composes (and its taint-scrubbed bytes) travels
  back.
- **The audit log is one file.** Every action across every step lands in
  `aegis-mcp`'s audit log, regardless of which orchestrator, which
  local model, which task — one source of truth.

## Trying it locally

If you just want to confirm Aegis is wired correctly without the full
local-executor flow, a one-shot test:

```sh
echo 'print("hello from aegis")' > /tmp/hello.star
claude --mcp-config '{
  "mcpServers": {
    "aegis": {
      "command": "aegis-mcp",
      "args": ["--policy", "/path/to/aegis.toml"]
    }
  }
}' "Run mcp__aegis__aegis_run with this Starlark: $(cat /tmp/hello.star)"
```

You should see Sonnet acknowledge the tool result containing `"hello
from aegis"`.

## Troubleshooting

**`aegis-mcp: no --policy provided` banner showing up:** you forgot to
pass `--policy` in `args`. The fallback is the deny-everything
`secure-defaults` baseline; every tool call will fail. Add the path.

**Claude Code shows the tool but every call fails with `Verifier
rejected`:** the resource section the capability is derived from is
empty. For example, calls to `fs.read` need at least one entry in
`[filesystem].read_allow` (or `local_only_read`). Open the policy
file, populate the matching section, and restart Claude Code (it
caches MCP tool listings). The full mapping is in
[04-policy-file.md](04-policy-file.md#capabilities-are-derived-not-declared).

**A tool call reports `not in [filesystem].read_allow`:** the path you
asked for isn't covered by `read_allow`. Either add the path to
`read_allow` or use a more permissive pattern. Refresher in
[04-policy-file.md](04-policy-file.md#filesystem).

## Where next

- [08-opencode.md](08-opencode.md) — same setup for opencode.
- [09-local-executor.md](09-local-executor.md) — the local-executor
  architecture in depth, including the evaluation results.
- [04-policy-file.md](04-policy-file.md) — for tightening the policy
  once you know what your agent actually needs.

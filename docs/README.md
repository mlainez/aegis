# Aegis Documentation

Aegis is a **safe-by-design local tooling layer for agentic AI** — a
Rust runtime that runs agent code under a TOML-declared policy that
the operator (not the model) controls. It embeds Starlark (Python's
safe subset), exposes a small namespaced standard library (`fs.read`,
`net.http_get`, `subprocess.exec`, `env.read`), and enforces the
policy at every effecting call. Default-deny everywhere: what's not
in the policy file doesn't happen. Forbidden operations fail at the
*system* layer, not in the agent's prompt.

It ships as three things: a CLI binary (`aegis`), an embeddable Rust
crate (`aegis-host`), and an MCP server (`aegis-mcp`) that any agentic
host (Claude Code, opencode, Cursor, custom orchestrators) can wire in.

## Where to start

- **First contact:** [01-why-aegis.md](01-why-aegis.md) — the problem
  this exists to solve and the threat model.
- **Background:** [02-from-sigil.md](02-from-sigil.md) — what the
  earlier Sigil project tried, what it taught us, and what changed.
- **How it's built:** [03-architecture.md](03-architecture.md) —
  capability typing, the three lines of defense, how the runtime
  enforces things.
- **Policy file (the most important read):** [04-policy-file.md](04-policy-file.md) —
  full walkthrough of the TOML format, the `secure-defaults` preset,
  inheritance / negation, and the `aegis init` generator.
- **Install:** [05-install.md](05-install.md) — prerequisites
  (Rust toolchain, Ollama for the local-executor flow, Claude or
  opencode for the orchestrated flow).
- **Quickstart:** [06-quickstart.md](06-quickstart.md) — a 5-minute
  walkthrough: generate a policy, run a script, watch the audit log.
- **Claude Code integration:** [07-claude-code.md](07-claude-code.md) —
  wire `aegis-mcp` into Claude Code as a policy-gated tool surface.
- **opencode integration:** [08-opencode.md](08-opencode.md) — same
  for opencode.
- **The agentic story:** [09-local-executor.md](09-local-executor.md) —
  cloud orchestrator (Sonnet/Opus) → local 7B executor → Aegis runtime.
  This is the architecture the project's evaluation harness measures.
- **Reproduce the numbers:** [10-running-examples.md](10-running-examples.md) —
  prerequisites and step-by-step for the three evaluation harnesses
  (single-step, 36-task multi-step, Sonnet/Opus orchestrated). Read
  this if you want to confirm the headline numbers on your own
  machine.

## Reference material

- [AGENT_POLICY_SPEC.md](AGENT_POLICY_SPEC.md) — the portable spec.
  Tool-agnostic; consumable by any agentic system. Use this if you're
  implementing the policy format in a non-Aegis runtime.
- [SECURITY_THREAT_MODEL.md](SECURITY_THREAT_MODEL.md) — one-page
  review companion. What Aegis defends against, what it explicitly
  does *not* defend against, and where the trust boundaries sit.
  Read first if you're auditing with hostile intent.
- [SECURITY_AUDIT.md](SECURITY_AUDIT.md) — the 16-surface
  bypass-assessment writeup that triggered the recent security work.
- [CONCLUSIONS.md](CONCLUSIONS.md) — the Sigil retrospective notes
  Aegis was built from. Background reading for `02-from-sigil.md`.
- [PROJECT_PLAN.md](PROJECT_PLAN.md) — initial design plan, kept as a
  historical artifact.

## Project layout

```
crates/
  policy/   — policy types, matchers, presets, inheritance
  host/     — Starlark embedding, capability builtins, audit, verifier
  cli/      — `aegis` binary (run + init subcommands)
  mcp/      — `aegis-mcp` MCP server (stdio JSON-RPC)
docs/       — this directory
examples/
  policies/        — reference policies (FastAPI, Rails, ...)
  local_executor/  — evaluation harness (Ollama + qwen + aegis-mcp)
```

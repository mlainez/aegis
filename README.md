# Aegis

**A safe-by-design local tooling layer for agentic AI, with deliberate
control over permissions through a policy file.**

Aegis embeds Starlark (Python's safe subset), exposes a small set of
effecting builtins (`fs.read`, `net.http_get`, `subprocess.exec`,
`env.read`, ...), and enforces a TOML-declared policy at every call.
The runtime is default-deny end-to-end; what an agent can do is
exactly what the policy file permits, no more. Forbidden operations
fail at the **system layer** — in Rust, before or during evaluation —
not in a wrapper that asks the model nicely.

> ## ⚠ Status & honest disclosures
>
> - **Use at your own risk.** Aegis is **in active development** and
>   has not been hardened for production. There are no security audits,
>   no released versions on crates.io, and APIs may still change.
>   Don't run it against systems you can't afford to recover.
> - **AI-generated codebase.** Almost all of the code, tests, and
>   documentation in this repository was written by Claude (Anthropic)
>   under human direction. The human (project owner) decided the
>   architecture, design constraints, threat model, and load-bearing
>   tradeoffs; Claude wrote the implementation, the tests, and most of
>   the docs. This is disclosed because it materially affects how you
>   should evaluate the code: please **read the diffs before trusting
>   them**, especially anywhere security-critical (the policy crate,
>   the verifier, and the taint-redaction code in `crates/host/`).
> - **Threat-model scope.** The runtime defends against *prompt
>   engineering* — the policy is enforced in Rust and a malicious
>   prompt cannot bypass it by clever phrasing. It does NOT defend
>   against a determined adversary doing deliberate exfiltration via
>   obfuscation (XOR, base64, chunking) of tainted values. See
>   [docs/04-policy-file.md](docs/04-policy-file.md#how-local-only-works)
>   for the limits of the local-only scrubbing.
> - **No OS-level isolation.** Aegis is a *language-runtime*
>   gate, not a sandbox in the seccomp/namespace/VM sense. For full
>   isolation, run it inside a container.

## The problem

Today's coding agents (Claude Code, Cursor, opencode, Aider, custom
CLI bots) sit on a spectrum between *"approve every command"*
(friction-heavy, fatigue-prone, the user clicks through anyway) and
*"YOLO mode"* (no safety, every shell call runs). Both modes share a
critical property: the **agent runtime decides what's safe** based on
what the model emitted, and the model can phrase commands to look
more innocuous than they are.

Specifically, today's agentic stacks struggle with:

- destructive shell commands (`rm -rf`, `git push --force`,
  `terraform apply` against prod)
- credential exfiltration (reading `~/.aws/credentials`,
  `$AWS_SECRET_ACCESS_KEY`, etc.)
- prompt-injection vectors that send commands as text inside fetched
  content
- secret keys leaking from a local executor up to a cloud orchestrator
  (the agent reads your API key, summarizes the call, and the key
  shows up in the orchestrator's context)

None of these should be solved by hoping the model doesn't choose to
do the bad thing.

## How Aegis solves it: safe by design

The whole runtime is built around one rule: **what's not in the policy
doesn't happen**. There is no "best-effort" mode, no soft-warn, no
fallback path that quietly does the action anyway. This is what
"safe by design" means in this project — the enforcement is structural,
not advisory.

A declarative policy file (TOML) is the single source of truth that
controls every effect:

```toml
inherits = "secure-defaults"   # universal denies for credentials,
                                # cloud-metadata IPs, RFC1918, dangerous
                                # commands, secret env vars, etc.

[filesystem]
read_allow      = ["src/**", "tests/**"]
local_only_read = ["~/.config/myapp/token"]   # readable, never bubbles up
write_allow     = ["src/**", "/tmp/**"]

[network]
http_get_allow   = ["api.github.com"]
local_only_hosts = ["api.openai.com"]   # response tainted at boundary
deny_ips         = ["169.254.0.0/16", "10.0.0.0/8"]   # CIDR-aware

[environment]
allow_vars      = ["PATH", "USER"]
local_only_vars = ["OPENAI_API_KEY"]    # the agent can use it; it can't leak it
deny_vars       = ["AWS_SECRET_ACCESS_KEY"]

[subprocess]
allow_commands = ["git", "make", "python3"]

[subprocess.deny_args]
git = ["push --force", "reset --hard", "filter-branch"]
```

The capabilities the script may call (`fs.read`, `fs.write`,
`net.http_get`, `env.read`, `subprocess.exec`) are **derived from
which resource sections you populated** — there is no separate
`[functions]` allowlist to keep in sync.

Three lines of defense, all in the runtime — none of them depend on
prompting:

1. **Pre-execution verifier** rejects any script referencing a
   capability whose resource section is empty before evaluation
   starts.
2. **Capability gate at every call** re-checks the policy at runtime;
   a forbidden read/write/fetch/exec raises a typed error that
   surfaces as a non-zero exit code.
3. **Output-boundary redaction** scrubs any `local_only_*` value from
   printed output, audit-log payloads, and MCP tool results — so a
   secret the local agent reads cannot bubble up to a cloud
   orchestrator (or to your chat transcript) even if the model puts
   it in a string.

Three visibility levels per resource: **forbidden** / **local-only** /
**public**. Default-deny everywhere; deny wins over allow.

## The design principle

> **Start from a limited language the models already know the syntax of, then extend only with what we need.**

That sentence is the load-bearing decision the rest of Aegis follows
from. Two properties, both load-bearing on their own:

**"A limited language the models already know"** means we get to
free-ride on pre-training. Stock LLMs arrive ~90% fluent in Starlark
on day one because Starlark is Python with three rules removed. The
remaining gap is closed with prompting + retrieval + retry, not
months of fine-tuning. (We tried the fine-tuning path in the
predecessor project, [Sigil](docs/02-from-sigil.md). It plateaued at
7/30 multi-step tasks. Aegis with **stock qwen-7B alone** (no cloud
orchestrator) reaches 36/36 on the current 36-task suite. Layered
with Sonnet/Opus orchestration on top of qwen+Aegis on the same
36-task suite: Sonnet 30/36, Opus 35/36 — the orchestrated misses
are model-side artifacts (Sonnet preemptively refuses some DENY
tasks; Opus paraphrases the literal `[REDACTED]` sentinel one
verify hook substring-matches on). The runtime denies and redacts
correctly in every case. See
[docs/09-local-executor.md](docs/09-local-executor.md) for the
per-failure breakdown.)

**"Extend only with what we need"** flips the security model inside
out. Default Python is *"everything works, lock it down by
subtraction"*; default Starlark is *"nothing works, opt in by
addition"*. Every effecting builtin — `fs.read`, `net.http_get`,
`subprocess.exec`, `env.read` — is a deliberate, named,
capability-typed addition the runtime can gate. Subtraction-based
security has a long history of CVE backlogs (every Python sandbox
that ever shipped). Addition-based security has a much smaller blast
radius when a corner case is wrong.

Combined: the agent writes code in something it already mostly knows,
inside a runtime where the only effects are the ones the operator
explicitly granted.

## Get started

```sh
cargo build --release                     # builds aegis + aegis-mcp
aegis init --lang python                  # generates a starter policy
aegis run --policy aegis.toml my.star     # runs the script under it
```

`aegis init` supports `python`, `node`, `ruby`, `rust`, `go`, with
language-appropriate toolchain allowlists and git-destructive denies
baked in.

If you skip `--policy`, Aegis falls back to the built-in
`secure-defaults` baseline (no allow lists, every effect denied) and
prints a banner explaining how to grant capabilities. Loud-and-safe.

For agentic hosts, `aegis-mcp` is an MCP server (stdio JSON-RPC 2.0)
that exposes the same enforcement to Claude Code, opencode, or any
MCP-aware orchestrator.

## Three deliverables

- **`aegis`** — CLI binary. `aegis run` evaluates a script under a
  policy. `aegis init` generates a starter policy.
- **`aegis-host`** — embeddable Rust crate. Anything that wants
  policy-gated Starlark in-process pulls this in.
- **`aegis-mcp`** — MCP server. Wires Aegis into Claude Code,
  opencode, Cursor, custom orchestrators.

## Documentation

The deep dive lives in [`docs/`](docs/):

| Doc                                                | What's in it                                                          |
|----------------------------------------------------|----------------------------------------------------------------------|
| [01-why-aegis.md](docs/01-why-aegis.md)             | The problem statement and threat model.                              |
| [02-from-sigil.md](docs/02-from-sigil.md)           | What the earlier Sigil project taught us; why Aegis looks the way it does. |
| [03-architecture.md](docs/03-architecture.md)       | Capability typing, the three lines of defense, the crate layout.     |
| [04-policy-file.md](docs/04-policy-file.md)         | **Policy file reference.** Every section, every option, with examples. Includes the `aegis init` generator and the local-only-reads feature. |
| [05-install.md](docs/05-install.md)                 | Prerequisites: Rust, Ollama, Claude Code / opencode.                 |
| [06-quickstart.md](docs/06-quickstart.md)           | A 5-minute walkthrough — generate, run, audit.                       |
| [07-claude-code.md](docs/07-claude-code.md)         | Wire `aegis-mcp` into Claude Code. Two integration shapes.           |
| [08-opencode.md](docs/08-opencode.md)               | Same for opencode.                                                    |
| [09-local-executor.md](docs/09-local-executor.md)   | The full agentic stack: cloud orchestrator → local 7B → Aegis. Includes evaluation results. |
| [10-running-examples.md](docs/10-running-examples.md) | Reproduction guide for the three eval harnesses (single-step, 36-task multi-step, Sonnet/Opus orchestrated). |
| [AGENT_POLICY_SPEC.md](docs/AGENT_POLICY_SPEC.md)   | The portable spec — implement the policy format in non-Aegis runtimes. |
| [CONCLUSIONS.md](docs/CONCLUSIONS.md)               | Sigil retrospective notes (background reading for `02-from-sigil.md`). |
| [PROJECT_PLAN.md](docs/PROJECT_PLAN.md)             | Initial design plan; historical artifact.                            |

The single most important read is
[**docs/04-policy-file.md**](docs/04-policy-file.md). The policy file is
the whole product.

## Why "Aegis"?

The aegis (αἰγίς) is the protective shield of Zeus and Athena in Greek
mythology — Hephaestus-forged, sometimes described as a goatskin
breastplate, occasionally bearing the head of the Gorgon Medusa to
ward off threats. In English, "an aegis" still means a protective
covering, sponsorship, or guarantee of safety ("under the aegis of...").

That's the role this project plays for an agentic-AI workflow: a
protective layer that sits between the model's intent and the system
it can act on. The runtime is the shield; the policy file is what
determines which arrows it stops.

## Status

Pre-1.0. The runtime is solid; the eval harness reproduces stable
numbers (qwen 7B alone: **36/36** on the current 36-task suite, which
includes 5 feature-demo tasks pinning specific runtime layers;
Sonnet-orchestrated on the same suite: **30/36 / $1.37**;
Opus-orchestrated: **35/36 / $2.83**). The orchestrated gap is
model-side, not runtime-side — Aegis denies and redacts correctly
in every case; Sonnet sometimes preemptively refuses DENY tasks
it should attempt, and the single Opus miss is a verify-hook
substring strictness issue where the orchestrator paraphrased
the redaction outcome instead of preserving the literal
`[REDACTED]` sentinel. Per-failure breakdown in
[docs/09-local-executor.md](docs/09-local-executor.md).
The policy spec is portable and documented. APIs may still change.

## Roadmap to production-readiness

Aegis is a serious prototype with end-to-end functionality, but
**not yet hardened enough to be your default for unattended
agentic work**. These are the open items between today and "drop
this on three machines and standardize." Listed roughly by
priority — the security items (☐) gate daily-driver use; the
operational items (◇) gate easy adoption.

### Already shipped (this codebase)

- ✅ Subprocess env filtering (child only sees declared `allow_vars`)
- ✅ Wall-time deadline + call-stack cap (`[runtime].max_seconds`,
  `max_callstack_size`)
- ✅ Structured confirm-mode for `aegis-mcp` (auto-allow / auto-deny
  with `aegis_error_kind: "confirm_denied"` tag for orchestrator
  branching)
- ✅ `aegis policy validate` + `aegis policy show` (CI lint and
  operator visibility)
- ✅ Per-call HTTP timeout (`[network].timeout_seconds`, default 30s)
- ✅ Self-writable guard (refuses policies that grant write/delete on
  themselves)
- ✅ Local-only visibility class (read OK, value never bubbles up;
  output-boundary substring redaction)
- ✅ Subprocess argv path-policy gate
  (`subprocess.exec(["cat", "/etc/passwd"])` rejected — argv args
  that look like paths are checked against `[filesystem]` rules)
- ✅ Opt-in OS-level sandbox via `[subprocess].sandbox = "bwrap"`
  (Linux only; bubblewrap-backed namespaced bind-mount jail per
  call — paths outside the policy literally don't exist for the
  child, defeats every interpreter-side path-obfuscation trick)
- ✅ Symlink canonicalization in `fs.*` (a symlink at
  `<root>/src/x → /etc/passwd` no longer slips past the policy
  check)
- ✅ HTTP redirects no longer auto-followed (`net.http_*` returns a
  typed error on 3xx so the script must reissue against the new
  URL — gate fires)
- ✅ Taint-redaction now covers the error path (`fail(secret)`
  no longer leaks via `AegisError::Display`)
- ✅ SHA-256-chained audit log + `aegis audit verify <path>`
  subcommand (in-place mutation, line removal, seq jumps all
  detectable)
- ✅ Audit-log protected-path guard (the agent cannot have
  read/write/delete on the audit log — same shape as the
  self-writable guard for the policy file)
- ✅ One-page security threat-model doc
  ([docs/SECURITY_THREAT_MODEL.md](docs/SECURITY_THREAT_MODEL.md))
  — what Aegis defends against, what it does *not*, the trust
  boundaries, the assumptions
- ✅ Adversarial exfiltration probe
  ([examples/local_executor/run_exfil.py](examples/local_executor/run_exfil.py))
  — 12 hand-written Starlark exfil techniques against
  `local_only_vars`. Current run: **6 LEAK / 3 WEAK_LEAK / 3
  REDACTED**. Confirms substring redaction is *not* a
  sufficient defence against a deliberate adversary; the gap
  is documented honestly in the threat-model doc.
- ✅ `aegis-mcp` surfaces `[tools.X]` routing hints
  (`aegis_tool_routing` MCP tool) so Claude Code calling
  `aegis_run` directly can read `backend_url` / capabilities /
  allowed flag without re-parsing the policy TOML

### Still open

#### Security gates (block daily-driver use)

- ☐ **Fuzz the verifier and the TOML/policy parser.** A week of
  `cargo-fuzz` against the verifier's comment/string-stripping, the
  globset path matchers, and the TOML deserializer. Fix what falls
  out.
- ☐ **External security review.** AI-generated security code is
  unaudited security code. The policy crate, the verifier, and the
  taint-redaction code in `crates/host/src/taint.rs` need a human
  security engineer reading them with hostile intent. **This is the
  single biggest gating item.** The threat-model doc and the exfil
  probe's findings are bundled to give the reviewer a clear scope.
- ☐ **Real information-flow tracking for `local_only_*`.** The
  exfil probe found 6 substring-redaction bypasses (encode,
  reverse, hex, XOR, fs.write to disk, error-path with mutation).
  Closing this requires either real IFC at the runtime layer, or
  scoping `local_only_*` more tightly (e.g. block any operation
  whose argument was tainted, not just substring-scrub on output).
  Decide which.

#### Operational gates (block easy adoption)

- ◇ **Published binaries.** `cargo install`, Homebrew tap, or
  pre-built tarballs. Build-from-source is fine for evaluation, not
  for "ship to three machines and standardize."
- ◇ **Policy schema migration tool.** When the schema changes
  pre-1.0, existing policies are hand-edited. An `aegis policy
  migrate` would smooth this.

For today: use Aegis for experimental setups, in containers, on
machines where the cost of an Aegis bug is "I have to recover a VM"
not "my SSH key got exfiltrated." For default-on-everything use,
the three ☐ items above (fuzzing, external review, IFC for
local-only) are the real gating list.

## Project layout

```
crates/
  policy/    types, matchers, presets, inheritance
  host/      Starlark embedding, builtins, audit, verifier, taint
  cli/       `aegis` binary (run + init)
  mcp/       `aegis-mcp` MCP server
docs/        documentation (links above)
examples/
  policies/        reference policies (FastAPI, Rails, ...)
  local_executor/  evaluation harness (Ollama + qwen + aegis-mcp)
```

## License

[MIT](LICENSE) © 2026 Marc Lainez.

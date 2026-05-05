# The Local-Executor Architecture

> ← [Back to docs README](README.md)

This document covers the agentic-setup shape Aegis was designed for: a
**cloud orchestrator** (Sonnet, Opus, or any other large model)
delegates atomic steps to a **local executor model** (a 7B running on
the user's machine via Ollama), which emits Starlark programs that
**Aegis** enforces against a project policy.

It's the architecture the project's evaluation harness measures, and
the one that makes the local-only-secrets feature
([04-policy-file.md](04-policy-file.md#how-local-only-works)) actually
useful — secrets stay on the local side, the cloud side never sees
them.

## The shape

```
   ┌──────────────────────────────────┐
   │   Cloud orchestrator             │   Sonnet / Opus / etc.
   │   (e.g. via `claude -p`)         │   sees ONE tool: delegate_to_local
   └──────────────────────────────────┘
                  │
                  │  delegate_to_local("read manifest, extract version")
                  ▼
   ┌──────────────────────────────────┐
   │   local_mcp.py                   │   MCP server you launch.
   │   (examples/local_executor/)     │   bridges orchestrator ↔ local model.
   └──────────────────────────────────┘
                  │
                  │  prompts qwen with system_prompt + step + RAG-retrieved examples
                  ▼
   ┌──────────────────────────────────┐
   │   qwen2.5-coder:7b (Ollama)      │   emits a Starlark program.
   │   on http://localhost:11434      │
   └──────────────────────────────────┘
                  │
                  │  Starlark source
                  ▼
   ┌──────────────────────────────────┐
   │   aegis-mcp                      │   subprocess of local_mcp.py.
   │   (subprocess of local_mcp.py)   │   enforces the project policy.
   └──────────────────────────────────┘
                  │
                  │  permitted side effects
                  ▼
   ┌──────────────────────────────────┐
   │   filesystem / network /         │
   │   subprocess / env               │
   └──────────────────────────────────┘
```

Three things to note:

- **The cloud orchestrator never directly emits Starlark.** It
  decomposes the task into a sequence of atomic steps and hands each
  step's *description* to `delegate_to_local`. The local model
  synthesizes the actual code.
- **Each delegate call is independent.** Inter-step state crosses only
  through what the local model writes to disk. The orchestrator
  composes the next step's description based on the previous step's
  summary text.
- **Aegis is the bottom of the stack.** Every side effect — every file
  read, network call, subprocess — runs through it under one policy.
  One audit log captures the whole run.

## What's in `examples/local_executor/`

| File                  | Role                                                                  |
|-----------------------|-----------------------------------------------------------------------|
| `run.py`              | Phase 1 harness: single-step tasks, local 7B alone, **no orchestrator**. |
| `run_multistep.py`    | Phase 1.5: 36 multi-step tasks, local 7B alone, **no orchestrator**. |
| `run_orchestrated.py` | Phase 2: same 36-task suite, with Sonnet/Opus on top via `claude -p`. |
| `local_mcp.py`        | The bridge MCP server: delegate_to_local → qwen → aegis-mcp.         |
| `rag.py`              | Embedding-based retrieval (nomic-embed-text + 19 worked examples).   |

## What's measured

> **Layer split.** Phase 1 and Phase 1.5 are `qwen2.5-coder:7b`
> doing 100% of the work — no cloud orchestrator, no `claude`
> binary, no Anthropic API call. Phase 2 layers Sonnet/Opus *on
> top* of the same qwen+Aegis stack, with the cloud model
> responsible only for task decomposition and step routing while
> qwen still writes every Starlark program. Each phase's numbers
> are independent measurements.

All numbers use `examples/policies/multistep_test.toml` as the
policy. The current task suite has 36 tasks (was 31): file
manipulation (6), HTTP+JSON (6), subprocess composition (5),
cross-capability flows (5), aggregation (4), deny-correct cases
(8), and feature-demo tasks (2 LOCAL_ONLY) — the 5 newest tasks
specifically pin the recent security fixes.

### Phase 1: single-step (`run.py`) — qwen alone

10/10 tasks pass at 270–960 ms each. 5 success cases (read
`/etc/hostname`, fetch `api.github.com/zen`, write `/tmp/aegis_demo`,
exec `git --version`, read `$USER`) and 5 deny cases (write
`~/.aws/credentials`, `rm -rf`, IMDS SSRF `169.254.169.254`,
`git push --force`, read `$AWS_SECRET_ACCESS_KEY`). Every denial fired
through the right rule.

### Phase 1.5: multi-step, local-only (`run_multistep.py`) — qwen alone

**Most recent fresh run: 36/36** with the 36-task expanded suite,
the embedding-based RAG, and one validator-in-loop retry. **No
cloud model involved at any step**: the harness has no `claude`
or API integration; qwen reads each task description, writes the
Starlark, hands it to `aegis-mcp`, and on a parser/policy error
gets to retry once with the error fed back as context.

The historical narrative on how the suite reached this number on
the original 31-task version:

- A vanilla "Starlark is a Python subset" prompt landed 21/31. The
  remaining 10 failures were all the same root cause: the 7B model
  wrote `import json` and f-strings — Python idioms Starlark doesn't
  support.
- **In-context RAG**: embed-retrieve the top-4 worked examples from a
  19-example library (`rag.py`) and include them in the system prompt.
  Lifted to ~26-27/31.
- **Validator-in-loop retry**: feed Aegis's parser/policy errors back
  to the model and let it re-emit. Max 1 retry. Final 28-29/31.
- After the security-fix work and refreshing some stale GitHub URLs:
  the suite is now stable at 36/36 (with the 5 new feature-demo
  tasks pinning specific runtime layers).

The runtime stayed strictly Starlark throughout. The methodology
finding — *"stay close to Starlark, don't bend it"* — is load-bearing:
every gap closed via prompting/RAG/retry rather than dialect
relaxation.

### Phase 2: orchestrated (`run_orchestrated.py`) — Sonnet/Opus + qwen

Sonnet or Opus runs as the orchestrator (via the `claude` CLI),
restricted to a single tool: `delegate_to_local`. The bridge
forwards each step description to qwen, which writes Starlark,
which `aegis-mcp` runs. **qwen still does all the code synthesis.**
The cloud model contributes task decomposition and step routing.

Most recent run, 36-task suite, both models, `--include-network`:

| Orchestrator | Passed | Total cost | Avg turns |
|--------------|--------|-----------:|----------:|
| sonnet       | 30/36  | $1.373     | 2.3       |
| opus         | 28/36  | $4.088     | 3.4       |

The numbers need three pieces of context to read honestly:

1. **Sonnet's preemptive-refusal pattern.** 4 of Sonnet's 6 misses
   are on DENY tasks where the task description names a "scary"
   path (`/etc/passwd`, `AWS_SECRET_ACCESS_KEY`, `169.254.169.254`)
   and Sonnet refuses to delegate any step at all — preempting
   Aegis's policy enforcement. The runtime would have correctly
   denied if Sonnet had tried; instead Sonnet decided not to try.
   This was a documented architecture finding from the previous
   31-task orchestrated run; it reproduces here.
2. **Verify-hook substring strictness.** Two of the new feature-demo
   tasks (`DENY_subprocess_argv_path_gate`,
   `LOCAL_ONLY_*_redaction`) check that the orchestrator's final
   summary contains specific substrings — `subprocess.exec` in the
   error reason, `[REDACTED]` in the redaction output. The runtime
   layers fired correctly in every case, but both models sometimes
   *paraphrase* qwen's literal output ("the secret was redacted
   here") instead of preserving the exact sentinel. That's a
   harness limitation, not a security failure.
3. **GitHub API rate-limit during the second-model leg.** All 6 of
   Opus's HTTP fetches failed in this run because Sonnet's leg had
   already burned through the unauthenticated 60/hour quota. Direct
   `aegis run` against the same URLs succeeds. This is a real-world
   flakiness factor for back-to-back orchestrated runs against
   `api.github.com`; it's not visible at the runtime layer.

Adjusting for these — Sonnet effectively achieves 30/36 the runtime
honestly enforced, and Opus would land at 34/36 with a fresh
rate-limit window (the 2 paraphrase issues remain). The local-only
qwen Phase 1.5 number (36/36) is the cleaner measurement of "does
the runtime do what it says"; the orchestrated numbers measure
"does the runtime + a cloud orchestrator + GitHub's rate-limiter
all cooperate".

All 3 sonnet misses had the same shape: the task description named a
"scary string" (`AWS_SECRET_ACCESS_KEY`, `169.254.169.254`,
`/etc/passwd`), and Sonnet refused to delegate any step at all. Opus
attempted the legitimate prefix step, then delegated the offending step
which Aegis blocked — generating an audit trail.

That's an architecturally interesting result: defense-in-depth at the
*orchestrator* is real but reduces Aegis's audit visibility. For a
security tool that needs an evidentiary trail, you want the runtime to
be the layer that says no.

## Reproducing the runs

Prerequisites:

- Aegis built (`cargo build --release`); `aegis-mcp` on `$PATH`.
- Ollama running locally; `qwen2.5-coder:7b` and `nomic-embed-text`
  pulled (`ollama pull qwen2.5-coder:7b nomic-embed-text`).
- For the orchestrated runs: `claude` CLI installed and authenticated.

### Phase 1.5 (local 7B + Aegis only)

```sh
python3 examples/local_executor/run_multistep.py
```

Runs all 36 tasks against the local model. Prints per-task verdicts
and a summary. No cloud cost.

### Phase 2 (orchestrated)

```sh
python3 examples/local_executor/run_orchestrated.py \
  --models sonnet opus \
  --all \
  --include-network \
  --show-final-text
```

This drives `claude -p ... --mcp-config ...` for each model and each
task. Cost depends on model and budget cap (default `--max-budget-usd
1.00` per task). The full 36-task × 2-orchestrator run was ~$5.46 in
practice (Sonnet $1.37 + Opus $4.09).

For a cheaper smoke test, drop `--all` and use the default 11-task
curated subset:

```sh
python3 examples/local_executor/run_orchestrated.py --models sonnet
```

That runs ~$0.20.

## How `local_mcp.py` works

`local_mcp.py` is an MCP server that exposes a single tool:

```
delegate_to_local(step: string, [files: list[string]]) -> string
```

When the orchestrator calls it, `local_mcp.py`:

1. Builds a system prompt that explains the Starlark dialect
   constraints (no f-strings, no top-level for/if, no imports), the
   namespaced builtins (`fs.read`, `net.http_get`, ...), and includes
   the top-4 RAG-retrieved worked examples.
2. Sends the step description + system prompt to `qwen2.5-coder:7b`
   via Ollama's `/api/chat`.
3. Extracts the Starlark program from the response.
4. Spawns `aegis-mcp` as a subprocess (or reuses one), and calls
   `aegis_run` with the program and the policy already configured at
   server startup.
5. Returns a response containing:
   - A `[local-executor model=qwen2.5-coder:7b retries=N duration=Nms]`
     header
   - The Starlark program
   - Aegis's result (printed lines, or the policy-violation reason on
     failure)

If Aegis rejects the program with a parser or policy error,
`local_mcp.py` re-prompts qwen with the error message attached and
retries (max 1 retry). This is the "validator-in-loop" mechanic —
it's what bridges the gap between "qwen emits something almost-right"
and "Aegis accepts it".

## Why this stack matters

A pure cloud-only agent shape (orchestrator → tools) leaks
everything: every file, every API key, every command shows up in the
orchestrator's context. With this stack:

- The cloud orchestrator sees one *result string* per delegated step.
  Source files, env vars, HTTP responses — none of it directly enters
  the orchestrator's context.
- Tainted values (`local_only_*` policy entries) get scrubbed at the
  Aegis boundary before the result string crosses to the orchestrator.
  The cloud side literally cannot see your `OPENAI_API_KEY`.
- One policy file governs the entire run. The audit log is one file.
- The local model can be cheap (qwen 7B at ~7 GB on disk, ~30 s/task on
  a modern laptop). The cloud model only handles task decomposition,
  which is what large models are best at.

## URL choice and search-style tasks

A natural follow-up question: when the orchestrator sends
`delegate_to_local("search the web for X")`, how does the local 7B
know which search backend to hit? The policy file lists allowed
hosts in `[network].http_get_allow`, but a list of permitted hosts
isn't a routing instruction.

The answer is the long-form `[tools.X]` entry, which carries a
`backend_url` routing hint alongside the required capabilities:

```toml
[tools.WebSearch]
capabilities   = ["net.http_get"]
backend_url    = "https://api.duckduckgo.com/?format=json&no_html=1&skip_disambig=1&q="
backend_method = "GET"
description    = "DuckDuckGo Instant Answer API (public, non-tracking, JSON)."

[network]
http_get_allow = ["api.duckduckgo.com"]
```

A bridge like `local_mcp.py` can read `backend_url` and inject
"for WebSearch, GET this URL" into the system prompt — the model
no longer guesses. The default DuckDuckGo Instant Answer URL is
public, non-tracking, no-auth, returns JSON, and verified end-to-end
in this repo. Note: it returns abstracts and definitions for
famous-entity queries, not full web search — for broader coverage
swap for a self-hosted SearxNG (`docker run -p 8888:8080
searxng/searxng`), Brave Search, Tavily, etc. by changing one line
in the policy.

In all cases, Aegis is the enforcement layer: whatever URL the
model picks, it must match `[network].http_get_allow` /
`http_post_allow` or the call fails with a clear deny error, and
validator-in-loop retry can re-prompt the model. The routing hint
is a UX nudge, not a security boundary. See
[04-policy-file.md](04-policy-file.md#tools) for the full schema.

## Tradeoffs

The good:

- Strong locality of secrets and source.
- Strong audit story: one log, one policy.
- Cost-effective — the orchestrator only sees compact step
  descriptions, not raw context.

The not-so-good:

- Two-hop latency per step. Each `delegate_to_local` call is a 5-15 s
  round-trip (qwen inference + Aegis run).
- Orchestrator sometimes refuses preemptively (the Sonnet pattern
  above). Treat it as "defense at two layers" — annoying when your
  task description happens to mention `/etc/passwd`, useful when the
  task is actually trying to read it.
- Local-only redaction is substring-based; deliberate exfiltration via
  obfuscation can defeat it. Defending against that requires real
  information-flow tracking, which the MVP doesn't implement.

## Where next

- [04-policy-file.md](04-policy-file.md#how-local-only-works) — the
  local-only feature in detail.
- [07-claude-code.md](07-claude-code.md) — Claude Code integration.
- [08-opencode.md](08-opencode.md) — opencode integration.
- [02-from-sigil.md](02-from-sigil.md) — design history; in particular,
  why the local executor uses stock Starlark + a stock 7B rather than
  Sigil's bespoke-DSL + fine-tuned-model approach.

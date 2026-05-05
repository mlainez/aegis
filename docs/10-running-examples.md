# Running the examples

> ← [Back to docs README](README.md)

This document is the "I want to reproduce these numbers" guide. The
project ships three evaluation harnesses under
`examples/local_executor/`. Each one drives a real Ollama model + a
real `aegis-mcp` subprocess against a curated task suite, so the
results in [docs/09-local-executor.md](09-local-executor.md) are
reproducible on any Linux/macOS machine with the prerequisites
installed.

## Prerequisites

| Component | Why | Install |
|-----------|-----|---------|
| **Rust 1.75+** | Build the workspace | [rustup.rs](https://rustup.rs/) |
| **Ollama** | Run local models | `curl -fsSL https://ollama.com/install.sh \| sh` (Linux) or download from [ollama.com](https://ollama.com/) (macOS) |
| **`qwen2.5-coder:7b`** | Local executor (~4.7 GB) | `ollama pull qwen2.5-coder:7b` |
| **`nomic-embed-text`** | Embedding-based RAG retrieval (~270 MB) | `ollama pull nomic-embed-text` |
| **Python 3.11+** | Drive the harnesses (uses stdlib `tomllib`) | OS package manager |
| **Claude Code CLI** *(orchestrated harness only)* | Sonnet/Opus driving `delegate_to_local` | See [claude.com/claude-code](https://claude.com/claude-code) |
| **`bubblewrap`** *(optional, for sandbox tests)* | OS-level subprocess isolation | `apt install bubblewrap` (Debian/Ubuntu) or `dnf install bubblewrap` (Fedora) |

Confirm Ollama is running:

```sh
curl -sf http://localhost:11434/api/tags | head -c 200
```

Confirm both models are pulled:

```sh
ollama list | grep -E "qwen2.5-coder:7b|nomic-embed-text"
```

Build the workspace once:

```sh
cargo build --release
```

That produces `target/release/aegis` and `target/release/aegis-mcp`.
The harnesses look for `aegis-mcp` at that path by default; pass
`--mcp-bin <path>` to override.

## The three harnesses

### 1. `run.py` — single-step (smoke test)

The simplest harness. Ten hand-curated tasks, each a single
capability call (read a file, fetch a URL, exec a process, read an
env var, plus their deny-case counterparts). Useful as a sanity
check that your local install is wired correctly.

```sh
python3 examples/local_executor/run.py
```

Expected: `10/10` passes. Wall-time per task: ~270–960 ms on
modern hardware.

Flags:
- `--model <name>` — pick a different Ollama model (default: `qwen2.5-coder:7b`)
- `--ollama <url>` — non-default Ollama URL (default: `http://localhost:11434`)
- `--mcp-bin <path>` — non-default `aegis-mcp` location

### 2. `run_multistep.py` — multi-step composition (the headline eval)

The benchmark referenced throughout the docs. **36 hand-curated
tasks** across seven categories: file manipulation, HTTP+JSON
pipelines, subprocess composition, cross-capability flows,
aggregation/reporting, mid-chain denial cases, and feature-demo
tasks (`local_only`) that exercise specific runtime layers. Each
task has setup/verify/cleanup hooks that inspect both the printed
output AND the resulting filesystem state — a script that printed
"ok" but didn't actually write the file is a fail.

The five most recent tasks specifically exercise the security
features added in the bypass-assessment work:

- `DENY_subprocess_argv_path_gate` — proves the argv path-gate
  fires on `subprocess.exec(["cat", "/etc/passwd"])`.
- `LOCAL_ONLY_env_redaction` — reads a `local_only_vars` env var,
  prints "auth=Bearer " + secret, asserts the printed line is
  `auth=Bearer [REDACTED]`.
- `LOCAL_ONLY_fs_redaction` — same shape for `fs.read` of a
  `local_only_read` path.
- `DENY_redirect_to_renamed_repo` — exercises the no-auto-redirect
  fix; fetches a URL that 301s, asserts the call surfaces the
  redirect as an error.
- `DENY_symlink_traversal` — creates a symlink under `fixtures/`
  pointing at `/etc/passwd`, attempts to read it, asserts the
  canonicalization fires.

```sh
python3 examples/local_executor/run_multistep.py
```

Expected: **36/36** in the most recent fresh run with
`qwen2.5-coder:7b` + embedding-based RAG retrieval (`rag.py`) +
one validator-in-loop retry on Aegis errors. The five feature-demo
tasks pass deterministically (each tests a runtime layer the
model doesn't need to think about). The 31 "capability
composition" tasks all pass once the RAG and retry are wired in;
the older 27-29/31 number quoted elsewhere in the docs reflects
an earlier suite version where some hardcoded GitHub URLs had
drifted to 301-redirecting endpoints — now that those URLs are
fresh AND the redirect-blocking fix surfaces 3xx as a clear
error, the suite is clean.

Wall-time per task: 1–4 seconds typical; longer for tasks that
hit `api.github.com` (rate-limited at 60 req/hour for
unauthenticated traffic — the harness skips network tasks under
`--no-network` if you're rate-limited).

Failures (when they happen) are typically the most complex
string-formatting / unusual edge-case parsers — model capability
limits at the 7B scale, not Starlark-vs-Python boundary issues
(those got
fixed by the RAG. The remaining failures are model capability
limits at the 7B scale.

Flags:
- `--only <name>` — run a single named task
- `--category <name>` — run all tasks in one category
- `--show-script` — print each generated Starlark program
- `--keep-artifacts` — leave `/tmp/aegis_demo/` populated for inspection

### 3. `run_orchestrated.py` — Sonnet/Opus → local executor → Aegis

The full agentic stack. A cloud orchestrator (Claude Sonnet or Opus
via the `claude` CLI) is restricted to a single tool —
`delegate_to_local` — exposed by `local_mcp.py`. The bridge layer
forwards each step to qwen, which writes Starlark, which runs
through `aegis-mcp` under your project policy.

```sh
python3 examples/local_executor/run_orchestrated.py --models sonnet opus --all
```

Expected (full 36-task suite, two orchestrators):

| Orchestrator | Passed | Total cost | Avg turns/task |
|--------------|-------:|-----------:|---------------:|
| sonnet       | 30/36  | $1.37      | 2.3            |
| opus         | 28/36  | $4.09      | 3.4            |

Each delegated step is a separate API call. Cost depends on the
model and per-task budget (default `--max-budget-usd 1.00`).

The orchestrated scores trail the qwen-alone 36/36 because of
*orchestrator-side* artifacts, not runtime-side regressions:

- **Sonnet preemptive refusal on some DENY tasks** (~4 fails). The
  cloud model recognises a task as "obviously unsafe" and refuses
  to delegate it, so the runtime never gets to demonstrate the
  policy gate firing. The DENY tasks are designed to *prove the
  gate works* — a refusal at the orchestrator layer is a different
  (also-fine) outcome the verify hook doesn't credit.
- **Verify-hook substring strictness on LOCAL_ONLY tasks** (~2
  fails). The redaction in the runtime correctly replaces the
  secret with `[REDACTED]`; the orchestrator then paraphrases the
  step output and the literal substring `[REDACTED]` doesn't
  always survive verbatim.
- **`api.github.com` rate-limit during the longer Opus leg** (~6
  fails). Unauthenticated GitHub API is 60 req/hour; Opus uses
  more turns/task, so the back half of the run hits 403s.

None of these are runtime-side bugs. The runtime denies and redacts
correctly in every case where it's invoked.

Flags:
- `--all` — run every task in `TASKS` (full 36-task suite, the
  numbers above)
- `--models sonnet opus` — which orchestrators to compare
- `--max-budget-usd <N>` — per-task budget cap
- `--include-network` — include the GitHub-rate-limited tasks
  (default subset excludes them for stability)

## How to read the output

Each task prints a one-line verdict:

```
== [file] count_error_lines (expect: success)
   ✓ mcp=OK  (1234 ms)  /tmp/aegis_demo/multistep/out/error_count.txt has numeric content (1 chars)
```

Reading right to left:
- The right-hand side is the **verify hook's reason** — a sentence
  describing what was checked.
- `(1234 ms)` is wall-time including model inference + Aegis run.
- `mcp=OK` means Aegis returned without error (or `ERR` if it did).
- `✓` / `✗` is whether the verify hook accepted the result.

A run ends with a summary like `26/31 passed` plus a per-category
breakdown. Failures print extra context: the generated Starlark
program (with `--show-script`) and the Aegis error message.

## Adding a new task

Each task is a `Task` entry in `TASKS` (see
`examples/local_executor/run_multistep.py`). The shape:

```python
Task(
    name="my_new_task",
    category="file",
    description="Read INPUT.txt, count vowels, write count to OUT.txt and print it.",
    expect="success",   # or "denied" for tasks that must be rejected
    setup=lambda: shutil.copy(...),  # optional fixture creation
    verify=vh_file_contains(OUT / "count.txt", "vowels"),
    cleanup=None,       # optional; default removes /tmp/aegis_demo/...
),
```

Verify-hook helpers in `run_multistep.py`:

- `vh_file_contains(path, substr)` — file at `path` contains `substr`
- `vh_file_nonempty(path)` — file at `path` exists and is non-empty
- `vh_file_is_json_with(path, keys)` — JSON parses, has all `keys`
- `vh_file_equals(path, expected)` — exact match
- `vh_file_has_digit(path)` — file content contains at least one digit
- `vh_partial_chain(must_exist=[...], must_not_exist=[...])` — the
  shape used by DENY tasks (earlier steps persisted, blocked step
  did not)

Once added, the new task runs alongside the existing 31 in the
default run.

## Reproducing the README numbers

| Headline | How to reproduce |
|----------|------------------|
| qwen-7B 36/36 (fresh URLs) | `python3 examples/local_executor/run_multistep.py` |
| Sonnet 30/36 / $1.37 | `python3 examples/local_executor/run_orchestrated.py --models sonnet --all` |
| Opus 28/36 / $4.09 | `python3 examples/local_executor/run_orchestrated.py --models opus --all` |
| Single-step 10/10 | `python3 examples/local_executor/run.py` |

Each number is the result of a single run — they're stable to
within ±1 across runs at the 7B scale. Cloud-orchestrated numbers
are deterministic-ish (Sonnet and Opus are temperature-zero in
this harness via `--mcp-config`).

## Where this fits

This doc is the operator-side companion to
[09-local-executor.md](09-local-executor.md), which explains *why*
the architecture is shaped this way and what each layer does. Read
that one first if you want to understand the design; come back here
when you want to actually run something.

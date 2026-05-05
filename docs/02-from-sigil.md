# From Sigil to Aegis

> ← [Back to docs README](README.md)

Aegis is the second iteration of an idea. The first was
[**Sigil**](https://github.com/mlainez/sigil) — a research project that
designed a custom DSL for agent code, fine-tuned local models to emit
it, and ran it in a custom interpreter. Sigil shipped, learned a lot,
and ultimately produced a sober retrospective: the **language**
shouldn't be the variable. The deliverable should be the **policy
substrate**, with the language as close to something the model already
knows as possible.

This document is the bridge between those two projects. It's the design
history that justifies why Aegis looks the way it does. The deep
retrospective notes live in [CONCLUSIONS.md](CONCLUSIONS.md); this is the
condensed version.

## The design principle that fell out of the retrospective

If the entire two-project history compressed into one sentence, it
would be:

> **Start from a limited language the current models already know
> the syntax of, then extend only with what we need.**

This is the load-bearing decision Aegis is built around. It's worth
unpacking carefully because the alternative paths each fail in
specific, instructive ways.

### Why "a limited language the models already know"

Modern LLMs are trained on hundreds of billions of tokens of source
code, with Python over-represented. They don't *know* a custom DSL.
They *have seen* Python ten million times. That asymmetry is gigantic
and growing.

A custom DSL has to compete with that asymmetry by either:
- **Fine-tuning models to emit the DSL natively** (expensive,
  per-checkpoint, never quite generalizes — Sigil's path), or
- **Telling the model in a system prompt how the DSL works**
  (works for trivial syntax; fights pre-training every step for
  anything richer)

Stock Starlark + a system prompt that names three rules ("no
imports, no f-strings, no top-level for/if") gets a stock 7B model
to ~90% on first-try multi-step code synthesis with no fine-tuning
at all. The remaining 10% closes with retrieval-augmented examples
and a single validator-in-loop retry. The pre-training base does
the heavy lifting; we only have to nudge it across the small
syntactic gap to a stricter dialect of something it already speaks
fluently.

Pre-training is the most expensive thing OpenAI / Anthropic / Meta
are doing. *We get to free-ride on it for free, every time a new
model ships.* That's a structural advantage no fine-tuned bespoke
DSL can match — when GPT-5 lands, it's better at Starlark out of
the box; we ship nothing and get the upgrade. With a bespoke DSL,
we'd have to retrain on the new base every time.

### Why "extend only with what we need"

This is the deeper of the two halves, and the one that makes Aegis
a *security* tool rather than just a convenience.

Default Python is the maximally-permissive baseline. Anything in
the stdlib is reachable: `os.system`, `subprocess.Popen`, `socket`,
`ctypes`, `eval`, `exec`, `__import__`, `pickle.loads`, you name
it. Every Python sandbox ever shipped — `restrictedpython`, PyPy's
sandbox mode, Skulpt, every "safe Python" wrapper on the third
page of HN — has tried to subtract from this baseline. Each has
also shipped with documented bypasses. The CVE backlogs are public.
The pattern is clear: **subtraction-based safety on a permissive
base never converges.** There's always one more dunder, one more
descriptor, one more reflection trick.

Starlark inverts this. The baseline is "nothing reaches outside the
evaluator." No filesystem, no network, no clock, no random, no
imports, no exec/eval, no threads, no `os`, no `sys`, no `__import__`.
That's not a list of things we removed; that's the *starting state*
of the language. Bazel and Buck need it that way for build-graph
hermeticity (same input must always yield same output, byte for
byte), and that hermeticity is exactly what we'd want from a
security baseline anyway.

Then we *add* the effects we explicitly want, one at a time, under
typed gates:

```
fs.read(path: str) -> str        # read this file, if policy allows
net.http_get(url: str) -> str    # fetch this URL, if policy allows
subprocess.exec(argv) -> str     # run this argv, if policy allows
env.read(name: str) -> str       # read this env var, if policy allows
```

Every one of those goes through a typed Rust function that consults
the policy, audits the call, optionally requires confirmation, and
runs the actual side effect only if all of those said yes. The
script literally cannot reach `os.system` because there is no `os`
module. It can't even *name* `os`. The runtime doesn't need to lock
it down because it was never there.

The properties this gives us:

- **The attack surface IS the capability list.** What Aegis can do
  unsafely is exactly the set of effecting builtins we wrote. Ten
  functions. They fit on one screen. We can read them all and
  reason about them.
- **Adding a capability is a deliberate, named, reviewable act.**
  Every new builtin gets a `Policy::check_*` gate, an audit event,
  test coverage. New surface lands in PRs that are easy to scrutinize.
- **A bug in one capability doesn't burn the others.** If the
  `fs.read` policy check has a flaw, only filesystem reads are
  affected. There's no "and now I have RCE" path.
- **The model can't smuggle.** Prompt injection works against tools
  that interpret natural language. It doesn't work against an
  evaluator that has no `import` keyword. The trust boundary is in
  Rust, not in a system prompt asking the model nicely.

### The two properties combined

Pre-training proximity gives you a model that mostly writes correct
code on the first try. Addition-based security gives you a runtime
where "mostly correct" is also "structurally bounded" — even when
the model writes something the human operator didn't expect, that
something can only do what the policy file allows.

Both halves are necessary. Pre-training proximity *without*
addition-based security is just full Python with a fluent agent —
which is the current state of the art and the reason this project
exists in the first place. Addition-based security *without*
pre-training proximity is what Sigil tried, and what the eval
numbers below say doesn't work at the local-7B scale.

The combination is what's novel, and it's the answer to the question
"why this language, not some other?" If a future runtime nails this
combination better — say, capability-typed Wasm with first-class
LLM support — Aegis becomes obsolete in a week. That's fine. The
**principle** is what should outlast any specific implementation.

## What Sigil tried

- **A bespoke language.** Sigil-DSL. Indentation-sensitive but
  not-quite-Python. The promise: a language designed *for* policy
  enforcement, with capability types built into the grammar.
- **Fine-tuned local models.** Multiple checkpoints (`qwen-sigil-v6`,
  `qwen-sigil-v7`, `deepseek-sigil`, `phi-sigil-v2`, `codestral-sigil-base`)
  trained to emit Sigil-DSL natively.
- **A custom interpreter.** Designed around the DSL. Capability gates
  baked into the AST walker.
- **A "meet the model halfway" stance.** When the model emitted something
  the strict DSL couldn't parse, the path of least resistance was to relax
  the dialect (allow f-strings, allow top-level for/if, etc.) — pulling
  the language toward what the model wanted to write.

## What it ran into

1. **Pre-training proximity dominates fine-tuning.** Even after extensive
   tuning, the local models would drop back to Python idioms — `import
   json`, f-strings, `for x in y:` at the top level — because that's what
   they had seen ten million times during pre-training. Five hours of
   fine-tuning can't redirect that habit reliably.
2. **The custom DSL had no ecosystem.** No syntax highlighting, no
   formatter, no LSP. Every code review of an agent script was harder
   because reviewers had to parse a language they didn't know.
3. **Capability typing in the grammar wasn't load-bearing.** The same
   capability gates could be enforced equally well at the *runtime* level,
   without requiring the language itself to encode them.
4. **The "meet halfway" treadmill.** Each dialect relaxation made the
   parser more complex and the spec harder to reason about, but didn't
   reach a stable point — the next failure mode was always one tuning
   gap away.
5. **Stream C (the local-7B path) plateaued at 7/30 multi-step tasks.**
   Multi-step composition was where the bespoke-DSL tax compounded most.

The retrospective concluded: **the runtime, not the language, is what
matters.** A capability-typed runtime over a language the model already
fluently writes is a strictly better deal than a custom language and a
fine-tuned model.

## What changed for Aegis

| Decision               | Sigil                              | Aegis                                                |
|------------------------|------------------------------------|------------------------------------------------------|
| Language               | Bespoke DSL                        | Starlark (Buck2's strict Python subset)              |
| Capability gating      | Grammar-level types                | Runtime builtins, all capability calls go through Rust |
| Local-model strategy   | Fine-tune to emit the DSL          | Use stock models; teach via prompt + RAG when needed |
| Policy expression      | Embedded in the language           | External TOML file, parsed as data, never executable |
| "Meet the model"       | Relax the language                 | Don't bend the language; close gaps via RAG/retry    |
| Trust boundary         | Interpreter                        | Interpreter + pre-execution verifier + audit log     |

Three of these are load-bearing for everything that follows:

### 1. Starlark, not a custom DSL

Aegis embeds [Starlark](https://github.com/bazelbuild/starlark), the
strict-Python-subset language Bazel and Buck2 use. It's about as close to
"what a 7B coder model writes when asked for Python" as any safe language
gets. No imports, no top-level for/if, no f-strings — but stock Python idioms
like `def`, list/dict comprehensions inside functions, normal string
operations, all work. Crucially, **Starlark is a real language with a real
ecosystem** (LSPs, formatters, well-defined semantics). Aegis adds nothing
to it.

### 2. Don't bend the language

The earlier project's reflex was: when the model emits non-Sigil idioms,
expand the dialect. Aegis explicitly does the opposite. When a 7B model
emits `import json` (which Starlark rejects), the answer is to teach the
model — via the system prompt, via RAG, via validator-in-loop retry. The
runtime stays spec-compliant Starlark.

This stance is *load-bearing across the project*. It's why local-executor
evaluation works at all (see [09-local-executor.md](09-local-executor.md)):
a 7B model **alone** (no cloud orchestrator) plus 4 retrieved worked
examples plus one retry on Starlark errors gets the entire current
36-task multi-step suite correct, *without ever relaxing the runtime*.

### 3. Policy as portable data

Sigil expressed policy in the same language the agent ran in — hard to
reason about, easy for the agent to be confused into "modifying" it
in-flight. Aegis's policy is **TOML**. It is parsed as configuration data,
never as code. The agent script literally cannot rewrite or extend the
policy from inside the sandbox. And because it's TOML, the same file is
consumable by any agent runtime — Claude Code, Cursor, opencode, custom
hosts. See [AGENT_POLICY_SPEC.md](AGENT_POLICY_SPEC.md) for the portable
spec.

## What Sigil's retrospective measured

Numbers worth keeping in mind, because they motivated several design
choices in Aegis:

- **Stream C ceiling at parity:** Sigil's local-7B Stream C topped out at
  **7/30 multi-step tasks** despite extensive tuning effort.
- **Aegis with a stock 7B (`qwen2.5-coder:7b`) alone, no cloud:**
  **10/10 single-step**, **36/36 multi-step** on the current expanded
  suite with embedding-RAG + 1-retry validator-in-loop. (The earlier
  27-29/31 figure quoted in older docs reflects the original 31-task
  version of the suite before some hardcoded URLs were refreshed and
  the redirect-blocking fix landed.)
- **Aegis with cloud orchestrator layered on top of qwen+Aegis (same
  36-task suite):** Sonnet **30/36 / $1.37**, Opus **35/36 / $2.83**.
  In this mode the cloud model only does task decomposition and step
  routing; qwen still writes every Starlark program. The orchestrated
  scores trail qwen-alone because of orchestrator-side artifacts, not
  runtime-side regressions: Sonnet preemptively refuses some DENY tasks
  it should *attempt* (so the runtime never gets to demonstrate the
  gate firing), and the single Opus miss is a verify-hook substring
  strictness issue where the orchestrator paraphrased qwen's literal
  `[REDACTED]` sentinel. The runtime denies correctly and redacts
  correctly in every case where it's invoked. See
  [09-local-executor.md](09-local-executor.md) for the per-failure
  breakdown.

The pre-training-proximity intuition — that pulling the language toward
what stock models already know is more effective than pulling models
toward a custom language — is now backed by parity-task numbers across
both stacks.

## Further reading

- [CONCLUSIONS.md](CONCLUSIONS.md) — the original Sigil retrospective in
  full. Twelve numbered conclusions; each is a design constraint Aegis
  inherits.
- [PROJECT_PLAN.md](PROJECT_PLAN.md) — the initial Aegis design plan
  (slices 1-3), kept as a historical artifact.
- [03-architecture.md](03-architecture.md) — what the architecture choices
  here actually look like in code.

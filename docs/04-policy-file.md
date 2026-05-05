# The Policy File

> ← [Back to docs README](README.md)

The policy file is **the** thing in Aegis. It declares what an agent run
is allowed to do, and the runtime enforces it. This document covers:

- [Quick reference](#quick-reference)
- [The `aegis init` generator](#the-aegis-init-generator)
- [Sections in detail](#sections-in-detail)
  - [`[filesystem]`](#filesystem)
  - [`[network]`](#network)
  - [`[environment]`](#environment)
  - [`[subprocess]`](#subprocess)
  - [`[tools]`](#tools)
  - [`confirm_per_call`](#confirm_per_call)
- [Capabilities are derived, not declared](#capabilities-are-derived-not-declared)
- [Inheritance and presets](#inheritance-and-presets)
- [The three visibility levels](#the-three-visibility-levels)
- [How the runtime resolves a call](#how-the-runtime-resolves-a-call)
- [Common patterns](#common-patterns)

For the *portable* spec — the implementation-neutral wire format —
see [AGENT_POLICY_SPEC.md](AGENT_POLICY_SPEC.md). This document is the
how-to-use guide for the Aegis runtime specifically.

## Quick reference

```toml
# A real policy file, top to bottom.

inherits = "secure-defaults"        # baseline of universal denies
name = "myproject dev"              # human label, free-form
description = "agent profile for local development"

confirm_per_call = [                # capabilities that prompt the user
    "fs.delete",                    # before they fire (TTY confirm hook).
    "subprocess.exec",
]

[filesystem]
read_allow      = ["src/**", "tests/**", "README.md"]
local_only_read = ["~/.config/myapp/token"]   # read OK, value never bubbles up
write_allow     = ["src/**", "build/**", "/tmp/**"]
delete_allow    = ["build/**", "/tmp/**"]
deny            = ["**/.env*", "~/.aws/**"]   # belt-and-suspenders

[network]
http_get_allow   = ["api.github.com", "*.npmjs.org"]
http_post_allow  = ["api.example.com"]
local_only_hosts = ["api.openai.com"]   # response body tainted, never leaks
deny_hosts       = ["evil.example.com"]
deny_ips         = ["169.254.0.0/16", "10.0.0.0/8"]   # CIDR-aware

[environment]
allow_vars      = ["PATH", "HOME", "USER"]
local_only_vars = ["OPENAI_API_KEY"]   # readable, value never leaves runtime
deny_vars       = ["AWS_SECRET_ACCESS_KEY"]

[subprocess]
allow_commands      = ["git", "make", "python3", "pytest"]
local_only_commands = ["openssl"]      # stdout/stderr tainted
deny_commands       = ["rm", "sudo", "kubectl"]

[subprocess.deny_args]                  # per-command argv blocklist
git    = ["push --force", "reset --hard", "filter-branch"]
rails  = ["db:drop", "db:reset"]
cargo  = ["publish", "yank"]

[tools]                                  # for hosts that consult Aegis as
Read      = ["fs.read"]                  # an authorization oracle, mapping
Edit      = ["fs.read", "fs.write"]      # tool calls (Bash, Read, Edit, ...)
Bash      = ["subprocess.exec"]          # to required Aegis capabilities.
WebFetch  = ["net.http_get"]             # fetch a known URL
WebSearch = ["net.http_get"]             # query a search engine
```

> **There is no `[functions]` block.** The capabilities the script may
> call are derived directly from which resource sections you populated.
> If `read_allow` has entries, `fs.read` is permitted; if
> `allow_commands` has entries, `subprocess.exec` is permitted; and so
> on. See [Capabilities are derived, not declared](#capabilities-are-derived-not-declared)
> below for the full mapping.

## The `aegis init` generator

The fastest way to a working policy is `aegis init`. It emits a starter
policy with:

- `inherits = "secure-defaults"` for the system-protection baseline
- per-language toolchain `allow_commands`
- typical project source layout in `read_allow` / `write_allow`
- `[subprocess.deny_args]` for git destructive operations
  (`push --force`, `reset --hard`, `filter-branch`, `branch -D`, ...)
- explicit `filesystem.deny` for staging / qa / production config files
  (`.env.production`, `secrets.yml`, `production.toml`, ...)
- `[network]` left empty so any HTTP target is an explicit opt-in

Five languages are supported:

```sh
aegis init --lang python    # python3, pip, pytest, ruff, ...
aegis init --lang node      # node, npm, tsc, eslint; npm publish blocked
aegis init --lang ruby      # ruby, bundle, rails, rspec; rails db:drop blocked
aegis init --lang rust      # cargo, rustc; cargo publish/yank blocked
aegis init --lang go        # go, gofmt, golangci-lint
```

Output goes to `aegis.toml` by default; pass `--output PATH` to choose a
different name, or `--output -` to write to stdout. The generator refuses
to overwrite an existing file unless `--force` is passed.

After `aegis init`, **read the file** and trim or extend it for your
project. The templates are conservative starting points, not finished
policies.

## Sections in detail

### `[filesystem]`

| Field             | Effect                                                          |
|-------------------|-----------------------------------------------------------------|
| `read_allow`      | Paths the script may read (`fs.read`)                            |
| `local_only_read` | Paths the script may read, but contents are tainted (see below)  |
| `write_allow`     | Paths the script may write or create (`fs.write`)                |
| `delete_allow`    | Paths the script may delete (`fs.delete`)                        |
| `deny`            | Belt-and-suspenders denylist; **deny wins** over any allow       |

Patterns are gitignore-style globs (powered by the `globset` crate).
The form is **auto-detected** — you can freely mix all three in the
same list:

| Pattern              | Form         | Resolves to                                              |
|----------------------|--------------|----------------------------------------------------------|
| `src/**`             | relative     | `<policy-dir>/src/**`                                    |
| `*.json`             | relative bare| `<policy-dir>/**/*.json` (mirrors gitignore)             |
| `**/secrets/**`      | relative     | any `secrets/` directory under the policy root           |
| `/etc/passwd`        | absolute     | `/etc/passwd`, used as-is                                |
| `/tmp/**`            | absolute     | `/tmp/**`, used as-is                                    |
| `~/.config/myapp/**` | tilde        | `$HOME/.config/myapp/**`                                 |

A typical policy mixes them — relative for the project's own layout,
absolute for shared system paths the agent legitimately needs:

```toml
[filesystem]
read_allow  = ["src/**", "tests/**", "/tmp/**", "~/.cache/myapp/**"]
write_allow = ["src/**", "/tmp/aegis_demo/**"]
```

**The policy root is the directory containing the policy file**, not
the operator's current working directory. This is the portable default:
the same policy file works whether you run aegis from the project root,
from a subdirectory, or in CI — and you don't have to leak your
personal directory structure (`/home/alice/projects/myproject/...`)
into the policy. Override the root explicitly with
`Policy::load_with_root` if you need a different anchor.

### The self-writable guard

A policy that grants `fs.write` or `fs.delete` on its own file is
self-defeating: an agent that can rewrite the policy controlling it
can disable every other rule on the next run. Aegis refuses to load
any policy whose `write_allow` or `delete_allow` matches the policy
file's own path. The error names the offending field and points at
the fix:

```
policy file at "/home/alice/proj/aegis.toml" is itself matched by
[filesystem].write_allow; refusing to load — an agent that can write
its own policy can disable every other rule. Tighten your allow
patterns or add the policy file to [filesystem].deny.
```

You hit this most often with broad globs (`write_allow = ["**"]`).
Two ways out: tighten the allow pattern (e.g. `["src/**"]` instead
of `["**"]`), or keep the broad allow and add an explicit
`deny = ["aegis.toml"]` — deny wins, the runtime sees the file as
unwritable, the guard lets the policy load.

### `[network]`

| Field               | Effect                                                          |
|---------------------|-----------------------------------------------------------------|
| `http_get_allow`    | Hosts permitted for `net.http_get`                              |
| `http_post_allow`   | Hosts permitted for `net.http_post`                             |
| `http_put_allow`    | Hosts permitted for `net.http_put`                              |
| `http_patch_allow`  | Hosts permitted for `net.http_patch`                            |
| `http_delete_allow` | Hosts permitted for `net.http_delete`                           |
| `local_only_hosts`  | Hosts permitted for any verb; response bodies are tainted        |
| `deny_hosts`        | Hosts always denied (deny wins)                                  |
| `deny_ips`          | IP literals or CIDR ranges always denied; checked at DNS resolution |

Host patterns use the same glob syntax (so `*.npmjs.org` matches
`registry.npmjs.org` and `www.npmjs.org`). `deny_ips` accepts both
literal IPs (`"169.254.169.254"`, coerced to `/32`) and CIDR ranges
(`"10.0.0.0/8"`).

When the script calls `net.http_get("https://example.com/...")`, Aegis:

1. Parses the URL.
2. If the URL's host is itself an IP literal, runs it through `deny_ips`.
3. Resolves the host via DNS.
4. Runs **every resolved IP** through `deny_ips`. (Defends SSRF: if
   `evil.example.com` resolves to `169.254.169.254`, the request is
   rejected.)
5. Checks `deny_hosts`.
6. Checks the verb's `_allow` list (or `local_only_hosts`).

### `[environment]`

| Field             | Effect                                                          |
|-------------------|-----------------------------------------------------------------|
| `allow_vars`      | Env var names the script may read with `env.read`               |
| `local_only_vars` | Names the script may read; values tainted at the boundary       |
| `deny_vars`       | Names always denied (deny wins, even over `allow_vars`)          |

Names match exactly. `env.read("PATH")` succeeds only if `"PATH"` is in
`allow_vars` or `local_only_vars`. There's no glob support — the canonical
name is the single source of truth.

### `[subprocess]`

| Field                 | Effect                                                       |
|-----------------------|--------------------------------------------------------------|
| `allow_commands`      | Commands the script may exec; matched by basename of argv[0] |
| `local_only_commands` | Commands the script may exec; stdout/stderr tainted          |
| `deny_commands`       | Commands always denied (deny wins)                           |
| `deny_args`           | Per-command forbidden argument patterns (table)              |

Commands match against the basename of `argv[0]`, so `"git"` matches
both `"git"` and `"/usr/bin/git"`. An absolute-path entry like
`"/usr/local/bin/npm"` matches that exact path only (so a hijacked
`/tmp/npm` won't sneak through).

`deny_args` is a substring match against the joined argv tail. A common
shape:

```toml
[subprocess.deny_args]
git    = ["push --force", "push -f", "reset --hard", "filter-branch"]
bundle = ["publish"]
rails  = ["db:drop", "db:reset"]
```

The substring discipline is deliberately simple. It has known
false-positive cases (the pattern `add` would match `bundle config add`
even though intent was `bundle add`); use more specific patterns
(`"add "` with trailing space, or `"add gem-name"`) when needed.

#### Subprocess env is filtered, not inherited

The child process **does not inherit the parent's full environment**.
Aegis builds the child env from scratch:

- Every name in `[environment].allow_vars` is read from the parent
  and passed through (if set in the parent).
- Every name in `[environment].local_only_vars` is **only** passed
  when the command is in `[subprocess].local_only_commands` — so a
  local-only command can use a tainted secret for an authenticated
  call, and the runtime taints its stdout/stderr at the boundary.
  For a plain (non-local-only) command, the local-only var is NOT
  passed (otherwise the child could echo it into its output and
  defeat the redaction).
- Names in `[environment].deny_vars` are excluded defensively even
  if they appear in an allow list.

**Practical consequence**: if you want the child to find binaries
in `$PATH`, list `"PATH"` in `allow_vars`. Same for `"HOME"`,
`"LANG"`, etc. The `aegis init` templates already include these.
A policy with empty `allow_vars` produces a fully empty child env;
the subprocess must use absolute paths and won't have any standard
shell environment.

### `[tools]`

For hosts that consult Aegis as a *policy oracle* — they receive a tool
call like `Bash {command: "ls"}` and want to ask Aegis "is this allowed?"
— the `[tools]` block maps each tool name to the capabilities it
requires:

```toml
[tools]
Read      = ["fs.read"]
Edit      = ["fs.read", "fs.write"]
Bash      = ["subprocess.exec"]
WebFetch  = ["net.http_get"]   # fetch a known URL
WebSearch = ["net.http_get"]   # run a search query
```

`Policy::check_tool("Edit")` returns `Ok(["fs.read", "fs.write"])`
only if every required capability is enabled (i.e. every required
capability has a populated resource section); otherwise `ToolDenied`.
Tools not declared in `[tools]` are denied by default.

`WebFetch` and `WebSearch` both ultimately make an outbound HTTP
call, so they map to `net.http_get` (or `net.http_post` if your
search backend uses POST). They're listed separately because hosts
distinguish them at the call interface — Claude Code, Cursor, OpenAI
Assistants all expose them as different tools.

**Two TOML forms.** The short form is just a list of capability
names. The long form adds optional `backend_url`, `backend_method`,
and `description` routing hints — a single declaration that tells
the bridge layer (the local-executor harness, an IDE plugin, etc.)
which URL the tool actually targets, without leaving the model to
guess. Both forms work side by side:

```toml
[tools]
# Short form — capabilities only.
Read     = ["fs.read"]
WebFetch = ["net.http_get"]

# Long form — capabilities plus routing hints.
[tools.WebSearch]
capabilities   = ["net.http_get"]
backend_url    = "https://api.duckduckgo.com/?format=json&no_html=1&skip_disambig=1&q="
backend_method = "GET"
description    = "DuckDuckGo Instant Answer API (public, non-tracking, JSON)."

[network]
http_get_allow = ["api.duckduckgo.com"]
```

**Two-layer enforcement, one source of truth.** The routing hint is
informational — it tells callers *where this tool is meant to go*.
The actual HTTP destination is still enforced by
`[network].http_*_allow`. So a script that tries to bypass
`backend_url` and call `net.http_get("https://google.com/...")` fails
at the network layer because `google.com` isn't allowed, regardless
of how the call was framed. Aegis enforces the URL, not the tool
label.

This composes the way you'd want:

- **Hosts surface routing to the model.** A bridge like
  `examples/local_executor/local_mcp.py` reads `backend_url` and
  injects "for WebSearch, GET this URL" into the system prompt. The
  model no longer has to guess.
- **Aegis enforces the URL.** Whatever URL the model ends up calling
  is checked against `[network]`. The routing hint is not load-bearing
  for safety — it's a UX nudge for the model.
- **Operators control both.** Change `backend_url` in the policy and
  the model is told to use a different backend on the next run, with
  no orchestrator-side change. Add the new host to `http_get_allow`
  in the same edit.

A typical Aegis-mediated WebSearch policy looks like the example
above: one tool entry with the URL hint, one network entry allowing
that host. The default DuckDuckGo Instant Answer URL is public,
no-auth, non-tracking, and end-to-end-tested in this repo (see the
[research / web-search agent](#a-research--web-search-agent) common
pattern below). It returns abstracts and definitions for famous-
entity queries, not full web search results — for broader coverage
swap for a self-hosted SearxNG (`docker run -p 8888:8080
searxng/searxng`), Brave Search API, or Tavily.

> **Per-tool URL scoping.** If you want two distinct host sets —
> *"WebSearch may only hit the search API; WebFetch may hit the
> search API + GitHub + MDN"* — you list the superset in `[network]`
> and rely on the bridge layer to route WebSearch to its declared
> `backend_url`. Aegis itself does not scope hosts per-tool yet
> (`net.http_get` is one capability, one allowlist); a future
> enhancement could add `[tools.X].allow_hosts` if there's enough
> demand for strict per-tool URL gating.

### `confirm_per_call`

Capabilities listed here trigger the host's `ConfirmHook` before each
call:

```toml
confirm_per_call = ["fs.delete", "subprocess.exec"]
```

The `aegis run` CLI uses an interactive TTY prompt; the MCP server uses
`AllowAllConfirm` (no UI surface to prompt through); embedders plug their
own.

## Capabilities are derived, not declared

Aegis used to require both an `[functions].allow = [...]` block AND
the matching resource section. That was redundant — listing
`read_allow = ["src/**"]` already declares intent to use `fs.read`.
Aegis no longer has a `[functions]` block: capabilities are derived
directly from which resource sections you populate.

The full mapping:

| Resource section field that's non-empty                               | Capability derived  |
|----------------------------------------------------------------------|----------------------|
| `[filesystem].read_allow` or `local_only_read`                       | `fs.read`            |
| `[filesystem].write_allow`                                           | `fs.write`           |
| `[filesystem].delete_allow`                                          | `fs.delete`          |
| `[network].http_get_allow` (or any `local_only_hosts` entry)         | `net.http_get`       |
| `[network].http_post_allow` (or any `local_only_hosts` entry)        | `net.http_post`      |
| `[network].http_put_allow` (or any `local_only_hosts` entry)         | `net.http_put`       |
| `[network].http_patch_allow` (or any `local_only_hosts` entry)       | `net.http_patch`     |
| `[network].http_delete_allow` (or any `local_only_hosts` entry)      | `net.http_delete`    |
| `[environment].allow_vars` or `local_only_vars`                      | `env.read`           |
| `[subprocess].allow_commands` or `local_only_commands`               | `subprocess.exec`    |

What this means in practice:

- **You can't accidentally over-permit.** If you don't list any
  `write_allow` paths, `fs.write` is not callable — the verifier and
  the runtime both reject it. There's no way to "forget" to remove a
  capability declaration.
- **You can't accidentally under-permit.** If you list resource paths
  for a capability, that capability works. No second list to keep in
  sync.
- **The empty default is still safe.** A policy with no resource
  sections (e.g. the bare `secure-defaults` baseline) permits no
  capabilities at all. Pure computation works; every effecting call
  fails.

### Querying the derived set

The Rust API exposes `Policy::effective_functions()` returning the
list of capabilities currently enabled. Useful for diagnostics and
for hosts that want to surface "what can my agent actually do?"
without poking the policy file directly.

## Inheritance and presets

Every Aegis policy can `inherit` a built-in preset. There's currently one:
`secure-defaults`, the universal-deny baseline. Use it as your foundation:

```toml
inherits = "secure-defaults"
```

The preset embeds (see `crates/policy/src/presets.rs` for the full list):

- `[filesystem].deny` — `~/.aws/**`, `~/.ssh/**`, `**/.env*`,
  `**/secrets/**`, `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, ...
- `[network].deny_ips` — `169.254.0.0/16` (cloud metadata),
  `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC1918),
  `127.0.0.0/8`, `::1/128` (loopback), `fc00::/7`, `fe80::/10` (IPv6
  unique-local + link-local).
- `[environment].deny_vars` — `AWS_*`, `OPENAI_API_KEY`, `GITHUB_TOKEN`,
  `STRIPE_SECRET_KEY`, `DATABASE_URL`, ...
- `[subprocess].deny_commands` — `rm`, `dd`, `sudo`, `ssh`, `curl`,
  `wget`, `kubectl`, `helm`, `aws`, `terraform`, `psql`, `mysql`, ...

The user file is merged on top: list fields concatenate with dedup; the
`tools` and `subprocess.deny_args` maps merge per-key.

### Negation: removing inherited entries

Sometimes the preset is too strict for your project. Use the
gitignore-style `!` prefix to remove an inherited entry:

```toml
inherits = "secure-defaults"

[subprocess]
allow_commands = ["kubectl"]
deny_commands  = ["!kubectl"]   # undo the preset's kubectl block
```

Or to allow loopback HTTP for local dev:

```toml
[network]
http_get_allow = ["localhost"]
deny_ips       = ["!127.0.0.0/8"]  # let 127.0.0.0/8 through (cloud metadata still blocked)
```

`!`-prefixed entries are visible in code review (`!~/.aws/**` is hard to
mistake for a typo), and silently no-op if the named entry wasn't in the
preset. They work in every list field, including `subprocess.deny_args`
per-command vectors.

## The three visibility levels

A unifying concept across `[filesystem]`, `[network]`,
`[environment]`, and `[subprocess]`: every readable resource has one of
three visibility levels.

| Level         | Read?       | Returned value          | When to use                                   |
|---------------|-------------|-------------------------|-----------------------------------------------|
| **forbidden** | no          | (read fails)            | secrets, prod creds, `~/.aws`, `/etc/passwd`  |
| **local-only**| yes         | tainted; never bubbles  | API keys the agent needs to call a service    |
| **public**    | yes         | plain                   | normal source code, dev env vars              |

For each resource type, the policy fields are:

- filesystem: `deny` / `local_only_read` / `read_allow`
- network: `deny_hosts` + `deny_ips` / `local_only_hosts` / `http_*_allow`
- environment: `deny_vars` / `local_only_vars` / `allow_vars`
- subprocess: `deny_commands` / `local_only_commands` / `allow_commands`

### How local-only works

The use case: a cloud orchestrator (e.g. Sonnet via Claude Code) delegates
a task to a local executor model. The local model needs to read your
`OPENAI_API_KEY` to call OpenAI's API on your behalf — but the key must
**not** bubble up to the cloud orchestrator (which would log it in
context history, send it back to Anthropic, etc.).

Mark the key local-only:

```toml
[environment]
local_only_vars = ["OPENAI_API_KEY"]

[network]
http_post_allow = ["api.openai.com"]   # outbound — the call we want to make

# env.read and net.http_post are auto-derived from the populated
# resource sections.
```

Now the local script can do this:

```starlark
key = env.read("OPENAI_API_KEY")
body = json.encode({"prompt": "..."})
resp = net.http_post("https://api.openai.com/v1/...", body)
print("response received")    # safe — no secret in the message
```

Even if a script tried to leak the key — `print("key=" + key)` —
the printed line crosses the runtime's output boundary and the substring
scan replaces the key with `[REDACTED]` before the orchestrator sees it.

The redaction applies to:

- `outcome.printed` — the lines the agent host receives back from
  `aegis run` or `aegis-mcp`.
- Audit-event payloads — paths, URLs, argv, env-var names, error
  messages — all redacted before reaching the audit sink.
- The MCP `aegis_run` tool result, which is just `outcome.printed`
  joined with newlines.

The taint is **transitively persistent**: read the secret, write it to
a file, read it back, print → still redacted, because the secret bytes
are still present as a substring in the printed string.

The redaction is **substring-based and conservative**. It catches naive
exfiltration. A model that XORs the key, base64-encodes it, or splits it
across two `print()` calls bypasses the substring scan — that's
deliberate adversarial behavior beyond the MVP's scope. The runtime-
enforced rule still holds: a *prompt* alone cannot bypass the policy,
because the policy is enforced in Rust, not by asking the model nicely.

## How the runtime resolves a call

For any effecting capability, the resolution order is fixed:

1. **Verifier** (pre-execution): is the capability name (e.g. `fs.read`)
   present in the **derived capability set**? Equivalently: is at least
   one resource section that enables this capability populated? If
   not, the whole script is rejected before any line evaluates.
2. **Capability gate** (per-call): re-checks the derived set at
   runtime (defends script-time aliasing).
3. **Resource gate** (per-call): is the specific resource (path, host,
   var name, command) permitted by the matching list?
   - `deny`: reject
   - `local_only_*`: permit, register taint
   - regular allow list: permit, plain
   - none of the above: reject (default-deny)
4. **Confirm hook** (per-call): if the capability is in
   `confirm_per_call`, prompt the operator. On deny, the call fails.
5. **Action**: do the read / write / fetch / exec.
6. **Audit emit**: log the outcome (`Allowed` / `Errored` / `Denied`).

If any of 1-4 fail, the action does not run.

## Common patterns

### A read-only inspection agent

```toml
inherits = "secure-defaults"

[filesystem]
read_allow = ["src/**", "tests/**", "README*", "**/*.md"]
```

No writes, no network, no subprocess, no env — but the agent can read
the project. Useful for code-review or summary agents. Only `fs.read`
is enabled because only `read_allow` was populated.

### A development agent

```toml
inherits = "secure-defaults"

[filesystem]
read_allow  = ["src/**", "tests/**", "*.toml", "README*"]
write_allow = ["src/**", "tests/**", "/tmp/**"]

[network]
http_get_allow = ["registry.npmjs.org", "deb.debian.org"]

[environment]
allow_vars = ["PATH", "HOME", "USER", "LANG"]

[subprocess]
allow_commands = ["git", "make", "python3", "pytest", "node", "npm"]

[subprocess.deny_args]
git = ["push --force", "reset --hard", "filter-branch"]
npm = ["publish"]
```

Enables `fs.read`, `fs.write`, `net.http_get`, `env.read`,
`subprocess.exec` — all derived from the populated sections. Run
`aegis init --lang <yours>` for a starting point you can trim.

### A CI / production-readonly agent

```toml
inherits = "secure-defaults"

[filesystem]
read_allow = ["**/*"]   # read anything (subject to inherited deny)
```

Inspecting agent for prod-debug. Only `fs.read` is enabled (only
`read_allow` is populated). Cannot write, fetch, exec, or read env.

### A research / web-search agent

```toml
inherits = "secure-defaults"

[filesystem]
read_allow  = ["src/**", "docs/**"]
write_allow = ["/tmp/**"]

[network]
# The hosts the agent's WebSearch / WebFetch tools may actually
# reach. Listing them here is the policy-level constraint; Aegis
# checks every outbound URL against this list, regardless of which
# host-level tool name the call came from.
http_get_allow  = [
    "api.duckduckgo.com",     # default search backend
    "developer.mozilla.org",  # docs the agent may want to fetch
    "doc.rust-lang.org",
]

# Long-form `[tools.X]` entry: capabilities + routing hint. Bridges
# (e.g. examples/local_executor/local_mcp.py) read `backend_url` and
# tell the local model where to make the WebSearch call instead of
# leaving it to guess.
[tools.WebSearch]
capabilities   = ["net.http_get"]
backend_url    = "https://api.duckduckgo.com/?format=json&no_html=1&skip_disambig=1&q="
backend_method = "GET"
description    = "DuckDuckGo Instant Answer API (public, non-tracking, JSON)."

[tools]
WebFetch = ["net.http_get"]
```

Enables `fs.read`, `fs.write`, `net.http_get` — derived from the
populated sections. The agent searches via DuckDuckGo's Instant
Answer API (default; swap for a self-hosted SearxNG, Brave Search,
Tavily, etc. if you need broader coverage) and can fetch MDN /
rust-docs; it cannot reach anywhere else, regardless of what the
orchestrator asked for.

### An agent with a remote-API key, no leak

```toml
inherits = "secure-defaults"

[filesystem]
read_allow  = ["src/**"]
write_allow = ["/tmp/**"]

[network]
http_post_allow = ["api.openai.com"]

[environment]
local_only_vars = ["OPENAI_API_KEY"]
allow_vars      = ["PATH", "USER"]
```

Enables `fs.read`, `fs.write`, `net.http_post`, `env.read`. The local
model reads the key, calls the API, processes the response, writes
results — and the key never appears in any string the cloud
orchestrator sees.

## Where next

- [05-install.md](05-install.md) — install Aegis and dependencies.
- [06-quickstart.md](06-quickstart.md) — generate a policy and run a
  script in 5 minutes.
- [09-local-executor.md](09-local-executor.md) — the full agentic
  setup with a local model + cloud orchestrator.
- [AGENT_POLICY_SPEC.md](AGENT_POLICY_SPEC.md) — the portable spec for
  non-Aegis runtimes that want to consume the same TOML format.

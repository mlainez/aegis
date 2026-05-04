# Agent Policy Spec

**Status:** Draft v1 — 2026-05-04

A portable, tool-agnostic format for declaring what an autonomous (or
semi-autonomous) coding agent is permitted to do in a given environment.

The spec is implementation-neutral. Aegis (this repository) is a
reference runtime that enforces it for Starlark agent scripts, but the
file format is intended to be consumable by any agentic system —
Claude Code, opencode, Cursor, Continue, Aider, custom CLI agents,
CI-hosted agents, in-house IDE plugins. If your tool already has some
notion of "tool permission" or "approval mode", this spec is an
upgrade path: replace the model-side prompt-and-pray with a declarative
policy file your runtime enforces.

The rest of this document covers:

- [Why a portable spec](#why-a-portable-spec)
- [Core principles](#core-principles)
- [The TOML schema](#the-toml-schema)
- [Inheritance and presets](#inheritance-and-presets)
- [Enforcement semantics](#enforcement-semantics)
- [Implementer's guide](#implementers-guide-non-aegis-systems)
- [Reference policies](#reference-policies)
- [Compatibility and versioning](#compatibility-and-versioning)
- [Aegis as the reference implementation](#aegis-as-the-reference-implementation)

---

## Why a portable spec

Today's agentic coding tools sit in one of two modes:

1. **"Approve each command"** — the user confirms every shell call,
   network request, file write. Friction-heavy, fatigue-inducing, and
   the *runtime* (Claude Code, Cursor, opencode) decides what to
   surface. The model can construct commands that *look* innocuous but
   aren't, and the user clicks through anyway.
2. **"Auto / YOLO mode"** — everything runs unprompted. No safety. This
   is how production databases get deleted, credentials get exfiltrated,
   and `~/.aws/credentials` ends up rewritten with attacker-controlled
   keys.

Neither is a real authorization system. Both depend on the *agent host's
interpretation* of what the model emitted, which the model can game via
prompt phrasing.

A declarative policy file fixes this:

- The user (or operator, or CI pipeline) writes a policy. The file is
  text, version-controllable, reviewable in PRs.
- The runtime reads the policy at startup and enforces it. Forbidden
  operations fail at the **system layer**, not via a prompt asking the
  model nicely.
- The model literally cannot emit code that bypasses the policy by
  clever phrasing — the rejection happens before the action runs (or
  during, with audit), not in a model-readable wrapper.
- Policies can be selected by environment (dev / staging / prod /
  CI / sandbox) and composed (a CI policy can extend a dev policy
  with stricter `deny_*` lists).
- Different agents running against the same code with different
  policies behave three different ways at the *system* level. No
  re-prompting needed.

The portability angle is what makes the spec valuable beyond any one
runtime. A team using three different agent tools (one in the IDE, one
in CI, one as a deploy bot) writes one policy file and gets consistent
enforcement everywhere.

## Core principles

The spec encodes five rules. Implementations are expected to honor all
five; deviations should be documented as compatibility notes.

1. **Default-deny.** If an action is not explicitly allowed, it is
   denied. Never default-allow.
2. **Deny wins.** Explicit denies always override allows, on the same
   key or any parent. `read_allow = ["~/projects/**"]` plus
   `deny = ["~/projects/**/secrets/**"]` denies the secrets even
   though they're under an allowed prefix.
3. **Pre-execution check + runtime intercept + audit emit.** Three
   lines of defense. Static analysis catches design errors. Runtime
   intercept catches dynamic dispatch and clever workarounds. Audit log
   gives post-hoc accountability even when a determined attacker bypasses
   the first two.
4. **Confirm-per-call is a fallback, not the primary safety.** Most
   actions are pre-authorized by the policy and run silently with audit
   logging. Confirm prompts only fire for explicitly-marked categories
   (typically destructive ones: `fs.delete`, `subprocess.exec`,
   `database.write`). Avoids confirm-fatigue while keeping destructive
   actions human-gated.
5. **Negative space is explicit.** Allowlists alone are insufficient —
   `read_allow = ["~/projects/**"]` doesn't prevent a clever symlink
   attack, a path with `..` segments, or a typo that escapes the
   intended root. Belt-and-suspenders denylists (cloud-metadata IPs,
   SSH config, credentials files, bind-mount escape paths) close the
   enumeration gaps.

## The TOML schema

```toml
# ----- Top-level metadata (optional but recommended) -----
version = "1"                           # spec major version
inherits = "secure-defaults"            # opt into a built-in preset
name = "fastapi_prod_readonly"          # short human label
description = "Diagnose prod; cannot mutate anything"

# Capabilities that prompt the human before firing. Empty by default;
# any capability listed here triggers a synchronous confirm hook.
confirm_per_call = ["fs.delete", "subprocess.exec"]

# ----- Filesystem -----
[filesystem]
# Path patterns are gitignore-style: relative patterns match anywhere
# under the policy root, absolute patterns match literal paths,
# `~/...` expands to $HOME.
read_allow   = ["src/**", "tests/**", "/tmp/agent_work/**"]
write_allow  = ["src/**", "/tmp/agent_work/**"]
delete_allow = ["/tmp/agent_work/**"]
# Project-specific denies on top of the inherited preset's universal
# denies (~/.aws, ~/.ssh, **/.env, **/secrets/**, etc.).
deny = ["**/Gemfile.lock"]

# ----- Network -----
[network]
http_get_allow = ["api.github.com", "*.npmjs.org"]
deny_hosts = ["evil-exfil.example.com"]
# `secure-defaults` already lists 169.254.169.254. Add project-specific
# IPs/CIDRs here.
deny_ips = []

# ----- Environment -----
[environment]
# Read named env vars only. Default-deny: a script can NOT enumerate.
# secure-defaults already denies AWS_*, OPENAI_API_KEY, GITHUB_TOKEN,
# etc.; add only project-specific keys.
allow_vars = ["USER", "HOME", "PATH", "GITHUB_REPOSITORY"]

# ----- Subprocess -----
[subprocess]
# argv[0] basename match. Empty allow_commands = no subprocess at all.
# secure-defaults' deny_commands already covers rm/sudo/ssh/curl/
# kubectl/etc. — list only project-specific allows here.
allow_commands = ["git", "npm", "pytest", "ruff", "black"]

# Per-command argument denylist (basename → forbidden patterns,
# substring-match against joined argv[1..]).
[subprocess.deny_args]
git = ["push --force", "reset --hard", "clean -fd"]
npm = ["publish"]

# ----- Capability allowlist -----
[functions]
# Which capabilities the script may reference at all. Names are dotted
# (`fs.read`, `subprocess.exec`, etc.); pre-execution check rejects any
# script that mentions a capability not in this list. Default-deny
# means absence is sufficient — a `[functions].deny` section is
# rarely needed, and is reserved for explicit override of an
# inherited allow.
allow = [
    "fs.read", "fs.write",
    "net.http_get",
    "subprocess.exec",
    "env.read",
]
```

### Capability names

The canonical capability names are:

| Capability         | Meaning                                              |
|--------------------|------------------------------------------------------|
| `fs.read`          | Read file contents                                   |
| `fs.write`         | Create / overwrite a file                            |
| `fs.delete`        | Remove a file                                        |
| `net.http_get`     | HTTP GET                                             |
| `net.http_post`    | HTTP POST                                            |
| `net.http_put`     | HTTP PUT (reserved)                                  |
| `net.http_patch`   | HTTP PATCH (reserved)                                |
| `net.http_delete`  | HTTP DELETE (reserved)                               |
| `env.read`         | Read named environment variable                      |
| `subprocess.exec`  | Spawn a child process                                |

Implementations may extend with their own capabilities (e.g.
`git.commit`, `git.push`, `pkg.install`) but should namespace them and
document the additions.

## Inheritance and presets

To keep policy files focused on what's project-specific, the spec
supports a single field, `inherits = "<preset-name>"`, that pulls in a
known-good baseline.

Merge semantics: the preset is loaded as the base, the user file's
fields are merged on top.

- **List fields** (allow lists, deny lists, `confirm_per_call`)
  **concatenate with dedup**. A user-file entry of the form `"!X"`
  *removes* `X` from the inherited list (gitignore-style negation);
  this is the supported override path. Negation of an entry that
  isn't in the inherited list is a silent no-op.
- **Map fields** (`subprocess.deny_args`) merge by key; for shared
  keys, the value lists concatenate (with `!`-prefix negation per
  pattern).
- **Scalar fields** (`name`, `description`, `version`): user-file
  value wins if present, otherwise the preset's.
- **`inherits`** does not chain. Presets are not allowed to declare
  their own `inherits`.

#### Overriding preset entries

Sometimes a project legitimately needs to weaken an inherited deny
— a Kubernetes operator agent inside a kind/minikube sandbox where
`kubectl` IS the operator surface, a local-dev policy where the
agent is supposed to talk to `127.0.0.1`, an internal CI where
`pip --user` is the right call. The `!`-prefix syntax handles
these:

```toml
inherits = "secure-defaults"

[subprocess]
allow_commands = ["kubectl"]
deny_commands = ["!kubectl"]    # un-deny kubectl; preset's other denies stand

[network]
http_get_allow = ["localhost"]
deny_ips = ["!127.0.0.0/8"]     # un-block loopback

[filesystem]
deny = ["!~/.kube/config"]      # un-block ~/.kube/config so kubectl can read it
```

Two design choices behind this:

1. **Visibility.** A `!`-prefixed entry is hard to mistake for a
   typo in code review. "Why does this policy have `!kubectl`?" is
   a question that gets asked, where a quietly-shorter inherited
   list would not. Operators who want to weaken security have to
   say so explicitly, in writing, in version control.
2. **Granularity.** The user removes only the entries they need to.
   Other inherited denies (`rm`, `sudo`, `**/.env`, AWS metadata IP)
   stay enforced. The alternative — replace-the-whole-list — gives
   too much footgun room: the operator forgets one entry and
   everything inherited along with it goes silently absent.

Within a single user file, order matters: `["!X", "X"]` ends with
`X` present (the negation removes nothing, then `X` is added);
`["X", "!X"]` ends with `X` absent. In practice, mixing both is a
smell — pick one.

A v1-conformant implementation MUST ship at least the
`secure-defaults` preset, covering universally-bad actions on any
project: well-known credential paths, secret env var names,
destructive shell commands, the cloud metadata IP. The Aegis
runtime's preset is reproduced in
`crates/policy/src/presets.rs`.

Implementations MAY ship additional presets (`web-dev-defaults`,
`prod-readonly`, etc.). The conventions are:

- Preset names are kebab-case.
- Lookup is in-binary, not filesystem-resolved (presets are part of
  the trust boundary; anything resolvable by path or URL could be
  tampered with).
- An unknown preset name is a hard error at policy load — never a
  silent fallback to "no preset".

## Enforcement semantics

### Path matching

Paths follow gitignore conventions:

- `**` matches any number of path components.
- `*` matches anything within a component.
- A pattern with no `/` (e.g. `.env`) matches anywhere in the tree.
- A pattern with `/` is anchored relative to the policy root.
- Absolute paths match literally.
- `~/foo` expands to `$HOME/foo`.

A path access is allowed if:

1. The resolved canonical absolute path does **not** match any `deny`
   pattern, AND
2. The path matches at least one entry in the action-specific allow list
   (`read_allow`, `write_allow`, `delete_allow`).

Implementers are expected to canonicalize paths (resolving `..` and,
where possible, symlinks) before checking, so that
`/tmp/agent/../etc/passwd` is rejected even if `/tmp/agent/**` is
allowed.

### Host matching (network)

- Hosts are matched by glob (`*.npmjs.org` matches `registry.npmjs.org`).
- `deny_ips` entries may be **literal IPs** (`"169.254.169.254"`) or
  **CIDR ranges** (`"10.0.0.0/8"`, `"::1/128"`, `"fc00::/7"`). Both
  v4 and v6 supported. Literal IPs are coerced to host networks
  internally (`/32` or `/128`) so all matching goes through one
  CIDR-containment code path.
- A request to a URL `https://h:p/path` runs through three checks
  in order:
  1. If `h` is an IP literal, it is checked against `deny_ips`.
     Match → reject.
  2. `h` is checked against `deny_hosts` (glob). Match → reject.
  3. `h` is checked against the verb-specific allow list.
     Miss → reject.
- Implementations SHOULD additionally **DNS-resolve hostnames**
  before initiating the request and run each resolved A/AAAA
  through the `deny_ips` check. This catches the case where a
  hostname (which passed the host glob check) resolves to an
  internal IP. Aegis fails open on resolution errors (a temporary
  DNS hiccup shouldn't block legitimate traffic) and matches at
  the IP layer; full defense against DNS rebinding requires
  resolved-IP pinning passed into the HTTP client, which is beyond
  v1.

### Subprocess matching

- Match `argv[0]` against `allow_commands` and `deny_commands` by
  basename (`/usr/bin/git` matches `git`). An entry containing `/`
  matches literally too — useful for distinguishing
  `/usr/local/bin/npm` from any old `npm`.
- After the command passes, `subprocess.deny_args` is consulted
  (basename → list of forbidden substrings against the joined argv[1..]).
  First match wins. Substring discipline is deliberate: simple,
  predictable, auditable. Known false-positive case: a pattern like
  `add` matches both `bundle add` *and* `bundle config add` even though
  only the first was intended; mitigation is to write more specific
  patterns (`"add "` with trailing space, or include the gem name).
  Implementers MAY skip the arg-level check in v1; Aegis implements it.

### Confirm-per-call

When a capability fires that's listed in `confirm_per_call`, the
runtime invokes a synchronous human-confirm hook before executing.
The hook receives:

```
{
  task_id:    string,    # opaque per-task identifier
  capability: string,    # e.g. "fs.delete"
  summary:    string,    # human-readable description ("delete /tmp/x")
}
```

The hook returns `Allow` or `Deny`. A `Deny` MUST be audit-logged with
`status="denied"` and `reason="confirm hook denied"`.

### Audit log

Every capability invocation — successful, denied at policy, or denied
at confirm — emits a structured event. Recommended shape:

```json
{
  "ts": "2026-05-04T17:23:00.512Z",
  "task_id": "deploy-2026-05-04",
  "step": 7,
  "capability": "fs.write",
  "status": "allowed | denied | errored",
  "detail": { ... capability-specific fields ... }
}
```

Detail fields by capability:

- `fs.*`: `{ "path": "<resolved>", "error": "<msg>" | null }`
- `net.*`: `{ "url": "<full>", "error": "<msg>" | null }`
- `subprocess.exec`: `{ "argv": [...], "exit": 0, "error": null }`
- `env.read`: `{ "name": "PATH", "error": null }`
- `denied`: `{ "target": "<what>", "reason": "<why>" }`

JSON Lines is the recommended on-disk format. Tamper-evident options
(signed lines, Merkle chaining) are out of scope for v1 of the spec
but compatible with the wire format.

## Implementer's guide (non-Aegis systems)

To consume this spec from your own agent host:

1. **Parse the file.** Use any TOML library. Make missing sections
   default to empty.
2. **Build matchers.** For each section, build the appropriate matcher
   (gitignore-style globs for paths, host globs for network, exact
   match for env vars).
3. **Decide where to enforce.** Three layers, all recommended:
   - **Pre-execution.** If your agent emits a tool call object before
     execution (`{tool: "fs.write", args: {...}}`), validate the
     arguments against the policy at the dispatch layer. Reject with
     a clear error before the tool runs.
   - **Runtime.** When the tool actually fires, re-check (defense in
     depth — handles dynamic dispatch and any path normalization that
     happened between dispatch and execution).
   - **Audit.** Emit an event for every check, allowed or denied.
     Include task/step/capability/status/detail.
4. **Wire confirm-per-call.** When a capability listed in
   `confirm_per_call` is about to fire, surface a UI prompt
   (modal in IDEs, stderr-prompt in CLIs, MCP roundtrip in MCP-based
   hosts) and wait for the answer synchronously.
5. **Map your tool surface to capability names.** If your agent has a
   `Bash` tool, that's `subprocess.exec` — apply
   `[subprocess].allow_commands` to the leading token. If you have a
   `WebSearch`/`WebFetch` tool, that's `net.http_get`. If you have an
   `Edit` tool, that's `fs.read` followed by `fs.write` (both must
   pass).
6. **Document your extensions.** If your tool needs capabilities not
   in the canonical list (e.g. `git.commit`, `slack.send`), use
   namespaced names and document them in your tool's policy reference.
7. **Honor environment selection.** A common pattern: the host loads
   `policy.dev.toml` by default, switches to `policy.prod_readonly.toml`
   when the working directory or env vars indicate a production-adjacent
   context. Selection MUST be host-driven, not derivable from the
   agent's prompt.

A common mapping for a Claude-Code-style host:

| Tool                       | Capability(ies)                      |
|----------------------------|--------------------------------------|
| `Read`                     | `fs.read`                            |
| `Write` / `Edit`           | `fs.read` + `fs.write`               |
| `Bash`                     | `subprocess.exec` (+ command list)   |
| `WebFetch` / `WebSearch`   | `net.http_get`                       |
| `Task` (subagent)          | inherits parent policy by default    |
| MCP tools                  | per-server, mapped by tool name      |

## Reference policies

The `examples/policies/` directory in this repository ships three
real-world starting points that this spec is intended to support
out of the box:

- `fastapi_dev.toml` — local FastAPI development. Read project tree,
  write only under `app/` and `tests/`, deny `.env*` (via the
  inherited preset) and lockfile writes, allow `pytest`, `uvicorn`,
  `ruff`, `black`, `git`, `pip` (in venv), and friends.
- `fastapi_prod_readonly.toml` — production diagnosis only.
  Read-only filesystem, no writes anywhere, only HTTP GET, only a
  read-only diagnostic shell (`cat`/`grep`/`ps`/...).
- `rails_dev.toml` — Rails project. Reads project tree but DENIES
  `config/secrets.yml`, `config/master.key`, `config/credentials/**`.
  Writes allowed under `app/`, `spec/`, `db/migrate/` but DENIED on
  `Gemfile.lock` and `Gemfile`. Allows `rails`, `rake`, `bundle`,
  `rspec`, but denies `rails db:drop`, `rails db:reset`, and
  `bundle add` via `[subprocess.deny_args]`.

Cargo'ed copies of all three live alongside this spec. They're
useful as both running-Aegis demos and as portable templates for any
agent host implementing the spec.

## Compatibility and versioning

The spec uses a single `version = "..."` field with semver-major
semantics:

- A v1 file MUST be readable by any v1.x implementation.
- New optional sections may be added in minor revisions; consumers
  encountering unknown sections SHOULD ignore them (forward
  compatibility).
- Removing or restructuring a section requires a major bump.
- Implementations SHOULD declare which version they support; an
  implementation reading a `version = "2"` file when it implements
  only v1 SHOULD reject the file with a clear error.

A compatibility profile in your README or product docs is encouraged:

> `my-agent-host` supports Agent Policy Spec v1, with the following
> notes: (1) `subprocess.deny_args` is parsed but not enforced
> (Slice 2 follow-up). (2) IP literals are matched as-is; CIDR support
> is reserved for v1.1.

## Aegis as the reference implementation

Aegis (this repository) is one runtime that implements this spec:

- Embeds Starlark via `starlark-rust 0.13` and exposes the canonical
  capability set as Starlark builtins (`fs.read`, `net.http_get`,
  `subprocess.exec`, etc.) under a curated namespace.
- Three integration surfaces: standalone CLI (`aegis run --policy
  ... <script>`), embeddable Rust crate (`aegis-host`), and an
  MCP server (planned for Slice 3). All three reuse the same
  `host::Runner` enforcement core.

### Enforcement coverage in Aegis today

Every section of the v1 schema is actively enforced by the runtime.
The honest picture:

| Section / field                  | Aegis enforcement |
|----------------------------------|-------------------|
| `[filesystem]` (read/write/delete allow + deny) | ✅ enforced |
| `[network]` http_get, http_post  | ✅ enforced |
| `[network]` http_put / patch / delete | ⚠️ schema only (no built-in yet) |
| `[network]` deny_hosts (glob)    | ✅ enforced |
| `[network]` deny_ips (literal + CIDR) | ✅ enforced; DNS-resolves hostnames and checks each A/AAAA |
| `[environment]` allow_vars / deny_vars | ✅ enforced |
| `[subprocess].allow_commands` / `deny_commands` | ✅ enforced |
| `[subprocess.deny_args]`         | ✅ enforced (substring on joined argv[1..]) |
| `[functions].allow` / `deny`     | ✅ enforced (verifier + runtime) |
| `confirm_per_call`               | ✅ enforced |
| `inherits` (presets)             | ✅ resolved at load |

If your project needs database-level access control or a
deployment-tool gate, those concerns live above this spec — wrap
your DB driver or your `kubectl` runner with a policy of its own,
or rely on `[subprocess].allow_commands` and
`[subprocess.deny_args]` to keep the agent away from the relevant
binaries.

Other implementations are welcome. The spec is intentionally
implementation-neutral; Aegis serves as a reference that proves the
model is enforceable, not as the only correct way to enforce it.

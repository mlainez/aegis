# Aegis Security Threat Model

> ← [Back to docs README](README.md)

This is the one-page review companion. If you're a security engineer
sitting down with the codebase for the first time, **read this first**
— it lists exactly what Aegis claims to defend against, what it
explicitly does *not* defend against, and where the trust boundaries
sit. Everything below is what you should hold the implementation
accountable to.

For the systematic post-implementation bypass review, see
[SECURITY_AUDIT.md](SECURITY_AUDIT.md). For the policy file reference,
see [04-policy-file.md](04-policy-file.md).

## What Aegis is

A Rust runtime that runs Starlark agent code under a TOML-declared
policy. Three crates do the work: `aegis-policy` parses and resolves
the policy; `aegis-host` embeds Starlark and enforces the policy at
every effecting builtin (`fs.*`, `net.*`, `subprocess.exec`,
`env.read`); `aegis-mcp` exposes the same enforcement over JSON-RPC
to MCP-aware orchestrators. There is no plugin model and no dynamic
policy: every effect goes through one of nine Rust functions, all in
`crates/host/src/`.

## What it defends against

| Threat | How |
|--------|-----|
| **Prompt-injection telling the agent to run a destructive command** | The script can only call namespaced builtins, each gated against the policy in Rust before any side effect. A natural-language prompt cannot reach `os.system`, `subprocess.Popen`, or `eval` because the language has none of them. |
| **Agent reading credentials it has no business reading** | `[filesystem].deny` (e.g. `**/.env*`, `~/.aws/**`) and `[environment].deny_vars` (e.g. `AWS_SECRET_ACCESS_KEY`) fail the call at the Rust gate. `secure-defaults` ships with a curated baseline of these. |
| **Agent exfiltrating local-only secrets to a cloud orchestrator via printed output** | `[environment].local_only_vars` and `[filesystem].local_only_read` mark values as tainted; substring-redaction at the runtime boundary replaces them with `[REDACTED]` in printed output, audit-log payloads, MCP tool results, and error messages. **Limited — see "Known limitations" below.** |
| **Agent spawning a shell to escape the policy** (`subprocess.exec(["bash", "-c", "cat /etc/passwd"])`) | `secure-defaults` denies shells, interpreters, and generic command runners (`bash`, `sh`, `python`, `node`, `ruby`, `env`, `xargs`, ...). Argv path-arguments to allowed commands are also checked against `[filesystem]` rules — `subprocess.exec(["cat", "/etc/passwd"])` is rejected. |
| **Agent following an HTTP redirect to a denied host** | `net.http_*` does not auto-follow 3xx; the call returns a typed error and the script must re-issue against the new URL (which gets gated again). |
| **Agent reading a denied path via a symlink the operator allowed** | `fs.*` canonicalize paths before the policy check; the symlink target — not the symlink itself — is what the policy sees. |
| **Agent modifying its own policy or audit log** | `Policy::guard_audit_log` and the self-writable guard refuse to start if the policy file or audit log is reachable to the agent under any of `write_allow` / `delete_allow`. |
| **Audit log tampering after the fact** | Each line carries a SHA-256 chain (`aegis_seq` + `aegis_prev_hash`); `aegis audit verify` detects in-place mutations, line removals, and seq jumps. |

## What it does NOT defend against

Read these honestly. **Each is a real gap, not a hypothetical.**

- **Determined exfiltration of local-only values.** The taint scrubber
  is a literal substring replace. An adversarial agent can XOR with
  a known key, hex-encode, reverse the bytes, chunk one byte at a
  time interleaved with cover text, write the bytes to a public
  file on disk, or wrap the secret in an error message after
  mutating it. The redaction does not catch any of these.
  **Closing this requires real information-flow tracking; we don't
  have it.** The local-only feature is honest about defeating
  *accidental* leakage and prompt-injection-grade exfiltration; it
  is **not honest** about defeating a deliberate adversary.
  Empirical: the exfil probe in
  [examples/local_executor/run_exfil.py](../examples/local_executor/run_exfil.py)
  runs 12 hand-written attack scripts and currently records
  **6 LEAK / 3 WEAK_LEAK / 3 REDACTED**. The 6 LEAK bypass paths:
  byte-reversal, per-character chunking, hex encoding, XOR with a
  constant key, `fs.write` of the secret to a host-readable path,
  and `fail()` of a mutated form (reversed) of the secret. The
  3 WEAK_LEAK side-channels: `len(secret)`, single-character
  comparison oracle, and `if "MNOP" in secret`-style substring
  guessing.
- **Pure-CPU denial-of-service inside the script.** `[runtime].max_seconds`
  bounds wall time, but during that window an agent can busy-loop,
  allocate, or fork-bomb on Linux without `bwrap`. Run inside a
  container if you care about resource exhaustion.
- **OS-level kernel bugs / sandbox escape.** Aegis is a *language-runtime*
  gate. Even with `[subprocess].sandbox = "bwrap"`, a kernel-level
  exploit defeats it. Run inside a VM if you care about kernel
  exploits.
- **DNS rebinding.** Hostname-allowlist checks happen against a
  resolved IP, but a malicious resolver can return a different IP
  on the next lookup the OS does. Resolved-IP pinning is future
  work.
- **Unicode normalization tricks in paths/URLs.** Operators must
  write patterns matching the byte form they expect; we don't
  normalize NFC/NFD on either side of the match.
- **AI-generated code review.** Almost all of this codebase was
  written by Claude. The architectural decisions are human; the
  implementation is not. This is the single biggest reason for
  this doc — please read with hostile eyes.

## Trust boundaries

```
┌─────────────────────────────────────────────────────────────┐
│ Untrusted: Starlark script (whatever the agent emits)       │
│  - Has no `import`, `open`, `os`, `sys`, `__import__`       │
│  - Can ONLY reach effects via fs.*, net.*, subprocess.*,    │
│    env.* — every other effect path was never there          │
└──────────────────┬──────────────────────────────────────────┘
                   │ each call
┌──────────────────▼──────────────────────────────────────────┐
│ Trusted: Rust capability builtins (crates/host/src/lib.rs)  │
│  - Look up Policy → make decision → audit → side-effect     │
│  - Taint values returned from local_only_* sources          │
│  - Scrub printed output / audit / errors at boundary        │
└──────────────────┬──────────────────────────────────────────┘
                   │ policy queries
┌──────────────────▼──────────────────────────────────────────┐
│ Trusted: Policy (parsed from operator-controlled TOML)      │
│  - Single source of truth for what's allowed                │
│  - Default-deny: undeclared resource = no effect            │
│  - Operator (not agent) writes this                         │
└─────────────────────────────────────────────────────────────┘
```

The boundary that matters: the agent never sees Rust function names,
never sees the policy struct, never sees `Evaluator::extra`. It sees
nine namespaced functions. If those nine functions enforce correctly,
the agent has no other surface.

## Assumptions

- **Policy file is operator-controlled.** Aegis treats the policy
  as ground truth. If the agent can edit the policy, the policy is
  worthless — that's why `Policy::guard_self_writable` refuses to
  start with a policy that grants write/delete on itself.
- **Single-threaded evaluation.** No TOCTOU between policy check
  and operation within one script — the evaluator is single-threaded.
  Two concurrent `aegis run` invocations against shared state are
  the operator's problem, not Aegis's.
- **Filesystem rooted at the policy file.** Relative patterns
  (`src/**`) anchor at the policy-file directory, not the CWD.
  Operators don't need to leak their machine's directory structure
  into the policy.
- **Network policy is hostname-first.** Most policies match on
  hostname; `[network].deny_ips` is a CIDR-aware second layer for
  IMDS / RFC1918 SSRF protection.

## Where to look in the code

If you're reviewing with hostile intent, these are the highest-value
files:

- `crates/policy/src/lib.rs` — every policy decision routes through
  here. Read `check_*` functions and the matchers
  (`PathMatcher`, `HostMatcher`, `IpNet` parsing).
- `crates/host/src/lib.rs` — every effecting builtin. Look for the
  pattern: pre-check, policy query, audit, side-effect, taint-on-return.
- `crates/host/src/taint.rs` — substring redaction. **Confirm for
  yourself that this is substring-only and that `run_exfil.py`'s
  findings reflect the same gap.**
- `crates/host/src/verifier.rs` — pre-execution AST scan. The
  defence-in-depth layer that rejects scripts referencing
  capabilities whose resource section is empty before evaluation.
- `crates/host/src/audit.rs` — the SHA-256 chain.

## Where this doc fits

| Doc | Purpose |
|-----|---------|
| **This doc** (`SECURITY_THREAT_MODEL.md`) | What Aegis claims to defend; what it doesn't. Read first. |
| [SECURITY_AUDIT.md](SECURITY_AUDIT.md) | The 16-surface bypass assessment that triggered the recent security work. Findings + fixes. |
| [04-policy-file.md](04-policy-file.md) | Policy file reference (operator-facing). |
| [03-architecture.md](03-architecture.md) | How the runtime is structured (developer-facing). |
| [examples/local_executor/run_exfil.py](../examples/local_executor/run_exfil.py) | The adversarial exfiltration probe — runs hand-written Starlark that *tries* to leak `local_only_var` values. Empirical version of the "what we don't defend against" list. |

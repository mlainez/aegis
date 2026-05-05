# Quickstart

> ← [Back to docs README](README.md)

Five minutes from a freshly built `aegis` to a script running under a
real policy.

Assumes you've already followed [05-install.md](05-install.md) (Rust +
`cargo build --release` + `aegis` on `$PATH`).

## 1. Generate a starter policy

In a project directory you want to play with:

```sh
cd ~/myproject
aegis init --lang python
# aegis: wrote aegis.toml (python). Review the file, then run with --policy aegis.toml.
```

The generated `aegis.toml` inherits `secure-defaults`, allows the Python
toolchain (`python3`, `pip`, `pytest`, `ruff`, ...), and explicitly blocks
git destructive operations and staging/qa/prod config files. Open it and
read it — the comments at the top explain what's already covered and
what you may want to extend.

If your project isn't Python, swap in `--lang node`, `ruby`, `rust`, or
`go`.

## 2. Write a tiny Starlark script

Create `count_lines.star`:

```starlark
content = fs.read("README.md")

def count_lines(text):
    n = 0
    for ch in text.elems():
        if ch == "\n":
            n += 1
    return n

print("README has", count_lines(content), "lines")
```

Two things to know about Starlark:

- It's the strict Python subset Bazel and Buck2 use. Loops, conditionals,
  and other control flow only work *inside `def`*.
- No imports, no f-strings. Use string concat or `.format()`.

The full notes are in `examples/local_executor/run_multistep.py`'s
`SYSTEM_PROMPT_TEMPLATE`, which is the same prompt the evaluation harness
gives a 7B model.

## 3. Run it

```sh
aegis run --policy aegis.toml count_lines.star
```

Expected:

```
README has 47 lines
```

The script's printed lines come out on stdout. Audit events go to stderr
by default — you'll see one `Allowed` event for the `fs.read`. To send
audit events to a file:

```sh
aegis run --policy aegis.toml --audit-log /tmp/audit.jsonl count_lines.star
tail -1 /tmp/audit.jsonl
# {"ts":"2026-05-05T07:50:00...","task_id":"count_lines.star","step":1,"capability":"fs.read","status":"allowed","detail":{"path":"...README.md","error":null}}
```

## 4. Watch a denial happen

Edit `count_lines.star` to read something the policy doesn't allow:

```starlark
secrets = fs.read("/etc/passwd")
print(secrets[:50])
```

Run:

```sh
aegis run --policy aegis.toml count_lines.star
echo "exit=$?"
```

You'll get a runtime denial:

```
aegis: policy violation: policy denies read on path "/etc/passwd": matches [filesystem].deny pattern
exit=2
```

`fs.read` itself is enabled (because `read_allow` is populated), so
the verifier lets the script through. The runtime gate then resolves
the path against the inherited `secure-defaults` deny list, sees
`/etc/passwd` matches, and rejects with exit 2.

Try the same script with a path that's not in any deny list but also
not in `read_allow` (e.g. `fs.read("/var/log/syslog")`) — you'll get
a similar runtime denial with the reason "not in
`[filesystem].read_allow`".

The exit codes:

| Code | Meaning                                          |
|------|--------------------------------------------------|
| 0    | Script ran successfully                           |
| 1    | Starlark eval error (parse, name, runtime)        |
| 2    | Policy violation at runtime                       |
| 3    | Pre-execution verifier rejection                  |
| 4    | Confirm hook denied                               |
| 5    | I/O or configuration error                        |
| 6    | Runtime cap exceeded (wall-time / call-stack)     |

## 5. Try a confirm-prompted capability

Edit your `aegis.toml`:

```toml
confirm_per_call = ["fs.delete"]

[filesystem]
delete_allow = ["/tmp/aegis_quickstart_*"]
```

(`fs.delete` is auto-derived from the populated `delete_allow`; no
separate `[functions]` declaration needed.)

Make a throwaway file and a script:

```sh
touch /tmp/aegis_quickstart_demo
cat > delete_demo.star <<'EOF'
fs.delete("/tmp/aegis_quickstart_demo")
print("deleted")
EOF
aegis run --policy aegis.toml delete_demo.star
```

In a TTY, you'll see:

```
[aegis] confirm fs.delete for task delete_demo.star: delete /tmp/aegis_quickstart_demo
        allow? [y/N]
```

Type `y` and the script proceeds. Type `n` (or just press Enter) and
the script fails with exit code 4.

In CI / non-TTY, the default confirm hook is `DenyAllConfirm` — same
script would fail with exit code 4 unless you pass `--yes` to override.

## 6. Run without a policy file (loud-and-safe fallback)

```sh
aegis run /tmp/random.star
```

Aegis prints a stderr banner explaining that no `--policy` was provided,
so it's using the built-in `secure-defaults` baseline alone — which has
**no allow lists**, so every effecting capability fails. Pure
computation and `print()` still work:

```sh
echo 'print("hello", 1 + 2)' > /tmp/safe.star
aegis run /tmp/safe.star
```

prints `hello 3`. Useful for quick experiments where you want guarantee-
nothing-effecting behavior.

## 7. The MCP server

The same enforcement is available over MCP (JSON-RPC 2.0 on stdio).

```sh
aegis-mcp --policy aegis.toml
# stays running, reads JSON-RPC requests from stdin
```

Most agentic hosts (Claude Code, opencode) talk to MCP servers
automatically once configured — see [07-claude-code.md](07-claude-code.md)
and [08-opencode.md](08-opencode.md) for the wiring.

For a hand test, you can speak the protocol manually:

```sh
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}' | aegis-mcp --policy aegis.toml
```

You'll get back the server's capability advertisement. The two methods
that matter operationally are `tools/list` and `tools/call`.

## Where next

- [04-policy-file.md](04-policy-file.md) — full policy reference (you'll
  want this open while you trim the generated file).
- [09-local-executor.md](09-local-executor.md) — the agentic setup with a
  local 7B model + cloud orchestrator.
- [07-claude-code.md](07-claude-code.md) — Claude Code integration.
- [08-opencode.md](08-opencode.md) — opencode integration.

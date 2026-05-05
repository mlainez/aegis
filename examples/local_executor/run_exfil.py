#!/usr/bin/env python3
"""Adversarial exfiltration probe for Aegis's local-only redaction.

This harness is the empirical companion to docs/SECURITY_THREAT_MODEL.md's
"What it does NOT defend against" section. It runs hand-written Starlark
scripts that *deliberately try* to leak a `local_only_var` through the
substring-redaction layer, and reports which techniques bypass it.

Unlike run_multistep.py and run_orchestrated.py, this harness uses NO
LLM. The Starlark for each technique is written by a human attacker
under the same constraints the runtime imposes (Starlark-strict, no
imports, no top-level for/if). The point is to measure the runtime,
not the model.

Each technique is tagged with one of:
  - REDACTED     : the literal secret bytes did not appear in any
                   output channel (printed text, error message, file
                   the host can read back). Substring scrub fired.
  - WEAK_LEAK    : a small amount of information leaked (length, a
                   comparison oracle, one bit per query). Not the full
                   secret, but exploitable with enough queries.
  - LEAK         : the secret is recoverable from the output the
                   harness sees. The substring-redaction layer was
                   bypassed.

The harness ALSO records, for LEAK results, the inverse function
that recovers the secret — so a security reviewer can confirm the
recovery is real and not just "looks like the secret."

Run:
    python3 examples/local_executor/run_exfil.py

Prerequisites:
    - cargo build --release  (produces target/release/aegis-mcp)
    - The fixture file /tmp/aegis_demo/multistep/fixtures/secrets/token.txt
      and the env var AEGIS_DEMO_SECRET are set up by setup_fixtures()
      below — no separate setup step needed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MCP_BIN = REPO_ROOT / "target" / "release" / "aegis-mcp"
DEFAULT_POLICY = REPO_ROOT / "examples" / "policies" / "multistep_test.toml"

WORKDIR = Path("/tmp/aegis_demo/exfil")
FIXTURES = WORKDIR / "fixtures"
SECRETS_DIR = FIXTURES / "secrets"
LEAK_DIR = WORKDIR / "leaks"
# Keep the policy file OUTSIDE the agent's write_allow tree so the
# self-writable guard doesn't refuse to load.
POLICY_PATH = Path("/tmp/aegis_exfil_probe.toml")

ENV_SECRET_NAME = "AEGIS_DEMO_SECRET"
ENV_SECRET_VALUE = "sk-env-do-not-leak-MNOP4321-fixture-secret"

# The runtime substring-redacts both the env var value AND the
# fixture-file value (if the file lies under [filesystem].local_only_read).
# We only exercise the env-var path here; the fs.read path uses the
# same redactor, so the conclusions transfer.

# IMPORTANT: this harness uses an alternate policy (exfil_probe.toml)
# that points local_only_read at the *exfil* fixture dir, not the
# multistep one. The two harnesses run in different directories.


# ---- MCP client (minimal, lifted from run_multistep.py) ----------------

class McpClient:
    def __init__(self, mcp_bin: Path, policy: Path) -> None:
        if not mcp_bin.exists():
            raise FileNotFoundError(
                f"aegis-mcp not found at {mcp_bin}. "
                f"Run `cargo build --release -p aegis-mcp` first."
            )
        self.proc = subprocess.Popen(
            [str(mcp_bin), "--policy", str(policy)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._id = 0
        self._call("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "aegis-exfil-probe", "version": "0"},
        })

    def _call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._id += 1
        req: dict[str, Any] = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            req["params"] = params
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("MCP server closed connection")
        return json.loads(line)

    def aegis_run(self, script: str, task_id: str) -> dict[str, Any]:
        return self._call("tools/call", {
            "name": "aegis_run",
            "arguments": {"script": script, "task_id": task_id},
        })

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


# ---- Fixture setup -----------------------------------------------------

POLICY_BODY = f"""# Auto-generated by run_exfil.py — do not commit.
inherits = "secure-defaults"
name = "exfil_probe"
description = "Fixture policy for the adversarial exfiltration harness."

[filesystem]
read_allow  = ["{WORKDIR}/**"]
local_only_read = ["{SECRETS_DIR}/**"]
write_allow = ["{WORKDIR}/**"]
delete_allow = ["{WORKDIR}/**"]

[network]
http_get_allow = ["api.github.com"]

[environment]
allow_vars      = ["USER", "HOME", "PATH"]
local_only_vars = ["{ENV_SECRET_NAME}"]

[subprocess]
allow_commands = ["echo", "cat", "printf"]
"""


def setup_fixtures() -> Path:
    """Build the fixture tree and write the auto-generated policy
    (outside the agent's write tree, so the self-writable guard
    doesn't refuse to load).  Returns the policy path."""
    if WORKDIR.exists():
        shutil.rmtree(WORKDIR)
    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    LEAK_DIR.mkdir(parents=True, exist_ok=True)
    (SECRETS_DIR / "token.txt").write_text(ENV_SECRET_VALUE, encoding="utf-8")
    os.environ[ENV_SECRET_NAME] = ENV_SECRET_VALUE
    POLICY_PATH.write_text(POLICY_BODY, encoding="utf-8")
    return POLICY_PATH


# ---- Technique definitions --------------------------------------------

@dataclass
class Technique:
    name: str
    category: str  # "control", "weak", "encoded", "side-channel", "covert-channel"
    description: str
    script: str
    # recover(printed_text) -> recovered_secret_or_None
    # If the recovered secret equals ENV_SECRET_VALUE, this is a LEAK.
    recover: Callable[[str], Optional[str]]
    # If the technique only leaks a small piece of info (length, a bit),
    # set this and return that info; result is WEAK_LEAK rather than LEAK.
    weak_recover: Optional[Callable[[str], Optional[str]]] = None


def _try(fn: Callable[[], Optional[str]]) -> Optional[str]:
    try:
        return fn()
    except Exception:
        return None


# ---------- 1. Raw print (control) ----------
# Expectation: REDACTED. The substring scrub fires; the printed line
# contains "[REDACTED]" instead of the secret.
T_RAW_PRINT = Technique(
    name="raw_print",
    category="control",
    description="print(secret) — naive leak attempt, expected to be redacted.",
    script=f'''
secret = env.read("{ENV_SECRET_NAME}")
print(secret)
''',
    recover=lambda out: out.strip() if ENV_SECRET_VALUE in out else None,
)


# ---------- 2. Length leak ----------
# Expectation: WEAK_LEAK. Length is a small int; redactor never sees
# anything to redact.
T_LENGTH = Technique(
    name="length_leak",
    category="side-channel",
    description="print(len(secret)) — leaks the secret's length.",
    script=f'''
secret = env.read("{ENV_SECRET_NAME}")
print(len(secret))
''',
    recover=lambda out: None,
    weak_recover=lambda out: f"length={out.strip()}" if out.strip().isdigit() else None,
)


# ---------- 3. Per-char comparison oracle ----------
# Expectation: WEAK_LEAK. Boolean for each character; with N queries
# (same-shape script with different probe chars) you recover the secret.
# We demonstrate one query that confirms the first char.
T_CMP_ORACLE = Technique(
    name="comparison_oracle",
    category="side-channel",
    description="print(secret[0] == 's') — confirms one character, one bit at a time.",
    script=f'''
secret = env.read("{ENV_SECRET_NAME}")
print(secret[0] == "s")
''',
    recover=lambda out: None,
    weak_recover=lambda out: f"first_char_is_s={out.strip()}",
)


# ---------- 4. Reverse-string ----------
# Expectation: LEAK. Reversed bytes never match the literal substring,
# so the redactor finds nothing. Reversing back recovers the secret.
T_REVERSE = Technique(
    name="reverse_bytes",
    category="encoded",
    description="print(secret reversed) — reversed bytes never match the substring.",
    script=f'''
secret = env.read("{ENV_SECRET_NAME}")
def rev(s):
    chars = []
    for i in range(len(s) - 1, -1, -1):
        chars.append(s[i])
    return "".join(chars)
print(rev(secret))
''',
    recover=lambda out: _try(lambda: out.strip()[::-1] if out.strip()[::-1] == ENV_SECRET_VALUE else None),
)


# ---------- 5. Per-char chunked output (one char per line, with cover) ----------
# Expectation: LEAK. The full string never appears as a contiguous
# substring in any single redaction window — depending on the
# redactor's scope (per-line vs per-output), this may or may not bypass.
T_CHUNKED = Technique(
    name="chunked_per_char",
    category="covert-channel",
    description="Print each character on its own line interleaved with cover text.",
    script=f'''
secret = env.read("{ENV_SECRET_NAME}")
def emit():
    for i in range(len(secret)):
        print("ch:" + secret[i])
emit()
''',
    recover=lambda out: _try(
        lambda: "".join(line[3:] for line in out.splitlines() if line.startswith("ch:"))
        if "".join(line[3:] for line in out.splitlines() if line.startswith("ch:")) == ENV_SECRET_VALUE
        else None
    ),
)


# ---------- 6. Hex-encode each byte ----------
# Expectation: LEAK. Hex digits never spell out the secret substring.
T_HEX = Technique(
    name="hex_encode",
    category="encoded",
    description="Encode each character as 2-char hex; recover by hex-decoding.",
    script=f'''
secret = env.read("{ENV_SECRET_NAME}")
HEX = "0123456789abcdef"
def to_hex(s):
    out = []
    for i in range(len(s)):
        c = s[i]
        b = ord(c)
        out.append(HEX[b // 16])
        out.append(HEX[b % 16])
    return "".join(out)
print(to_hex(secret))
''',
    recover=lambda out: _try(
        lambda: bytes.fromhex(out.strip()).decode("utf-8")
        if bytes.fromhex(out.strip()).decode("utf-8") == ENV_SECRET_VALUE
        else None
    ),
)


# ---------- 7. XOR with constant key ----------
# Expectation: LEAK. The XOR ciphertext never contains the substring.
# Recoverable with the known key.
XOR_KEY = 0x5A
T_XOR = Technique(
    name="xor_constant_key",
    category="encoded",
    description=f"Print bytewise XOR with constant key 0x{XOR_KEY:02x}; recover by XORing back.",
    script=f'''
secret = env.read("{ENV_SECRET_NAME}")
HEX = "0123456789abcdef"
KEY = {XOR_KEY}
def xor_hex(s):
    out = []
    for i in range(len(s)):
        b = ord(s[i]) ^ KEY
        out.append(HEX[b // 16])
        out.append(HEX[b % 16])
    return "".join(out)
print(xor_hex(secret))
''',
    recover=lambda out: _try(
        lambda: "".join(chr(b ^ XOR_KEY) for b in bytes.fromhex(out.strip()))
        if "".join(chr(b ^ XOR_KEY) for b in bytes.fromhex(out.strip())) == ENV_SECRET_VALUE
        else None
    ),
)


# ---------- 8. fail() with secret ----------
# Expectation: REDACTED. The error-path scrubber should fire.
T_FAIL_RAW = Technique(
    name="fail_raw",
    category="control",
    description="fail(secret) — raise an error containing the secret. Error-path redaction should fire.",
    script=f'''
secret = env.read("{ENV_SECRET_NAME}")
fail(secret)
''',
    recover=lambda out: out.strip() if ENV_SECRET_VALUE in out else None,
)


# ---------- 9. fail() with reversed secret ----------
# Expectation: LEAK. The error-path scrubber works on the substring;
# the reversed bytes don't match.
T_FAIL_REVERSED = Technique(
    name="fail_reversed",
    category="encoded",
    description="fail(reverse(secret)) — error-path redaction is substring-based; reversed bytes bypass.",
    script=f'''
secret = env.read("{ENV_SECRET_NAME}")
def rev(s):
    chars = []
    for i in range(len(s) - 1, -1, -1):
        chars.append(s[i])
    return "".join(chars)
fail(rev(secret))
''',
    recover=lambda out: _try(
        lambda: ENV_SECRET_VALUE if ENV_SECRET_VALUE in out[::-1] else None
    ),
)


# ---------- 10. Subprocess echo of the secret ----------
# Expectation: REDACTED. echo's stdout traverses the runtime; the
# substring redactor sees the value and replaces it.
T_SUBPROCESS_ECHO = Technique(
    name="subprocess_echo",
    category="control",
    description="subprocess.exec(['echo', secret]) — passes secret as argv, echo prints it.",
    script=f'''
secret = env.read("{ENV_SECRET_NAME}")
out = subprocess.exec(["echo", secret])
print(out)
''',
    recover=lambda out: out.strip() if ENV_SECRET_VALUE in out else None,
)


# ---------- 11. Write to file then read back via host ----------
# Expectation: depends on whether fs.write content is scrubbed. Per
# the threat model, redaction applies at "output / audit / MCP" — the
# bytes ON DISK are not scrubbed. The host harness reads the file
# directly (NOT through aegis-mcp) and confirms the secret landed
# there in plaintext. This is a leak of a different kind: not via
# the MCP boundary, but to a place the host process can read.
T_FS_WRITE = Technique(
    name="fs_write_to_disk",
    category="covert-channel",
    description="fs.write(public_path, secret) — content on disk is NOT redacted; host reading the file outside aegis-mcp recovers it.",
    script=f'''
secret = env.read("{ENV_SECRET_NAME}")
fs.write("{LEAK_DIR}/leaked.txt", secret)
print("wrote_leak")
''',
    recover=lambda out: _try(
        lambda: (LEAK_DIR / "leaked.txt").read_text(encoding="utf-8")
        if (LEAK_DIR / "leaked.txt").exists()
        and (LEAK_DIR / "leaked.txt").read_text(encoding="utf-8") == ENV_SECRET_VALUE
        else None
    ),
)


# ---------- 12. Substring guess oracle ----------
# Expectation: WEAK_LEAK. Confirms a guessed substring is present
# without revealing the surrounding context — but each query reveals
# 1 bit. With dictionary attacks this is exploitable.
T_SUBSTRING_GUESS = Technique(
    name="substring_guess",
    category="side-channel",
    description="if 'MNOP' in secret: print('match') — a known dictionary entry confirms presence.",
    script=f'''
secret = env.read("{ENV_SECRET_NAME}")
def check():
    if "MNOP" in secret:
        return "match"
    return "no_match"
print(check())
''',
    recover=lambda out: None,
    weak_recover=lambda out: f"contains_MNOP={out.strip()=='match'}",
)


TECHNIQUES = [
    T_RAW_PRINT,
    T_LENGTH,
    T_CMP_ORACLE,
    T_REVERSE,
    T_CHUNKED,
    T_HEX,
    T_XOR,
    T_FAIL_RAW,
    T_FAIL_REVERSED,
    T_SUBPROCESS_ECHO,
    T_FS_WRITE,
    T_SUBSTRING_GUESS,
]


# ---- Result classification --------------------------------------------

@dataclass
class Result:
    technique: Technique
    printed: str
    is_error: bool
    verdict: str  # "REDACTED", "WEAK_LEAK", "LEAK"
    leaked_value: Optional[str]
    note: str


def classify(t: Technique, printed: str, is_error: bool) -> Result:
    # Did the LITERAL secret bytes appear anywhere?
    if ENV_SECRET_VALUE in printed:
        return Result(t, printed, is_error, "LEAK", ENV_SECRET_VALUE,
                      "literal secret bytes present in output")

    recovered = t.recover(printed)
    if recovered == ENV_SECRET_VALUE:
        return Result(t, printed, is_error, "LEAK", recovered,
                      "secret recovered via inverse function")

    if t.weak_recover is not None:
        info = t.weak_recover(printed)
        if info:
            return Result(t, printed, is_error, "WEAK_LEAK", info,
                          "side-channel info exposed but not full secret")

    return Result(t, printed, is_error, "REDACTED", None,
                  "no recoverable info in output")


# ---- Driver ------------------------------------------------------------

def run_one(client: McpClient, t: Technique) -> Result:
    resp = client.aegis_run(t.script.lstrip(), task_id=f"exfil-{t.name}")
    result = resp.get("result", {})
    is_error = bool(result.get("isError"))
    text = ""
    for chunk in result.get("content", []):
        if chunk.get("type") == "text":
            text += chunk.get("text", "")
    return classify(t, text, is_error)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mcp-bin", type=Path, default=DEFAULT_MCP_BIN)
    parser.add_argument("--only", help="Run only this technique by name", default=None)
    parser.add_argument("--show-script", action="store_true", help="Print each Starlark before running")
    parser.add_argument("--show-output", action="store_true", help="Print each MCP output verbatim")
    args = parser.parse_args()

    if not args.mcp_bin.exists():
        print(f"FAIL: aegis-mcp not built at {args.mcp_bin}", file=sys.stderr)
        return 2

    policy = setup_fixtures()
    print(f"# policy: {policy}")
    print(f"# secret: ENV[{ENV_SECRET_NAME}] = {ENV_SECRET_VALUE!r}")
    print()

    client = McpClient(args.mcp_bin, policy)
    try:
        results: list[Result] = []
        for t in TECHNIQUES:
            if args.only and t.name != args.only:
                continue
            if args.show_script:
                print(f"--- script for {t.name} ---")
                print(t.script.strip())
                print("--- end script ---")
            r = run_one(client, t)
            results.append(r)
            mark = {
                "REDACTED": "✓ REDACTED",
                "WEAK_LEAK": "~ WEAK_LEAK",
                "LEAK":     "✗ LEAK",
            }[r.verdict]
            print(f"{mark:<14} [{t.category}] {t.name}")
            print(f"   {t.description}")
            print(f"   note: {r.note}")
            if r.leaked_value:
                shown = r.leaked_value
                if len(shown) > 80:
                    shown = shown[:77] + "..."
                print(f"   leaked: {shown!r}")
            if args.show_output:
                print(f"   raw output: {r.printed!r}")
            print()

        # Summary
        leaks = [r for r in results if r.verdict == "LEAK"]
        weak = [r for r in results if r.verdict == "WEAK_LEAK"]
        ok = [r for r in results if r.verdict == "REDACTED"]
        print("=" * 60)
        print(f"# summary: {len(ok)} REDACTED, {len(weak)} WEAK_LEAK, {len(leaks)} LEAK "
              f"(of {len(results)} techniques)")
        print()
        if leaks:
            print("# bypass paths confirmed (substring redaction insufficient):")
            for r in leaks:
                print(f"  - {r.technique.name} ({r.technique.category})")
        if weak:
            print("# side-channels confirmed (small per-query info):")
            for r in weak:
                print(f"  - {r.technique.name} ({r.technique.category})")
        return 1 if leaks else 0
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())

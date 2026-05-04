"""Embedding-based retrieval for Starlark code examples.

Used by run_multistep.py to inject the 3-4 most relevant worked examples
into the per-task system prompt, instead of always shipping the same 8.
The library is curated specifically against the failure modes we
observed: top-level for/if (rewritten as def + call), f-strings,
import json, list comprehensions, multi-step fetch, multi-subprocess
composition.

Embedding: Ollama /api/embeddings with `nomic-embed-text` (already
installed on this host). Cosine similarity between task description
and each library example's description; pick the top K.

The library lives entirely in this file so it's reviewable as one
unit. Adding an example: drop a new dict in EXAMPLES with `id`,
`desc` (used for retrieval matching — describe WHAT the example
demonstrates), and `code` (the Starlark program text).
"""

from __future__ import annotations

import json
import math
import urllib.request
from typing import Any


EMBED_HOST = "http://localhost:11434"
EMBED_MODEL = "nomic-embed-text"


EXAMPLES: list[dict[str, Any]] = [
    {
        "id": "iterate_lines_count_matching",
        "desc": (
            "iterate over the lines of a multi-line text and count how "
            "many lines match a substring or condition; write the count "
            "to a file. Pattern: wrap a for/if loop inside a def, then "
            "call the def. Top-level for/if is REJECTED."
        ),
        "code": """log = fs.read("/tmp/aegis_demo/log.txt")

def count_errors(text):
    n = 0
    for line in text.split("\\n"):
        if "[ERROR]" in line:
            n = n + 1
    return n

errors = count_errors(log)
fs.write("/tmp/out/error_count.txt", str(errors))
print("errors: " + str(errors))""",
    },
    {
        "id": "iterate_filter_via_comprehension",
        "desc": (
            "filter the lines of a text that contain a substring, keeping "
            "only the matches. Pattern: list comprehension at top level "
            "(comprehensions ARE allowed at top level — only `for` "
            "statements are not)."
        ),
        "code": """log = fs.read("/tmp/aegis_demo/log.txt")
lines = log.split("\\n")
matches = [l for l in lines if "[ERROR]" in l]
fs.write("/tmp/out/errors.txt", "\\n".join(matches))
print("found " + str(len(matches)) + " matching lines")""",
    },
    {
        "id": "extract_first_match_via_def",
        "desc": (
            "scan a multi-line file for the first line matching a prefix "
            "(like 'version = '), extract a substring, and write it. "
            "Pattern: def with for+if, returning the extracted value; "
            "use string .replace and .strip to clean."
        ),
        "code": """body = fs.read("/tmp/aegis_demo/manifest.toml")

def find_version(text):
    for line in text.split("\\n"):
        if line.startswith("version = "):
            return line.replace("version = ", "").strip().strip('"')
    return ""

v = find_version(body)
fs.write("/tmp/out/version.txt", v)
print(v)""",
    },
    {
        "id": "compare_two_via_ternary",
        "desc": (
            "compare two values (file contents, integers, fields) and "
            "produce one result OR another based on which is greater "
            "or equal. Pattern: inline ternary `a if cond else b` works "
            "at top level. Top-level `if` statements do NOT work."
        ),
        "code": """a = fs.read("/tmp/aegis_demo/file_a.txt")
b = fs.read("/tmp/aegis_demo/file_b.txt")
result = "match" if a == b else "differ"
fs.write("/tmp/out/cmp.txt", result)
print(result)""",
    },
    {
        "id": "fetch_parse_extract_field",
        "desc": (
            "fetch a JSON API endpoint, decode the JSON, and extract a "
            "specific top-level field. Write the extracted value to a "
            "file. Pattern: net.http_get + json.decode + dict access."
        ),
        "code": """body = net.http_get("https://api.example.com/repo")
data = json.decode(body)
description = data["description"]
fs.write("/tmp/out/desc.txt", description)
print(description)""",
    },
    {
        "id": "fetch_extract_nested_field",
        "desc": (
            "fetch a JSON API and extract a NESTED field from the "
            "decoded object (e.g. data['owner']['login']). Pattern: "
            "chained dict access after json.decode."
        ),
        "code": """body = net.http_get("https://api.example.com/repo")
data = json.decode(body)
owner_login = data["owner"]["login"]
fs.write("/tmp/out/owner.txt", owner_login)
print("owner: " + owner_login)""",
    },
    {
        "id": "fetch_array_field_join",
        "desc": (
            "fetch a JSON API where one field is a list/array, decode "
            "and join the array elements into a comma-separated string. "
            "Handle empty array as a special case via inline ternary."
        ),
        "code": """body = net.http_get("https://api.example.com/repo")
data = json.decode(body)
topics = data["topics"]
result = ", ".join(topics) if len(topics) > 0 else "none"
fs.write("/tmp/out/topics.txt", result)
print(result)""",
    },
    {
        "id": "fetch_n_times_with_def",
        "desc": (
            "fetch a URL N times (N>=2) and aggregate the results into "
            "a single string with newline separators. Pattern: def "
            "wrapping `for i in range(n)`, returning the joined output."
        ),
        "code": """def fetch_n(url, n):
    out = []
    for i in range(n):
        out.append(net.http_get(url))
    return out

results = fetch_n("https://api.example.com/zen", 3)
agg = "\\n".join(results)
fs.write("/tmp/out/aggregate.txt", agg)
print(agg)""",
    },
    {
        "id": "compare_two_api_responses",
        "desc": (
            "fetch two distinct API endpoints, decode each as JSON, "
            "compare a numeric field across them, write a JSON object "
            "mapping each name to its value, and print which is larger."
        ),
        "code": """body_a = net.http_get("https://api.example.com/repo/a")
body_b = net.http_get("https://api.example.com/repo/b")
a = json.decode(body_a)
b = json.decode(body_b)
sizes = {a["full_name"]: a["size"], b["full_name"]: b["size"]}
fs.write("/tmp/out/sizes.json", json.encode(sizes))
larger = a["full_name"] if a["size"] >= b["size"] else b["full_name"]
print("larger: " + larger)""",
    },
    {
        "id": "multi_subprocess_compose",
        "desc": (
            "run two or more subprocess commands sequentially, capture "
            "their outputs (with .strip), build a structured text body, "
            "write it to a file. Pattern: subprocess.exec calls + string "
            "concatenation."
        ),
        "code": """version = subprocess.exec(["git", "--version"]).strip()
help_text = subprocess.exec(["git", "--help"])
first = help_text.split("\\n")[0]
body = "version: " + version + "\\nfirst-help: " + first
fs.write("/tmp/out/git_info.txt", body)
print(body)""",
    },
    {
        "id": "subprocess_count_lines",
        "desc": (
            "run a subprocess command (find, ls, grep, etc.) whose "
            "output is line-separated, count the non-empty lines, write "
            "the integer count to a file. Pattern: subprocess.exec + "
            ".split + filter empties + len."
        ),
        "code": """out = subprocess.exec(["find", "/tmp/aegis_demo", "-name", "*.txt", "-type", "f"])
lines = [l for l in out.split("\\n") if l.strip() != ""]
fs.write("/tmp/out/count.txt", str(len(lines)))
print("count: " + str(len(lines)))""",
    },
    {
        "id": "subprocess_extract_first_token",
        "desc": (
            "run a subprocess command whose output starts with a number "
            "followed by whitespace and other tokens (like `wc -l file` "
            "→ '7 file'). Extract the first whitespace-separated token "
            "as an integer string."
        ),
        "code": """out = subprocess.exec(["wc", "-l", "/tmp/aegis_demo/log.txt"]).strip()
first = out.split()[0]
fs.write("/tmp/out/n.txt", first)
print("n: " + first)""",
    },
    {
        "id": "env_to_json",
        "desc": (
            "read multiple environment variables, build a JSON object "
            "with them, encode and write to a file. Pattern: env.read "
            "calls + dict literal + json.encode."
        ),
        "code": """user = env.read("USER")
home = env.read("HOME")
data = {"user": user, "home": home}
encoded = json.encode(data)
fs.write("/tmp/out/whoami.json", encoded)
print(encoded)""",
    },
    {
        "id": "render_template_with_replace",
        "desc": (
            "read a template file containing literal placeholders like "
            "{USER} and {HOME}, substitute the placeholders with values "
            "(env vars or computed), write the rendered output. Pattern: "
            "str.replace, NOT f-strings."
        ),
        "code": """tpl = fs.read("/tmp/aegis_demo/template.txt")
user = env.read("USER")
home = env.read("HOME")
rendered = tpl.replace("{USER}", user).replace("{HOME}", home)
fs.write("/tmp/out/rendered.txt", rendered)
print(rendered)""",
    },
    {
        "id": "merge_config_with_value",
        "desc": (
            "read a JSON config file, decode it, add or update a field "
            "(e.g. with an env var value), encode and write back. "
            "Pattern: json.decode + dict assignment + json.encode."
        ),
        "code": """body = fs.read("/tmp/aegis_demo/config.json")
cfg = json.decode(body)
cfg["home_dir"] = env.read("HOME")
fs.write("/tmp/out/config_merged.json", json.encode(cfg))
print(json.encode(cfg))""",
    },
    {
        "id": "count_per_category_via_def",
        "desc": (
            "iterate over rows of structured data (CSV, log lines, "
            "etc.), count occurrences per category/key, build a result "
            "dict, encode as JSON and write. Pattern: def with for "
            "loop accumulating into a dict."
        ),
        "code": """body = fs.read("/tmp/aegis_demo/data.csv")

def count_by_kind(text):
    counts = {}
    rows = text.split("\\n")
    for row in rows[1:]:
        if row == "":
            continue
        parts = row.split(",")
        kind = parts[1]
        counts[kind] = counts.get(kind, 0) + 1
    return counts

result = count_by_kind(body)
fs.write("/tmp/out/by_kind.json", json.encode(result))
print(json.encode(result))""",
    },
    {
        "id": "build_table_with_format",
        "desc": (
            "read several files, compute a per-file statistic (word "
            "count, line count, etc.), write a formatted text table "
            "with header. Pattern: .format() for formatting numbers; "
            "string concatenation for the body."
        ),
        "code": """a = fs.read("/tmp/aegis_demo/a.txt")
b = fs.read("/tmp/aegis_demo/b.txt")
c = fs.read("/tmp/aegis_demo/c.txt")
header = "file\\twords\\n"
rows = (
    "a.txt\\t{}\\n".format(len(a.split())) +
    "b.txt\\t{}\\n".format(len(b.split())) +
    "c.txt\\t{}\\n".format(len(c.split()))
)
table = header + rows
fs.write("/tmp/out/word_table.tsv", table)
print(table)""",
    },
    {
        "id": "append_to_existing_log",
        "desc": (
            "read an existing log/audit file, append a new line, write "
            "back. Pattern: fs.read + concatenate with new line + fs.write."
        ),
        "code": """existing = fs.read("/tmp/aegis_demo/audit.txt")
extended = existing + "2026-05-04 entry-3\\n"
fs.write("/tmp/out/audit_extended.txt", extended)
print(str(len(extended.split("\\n")) - 1) + " lines")""",
    },
    {
        "id": "extract_dependency_names",
        "desc": (
            "read a manifest/config file with a [section] header and "
            "key=value lines under it (TOML-shaped), find the section, "
            "extract just the LHS names (dependency names), write them "
            "one per line. Pattern: def scanning lines, tracking "
            "in-section state, splitting on '='."
        ),
        "code": """body = fs.read("/tmp/aegis_demo/manifest.toml")

def deps_from_toml(text):
    out = []
    in_deps = False
    for line in text.split("\\n"):
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            in_deps = (s == "[dependencies]")
            continue
        if in_deps and "=" in s:
            name = s.split("=")[0].strip()
            if name != "":
                out.append(name)
    return out

names = deps_from_toml(body)
fs.write("/tmp/out/dep_names.txt", "\\n".join(names))
print("count: " + str(len(names)))""",
    },
]


_embedding_cache: dict[str, list[float]] = {}


def embed(text: str, host: str = EMBED_HOST, model: str = EMBED_MODEL) -> list[float]:
    """Embed `text` via Ollama. Cached so repeated lookups (per-task
    library scan) don't re-invoke the model."""
    if text in _embedding_cache:
        return _embedding_cache[text]
    req = json.dumps({"model": model, "prompt": text}).encode()
    request = urllib.request.Request(
        f"{host}/api/embeddings",
        data=req,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as resp:
        body = json.loads(resp.read())
    vec = body["embedding"]
    _embedding_cache[text] = vec
    return vec


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def precompute_library_embeddings(host: str = EMBED_HOST, model: str = EMBED_MODEL) -> None:
    """Force-warm the cache for every example's description. Safe to
    call once at startup so the first task doesn't pay for K
    embeddings."""
    for ex in EXAMPLES:
        embed(ex["desc"], host=host, model=model)


def retrieve(task_text: str, k: int = 4, host: str = EMBED_HOST, model: str = EMBED_MODEL) -> list[dict[str, Any]]:
    """Return the top-K examples by cosine similarity to the task's
    description."""
    task_vec = embed(task_text, host=host, model=model)
    scored: list[tuple[float, dict[str, Any]]] = []
    for ex in EXAMPLES:
        ex_vec = embed(ex["desc"], host=host, model=model)
        scored.append((_cosine(task_vec, ex_vec), ex))
    scored.sort(reverse=True, key=lambda t: t[0])
    return [ex for _score, ex in scored[:k]]


def render_examples(examples: list[dict[str, Any]]) -> str:
    """Render a list of examples as the WORKED EXAMPLES section of the
    system prompt (column-0 friendly)."""
    parts: list[str] = []
    for i, ex in enumerate(examples, 1):
        parts.append(f"--- Example {i}: {ex['desc']} ---\n{ex['code']}\n")
    return "\n".join(parts)

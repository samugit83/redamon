"""Shared helpers for the urlscan lab's scripts. Stdlib only.

- load_yaml: the YAML subset expected_results.yaml is written in (block
  mappings and sequences, flow [..] and {..}, quoted and plain scalars,
  comments). No anchors, no block scalars: they raise, never misparse.
- env_value: one value from the repository's .env, read by NAME. Callers never
  print it.
- cypher_rows: read-only Cypher through cypher-shell inside redamon-neo4j, so
  the password stays in that container and muted nodes are included.
- Webapp: a signed-in session with UI_LOGIN_USERNAME / UI_LOGIN_PASSWORD.
- tokens / substitute: the planted values (generated/tokens.json, checked
  against token_hashes.json) and the <<T1>>-style placeholders of the checks.
"""
from __future__ import annotations

import base64
import hashlib
import http.cookiejar
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
GEN = HERE / "generated"
RUNS = GEN / "runs"
NEO4J = "redamon-neo4j"
ORCHESTRATOR = "redamon-recon-orchestrator"
HOOKS = ("URLSCAN_API_BASE", "REDAMON_LAB_CDN_PREFIXES", "REDAMON_LAB_PROJECT_IDS")
CONTAINERS = ("uslab-web", "uslab-excluded", "uslab-edge", "uslab-origin", "uslab-decoy",
              "uslab-oldip", "uslab-outsider")
FAKE = "http://192.88.97.30"
_PID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


# --------------------------------------------------------------------------- YAML subset

class YamlError(ValueError):
    pass


def _strip_comment(line: str) -> str:
    quote = None
    i = 0
    while i < len(line):
        c = line[i]
        if quote == '"' and c == "\\":
            i += 2
            continue
        if quote:
            if c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
        i += 1
    return line


def _quoted(s: str, i: int) -> tuple[str, int]:
    q = s[i]
    out, i = [], i + 1
    while i < len(s):
        c = s[i]
        if q == "'" and c == "'":
            if s[i + 1:i + 2] == "'":
                out.append("'")
                i += 2
                continue
            return "".join(out), i + 1
        if q == '"' and c == "\\":
            nxt = s[i + 1:i + 2]
            if nxt == "u":
                out.append(chr(int(s[i + 2:i + 6], 16)))
                i += 6
                continue
            out.append({"n": "\n", "t": "\t", "\\": "\\", '"': '"', "/": "/"}.get(nxt, "\\" + nxt))
            i += 2
            continue
        if q == '"' and c == '"':
            return "".join(out), i + 1
        out.append(c)
        i += 1
    raise YamlError(f"unterminated quote in {s!r}")


def _plain(text: str):
    t = text.strip()
    if t in ("true", "True"):
        return True
    if t in ("false", "False"):
        return False
    if t in ("null", "~", ""):
        return None
    if re.fullmatch(r"[-+]?[0-9]+", t):
        return int(t)
    if re.fullmatch(r"[-+]?[0-9]*\.[0-9]+", t):
        return float(t)
    if t[:1] in ("&", "*", "|", ">", "!", "%", "@", "`"):
        raise YamlError(f"unsupported YAML construct {t!r}")
    return t


def _skip_ws(s: str, i: int) -> int:
    while i < len(s) and s[i] in " \t":
        i += 1
    return i


def _flow(s: str, i: int, stops: str):
    i = _skip_ws(s, i)
    if i >= len(s):
        raise YamlError(f"unexpected end in {s!r}")
    c = s[i]
    if c == "[":
        out, i = [], _skip_ws(s, i + 1)
        while True:
            if s[i:i + 1] == "]":
                return out, i + 1
            value, i = _flow(s, i, ",]")
            out.append(value)
            i = _skip_ws(s, i)
            if s[i:i + 1] == ",":
                i = _skip_ws(s, i + 1)
            elif s[i:i + 1] != "]":
                raise YamlError(f"expected , or ] in {s!r}")
    if c == "{":
        out, i = {}, _skip_ws(s, i + 1)
        while True:
            if s[i:i + 1] == "}":
                return out, i + 1
            if s[i] in "\"'":
                key, i = _quoted(s, i)
            else:
                j = i
                while j < len(s) and not (s[j] == ":" and s[j + 1:j + 2] in (" ", "")):
                    j += 1
                key, i = s[i:j].strip(), j
            i = _skip_ws(s, i)
            if s[i:i + 1] != ":":
                raise YamlError(f"expected : after {key!r} in {s!r}")
            value, i = _flow(s, i + 1, ",}")
            out[key] = value
            i = _skip_ws(s, i)
            if s[i:i + 1] == ",":
                i = _skip_ws(s, i + 1)
            elif s[i:i + 1] != "}":
                raise YamlError(f"expected , or }} in {s!r}")
    if c in "\"'":
        return _quoted(s, i)
    j = i
    while j < len(s) and s[j] not in stops:
        j += 1
    return _plain(s[i:j]), j


def _value(text: str):
    text = text.strip()
    if text[:1] in "[{\"'":
        value, end = _flow(text, 0, "")
        if text[end:].strip():
            raise YamlError(f"trailing text after a value: {text!r}")
        return value
    return _plain(text)


def _split_key(content: str):
    """(key, rest) when the line is `key: rest`, else None."""
    if content[:1] in "\"'":
        try:
            key, i = _quoted(content, 0)
        except YamlError:
            return None
        rest = content[i:]
        if rest[:1] == ":" and rest[1:2] in ("", " "):
            return key, rest[1:].strip()
        return None
    if content[:1] in "[{":
        return None
    m = re.match(r"^([^:]+?):(?:\s+(.*))?$", content)
    if not m:
        return None
    return m.group(1).strip(), (m.group(2) or "").strip()


def _is_item(content: str) -> bool:
    return content == "-" or content.startswith("- ")


def _block(lines: list, i: int, indent: int):
    if _is_item(lines[i][1]):
        return _sequence(lines, i, indent)
    out = {}
    while i < len(lines) and lines[i][0] == indent and not _is_item(lines[i][1]):
        kv = _split_key(lines[i][1])
        if kv is None:
            raise YamlError(f"line {lines[i][2]}: expected `key: value`, got {lines[i][1]!r}")
        key, rest = kv
        if key in out:
            raise YamlError(f"line {lines[i][2]}: duplicate key {key!r}")
        i += 1
        if rest:
            out[key] = _value(rest)
        elif i < len(lines) and lines[i][0] > indent:
            out[key], i = _block(lines, i, lines[i][0])
        elif i < len(lines) and lines[i][0] == indent and _is_item(lines[i][1]):
            out[key], i = _sequence(lines, i, indent)
        else:
            out[key] = None
    if i < len(lines) and lines[i][0] > indent:
        raise YamlError(f"line {lines[i][2]}: unexpected indentation")
    return out, i


def _sequence(lines: list, i: int, indent: int):
    out = []
    while i < len(lines) and lines[i][0] == indent and _is_item(lines[i][1]):
        content = lines[i][1]
        rest = content[1:].lstrip()
        if not rest:
            i += 1
            if i < len(lines) and lines[i][0] > indent:
                value, i = _block(lines, i, lines[i][0])
            else:
                value = None
        elif _split_key(rest) is not None:
            child = indent + len(content) - len(rest)
            lines[i] = (child, rest, lines[i][2])
            value, i = _block(lines, i, child)
        else:
            value, i = _value(rest), i + 1
        out.append(value)
    return out, i


def load_yaml(text: str):
    lines = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw).rstrip()
        if not line.strip() or line.strip() == "---":
            continue
        stripped = line.lstrip(" ")
        if stripped.startswith("\t"):
            raise YamlError(f"line {n}: tab indentation")
        lines.append((len(line) - len(stripped), stripped, n))
    if not lines:
        return None
    value, i = _block(lines, 0, lines[0][0])
    if i != len(lines):
        raise YamlError(f"line {lines[i][2]}: unexpected content")
    return value


# --------------------------------------------------------------------------- .env, tokens

def env_value(name: str) -> str | None:
    """One .env value by name (the environment wins). Never print what this returns."""
    if os.environ.get(name):
        return os.environ[name]
    env = REPO / ".env"
    if not env.is_file():
        return None
    for line in env.read_text(encoding="utf-8").splitlines():
        if line.startswith(name + "="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def lab_meta() -> dict:
    path = GEN / "lab.json"
    if not path.is_file():
        raise SystemExit("[!] generated/lab.json missing: run ./up.sh (or gen_lab.py) first")
    return json.loads(path.read_text())


def load_tokens() -> dict:
    """The planted values, refused when they disagree with token_hashes.json."""
    tokens = json.loads((GEN / "tokens.json").read_text())
    hashes = json.loads((GEN / "token_hashes.json").read_text())
    for label, value in tokens.items():
        if hashlib.sha256(value.encode()).hexdigest() != hashes.get(label, {}).get("sha256"):
            raise SystemExit(f"[!] token {label} does not match token_hashes.json: regenerate the lab")
    return tokens


def placeholders(tokens: dict, meta: dict) -> dict:
    values = dict(tokens)
    for key, bundle in meta.get("bundles", {}).items():
        values[f"{key.upper()}_JS_SHA"] = bundle["sha256"]
        values[f"{key.upper()}_JS_NAME"] = bundle["name"]
    return values


def substitute(text: str, values: dict, regex: bool = True) -> str:
    def repl(m):
        name = m.group(1)
        if name not in values:
            raise KeyError(f"unknown placeholder <<{name}>>")
        return re.escape(values[name]) if regex else values[name]
    return re.sub(r"<<([A-Z0-9_]+)>>", repl, text)


# --------------------------------------------------------------------------- Neo4j

def check_pid(pid: str) -> str:
    if not _PID.match(pid or ""):
        raise SystemExit(f"[!] not a project id: {pid!r}")
    return pid


def cypher_rows(query: str, pid: str) -> list:
    """The `v` column of a read-only query that uses $pid. Each value travels
    base64-encoded through cypher-shell's plain output, which a quoted string
    would not survive."""
    check_pid(pid)
    wrapped = (f"CALL {{ {query} }}\n"
               "RETURN apoc.text.base64Encode(apoc.convert.toJson({v: v})) AS b;")
    cmd = ["docker", "exec", "-i", NEO4J, "sh", "-c",
           'cypher-shell -u neo4j -p "${NEO4J_AUTH#neo4j/}" --format plain -P "$1"', "sh",
           f'pid => "{pid}"']
    for _ in range(6):
        out = subprocess.run(cmd, input=wrapped, capture_output=True, text=True, timeout=300)
        # Neo4j locks the user name for a few seconds after any client's third
        # wrong password; another client's mistake must not fail a lab check.
        if out.returncode == 0 or "too many times in a row" not in out.stderr:
            break
        time.sleep(6)
    if out.returncode != 0:
        raise RuntimeError(f"cypher-shell failed ({out.returncode}): {out.stderr.strip()[:300]}")
    rows = []
    for line in out.stdout.splitlines()[1:]:
        line = line.strip().strip('"')
        if line:
            rows.append(json.loads(base64.b64decode(line))["v"])
    return rows


# --------------------------------------------------------------------------- webapp, fake urlscan

def web_base() -> str:
    return os.environ.get("REDAMON_WEB") or f"http://localhost:{env_value('WEBAPP_PORT') or '3000'}"


class Webapp:
    """A signed-in webapp session (partial recon has no MCP tool)."""

    def __init__(self):
        self.base = web_base()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        user, password = env_value("UI_LOGIN_USERNAME"), env_value("UI_LOGIN_PASSWORD")
        if not user or not password:
            raise SystemExit("[!] UI_LOGIN_USERNAME / UI_LOGIN_PASSWORD missing from .env")
        status, out = self.call("POST", "/api/auth/login", {"email": user, "password": password})
        if status != 200:
            raise SystemExit(f"[!] webapp login refused ({status})")

    def call(self, method: str, path: str, body: dict | None = None, timeout: int = 120):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                raw = resp.read()
                return resp.status, json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, {"error": raw.decode("utf-8", "replace")[:300]}


def fake(method: str, path: str, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(FAKE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def orchestrator_hooks() -> dict:
    """The three lab hooks as the running orchestrator sees them. Only these
    names are read from its environment; nothing else is kept or printed."""
    out = subprocess.run(["docker", "inspect", "-f", "{{json .Config.Env}}", ORCHESTRATOR],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"[!] cannot inspect {ORCHESTRATOR}: is the stack up?")
    found = {}
    for item in json.loads(out.stdout or "[]"):
        name, _, value = item.partition("=")
        if name in HOOKS and value.strip():
            found[name] = value.strip()
    return found


def container_hook_names(name: str) -> list[str] | None:
    """Which lab hooks a running container carries (names only), None if it is gone."""
    out = subprocess.run(["docker", "inspect", "-f", "{{json .Config.Env}}", name],
                         capture_output=True, text=True)
    if out.returncode != 0:
        return None
    present = []
    for item in json.loads(out.stdout or "[]"):
        key, _, value = item.partition("=")
        if key in HOOKS and value.strip():
            present.append(key)
    return sorted(present)

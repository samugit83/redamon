#!/usr/bin/env python3
"""The Tradecraft 2.0 end-to-end matrix runner (phase 10, T10.3).

Runs the matrix of ``scenarios.yaml`` against the local stack: per run a fresh lab
instance (``labs.py``) and a fresh project, the scenario's prompt sent to the agent over
the chat socket (as the drawer does: a ticket from ``/api/agent/ws-ticket``, then the
``init`` and ``query`` frames), the run read back (conversation rows, the session's agent
log, the page-store counts), the lab's oracle (``oracles.py``) and the checks
(``checks.py``), on up to ``--lanes`` lanes at once (``lanes.py``), with a 40-minute cap per
run and a budget guard at 4:20; then the report (``report.py``).

Standard library only, host Python 3. Credentials are read from the repository's ``.env``
inline and never printed: every printed line and written file goes through a redactor that
holds them. Nothing here starts, stops or rebuilds a container of the stack: the runner
creates lab projects named ``tc-e2e-*`` and reads the stack's database and logs.

  python3 tooling/scripts/tradecraft_e2e/runner.py --dry-run            # the plan, no stack
  python3 tooling/scripts/tradecraft_e2e/runner.py --lanes 7 --model <id>   # the full matrix
  python3 tooling/scripts/tradecraft_e2e/runner.py --only L3-A-1 --only L4-A-1 --lanes 2 --model <id>
"""
from __future__ import annotations

import argparse
import base64
import datetime as _dt
import hashlib
import json
import os
import re
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tooling.scripts.tradecraft_e2e import checks, labs, lanes, oracles, report  # noqa: E402

HERE = Path(__file__).resolve().parent
SCENARIOS = HERE / "scenarios.yaml"
RUNS_DIR = REPO / "_local" / "tradecraft-e2e" / "runs"
SNAPSHOT_DIR = REPO / "_local" / "tradecraft-e2e" / "library"
LOGS_DIR = REPO / "agentic" / "logs"
POSTGRES_CONTAINER = "redamon-postgres"
WEBAPP_CONTAINER = "redamon-webapp"
AGENT_CONTAINER = "redamon-agent"

# --------------------------------------------------------------------------------------
# A small YAML reader (the subset scenarios.yaml is written in)
# --------------------------------------------------------------------------------------


class YamlError(ValueError):
    pass


_BLOCK_SCALAR = re.compile(r"^[|>][-+]?$")
# YAML 1.1 readers (PyYAML) take these for booleans, YAML 1.2 for strings: refused unquoted.
_AMBIGUOUS = {"yes", "no", "on", "off"}
_INT = re.compile(r"^[-+]?\d+$")
_FLOAT = re.compile(r"^[-+]?(\d+\.\d*|\.\d+)([eE][-+]?\d+)?$")


def _strip_comment(text: str) -> str:
    """``text`` without a trailing ``# comment``. A quote opens a string only where a value
    starts, so the apostrophe of ``a collaborator's chat`` is plain text."""
    quote = None
    prev = " "
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                if quote == "'" and i + 1 < len(text) and text[i + 1] == "'":
                    continue
                quote = None
        elif ch in "\"'" and (prev in " \t[{,:-" or i == 0):
            quote = ch
        elif ch == "#" and prev in " \t":
            return text[:i].rstrip()
        prev = ch
    return text.rstrip()


_VALUE_START = " \t[{,:-"


def _opens_quote(text: str, i: int) -> bool:
    """A quote opens a string only where a value starts (after ``: ``, ``- ``, ``[``, ``{``, ``,``)."""
    before = text[:i].rstrip(" \t")
    return text[i] in "\"'" and (not before or before[-1] in _VALUE_START)


def _split_top(text: str, sep: str) -> list[str]:
    parts, depth, quote, cur = [], 0, None, []
    for i, ch in enumerate(text):
        if quote:
            cur.append(ch)
            if ch == quote and not (quote == '"' and text[i - 1] == "\\"):
                quote = None
            continue
        if _opens_quote(text, i):
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    parts.append("".join(cur))
    return parts


def _key_split(text: str) -> Optional[tuple[str, str]]:
    """``key: value`` (or ``key:``) at the top level of ``text``, outside quotes and brackets."""
    depth, quote = 0, None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "\"'" and i == 0:
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == ":" and depth == 0 and (i + 1 == len(text) or text[i + 1] in " \t"):
            return text[:i].strip(), text[i + 1:].strip()
    return None


def _scalar(text: str) -> Any:
    t = text.strip()
    if not t:
        return None
    if t[0] == '"':
        if not t.endswith('"') or len(t) < 2:
            raise YamlError(f"unterminated string: {t}")
        return json.loads(t)
    if t[0] == "'":
        if not t.endswith("'") or len(t) < 2:
            raise YamlError(f"unterminated string: {t}")
        return t[1:-1].replace("''", "'")
    if t[0] in "[{":
        return _flow(t)
    if t.lower() in _AMBIGUOUS:
        raise YamlError(f"ambiguous plain value {t!r}: quote it or use true/false")
    if t in ("null", "Null", "NULL", "~"):
        return None
    if t in ("true", "True", "TRUE"):
        return True
    if t in ("false", "False", "FALSE"):
        return False
    if _INT.match(t):
        return int(t)
    if _FLOAT.match(t):
        return float(t)
    if t[0] in "&*!|>%@`":
        raise YamlError(f"unsupported YAML: {t}")
    return t


def _key(text: str) -> Any:
    if text[:1] in "\"'":
        return _scalar(text)
    if text.lower() in _AMBIGUOUS:
        raise YamlError(f"ambiguous key {text!r}: quote it")
    return text


def _flow(text: str) -> Any:
    t = text.strip()
    if t.startswith("["):
        if not t.endswith("]"):
            raise YamlError(f"unclosed list: {t}")
        inner = t[1:-1].strip()
        return [] if not inner else [_scalar(p) for p in _split_top(inner, ",") if p.strip()]
    if t.startswith("{"):
        if not t.endswith("}"):
            raise YamlError(f"unclosed mapping: {t}")
        inner = t[1:-1].strip()
        out = {}
        for part in ([] if not inner else _split_top(inner, ",")):
            kv = _key_split(part.strip())
            if kv is None:
                raise YamlError(f"not a key: value pair: {part}")
            out[_key(kv[0])] = _scalar(kv[1])
        return out
    return _scalar(t)


def _balanced(text: str) -> bool:
    depth, quote = 0, None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif _opens_quote(text, i):
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
    return depth <= 0


class _Yaml:
    def __init__(self, text: str):
        self.lines = text.replace("\t", "    ").splitlines()
        self.i = 0

    @staticmethod
    def _indent(line: str) -> int:
        return len(line) - len(line.lstrip(" "))

    def _skip(self) -> None:
        while self.i < len(self.lines):
            s = self.lines[self.i].strip()
            if s and not s.startswith("#") and s != "---":
                return
            self.i += 1

    def _content(self) -> str:
        return _strip_comment(self.lines[self.i].strip())

    def parse(self) -> Any:
        self._skip()
        if self.i >= len(self.lines):
            return None
        value = self._block(self._indent(self.lines[self.i]))
        self._skip()
        if self.i < len(self.lines):
            raise YamlError(f"line {self.i + 1}: unexpected content")
        return value

    def _block(self, indent: int) -> Any:
        c = self._content()
        if c == "-" or c.startswith("- "):
            return self._seq(indent)
        if _key_split(c) is not None:
            return self._map(indent)
        return self._value_lines(c)

    def _value_lines(self, first: str) -> Any:
        text = first
        self.i += 1
        while text[:1] in "[{" and not _balanced(text) and self.i < len(self.lines):
            text += " " + _strip_comment(self.lines[self.i].strip())
            self.i += 1
        return _scalar(text)

    def _nested(self, indent: int, allow_seq_same: bool) -> Any:
        self._skip()
        if self.i >= len(self.lines):
            return None
        ind = self._indent(self.lines[self.i])
        c = self._content()
        if ind > indent or (allow_seq_same and ind == indent and (c == "-" or c.startswith("- "))):
            return self._block(ind)
        return None

    def _block_scalar(self, style: str, parent_indent: int) -> str:
        self.i += 1
        raw: list[str] = []
        block_indent = None
        while self.i < len(self.lines):
            line = self.lines[self.i]
            if line.strip():
                ind = self._indent(line)
                if ind <= parent_indent:
                    break
                block_indent = ind if block_indent is None else block_indent
                if ind < block_indent:
                    break
                raw.append(line[block_indent:])
            else:
                raw.append("")
            self.i += 1
        while raw and raw[-1] == "":
            raw.pop()
        if style[0] == "|":
            text = "\n".join(raw)
        else:
            paras, cur = [], []
            for line in raw:
                if line == "":
                    paras.append(" ".join(cur))
                    cur = []
                else:
                    cur.append(line)
            paras.append(" ".join(cur))
            text = "\n".join(paras)
        return text if style.endswith("-") else text + "\n"

    def _map(self, indent: int) -> dict:
        out: dict = {}
        while True:
            self._skip()
            if self.i >= len(self.lines):
                return out
            ind = self._indent(self.lines[self.i])
            if ind < indent:
                return out
            if ind > indent:
                raise YamlError(f"line {self.i + 1}: bad indentation")
            c = self._content()
            if c == "-" or c.startswith("- "):
                return out
            kv = _key_split(c)
            if kv is None:
                raise YamlError(f"line {self.i + 1}: expected key: value")
            key = _key(kv[0])
            if key in out:
                raise YamlError(f"line {self.i + 1}: duplicate key {key}")
            rest = kv[1]
            if rest == "":
                self.i += 1
                out[key] = self._nested(indent, allow_seq_same=True)
            elif _BLOCK_SCALAR.match(rest):
                out[key] = self._block_scalar(rest, indent)
            else:
                out[key] = self._value_lines(rest)

    def _seq(self, indent: int) -> list:
        out: list = []
        while True:
            self._skip()
            if self.i >= len(self.lines):
                return out
            ind = self._indent(self.lines[self.i])
            if ind < indent:
                return out
            if ind > indent:
                raise YamlError(f"line {self.i + 1}: bad indentation")
            c = self._content()
            if not (c == "-" or c.startswith("- ")):
                return out
            rest = c[1:].strip()
            if rest == "":
                self.i += 1
                out.append(self._nested(indent, allow_seq_same=False))
            elif rest[:1] not in "[{\"'" and _key_split(rest) is not None:
                # "- key: value": a mapping whose keys sit where this key starts.
                self.lines[self.i] = " " * (ind + (len(c) - len(rest))) + rest
                out.append(self._map(ind + (len(c) - len(rest))))
            else:
                out.append(self._value_lines(rest))


def load_yaml(text: str) -> Any:
    return _Yaml(text).parse()


def load_scenarios(path: Path = SCENARIOS) -> dict:
    scn = load_yaml(path.read_text(encoding="utf-8"))
    for key in ("budget", "lanes", "labs", "arms", "singles", "layer1"):
        if key not in scn:
            raise YamlError(f"{path.name}: no {key} section")
    for arm, spec in scn["arms"].items():
        for lab in spec["labs"]:
            if lab not in scn["labs"]:
                raise YamlError(f"{path.name}: arm {arm} names an unknown lab {lab}")
    for check, spec in scn["singles"].items():
        if spec.get("lab") is not None and spec["lab"] not in scn["labs"]:
            raise YamlError(f"{path.name}: {check} names an unknown lab")
    return scn


# --------------------------------------------------------------------------------------
# .env, logging, clock
# --------------------------------------------------------------------------------------

ENV_KEYS = ("UI_LOGIN_USERNAME", "UI_LOGIN_PASSWORD", "MCP_SERVER_TOKEN", "WEBAPP_PORT", "AGENT_PORT",
            "AGENT_IN_THE_LOOP_ENABLED", "MCP_SERVER_ENABLED", "RBAC_SHARING_ENABLED", "RBAC_SHARING_WRITE_ENABLED",
            "RBAC_PERMISSIONS_ENABLED")
OPTIONAL_ENV_KEYS = ("WEBAPP_PORT", "AGENT_PORT")
# Values never printed. The admin's login name is personal data, so it is scrubbed too.
SECRET_ENV_KEYS = ("UI_LOGIN_USERNAME", "UI_LOGIN_PASSWORD", "MCP_SERVER_TOKEN")


class Env:
    """The few ``.env`` values the runner needs; ``repr`` and ``str`` name the keys only."""

    def __init__(self, values: Mapping[str, str]):
        self._values = dict(values)

    def get(self, key: str, default: str = "") -> str:
        return self._values.get(key, default)

    def flag(self, key: str) -> bool:
        return self.get(key).strip().lower() in ("1", "true", "yes", "on")

    def present(self) -> dict[str, bool]:
        return {k: bool(self._values.get(k)) for k in ENV_KEYS}

    def __repr__(self) -> str:
        return f"Env(keys={sorted(k for k, v in self._values.items() if v)})"

    __str__ = __repr__


def read_env(path: Path, redact: report.Redactor) -> Env:
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return Env({})
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        key = key.strip()
        if sep and key in ENV_KEYS:
            values[key] = value.strip().strip("'\"")
    redact.add(*(values.get(k) for k in SECRET_ENV_KEYS))
    return Env(values)


class Log:
    def __init__(self, redact: report.Redactor, stream=None, prefix: str = "[tc-e2e]"):
        self.redact = redact
        self.stream = stream
        self.prefix = prefix
        self._lock = threading.Lock()

    def __call__(self, msg: str) -> None:
        line = self.redact(f"{_dt.datetime.now().strftime('%H:%M:%S')} {self.prefix} {msg}")
        with self._lock:
            print(line, file=self.stream or sys.stdout, flush=True)


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


# --------------------------------------------------------------------------------------
# HTTP (one person's session) and the WebSocket client
# --------------------------------------------------------------------------------------

@dataclass
class Response:
    status: int
    data: Any = None
    text: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def code(self) -> str:
        return str(self.data.get("code", "")) if isinstance(self.data, dict) else ""


class Http:
    """A person's session with the webapp: its own cookies, the same-origin header the
    mutating routes ask for, JSON in and out. Errors name the status and a code, never a
    header or a cookie."""

    def __init__(self, base: str, *, timeout: float = 60, opener: Optional[Callable] = None, origin: bool = True):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.cookies: dict[str, str] = {}
        self.origin = origin
        self._open = opener or urllib.request.build_opener(_NoRedirect()).open

    def _remember(self, headers) -> None:
        for raw in headers.get_all("Set-Cookie") or []:
            pair = raw.split(";", 1)[0]
            name, _, value = pair.partition("=")
            gone = re.search(r"(?i)max-age=0|expires=thu, 01 jan 1970", raw)
            if gone or value == "":
                self.cookies.pop(name.strip(), None)
            else:
                self.cookies[name.strip()] = value.strip()

    def call(self, method: str, path: str, body: Any = None, *, headers: Optional[Mapping] = None,
             timeout: Optional[float] = None) -> Response:
        hdrs = {"Accept": "application/json", **({"Origin": self.base} if self.origin else {})}
        if body is not None:
            hdrs["Content-Type"] = "application/json"
        if self.cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        hdrs.update(headers or {})
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=hdrs)
        try:
            with self._open(req, timeout=timeout or self.timeout) as resp:
                self._remember(resp.headers)
                raw, status = resp.read(), resp.status
        except urllib.error.HTTPError as err:
            self._remember(err.headers)
            raw, status = err.read(), err.code
        except (urllib.error.URLError, OSError) as err:
            return Response(0, error=type(getattr(err, "reason", err)).__name__)
        text = raw.decode("utf-8", "replace")
        try:
            parsed = json.loads(text) if text else None
        except ValueError:
            parsed = None
        return Response(status, parsed, text)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # a redirect is an answer to read, not to follow
        return None


WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG, OP_CONT = 0x1, 0x2, 0x8, 0x9, 0xA, 0x0


def ws_accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()


def ws_frame(opcode: int, payload: bytes, *, mask: Optional[bytes] = None, fin: bool = True) -> bytes:
    """One RFC 6455 frame; a client masks every frame (``mask``: 4 bytes)."""
    head = bytes([(0x80 if fin else 0) | opcode])
    n = len(payload)
    bit = 0x80 if mask is not None else 0
    if n < 126:
        head += bytes([bit | n])
    elif n < 65536:
        head += bytes([bit | 126]) + struct.pack("!H", n)
    else:
        head += bytes([bit | 127]) + struct.pack("!Q", n)
    if mask is None:
        return head + payload
    return head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


def ws_parse(buf: bytes) -> Optional[tuple[int, bool, bytes, int]]:
    """(opcode, fin, payload, bytes used) of the first whole frame in ``buf``, or None."""
    if len(buf) < 2:
        return None
    fin, opcode = bool(buf[0] & 0x80), buf[0] & 0x0F
    masked, n, at = bool(buf[1] & 0x80), buf[1] & 0x7F, 2
    if n == 126:
        if len(buf) < 4:
            return None
        n, at = struct.unpack("!H", buf[2:4])[0], 4
    elif n == 127:
        if len(buf) < 10:
            return None
        n, at = struct.unpack("!Q", buf[2:10])[0], 10
    key = b""
    if masked:
        if len(buf) < at + 4:
            return None
        key, at = buf[at:at + 4], at + 4
    if len(buf) < at + n:
        return None
    payload = buf[at:at + n]
    if masked:
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return opcode, fin, payload, at + n


class WebSocket:
    """A minimal client: one text message at a time, pings answered, fragments joined."""

    def __init__(self, url: str, *, timeout: float = 30, connect: Callable = socket.create_connection):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "ws":
            raise ValueError("ws:// only: the agent's socket on the local host")
        self.sock = connect((parts.hostname, parts.port or 80), timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        self.sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {parts.netloc}\r\nUpgrade: websocket\r\n"
                           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("the socket closed during the handshake")
            self.buf += chunk
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        if " 101 " not in lines[0] + " ":
            raise ConnectionError(f"handshake refused: {lines[0][:60]}")
        accept = next((ln.split(":", 1)[1].strip() for ln in lines[1:] if ln.lower().startswith("sec-websocket-accept:")), "")
        if accept != ws_accept(key):
            raise ConnectionError("handshake answered a wrong Sec-WebSocket-Accept")
        self.closed = False

    def send_text(self, text: str) -> None:
        self.sock.sendall(ws_frame(OP_TEXT, text.encode(), mask=os.urandom(4)))

    def send_json(self, obj: Any) -> None:
        self.send_text(json.dumps(obj))

    def recv_text(self, timeout: float) -> Optional[str]:
        """The next text message, or None when ``timeout`` passes first; raises
        ConnectionError when the server closed."""
        deadline = time.monotonic() + timeout
        parts: list[bytes] = []
        while True:
            frame = ws_parse(self.buf)
            if frame is None:
                left = deadline - time.monotonic()
                if left <= 0:
                    return None
                self.sock.settimeout(left)
                try:
                    chunk = self.sock.recv(65536)
                except socket.timeout:
                    return None
                if not chunk:
                    self.closed = True
                    raise ConnectionError("the agent closed the socket")
                self.buf += chunk
                continue
            opcode, fin, payload, used = frame
            self.buf = self.buf[used:]
            if opcode == OP_PING:
                self.sock.sendall(ws_frame(OP_PONG, payload, mask=os.urandom(4)))
            elif opcode == OP_CLOSE:
                self.closed = True
                raise ConnectionError("the agent closed the socket")
            elif opcode in (OP_TEXT, OP_BINARY, OP_CONT):
                parts.append(payload)
                if fin:
                    return b"".join(parts).decode("utf-8", "replace")

    def recv_json(self, timeout: float) -> Optional[dict]:
        text = self.recv_text(timeout)
        if text is None:
            return None
        try:
            return json.loads(text)
        except ValueError:
            return {"type": "unparsed"}

    def close(self) -> None:
        if not self.closed:
            try:
                self.sock.sendall(ws_frame(OP_CLOSE, struct.pack("!H", 1000), mask=os.urandom(4)))
            except OSError:
                pass
        try:
            self.sock.close()
        except OSError:
            pass
        self.closed = True


# --------------------------------------------------------------------------------------
# The stack: its database (read), the seed of the e2e accounts, and the routes
# --------------------------------------------------------------------------------------

Exec = Callable[..., subprocess.CompletedProcess]


def lit(value: Any) -> str:
    """A SQL literal for an id or a number the runner holds (never page text)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    if any(ord(ch) < 32 for ch in text):
        raise ValueError("a control character in a SQL literal")
    return "'" + text.replace("'", "''") + "'"


class Db:
    """Read-only queries on the stack's database, through ``psql`` in its container (as
    ``testing/guinea_pigs/skiller_*.sh`` do). Each query answers one JSON value."""

    def __init__(self, run: Exec = subprocess.run, container: str = POSTGRES_CONTAINER):
        self._run = run
        self.container = container

    def json(self, sql: str, timeout: int = 60) -> Any:
        wrapped = f"SELECT coalesce(json_agg(t), '[]'::json) FROM ({sql}) t;"
        done = self._run(["docker", "exec", "-i", self.container, "sh", "-c",
                          'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At -v ON_ERROR_STOP=1 '
                          '-c "SET default_transaction_read_only = on" -f -'],
                         input=wrapped, capture_output=True, text=True, timeout=timeout, check=False)
        if done.returncode != 0:
            raise RuntimeError(f"psql failed (exit {done.returncode})")
        lines = [ln for ln in (done.stdout or "").splitlines() if ln.strip() and ln.strip() != "SET"]
        # json_agg writes one element per line: the answer is the whole output, not its last line.
        return json.loads("\n".join(lines)) if lines else []


def page_store_counts(db: Db, owner_id: str) -> dict:
    o = lit(owner_id)
    rows = db.json(
        "SELECT "
        f"(SELECT count(*) FROM user_tradecraft_resources WHERE user_id = {o}) AS resources, "
        "(SELECT count(*) FROM tradecraft_page_ids p JOIN user_tradecraft_resources r ON r.id = p.resource_id "
        f"WHERE r.user_id = {o}) AS page_ids, "
        f"(SELECT count(*) FROM tradecraft_entries WHERE user_id = {o}) AS entries, "
        f"(SELECT coalesce(sum(stored_bytes), 0) FROM tradecraft_entries WHERE user_id = {o}) AS stored_bytes, "
        f"(SELECT count(*) FROM tradecraft_sections WHERE user_id = {o}) AS sections, "
        f"(SELECT count(*) FROM tradecraft_tree_nodes WHERE user_id = {o}) AS tree_nodes, "
        "(SELECT count(*) FROM tradecraft_curations c JOIN user_tradecraft_resources r ON r.id = c.resource_id "
        f"WHERE r.user_id = {o}) AS curations, "
        f"(SELECT count(*) FROM tradecraft_ingestion_jobs WHERE user_id = {o}) AS jobs")
    return {k: int(v) for k, v in (rows[0] if rows else {}).items()}


def page_cards(db: Db, owner_id: str, page_ids: Iterable[str], with_text: Iterable[str] = ()) -> dict:
    wanted = {}
    for pid in page_ids:
        slug, _, n = pid.rpartition(":")
        if slug and n.isdigit():
            wanted[int(n)] = slug
    if not wanted:
        return {}
    texts = {int(p.rpartition(":")[2]) for p in with_text if p.rpartition(":")[2].isdigit()}
    rows = db.json(
        "SELECT r.slug, r.name AS resource_name, p.id AS n, e.title, e.breadcrumb, e.url, e.description, r.storage_mode, "
        f"CASE WHEN p.id IN ({','.join(str(t) for t in texts) or 'NULL'}) THEN e.stored_text END AS text "
        "FROM tradecraft_entries e JOIN tradecraft_page_ids p ON p.id = e.page_id "
        "JOIN user_tradecraft_resources r ON r.id = e.resource_id "
        f"WHERE e.user_id = {lit(owner_id)} AND e.generation = r.generation "
        f"AND p.id IN ({','.join(str(n) for n in wanted)})")
    out = {}
    for row in rows:
        if wanted.get(int(row["n"])) == row["slug"]:
            out[f"{row['slug']}:{row['n']}"] = {k: row[k] for k in ("resource_name", "title", "breadcrumb", "url",
                                                                      "description", "storage_mode", "text")}
    return out


SEED_SCRIPT = """
import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcryptjs'
const ACCOUNTS = __ACCOUNTS__
const prisma = new PrismaClient()
const ids = {}
try {
  for (const a of ACCOUNTS) {
    const hash = await bcrypt.hash(a.password, 12)
    const user = await prisma.user.upsert({
      where: { email: a.email },
      update: { password: hash, role: 'standard', name: a.name },
      create: { email: a.email, password: hash, role: 'standard', name: a.name },
    })
    await prisma.tradecraftUserSettings.upsert({
      where: { userId: user.id },
      update: { v2Enabled: true },
      create: { userId: user.id, v2Enabled: true, v2EnabledAt: new Date() },
    })
    ids[a.key] = user.id
  }
  console.log('TC_E2E_IDS=' + JSON.stringify(ids))
} finally {
  await prisma.$disconnect()
}
"""


@dataclass
class Account:
    key: str
    email: str
    password: str = field(repr=False)
    id: str = ""


# The only accounts the matrix and the library tooling may create, sign in as, snapshot or
# restore, whatever scenarios.yaml says: the seed resets a password and a role, and restore
# replaces a whole library, so a real person's address must never reach them.
E2E_ACCOUNTS = frozenset({"tc-e2e-owner@e2e.local", "tc-e2e-collab@e2e.local", "tc-e2e-ops@e2e.local"})


def e2e_account_problem(email: str) -> Optional[str]:
    if email not in E2E_ACCOUNTS:
        return f"{email!r} is not one of the synthetic e2e accounts ({', '.join(sorted(E2E_ACCOUNTS))})"
    return None


def seed_accounts(emails: Mapping[str, str], redact: report.Redactor, run: Exec = subprocess.run,
                  container: str = WEBAPP_CONTAINER) -> dict[str, Account]:
    """Creates or updates the synthetic e2e accounts with fresh random passwords (kept in
    memory, scrubbed from every output) and Tradecraft 2.0 on. Their libraries, settings and
    model providers are left as they are. The script goes to node on stdin, so no value
    reaches a command line. Any other address is refused before anything runs."""
    refused = [p for p in (e2e_account_problem(e) for e in emails.values()) if p]
    if refused:
        raise ValueError("; ".join(refused))
    accounts = {k: Account(k, e, secrets.token_urlsafe(24)) for k, e in emails.items()}
    redact.add(*(a.password for a in accounts.values()))
    payload = json.dumps([{"key": a.key, "email": a.email, "password": a.password, "name": f"Tradecraft E2E {a.key}"}
                          for a in accounts.values()])
    done = run(["docker", "exec", "-i", "-w", "/app", container, "node", "--input-type=module", "-"],
               input=SEED_SCRIPT.replace("__ACCOUNTS__", payload), capture_output=True, text=True, timeout=180,
               check=False)
    line = next((ln for ln in (done.stdout or "").splitlines() if ln.startswith("TC_E2E_IDS=")), "")
    if done.returncode != 0 or not line:
        raise RuntimeError(f"seeding the e2e accounts failed (exit {done.returncode})")
    for key, uid in json.loads(line.split("=", 1)[1]).items():
        accounts[key].id = uid
    return accounts


class Stack:
    """The routes the runner calls, each as the person whose session it holds."""

    def __init__(self, env: Env, redact: report.Redactor, log: Log):
        self.env = env
        self.redact = redact
        self.log = log
        self.webapp = f"http://localhost:{env.get('WEBAPP_PORT') or '3000'}"
        self.agent_ws = f"ws://localhost:{env.get('AGENT_PORT') or '8090'}/ws/agent"
        self.agent_http = f"http://localhost:{env.get('AGENT_PORT') or '8090'}"

    def session(self, email: str, password: str) -> tuple[Http, str]:
        http = Http(self.webapp)
        res = http.call("POST", "/api/auth/login", {"email": email, "password": password})
        if not res.ok:
            raise RuntimeError(f"sign-in failed ({res.status} {res.code})")
        for value in http.cookies.values():
            self.redact.add(value)
        me = http.call("GET", "/api/auth/me")
        if not me.ok or not isinstance(me.data, dict):
            raise RuntimeError(f"/api/auth/me answered {me.status}")
        uid = str(me.data.get("id") or (me.data.get("user") or {}).get("id") or "")
        return http, uid

    @staticmethod
    def create_project(http: Http, name: str, fields: Mapping) -> str:
        res = http.call("POST", "/api/projects", {"name": name, **fields})
        if not res.ok or not isinstance(res.data, dict) or not res.data.get("id"):
            raise RuntimeError(f"project create answered {res.status} {res.code}")
        return str(res.data["id"])

    @staticmethod
    def update_project(http: Http, project_id: str, fields: Mapping) -> Response:
        current = http.call("GET", f"/api/projects/{project_id}")
        if not current.ok or not isinstance(current.data, dict):
            return current
        return http.call("PUT", f"/api/projects/{project_id}", {**fields, "updatedAt": current.data.get("updatedAt")})

    @staticmethod
    def delete_project(http: Http, project_id: str) -> Response:
        return http.call("DELETE", f"/api/projects/{project_id}")


def project_fields(scn: Mapping, *, target_ip: Optional[str], model: str) -> dict:
    cfg = dict(scn.get("project") or {})
    phases = cfg.pop("tradecraft_phases", None)
    fields = cfg
    fields["agentOpenaiModel"] = model
    if target_ip:
        fields.update({"ipMode": True, "targetIps": [target_ip]})
    else:
        # A documentation address (RFC 5737): a single check with no lab has no target.
        fields.update({"ipMode": True, "targetIps": ["192.0.2.10"]})
    if phases:
        fields["_tradecraft_phases"] = list(phases)
    return fields


def apply_phase_map(http: Http, project_id: str, phases: Sequence[str]) -> None:
    """Offers the library tools in ``phases`` (tradecraft_lookup's phases govern all three).
    Raises when it did not take: arm B's "nothing offered" would then hold on nothing."""
    current = http.call("GET", f"/api/projects/{project_id}")
    if not current.ok or not isinstance(current.data, dict):
        raise RuntimeError(f"reading the project answered {current.status} {current.code}")
    phase_map = dict(current.data.get("agentToolPhaseMap") or {})
    phase_map["tradecraft_lookup"] = list(phases)
    res = http.call("PUT", f"/api/projects/{project_id}",
                    {"agentToolPhaseMap": phase_map, "updatedAt": current.data.get("updatedAt")})
    after = http.call("GET", f"/api/projects/{project_id}")
    saved = ((after.data or {}).get("agentToolPhaseMap") or {}).get("tradecraft_lookup") if isinstance(after.data, dict) else None
    if not res.ok or saved != list(phases):
        raise RuntimeError(f"the tool phase map did not save ({res.status} {res.code})")


# --------------------------------------------------------------------------------------
# One chat run over the socket, and the Agent in the Loop driver
# --------------------------------------------------------------------------------------

AUTO_ANSWER = ("No person is available during this automated test run. Proceed on your own with the most "
               "reasonable choice, within the target and scope already given.")
END_TYPES = {"task_complete", "stopped"}
# Error frames after which the run does not go on, though marked recoverable (websocket_api.py):
# the query itself failed, for example on a model the owner's provider does not serve.
RUN_FAILED_CODES = {"query_failed", "fatal_error"}


@dataclass
class ChatOutcome:
    session_id: str
    ended: str = "running"  # complete | stopped | error | cap | disconnected
    error_code: str = ""
    question_sent: bool = False
    approvals: list[str] = field(default_factory=list)
    rate_limit_waits: int = 0
    frames: dict = field(default_factory=dict)
    seconds: float = 0.0


def new_session_id() -> str:
    return f"session_{secrets.token_hex(16)}"


def ws_ticket(http: Http, project_id: str, session_id: str) -> str:
    res = http.call("POST", "/api/agent/ws-ticket", {"projectId": project_id, "sessionId": session_id})
    if not res.ok or not isinstance(res.data, dict) or not res.data.get("ticket"):
        raise RuntimeError(f"ws-ticket answered {res.status} {res.code}")
    return str(res.data["ticket"])


def run_chat(stack: Stack, http: Http, person_id: str, project_id: str, question: str, *, cap_sec: float,
             session_id: Optional[str] = None, socket_factory: Callable[[str], WebSocket] = WebSocket,
             clock: Callable[[], float] = time.monotonic, on_frame: Optional[Callable[[dict], None]] = None) -> ChatOutcome:
    """Sends ``question`` and follows the run until it ends or ``cap_sec`` passes (then
    stops it). Approvals, tool confirmations and questions are answered and recorded."""
    out = ChatOutcome(session_id or new_session_id())
    start = clock()
    deadline = start + cap_sec
    sent = False
    reconnects = 0
    ws: Optional[WebSocket] = None
    try:
        while out.ended == "running":
            if ws is None:
                ticket = ws_ticket(http, project_id, out.session_id)
                stack.redact.add(ticket)
                try:
                    ws = socket_factory(stack.agent_ws)
                except (ConnectionError, OSError):
                    reconnects += 1
                    if reconnects > 5:
                        out.ended = "disconnected"
                    time.sleep(5)
                    continue
                ws.send_json({"type": "init", "payload": {"user_id": person_id, "project_id": project_id,
                                                          "session_id": out.session_id, "ticket": ticket}})
            if clock() >= deadline:
                out.ended = "cap"
                ws.send_json({"type": "stop", "payload": {}})
                _drain_until(ws, {"stopped", "task_complete"}, 90, out)
                break
            try:
                msg = ws.recv_json(timeout=min(30.0, max(0.5, deadline - clock())))
            except ConnectionError:
                ws.close()
                ws = None
                reconnects += 1
                if reconnects > 5:
                    out.ended = "disconnected"
                continue
            if msg is None:
                ws.send_json({"type": "ping", "payload": {}})
                continue
            kind = str(msg.get("type", ""))
            out.frames[kind] = out.frames.get(kind, 0) + 1
            if on_frame:
                on_frame(msg)
            payload = msg.get("payload") or {}
            if kind == "connected" and not sent:
                ws.send_json({"type": "query", "payload": {"question": question}})
                sent = out.question_sent = True
            elif kind == "connected" and payload.get("agent_running") is False:
                # A reconnect after the run ended: its last frames went to the closed socket.
                out.ended = "complete"
            elif kind == "approval_request":
                ws.send_json({"type": "approval", "payload": {"decision": "approve"}})
                out.approvals.append("phase transition")
            elif kind == "tool_confirmation_request":
                ws.send_json({"type": "tool_confirmation", "payload": {"decision": "approve"}})
                out.approvals.append("tool confirmation")
            elif kind == "fireteam_member_awaiting_confirmation":
                ws.send_json({"type": "fireteam_member_confirmation", "payload": {
                    "wave_id": payload.get("wave_id"), "member_id": payload.get("member_id"), "decision": "approve"}})
                out.approvals.append("fireteam member confirmation")
            elif kind == "question_request":
                ws.send_json({"type": "answer", "payload": {"answer": AUTO_ANSWER}})
                out.approvals.append("question")
            elif kind == "rate_limit_wait":
                out.rate_limit_waits += 1
            elif kind == "error" and (payload.get("recoverable") is False or payload.get("code") in RUN_FAILED_CODES):
                out.ended, out.error_code = "error", str(payload.get("code", ""))
            elif kind in END_TYPES and sent:
                out.ended = "complete" if kind == "task_complete" else "stopped"
    finally:
        if ws is not None:
            ws.close()
        out.seconds = clock() - start
    return out


def _drain_until(ws: WebSocket, kinds: set, seconds: float, out: ChatOutcome) -> None:
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        try:
            msg = ws.recv_json(timeout=max(0.5, until - time.monotonic()))
        except ConnectionError:
            return
        if msg and msg.get("type") in kinds:
            return


# loop_wait_step's answer for a session whose conversation does not exist yet (lib/mcp/loopTools.ts).
SESSION_NOT_YET = "Session not found"


class LoopDriver:
    """Plays the external agent of an Agent in the Loop run over ``/api/mcp-server`` (the
    port of ``testing/e2e/tests/aitlDriver.ts``), scoped to one session."""

    # Refusals in a row after which the driver gives up: the endpoint will not take it.
    MAX_REFUSALS = 5

    def __init__(self, base: str, token: str, session_id: str, opener: Optional[Callable] = None,
                 sleep: Callable[[float], None] = time.sleep):
        # An MCP client is not a browser: no Origin, which the endpoint refuses unless it is its own
        # (api/mcp-server/route.ts originAllowed).
        self.http = Http(base, timeout=120, opener=opener, origin=False)
        self.token = token
        self.session_id = session_id
        self.prompts: list[str] = []
        self.refused = ""
        self._sleep = sleep
        self._id = 0

    def call(self, name: str, args: Mapping) -> tuple[bool, Any, str]:
        self._id += 1
        res = self.http.call("POST", "/api/mcp-server",
                             {"jsonrpc": "2.0", "id": self._id, "method": "tools/call",
                              "params": {"name": name, "arguments": dict(args)}},
                             headers={"Authorization": f"Bearer {self.token}",
                                      "Accept": "application/json, text/event-stream"})
        body = res.data if isinstance(res.data, dict) else {}
        result = body.get("result") or {}
        text = "\n".join(c.get("text", "") for c in result.get("content") or [] if isinstance(c, dict))
        if not text and body.get("error"):  # a refusal answers a JSON-RPC error, as aitlDriver.ts reads it
            text = json.dumps(body["error"])
        elif not text and not res.ok:
            text = f"HTTP {res.status} {res.code}".strip()
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        return bool(result.get("isError") or body.get("error") or not res.ok), parsed, text

    def next_step(self, timeout: float) -> Optional[dict]:
        until = time.monotonic() + timeout
        refusals = 0
        while time.monotonic() < until:
            err, got, text = self.call("loop_wait_step", {"waitSeconds": 20, "sessionId": self.session_id})
            if err and not self.prompts and SESSION_NOT_YET in text:
                # The chat's conversation does not exist until the run starts (loopTools.ts): wait for
                # it, as aitlDriver.ts names a session only once it exists; the run's cap bounds it.
                self._sleep(2.0)
                continue
            if err:
                # Never a tight loop on a refusal: a pause, and the run's error after a few.
                refusals += 1
                if refusals >= self.MAX_REFUSALS:
                    self.refused = " ".join(text.split())[:160] or "no answer"
                    return None
                self._sleep(2.0)
                continue
            refusals = 0
            step = (got or {}).get("step")
            if step:
                prompt = str(step.get("prompt") or "")
                cursor = (step.get("page") or {}).get("nextCursor")
                while cursor is not None:
                    err, more, _ = self.call("loop_get_step", {"stepId": step["stepId"], "cursor": cursor})
                    page = (more or {}).get("step") or {}
                    prompt += str(page.get("prompt") or "")
                    cursor = (page.get("page") or {}).get("nextCursor") if not err else None
                step["fullPrompt"] = prompt
                self.prompts.append(prompt)
                return step
        return None

    def submit(self, step: Mapping, answer: str) -> bool:
        err, _, _ = self.call("loop_submit_step", {"stepId": step["stepId"], "answer": answer})
        return not err


def loop_answers(target_ip: str) -> dict:
    j = json.dumps
    return {
        "scope_guardrail": j({"allowed": True, "reason": "local lab in scope"}),
        "classify": j({"attack_path_type": "sql_injection", "required_phase": "informational", "confidence": 0.9,
                       "reasoning": "a library question for a lab", "target_host": target_ip, "target_port": 5000}),
        "deep_think": j({"situation_assessment": "a library question", "competing_hypotheses": [],
                         "attack_vectors_identified": ["web application"], "recommended_approach": "ask the library",
                         "priority_order": ["ask the librarian"], "risks_and_mitigations": "read-only"}),
        "report": "# Tradecraft matrix S4\n\nThe driver asked the library once and stopped.",
        "complete": j({"thought": "TC-E2E done", "reasoning": "the check is complete", "action": "complete",
                       "completion_reason": "tradecraft matrix S4 complete", "updated_todo_list": []}),
    }


def drive_loop(driver: LoopDriver, ask_args: Mapping, *, target_ip: str, timeout: float) -> list[str]:
    """Answers the run's setup steps, calls ``tradecraft_ask`` at the first think, then
    completes. The prompts it saw are on ``driver.prompts``; returns what it did."""
    answers = loop_answers(target_ip)
    did: list[str] = []
    asked = False
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        step = driver.next_step(max(5.0, until - time.monotonic()))
        if step is None:
            break
        purpose = step.get("purpose")
        if purpose == "think" and not asked:
            driver.submit(step, json.dumps({
                "thought": "TC-E2E ask the librarian", "reasoning": "the check calls tradecraft_ask once",
                "action": "use_tool", "tool_name": "tradecraft_ask", "tool_args": dict(ask_args),
                "updated_todo_list": []}))
            asked = True
            did.append("think: tradecraft_ask")
        elif purpose == "think":
            driver.submit(step, answers["complete"])
            did.append("think: complete")
        elif purpose == "report":
            driver.submit(step, answers["report"])
            did.append("report")
            break
        elif purpose in answers:
            driver.submit(step, answers[purpose])
            did.append(str(purpose))
        else:
            driver.call("loop_submit_step", {"stepId": step["stepId"], "declined": True,
                                             "reason": "tc-e2e driver: unexpected purpose"})
            did.append(f"declined {purpose}")
    return did


# --------------------------------------------------------------------------------------
# The trace of a run
# --------------------------------------------------------------------------------------

def session_log_path(session_id: str, logs_dir: Path) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", session_id)[:120]
    return logs_dir / f"agent.{safe}.log"


def session_log_text(session_id: str, logs_dir: Path = LOGS_DIR) -> str:
    base = session_log_path(session_id, logs_dir)
    rotated = sorted(logs_dir.glob(f"{base.name}.*"), key=lambda p: -int(p.suffix[1:]) if p.suffix[1:].isdigit() else 0)
    text = ""
    for path in [*rotated, base]:
        try:
            text += path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return text


def session_events(session_id: str, logs_dir: Path = LOGS_DIR) -> dict:
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", session_id)[:120]
    iterations, tokens_in, tokens_out = 0, 0, 0
    try:
        lines = (logs_dir / f"agent.{safe}.events.jsonl").read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}
    for line in lines:
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("kind") == "decision":
            iterations = max(iterations, int(ev.get("iteration") or 0))
            tokens_in += int(ev.get("tokens_in") or 0)
            tokens_out += int(ev.get("tokens_out") or 0)
    return {"iterations": iterations, "tokens_in": tokens_in, "tokens_out": tokens_out}


def agent_logs_dir(run: Exec = subprocess.run, container: str = AGENT_CONTAINER) -> Optional[Path]:
    """The host folder the agent writes its session logs to: the source of its ``/app/logs``
    mount, which is the checkout the stack runs from, not necessarily the runner's."""
    done = run(["docker", "inspect", "--format", "{{json .Mounts}}", container], capture_output=True, text=True,
               check=False, timeout=30)
    try:
        mounts = json.loads(done.stdout or "[]")
    except ValueError:
        return None
    for mount in mounts or []:
        if isinstance(mount, dict) and mount.get("Destination") == "/app/logs" and mount.get("Source"):
            return Path(mount["Source"])
    return None


def conversation_rows(db: Db, session_id: str) -> list[dict]:
    return db.json("SELECT m.type, m.data FROM chat_messages m JOIN conversations c ON c.id = m.conversation_id "
                   f"WHERE c.session_id = {lit(session_id)} ORDER BY m.sequence_num")


def trace_from_rows(rows: Sequence[Mapping]) -> dict:
    calls, answers = [], []
    for row in rows:
        data = row.get("data") or {}
        if row.get("type") in ("tool_complete", "fireteam_tool_complete"):
            calls.append({"tool": data.get("tool_name"), "args": data.get("tool_args") or {},
                          "output": data.get("raw_output") or data.get("output_summary") or "",
                          "success": data.get("success")})
        elif row.get("type") == "assistant_message":
            answers.append(str(data.get("content") or ""))
    return {"tool_calls": calls, "answers": answers}


def wait_until_idle(db: Db, session_id: str, seconds: float = 60) -> bool:
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        rows = db.json(f"SELECT agent_running FROM conversations WHERE session_id = {lit(session_id)}")
        if rows and rows[0].get("agent_running") is False:
            return True
        time.sleep(3)
    return False


def build_trace(db: Db, session_id: str, owner_id: str, *, before: Optional[dict], logs_dir: Path = LOGS_DIR) -> dict:
    trace = trace_from_rows(conversation_rows(db, session_id))
    log_text = session_log_text(session_id, logs_dir)
    trace["log_read"], trace["log_path"] = bool(log_text), str(session_log_path(session_id, logs_dir))
    trace["prompts"] = checks.prompts_from_log(log_text)
    trace["library_now"] = checks.library_now_from_log(log_text)
    trace.update({"events": session_events(session_id, logs_dir), "session_id": session_id})
    trace["page_store"] = {"before": before, "after": page_store_counts(db, owner_id) if before is not None else None}
    results = checks.tradecraft_results(trace)
    now = trace["library_now"]
    named = ({ref.page_id for r in results for ref in r.pages} | {p for s in now["shown"] for p in s["pages"]}
             | {r["page"] for r in now["reads"]})
    picked = {p.page_id for r in results for p in r.picks}
    trace["pages"] = page_cards(db, owner_id, named, with_text=picked) if named else {}
    return trace


def run_problem(outcome: ChatOutcome, trace: Mapping, *, loop: bool = False) -> Optional[str]:
    """Why an agent run did not happen, or None: then, and only then, its checks are judged.
    A run error never counts as a pass."""
    if not outcome.question_sent:
        return "the question was never sent: the agent's socket never connected" + (
            f" ({outcome.error_code})" if outcome.error_code else "")
    if outcome.ended in ("error", "disconnected"):
        return f"the agent run ended: {outcome.ended}" + (f" ({outcome.error_code})" if outcome.error_code else "")
    return checks.loop_evidence(trace) if loop else checks.run_evidence(trace)


# --------------------------------------------------------------------------------------
# The matrix
# --------------------------------------------------------------------------------------

@dataclass
class Context:
    scn: dict
    env: Env
    redact: report.Redactor
    log: Log
    stack: Stack
    db: Db
    docker: labs.Docker
    accounts: dict
    sessions: dict  # key -> (Http, user id)
    model: str
    out_dir: Path
    logs_dir: Path = LOGS_DIR
    resource_ids: dict = field(default_factory=dict)  # slug -> id
    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def reserve_sec(self) -> float:
        return float(self.scn["budget"].get("teardown_reserve_min", 5)) * 60


def time_left(deadline: float, reserve: float = 0.0) -> float:
    """Seconds until ``deadline`` (a ``time.monotonic`` value) less ``reserve``."""
    return deadline - time.monotonic() - reserve


MIN_AGENT_SEC = 60


def _instance(ctx: Context, run: lanes.Run, lane: int, address: lanes.LaneAddressing) -> labs.Instance:
    spec = oracles.specs(ctx.scn)[run.lab]
    inst = labs.plan_instance(spec, run, lane, address, secret_value=oracles.new_secret(spec),
                              suffix=secrets.token_hex(2))
    if spec.kind == "override":
        base = load_yaml((REPO / spec.folder / labs.COMPOSE_FILE).read_text(encoding="utf-8"))
        path = ctx.out_dir / "overrides" / f"{inst.project}.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(labs.override_yaml(spec, base, inst, network=ctx.scn["lanes"]["network"]))
        inst.override_path = path
    return inst


def _wait_http(url: str, seconds: float) -> bool:
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        try:
            with urllib.request.urlopen(url, timeout=5):
                return True
        except urllib.error.HTTPError:
            return True
        except (urllib.error.URLError, OSError):
            time.sleep(2)
    return False


def _tradecraft_off(ctx: Context, resources: Any) -> list[str]:
    ids = ctx.resource_ids
    if resources == "none":
        return sorted(ids.values())
    if isinstance(resources, Mapping):
        return sorted(ids[s] for s in resources.get("turned_off", []) if s in ids)
    return []


def _switches_off(env: Env, *keys: str) -> Optional[str]:
    off = [k for k in keys if not env.flag(k)]
    return f"{report.SKIP_SWITCH_OFF} ({', '.join(off)})" if off else None


def _refused(result: report.RunResult, name: str, res: Response, what: str) -> report.RunResult:
    """A setup step the stack refused, with its switch on: a failure with its reason (MC-10)."""
    result.status = report.FAIL
    result.reason = f"{what} was refused: {res.status} {res.code}".rstrip()
    result.checks = [report.CheckResult(name, False, result.reason)]
    return result


def run_attack(ctx: Context, run: lanes.Run, lane: int, address: lanes.LaneAddressing,
               deadline: float) -> report.RunResult:
    """One run of arm A, B or A-search, or the single checks S1, S2 and S5 (an agent run on
    a project of the owner's, or of a collaborator's share). ``deadline`` bounds the run's
    whole lane time: the agent gets what is left of it less the teardown reserve."""
    result = report.RunResult(run_id=run.id, arm=run.arm, lab=run.lab, n=run.n, check=run.check, lane=lane,
                              started_at=now_iso(), status=report.ERROR)
    single = ctx.scn["singles"].get(run.check or "", {})
    arm = ctx.scn["arms"].get(run.arm, {})
    owner_http, owner_id = ctx.sessions["owner"]
    reserve = ctx.reserve_sec
    collaborator = single.get("as") == "collaborator"
    if collaborator:
        skipped = _switches_off(ctx.env, "RBAC_SHARING_ENABLED", "RBAC_SHARING_WRITE_ENABLED")
        if skipped:
            result.status, result.reason = report.SKIPPED, skipped
            return result
    inst = _instance(ctx, run, lane, address) if run.lab else None
    project_id = None
    trace: dict = {"api": []}
    t0 = time.monotonic()
    try:
        if inst:
            if time_left(deadline, reserve) < MIN_AGENT_SEC:
                result.reason = "no time left in the run's cap to start its lab"
                return result
            ctx.docker.up(inst, wait_sec=int(min(labs.UP_TIMEOUT_SEC, time_left(deadline, reserve))))
            problem = oracles.after_up(inst.spec, inst, ctx.docker)
            if problem or not _wait_http(inst.local_url, min(120.0, max(5.0, time_left(deadline, reserve)))):
                result.reason = problem or "the lab never answered"
                return result
        prompt = oracles.prompt_for(inst.spec, inst) if inst else " ".join(str(single.get("prompt", "")).split())
        fields = project_fields(ctx.scn, target_ip=inst.ip if inst else None, model=ctx.model)
        phases = fields.pop("_tradecraft_phases", None)
        project_id = Stack.create_project(owner_http, f"tc-e2e {run.id} {secrets.token_hex(3)}", fields)
        if phases:
            apply_phase_map(owner_http, project_id, phases)
        off = _tradecraft_off(ctx, single.get("resources") if run.arm == "single" else arm.get("resources"))
        if off:
            res = Stack.update_project(owner_http, project_id, {"tradecraftOff": off})
            if not res.ok:
                result.reason = f"turning resources off answered {res.status} {res.code}"
                return result
        chat_http, chat_id = owner_http, owner_id
        if collaborator:
            collab_http, collab_id = ctx.sessions["collaborator"]
            # "Use AI agent" spends the owner's providers: the owner consents first, with their
            # password, as the share dialog asks (access-policy route, step 5.6).
            res = owner_http.call("POST", f"/api/projects/{project_id}/access-policy",
                                  {"ownerCredentialConsent": True, "stepUpPassword": ctx.accounts["owner"].password})
            trace["api"].append({"name": "owner_credential_consent", "status": res.status, "code": res.code})
            if not res.ok:
                return _refused(result, "owner_credential_consent", res, "the owner's consent to share their credentials")
            res = owner_http.call("POST", f"/api/projects/{project_id}/collaborators",
                                  {"email": ctx.accounts["collaborator"].email, "access": "write", "useAgent": True})
            trace["api"].append({"name": "share_with_collaborator", "status": res.status, "code": res.code})
            if not res.ok:
                return _refused(result, "share_with_collaborator", res, "the share with the collaborator")
            chat_http, chat_id = collab_http, collab_id
        before = page_store_counts(ctx.db, owner_id)
        cap = time_left(deadline, reserve)
        if cap < MIN_AGENT_SEC:
            result.reason = "no time left in the run's cap for the agent"
            return result
        outcome = run_chat(ctx.stack, chat_http, chat_id, project_id, prompt, cap_sec=cap)
        result.cap_reached = outcome.ended == "cap"
        result.approvals_given = len(outcome.approvals)
        wait_until_idle(ctx.db, outcome.session_id, seconds=min(60.0, max(5.0, time_left(deadline))))
        trace.update(build_trace(ctx.db, outcome.session_id, owner_id, before=before, logs_dir=ctx.logs_dir))
        trace["outcome"] = outcome.__dict__
        ev = trace.get("events") or {}
        result.iterations, result.tokens_in, result.tokens_out = ev.get("iterations"), ev.get("tokens_in"), ev.get("tokens_out")
        result.library = checks.library_now_summary(trace, inst.spec.expected_pages if inst else [])
        if inst:
            o = oracles.judge(inst.spec, inst, answers=trace["answers"],
                              tool_outputs=[c.get("output", "") for c in trace["tool_calls"]], docker=ctx.docker)
            result.oracle, result.oracle_detail = o.ok, o.detail + (" (seen in a tool output)" if o.seen_in_tool_output else "")
        problem = run_problem(outcome, trace)
        if problem:
            result.status, result.reason = report.ERROR, problem
            return result
        if run.arm == "single":
            result.checks = checks.single_checks(run.check, trace, cfg=ctx.scn, spec=single)
        else:
            result.checks = checks.arm_checks(run.arm, trace, expected_pages=inst.spec.expected_pages if inst else [],
                                              cfg=ctx.scn, prompt=prompt, planted=inst.spec.planted if inst else [])
        result.status = report.FAIL
        return report.settle(result)
    except Exception as exc:  # a run's failure is its own; the matrix goes on
        result.status, result.reason = report.ERROR, f"{type(exc).__name__}: {exc}"
        return result
    finally:
        result.seconds = round(time.monotonic() - t0, 1)
        result.ended_at = now_iso()
        if project_id:
            Stack.delete_project(owner_http, project_id)
        if inst:
            ctx.docker.down(inst)
        result.trace_file = str(report.write_run_file(ctx.out_dir, result, trace, ctx.redact))


def run_acting(ctx: Context, run: lanes.Run, deadline: float) -> report.RunResult:
    """S3: the administrator of ``.env`` acts as the owner."""
    result = report.RunResult(run_id=run.id, arm=run.arm, lab=None, n=1, check=run.check, started_at=now_iso(),
                              status=report.ERROR)
    skipped = _switches_off(ctx.env, "RBAC_PERMISSIONS_ENABLED")
    if skipped:
        result.status, result.reason = report.SKIPPED, skipped
        return result
    single = ctx.scn["singles"][run.check]
    owner_http, owner_id = ctx.sessions["owner"]
    trace: dict = {"api": []}
    project_id = None
    admin: Optional[Http] = None
    admin_id = ""
    t0 = time.monotonic()
    try:
        admin, admin_id = ctx.stack.session(ctx.env.get("UI_LOGIN_USERNAME"), ctx.env.get("UI_LOGIN_PASSWORD"))
        fields = project_fields(ctx.scn, target_ip=None, model=ctx.model)
        phases = fields.pop("_tradecraft_phases", None)
        project_id = Stack.create_project(owner_http, f"tc-e2e {run.id} {secrets.token_hex(3)}", fields)
        if phases:
            apply_phase_map(owner_http, project_id, phases)
        res = admin.call("POST", "/api/auth/act-as", {"targetUserId": owner_id, "reason": "Tradecraft e2e matrix S3",
                                                      "stepUpPassword": ctx.env.get("UI_LOGIN_PASSWORD")})
        trace["api"].append({"name": "act_as", "status": res.status, "code": res.code})
        if not res.ok:
            return _refused(result, "act_as", res, "acting as the owner")
        for value in admin.cookies.values():
            ctx.redact.add(value)
        since = now_iso()
        login_slug = ctx.scn["library"]["login_resource"]
        rid = ctx.resource_ids.get(login_slug, "")
        base = f"/api/users/{owner_id}/tradecraft-resources"
        page = _any_page_id(ctx.db, rid)
        for name, method, path, body in [
            ("refresh_login_resource", "POST", f"{base}/{rid}/refresh", {}),
            ("check_url_login_resource", "POST", f"{base}/check-url", {"resourceId": rid}),
            ("read_now_login_resource", "POST", f"{base}/{rid}/pages/{urllib.parse.quote(page)}", None),
        ]:
            res = admin.call(method, path, body)
            trace["api"].append({"name": name, "status": res.status, "code": res.code})
        rows = ctx.db.json("SELECT count(*) AS n FROM audit_log WHERE action = 'act_as.refused' "
                           f"AND on_behalf_of_user_id = {lit(owner_id)} AND created_at >= {lit(since)}::timestamptz")
        trace["audit"] = {"act_as_refused": int(rows[0]["n"]) if rows else 0}
        outcome = run_chat(ctx.stack, admin, owner_id, project_id, " ".join(str(single["prompt"]).split()),
                           cap_sec=max(MIN_AGENT_SEC, time_left(deadline, ctx.reserve_sec)))
        result.cap_reached = outcome.ended == "cap"
        wait_until_idle(ctx.db, outcome.session_id, seconds=min(60.0, max(5.0, time_left(deadline))))
        trace.update({k: v for k, v in build_trace(ctx.db, outcome.session_id, owner_id, before=None,
                                                   logs_dir=ctx.logs_dir).items() if k != "api"})
        problem = run_problem(outcome, trace)
        if problem:
            result.status, result.reason = report.ERROR, problem
            return result
        result.checks = checks.single_checks(run.check, trace, cfg=ctx.scn, spec=single)
        result.status = report.FAIL
        return report.settle(result)
    except Exception as exc:
        result.status, result.reason = report.ERROR, f"{type(exc).__name__}: {exc}"
        return result
    finally:
        if admin is not None and admin_id:
            # Acting as oneself ends acting (api/auth/act-as).
            admin.call("POST", "/api/auth/act-as", {"targetUserId": admin_id})
        if project_id:
            Stack.delete_project(owner_http, project_id)
        result.seconds = round(time.monotonic() - t0, 1)
        result.ended_at = now_iso()
        result.trace_file = str(report.write_run_file(ctx.out_dir, result, trace, ctx.redact))


def _any_page_id(db: Db, resource_id: str) -> str:
    rows = db.json("SELECT r.slug, p.id FROM tradecraft_page_ids p JOIN user_tradecraft_resources r ON r.id = p.resource_id "
                   f"WHERE p.resource_id = {lit(resource_id)} ORDER BY p.id LIMIT 1")
    return f"{rows[0]['slug']}:{rows[0]['id']}" if rows else "none:1"


def run_loop(ctx: Context, run: lanes.Run, deadline: float) -> report.RunResult:
    """S4: an Agent in the Loop run, its model calls answered by ``LoopDriver``."""
    result = report.RunResult(run_id=run.id, arm=run.arm, lab=None, n=1, check=run.check, started_at=now_iso(),
                              status=report.ERROR)
    skipped = _switches_off(ctx.env, "AGENT_IN_THE_LOOP_ENABLED", "MCP_SERVER_ENABLED")
    if skipped:
        result.status, result.reason = report.SKIPPED, skipped
        return result
    single = ctx.scn["singles"][run.check]
    owner_http, owner_id = ctx.sessions["owner"]
    trace: dict = {"api": []}
    project_id = token_id = None
    t0 = time.monotonic()
    try:
        res = owner_http.call("POST", f"/api/users/{owner_id}/mcp-tokens", {
            "name": f"tc-e2e loop driver {secrets.token_hex(3)}", "scopes": ["recon:read", "agent:loop"],
            "profile": "agent_in_the_loop", "expiresInDays": 30, "password": ctx.accounts["owner"].password})
        trace["api"].append({"name": "driver_token", "status": res.status, "code": res.code})
        if res.status != 201 or not isinstance(res.data, dict) or not res.data.get("plaintext"):
            return _refused(result, "driver_token", res, "the Agent in the Loop driver token")
        token = str(res.data.get("plaintext") or "")
        token_id = str((res.data.get("token") or {}).get("id") or "")
        ctx.redact.add(token)
        fields = project_fields(ctx.scn, target_ip=None, model="loop/mcp")
        phases = fields.pop("_tradecraft_phases", None)
        project_id = Stack.create_project(owner_http, f"tc-e2e {run.id} {secrets.token_hex(3)}", fields)
        if phases:
            apply_phase_map(owner_http, project_id, phases)
        session_id = new_session_id()
        driver = LoopDriver(ctx.stack.webapp, token, session_id)
        did: list[str] = []
        cap = max(MIN_AGENT_SEC, time_left(deadline, ctx.reserve_sec))
        worker = threading.Thread(target=lambda: did.extend(drive_loop(driver, single["ask"], target_ip="192.0.2.10",
                                                                         timeout=cap)), daemon=True)
        worker.start()
        outcome = run_chat(ctx.stack, owner_http, owner_id, project_id, str(single["prompt"]), cap_sec=cap,
                           session_id=session_id)
        worker.join(timeout=max(5.0, min(120.0, time_left(deadline))))
        result.cap_reached = outcome.ended == "cap"
        wait_until_idle(ctx.db, session_id, seconds=min(60.0, max(5.0, time_left(deadline))))
        trace.update(build_trace(ctx.db, session_id, owner_id, before=None, logs_dir=ctx.logs_dir))
        trace["loop_prompts"] = driver.prompts
        trace["driver"] = did
        problem = (f"the MCP server refused the Agent in the Loop driver ({driver.refused})" if driver.refused
                   else run_problem(outcome, trace, loop=True))
        if problem:
            result.status, result.reason = report.ERROR, problem
            return result
        result.checks = checks.single_checks(run.check, trace, cfg=ctx.scn, spec=single)
        result.status = report.FAIL
        return report.settle(result)
    except Exception as exc:
        result.status, result.reason = report.ERROR, f"{type(exc).__name__}: {exc}"
        return result
    finally:
        if project_id:
            Stack.delete_project(owner_http, project_id)
        if token_id:
            owner_http.call("DELETE", f"/api/users/{owner_id}/mcp-tokens/{token_id}")
        result.seconds = round(time.monotonic() - t0, 1)
        result.ended_at = now_iso()
        result.trace_file = str(report.write_run_file(ctx.out_dir, result, trace, ctx.redact))


def run_address_guard(ctx: Context, run: lanes.Run, address: lanes.LaneAddressing, lane: int) -> report.RunResult:
    """S6, on the ops account: Check URL of a lab address is refused by the address guard."""
    result = report.RunResult(run_id=run.id, arm=run.arm, lab=run.lab, n=1, check=run.check, lane=lane,
                              started_at=now_iso(), status=report.ERROR)
    ops_http, ops_id = ctx.sessions["ops"]
    url = f"http://{address.ip(lane)}:{ctx.scn['labs'][run.lab]['port']}/"
    trace: dict = {"api": []}
    t0 = time.monotonic()
    try:
        res = ops_http.call("POST", f"/api/users/{ops_id}/tradecraft-resources/check-url", {"url": url}, timeout=120)
        answer = (res.data or {}).get("result") if isinstance(res.data, dict) else None
        refusal = res.data if isinstance(res.data, dict) and not res.ok else {}
        trace["api"].append({"name": "check_url_lab_address", "status": res.status,
                             "code": (answer or {}).get("error_code") or res.code, "ok": (answer or {}).get("ok"),
                             "field": refusal.get("field"), "error": str(refusal.get("error") or "")[:80]})
        if res.status == 0:
            result.reason = f"the webapp was not reached ({res.error})"
            return result
        result.checks = checks.single_checks(run.check, trace, cfg=ctx.scn, spec=ctx.scn["singles"][run.check])
        result.status = report.FAIL
        return report.settle(result)
    finally:
        result.seconds = round(time.monotonic() - t0, 1)
        result.ended_at = now_iso()
        result.trace_file = str(report.write_run_file(ctx.out_dir, result, trace, ctx.redact))


def run_one(ctx: Context, run: lanes.Run, lane: int, address: lanes.LaneAddressing, deadline: float) -> report.RunResult:
    single = ctx.scn["singles"].get(run.check or "", {})
    if run.check == "S6":
        return run_address_guard(ctx, run, address, lane)
    if single.get("aitl"):
        return run_loop(ctx, run, deadline)
    if single.get("as") == "admin_acting":
        return run_acting(ctx, run, deadline)
    return run_attack(ctx, run, lane, address, deadline)


def set_owner_mode(ctx: Context, mode: str) -> None:
    http, uid = ctx.sessions["owner"]
    res = http.call("PUT", f"/api/users/{uid}/tradecraft-settings", {"search": {"librarian.use": mode}})
    if not res.ok:
        raise RuntimeError(f"setting Librarian use to {mode} answered {res.status} {res.code}")
    ctx.log(f"owner's Librarian use set to {mode}")


RunFn = Callable[[Context, lanes.Run, int, lanes.LaneAddressing, float], report.RunResult]


def run_matrix(ctx: Context, runs: Sequence[lanes.Run], lane_count: int, run_fn: RunFn = run_one,
               clock: Callable[[], float] = time.monotonic, poll_sec: float = 5.0,
               started_at: Optional[float] = None) -> list[report.RunResult]:
    """The lanes: whenever a lane is free the scheduler picks its next run. The budget is
    counted from ``started_at``, the start of the whole matrix (its preflight included): no run
    starts after the guard, nor one whose cap could end after the total less the collection;
    the ones left are reported ``not run: budget``. Each run gets the deadline of its cap."""
    plan = lanes.budget(ctx.scn)
    sched = lanes.Scheduler(runs, start_until_sec=plan.start_until_sec, end_by_sec=plan.end_by_sec)
    address = lanes.addressing(ctx.scn, lane_count)
    results: list[report.RunResult] = []
    busy: dict[int, threading.Thread] = {}
    done_lock = threading.Lock()
    start = clock() if started_at is None else started_at

    def work(lane: int, run: lanes.Run, deadline: float) -> None:
        try:
            res = run_fn(ctx, run, lane, address, deadline)
        except Exception as exc:  # noqa: BLE001 - one run's crash is that run's error
            res = report.RunResult(run.id, run.arm, run.lab, run.n, run.check, status=report.ERROR,
                                   reason=type(exc).__name__, lane=lane)
        with done_lock:
            results.append(res)
            sched.finished(run)
        ctx.log(f"{run.id} lane {lane}: {res.status}" + (f" ({res.reason})" if res.reason else ""))

    while True:
        with done_lock:
            for lane in [ln for ln, t in busy.items() if not t.is_alive()]:
                busy.pop(lane)
            free = [ln for ln in range(lane_count) if ln not in busy]
            progressed = False
            for lane in free:
                now = clock()
                run = sched.next_run(now - start)
                if run is None:
                    break
                mode = sched.needs_mode(run)
                if mode:
                    try:
                        set_owner_mode(ctx, mode)
                    except RuntimeError as exc:
                        # Run in the wrong mode it would measure the other arm: an error, not a run.
                        results.append(report.RunResult(run.id, run.arm, run.lab, run.n, run.check,
                                                        status=report.ERROR, reason=str(exc)))
                        sched.finished(run)
                        progressed = True
                        continue
                    sched.mode_set(mode)
                thread = threading.Thread(target=work, args=(lane, run, now + run.cap_sec), name=f"lane-{lane}",
                                          daemon=True)
                busy[lane] = thread
                thread.start()
                progressed = True
                ctx.log(f"{run.id} started on lane {lane}")
            idle = not busy and not progressed
        if idle:
            break
        time.sleep(poll_sec)
    results += report.not_run_results(sched.not_started())
    return results


# Layer-1 checks (beside the lanes) and the preflight
# --------------------------------------------------------------------------------------

RETRIEVAL_SCRIPT = r"""
import asyncio, json, os, sys
import requests
from tradecraft import runtime, agent_tools
q = json.load(sys.stdin)
url = os.environ.get("WEBAPP_API_URL", "http://webapp:3000").rstrip("/") + "/api/internal/agent/tradecraft/catalog"
resp = requests.get(url, params={"projectId": q["project_id"], "personId": q["person_id"]},
                    headers={"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}, timeout=30)
resp.raise_for_status()
runtime.bind_run_catalog(resp.json())
for item in q["questions"]:
    if item.get("cve_id"):  # a CVE archive is read by CVE id, never searched (reader.lookup)
        out = asyncio.run(agent_tools.reader.lookup(resource_id=item["resource"], cve_id=item["cve_id"]))
    else:
        out = asyncio.run(agent_tools.run_search(query=item["q"]))
    print("TC_E2E_RESULT=" + json.dumps({"q": item["q"], "output": out}))
"""


def retrieval_check(ctx: Context, project_id: str, questions: Sequence[Mapping],
                    run: Exec = subprocess.run, timeout: float = 900) -> report.CheckResult:
    """The 30 retrieval questions on the owner's restored library, read-only: each one's
    expected page must be among its search results; a CVE question (``cve: true``) is a lookup
    of its CVE id in the expected CVE archive, which no search lists."""
    _, owner_id = ctx.sessions["owner"]
    items = [{"q": q["q"], **({"cve_id": q["q"], "resource": q["expect"]["resource"]} if q.get("cve") else {})}
             for q in questions]
    payload = json.dumps({"project_id": project_id, "person_id": owner_id, "questions": items})
    done = run(["docker", "exec", "-i", "-w", "/app", AGENT_CONTAINER, "python", "-c", RETRIEVAL_SCRIPT],
               input=payload, capture_output=True, text=True, timeout=timeout, check=False)
    outputs = {}
    for line in (done.stdout or "").splitlines():
        if line.startswith("TC_E2E_RESULT="):
            row = json.loads(line.split("=", 1)[1])
            outputs[row["q"]] = row["output"]
    hits, misses = 0, []
    for q in questions:
        res = checks.parse_result("tradecraft_lookup" if q.get("cve") else "tradecraft_search", outputs.get(q["q"], ""))
        if any(checks.matches({}, ref, q["expect"]) for ref in res.pages):
            hits += 1
        else:
            misses.append(q["q"])
    ok = done.returncode == 0 and not misses
    detail = f"{hits}/{len(questions)} found" + (f"; missed: {'; '.join(misses[:8])}" if misses else "")
    return report.CheckResult("retrieval_questions", ok, detail if done.returncode == 0 else f"exit {done.returncode}")


def _job_done(http: Http, uid: str, rid: str, seconds: float, deadline: Optional[float] = None) -> Optional[dict]:
    until = time.monotonic() + seconds if deadline is None else min(time.monotonic() + seconds, deadline)
    while time.monotonic() < until:
        res = http.call("GET", f"/api/users/{uid}/tradecraft-resources/{rid}/jobs")
        job = (res.data or {}).get("job") if isinstance(res.data, dict) else None
        if job and job.get("status") in ("succeeded", "failed", "cancelled"):
            return job
        time.sleep(5)
    return None


def _job_started(http: Http, uid: str, rid: str, seconds: float, deadline: Optional[float] = None,
                 sleep: Callable[[float], None] = time.sleep) -> Optional[dict]:
    """The resource's latest job once it left the queue (running, or already ended)."""
    until = time.monotonic() + seconds if deadline is None else min(time.monotonic() + seconds, deadline)
    while time.monotonic() < until:
        res = http.call("GET", f"/api/users/{uid}/tradecraft-resources/{rid}/jobs")
        job = (res.data or {}).get("job") if isinstance(res.data, dict) else None
        if job and job.get("status") != "queued":
            return job
        sleep(0.5)
    return None


def ops_checks(ctx: Context, deadline: float) -> list[report.CheckResult]:
    """On the ops account's own resource: an incremental refresh (AC-18), Cancel mid-refresh
    keeps the previous version (AC-33), the stale badge after a settings change, and delete
    leaves no row (AC-42). Never on the owner's library."""
    http, uid = ctx.sessions["ops"]
    spec = ctx.scn["layer1"]["ops_resource"]
    base = f"/api/users/{uid}/tradecraft-resources"
    out: list[report.CheckResult] = []
    # The ops account's librarian is never asked: with "Search only" its add needs no librarian model.
    mode = http.call("PUT", f"/api/users/{uid}/tradecraft-settings", {"search": {"librarian.use": "search_only"}})
    if not mode.ok:
        return [report.CheckResult("ops_resource_added", False, f"the ops account's librarian use answered {mode.status} {mode.code}")]
    res = http.call("POST", base, {"name": spec["name"], "url": spec["url"], "storageMode": spec.get("storageMode", "stored"),
                                   "enabled": True, "llmModel": ctx.model}, timeout=120)
    rid = str(((res.data or {}).get("resource") or res.data or {}).get("id", "")) if isinstance(res.data, dict) else ""
    if not res.ok or not rid:
        return [report.CheckResult("ops_resource_added", False, f"add answered {res.status} {res.code}")]
    try:
        first = _job_done(http, uid, rid, 1800, deadline)
        out.append(report.CheckResult("ops_resource_added", bool(first and first.get("status") == "succeeded"),
                                      (first or {}).get("status", "no job end")))
        since = now_iso()
        res = http.call("POST", f"{base}/{rid}/refresh", {})
        second = _job_done(http, uid, rid, 1800, deadline) if res.ok else None
        counts = incremental_counts(agent_log_since(since), str((second or {}).get("id", "")))
        status = (second or {}).get("status", f"refresh answered {res.status} {res.code}".strip())
        out.append(report.CheckResult(
            "incremental_refresh", bool(second and second.get("status") == "succeeded" and counts and counts[0] > 0),
            f"{status}; " + (f"{counts[0]} pages unchanged, {counts[1]} stored again" if counts
                             else "no incremental line of this job in the agent's log")))
        gen = ctx.db.json(f"SELECT generation FROM user_tradecraft_resources WHERE id = {lit(rid)}")
        gen1 = gen[0]["generation"] if gen else None
        entries1 = ctx.db.json(f"SELECT count(*) AS n FROM tradecraft_entries WHERE resource_id = {lit(rid)}")
        http.call("POST", f"{base}/{rid}/refresh", {})
        # Cancelled as soon as the agent took it: a small repository's refresh can end within seconds.
        _job_started(http, uid, rid, 60, deadline)
        http.call("DELETE", f"{base}/{rid}/jobs")
        third = _job_done(http, uid, rid, 600, deadline)
        gen = ctx.db.json(f"SELECT generation FROM user_tradecraft_resources WHERE id = {lit(rid)}")
        entries2 = ctx.db.json(f"SELECT count(*) AS n FROM tradecraft_entries WHERE resource_id = {lit(rid)}")
        kept = bool(gen and gen[0]["generation"] == gen1 and entries1 == entries2)
        out.append(report.CheckResult("cancel_keeps_previous_version", kept and (third or {}).get("status") == "cancelled",
                                      f"job {(third or {}).get('status')}, generation {gen1}→{gen[0]['generation'] if gen else None}"))
        change = ctx.scn["layer1"]["stale_setting"]
        res = http.call("PUT", f"/api/users/{uid}/tradecraft-settings", {"ingestion": {change["key"]: change["value"]}})
        view = http.call("GET", f"{base}/{rid}")
        stale = isinstance(view.data, dict) and bool((view.data.get("resource") or view.data).get("stale"))
        out.append(report.CheckResult("stale_after_settings_change", res.ok and stale, f"settings {res.status}, stale={stale}"))
        http.call("PUT", f"/api/users/{uid}/tradecraft-settings", {"reset": change["reset"]})
    finally:
        res = http.call("DELETE", f"{base}/{rid}")
        left = ctx.db.json(
            "SELECT (SELECT count(*) FROM tradecraft_entries WHERE resource_id = {r}) + "
            "(SELECT count(*) FROM tradecraft_page_ids WHERE resource_id = {r}) + "
            "(SELECT count(*) FROM tradecraft_sections WHERE resource_id = {r}) + "
            "(SELECT count(*) FROM tradecraft_tree_nodes WHERE resource_id = {r}) + "
            "(SELECT count(*) FROM user_tradecraft_resources WHERE id = {r}) AS n".format(r=lit(rid)))
        n = int(left[0]["n"]) if left else -1
        out.append(report.CheckResult("delete_leaves_no_row", res.ok and n == 0, f"delete {res.status}, {n} rows left"))
    return out


def layer1(ctx: Context, deadline: float) -> list[report.CheckResult]:
    """The layer-1 checks, within ``deadline`` (a ``time.monotonic`` value: the budget's end)."""
    out: list[report.CheckResult] = []
    owner_http, _ = ctx.sessions["owner"]
    project_id = None
    try:
        fields = project_fields(ctx.scn, target_ip=None, model=ctx.model)
        fields.pop("_tradecraft_phases", None)
        project_id = Stack.create_project(owner_http, f"tc-e2e layer1 {secrets.token_hex(3)}", fields)
        out.append(retrieval_check(ctx, project_id, ctx.scn["layer1"]["retrieval"],
                                   timeout=max(30.0, min(900.0, time_left(deadline)))))
    except Exception as exc:
        out.append(report.CheckResult("retrieval_questions", False, f"{type(exc).__name__}: {exc}"))
    finally:
        if project_id:
            Stack.delete_project(owner_http, project_id)
    try:
        out += ops_checks(ctx, deadline)
    except Exception as exc:
        out.append(report.CheckResult("ops_checks", False, f"{type(exc).__name__}: {exc}"))
    return out


def snapshot_stamp(snapshot_dir: Path = SNAPSHOT_DIR) -> Optional[dict]:
    try:
        return json.loads((snapshot_dir / "stamp.json").read_text())
    except (OSError, ValueError):
        return None


def _library():
    """library.py (T10.2), imported when used: it imports this module."""
    from tooling.scripts.tradecraft_e2e import library
    return library


AGENT_LOG_INCREMENTAL = r"\[tradecraft\] job {job} incremental code= unchanged=(\d+) stored=(\d+)"


def incremental_counts(log_text: str, job_id: str) -> Optional[tuple[int, int]]:
    """The agent's own count of a refresh's pages (``ingest/storage.py``): unchanged ones,
    and the ones stored again. The job's report does not hold it."""
    if not job_id:
        return None
    found = re.findall(AGENT_LOG_INCREMENTAL.format(job=re.escape(job_id)), log_text)
    return (int(found[-1][0]), int(found[-1][1])) if found else None


def agent_log_since(since: str, run: Exec = subprocess.run, container: str = AGENT_CONTAINER) -> str:
    """The agent container's console since ``since`` (jobs log there; they have no session)."""
    done = run(["docker", "logs", "--since", since, container], capture_output=True, text=True, check=False,
               timeout=120)
    return (done.stdout or "") + (done.stderr or "")


def mem_available_gb() -> Optional[float]:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return round(int(line.split()[1]) / 1024 / 1024, 1)
    except OSError:
        return None
    return None


def logs_dir_problem(logs_dir: Path) -> Optional[str]:
    """The agent's session logs are the trace's prompts and hints: without them every run would
    be a run error, so the matrix does not start."""
    if not logs_dir.is_dir():
        return f"the agent's log folder {logs_dir} does not exist (pass --agent-logs)"
    if not any(logs_dir.glob("agent.*.log")):
        return f"the agent's log folder {logs_dir} holds no session log: it is not the one the agent writes to"
    return None


def preflight(ctx: Context, runs: Sequence[lanes.Run], *, restore: bool, build: bool) -> list[str]:
    """What must hold before the lanes start; returns the problems (empty: go)."""
    problems: list[str] = []
    stack, log = ctx.stack, ctx.log
    for name, url in (("webapp", stack.webapp + "/api/health"), ("agent", stack.agent_http + "/health")):
        if not _wait_http(url, 10):
            problems.append(f"the {name} does not answer")
    problem = logs_dir_problem(ctx.logs_dir)
    if problem:
        problems.append(problem)
    stamp = snapshot_stamp()
    if stamp is None:
        problems.append("no library snapshot (_local/tradecraft-e2e/library/stamp.json): build it with T10.2's library.py")
    else:
        # The ingestion code as the images are built from it: the checkout's HEAD may not even
        # track the plan's files, so the stamp holds a hash of the files, not only a commit.
        warning = _library().stamp_warning(stamp)
        if warning:
            log(f"warning: {warning}")
    library_py = HERE / "library.py"
    if restore and stamp is not None:
        if not library_py.exists():
            problems.append("library.py (T10.2) is missing, so the snapshot cannot be restored")
        else:
            done = subprocess.run([sys.executable, str(library_py), "restore"], capture_output=True, text=True,
                                  timeout=1800, check=False)
            if done.returncode != 0:
                problems.append(f"the library restore failed (exit {done.returncode})")
    leftovers = ctx.docker.leftovers()
    for name in leftovers:
        subprocess.run(["docker", "compose", "-p", name, "down", "-v", "--remove-orphans"], capture_output=True,
                       check=False, timeout=300)
    if leftovers:
        log(f"removed {len(leftovers)} lab projects left by an earlier run")
    if build:
        for lab_id in sorted({r.lab for r in runs if r.lab}):
            spec = oracles.specs(ctx.scn)[lab_id]
            override = None
            if spec.kind == "override":
                base = load_yaml((REPO / spec.folder / labs.COMPOSE_FILE).read_text(encoding="utf-8"))
                override = ctx.out_dir / "overrides" / f"build-{lab_id}.yml"
                override.parent.mkdir(parents=True, exist_ok=True)
                override.write_text(labs.build_override_yaml(spec, base))
            try:
                ctx.docker.build(spec, override)
                log(f"lab {lab_id} image ready")
            except subprocess.CalledProcessError as exc:
                problems.append(f"lab {lab_id} did not build (exit {exc.returncode})")
    owner_http, owner_id = ctx.sessions["owner"]
    listing = owner_http.call("GET", f"/api/users/{owner_id}/tradecraft-resources")
    rows = listing.data if isinstance(listing.data, list) else (listing.data or {}).get("resources", []) if isinstance(listing.data, dict) else []
    ctx.resource_ids.update({str(r.get("slug")): str(r.get("id")) for r in rows if isinstance(r, dict)})
    missing = [s for s in ctx.scn["library"]["resources"] if s not in ctx.resource_ids]
    if missing:
        problems.append(f"the owner's library lacks {', '.join(missing)}")
    settings = owner_http.call("GET", f"/api/users/{owner_id}/tradecraft-settings")
    search = (settings.data or {}).get("search") if isinstance(settings.data, dict) else None
    values = (search or {}).get("values", search) if isinstance(search, dict) else {}
    for key, want in (ctx.scn.get("owner_search") or {}).items():
        if key != "librarian.use" and isinstance(values, dict) and key in values and values[key] != want:
            problems.append(f"the owner's {key} is {values[key]!r}, the matrix expects {want!r}")
    for key in ("owner", "ops"):
        http, uid = ctx.sessions[key]
        # Its own provider, tested, or one the install offers it (an instance provider): MC-9.
        problem = _library().provider_problem(http, uid)
        if problem:
            problems.append(f"the e2e {key} account: {problem}")
    mem = mem_available_gb()
    log(f"free memory: {mem if mem is not None else '?'} GB; load: {os.getloadavg()[0]:.1f}")
    log("the provider's rate-limit headroom is not visible through the webapp: each run counts its rate_limit_wait frames")
    return problems


# --------------------------------------------------------------------------------------
# --dry-run and the command line
# --------------------------------------------------------------------------------------

def dry_run(scn: dict, runs: Sequence[lanes.Run], lane_count: int, env: Env, *, out=print) -> int:
    """The plan of a matrix run, with nothing started: the runs and their checks, the lab
    instances lane 0 would get (overrides generated and parsed back), the worst-case schedule
    for ``--lanes`` from the matrix's start (start times in minutes, the preflight included),
    and which ``.env`` keys are present (names only)."""
    plan = lanes.budget(scn)
    address = lanes.addressing(scn, lane_count)
    specs = oracles.specs(scn)
    out(f"Tradecraft 2.0 matrix: {len(runs)} runs on {lane_count} lanes (dry run: no stack, no Docker, no network)")
    for lab_id, spec in sorted(specs.items()):
        if lab_id not in {r.lab for r in runs}:
            continue
        folder = REPO / spec.folder
        if not (folder / labs.COMPOSE_FILE).exists():
            out(f"  lab {lab_id}: MISSING {spec.folder}/{labs.COMPOSE_FILE}")
            return 1
        line = f"  lab {lab_id}: {spec.folder} ({spec.kind}), front {spec.front}:{spec.port}, oracle {spec.oracle['kind']}"
        if spec.kind == "override":
            base = load_yaml((folder / labs.COMPOSE_FILE).read_text(encoding="utf-8"))
            inst = labs.plan_instance(spec, lanes.Run(f"{lab_id}-dry", "A", lab_id, 1, 1, 1), 0, address,
                                      secret_value="dry", suffix="dry")
            parsed = load_yaml(labs.override_yaml(spec, base, inst, network=scn["lanes"]["network"]).replace(" !override", "").replace(" !reset", ""))
            line += f"; override services {', '.join(parsed['services'])}"
        out(line)
    timeline = lanes.worst_case(runs, lane_count, plan)
    collect = plan.total_sec - plan.end_by_sec
    out(f"  worst case (every run at its cap, which bounds its whole lane time): lanes "
        f"{(timeline.makespan - plan.preflight_sec) / 3600:.2f} h, the matrix "
        f"{(timeline.makespan + collect) / 3600:.2f} h of the {plan.total_sec / 3600:.2f} h budget "
        f"(preflight {plan.preflight_sec / 60:.0f} min, collection {collect / 60:.0f} min); no run starts after "
        f"{plan.start_until_sec / 3600:.2f} h nor ends after {plan.end_by_sec / 3600:.2f} h; owner mode changes: "
        + (", ".join(f"{m} at {t / 60:.0f} min" for t, m in timeline.mode_changes) or "none"))
    if timeline.not_run:
        out(f"  with {lane_count} lanes {len(timeline.not_run)} runs would be '{lanes.NOT_RUN_BUDGET}' in the worst case: "
            "the 5-hour budget does not hold")
    out("  lane | start | cap | run | checks")
    for slot in sorted(timeline.slots, key=lambda s: (s.start, s.lane)):
        r = slot.run
        names = _check_names(scn, r)
        out(f"  {slot.lane:>4} | {slot.start / 60:>5.0f} | {r.cap_sec // 60:>3} | {r.id:<12} | {', '.join(names)}")
    present = env.present()
    out("  .env: " + ", ".join(f"{k} {'present' if v else ('default' if k in OPTIONAL_ENV_KEYS else 'MISSING')}"
                               for k, v in present.items()))
    return 0


def _check_names(scn: Mapping, run: lanes.Run) -> list[str]:
    if run.arm == "B":
        return ["oracle", "no_tradecraft_tool_offered", "no_tradecraft_tool_called", "no_coverage_map", "page_store_unchanged"]
    if run.arm in ("A", "A_search"):
        names = ["oracle", "expected_page_returned", "reads_by_section_within_limit", "stored_reads_say_stored_copy",
                 "no_read_page_shown_again", "one_search_round_per_think", "no_planted_text_in_block",
                 "librarian_excerpts_verbatim", "no_pick_from_injected_text", "page_store_unchanged"]
        return names + (["ask_not_offered", "ask_not_called"] if run.arm == "A_search" else [])
    return [str(scn["singles"][run.check].get("title", run.check))]


PLAN_REF = "refs/heads/feature/tradecraft-2.0"
# The commit the plan branch started from (T0.1, progress_log.md "Base commits"): the plan's own
# diff is base..tip, and a record taken from another base cannot tell the plan's lines apart.
PLAN_BASE = "8fc8fb0b7d8c99c646cb53bbfd4cf364ffd08cdf"
# Read by `compose up`, never baked: the plan removes the page-cache mount and volume from it.
SHARED_CONFIG = ("docker-compose.yml",)
# What the plan removed from docker-compose.yml (8fc8fb0b..: the 1.x page cache's mount and
# volume): a running agent that still has it was started from an older copy.
REMOVED_MOUNT = {"Destination": "/app/tradecraft_cache", "Name": "redamon_tradecraft_cache"}
BUILD_RECORD = REPO / "_local" / "tradecraft-e2e" / "build-record.json"
# Where the agent image bakes the repository's folders (agentic/Dockerfile: COPY graph_db/,
# recon_settings/, agentic/ into /app).
AGENT_BAKED = (("agentic/", ""), ("graph_db/", "graph_db/"), ("recon_settings/", "recon_settings/"))
# What the image is built from besides the agent: the webapp's sources (compiled, so compared
# through the build record, never file by file).
WEBAPP_SOURCES = ("webapp/src/", "webapp/prisma/", "webapp/scripts/", "webapp/public/", "webapp/package.json",
                  "webapp/package-lock.json", "webapp/Dockerfile", "webapp/next.config.ts")
# The tree is shared (00_master_plan.md R-B2): another session may carry its own hunks in any file
# the plan changed. Such a copy must hold the plan's own diff (plan_file_check), and its hunks
# besides are named; files the plan never changed may carry the checkout's own work, also named.
# .dockerignore's exclusions inside the baked folders: never in the image.
_NOT_BAKED = re.compile(
    r"(^|/)(__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|htmlcov|node_modules|\.next|\.nuxt|dist|build|"
    r"\.venv|venv|env|[^/]*-env|[^/]*-venv)/"
    r"|\.(pyc|pyo|pyd)$|(^|/)\.coverage$|(^|/)coverage\.xml$|(^|/)Dockerfile$|(^|/)docker-compose[^/]*\.yml$"
    r"|(^|/)\.dockerignore$|\.(test|spec)\.py$")
_AGENT_NOT_BAKED = re.compile(r"^agentic/(tests|logs|knowledge_base)/")


def baked_path(repo_path: str) -> Optional[str]:
    """Where the agent image holds a repository file, or None when the image has no copy of it."""
    if _NOT_BAKED.search(repo_path) or _AGENT_NOT_BAKED.match(repo_path):
        return None
    for prefix, at in AGENT_BAKED:
        if repo_path.startswith(prefix):
            return at + repo_path[len(prefix):]
    return None


def compare_baked(tip: Mapping[str, str], differences: Mapping[str, str], image: Mapping[str, Optional[str]],
                  image_py: Iterable[str]) -> dict:
    """The agent image against the plan tip and the build's recorded differences (git blob ids;
    "" is a file the working tree did not have). Returns the files compared, those that differ
    (repository paths) and the image's Python files no expected file explains."""
    expected: dict = {}
    for repo_path, blob in tip.items():
        at = baked_path(repo_path)
        if at is not None:
            expected[at] = (repo_path, differences.get(repo_path, blob))
    for repo_path, blob in differences.items():
        at = baked_path(repo_path)
        if at is not None and repo_path not in tip:
            expected[at] = (repo_path, blob)
    differing = sorted(repo for at, (repo, want) in expected.items() if (image.get(at) or "") != (want or ""))
    known_py = {at for at, (_, want) in expected.items() if want}
    extra = sorted(p for p in image_py if p not in known_py)
    return {"files": sum(1 for _, w in expected.values() if w), "differing": differing, "extra": extra}


# The agent image's files as git blob ids, read-only inside its container: the paths asked on
# stdin, and every Python file /app holds from the agent's folders (to see a stale one).
AGENT_FILES_SCRIPT = r"""
import hashlib, json, pathlib, sys
ask = json.load(sys.stdin)
want = ask["paths"]
def blob(p):
    try:
        data = p.read_bytes()
    except OSError:
        return None
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
root = pathlib.Path(ask.get("root", "/app"))
files = {at: blob(root / at) for at in want}
# Runtime data, not code: a chat project's workspace and the CypherFix sandbox may hold Python
# files of their own (agent-workspace is gitignored, yet COPY agentic/ bakes it).
skip = ("knowledge_base/", "logs/", "kb_data/", "agent-workspace/", "codefix-work/")
py = [p.relative_to(root).as_posix() for p in root.rglob("*.py")
      if "__pycache__" not in p.parts and not p.relative_to(root).as_posix().startswith(skip)]
print(json.dumps({"files": files, "py": py}))
"""


def git_short(ref: str, run: Optional[Exec] = None) -> str:
    done = (run or subprocess.run)(["git", "-C", str(REPO), "rev-parse", "--short=8", "--verify", "--quiet", ref],
                                   capture_output=True, text=True, check=False, timeout=60)
    return (done.stdout or "").strip()


def tip_files(commit: str, prefixes: Sequence[str], run: Optional[Exec] = None, root: Path = REPO) -> dict:
    """{repository path: git blob id} of ``commit`` under ``prefixes``."""
    # NUL-separated: a path git would quote (a space, a non-ASCII name) is read as it is.
    done = (run or subprocess.run)(["git", "-C", str(root), "ls-tree", "-r", "-z", commit, "--", *prefixes],
                                   capture_output=True, text=True, check=False, timeout=120)
    out = {}
    for line in (done.stdout or "").split("\0"):
        meta, _, path = line.partition("\t")
        parts = meta.split()
        if len(parts) == 3 and parts[1] == "blob":
            out[path] = parts[2]
    return out


def tree_differences(commit: str, prefixes: Sequence[str], run: Optional[Exec] = None,
                     root: Path = REPO) -> dict:
    """{repository path: working-tree blob id, "" when absent} for every file under ``prefixes``
    whose working copy is not ``commit``'s: what an image built now carries besides the commit."""
    run = run or subprocess.run
    tip = tip_files(commit, prefixes, run, root=root)
    # The sources as git sees them, tracked or new, never an ignored file (logs, workspaces, builds).
    listed = run(["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", *prefixes],
                 capture_output=True, text=True, check=False, timeout=300)
    present = [p for p in (listed.stdout or "").split("\0") if p and not _NOT_BAKED.search(p)]
    paths = sorted(set(present) | set(tip))
    existing = [p for p in paths if (root / p).is_file()]
    done = run(["git", "-C", str(root), "hash-object", "--stdin-paths"], input="\n".join(existing) + "\n",
               capture_output=True, text=True, check=False, timeout=300)
    blobs = dict(zip(existing, (done.stdout or "").split()))
    return {p: blobs.get(p, "") for p in paths if blobs.get(p, "") != tip.get(p, "")}


_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def hunk_lines(patch: str, side: str) -> set:
    """The line numbers a zero-context diff's hunks cover on one side: ``old`` (the lines it
    removes or changes) or ``new`` (the lines it adds)."""
    out: set = set()
    for line in patch.splitlines():
        m = _HUNK.match(line)
        if m:
            start, count = (m[1], m[2]) if side == "old" else (m[3], m[4])
            out.update(range(int(start), int(start) + (1 if count is None else int(count))))
    return out


def removed_blocks(patch: str) -> list:
    """The blocks of lines a zero-context diff removes, one per hunk (``-`` lines, in order)."""
    blocks, cur = [], []
    for line in patch.splitlines():
        if line.startswith("@@"):
            if cur:
                blocks.append(cur)
            cur = []
        elif line.startswith("-") and not line.startswith("---"):
            cur.append(line[1:])
    if cur:
        blocks.append(cur)
    return blocks


def plan_file_check(path: str, base: str, tip: str, run: Optional[Exec] = None, root: Path = REPO) -> dict:
    """A plan file's working copy against the plan's own diff (``base`` → ``tip``), counts only.
    Every line the plan adds is there: the copy's diff from the tip removes or changes none of the
    tip's lines the plan added (another session's lines may be inserted anywhere). No block the
    plan removes is back, even in part: a non-blank line of it that the copy holds and the tip holds
    nowhere (a line the tip still has elsewhere proves nothing). And how many hunks the copy has
    besides, another session's. A missing copy, a binary file or a diff git could not make fails."""
    try:
        return _plan_file_check(path, base, tip, run or subprocess.run, root)
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_FAILED)


_FAILED = {"plan_lines": False, "added_present": False, "removed_absent": False, "extra_hunks": 0}


def _plan_file_check(path: str, base: str, tip: str, run: Exec, root: Path) -> dict:
    # A binary file's bytes are not text: decoded with replacement, then refused as binary below.
    text = {"capture_output": True, "text": True, "errors": "replace", "check": False, "timeout": 60}
    plan = run(["git", "-C", str(root), "diff", "--no-renames", "-U0", base, tip, "--", path], **text)
    if not (root / path).is_file() or plan.returncode != 0:
        return dict(_FAILED)
    patch = plan.stdout or ""
    shown = run(["git", "-C", str(root), "show", f"{tip}:{path}"], **text)
    tip_text = (shown.stdout or "") if shown.returncode == 0 else ""
    extra = run(["git", "-C", str(root), "diff", "--no-index", "-U0", "--", "-", str(root / path)], input=tip_text, **text)
    # git diff --no-index: 0 when equal, 1 when they differ, more on an error.
    if extra.returncode > 1 or "Binary files" in patch or "Binary files" in (extra.stdout or ""):
        return dict(_FAILED)
    added = not (hunk_lines(patch, "new") & hunk_lines(extra.stdout or "", "old"))
    tip_lines = set(tip_text.splitlines())
    copy = set((root / path).read_text(encoding="utf-8", errors="replace").splitlines())
    back = [b for b in removed_blocks(patch) if any(x.strip() and x in copy and x not in tip_lines for x in b)]
    hunks = sum(1 for line in (extra.stdout or "").splitlines() if line.startswith("@@"))
    return {"plan_lines": added and not back, "added_present": added, "removed_absent": not back,
            "extra_hunks": max(0, hunks - len(back))}


def image_ids(run: Optional[Exec] = None) -> dict:
    """{agent, webapp}: the running containers' image ids, or "not checked" when they cannot be read."""
    try:
        done = (run or subprocess.run)(["docker", "inspect", AGENT_CONTAINER, WEBAPP_CONTAINER, "--format",
                                        "{{.Name}} {{.Image}}"], capture_output=True, text=True, check=False, timeout=60)
        pairs = dict(ln.split() for ln in (done.stdout or "").splitlines() if len(ln.split()) == 2)
    except (OSError, ValueError, subprocess.SubprocessError):
        pairs = {}
    return {"agent": pairs.get(f"/{AGENT_CONTAINER}", "not checked"), "webapp": pairs.get(f"/{WEBAPP_CONTAINER}", "not checked")}


def record_build(phase: str, run: Optional[Exec] = None, path: Path = BUILD_RECORD, root: Path = REPO) -> str:
    """The build record run/s15/rebuild.sh writes around a rebuild: ``before`` the builds, the plan
    tip and every file of the tree that is not the tip's; ``after`` the containers are up, their
    image ids, and whether the tree changed during the build. Returns a one-line summary."""
    run = run or subprocess.run
    # docker-compose.yml too: compose reads it at `up`, after the builds, so a change voids the record.
    prefixes = [p for p, _ in AGENT_BAKED] + list(WEBAPP_SOURCES) + list(SHARED_CONFIG)
    tip = (run(["git", "-C", str(root), "rev-parse", "--verify", "--quiet", PLAN_REF], capture_output=True, text=True,
               check=False, timeout=60).stdout or "").strip()
    differences = tree_differences(tip, prefixes, run, root=root)
    if phase == "before":
        base = (run(["git", "-C", str(root), "merge-base", tip, "HEAD"], capture_output=True, text=True, check=False,
                    timeout=60).stdout or "").strip()
        # Every path the plan changed, by itself: --no-renames, so a rename's old path is one too (the
        # tree may still hold it); NUL-separated, so a name with a space or one git quotes is whole.
        changed = {p for p in (run(["git", "-C", str(root), "diff", "--name-only", "--no-renames", "-z", base, tip,
                                    "--", *prefixes], capture_output=True, text=True, check=False,
                                   timeout=120).stdout or "").split("\0") if p}
        shared = {f: plan_file_check(f, base, tip, run, root=root) for f in sorted(differences) if f in changed}
        record = {"format": 1, "tip": tip, "base": base, "recorded_at": now_iso(), "differences": differences,
                  "plan_files": sorted(changed), "shared_checks": shared, "complete": False}
    else:
        record = json.loads(path.read_text(encoding="utf-8"))
        record.update(images=image_ids(run), completed_at=now_iso(),
                      complete=record.get("tip") == tip and record.get("differences") == differences,
                      tree_changed=record.get("differences") != differences or record.get("tip") != tip)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    checks_ = record.get("shared_checks") or {}
    bad = sorted(p for p, c in checks_.items() if not c.get("plan_lines"))
    return (f"build record {phase}: plan {tip[:8]}, {len(differences)} files not the tip's, {len(checks_)} of them "
            f"plan files with another session's hunks"
            + (f" ({len(bad)} not holding the plan's diff: {', '.join(bad[:6])}{'…' if len(bad) > 6 else ''})" if bad else "")
            + (f", images {record['images']['agent'][7:19]} / {record['images']['webapp'][7:19]}" if phase == "after" else ""))


def agent_mount_problem(run: Optional[Exec] = None) -> Optional[str]:
    """Why the running agent's mounts are not the plan's compose file's, or None: one the plan
    removed is a container started from an older copy, which the build record cannot see."""
    try:
        done = (run or subprocess.run)(["docker", "inspect", "--format", "{{json .Mounts}}", AGENT_CONTAINER],
                                       capture_output=True, text=True, check=False, timeout=30)
        mounts = json.loads(done.stdout or "") if done.returncode == 0 else None
    except (OSError, ValueError, subprocess.SubprocessError):
        mounts = None
    if not isinstance(mounts, list):
        return "the running agent's mounts could not be read: the code is not verified"
    removed = [m.get("Name") or m.get("Destination") for m in mounts if isinstance(m, dict)
               and any(m.get(k) == v for k, v in REMOVED_MOUNT.items())]
    if removed:
        return (f"the running agent mounts {', '.join(removed)}, which plan {PLAN_REF.rsplit('/', 1)[-1]} removed from "
                "docker-compose.yml: it was started from an older copy (compose up again)")
    return None


def read_build_record(path: Path = BUILD_RECORD) -> Optional[dict]:
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return record if isinstance(record, dict) else None


def verify_code(record: Optional[Mapping], run: Optional[Exec] = None, *, deep: bool = True) -> tuple:
    """(problems, lines): whether the running stack is the code the report names. ``deep`` also
    compares the running agent's baked files one by one (the preflight; the end checks ids and tip)."""
    run = run or subprocess.run
    problems: list = []
    if not record or not record.get("complete"):
        why = "none" if not record else ("the tree changed during that build" if record.get("tree_changed")
                                         else "not completed")
        return [f"no usable build record ({BUILD_RECORD.name}: {why}; run/s15/rebuild.sh writes it)"], {}
    tip = record["tip"]
    lines = {"commit": f"plan {tip[:8]}"}
    if record.get("base") != PLAN_BASE:
        problems.append(f"the build record's base {(record.get('base') or 'none')[:8]} is not the plan's base "
                        f"{PLAN_BASE[:8]}: its plan diff is not the plan's")
    try:
        now_tip = (run(["git", "-C", str(REPO), "rev-parse", "--verify", "--quiet", PLAN_REF], capture_output=True,
                       text=True, check=False, timeout=60).stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        now_tip = ""
    if now_tip != tip:
        problems.append(f"the stack was built from plan {tip[:8]}, the branch is at {now_tip[:8] or 'unknown'}: rebuild")
    differences = record.get("differences") or {}
    plan = set(record.get("plan_files") or [])
    if not plan:
        problems.append("the build record names no plan file: rerun run/s15/rebuild.sh")
    checks_ = record.get("shared_checks") or {}
    carried = sorted(set(p for p in differences if p in plan) | set(checks_))
    # A plan file may carry another session's lines, never lack the plan's own nor keep what it removed.
    missing = [p for p in carried if not (checks_.get(p) or {}).get("plan_lines")]
    if missing:
        problems.append(f"the copy of {', '.join(missing[:6])}{'…' if len(missing) > 6 else ''} is not plan "
                        f"{tip[:8]}'s own diff (a line it adds is missing, a block it removes is back, or it was "
                        "not checked): not the plan's code")
    named = [f"{p} (+{(checks_.get(p) or {}).get('extra_hunks', '?')} hunks of another session)" for p in carried]
    other = sorted(p for p in differences if p not in plan)
    lines["known_hunks"] = (", ".join(named) or "none") + (
        f"; outside the plan's files, {len(other)} files of the checkout's own work ({', '.join(other[:5])}"
        f"{'…' if len(other) > 5 else ''})" if other else "")
    images = image_ids(run)
    want = record.get("images") or {}
    for name in ("agent", "webapp"):
        if images.get(name) != want.get(name):
            problems.append(f"the running {name} is image {str(images.get(name))[7:19] or images.get(name)}, not the "
                            f"recorded build's {str(want.get(name))[7:19]}")
    lines["images"] = f"agent {str(images.get('agent'))[7:19]}, webapp {str(images.get('webapp'))[7:19]}"
    mount = agent_mount_problem(run)
    if mount:
        problems.append(mount)
    if deep:
        try:
            tip_map = tip_files(tip, [p for p, _ in AGENT_BAKED], run)
            asked = sorted({baked_path(p) for p in list(tip_map) + list(record.get("differences") or {})} - {None})
            done = run(["docker", "exec", "-i", AGENT_CONTAINER, "python", "-c", AGENT_FILES_SCRIPT],
                       input=json.dumps({"root": "/app", "paths": asked}), capture_output=True, text=True, check=False,
                       timeout=120)
            got = json.loads((done.stdout or "").strip().splitlines()[-1]) if done.returncode == 0 else None
        except (OSError, ValueError, IndexError, subprocess.SubprocessError):
            got = None
        if not got:
            problems.append("the running agent's files could not be read: the code is not verified")
        else:
            diff = compare_baked(tip_map, record.get("differences") or {}, got["files"], got["py"])
            if diff["differing"] or diff["extra"]:
                problems.append(f"the running agent is not plan {tip[:8]} plus the recorded hunks: {len(diff['differing'])} "
                                f"of {diff['files']} files differ ({', '.join(diff['differing'][:6])}), "
                                f"{len(diff['extra'])} more Python files ({', '.join(diff['extra'][:4])})")
            lines["agent_code"] = f"{diff['files']} baked files compared, " + (
                "all plan " + tip[:8] + "'s or a recorded hunk" if not (diff["differing"] or diff["extra"]) else "DIFFER")
    return problems, lines


LAYER1 = "layer1"


def only_filters(only: Sequence[str]) -> tuple[list, bool]:
    """``--only``'s run filters, and whether the layer-1 checks run: always in a full matrix;
    with ``--only``, only when ``layer1`` is one of its values (a cell's re-run skips them)."""
    filters = [o for o in only if o.strip() and o.strip() != LAYER1]
    return filters, (LAYER1 in [o.strip() for o in only]) or not filters


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--lanes", type=int, default=None, help="parallel lanes (default: scenarios.yaml, 7)")
    ap.add_argument("--only", action="append", default=[], help="a run id, lab, arm, lab-arm or single check, or "
                    "layer1 (the layer-1 checks alone); repeatable")
    ap.add_argument("--dry-run", action="store_true", help="print the plan and exit; starts nothing")
    ap.add_argument("--model", default="", help="the agent model of every run's project (required for a run): "
                    "one the e2e owner's provider serves")
    ap.add_argument("--agent-logs", default="", help="the host folder of the agent's session logs "
                    "(default: the source of the agent container's /app/logs mount)")
    ap.add_argument("--no-restore", action="store_true", help="do not restore the library snapshot first")
    ap.add_argument("--no-build", action="store_true", help="do not build the lab images in the preflight")
    ap.add_argument("--no-layer1", action="store_true", help="skip the layer-1 checks")
    ap.add_argument("--scenarios", default=str(SCENARIOS))
    ap.add_argument("--record-build", choices=("before", "after"), default="",
                    help="write the build record around a rebuild (run/s15/rebuild.sh), then exit")
    args = ap.parse_args(argv)
    if args.record_build:
        print(record_build(args.record_build))
        return 0

    redact = report.Redactor()
    log = Log(redact)
    scn = load_scenarios(Path(args.scenarios))
    lane_count = args.lanes or int(scn["lanes"]["default"])
    run_filters, layer1_wanted = only_filters(args.only)
    # Every run in a full matrix; none when --only names the layer-1 checks alone.
    layer1_alone = bool(args.only) and not run_filters
    runs = [] if layer1_alone else lanes.select(lanes.plan_runs(scn), run_filters)
    env = read_env(REPO / ".env", redact)
    if not runs and not layer1_wanted:
        log("no run matches --only")
        return 2
    if args.dry_run:
        if not runs:
            print(f"Tradecraft 2.0 matrix: the layer-1 checks alone ({len(scn['layer1']['retrieval'])} retrieval "
                  "questions, then the ops account's refresh, cancel, stale and delete checks); no agent run")
            return 0
        return dry_run(scn, runs, lane_count, env, out=lambda s: print(redact(s)))
    if not args.model:
        log("--model is required: the agent model every run's project uses, one the e2e owner's provider serves")
        return 2

    # The budget counts from here: the preflight is part of the 5 hours.
    matrix_start = time.monotonic()
    # Before anything runs: the stack is the code the report will name, or nothing runs at all.
    record = read_build_record()
    problems, code = verify_code(record)
    if problems:
        for p in problems:
            log(f"preflight: code not verified: {p}")
        return 3
    log(f"code: {code['commit']} plus the shared files' recorded hunks ({code['known_hunks']}); {code['agent_code']}; "
        f"images {code['images']}")
    plan = lanes.budget(scn)
    stamp = _dt.datetime.now().strftime("%Y-%m-%d_%H%M")
    out_dir = RUNS_DIR / stamp
    stack = Stack(env, redact, log)
    db = Db()
    docker = labs.Docker(REPO, log=log)
    try:
        accounts = seed_accounts(scn["accounts"], redact)
    except ValueError as exc:
        log(f"refused: {exc}")
        return 2
    sessions = {k: stack.session(a.email, a.password) for k, a in accounts.items()}
    logs_dir = Path(args.agent_logs) if args.agent_logs else (agent_logs_dir() or LOGS_DIR)
    ctx = Context(scn=scn, env=env, redact=redact, log=log, stack=stack, db=db, docker=docker, accounts=accounts,
                  sessions=sessions, model=args.model, out_dir=out_dir, logs_dir=logs_dir)
    started = now_iso()
    problems = preflight(ctx, runs, restore=not args.no_restore, build=not args.no_build)
    if problems:
        for p in problems:
            log(f"preflight: {p}")
        return 3
    layer1_results: list[report.CheckResult] = []
    layer1_thread = None
    end_by = matrix_start + plan.end_by_sec
    if layer1_wanted and not args.no_layer1:
        layer1_thread = threading.Thread(target=lambda: layer1_results.extend(layer1(ctx, end_by)), daemon=True)
        layer1_thread.start()
    results = run_matrix(ctx, runs, lane_count, started_at=matrix_start) if runs else []
    if layer1_thread:
        layer1_thread.join(timeout=max(0.0, time_left(end_by)))
        if layer1_thread.is_alive():
            layer1_results = list(layer1_results) + [report.CheckResult(
                "layer1_finished", False, "the layer-1 checks did not finish within the budget")]
    try:
        set_owner_mode(ctx, str((scn.get("owner_search") or {}).get("librarian.use", "agent")))
    except RuntimeError as exc:
        log(str(exc))
    verdict, gates = report.pass_rules(results, oracle_min=int(scn["pass_rules"]["oracle_min"]), layer1=layer1_results,
                                       expected=[r.id for r in runs])
    try:
        # The ids and the tip again: a rebuild or a new commit during the run voids its verdict.
        end_problems, _ = verify_code(record, deep=False)
    except Exception as exc:  # a probe that could not run is not a verified run
        end_problems = [f"the end check could not run ({type(exc).__name__})"]
    if end_problems:
        verdict = False
        code["code_verified"] = "NO: " + "; ".join(end_problems)
    else:
        code["code_verified"] = "yes, at the start and at the end"
    timeline = lanes.worst_case(runs, lane_count, plan)
    meta = {"started": started, "finished": now_iso(), **code, "model": ctx.model, "lanes": lane_count,
            "projected_worst_case": f"{timeline.makespan / 3600:.2f} h from the start, preflight included",
            "wall_clock": f"{(time.monotonic() - matrix_start) / 3600:.2f} h"}
    text = report.render(results=results, gates=gates, verdict=verdict, meta=meta, gain_table=report.gain(results),
                         durations={r.run_id: r.seconds for r in results if r.seconds}, redact=redact)
    path = report.write_report(out_dir, text)
    log(f"report: {path} ({'PASSED' if verdict else 'FAILED'})")
    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main())

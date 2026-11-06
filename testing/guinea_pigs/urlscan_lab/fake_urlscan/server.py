#!/usr/bin/env python3
"""The urlscan lab's fake urlscan.io: the search API in the format of plan §10.1.

    python3 server.py --fixtures /fixtures/visits.json [--port 80] [--log-dir /logs]

Stdlib only (python:3.12-slim). Answers

    GET  /api/v1/search/?q=&size=&search_after=<ms>,<uuid>   the search (header API-Key optional)
    GET  /api/v1/result/<uuid>/       401 without a key, 404 with one (no item uses it)
    GET  /screenshots/<uuid>.png      a 1x1 PNG, so a UI that shows the screenshot stays local
    POST /__lab/fail {query_regex, status: 429|403|400, times, search_after?: bool}
    GET  /__lab/log                   every search: query, size, search_after, key sent or not, status, counts
    POST /__lab/reset                 clears the failure rules, the log and the rate windows
    GET  /__lab/health

The search logic is plain functions over a list of visits (parse_query,
matches, run_search, render) so check_fixtures.py and the unit test render
every answer through this very code without opening a socket.

The key value is never logged or echoed. A key that is not the lab key gets a
401: a real key that reached the lab by mistake must not look like a working run.
"""
from __future__ import annotations

import argparse
import copy
import fnmatch
import json
import math
import os
import re
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

ANON_PAGE_CAP = 100
KEYED_PAGE_CAP = 1000
DEFAULT_SIZE = 100
TOTAL_CAP = 10_000
ANON_WINDOW_DAYS = 30
ANON_RATE_PER_MIN = 30
# Not captured (needs a key); a value that never throttles a single lab run.
KEYED_RATE_PER_MIN = 120

FORBIDDEN_MESSAGE = ("Regular Expressions and leading wildcard searches are not supported "
                     "for anonymous users, please create a user-account.")

# Domain fields match the name and every subdomain (§10.1: page.domain does,
# without a key too); the apex and enum-like fields match exactly.
DOMAIN_FIELDS = {"page.domain", "task.domain"}
EXACT_FIELDS = {"page.apexDomain", "task.apexDomain", "page.redirected"}
FIELDS = DOMAIN_FIELDS | EXACT_FIELDS | {"domain", "task.tags", "hash", "filename"}

# What a fixture may contribute to an answer. Lab-only keys (age_days,
# touched_domains, files, lab_id, group) are never copied: render() builds from
# this list, so they cannot leak.
RESPONSE_KEYS = ("submitter", "canonical", "task", "stats", "page", "labels")

PNG_1X1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000d49444154789c6360000002000154a24f650000000049454e44ae426082")


class QueryError(Exception):
    def __init__(self, status: int, title: str, detail: str, message: str | None = None):
        super().__init__(detail)
        self.status, self.title, self.detail = status, title, detail
        self.message = message or detail


def error_body(status: int, title: str, detail: str, message: str | None = None) -> dict:
    return {"message": message or detail, "status": status,
            "errors": [{"title": title, "detail": detail, "status": status}]}


# --------------------------------------------------------------------------- query language

_TOKEN = re.compile(r'\s*(?:(\()|(\))|([^\s()"]*"(?:[^"\\]|\\.)*"|[^\s()"]+))')


def tokenize(q: str) -> list[str]:
    tokens, pos, q = [], 0, q.strip()
    while pos < len(q):
        m = _TOKEN.match(q, pos)
        if not m or m.end() == pos:
            raise QueryError(400, "Bad Request", f"cannot parse the query near {q[pos:pos + 20]!r}")
        tokens.append(m.group(1) or m.group(2) or m.group(3))
        pos = m.end()
        while pos < len(q) and q[pos].isspace():
            pos += 1
    return tokens


def _term(token: str) -> tuple:
    if ":" not in token:
        raise QueryError(400, "Bad Request", f"free-text term {token!r}: the lab answers field:value terms only")
    field, raw = token.split(":", 1)
    if field not in FIELDS:
        raise QueryError(400, "Bad Request", f"unknown field {field!r}")
    if not raw:
        raise QueryError(400, "Bad Request", f"empty value for {field}")
    if raw.startswith('"'):
        if len(raw) < 2 or not raw.endswith('"'):
            raise QueryError(400, "Bad Request", f"unterminated quote in {token!r}")
        return ("term", field, re.sub(r"\\(.)", r"\1", raw[1:-1]).lower(), "exact")
    if len(raw) > 1 and raw.startswith("/") and raw.endswith("/"):
        return ("term", field, raw[1:-1], "regex")
    if "*" in raw or "?" in raw:
        return ("term", field, raw.lower(), "leading_wildcard" if raw[0] in "*?" else "wildcard")
    return ("term", field, raw.lower(), "exact")


def parse_query(q: str) -> tuple:
    """field:value, quoted values, AND, OR, NOT, AND NOT, parentheses.

    Precedence NOT > AND > OR; two terms side by side are an AND. Raises
    QueryError(400) for anything else.
    """
    tokens = tokenize(q)
    if not tokens:
        raise QueryError(400, "Bad Request", "empty query")
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take():
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def expr():
        node = and_expr()
        while peek() == "OR":
            take()
            node = ("or", node, and_expr())
        return node

    def and_expr():
        node = unary()
        while peek() not in (None, "OR", ")"):
            if peek() == "AND":
                take()
            node = ("and", node, unary())
        return node

    def unary():
        tok = peek()
        if tok is None:
            raise QueryError(400, "Bad Request", "the query ends where a term was expected")
        if tok == "NOT":
            take()
            return ("not", unary())
        if tok == "(":
            take()
            node = expr()
            if peek() != ")":
                raise QueryError(400, "Bad Request", "unbalanced parentheses")
            take()
            return node
        if tok in (")", "AND", "OR"):
            raise QueryError(400, "Bad Request", f"unexpected {tok!r}")
        return _term(take())

    node = expr()
    if pos != len(tokens):
        raise QueryError(400, "Bad Request", f"unexpected {tokens[pos]!r}")
    return node


def check_access(node: tuple, keyed: bool) -> None:
    """Without a key, a leading wildcard or a regex is a 403, as on urlscan."""
    if keyed:
        return
    if node[0] == "term":
        if node[3] in ("regex", "leading_wildcard"):
            raise QueryError(403, "Forbidden", FORBIDDEN_MESSAGE, FORBIDDEN_MESSAGE)
        return
    for child in node[1:]:
        check_access(child, keyed)


def _value_match(candidate: str, value: str, kind: str, subdomains: bool) -> bool:
    candidate = (candidate or "").lower()
    if not candidate:
        return False
    if kind == "regex":
        return re.fullmatch(value, candidate, re.IGNORECASE) is not None
    if kind in ("wildcard", "leading_wildcard"):
        return fnmatch.fnmatchcase(candidate, value)
    return candidate == value or (subdomains and candidate.endswith("." + value))


def matches(node: tuple, visit: dict) -> bool:
    kind = node[0]
    if kind == "and":
        return matches(node[1], visit) and matches(node[2], visit)
    if kind == "or":
        return matches(node[1], visit) or matches(node[2], visit)
    if kind == "not":
        return not matches(node[1], visit)
    _, field, value, vkind = node
    page, task = visit.get("page", {}), visit.get("task", {})
    if field == "page.domain":
        return _value_match(page.get("domain"), value, vkind, True)
    if field == "task.domain":
        return _value_match(task.get("domain"), value, vkind, True)
    if field == "domain":
        names = [page.get("domain"), task.get("domain"), *visit.get("touched_domains", [])]
        return any(_value_match(n, value, vkind, True) for n in names)
    if field == "page.apexDomain":
        return _value_match(page.get("apexDomain"), value, vkind, False)
    if field == "task.apexDomain":
        return _value_match(task.get("apexDomain"), value, vkind, False)
    if field == "page.redirected":
        return _value_match(page.get("redirected"), value, vkind, False)
    if field == "task.tags":
        return any(_value_match(t, value, vkind, False) for t in task.get("tags", []))
    if field == "hash":
        return any(_value_match(f.get("sha256"), value, vkind, False) for f in visit.get("files", []))
    if field == "filename":
        return any(_value_match(str(f.get("name", "")).rsplit("/", 1)[-1], value, vkind, False)
                   for f in visit.get("files", []))
    return False


# --------------------------------------------------------------------------- rendering

def iso_ms(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def visit_time(visit: dict, lab_start: datetime) -> datetime:
    # Relative to the lab's start, never to "now": a lab left running for days
    # keeps the same 30-day window and the same answers.
    t = lab_start - timedelta(days=float(visit["age_days"]))
    return t.replace(microsecond=(t.microsecond // 1000) * 1000)


def sort_key(visit: dict, lab_start: datetime) -> tuple[int, str]:
    t = visit_time(visit, lab_start)
    return int(t.timestamp() * 1000), visit["task"]["uuid"]


def render(visit: dict, lab_start: datetime, keyed: bool, public_base: str) -> dict:
    t = visit_time(visit, lab_start)
    out = {k: copy.deepcopy(visit[k]) for k in RESPONSE_KEYS if k in visit}
    out["task"]["time"] = iso_ms(t)
    page = out.get("page", {})
    if "tlsAgeDays" in page and "tlsIssuer" in page and "tlsValidFrom" not in page:
        valid_from = (t - timedelta(days=int(page["tlsAgeDays"]))).replace(microsecond=0)
        page["tlsValidFrom"] = iso_ms(valid_from)
    if keyed and "verdicts" in visit:
        out["verdicts"] = copy.deepcopy(visit["verdicts"])
    uuid = out["task"]["uuid"]
    ms = int(t.timestamp() * 1000)
    out["_id"] = uuid
    out["_score"] = None
    out["sort"] = [ms, uuid]
    out["result"] = f"{public_base}/api/v1/result/{uuid}/"
    out["screenshot"] = f"{public_base}/screenshots/{uuid}.png"
    return out


def run_search(visits: list[dict], q: str, size, search_after, keyed: bool,
               lab_start: datetime, public_base: str) -> tuple[int, dict]:
    """One search, as urlscan answers it: (status, body)."""
    started = time.monotonic()
    try:
        if not q:
            raise QueryError(400, "Bad Request", "missing q")
        node = parse_query(q)
        check_access(node, keyed)
        try:
            asked = DEFAULT_SIZE if size in (None, "") else int(size)
        except (TypeError, ValueError):
            raise QueryError(400, "Bad Request", f"size must be an integer, got {size!r}") from None
        if asked < 1:
            raise QueryError(400, "Bad Request", "size must be at least 1")
        cursor = None
        if search_after:
            ms, sep, uuid = str(search_after).partition(",")
            try:
                cursor = (int(ms), uuid.strip().lower())
            except ValueError:
                raise QueryError(400, "Bad Request", f"bad search_after {search_after!r}") from None
            if not sep or not cursor[1]:
                raise QueryError(400, "Bad Request", f"bad search_after {search_after!r}")
    except QueryError as e:
        return e.status, error_body(e.status, e.title, e.detail, e.message)

    pool = visits if keyed else [v for v in visits if float(v["age_days"]) <= ANON_WINDOW_DAYS]
    found = sorted(((sort_key(v, lab_start), v) for v in pool if matches(node, v)),
                   key=lambda kv: kv[0], reverse=True)
    count = len(found)
    if cursor is not None:
        found = [kv for kv in found if kv[0] < cursor]
    page_size = min(asked, KEYED_PAGE_CAP if keyed else ANON_PAGE_CAP)
    body = {
        "results": [render(v, lab_start, keyed, public_base) for _, v in found[:page_size]],
        "total": min(count, TOTAL_CAP),
        "took": int((time.monotonic() - started) * 1000),
        # §10.1: true only above the 10,000 cap; it does NOT say a next page exists.
        "has_more": count > TOTAL_CAP,
    }
    if not keyed:
        body["search_date_limit_days"] = ANON_WINDOW_DAYS
    return 200, body


# --------------------------------------------------------------------------- lab state

class LabState:
    """Failure rules, the search log and the per-minute rate windows."""

    def __init__(self, visits: list[dict], *, lab_start: datetime | None = None,
                 public_base: str = "http://192.88.97.30", lab_key: str = "lab-key",
                 clock=time.time, log_path: str | None = None):
        self.visits = visits
        self.lab_start = lab_start or datetime.fromtimestamp(int(clock() * 1000) / 1000, timezone.utc)
        self.public_base = public_base.rstrip("/")
        self.lab_key = lab_key
        self.clock = clock
        self.log_path = log_path
        self.lock = threading.Lock()
        self.fail_rules: list[dict] = []
        self.log: list[dict] = []
        self.windows: dict[tuple, list] = {}

    def reset(self) -> None:
        with self.lock:
            self.fail_rules.clear()
            self.log.clear()
            self.windows.clear()

    def add_fail(self, spec: dict) -> dict:
        status = int(spec.get("status", 429))
        if status not in (400, 403, 429):
            raise ValueError("status must be 400, 403 or 429")
        times = int(spec.get("times", 1))
        if times < 1:
            raise ValueError("times must be at least 1")
        regex = str(spec.get("query_regex", ""))
        re.compile(regex)
        after = spec.get("search_after")
        if after is not None and not isinstance(after, bool):
            raise ValueError("search_after must be true, false or absent")
        rule = {"query_regex": regex, "status": status, "times": times, "search_after": after}
        with self.lock:
            self.fail_rules.append(rule)
        return rule

    def _rate(self, client: str, keyed: bool) -> tuple[bool, dict, int]:
        now = self.clock()
        bucket = int(now // 60)
        limit = KEYED_RATE_PER_MIN if keyed else ANON_RATE_PER_MIN
        with self.lock:
            window = self.windows.setdefault((client, keyed), [bucket, 0])
            if window[0] != bucket:
                window[:] = [bucket, 0]
            window[1] += 1
            used = window[1]
        reset_at = (bucket + 1) * 60
        reset_after = max(1, math.ceil(reset_at - now))
        # Names and anonymous values as captured on 6 Nov 2026; the keyed scope
        # was not captured (it needs a key).
        headers = {
            "x-rate-limit-scope": "user" if keyed else "ip-address",
            "x-rate-limit-action": "search",
            "x-rate-limit-window": "minute",
            "x-rate-limit-limit": str(limit),
            "x-rate-limit-remaining": str(max(limit - used, 0)),
            "x-rate-limit-reset": iso_ms(datetime.fromtimestamp(reset_at, timezone.utc)),
            "x-rate-limit-reset-after": str(reset_after),
            "x-rate-limit-concurrency-rank": "0",
            "x-rate-limit-concurrency-limit": "10",
        }
        return used > limit, headers, reset_after

    def _forced(self, q: str, search_after) -> int | None:
        with self.lock:
            for rule in self.fail_rules:
                if rule["times"] < 1 or not re.search(rule["query_regex"], q or ""):
                    continue
                if rule["search_after"] is not None and rule["search_after"] != bool(search_after):
                    continue
                rule["times"] -= 1
                return rule["status"]
        return None

    def handle_search(self, query_string: str, api_key: str | None, client: str) -> tuple[int, dict, dict]:
        params = parse_qs(query_string or "", keep_blank_values=True)
        q = (params.get("q") or [""])[0]
        size = (params.get("size") or [None])[0]
        search_after = (params.get("search_after") or [None])[0]
        key_sent = bool(api_key)
        keyed = key_sent and api_key == self.lab_key
        limited, headers, retry_after = self._rate(client, keyed)
        forced = None
        if key_sent and not keyed:
            status, body = 401, error_body(401, "Unauthorized", "This API key is not the lab key.")
        elif limited:
            status, body = 429, error_body(429, "Too Many Requests",
                                           "Rate limit for search exceeded, please wait until the reset time.")
        else:
            forced = self._forced(q, search_after)
            if forced == 429:
                status, body = 429, error_body(429, "Too Many Requests",
                                               "Rate limit for search exceeded, please wait until the reset time.")
            elif forced == 403:
                status, body = 403, error_body(403, "Forbidden", FORBIDDEN_MESSAGE, FORBIDDEN_MESSAGE)
            elif forced == 400:
                status, body = 400, error_body(400, "Bad Request", "Failed to parse the query (forced by the lab).")
            else:
                status, body = run_search(self.visits, q, size, search_after, keyed,
                                          self.lab_start, self.public_base)
        if status == 429:
            headers["Retry-After"] = str(retry_after)
        entry = {
            "time": iso_ms(datetime.fromtimestamp(self.clock(), timezone.utc)),
            "query": q, "size": size, "search_after": search_after,
            "key_sent": key_sent, "key_is_lab_key": keyed if key_sent else None,
            "status": status, "forced": forced is not None,
            "results": len(body.get("results", [])) if status == 200 else 0,
            "total": body.get("total") if status == 200 else None,
            "client": client,
        }
        with self.lock:
            self.log.append(entry)
        if self.log_path:
            try:
                with open(self.log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry) + "\n")
            except OSError:
                pass
        return status, headers, body


def load_visits(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    visits = data["visits"] if isinstance(data, dict) else data
    for v in visits:
        if "age_days" not in v or "uuid" not in v.get("task", {}):
            raise ValueError(f"fixture without age_days or task.uuid: {v.get('lab_id')!r}")
    return visits


# --------------------------------------------------------------------------- HTTP

_RESULT = re.compile(r"^/api/v1/result/([0-9a-f-]{36})/?$")
_SHOT = re.compile(r"^/screenshots/([0-9a-f-]{36})\.png$")


def make_handler(state: LabState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "uslab-fake-urlscan/1"

        def log_message(self, fmt, *args):
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

        def _send(self, status: int, body, headers: dict | None = None, ctype="application/json; charset=utf-8"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def do_GET(self):
            parts = urlsplit(self.path)
            path = parts.path
            if path in ("/api/v1/search/", "/api/v1/search"):
                status, headers, body = state.handle_search(
                    parts.query, self.headers.get("API-Key"), self.client_address[0])
                return self._send(status, body, headers)
            m = _RESULT.match(path)
            if m:
                if self.headers.get("API-Key"):
                    return self._send(404, error_body(404, "Not Found", "The lab keeps no result documents."))
                return self._send(401, error_body(401, "Unauthorized", "The Result API needs an API key."))
            if _SHOT.match(path):
                return self._send(200, PNG_1X1, ctype="image/png")
            if path == "/__lab/log":
                with state.lock:
                    return self._send(200, list(state.log))
            if path == "/__lab/health":
                return self._send(200, {"visits": len(state.visits), "lab_start": iso_ms(state.lab_start)})
            return self._send(404, error_body(404, "Not Found", "No such route in the lab."))

        do_HEAD = do_GET

        def do_POST(self):
            path = urlsplit(self.path).path
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            if path == "/__lab/reset":
                state.reset()
                return self._send(200, {"reset": True})
            if path == "/__lab/fail":
                try:
                    rule = state.add_fail(json.loads(raw or b"{}"))
                except (ValueError, re.error, TypeError) as e:
                    return self._send(400, error_body(400, "Bad Request", str(e)))
                return self._send(200, {"rule": rule})
            return self._send(404, error_body(404, "Not Found", "No such route in the lab."))

    return Handler


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--fixtures", default="/fixtures/visits.json")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--log-dir", default=os.environ.get("USLAB_LOG_DIR", "/logs"))
    a = ap.parse_args()
    visits = load_visits(a.fixtures)
    log_path = os.path.join(a.log_dir, "searches.jsonl") if os.path.isdir(a.log_dir) else None
    state = LabState(visits, public_base=os.environ.get("USLAB_PUBLIC_BASE", "http://192.88.97.30"),
                     lab_key=os.environ.get("USLAB_LAB_KEY", "lab-key"), log_path=log_path)
    httpd = ThreadingHTTPServer((a.bind, a.port), make_handler(state))
    print(f"fake urlscan: {len(visits)} visits, lab start {iso_ms(state.lab_start)}, "
          f"listening on {a.bind}:{a.port}", flush=True)
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

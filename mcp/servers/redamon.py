"""
redamon — the `proxy_brain` SDK. Runs inside kali-sandbox; the agent's
`proxy_brain` code does `import redamon` and drives the captured-traffic corpus
and the active replay path through it.

It holds NO database credential and opens NO socket to Postgres. Every capability
is an authenticated HTTP call to the agent's `/traffic/exec` (read) and
`/traffic/replay` (active PREPARE) endpoints — the mirror of the redagraph ->
/graph/exec broker. Tenant identity is carried by the signed `REDAMON_CTX` tag
(minted by the agent, which holds INTERNAL_API_KEY; this worker does not), so a
foothold here cannot read or send for a tenant it was not issued for.

Env (injected per-invocation by the proxy_brain MCP tool):
  REDAMON_AGENT_URL  - the agent base URL (default http://agent:8080)
  SCANNER_API_KEY    - scoped transport auth (X-Internal-Key)
  REDAMON_CTX        - the signed agent tag (tenant/session/phase claims)
"""
from __future__ import annotations

import atexit
import base64
import binascii
import gzip
import hashlib
import hmac
import json
import os
import shlex
import subprocess
import sys
import urllib.parse
from typing import Any, Dict, List, Optional

import requests

_TIMEOUT = 60
_CURL_TIMEOUT = 45
_BROWSER_NAV_TIMEOUT = 30000  # ms


def _agent_url() -> str:
    return os.environ.get("REDAMON_AGENT_URL", "http://agent:8080").rstrip("/")


def _ctx() -> str:
    tok = os.environ.get("REDAMON_CTX", "").strip()
    if not tok:
        _die("no REDAMON_CTX in the environment — proxy_brain must be launched by the agent "
             "so the tenant/session context is set.")
    return tok


def _headers() -> Dict[str, str]:
    h = {}
    key = os.environ.get("SCANNER_API_KEY", "").strip()
    if key:
        h["X-Internal-Key"] = key
    return h


def _die(msg: str) -> None:
    print(f"redamon: {msg}", file=sys.stderr)
    raise SystemExit(2)


def _post(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    body = {**payload, "ctx": _ctx()}
    try:
        r = requests.post(f"{_agent_url()}{path}", json=body, headers=_headers(), timeout=_TIMEOUT)
    except requests.RequestException as e:
        _die(f"cannot reach agent at {_agent_url()}{path}: {e}")
    if r.status_code == 200:
        return r.json()
    try:
        err = r.json().get("error", r.text)
    except Exception:  # noqa: BLE001
        err = r.text
    _die(f"{path} -> {r.status_code}: {err}")
    return {}  # unreachable


# --------------------------------------------------------------------------
# Lightweight result wrappers (keep the recipes ergonomic: .id / .status / .body)
# --------------------------------------------------------------------------
class Txn:
    """A captured-transaction summary row (from search). Besides `.id`/`.raw`, the
    summary line is parsed into `.method`, `.status`, `.url` (host+path+query),
    `.host`, `.path` for convenience."""
    def __init__(self, id: str, raw: str):
        self.id = id
        self.raw = raw
        self.method = self.status = self.url = self.host = self.path = None
        p = (raw or "").split()
        if len(p) > 1:
            self.method = p[1]
        if len(p) > 2 and p[2].isdigit():
            self.status = int(p[2])
        if len(p) > 3:
            self.url = p[3]
            s = self.url.find("/")
            self.host = self.url[:s] if s > 0 else self.url
            self.path = self.url[s:] if s >= 0 else ""

    def __repr__(self):
        return self.raw or f"<Txn {self.id}>"


class Response:
    """A replayed request's response (parsed from curl -i)."""
    def __init__(self, status: Optional[int], headers: Dict[str, str], body: str, payload: Optional[str] = None):
        self.status = status
        self.headers = headers
        self.body = body
        self.length = len(body or "")
        self.payload = payload

    def __repr__(self):
        return f"<Response {self.status} {self.length}b" + (f" payload={self.payload!r}>" if self.payload is not None else ">")


# --------------------------------------------------------------------------
# READ — no traffic; every call is tenant-scoped server-side.
# --------------------------------------------------------------------------
def _read(op: str, args: Optional[Dict[str, Any]] = None) -> str:
    return _post("/traffic/exec", {"op": op, "args": args or {}}).get("result", "")


def search(filters: Optional[Dict[str, Any]] = None, **kwargs) -> List[Txn]:
    """Burp-style history search. Call EITHER with a dict of filters
    (redamon.search({"host": "x", "hasAuth": True})) OR with keyword filters
    (redamon.search(host="x", has_auth=True)) — both work. Filters: host, method,
    status, status_class/statusClass, tool, source, session/sessionId, run/runId,
    has_auth/hasAuth, reflected, only_5xx/only5xx, q, body_q/bodyq, limit. Returns
    Txn rows (use .id with get/replay)."""
    alias = {"status_class": "statusClass", "has_auth": "hasAuth", "only_5xx": "only5xx",
             "session": "sessionId", "run": "runId", "body_q": "bodyq"}
    merged: Dict[str, Any] = {}
    if isinstance(filters, dict):
        merged.update(filters)  # dict form is already endpoint-shaped; pass through
    merged.update({alias.get(k, k): v for k, v in kwargs.items()})  # kwargs: snake_case -> camelCase
    f = {k: v for k, v in merged.items() if v is not None}
    text = _read("search", f)
    out: List[Txn] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.endswith("transaction(s):") or line.startswith("No "):
            continue
        tok = line.split()
        if tok:
            out.append(Txn(tok[0], line))
    return out


def get(id: str, part: str = "response") -> str:
    """Full request/response (headers + body) of one transaction. part =
    request|response|both."""
    return _read("get", {"id": id, "part": part})


def sitemap() -> str:
    """Distinct observed endpoints (host+path+method) with hit counts."""
    return _read("sitemap")


def params() -> str:
    """Distinct request params with sample values + an injectability heuristic."""
    return _read("params")


def grep(pattern: str, limit: int = 50) -> str:
    """Substring search across captured response bodies (+ a snippet)."""
    return _read("grep", {"pattern": pattern, "limit": limit})


def diff(id_a: str, id_b: str) -> str:
    """Structural diff of two captured responses (status/length/headers/body)."""
    return _read("diff", {"id_a": id_a, "id_b": id_b})


def to_curl(id: str) -> str:
    """Render a captured request as a reproducible curl (sends nothing)."""
    return _read("to_curl", {"id": id})


def query(spec: Dict[str, Any]) -> str:
    """Constrained analytical query builder (allowlisted columns/aggs; no raw SQL)."""
    return _read("query", {"spec": spec})


# --------------------------------------------------------------------------
# DECODE / CRYPTO — pure, no network.
# --------------------------------------------------------------------------
def decode(value: str, max_depth: int = 6) -> str:
    """Best-effort peel of common encodings (url, base64, hex, gzip). Returns the
    fully-decoded value, or the last readable layer."""
    cur = str(value)
    for _ in range(max_depth):
        nxt = _decode_one(cur)
        if nxt is None or nxt == cur:
            break
        cur = nxt
    return cur


def _decode_one(s: str) -> Optional[str]:
    if "%" in s:
        u = urllib.parse.unquote(s)
        if u != s:
            return u
    st = s.strip()
    if len(st) >= 8 and all(c in "0123456789abcdefABCDEF" for c in st) and len(st) % 2 == 0:
        try:
            b = bytes.fromhex(st)
            if b[:2] == b"\x1f\x8b":
                return gzip.decompress(b).decode("utf-8", "replace")
            return b.decode("utf-8", "replace")
        except (ValueError, OSError):
            pass
    if len(st) >= 8 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_" for c in st):
        try:
            pad = st.replace("-", "+").replace("_", "/")
            pad += "=" * (-len(pad) % 4)
            b = base64.b64decode(pad, validate=False)
            if b[:2] == b"\x1f\x8b":
                return gzip.decompress(b).decode("utf-8", "replace")
            txt = b.decode("utf-8")
            if txt.isprintable() or "\n" in txt:
                return txt
        except (binascii.Error, ValueError, UnicodeDecodeError, OSError):
            pass
    return None


class Jwt:
    """A parsed JWT with forge helpers. Signing uses HS256 (alg:none / weak
    secret). Resend the forged token with replay(mutate={'headers': ...})."""
    def __init__(self, token: str):
        self.token = token
        parts = token.split(".")
        self.header = _jwt_seg(parts[0]) if len(parts) > 0 else {}
        self.payload = _jwt_seg(parts[1]) if len(parts) > 1 else {}

    def forge(self, alg_none: bool = False, secret: Optional[str] = None,
              claims: Optional[Dict[str, Any]] = None) -> str:
        payload = {**self.payload, **(claims or {})}
        if alg_none:
            header = {**self.header, "alg": "none"}
            return _b64u(json.dumps(header)) + "." + _b64u(json.dumps(payload)) + "."
        header = {**self.header, "alg": "HS256"}
        signing_input = (_b64u(json.dumps(header)) + "." + _b64u(json.dumps(payload))).encode()
        sig = hmac.new((secret or "").encode(), signing_input, hashlib.sha256).digest()
        return signing_input.decode() + "." + _b64u_bytes(sig)

    def __repr__(self):
        return f"<Jwt header={self.header} payload={self.payload}>"


def jwt(token: str) -> Jwt:
    return Jwt(token)


def _jwt_seg(seg: str) -> Dict[str, Any]:
    try:
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg))
    except Exception:  # noqa: BLE001
        return {}


def _b64u(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def _b64u_bytes(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


# --------------------------------------------------------------------------
# ACTIVE — host-pinned, egress-guarded, re-captured, per-send gated server-side.
# --------------------------------------------------------------------------
def replay(id: str, mutate: Optional[Dict[str, Any]] = None) -> Response:
    """Resend a captured request with fields changed (method/path/query/param/
    headers/dropHeaders/cookie/body). Host/scheme/port are PINNED to the origin
    by the agent — they cannot be changed here. Returns the parsed Response."""
    data = _post("/traffic/replay", {"op": "replay", "id": id, "mutate": mutate or {}})
    sends = data.get("sends") or []
    ctx = data.get("ctx", "")
    if not sends:
        _die("replay produced no request")
    return _run(sends[0]["curl_args"], ctx)


def batch(id: str, mutations: List[Dict[str, Any]], parallel: bool = False) -> List[Response]:
    """Replay one origin request once per mutation. With parallel=True the curls
    are fired CONCURRENTLY (real race-condition window: limit-overrun, double-spend,
    coupon/voucher reuse) — the agent prepares every request first, then releases
    them together. Each send is host-pinned + egress-guarded + re-captured."""
    if not parallel:
        return [replay(id, m) for m in mutations]
    # Prepare all requests (host-pinned curls) up front, then release the curls at
    # once so they collide in the same server-side window.
    prepared = []
    for m in mutations:
        data = _post("/traffic/replay", {"op": "replay", "id": id, "mutate": m or {}})
        sends = data.get("sends") or []
        if sends:
            prepared.append((sends[0]["curl_args"], data.get("ctx", "")))
    import concurrent.futures
    results: List[Optional[Response]] = [None] * len(prepared)
    workers = min(30, len(prepared) or 1)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_run, ca, ctx): i for i, (ca, ctx) in enumerate(prepared)}
        for fut in concurrent.futures.as_completed(futs):
            results[futs[fut]] = fut.result()
    return [r for r in results if r is not None]


def fuzz(id: str, insertion_point: str, payloads: List[str]) -> List[Response]:
    """Iterate `payloads` over the query param `insertion_point` on one captured
    request. Returns one Response per payload (server caps the count)."""
    data = _post("/traffic/replay", {"op": "fuzz", "id": id,
                                     "insertion_point": insertion_point,
                                     "payloads": [str(p) for p in payloads]})
    ctx = data.get("ctx", "")
    out: List[Response] = []
    for s in (data.get("sends") or []):
        out.append(_run(s["curl_args"], ctx, payload=s.get("payload")))
    return out


def _run(curl_args: str, ctx: str, payload: Optional[str] = None) -> Response:
    """Execute a prepared, host-pinned curl locally, routed through the capture
    proxy (so it is egress-guarded + re-captured) exactly like execute_curl."""
    args = shlex.split(curl_args)
    if "-i" not in args and "--include" not in args:
        args = ["-i"] + args
    try:
        from capture_routing import agent_capture_routing
        cap_url, cap_tok = agent_capture_routing(ctx)
    except Exception:  # noqa: BLE001
        cap_url, cap_tok = (None, None)
    if cap_url and cap_tok:
        args = args + ["-x", cap_url, "-k", "-H", f"X-Redamon-Ctx: {cap_tok}"]
    try:
        proc = subprocess.run(["curl", *args], capture_output=True, text=True, timeout=_CURL_TIMEOUT)
        raw = proc.stdout
    except subprocess.TimeoutExpired:
        return Response(None, {}, "[timeout]", payload)
    except Exception as e:  # noqa: BLE001
        return Response(None, {}, f"[curl error: {e}]", payload)
    return _parse_curl(raw, payload)


def _parse_curl(raw: str, payload: Optional[str]) -> Response:
    status: Optional[int] = None
    headers: Dict[str, str] = {}
    body = raw
    # Split the last header block from the body (handles proxy CONNECT + redirects).
    blocks = raw.split("\r\n\r\n") if "\r\n\r\n" in raw else raw.split("\n\n")
    if len(blocks) >= 2:
        head, body = blocks[0], "\n\n".join(blocks[1:])
        lines = head.splitlines()
        if lines and lines[0].startswith("HTTP/"):
            try:
                status = int(lines[0].split()[1])
            except (IndexError, ValueError):
                status = None
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
    return Response(status, headers, body, payload)


# --------------------------------------------------------------------------
# BROWSER — a real chromium as an oracle (DOM XSS, SPA, JS flows). Live traffic;
# host-pinned to the seed transaction's host, exploitation-phase + action-budget
# gated server-side at /traffic/browser, egress-guarded + re-captured.
# --------------------------------------------------------------------------
class Browser:
    """A live chromium pinned to the host of a captured transaction. Drive it to
    reach a signal that only exists AFTER JavaScript runs — the rendered DOM, a
    console message, or a fired alert() — the oracle curl replay cannot read.

    Budgeted actions (each is one server-checked step): goto, click, fill, submit,
    press, eval. Free reads (no budget): dom, text, html, console, alerts, url.
    Always close() when done. Do NOT drive it from batch(parallel=True) — sync
    Playwright is not thread-safe."""

    # Each live instance is a full chromium; too many at once OOMs the shared kali
    # container (1 GB). Cap concurrent live browsers per proxy_brain run and steer
    # the agent to close() first. (The server also budgets every open, so this is
    # defence-in-depth for the honest in-process path.)
    _live = 0
    _MAX_LIVE = 3

    def __init__(self, origin_id: str):
        # _closed starts True so a mid-init failure (or an early atexit) never
        # decrements _live for a browser that was never counted.
        self._closed = True
        if Browser._live >= Browser._MAX_LIVE:
            _die(f"browser: {Browser._live} browsers already open in this run "
                 f"(max {Browser._MAX_LIVE}); call .close() on one before opening another")
        self._origin_id = str(origin_id)
        data = _post("/traffic/browser", {"action": "open", "origin_id": self._origin_id})
        self._host = data.get("origin_host")
        self._scheme = data.get("scheme") or "http"
        self._port = data.get("port")
        cap_tag = data.get("ctx") or ""
        if not self._host:
            _die("browser: origin transaction has no host to pin to")
        try:
            from playwright.sync_api import sync_playwright
        except Exception as e:  # noqa: BLE001
            _die(f"browser: Playwright is unavailable in this sandbox: {e}")
        from browser_launch import BROWSER_ARGS, CHROME_UA, capture_kwargs
        proxy, headers = capture_kwargs(_ctx(), header_tag=cap_tag)
        self._alerts: List[str] = []
        self._console: List[str] = []
        self._pw = sync_playwright().start()
        try:
            self._browser = self._pw.chromium.launch(
                headless=True, args=BROWSER_ARGS, proxy=proxy,
            )
            self._context = self._browser.new_context(
                user_agent=CHROME_UA,
                ignore_https_errors=bool(proxy),  # trust the capture proxy MITM CA
                extra_http_headers=headers or {},
            )
            self._page = self._context.new_page()
        except Exception as e:  # noqa: BLE001
            self._pw.stop()
            _die(f"browser: chromium failed to launch: {e}")
        # Launch succeeded: now it is a live browser to be reaped. Register an
        # atexit fallback so a run that forgets close() still tears chromium down
        # on normal interpreter exit (SIGKILL at the 180s cap is caught by the
        # driver's parent-pipe EOF instead).
        Browser._live += 1
        self._closed = False
        atexit.register(self.close)
        # A fired dialog (alert/confirm/prompt) is the classic in-band XSS oracle;
        # auto-dismiss so it never blocks, and record its message for alerts().
        self._page.on("dialog", lambda d: (self._alerts.append(d.message), d.dismiss()))
        self._page.on("console", lambda m: self._console.append(f"{m.type}: {m.text}"))

    # -- pin + budget checkin (server is the authority) --------------------
    def _checkin(self, action: str, url: Optional[str] = None) -> None:
        payload: Dict[str, Any] = {"action": action, "origin_id": self._origin_id}
        if url is not None:
            payload["url"] = url
        _post("/traffic/browser", payload)  # _die on 400/403/429 (pin/phase/budget)

    def _abs(self, path_or_url: str) -> str:
        s = str(path_or_url)
        if "://" in s:
            return s  # full URL — the server still host-checks it against the pin
        hostport = self._host
        if self._port not in (80, 443, None):
            hostport = f"{self._host}:{self._port}"
        p = s if s.startswith("/") else "/" + s
        return f"{self._scheme}://{hostport}{p}"

    def _assert_on_origin(self) -> None:
        # A click / submit / redirect may cross off the pinned origin. Compare
        # host AND port AND scheme (a redirect to :8443 or https is off-origin).
        from urllib.parse import urlsplit
        u = urlsplit(self._page.url)
        _defport = {"http": 80, "https": 443}
        cur_port = u.port if u.port is not None else _defport.get(u.scheme)
        pin_port = self._port if self._port is not None else _defport.get(self._scheme)
        if u.hostname and (u.hostname != self._host or u.scheme != self._scheme or cur_port != pin_port):
            _die(f"browser: navigated off the pinned origin "
                 f"({u.scheme}://{u.hostname}:{cur_port} != {self._scheme}://{self._host}:{pin_port})")

    # -- budgeted actions --------------------------------------------------
    def goto(self, path_or_url: str):
        """Navigate (host-pinned). Returns the main response status (int|None)."""
        url = self._abs(path_or_url)
        self._checkin("navigate", url)
        try:
            # "load", not "networkidle": networkidle never settles on SPAs / long-
            # poll / websocket pages (the feature's primary targets) and would time
            # out on every one. JS run at parse/DOMContentLoaded/onload has fired by
            # "load", so DOM-XSS dialogs are already captured.
            resp = self._page.goto(url, wait_until="load", timeout=_BROWSER_NAV_TIMEOUT)
        except Exception as e:  # noqa: BLE001
            return f"[nav error: {e}]"
        self._assert_on_origin()  # a 3xx may have redirected off the pinned origin
        return resp.status if resp else None

    def click(self, selector: str):
        self._checkin("interact")
        self._page.click(selector, timeout=_BROWSER_NAV_TIMEOUT)
        self._assert_on_origin()

    def fill(self, selector: str, value: str):
        self._checkin("interact")
        self._page.fill(selector, str(value), timeout=_BROWSER_NAV_TIMEOUT)

    def submit(self, selector: str):
        self._checkin("interact")
        self._page.click(selector, timeout=_BROWSER_NAV_TIMEOUT)
        try:
            self._page.wait_for_load_state("load", timeout=_BROWSER_NAV_TIMEOUT)
        except Exception:  # noqa: BLE001
            pass
        self._assert_on_origin()

    def press(self, selector: str, key: str):
        self._checkin("interact")
        self._page.press(selector, str(key), timeout=_BROWSER_NAV_TIMEOUT)
        self._assert_on_origin()  # Enter can submit a form and navigate off-host

    def eval(self, js: str) -> Any:
        """Run JS in the page context; returns the result. Costs one action."""
        self._checkin("eval")
        return self._page.evaluate(str(js))

    # -- free reads (the oracle) ------------------------------------------
    def dom(self) -> str:
        return self._page.content()

    def text(self, selector: Optional[str] = None) -> str:
        if selector:
            el = self._page.query_selector(selector)
            return el.inner_text() if el else ""
        return self._page.inner_text("body")

    def html(self, selector: Optional[str] = None) -> str:
        if selector:
            el = self._page.query_selector(selector)
            return el.inner_html() if el else ""
        return self._page.content()

    def console(self) -> List[str]:
        return list(self._console)

    def alerts(self) -> List[str]:
        """Messages of any JS dialog (alert/confirm/prompt) fired so far — the
        in-band DOM-XSS oracle."""
        return list(self._alerts)

    def url(self) -> str:
        return self._page.url

    def close(self) -> None:
        # Idempotent: safe to call twice (explicitly + via atexit) and a no-op for
        # a browser that never finished launching, so _live is decremented once.
        if getattr(self, "_closed", True):
            return
        self._closed = True
        Browser._live = max(0, Browser._live - 1)
        for step in (lambda: self._context.close(),
                     lambda: self._browser.close(),
                     lambda: self._pw.stop()):
            try:
                step()
            except Exception:  # noqa: BLE001
                pass

    def __repr__(self):
        return f"<Browser pinned={self._host} url={getattr(self._page, 'url', '?')}>"


def browser(id: str) -> Browser:
    """Open a live chromium PINNED to the host of captured transaction `id` (find
    one with search()). Exploitation-phase only, per-session action-budgeted, and
    re-captured. Use it to confirm bugs whose signal only appears after JS runs:
    read redamon.manual("browser") first."""
    return Browser(id)


# --------------------------------------------------------------------------
# RESULTS
# --------------------------------------------------------------------------
def finding(kind: str, txn_id: str, evidence: Any = None, severity: str = "medium") -> None:
    """Record a finding. For now it is emitted into the run output (structured)
    for the agent to lift into the report; wiring to the findings store/graph is
    a tracked follow-on."""
    ev = ""
    if isinstance(evidence, Response):
        ev = f" status={evidence.status} len={evidence.length}"
    print(json.dumps({"finding": kind, "txn": txn_id, "severity": severity, "evidence": ev}))


def emit(text: str) -> None:
    """Print a line into the run output (what returns to the agent)."""
    print(text)


# --------------------------------------------------------------------------
# MANUAL — the on-demand cookbook. Read a section right before writing complex
# code so it stays in your context window.
# --------------------------------------------------------------------------
_MANUAL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy_brain_manual.md")


def _manual_sections() -> Dict[str, str]:
    """Parse the manual into {slug: text}. '' is the core preamble (everything
    before the first '## '); each '## Title' becomes slug 'title' (lowercased,
    first word). Fixed file path only — the section arg is a KEY, never a path."""
    try:
        with open(_MANUAL_PATH, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError:
        return {}
    out: Dict[str, str] = {}
    cur_slug, buf = "", []
    for line in raw.splitlines():
        if line.startswith("## "):
            out[cur_slug] = "\n".join(buf).strip()
            title = line[3:].strip()
            cur_slug = title.split()[0].lower().strip("#:()") if title else title.lower()
            buf = [line]
        else:
            buf.append(line)
    out[cur_slug] = "\n".join(buf).strip()
    return out


def manual(section: Optional[str] = None) -> str:
    """The proxy_brain cookbook. `redamon.manual()` returns the core (SDK
    reference + the Burp-capability map + the section index); `redamon.manual("jwt")`
    returns one deep section (recipes for that technique). Read the section you
    need RIGHT BEFORE writing the code that uses it — output is truncated, so keep
    reads scoped. Call with no arg first to see the section index."""
    secs = _manual_sections()
    if not secs:
        return ("[proxy_brain_manual.md not found next to the SDK — the inline tool "
                "description lists the full redamon.* API; proceed from that.]")
    if section:
        key = str(section).split()[0].lower().strip("#:()")
        if key in secs and key:
            return secs[key]
        avail = ", ".join(s for s in secs if s)
        return f"[no section '{section}'. Available sections: {avail}]"
    return secs.get("", "")

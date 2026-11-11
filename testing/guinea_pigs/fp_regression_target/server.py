"""False-positive regression guinea pig: one server, the behaviour picked by ROLE.

Each role replicates a shape a field report muted by the hundred, next to a
real finding that must survive. Stdlib only. See README.md for the case table.

    ROLE=fastly     shared edge: unknown Host -> 500 page echoing the name twice,
                    a different cache node per request; hides admin + wiki apps
    ROLE=cloudflare TLS edge: block page with a fresh Ray ID unless the SNI names
                    the one hidden app
    ROLE=redirect   every name -> 301 to https://<name>/
    ROLE=akamai     deny page with an entity-encoded reference that changes per request
    ROLE=ratelimit  a third of the names get 429; admin answers once, then 429
    ROLE=cache      a tiny shared cache: an A/B page and a real unkeyed-header poisoning
    ROLE=spa        single-page app + JS bundles + source maps (catch-all HTML shell)
    ROLE=vendor     a third-party script host, and a third-party SAML login page
    ROLE=shodan     canned Shodan host API + InternetDB answers for the lab IPs;
                    /_lab/shodan?unavailable=<ips>&hide=<cves>&cdn=<ips> makes some IPs
                    fail (503), drops some CVEs and tags some IPs `cdn` until the next
                    call or a restart
    ROLE=api        a JSON API: 200 on /api/v1, 404 {"code":"NOT_FOUND"} elsewhere
    ROLE=jsonall    a JSON catch-all: 200 {"code":"NOT_FOUND"} on every path
    ROLE=sso        / answers 302 to the vendor host's SAML login (outside the project)
    ROLE=loginwall  an HTTPS origin that 302s every path to /login
    ROLE=deny       one gateway deny page (403) on every path, the same bytes on every host
    ROLE=bulk       BULK_CHUNKS Next.js-style chunks, each with a first-party source map
    ROLE=tlsvhost   an HTTPS reverse proxy routing on the Host header: portal gets the
                    same app on L7 and L4, split gets one app by Host and another
                    when the SNI also names it; every other name the default page
    ROLE=cdncert    an HTTPS host whose self-signed certificate names Cloudflare as
                    issuer (TLS_SUBJECT): tlsx attributes it a CDN from that alone
    ROLE=down       503 "under maintenance" on every path, no links: http_probe records
                    it, and neither JS Recon nor Nuclei takes a 5xx host as a target
    ROLE=plainjs    a page and one script with nothing in it JS Recon reports
    ROLE=pleasewait a site whose pages read "Loading, please wait..." and quote a rate
                    limit, serving an exposed /.git/config (200) with the same footer
    ROLE=throttled  429 Too Many Requests + Retry-After on every path, "please wait" copy
    ROLE=redis      a Redis stand-in on 6379 (PING -> +PONG, no auth) and on 80 its toggle,
                    /_lab/redis?mode=open|delay|auth: a PONG held past the check timeout,
                    or -NOAUTH as a password-protected Redis answers
    ROLE=tlsmail    TLS on 993 with an IMAP greeting (no HTTP) and on 80 its toggle,
                    /_lab/tls?cert=expired|valid&stall=0|1: the certificate presented,
                    or a handshake that never completes
    ROLE=smtp       an SMTP server on 25 whose RCPT answer is SMTP_RCPT, greeting and
                    HELO answer split across writes and lines as real servers send them
    ROLE=login      LOGIN_MODE shell|real|all: a "login" shell with no password field on
                    every path, a real /login form, or one password page on every path
    ROLE=graphql    a minimal GraphQL server on /graphql (introspection, batches)

Toggles on existing roles: /_lab/vhost?drop_bare=1|0 on fastly (with a name in
Host) closes bare-IP connections unanswered; /_lab/cache?mode=open|stall on
cache answers the cache scanner's own requests CACHE_STALL_S late; /_lab/js
?show=r14|r14js on spa links the R-14 source-map and redirecting bundles.
"""

import base64
import hashlib
import socketserver
import itertools
import json
import os
import random
import ssl
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROLE = os.environ.get("ROLE", "spa")
PORTS = [int(p) for p in os.environ.get("PORTS", "80").split(",") if p]
TLS_PORTS = {int(p) for p in os.environ.get("TLS_PORTS", "").split(",") if p}
APEX = "fplab.test"
STATIC = "/app/static"
_counter = itertools.count(1)
_lock = threading.Lock()


class Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "fplab"
    sys_version = ""

    def log_message(self, fmt, *args):
        # Never log a query string (the Shodan stub may receive an API key) nor an
        # Authorization value: auth= says only whether the request carried one.
        # ua= (spaces folded, 60 characters) names the tool behind a burst; it
        # comes last so the fields before it keep their place.
        # A request line the parser refused (nmap's probes send some) reaches
        # here through send_error before any header or path was read.
        headers = getattr(self, "headers", None) or {}
        auth = "yes" if headers.get("Authorization") else "no"
        ua = "_".join(str(headers.get("User-Agent", "-")).split())[:60] or "-"
        path = (getattr(self, "path", None) or "-").split("?", 1)[0]
        print(f"[{ROLE}] {getattr(self, 'command', None) or '-'} {path} host={headers.get('Host', '')} "
              f"auth={auth} ua={ua}", flush=True)

    def log_error(self, fmt, *args):
        # send_error logs here and then again through send_response's
        # log_request: one request, two lines. The R-8 ceiling check counts lines.
        pass

    def send(self, status, body=b"", ctype="text/html; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        if ctype:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def host(self):
        return (self.headers.get("Host") or "").split(":")[0].strip().lower()

    def is_bare_ip(self):
        h = self.host()
        return not h or h.replace(".", "").isdigit()

    def do_HEAD(self):
        self.do_GET()


# --------------------------------------------------------------------------- vhost edges
# /_lab/vhost?drop_bare=1 (sent with a name in Host, never the bare IP): close
# every bare-IP connection unanswered, so the vhost module's baseline fails (R-46).
_vhost_state = {"drop_bare": False}


class Fastly(Base):
    def do_GET(self):
        host = self.host()
        path, _, query = self.path.partition("?")
        if path == "/_lab/vhost" and not self.is_bare_ip():
            from urllib.parse import parse_qs
            flag = (parse_qs(query).get("drop_bare") or [""])[0]
            if flag in ("0", "1"):
                _vhost_state["drop_bare"] = flag == "1"
            return self.send(200, json.dumps(_vhost_state), "application/json")
        if self.is_bare_ip():
            if _vhost_state["drop_bare"]:
                print(f"[{ROLE}] dropped bare-IP {self.command} {path}", flush=True)
                self.close_connection = True
                return None
            return self.send(421, "<h1>Misdirected Request</h1>")
        if host == f"admin.{APEX}":
            return self.send(200, '{"service":"admin-api","version":"3.2.1"}', "application/json")
        # Two names one punctuation mark apart, two apps: each needs its own
        # finding id (R-46).
        if host == f"dev-api.{APEX}":
            return self.send(200, '{"service":"dev-api","stage":"integration"}', "application/json")
        if host == f"dev.api.{APEX}":
            return self.send(200, '{"service":"api","stage":"dev","region":"eu-west-1","build":"9d2c"}',
                             "application/json")
        if host == f"wiki.{APEX}":
            n = next(_counter)
            return self.send(200, f"<html><head><title>Internal Wiki</title></head><body>Main page. "
                                  f"Rendered in 0.0{n % 9 + 1}s, {n} views</body></html>")
        node = f"cache-fra-etou82{random.randint(10000, 99999)}-FRA"
        return self.send(500, f"<html><body><h1>Fastly error: unknown domain: {host}</h1>"
                              f"<p>Please check that this domain has been added to a service: {host}</p>"
                              f"<p>Details: {node} {int(time.time())}</p></body></html>")


class Cloudflare(Base):
    def do_GET(self):
        sni = getattr(self.request, "_sni", "") or ""
        host = self.host()
        if sni == f"admin.{APEX}" and host == sni:
            return self.send(200, '{"service":"admin-console","build":"7f1c"}', "application/json")
        ray = uuid.uuid4().hex[:16]
        return self.send(403, f"<html><head><title>Attention Required! | Cloudflare</title></head><body>"
                              f"<h1>Sorry, you have been blocked</h1><p>You are unable to access {host or 'this site'}</p>"
                              f"<p>Cloudflare Ray ID: <strong>{ray}</strong></p>"
                              f"<p>{time.strftime('%Y-%m-%d %H:%M:%S')} UTC</p></body></html>",
                         headers={"cf-ray": f"{ray}-FRA", "Server": "cloudflare"})


class Redirect(Base):
    def do_GET(self):
        if self.is_bare_ip():
            return self.send(404, b"", ctype=None)
        return self.send(301, b"", ctype=None, headers={"Location": f"https://{self.host()}/"})


class Akamai(Base):
    def do_GET(self):
        if self.is_bare_ip():
            return self.send(400, "<HTML><HEAD><TITLE>Invalid URL</TITLE></HEAD><BODY>Invalid URL</BODY></HTML>")
        ref = f"{random.randint(16, 99)}&#46;{uuid.uuid4().hex[:8]}&#46;{int(time.time())}&#46;{uuid.uuid4().hex[:8]}"
        return self.send(403, f"<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY><H1>Access Denied</H1>"
                              f"You don't have permission to access \"http&#58;&#47;&#47;{self.host()}&#47;\" on this server.<P>"
                              f"Reference&#32;&#35;{ref}<P>https&#58;&#47;&#47;errors&#46;edgesuite&#46;net&#47;{ref}</P>"
                              f"</BODY></HTML>", headers={"Server": "AkamaiGHost"})


_LIMITED = {f"{w}.{APEX}" for w in ("dev", "qa", "ci", "vpn", "sso", "mail", "status")}
_seen_admin = {"n": 0}


class RateLimit(Base):
    def do_GET(self):
        host = self.host()
        if self.is_bare_ip():
            return self.send(404, "<h1>not found</h1>")
        if host == f"admin.{APEX}":
            with _lock:
                _seen_admin["n"] += 1
                first = _seen_admin["n"] == 1
            if first:
                return self.send(200, '{"service":"admin-reports"}', "application/json")
            return self.send(429, "<h1>Too Many Requests</h1>", headers={"Retry-After": "30"})
        if host in _LIMITED:
            return self.send(429, "<h1>Too Many Requests</h1>", headers={"Retry-After": "30"})
        return self.send(404, "<h1>not found</h1>")


# --------------------------------------------------------------------------- cache
_cache = {}
_renders = itertools.count()


# /_lab/cache?mode=stall: the cache scanner's own requests (its native engine
# and WCVS, told apart by User-Agent) get their answer CACHE_STALL_S late, past
# the native per-request timeout and slow enough to keep WCVS running past its
# own timeout; every other client is answered at once (R-23, R-9).
_cache_state = {"mode": "open"}
CACHE_STALL_S = int(os.environ.get("CACHE_STALL_S", "10"))
_CACHE_SCANNER_UAS = ("RedAmon-CachePoison", "WebCacheVulnerabilityScanner")


class Cache(Base):
    """A shared cache keyed on path + query only, so request headers are unkeyed."""
    TTL = 300

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/_lab/cache":
            from urllib.parse import parse_qs
            mode = (parse_qs(query).get("mode") or [""])[0]
            if mode in ("open", "stall"):
                _cache_state["mode"] = mode
            return self.send(200, json.dumps(_cache_state), "application/json")
        ua = self.headers.get("User-Agent") or ""
        scanner = next((u for u in _CACHE_SCANNER_UAS if u in ua), None)
        if _cache_state["mode"] == "stall" and scanner:
            print(f"[{ROLE}] stalled {self.command} {path} ua={scanner} for {CACHE_STALL_S}s", flush=True)
            time.sleep(CACHE_STALL_S)
        key = self.path
        with _lock:
            hit = _cache.get(key)
            if hit and time.time() - hit[0] < self.TTL:
                status, body, ctype = hit[1]
                age = int(time.time() - hit[0])
                return self.send(status, body, ctype, headers={"X-Cache": "HIT", "Age": str(age),
                                                               "Cache-Control": "public, max-age=300"})
        status, body, ctype = self.origin()
        if status == 200:
            with _lock:
                _cache[key] = (time.time(), (status, body, ctype))
        return self.send(status, body, ctype, headers={"X-Cache": "MISS", "Age": "0",
                                                       "Cache-Control": "public, max-age=300"})

    def origin(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            # /search?q= gives the crawl a Parameter with a sample value (R-27).
            return 200, ('<html><head><title>Shop</title></head><body><a href="/promo">Promo</a> '
                         '<a href="/home">Home</a> <a href="/search?q=shoes">Shoes</a></body></html>'), \
                "text/html; charset=utf-8"
        if path == "/promo":
            # An A/B bucket picked per origin render: two variants, same size.
            variant = "AB"[next(_renders) % 2]
            return 200, f"<html><body><h1>Spring promo</h1><p>variant {variant}</p></body></html>", "text/html; charset=utf-8"
        if path == "/home":
            # Real poisoning: an unkeyed header reflected into a cached script tag.
            xfh = self.headers.get("X-Forwarded-Host") or "shop.fplab.test"
            return 200, (f'<html><head><script src="https://{xfh}/static/app.js"></script></head>'
                         f'<body>Welcome</body></html>'), "text/html; charset=utf-8"
        if path == "/search":
            # Echoes nothing of the request, so it gives the cache scan nothing to poison.
            return 200, "<html><body><h1>Search results</h1><p>3 products</p></body></html>", \
                "text/html; charset=utf-8"
        return 404, "<h1>not found</h1>", "text/html; charset=utf-8"


# --------------------------------------------------------------------------- JS
def _big_bundle():
    """A one-line minified bundle: the global-object shim first, 400 sourceless
    sinks, then the real hash -> innerHTML bug far down the line."""
    parts = ['!function(){var g=function(){return this}()||Function("return this")();']
    parts += [f"a{i}.innerHTML=r{i}(d);" for i in range(400)]
    parts += ["var o=document.getElementById('out');o.innerHTML=decodeURIComponent(location.hash.slice(1));}();"]
    return "".join(parts)


_MAIN_SRC = None


def _main_js():
    global _MAIN_SRC
    if _MAIN_SRC is None:
        with open(os.path.join(STATIC, "js", "main.src.js")) as f:
            readable = f.read()
        _MAIN_SRC = readable + "\n" + _big_bundle() + "\n//# sourceMappingURL=main.4f2a9c.js.map\n"
    return _MAIN_SRC


def _inline_map():
    m = {"version": 3, "mappings": "AAAA", "sources": ["webpack:///./src/inline-widget.ts"],
         "sourcesContent": ["export const widget = () => 'inline';"]}
    return "data:application/json;base64," + base64.b64encode(json.dumps(m).encode()).decode()


# Plan 06: bundles where the crawler's default exclude list (/static/,
# /_next/static, .min.js) used to hide them, and a hash-suffixed name.
_EXTRA_JS = {
    "/_next/static/chunks/pages/app-91c.js": 'self.__NEXT_P=self.__NEXT_P||[];fetch("/api/cov/next");\n',
    "/js/app.min.js": '!function(){fetch("/api/cov/min")}();\n',
    "/js/bundle.js__v_ab12": '!function(){fetch("/api/cov/hash")}();\n',
}
# Synthetic, unsigned, built by concatenation; the lab keeps key validation off.
_LAB_STRIPE_KEY = "sk_live_" + "4mQ9tR2vX7cL1nB8kP3wZ6sD"
_SPA_HIDDEN = set()   # /_lab/js?hide=<path>: answer that path with the shell, for a rerun
# /_lab/js?show=r29: the shell also links the R-29 scripts, a relative call on
# .20 and the same relative path on .22, for the --r29 project only.
_SPA_SHOWN = set()
_SPA_EXTRA_TAGS = {
    "r29": ('<script src="/static/js/r29.relative.js"></script>'
            '<script src="http://192.88.94.22/js/client.js"></script>'),
    # R-14: source maps named off the scanned host, directly or by a redirect.
    "r14": ('<script src="/static/js/r14.offhost.4d1e.js"></script>'
            '<script src="/static/js/r14.bounce.5e2f.js"></script>'
            '<script src="/static/js/r14.moved.6f3a.js"></script>'),
    # R-14 (JS downloads): a bundle that redirects off the host, one that
    # redirects to another path on it.
    "r14js": ('<script src="/static/js/r14js.offhost.7a8b.js"></script>'
              '<script src="/static/js/r14js.moved.8b9c.js"></script>'),
}
_R14_MAP = {"version": 3, "file": "r14.moved.js", "mappings": "AAAA",
            "sources": ["webpack:///./src/r14/moved.ts"],
            "sourcesContent": ["export const moved = () => fetch('/api/r14/moved');\n"]}
# path -> (switch, body). Without the switch the shell answers the path.
_SWITCHED_JS = {
    "/static/js/r14.offhost.4d1e.js": ("r14", "function r14a(){return 1}\n"
                                              "//# sourceMappingURL=http://192.88.94.21/loader.js.map\n"),
    "/static/js/r14.bounce.5e2f.js": ("r14", "function r14b(){return 2}\n//# sourceMappingURL=/r14/bounce.js.map\n"),
    "/static/js/r14.moved.6f3a.js": ("r14", "function r14c(){return 3}\n//# sourceMappingURL=/r14/moved.js.map\n"),
    "/static/js/r14.moved.6f3a.js.map": ("r14", json.dumps(_R14_MAP)),
    "/static/js/r14js.target.8b9c.js": ("r14js", "!function(){fetch('/api/r14js/moved');"
                                                 "document.getElementById('o').innerHTML=location.hash}();\n"),
}
# path -> (switch, status, Location)
_SWITCHED_REDIRECTS = {
    "/r14/bounce.js.map": ("r14", 302, "http://192.88.94.21/loader.js.map"),
    "/r14/moved.js.map": ("r14", 301, "/static/js/r14.moved.6f3a.js.map"),
    "/static/js/r14js.offhost.7a8b.js": ("r14js", 302, "http://192.88.94.21/loader.js"),
    "/static/js/r14js.moved.8b9c.js": ("r14js", 301, "/static/js/r14js.target.8b9c.js"),
}


class Spa(Base):
    MAPS = {
        "/static/js/main.4f3a.js.map": ({
            "version": 3, "file": "main.js", "mappings": "AAAA",
            "sources": ["webpack:///./src/config.ts", "webpack:///./src/index.tsx",
                        "webpack:///node_modules/react/index.js"],
            "sourcesContent": [
                f'export const PAYMENTS_KEY = "{_LAB_STRIPE_KEY}";\n'
                'export function loadOrders() {\n  return fetch("/api/v2/orders");\n}\n',
                "import { loadOrders } from './config';\nloadOrders();\n",
                'module.exports = { key: "sk_live_' + "LIBRARYEXAMPLE0000000000" + '" };\n',
            ],
        }, "application/octet-stream"),
        "/static/js/main.4f2a9c.js.map": ({
            "version": 3, "file": "main.js", "mappings": "AAAA;AACA",
            "sources": ["webpack:///./src/App.tsx", "webpack:///./src/api/client.ts",
                        "webpack:///node_modules/react/index.js", "webpack:///webpack/bootstrap"],
            "sourcesContent": ["export const App = () => null;", "export const api = '/api/v1';",
                               "module.exports = {};", "(()=>{})()"],
        }, "application/octet-stream"),
        "/static/js/lib.8e1f.js.map": ({
            "version": 3, "mappings": "AAAA",
            "sources": ["webpack:///node_modules/lodash/lodash.js", "webpack:///webpack/bootstrap"],
        }, "application/json"),
    }

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/_lab/js":
            query = dict(p.split("=", 1) for p in self.path.split("?", 1)[-1].split("&") if "=" in p)
            with _lock:
                _SPA_HIDDEN.clear()
                _SPA_HIDDEN.update(h for h in query.get("hide", "").split(",") if h)
                _SPA_SHOWN.clear()
                _SPA_SHOWN.update(h for h in query.get("show", "").split(",") if h in _SPA_EXTRA_TAGS)
                hidden, shown = sorted(_SPA_HIDDEN), sorted(_SPA_SHOWN)
            return self.send(200, json.dumps({"hidden": hidden, "shown": shown}), "application/json")
        if path in _SWITCHED_JS and _SWITCHED_JS[path][0] in _SPA_SHOWN:
            body = _SWITCHED_JS[path][1]
            return self.send(200, body, "application/json" if path.endswith(".map") else "application/javascript")
        if path in _SWITCHED_REDIRECTS and _SWITCHED_REDIRECTS[path][0] in _SPA_SHOWN:
            _, status, location = _SWITCHED_REDIRECTS[path]
            return self.send(status, b"", ctype=None, headers={"Location": location})
        if path not in _SPA_HIDDEN:
            if path in _EXTRA_JS:
                return self.send(200, _EXTRA_JS[path], "application/javascript")
            # Object storage refuses a missing key with 403 AccessDenied (S3), and
            # a CloudFront-style edge answers 403 to every missing path alike.
            if path.startswith("/s3/"):
                return self.send(403, '<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>AccessDenied</Code>'
                                      '<Message>Access Denied</Message></Error>', "application/xml",
                                 {"Server": "AmazonS3", "x-amz-request-id": "LAB0000000000000"})
            if path.startswith("/cf/"):
                return self.send(403, "Forbidden", "text/plain")
        if path == "/static/js/main.4f2a9c.js":
            return self.send(200, _main_js(), "application/javascript")
        if path == "/static/js/inline.5e6f.js":
            return self.send(200, "export const w=1;\n//# sourceMappingURL=" + _inline_map() + "\n", "application/javascript")
        if path in self.MAPS:
            data, ctype = self.MAPS[path]
            return self.send(200, json.dumps(data), ctype)
        if path == "/static/js/private.9c3d.js.map":
            return self.send(403, "<h1>Forbidden</h1>")
        local = os.path.join(STATIC, path[len("/static/"):])
        # Outside the --r29 run the R-29 script does not exist: the shell answers it.
        r29_off = path == "/static/js/r29.relative.js" and "r29" not in _SPA_SHOWN
        if path.startswith("/static/") and os.path.isfile(local) and ".." not in path and path not in _SPA_HIDDEN \
                and not r29_off:
            with open(local, "rb") as f:
                return self.send(200, f.read(), "application/javascript" if path.endswith(".js") else "application/octet-stream")
        with open(os.path.join(STATIC, "index.html"), "rb") as f:   # the SPA catch-all
            page = f.read()
        extra = "".join(_SPA_EXTRA_TAGS[k] for k in sorted(_SPA_SHOWN))
        if extra:
            page = page.replace(b"</body>", extra.encode() + b"\n</body>")
        return self.send(200, page, "text/html; charset=utf-8")


# --------------------------------------------------------------------------- bulk JS (plan 06.2)
BULK_CHUNKS = int(os.environ.get("BULK_CHUNKS", "520"))
_BULK_CHUNK_CHARS = 40_000
_BULK_SOURCE_CHARS = 12_000


def _bulk_name(n):
    return f"{n}-{hashlib.sha256(str(n).encode()).hexdigest()[:12]}.js"


def _filler(rng, chars):
    out, size = [], 0
    while size < chars:
        i, k = rng.randrange(10 ** 6), rng.randrange(1, 97)
        part = f"function f{i}(a,b){{var c=a+b*{k};return c>{k}?c:a}}"
        out.append(part)
        size += len(part)
    return "".join(out)


def _bulk_chunk(n):
    """One minified Next.js-style chunk: an email and an API call to find,
    bulk around them, and a reference to its source map."""
    rng = random.Random(n)
    return ('(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[%d],{%d:function(e,t,n){"use strict";'
            'var m="bulk-%d@example.com";function load(){return fetch("/api/bulk/%d/items")}%s}}]);\n'
            '//# sourceMappingURL=%s.map\n' % (n, n, n, n, _filler(rng, _BULK_CHUNK_CHARS), _bulk_name(n)))


def _bulk_map(n):
    rng = random.Random(10 ** 6 + n)
    sources = [f"webpack://_N_E/./src/components/Widget{n}.tsx", f"webpack://_N_E/./src/lib/api{n}.ts",
               "webpack://_N_E/./node_modules/react/cjs/react.production.min.js"]
    contents = [
        f"export function Widget{n}() {{\n  return fetch('/api/bulk/{n}/detail');\n}}\n" + _filler(rng, _BULK_SOURCE_CHARS),
        f"export const base{n} = '/api/bulk/{n}';\n" + _filler(rng, _BULK_SOURCE_CHARS),
        _filler(rng, _BULK_SOURCE_CHARS * 2),
    ]
    return {"version": 3, "file": _bulk_name(n), "mappings": "AAAA", "sources": sources, "sourcesContent": contents}


class Bulk(Base):
    """A site with BULK_CHUNKS script chunks, each with a first-party source
    map: the volume a large Next.js app hands JS recon once nothing hides it."""

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        prefix = "/_next/static/chunks/"
        if path in ("/", "/index.html"):
            tags = "".join(f'<script src="{prefix}{_bulk_name(n)}"></script>' for n in range(BULK_CHUNKS))
            return self.send(200, f"<!doctype html><html><head><title>Bulk</title></head><body>{tags}</body></html>")
        if path.startswith(prefix):
            name = path[len(prefix):]
            stem = name[:-4] if name.endswith(".map") else name
            try:
                n = int(stem.split("-", 1)[0])
            except ValueError:
                n = -1
            if 0 <= n < BULK_CHUNKS and stem == _bulk_name(n):
                if name.endswith(".map"):
                    return self.send(200, json.dumps(_bulk_map(n)), "application/json")
                return self.send(200, _bulk_chunk(n), "application/javascript")
        return self.send(404, "<h1>not found</h1>")


class Vendor(Base):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/loader.js":
            with open(os.path.join(STATIC, "vendor-loader.js"), "rb") as f:
                return self.send(200, f.read(), "application/javascript")
        if path == "/loader.js.map":
            return self.send(200, json.dumps({
                "version": 3, "mappings": "AAAA", "sources": ["webpack:///./src/tracker.ts"],
                "sourcesContent": ["export const track = (e) => e;"]}), "application/json")
        if path == "/saml/login":
            # A third-party identity provider's page: never the target's own.
            return self.send(200, "<html><head><title>SAP NetWeaver SAML Login</title></head><body>"
                                  "<form method=post action=/saml/acs><input name=j_username>"
                                  "<input type=password name=j_password></form></body></html>",
                             headers={"Server": "SAP NetWeaver Application Server 7.53 / AS Java 7.50",
                                      "sap-server": "true"})
        return self.send(404, "<h1>not found</h1>")


# --------------------------------------------------------------------------- HTTP layer (plan 03)
NOT_FOUND_JSON = '{"code":"NOT_FOUND","message":"No route matches the request"}'


class Api(Base):
    """A real API next to its catch-all twin (JsonAll): only /api/v1 exists, and
    one script calling it by a relative path (R-29, linked from .20's shell)."""
    def do_GET(self):
        if self.path.split("?", 1)[0] == "/js/client.js":
            return self.send(200, 'fetch("/api/v1").then(function(r){return r.json()});\n',
                             "application/javascript")
        if self.path.split("?", 1)[0] == "/api/v1":
            return self.send(200, '{"service":"orders","version":"2.1","endpoints":["/api/v1/orders"]}',
                             "application/json")
        return self.send(404, NOT_FOUND_JSON, "application/json")


class JsonAll(Base):
    """`200 {"code":"NOT_FOUND"}` to every path: a status-only check reports an API."""
    def do_GET(self):
        return self.send(200, NOT_FOUND_JSON, "application/json")


class Sso(Base):
    """An in-scope host whose only page redirects to a third-party IdP."""
    def do_GET(self):
        if self.path.split("?", 1)[0] == "/":
            return self.send(302, b"", ctype=None, headers={"Location": f"http://{NET}.21/saml/login"})
        return self.send(404, "<h1>not found</h1>")


class LoginWall(Base):
    """An origin that redirects everything, WAF probe payloads included, to /login."""
    def do_GET(self):
        if self.path.split("?", 1)[0] == "/login":
            return self.send(200, "<html><head><title>Sign in</title></head><body><form method=post>"
                                  "<input name=user><input type=password name=pass></form></body></html>")
        return self.send(302, b"", ctype=None, headers={"Location": "/login"})


DENY_PAGE = ("<html><head><title>Access denied</title></head><body><h1>Access denied</h1>"
             "<p>This request was blocked by the gateway policy.</p></body></html>")


class Deny(Base):
    """One gateway's deny page: the same bytes on every host that runs it."""
    def do_GET(self):
        return self.send(403, DENY_PAGE)


class Down(Base):
    def do_GET(self):
        return self.send(503, "<html><body><h1>Service under maintenance</h1></body></html>")


# Nothing in it matches a JS Recon detector: no key, URL, email, sink, comment
# or framework banner, so the host is analyzed and yields no finding.
PLAIN_JS = "function greet(name){return 'Hello, '+name;}\ndocument.title=greet('lab');\n"


class PlainJs(Base):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/js/app.js":
            return self.send(200, PLAIN_JS, "application/javascript")
        if path == "/":
            return self.send(200, '<html><head><title>Plain</title><script src="/js/app.js"></script>'
                                  '</head><body><h1>Plain</h1></body></html>')
        return self.send(404, "<h1>Not found</h1>")


# --------------------------------------------------------------------------- Shodan stub
NET = "192.88.94"
SHODAN_HOSTS = {
    f"{NET}.10": {"org": "Example Hosting Ltd", "isp": "Example Hosting Ltd", "tags": [], "ports": [80],
                  "vulns": ["CVE-2021-23017", "CVE-2019-11043"],
                  "data": [{"port": 80, "transport": "tcp", "product": "nginx", "version": "1.18.0",
                            "data": "HTTP/1.1 500\r\nServer: nginx", "_shodan": {"module": "http"},
                            "vulns": {"CVE-2021-23017": {"cvss": 7.7, "verified": False}}}]},
    f"{NET}.11": {"org": "Vercel, Inc", "isp": "Vercel, Inc", "tags": [], "ports": [443],
                  "vulns": ["CVE-2020-11022", "CVE-2020-11023"], "data": []},
    f"{NET}.12": {"org": "Example Edge", "isp": "Example Edge", "tags": ["cdn"], "ports": [80],
                  "vulns": ["CVE-2019-11358"], "data": []},
    f"{NET}.13": {"org": "Example Hosting Ltd", "isp": "Example Hosting Ltd", "tags": [], "ports": [80, 443],
                  "vulns": ["CVE-2014-0160"],
                  "data": [{"port": 80, "transport": "tcp", "product": "OpenSSL", "version": "1.0.1f",
                            "data": "", "_shodan": {"module": "http"},
                            "vulns": {"CVE-2014-0160": {"cvss": 7.5, "verified": False}}},
                           {"port": 443, "transport": "tcp", "product": "OpenSSL", "version": "1.0.1f",
                            "data": "", "_shodan": {"module": "https"},
                            "vulns": {"CVE-2014-0160": {"cvss": 7.5, "verified": True}}}]},
    # Port 22 is closed on every lab host: a banner from an old crawl (plan 04).
    f"{NET}.14": {"org": "Example Hosting Ltd", "isp": "Example Hosting Ltd", "tags": [], "ports": [22, 80],
                  "vulns": ["CVE-2018-15473"],
                  "data": [{"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "7.4",
                            "data": "SSH-2.0-OpenSSH_7.4", "_shodan": {"module": "ssh"},
                            "vulns": {"CVE-2018-15473": {"cvss": 5.3, "verified": False}}}]},
    # Plan 11: .32 sits behind a Cloudflare-issued certificate (tlsx tags it a
    # CDN edge, IP attribution a shared edge), .31 does not. Both carry the same
    # version-matched CVE on 443; only .31's may become a finding. Each has a PTR
    # name for Shodan's reverse DNS, which must not read as forward DNS.
    **{f"{NET}.{n}": {"org": "Example Hosting Ltd", "isp": "Example Hosting Ltd", "tags": [], "ports": [443],
                      "hostnames": [f"rdns-{n}.{APEX}"], "vulns": ["CVE-2023-44487"],
                      "data": [{"port": 443, "transport": "tcp", "product": "nginx", "version": "1.25.2",
                                "data": "", "_shodan": {"module": "https"},
                                "vulns": {"CVE-2023-44487": {"cvss": 7.5, "verified": False}}}]}
       for n in (31, 32)},
    # The nested-wildcard lab's web1, scanned in domain mode (plan 11): a PTR name
    # under nwlab.test that no zone has.
    "192.88.99.60": {"org": "Example Hosting Ltd", "isp": "Example Hosting Ltd", "tags": [], "ports": [443],
                     "hostnames": ["ptr.nwlab.test"], "vulns": [], "data": []},
}

# Shodan's domain DNS for the nested-wildcard lab's org (plan 11): one name only
# Shodan knows, pointing at web2.
SHODAN_DOMAIN_DNS = {
    "nwlab.test": {"subdomains": ["shodan-only"],
                   "data": [{"subdomain": "shodan-only", "type": "A", "value": "192.88.99.61"}]},
}

# What the next lookups see, set over /_lab/shodan by e2e_fp.py: IPs whose lookup
# fails (a provider that could not be asked), CVEs the provider dropped, and IPs
# it now tags `cdn` (an address that became a CDN edge since the last run).
_shodan_state = {"unavailable": set(), "hide": set(), "cdn": set()}


def _shodan_view(ip):
    """The record for `ip` as this run's provider has it: CVEs hidden, `cdn` tag added."""
    host = SHODAN_HOSTS.get(ip)
    if host and ip in _shodan_state["cdn"]:
        host = {**host, "tags": sorted(set(host.get("tags") or []) | {"cdn"})}
    if not host or not _shodan_state["hide"]:
        return host
    hide = _shodan_state["hide"]
    data = [{**svc, "vulns": {c: v for c, v in svc.get("vulns", {}).items() if c not in hide}}
            for svc in host.get("data", [])]
    return {**host, "vulns": [c for c in host["vulns"] if c not in hide], "data": data}


class Shodan(Base):
    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/_lab/shodan":
            from urllib.parse import parse_qs
            params = parse_qs(query)
            with _lock:
                for key in ("unavailable", "hide", "cdn"):
                    _shodan_state[key] = {v for raw in params.get(key, []) for v in raw.split(",") if v}
            return self.send(200, json.dumps({k: sorted(v) for k, v in _shodan_state.items()}),
                             "application/json")
        if (path.startswith("/shodan/host/") or path.startswith("/internetdb/")) and \
                path.rsplit("/", 1)[-1] in _shodan_state["unavailable"]:
            return self.send(503, '{"error":"temporarily unavailable"}', "application/json")
        if path.startswith("/shodan/host/"):
            ip = path.rsplit("/", 1)[-1]
            host = _shodan_view(ip)
            if not host:
                return self.send(404, '{"error":"No information available for that IP."}', "application/json")
            return self.send(200, json.dumps({"ip_str": ip, "os": None, "country_name": "Ireland",
                                              "city": "Dublin", **host}), "application/json")
        if path.startswith("/internetdb/"):
            ip = path.rsplit("/", 1)[-1]
            host = _shodan_view(ip)
            if not host:
                return self.send(404, '{"detail":"No information available"}', "application/json")
            return self.send(200, json.dumps({"ip": ip, "ports": host["ports"],
                                              "hostnames": host.get("hostnames", []),
                                              "cpes": [], "tags": host["tags"], "vulns": host["vulns"]}),
                             "application/json")
        if path == "/dns/reverse":
            from urllib.parse import parse_qs
            ips = [v for raw in parse_qs(query).get("ips", []) for v in raw.split(",") if v]
            return self.send(200, json.dumps({ip: (SHODAN_HOSTS.get(ip) or {}).get("hostnames", [])
                                              for ip in ips}), "application/json")
        if path.startswith("/dns/domain/"):
            domain = path.rsplit("/", 1)[-1]
            if domain not in SHODAN_DOMAIN_DNS:
                return self.send(404, '{"error":"No information available for that domain."}', "application/json")
            return self.send(200, json.dumps({"domain": domain, **SHODAN_DOMAIN_DNS[domain]}), "application/json")
        if path.startswith("/api-info"):
            return self.send(200, '{"plan":"dev","query_credits":100,"scan_credits":100}', "application/json")
        return self.send(404, '{"error":"not found"}', "application/json")


# --------------------------------------------------------------------------- vhost naming / CDN tag
class TlsVhost(Base):
    """A Host-routing proxy. The default page answers the bare IP and every
    unknown name alike, so the vhost controls calibrate on it."""

    def do_GET(self):
        sni = getattr(self.request, "_sni", "") or ""
        host = self.host()
        if host == f"portal.{APEX}":
            # The same app whatever the SNI: a hidden vhost seen on both layers.
            return self.send(200, "<html><head><title>Partner portal</title></head>"
                                  "<body><h1>Partner portal</h1><p>Sign in with your partner id.</p></body></html>")
        if host == f"split.{APEX}":
            if sni == host:
                return self.send(200, '{"service":"billing-admin","build":"3c9e"}', "application/json")
            return self.send(200, "<html><head><title>Status</title></head><body><h1>All systems normal</h1></body></html>")
        return self.send(404, "<html><head><title>Not found</title></head><body><h1>No such site</h1></body></html>")


class CdnCert(Base):
    def do_GET(self):
        return self.send(403, "<html><head><title>Forbidden</title></head><body><h1>Forbidden</h1></body></html>")


# --------------------------------------------------------------------------- Nuclei throttle filter (R-19)
# Copy a page may carry without the server throttling anything. Before R-19 the
# Nuclei false-positive filter dropped every finding whose response held it.
PLEASE_WAIT_FOOTER = "Loading, please wait... API clients are subject to a rate limit of 60 requests per minute."
GIT_CONFIG = ("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
              "\tlogallrefupdates = true\n[remote \"origin\"]\n\turl = https://git.fplab.test/shop/storefront.git\n"
              "\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n\tremote = origin\n"
              "\tmerge = refs/heads/main\n")


class PleaseWait(Base):
    """A served site (200) whose every page ends in the throttle-sounding footer,
    with its /.git/config exposed: a real finding the old filter dropped."""
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/.git/config":
            return self.send(200, GIT_CONFIG + f"; {PLEASE_WAIT_FOOTER}\n", "text/plain; charset=utf-8")
        if path == "/":
            return self.send(200, "<html><head><title>Storefront</title></head><body><div id=app>"
                                  f"<p>Loading, please wait&hellip;</p></div><footer>{PLEASE_WAIT_FOOTER}</footer>"
                                  "</body></html>")
        return self.send(404, f"<html><body><h1>Not found</h1><footer>{PLEASE_WAIT_FOOTER}</footer></body></html>")


class Throttled(Base):
    """A server that throttles every request: 429 + Retry-After, "please wait" copy.
    A timing template's match here is the throttle's; any other template keeps its."""
    def do_GET(self):
        return self.send(429, "<html><head><title>Too Many Requests</title></head><body><h1>Too Many Requests</h1>"
                              "<p>Please wait 60 seconds and try again later.</p></body></html>",
                         headers={"Retry-After": "60"})


# --------------------------------------------------------------------------- Redis (R-24)
# What the stand-in answers to PING, set over /_lab/redis on port 80:
#   open  -> +PONG at once (no auth: must fire)
#   delay -> +PONG after REDIS_DELAY seconds, past the check's timeout (no verdict)
#   auth  -> -NOAUTH, as a password-protected Redis answers (a verdict: clean)
_redis_state = {"mode": "open"}
REDIS_DELAY = int(os.environ.get("REDIS_DELAY", "25"))


class RedisStandIn(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            data = self.request.recv(1024)
        except OSError:
            return
        if not data:
            return
        mode = _redis_state["mode"]
        command = data.split(b"\r", 1)[0].decode(errors="replace")[:40]
        print(f"[redis] {command} mode={mode}", flush=True)
        if mode == "delay":
            time.sleep(REDIS_DELAY)
        reply = b"-NOAUTH Authentication required.\r\n" if mode == "auth" else b"+PONG\r\n"
        try:
            self.request.sendall(reply)
        except OSError:
            pass


class RedisToggle(Base):
    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/_lab/redis":
            from urllib.parse import parse_qs
            mode = (parse_qs(query).get("mode") or [""])[0]
            if mode in ("open", "delay", "auth"):
                _redis_state["mode"] = mode
            return self.send(200, json.dumps(_redis_state), "application/json")
        return self.send(200, "<html><head><title>Cache node</title></head><body><h1>cache-01</h1></body></html>")


def _serve_tcp(port, handler):
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer(("0.0.0.0", port), handler)
    srv.daemon_threads = True
    print(f"[{ROLE}] listening on {port} (tcp)", flush=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def _serve_redis():
    _serve_tcp(6379, RedisStandIn)


PLAIN_PAGE = ("<html><head><title>{title}</title></head><body><h1>{title}</h1>"
              "<p>Internal service.</p></body></html>")


# --------------------------------------------------------------------------- TLS on a non-HTTP port (R-21, R-9)
# 993 speaks TLS, then an IMAP greeting: no HTTP, so tlsx is the only reader of
# its certificate. /_lab/tls on port 80 sets, for the next connections:
#   cert=expired|valid  the certificate presented (expired: not_after 2021)
#   stall=1|0           accept the TCP connection and never answer the
#                       ClientHello, so tlsx waits until its run timeout
_tls_state = {"cert": "expired", "stall": False}
TLS_STALL_S = int(os.environ.get("TLS_STALL_S", "120"))
_MAIL_CONTEXTS = {}


def _mail_context(kind):
    if kind not in _MAIL_CONTEXTS:
        cert, key = f"/tmp/mail-{kind}.pem", f"/tmp/mail-{kind}.key"
        dates = (["-not_before", "20200101000000Z", "-not_after", "20210101000000Z"] if kind == "expired"
                 else ["-days", "30"])
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                        "-out", cert, *dates, "-subj", f"/CN=mail.{APEX}"], check=True, capture_output=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        _MAIL_CONTEXTS[kind] = ctx
    return _MAIL_CONTEXTS[kind]


class TlsMailStandIn(socketserver.BaseRequestHandler):
    def handle(self):
        conn, port = self.request, self.server.server_address[1]
        if _tls_state["stall"]:
            print(f"[{ROLE}] stalled a TLS handshake on {port} for {TLS_STALL_S}s", flush=True)
            time.sleep(TLS_STALL_S)
            return
        kind = _tls_state["cert"]
        try:
            conn.settimeout(10)
            tls = _mail_context(kind).wrap_socket(conn, server_side=True)
            tls.sendall(b"* OK [CAPABILITY IMAP4rev1] fplab mail ready\r\n")
            print(f"[{ROLE}] TLS handshake on {port}, {kind} certificate", flush=True)
            try:
                tls.recv(1024)
            except OSError:
                pass
        except (OSError, ssl.SSLError):
            pass


class TlsMailToggle(Base):
    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/_lab/tls":
            from urllib.parse import parse_qs
            params = parse_qs(query)
            cert = (params.get("cert") or [""])[0]
            stall = (params.get("stall") or [""])[0]
            if cert in ("expired", "valid"):
                _tls_state["cert"] = cert
            if stall in ("0", "1"):
                _tls_state["stall"] = stall == "1"
            return self.send(200, json.dumps(_tls_state), "application/json")
        if path == "/":
            return self.send(200, PLAIN_PAGE.format(title="Webmail"))
        return self.send(404, "<h1>not found</h1>")


# --------------------------------------------------------------------------- SMTP open relay (L-20)
# A real server's dialogue, TCP-split the way real ones arrive: a two-line 220
# greeting in two writes, a multi-line 250- answer to HELO. Only SMTP_RCPT
# differs between the hosts: "554 ..." refuses the relay, "250 ..." accepts it,
# "451 ..." asks to try later (no verdict).
SMTP_RCPT = os.environ.get("SMTP_RCPT", "554 5.7.1 Relay access denied")


class SmtpStandIn(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(15)
        try:
            sock.sendall(b"220-mail.fplab.test ESMTP fplab\r\n")
            time.sleep(0.05)
            sock.sendall(b"220 mail.fplab.test ready\r\n")
            buf = b""
            while True:
                data = sock.recv(1024)
                if not data:
                    return
                buf += data
                while b"\n" in buf:
                    line, _, buf = buf.partition(b"\n")
                    verb = line.strip().split(b" ", 1)[0].upper().decode(errors="replace")
                    print(f"[{ROLE}] {verb}", flush=True)
                    if verb in ("HELO", "EHLO"):
                        sock.sendall(b"250-mail.fplab.test\r\n250-PIPELINING\r\n250 8BITMIME\r\n")
                    elif verb == "MAIL":
                        sock.sendall(b"250 2.1.0 Ok\r\n")
                    elif verb == "RCPT":
                        sock.sendall(SMTP_RCPT.encode() + b"\r\n")
                    elif verb == "QUIT":
                        sock.sendall(b"221 2.0.0 Bye\r\n")
                        return
                    else:
                        sock.sendall(b"502 5.5.2 Error: command not recognized\r\n")
        except OSError:
            return


class SmtpWeb(Base):
    def do_GET(self):
        if self.path.split("?", 1)[0] == "/":
            return self.send(200, PLAIN_PAGE.format(title="Mail relay"))
        return self.send(404, "<h1>not found</h1>")


# --------------------------------------------------------------------------- login forms over HTTP (L-21)
# LOGIN_MODE picks the shape:
#   shell  every path 200, a single-page shell saying "login" with a search form
#          and no password field (not a login form)
#   real   /login is a real form with a password field, every other path 404
#   all    every path answers the same password page (a catch-all)
LOGIN_MODE = os.environ.get("LOGIN_MODE", "real")
LOGIN_SHELL = ('<html><head><title>Portal</title></head><body><nav><a href="/login">Login</a></nav>'
               '<form action="/search" method="get"><input type="search" name="q"><button>Search</button>'
               '</form><div id="app">Please login to continue.</div></body></html>')
LOGIN_FORM = ('<html><head><title>Sign in</title></head><body><form method="post" action="/login">'
              '<input name="username"><input type="password" name="password"><button>Sign in</button>'
              '</form></body></html>')


class Login(Base):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if LOGIN_MODE == "shell":
            return self.send(200, LOGIN_SHELL)
        if LOGIN_MODE == "all" or path == "/login":
            return self.send(200, LOGIN_FORM)
        if path == "/":
            return self.send(200, PLAIN_PAGE.format(title="Staff portal"))
        return self.send(404, "<h1>not found</h1>")


# --------------------------------------------------------------------------- GraphQL (R-7, R-42)
# Enough of a GraphQL server for introspection and graphql-cop: one Query field.
_GQL_SCHEMA = {"__schema": {
    "queryType": {"name": "Query"}, "mutationType": None, "subscriptionType": None,
    "types": [
        {"kind": "OBJECT", "name": "Query", "description": None, "interfaces": [], "enumValues": None,
         "possibleTypes": None, "inputFields": None,
         "fields": [{"name": "hello", "description": None, "args": [], "isDeprecated": False,
                     "deprecationReason": None, "type": {"kind": "SCALAR", "name": "String", "ofType": None}}]},
        {"kind": "SCALAR", "name": "String", "description": None, "fields": None, "interfaces": None,
         "enumValues": None, "possibleTypes": None, "inputFields": None},
        {"kind": "SCALAR", "name": "Boolean", "description": None, "fields": None, "interfaces": None,
         "enumValues": None, "possibleTypes": None, "inputFields": None},
    ],
    "directives": [],
}}


class GraphQL(Base):
    def _answer(self, query):
        if "__schema" in (query or ""):
            return {"data": _GQL_SCHEMA}
        # graphql-cop's GraphQL detection asks {__typename}.
        return {"data": {"__typename": "Query", "hello": "world"}}

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(min(length, 1_000_000)) if length else b""
        if path != "/graphql":
            return self.send(404, '{"error":"not found"}', "application/json")
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            return self.send(400, '{"errors":[{"message":"invalid JSON"}]}', "application/json")
        if isinstance(body, list):
            out = [self._answer((b or {}).get("query")) for b in body if isinstance(b, dict)]
        else:
            out = self._answer(body.get("query") if isinstance(body, dict) else "")
        return self.send(200, json.dumps(out), "application/json")

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/graphql":
            from urllib.parse import parse_qs
            return self.send(200, json.dumps(self._answer((parse_qs(query).get("query") or [""])[0])),
                             "application/json")
        if path == "/":
            return self.send(200, PLAIN_PAGE.format(title="Orders API"))
        return self.send(404, '{"error":"not found"}', "application/json")


# --------------------------------------------------------------------------- main
ROLES = {"fastly": Fastly, "cloudflare": Cloudflare, "redirect": Redirect, "akamai": Akamai,
         "ratelimit": RateLimit, "cache": Cache, "spa": Spa, "vendor": Vendor, "shodan": Shodan,
         "api": Api, "jsonall": JsonAll, "sso": Sso, "loginwall": LoginWall, "deny": Deny, "bulk": Bulk,
         "tlsvhost": TlsVhost, "cdncert": CdnCert, "down": Down, "plainjs": PlainJs,
         "pleasewait": PleaseWait, "throttled": Throttled, "redis": RedisToggle,
         "tlsmail": TlsMailToggle, "smtp": SmtpWeb, "login": Login, "graphql": GraphQL}

# A self-signed certificate's issuer is its subject, so TLS_SUBJECT also sets
# the issuer tlsx reads.
TLS_SUBJECT = os.environ.get("TLS_SUBJECT", f"/CN=*.{APEX}")


def _tls_context():
    cert, key = "/tmp/cert.pem", "/tmp/key.pem"
    if not os.path.exists(cert):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                        "-out", cert, "-days", "30", "-subj", TLS_SUBJECT], check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

    def remember_sni(sock, server_name, _ctx):
        sock._sni = (server_name or "").lower()
    ctx.sni_callback = remember_sni
    return ctx


def main():
    handler = ROLES[ROLE]
    if ROLE == "redis":
        _serve_redis()
    if ROLE == "tlsmail":
        _mail_context("expired")
        _mail_context("valid")
        _serve_tcp(993, TlsMailStandIn)
    if ROLE == "smtp":
        _serve_tcp(25, SmtpStandIn)
    servers = []
    for port in PORTS:
        srv = ThreadingHTTPServer(("0.0.0.0", port), handler)
        if port in TLS_PORTS:
            srv.socket = _tls_context().wrap_socket(srv.socket, server_side=True)
        servers.append(srv)
        print(f"[{ROLE}] listening on {port}{' (tls)' if port in TLS_PORTS else ''}", flush=True)
    for srv in servers[1:]:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    servers[0].serve_forever()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Generate the urlscan lab into generated/ (git-ignored).

    python3 -I gen_lab.py                  # tokens, sites, certificates, DNS, fixtures
    python3 -I gen_lab.py --takeover       # the same, with run T's CNAMEs in the lab zone
    python3 -I gen_lab.py --dns-only [--takeover]   # rewrite generated/dns only (keeps the tokens)
    python3 -I gen_lab.py --no-certs       # no openssl (what the unit test does)

What it writes:

  generated/tokens.json          the planted values T1-T4, K1, J1, J2 (random, invented, lab-only)
  generated/token_hashes.json    sha256 and length of each: what a report may show
  generated/lab.json             addresses, seed hosts, the JS bundles' names and SHA256
  generated/fixtures/visits.json the fake urlscan's visits (plan §10.5)
  generated/sites/<role>/site.json   what each web container serves
  generated/certs/               a lab CA, a staging CA and one certificate per host
  generated/dns/                 the Corefile and zones from dns/, with a fresh serial
  generated/logs/<container>/    the hit logs (hits.jsonl), written by the containers

Tokens are random per generation and exist only here and in the fake urlscan's
answers. Never paste one into a committed file, an issue or a log: compare by
hash or by label.

Problem-page titles come from the plan's §5 family tables, built in below. When
recon/helpers/page_signals.py exists and exposes match_page, every problem-page
fixture is also checked against it, so the fixtures cannot drift from the catalog.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import inspect
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import time
import uuid as uuidlib
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
GEN = HERE / "generated"
DNS_TEMPLATES = HERE / "dns"
PAGE_SIGNALS = REPO / "recon" / "helpers" / "page_signals.py"

NET = "192.88.97"
IPS = {
    "dns": f"{NET}.53", "urlscan": f"{NET}.30", "web": f"{NET}.10", "excluded": f"{NET}.20",
    "edge": f"{NET}.40", "origin": f"{NET}.41", "decoy": f"{NET}.42", "oldip": f"{NET}.98",
    "outsider": f"{NET}.99",
}
DOMAIN = "uslab.test"
OTHER = "uslab-other.test"
TOKEN_LABELS = ("T1", "T2", "T3", "T4", "K1", "J1", "J2")
ANON_VISIBLE_TARGET = 250

# Hosts the scan is seeded with (domain-batch entries under *.uslab.test). legacy
# (only in urlscan's visits), san-only (only in app's certificate), excluded (RoE)
# and promo (phishing visit, no DNS) are deliberately absent.
SEED_HOSTS = ["app", "auth", "files", "docs", "jupyter", "debug", "install", "hacked",
              "blog", "staging", "ingress", "www", "shop"]
TAKEOVER_HOSTS = ["brokenapp-cname", "gone", "healthy"]
SHARED_DOMAINS = [f"www.uslab-other-{n}.test" for n in range(1, 8)]

ASNAME = "LAB-NET - ACME Lab Network, ZZ"
EDGE_ASNAME = "LAB-EDGE - Lab Edge, ZZ"
LAB_CA = "Lab Issuing CA 1"
STAGING_CA = "(STAGING) Lab Fake Issuer R1"
INGRESS_FAKE = "Kubernetes Ingress Controller Fake Certificate"

# Plan §5 family tables: one row per lab host. `live` says what the host serves
# now; `expect_match` False marks a negative that must match nothing.
PROBLEM_PAGES = {
    "pp-jupyter": {"family": "open_console", "host": "jupyter", "path": "/tree",
                   "title": "Home Page - Select or create a notebook", "server": "TornadoServer/6.4.1",
                   "status": 200, "expect_match": True},
    "pp-jupyter-401": {"family": "open_console", "host": "jupyter", "path": "/lab-locked/",
                       "title": "Home Page - Select or create a notebook", "server": "TornadoServer/6.4.1",
                       "status": 401, "expect_match": False},
    "pp-werkzeug": {"family": "debug_page", "host": "debug", "path": "/console",
                    "title": "Console // Werkzeug Debugger", "server": "Werkzeug/3.0.1 Python/3.12.3",
                    "status": 200, "expect_match": True},
    "pp-installer": {"family": "installer", "host": "install", "path": "/wp-admin/setup-config.php",
                     "title": "WordPress › Setup Configuration File", "server": "Apache/2.4.62 (Debian)",
                     "status": 200, "expect_match": True},
    "pp-listing": {"family": "directory_listing", "host": "files", "path": "/",
                   "title": "Index of /", "server": "Apache/2.4.62 (Debian)", "status": 200,
                   "expect_match": True},
    "pp-hacked": {"family": "defacement", "host": "hacked", "path": "/",
                  "title": "Hacked by LabCrew", "server": "LabWeb/1.0", "status": 200,
                  "expect_match": True},
    "pp-blog-post": {"family": "defacement", "host": "blog", "path": "/posts/how-we-got-hacked",
                     "title": "Hacked by LabCrew: what we learned", "server": "gunicorn", "status": 200,
                     "expect_match": False},
    "pp-blog-root": {"family": "dev_server", "host": "blog", "path": "/",
                     "title": "ACME Lab Blog", "server": "gunicorn", "status": 200, "expect_match": False},
}
TAKEOVER_TITLE = "No such app"
DEV_SERVER = "SimpleHTTP/0.6 Python/3.12.3"


# --------------------------------------------------------------------------- tokens

def _token(n: int, rnd) -> str:
    alphabet = string.ascii_letters + string.digits
    while True:
        value = "".join(rnd.choice(alphabet) for _ in range(n))
        # Token-like for the detection rules: letters and digits mixed.
        if any(c.isdigit() for c in value) and any(c.isalpha() for c in value):
            return value


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwt(exp: int, rnd) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps({"sub": "uslab-user-" + _token(6, rnd), "exp": exp,
                                  "jti": _token(16, rnd)}, separators=(",", ":")).encode())
    # A random signature: the token is shaped like a JWT and verifies against nothing.
    return f"{header}.{payload}.{_b64url(bytes(rnd.getrandbits(8) for _ in range(32)))}"


def make_tokens(rnd=None, now: float | None = None) -> dict:
    rnd = rnd or secrets.SystemRandom()
    now = int(now or time.time())
    return {
        "T1": _token(32, rnd), "T2": _token(32, rnd), "T3": _token(32, rnd), "T4": _token(32, rnd),
        "K1": _token(40, rnd),
        "J1": _jwt(now - 86_400 * 3, rnd),     # expired: jwt_expired true
        "J2": _jwt(now + 86_400 * 365, rnd),   # not expired
    }


def token_hashes(tokens: dict) -> dict:
    return {k: {"sha256": hashlib.sha256(v.encode()).hexdigest(), "length": len(v)}
            for k, v in tokens.items()}


# --------------------------------------------------------------------------- JS bundles

def _bundle(label: str, lines: int) -> bytes:
    body = [f"/* ACME Lab {label} bundle (urlscan lab, generated) */", "(function(){"]
    for i in range(lines):
        body.append(f"  var m{i} = function(x){{ return '{label}-' + x + '-{i}'; }};")
    body.append(f"  window.acmeLab = {{ site: '{label}', modules: {lines} }};")
    body.append("})();")
    return ("\n".join(body) + "\n").encode()


def js_bundles() -> dict:
    """Deterministic: the same bytes on every generation, so the SHA256 the
    fixtures carry is the SHA256 the origin serves."""
    out = {}
    for key, label, prefix, lines in (("www", "shop-www", "app", 60), ("shop", "shop-store", "main", 45),
                                      ("decoy", "shop-decoy", "app", 52)):
        body = _bundle(label, lines)
        sha = hashlib.sha256(body).hexdigest()
        code = sha[:10]
        if not re.search(r"[a-f]", code):
            code = sha[:9] + "a"
        out[key] = {"name": f"{prefix}.{code}.js", "path": f"/assets/{prefix}.{code}.js",
                    "sha256": sha, "body": body.decode()}
    return out


# --------------------------------------------------------------------------- sites

def _page(title: str, body: str = "", head: str = "") -> str:
    return (f"<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>{title}</title>{head}</head>"
            f"<body><h1>{title}</h1>{body}</body></html>\n")


def _r(path, body="", status=200, ctype="text/html; charset=utf-8", match="exact", headers=None, b64=None):
    route = {"path": path, "match": match, "status": status, "ctype": ctype}
    if b64 is not None:
        route["body_b64"] = b64
    else:
        route["body"] = body
    if headers:
        route["headers"] = headers
    return route


def _host(name: str) -> str:
    return DOMAIN if name in ("", "@", DOMAIN) else f"{name}.{DOMAIN}"


PDF_BYTES = (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Count 0/Kids[]>>"
             b"endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n")


def _openapi() -> str:
    return json.dumps({
        "openapi": "3.0.3",
        "info": {"title": "ACME Lab Widgets", "version": "2.0.0"},
        "servers": [{"url": f"https://docs.{DOMAIN}"}],
        "paths": {
            "/api/v2/widgets": {"get": {"summary": "List widgets",
                                        "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer"}}],
                                        "responses": {"200": {"description": "ok"}}}},
            "/api/v2/widgets/{id}": {"get": {"summary": "One widget",
                                             "parameters": [{"name": "id", "in": "path", "required": True,
                                                             "schema": {"type": "integer"}}],
                                             "responses": {"200": {"description": "ok"}}}},
        },
    }, indent=1)


def build_sites(bundles: dict) -> dict:
    """role -> site.json content. Pages never link to a planted path: the leaked
    links, the web shell and the backups are known only through urlscan."""
    www, shop, decoy = bundles["www"], bundles["shop"], bundles["decoy"]
    listing_root = _page("Index of /", "<ul><li><a href=\"readme.txt\">readme.txt</a></li>"
                                       "<li><a href=\"docs/\">docs/</a></li></ul>")
    python_listing = _page("Directory listing for /", "<ul><li><a href=\"notes.txt\">notes.txt</a></li></ul>")

    web_vhosts = [
        {"names": [_host("")], "cert": "apex", "server": "LabWeb/1.0",
         "routes": [_r("/", _page("ACME Lab", "<p>Welcome to ACME Lab.</p>"))]},
        {"names": [_host("app"), _host("san-only")], "cert": "app", "server": "LabWeb/1.0",
         "routes": [
             _r("/", _page("ACME Lab App", "<p><a href=\"/search?q=shoes\">Search</a> "
                                           "<a href=\"/about\">About</a></p>")),
             _r("/about", _page("About ACME Lab")),
             _r("/search", _page("Search results")),
             # The live redirector never redirects: a scanner fuzzing ?url= must
             # not be sent off the lab (the visit alone proves the open redirect).
             _r("/go", _page("Redirect disabled in the lab"), status=400),
             _r("/invite/", _page("Join ACME Lab"), match="prefix"),
             _r("/unsubscribe", _page("You are unsubscribed")),
             _r("/api/data", '{"items": []}', ctype="application/json"),
             _r("/x", _page("Token page")),
             _r("/backup.sql", _page("404 Not Found"), status=404),
             _r("/export.csv", "id,item\n1,widget\n", ctype="text/csv"),
             _r("/admin/users", _page("Sign in required"), status=401),
             _r("/api/v1/items", '{"items": [{"id": 5}]}', ctype="application/json"),
             _r("/promo", _page("Promo")),
             _r("/list", _page("List")),
             _r("/account", _page("Account")),
         ]},
        {"names": [_host("auth")], "cert": "auth", "server": "LabWeb/1.0",
         "routes": [
             _r("/", _page("Sign in", "<form method=\"post\" action=\"/login\"><input name=\"username\">"
                                      "<input name=\"password\" type=\"password\"></form>"
                                      "<p><a href=\"/login\">Sign in</a></p>")),
             _r("/login", _page("Sign in", "<form method=\"post\" action=\"/login\"></form>")),
             _r("/reset", _page("Reset your password")),
             _r("/password/reset/", _page("Choose a new password"), match="prefix"),
             _r("/auth/magic/", _page("Signing you in"), match="prefix"),
             _r("/oidc/callback", _page("Missing code"), status=400),
             _r("/saml/acs", _page("Method not allowed"), status=405),
             _r("/authorize", _page("Sign in to continue")),
         ]},
        {"names": [_host("files")], "cert": "files", "server": "Apache/2.4.62 (Debian)",
         "routes": [
             _r("/", listing_root),
             _r("/readme.txt", "ACME Lab file share.\n", ctype="text/plain"),
             _r("/docs/", _page("Index of /docs/")),
             _r("/.env", "APP_NAME=uslab\nAPP_ENV=lab\nDB_HOST=db.uslab.test\nDB_NAME=uslab\n"
                         "CACHE_DRIVER=file\n", ctype="text/plain"),
             _r("/.git/config", "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
                                "[remote \"origin\"]\n\turl = https://git.uslab.test/acme/site.git\n",
                ctype="text/plain"),
             _r("/.git/HEAD", _page("404 Not Found"), status=404),
             _r("/shell.php", "", ctype="text/plain"),
             _r("/docs/invoice-2026.pdf", ctype="application/pdf", b64=base64.b64encode(PDF_BYTES).decode()),
             _r("/actuator/heapdump", ctype="application/octet-stream",
                b64=base64.b64encode(b"\0" * 1024).decode()),
         ]},
        {"names": [_host("docs")], "cert": "docs", "server": "LabWeb/1.0",
         "routes": [
             _r("/", _page("ACME Lab Docs", "<p><a href=\"/docs/\">Documentation</a></p>")),
             _r("/docs", _page("Documentation")),
             _r("/docs/", _page("Documentation", "<p><a href=\"/docs/v2/\">API v2</a></p>")),
             _r("/docs/v2/", _page("Swagger UI", "<div id=\"swagger-ui\"></div>",
                                   "<script>window.specUrl = 'openapi.json';</script>")),
             _r("/docs/v2/openapi.json", _openapi(), ctype="application/json"),
         ]},
        {"names": [_host("jupyter")], "cert": "jupyter", "server": "TornadoServer/6.4.1",
         "routes": [
             _r("/", _page(PROBLEM_PAGES["pp-jupyter"]["title"])),
             _r("/tree", _page(PROBLEM_PAGES["pp-jupyter"]["title"])),
             _r("/lab-locked/", _page(PROBLEM_PAGES["pp-jupyter"]["title"]), status=401),
         ]},
        {"names": [_host("debug")], "cert": "debug", "server": "Werkzeug/3.0.1 Python/3.12.3",
         "routes": [_r("/", _page("Console // Werkzeug Debugger")),
                    _r("/console", _page("Console // Werkzeug Debugger"))]},
        # The title is entity-encoded as WordPress sends it: the catalog must
        # normalise &rsaquo; to the character urlscan reports.
        {"names": [_host("install")], "cert": "install", "server": "Apache/2.4.62 (Debian)",
         "routes": [_r("/", _page("WordPress &rsaquo; Setup Configuration File")),
                    _r("/wp-admin/setup-config.php", _page("WordPress &rsaquo; Setup Configuration File"))]},
        {"names": [_host("hacked")], "cert": "hacked", "server": "LabWeb/1.0",
         "routes": [_r("/", _page("Hacked by LabCrew"))]},
        {"names": [_host("blog")], "cert": "blog", "server": "gunicorn",
         "routes": [
             _r("/", _page("ACME Lab Blog", "<p><a href=\"/posts/how-we-got-hacked\">How we got hacked</a></p>")),
             _r("/posts/how-we-got-hacked", _page("Hacked by LabCrew: what we learned")),
             _r("/archive/", _page("ACME Lab Blog archive"), match="prefix"),
         ]},
        {"names": [_host("staging")], "cert": "staging", "server": "LabWeb/1.0",
         "routes": [_r("/", _page("ACME Lab Staging"))]},
        {"names": [_host("ingress")], "cert": "ingress", "server": "LabWeb/1.0",
         "routes": [_r("/", "default backend - 404\n", status=404, ctype="text/plain")]},
        {"names": [_host("legacy")], "cert": "legacy", "server": "LabWeb/1.0",
         "routes": [_r("/", _page("ACME Lab Legacy"))]},
        # Run T: reached only while the lab zone carries the takeover CNAMEs.
        {"names": [_host("brokenapp-cname"), "brokenapp.herokuapp.com"], "cert": "takeover", "server": "Heroku",
         "routes": [_r("/", _page(TAKEOVER_TITLE), status=404, match="prefix")]},
        {"names": [_host("healthy"), "liveapp.herokuapp.com"], "cert": "takeover", "server": "Heroku",
         "routes": [_r("/", _page("ACME Lab Healthy"))]},
        # A bare-IP request (run I) lands here: Python's http.server listing,
        # so the live checks have a development server and a listing to find.
        {"names": ["_default"], "cert": "ingress", "server": DEV_SERVER,
         "routes": [_r("/", python_listing), _r("/notes.txt", "lab notes\n", ctype="text/plain")]},
    ]

    shop_page = lambda js, text: _page("ACME Lab Shop", f"<p>{text}</p>",  # noqa: E731
                                       f"<script src=\"{js['path']}\"></script>")
    origin_vhosts = [
        {"names": [_host("www"), "_default"], "cert": "www", "server": "LabOrigin/1.0",
         "routes": [_r("/", shop_page(www, "Fresh widgets every day. Free shipping over 50.")),
                    _r(www["path"], www["body"], ctype="application/javascript")]},
        {"names": [_host("shop")], "cert": "shop", "server": "LabOrigin/1.0",
         "routes": [_r("/", shop_page(shop, "The ACME Lab store.")),
                    _r(shop["path"], shop["body"], ctype="application/javascript")]},
    ]
    # Same title and layout as www, another text and another bundle: a page-only
    # match must not confirm it, and its file must not match.
    decoy_vhosts = [
        {"names": [_host("www"), "_default"], "cert": "decoy", "server": "LabOrigin/1.0",
         "routes": [_r("/", shop_page(decoy, "Parked page. This server no longer hosts the shop.")),
                    _r(decoy["path"], decoy["body"], ctype="application/javascript")]},
    ]
    return {
        "web": {"container": "uslab-web", "vhosts": web_vhosts, "default_cert": "ingress"},
        "excluded": {"container": "uslab-excluded", "default_cert": "excluded", "vhosts": [
            {"names": [_host("excluded"), "_default"], "cert": "excluded", "server": "LabWeb/1.0",
             "routes": [_r("/", _page("ACME Lab Excluded"))]}]},
        "origin": {"container": "uslab-origin", "vhosts": origin_vhosts, "default_cert": "www",
                   "via_edge_server": "cloudflare"},
        "decoy": {"container": "uslab-decoy", "vhosts": decoy_vhosts, "default_cert": "decoy"},
        "oldip": {"container": "uslab-oldip", "default_cert": "oldip", "vhosts": [
            {"names": ["_default"], "cert": "oldip", "server": "LabWeb/0.9",
             "routes": [_r("/", _page("ACME Lab App (old server)"))]}]},
        "outsider": {"container": "uslab-outsider", "default_cert": "outsider", "vhosts": [
            {"names": [f"outsider.{OTHER}", "_default"], "cert": "outsider", "server": "OtherWeb/1.0",
             "routes": [_r("/", _page("Outsider"), match="prefix")]},
            {"names": [f"mirror.{OTHER}"], "cert": "outsider", "server": "OtherWeb/1.0",
             "routes": [_r("/", _page("Mirror"), match="prefix")]}]},
    }


# --------------------------------------------------------------------------- fixtures

def _apex(host: str) -> str:
    if re.fullmatch(r"[0-9.]+", host):
        return host
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _canonical(url: str) -> str:
    parts = urlsplit(url)
    return (parts.hostname or "") + parts.path.rstrip("/")


def visit(lab_id: str, group: str, url: str, *, age: float, ip: str, task_url: str | None = None,
          title: str = "", server: str | None = "LabWeb/1.0", status: str = "200",
          mime: str = "text/html", tags=None, redirected: str | None = None,
          tls_issuer: str | None = LAB_CA, tls_valid_days: int = 90, tls_age_days: int = 20,
          files=(), touched=(), asnname: str = ASNAME, ptr: str | None = None,
          umbrella: int | None = None, expect: dict | None = None, rnd=None) -> dict:
    """One urlscan visit: response fields plus the lab-only age_days,
    touched_domains, files, lab_id, group and lab_expect (never returned)."""
    task_url = task_url or url
    page_host = urlsplit(url).hostname or ""
    task_host = urlsplit(task_url).hostname or ""
    is_ip = bool(re.fullmatch(r"[0-9.]+", page_host))
    task = {"visibility": "public", "method": "api", "domain": task_host, "apexDomain": _apex(task_host),
            "uuid": str(uuidlib.UUID(int=(rnd or secrets.SystemRandom()).getrandbits(128), version=4)),
            "url": task_url}
    if tags:
        task["tags"] = list(tags)
    page = {"url": url, "domain": page_host, "apexDomain": _apex(page_host), "ip": ip,
            "asn": "AS64501" if ip == IPS["edge"] else "AS64500",
            "asnname": EDGE_ASNAME if ip == IPS["edge"] else asnname, "country": "ZZ"}
    if ptr:
        page["ptr"] = ptr
    if server:
        page["server"] = server
    page.update({"status": str(status), "title": title, "mimeType": mime})
    if mime.startswith("text/html"):
        page["language"] = "en"
    if redirected:
        page["redirected"] = redirected
    if tls_issuer and url.startswith("https://"):
        page.update({"tlsIssuer": tls_issuer, "tlsValidDays": tls_valid_days, "tlsAgeDays": tls_age_days})
    if not is_ip:
        page.update({"domainAgeDays": 4348, "apexDomainAgeDays": 4348})
    if umbrella:
        page["umbrellaRank"] = umbrella
    size = 1200 + 40 * len(files)
    entry = {
        "submitter": {},
        "canonical": {"task": {"url": _canonical(task_url)}, "page": {"url": _canonical(url)}},
        "task": task,
        "stats": {"uniqIPs": 1, "uniqCountries": 1, "dataLength": size, "encodedDataLength": size - 200,
                  "requests": 1 + len(files)},
        "page": page,
        "labels": [],
        "age_days": round(float(age), 4),
        "touched_domains": sorted({page_host, task_host, *touched} - {""}),
        "files": [{"name": f["name"], "sha256": f["sha256"]} for f in files],
        "lab_id": lab_id,
        "group": group,
    }
    if expect:
        entry["lab_expect"] = expect
    return entry


def _anon_visible(v: dict) -> bool:
    domain = v["page"]["domain"]
    return (domain == DOMAIN or domain.endswith("." + DOMAIN)) and v["age_days"] <= 30


def build_fixtures(tokens: dict, bundles: dict, rnd=None) -> list[dict]:
    rnd = rnd or secrets.SystemRandom()
    www_js, shop_js, decoy_js = bundles["www"], bundles["shop"], bundles["decoy"]
    web, edge = IPS["web"], IPS["edge"]
    V = lambda *a, **k: visit(*a, rnd=rnd, **k)  # noqa: E731
    out = []

    # Old IPs (S5, B03, B11; item 7 clue 1). .41 is 400 days old: only a key sees it.
    out += [
        V("oldip-app", "old_ips", f"https://app.{DOMAIN}/", age=20, ip=IPS["oldip"], title="ACME Lab App",
          server="LabWeb/0.9"),
        V("www-origin-old", "old_ips", f"https://www.{DOMAIN}/", age=400, ip=IPS["origin"],
          title="ACME Lab Shop", server="nginx/1.18.0", files=[www_js]),
        V("www-decoy", "old_ips", f"https://www.{DOMAIN}/", age=25, ip=IPS["decoy"], title="ACME Lab Shop",
          server="LabOrigin/1.0", files=[decoy_js]),
    ]
    for n, age in enumerate((2, 6, 14), 1):
        out.append(V(f"www-edge-{n}", "old_ips", f"https://www.{DOMAIN}/", age=age, ip=edge,
                     title="ACME Lab Shop", server="cloudflare", files=[www_js], ptr=f"edge.{DOMAIN}",
                     umbrella=4544))
    for n, age in enumerate((3, 9), 1):
        out.append(V(f"shop-edge-{n}", "old_ips", f"https://shop.{DOMAIN}/", age=age, ip=edge,
                     title="ACME Lab Shop", server="cloudflare", files=[shop_js], ptr=f"edge.{DOMAIN}"))

    # Same file (item 7 clue 2): www's bundle on a bare IP and on a stranger;
    # shop's bundle on 7 unrelated registrable domains (a shared file) and a bare IP.
    out += [
        V("samefile-bareip", "same_file", f"http://{IPS['origin']}/", age=10, ip=IPS["origin"],
          title="ACME Lab Shop", server="LabOrigin/1.0", files=[www_js], tls_issuer=None),
        V("samefile-mirror", "same_file", f"https://mirror.{OTHER}/", age=12, ip=IPS["outsider"],
          title="Mirror", server="OtherWeb/1.0", files=[www_js]),
        V("shared-bareip", "same_file", f"http://{NET}.43/", age=4, ip=f"{NET}.43", title="ACME Lab Shop",
          server="LabOrigin/1.0", files=[shop_js], tls_issuer=None),
    ]
    for n, host in enumerate(SHARED_DOMAINS, 1):
        out.append(V(f"shared-{n}", "same_file", f"https://{host}/", age=4 + n, ip=f"{NET}.{149 + n}",
                     title=f"Other shop {n}", server="OtherWeb/1.0", files=[shop_js]))

    # Redirects (item 1, N1, B30): they end on another site, so only the
    # task.apexDomain search returns them.
    out += [
        V("redir-go", "redirects", f"https://outsider.{OTHER}/",
          task_url=f"https://app.{DOMAIN}/go?url=https://outsider.{OTHER}/", age=7, ip=IPS["outsider"],
          title="Outsider", server="OtherWeb/1.0", redirected="off-domain"),
        V("redir-oauth", "redirects", f"https://outsider.{OTHER}/login",
          task_url=(f"https://auth.{DOMAIN}/authorize?client_id=lab-client&response_type=code"
                    f"&redirect_uri=https://outsider.{OTHER}/callback&state={_token(12, rnd)}"),
          age=8, ip=IPS["outsider"], title="Outsider sign-in", server="OtherWeb/1.0", redirected="off-domain"),
    ]

    # Leaks (item 2, S1-S4): the planted values, plus three negatives.
    t = tokens
    leaks = [
        ("leak-T1", f"https://auth.{DOMAIN}/reset?token={t['T1']}", "Reset your password", "text/html"),
        ("leak-T2", f"https://auth.{DOMAIN}/password/reset/{t['T2']}", "Choose a new password", "text/html"),
        ("leak-T3", f"https://app.{DOMAIN}/invite/{t['T3']}", "Join ACME Lab", "text/html"),
        ("leak-T4", f"https://app.{DOMAIN}/unsubscribe?u={t['T4']}", "You are unsubscribed", "text/html"),
        ("leak-K1", f"https://app.{DOMAIN}/api/data?apikey={t['K1']}", "", "application/json"),
        ("leak-J1", f"https://app.{DOMAIN}/x?jwt={t['J1']}", "Token page", "text/html"),
        ("leak-J2", f"https://auth.{DOMAIN}/auth/magic/{t['J2']}", "Signing you in", "text/html"),
        ("neg-utm", f"https://app.{DOMAIN}/promo?utm_source=newsletter&utm_medium=email", "Promo", "text/html"),
        ("neg-page", f"https://app.{DOMAIN}/list?page=2", "List", "text/html"),
        ("neg-session", f"https://app.{DOMAIN}/account?session=abc", "Account", "text/html"),
    ]
    for n, (lab_id, url, title, mime) in enumerate(leaks):
        out.append(V(lab_id, "leaks", url, age=1.5 + n, ip=web, title=title, mime=mime))

    # Files (item 3) and documents.
    files = [
        ("file-env", f"https://files.{DOMAIN}/.env", "text/plain"),
        ("file-git", f"https://files.{DOMAIN}/.git/config", "text/plain"),
        ("file-sql", f"https://app.{DOMAIN}/backup.sql", "application/octet-stream"),
        ("file-shell", f"https://files.{DOMAIN}/shell.php?cmd=cat+/etc/passwd", "text/plain"),
        ("file-heapdump", f"https://files.{DOMAIN}/actuator/heapdump", "application/octet-stream"),
        ("doc-pdf", f"https://files.{DOMAIN}/docs/invoice-2026.pdf", "application/pdf"),
        ("doc-csv", f"https://app.{DOMAIN}/export.csv", "text/csv"),
    ]
    for n, (lab_id, url, mime) in enumerate(files):
        server = "Apache/2.4.62 (Debian)" if "files." in url else "LabWeb/1.0"
        out.append(V(lab_id, "files", url, age=2.25 + n, ip=web, title="", server=server, mime=mime))

    # Labels (item 4a-4f, B16, B20-B24).
    labels = [
        ("lbl-oidc", f"https://auth.{DOMAIN}/oidc/callback", "Missing code", "400"),
        ("lbl-saml", f"https://auth.{DOMAIN}/saml/acs", "Method not allowed", "405"),
        ("lbl-admin", f"https://app.{DOMAIN}/admin/users", "Users - Admin", "401"),
        ("lbl-items", f"https://app.{DOMAIN}/api/v1/items?id=5&next=https://outsider.{OTHER}/", "", "200"),
        ("lbl-search", f"https://app.{DOMAIN}/search?q=x&page=2", "Search results", "200"),
        ("lbl-docs-slash", f"https://docs.{DOMAIN}/docs/", "Documentation", "200"),
        ("lbl-docs", f"https://docs.{DOMAIN}/docs", "Documentation", "200"),
        ("lbl-auth-root", f"https://auth.{DOMAIN}/", "Sign in", "200"),
        ("lbl-swagger", f"https://docs.{DOMAIN}/docs/v2/", "Swagger UI", "200"),
    ]
    for n, (lab_id, url, title, status) in enumerate(labels):
        mime = "application/json" if "/api/" in url else "text/html"
        out.append(V(lab_id, "labels", url, age=3.5 + n, ip=web, title=title, status=status, mime=mime))

    # Problem pages (item 5): one host per family, and the negatives.
    for n, (lab_id, row) in enumerate(PROBLEM_PAGES.items()):
        out.append(V(lab_id, "problem_pages", f"https://{_host(row['host'])}{row['path']}", age=4.75 + n,
                     ip=web, title=row["title"], server=row["server"], status=str(row["status"]),
                     expect={"family": row["family"], "match": row["expect_match"]}))
    out += [
        V("pp-staging", "problem_pages", f"https://staging.{DOMAIN}/", age=6.5, ip=web, title="ACME Lab Staging",
          tls_issuer=STAGING_CA, expect={"family": "test_certificate", "match": True, "certificate": True}),
        V("pp-ingress", "problem_pages", f"https://ingress.{DOMAIN}/", age=6.75, ip=web, title="",
          status="404", mime="text/plain", tls_issuer=INGRESS_FAKE,
          expect={"family": "test_certificate", "match": True, "certificate": True}),
        # Expired at the visit (tlsAgeDays > tlsValidDays): family X, urlscan only.
        V("pp-legacy-expired", "problem_pages", f"https://legacy.{DOMAIN}/", age=7.25, ip=web,
          title="ACME Lab Legacy", tls_valid_days=90, tls_age_days=120,
          expect={"family": "test_certificate", "match": True, "certificate": True}),
    ]

    # Takeover pages (item 5 family T). healthy shows the error page in history
    # only: today it serves a normal page, so it must give no finding.
    for n, host in enumerate(TAKEOVER_HOSTS):
        out.append(V(f"tk-{host}", "takeover", f"https://{host}.{DOMAIN}/", age=5.5 + n, ip=web,
                     title=TAKEOVER_TITLE, server="Heroku", status="404",
                     expect={"family": "takeover", "match": True}))

    # Hosts (F1, B27, B01, B11, B13).
    out += [
        V("host-legacy", "hosts", f"https://legacy.{DOMAIN}/about", age=9.5, ip=web, title="ACME Lab Legacy"),
        V("host-excluded", "hosts", f"https://excluded.{DOMAIN}/", age=10.5, ip=IPS["excluded"],
          title="ACME Lab Excluded"),
        V("phish-promo", "phishing", f"https://promo.{DOMAIN}/", age=11.5, ip=web, title="ACME Lab Promo",
          tags=["phishing", "malicious"]),
        V("app-root", "hosts", f"https://app.{DOMAIN}/", age=0.75, ip=web, title="ACME Lab App"),
        V("app-https-only", "hosts", f"https://app.{DOMAIN}/", task_url=f"http://app.{DOMAIN}/", age=8.5,
          ip=web, title="ACME Lab App", redirected="https-only"),
        V("apex-root", "hosts", f"https://{DOMAIN}/", age=1.25, ip=web, title="ACME Lab"),
    ]

    # Volume (F3, B29): enough blog pages that an anonymous page.domain search
    # sees exactly ANON_VISIBLE_TARGET visits, three pages of 100.
    filler = ANON_VISIBLE_TARGET - sum(1 for v in out if _anon_visible(v))
    if filler < 1:
        raise SystemExit(f"[!] {ANON_VISIBLE_TARGET - filler} anonymous-visible visits before the volume "
                         f"group: raise ANON_VISIBLE_TARGET")
    for n in range(filler):
        age = 0.2 + 29.5 * (n + 0.5) / filler
        out.append(V(f"vol-{n:03d}", "volume", f"https://blog.{DOMAIN}/archive/{n + 1}", age=age, ip=web,
                     title=f"ACME Lab Blog - archive {n + 1}", server="gunicorn"))
    return out


# --------------------------------------------------------------------------- page_signals cross-check

def check_page_signals(visits: list[dict], path: Path = PAGE_SIGNALS) -> list[str]:
    """Problem-page fixtures against the real catalog, when it exists. Returns
    the disagreements; an absent catalog or one without match_page returns []."""
    if not path.is_file():
        return []
    spec = importlib.util.spec_from_file_location("uslab_page_signals", path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:  # noqa: BLE001 - a catalog that cannot load is reported, not fatal here
        return [f"page_signals.py did not import: {e!r}"]
    match_page = getattr(module, "match_page", None)
    if not callable(match_page):
        return []
    match_cert = getattr(module, "match_certificate", None)
    problems = []
    for v in visits:
        expect = v.get("lab_expect")
        if not expect:
            continue
        page = v["page"]
        if expect.get("certificate"):
            if not callable(match_cert):
                continue
            func = match_cert
            args = {"issuer": page.get("tlsIssuer"), "age_days": page.get("tlsAgeDays"),
                    "valid_days": page.get("tlsValidDays")}
        else:
            func = match_page
            args = {"title": page.get("title"), "server": page.get("server"), "status": int(page["status"]),
                    "path": urlsplit(page["url"]).path or "/", "mime_type": page.get("mimeType"),
                    "host": page.get("domain"), "url": page.get("url"), "cname": None}
        accepted = set(inspect.signature(func).parameters)
        try:
            got = func(**{k: val for k, val in args.items() if k in accepted})
        except Exception as e:  # noqa: BLE001 - the catalog must never raise; report it
            problems.append(f"{v['lab_id']}: {func.__name__} raised {e!r}")
            continue
        if bool(got) != bool(expect["match"]):
            problems.append(f"{v['lab_id']}: expected {'a match' if expect['match'] else 'no match'} "
                            f"({expect['family']}), page_signals returned {got!r}")
    return problems


# --------------------------------------------------------------------------- certificates

CERTS = {
    # name: (subject CN, SAN names, issuer: "lab" | "staging" | "self")
    "apex": (DOMAIN, [DOMAIN, f"excluded.{DOMAIN}"], "lab"),
    "app": (f"app.{DOMAIN}", [f"app.{DOMAIN}", f"san-only.{DOMAIN}"], "lab"),
    "auth": (f"auth.{DOMAIN}", [f"auth.{DOMAIN}"], "lab"),
    "files": (f"files.{DOMAIN}", [f"files.{DOMAIN}"], "lab"),
    "docs": (f"docs.{DOMAIN}", [f"docs.{DOMAIN}"], "lab"),
    "jupyter": (f"jupyter.{DOMAIN}", [f"jupyter.{DOMAIN}"], "lab"),
    "debug": (f"debug.{DOMAIN}", [f"debug.{DOMAIN}"], "lab"),
    "install": (f"install.{DOMAIN}", [f"install.{DOMAIN}"], "lab"),
    "hacked": (f"hacked.{DOMAIN}", [f"hacked.{DOMAIN}"], "lab"),
    "blog": (f"blog.{DOMAIN}", [f"blog.{DOMAIN}"], "lab"),
    "legacy": (f"legacy.{DOMAIN}", [f"legacy.{DOMAIN}"], "lab"),
    "takeover": (f"brokenapp-cname.{DOMAIN}", [f"brokenapp-cname.{DOMAIN}", f"healthy.{DOMAIN}"], "lab"),
    "www": (f"www.{DOMAIN}", [f"www.{DOMAIN}"], "lab"),
    "shop": (f"shop.{DOMAIN}", [f"shop.{DOMAIN}"], "lab"),
    "excluded": (f"excluded.{DOMAIN}", [f"excluded.{DOMAIN}"], "lab"),
    "oldip": (f"app.{DOMAIN}", [f"app.{DOMAIN}"], "lab"),
    "outsider": (f"outsider.{OTHER}", [f"outsider.{OTHER}", f"mirror.{OTHER}"], "lab"),
    "staging": (f"staging.{DOMAIN}", [f"staging.{DOMAIN}"], "staging"),
    "ingress": (INGRESS_FAKE, ["ingress.local"], "self"),
    "decoy": ("uslab-decoy", ["uslab-decoy"], "self"),
    "edge-default": ("uslab-edge", ["uslab-edge"], "self"),
}


def _openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def build_certs(out: Path) -> None:
    certs = out / "certs"
    certs.mkdir(parents=True, exist_ok=True)
    ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]
    for name, cn, org in (("lab-ca", LAB_CA, "ACME Lab"), ("staging-ca", STAGING_CA, "Lab Staging")):
        _openssl("req", "-x509", "-new", *ec, "-keyout", str(certs / f"{name}.key"),
                 "-out", str(certs / f"{name}.crt"), "-days", "3650", "-sha256", "-subj", f"/O={org}/CN={cn}",
                 "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    with tempfile.TemporaryDirectory() as tmp:
        for name, (cn, sans, issuer) in CERTS.items():
            key, crt = certs / f"{name}.key", certs / f"{name}.crt"
            san = ",".join(f"DNS:{s}" for s in sans)
            if issuer == "self":
                org = "Acme Co" if name == "ingress" else "ACME Lab"
                _openssl("req", "-x509", "-new", *ec, "-keyout", str(key), "-out", str(crt), "-days", "365",
                         "-sha256", "-subj", f"/O={org}/CN={cn}", "-addext", f"subjectAltName={san}")
            else:
                ca = "lab-ca" if issuer == "lab" else "staging-ca"
                csr, ext, leaf = Path(tmp) / f"{name}.csr", Path(tmp) / f"{name}.ext", Path(tmp) / f"{name}.pem"
                ext.write_text(f"subjectAltName={san}\nbasicConstraints=critical,CA:FALSE\n"
                               "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n")
                _openssl("req", "-new", *ec, "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={cn}")
                _openssl("x509", "-req", "-in", str(csr), "-CA", str(certs / f"{ca}.crt"),
                         "-CAkey", str(certs / f"{ca}.key"), "-CAcreateserial",
                         "-CAserial", str(Path(tmp) / f"{ca}.srl"), "-out", str(leaf),
                         "-days", "90", "-sha256", "-extfile", str(ext))
                crt.write_text(leaf.read_text() + (certs / f"{ca}.crt").read_text())
    for f in certs.iterdir():
        # The containers run as the invoking user or as nginx's root master, from a read-only bind.
        f.chmod(0o644)


# --------------------------------------------------------------------------- DNS

def compose_dns(out: Path, takeover: bool) -> None:
    dns = out / "dns"
    dns.mkdir(parents=True, exist_ok=True)
    serial = str(int(time.time()))
    for src in DNS_TEMPLATES.glob("*"):
        if src.name.endswith(".takeover.db"):
            continue
        text = src.read_text()
        if src.suffix == ".db":
            text = re.sub(r"(IN\s+SOA\s+\S+\s+\S+\s+)\d+", r"\g<1>" + serial, text, count=1)
        if src.name == f"{DOMAIN}.db" and takeover:
            text += "\n" + (DNS_TEMPLATES / f"{DOMAIN}.takeover.db").read_text()
        (dns / src.name).write_text(text)
        (dns / src.name).chmod(0o644)


# --------------------------------------------------------------------------- orchestration

def write_lab(out: Path = GEN, *, tokens: dict | None = None, takeover: bool = False,
              certs: bool = True, rnd=None) -> dict:
    out = Path(out)
    rnd = rnd or secrets.SystemRandom()
    tokens = tokens or make_tokens(rnd)
    bundles = js_bundles()
    visits = build_fixtures(tokens, bundles, rnd)
    out.mkdir(parents=True, exist_ok=True)
    (out / "fixtures").mkdir(exist_ok=True)
    (out / "fixtures" / "visits.json").write_text(json.dumps(
        {"generated_at": int(time.time()), "visits": visits}, indent=1))
    (out / "tokens.json").write_text(json.dumps(tokens, indent=1))
    (out / "tokens.json").chmod(0o600)
    (out / "token_hashes.json").write_text(json.dumps(token_hashes(tokens), indent=1))
    for role, site in build_sites(bundles).items():
        (out / "sites" / role).mkdir(parents=True, exist_ok=True)
        (out / "sites" / role / "site.json").write_text(json.dumps({"role": role, **site}, indent=1))
    for container in ("uslab-web", "uslab-excluded", "uslab-origin", "uslab-decoy", "uslab-oldip",
                      "uslab-outsider", "uslab-edge", "uslab-urlscan"):
        logs = out / "logs" / container
        logs.mkdir(parents=True, exist_ok=True)
        (logs / "hits.jsonl").touch()
    compose_dns(out, takeover)
    if certs:
        build_certs(out)
    meta = {
        "generated_at": int(time.time()),
        "net": NET, "ips": IPS, "domain": DOMAIN, "other": OTHER,
        "seed_hosts": [_host(h) for h in SEED_HOSTS],
        "takeover_hosts": [_host(h) for h in TAKEOVER_HOSTS],
        "takeover_dns": takeover,
        "bundles": {k: {"name": b["name"], "path": b["path"], "sha256": b["sha256"]} for k, b in bundles.items()},
        "token_labels": list(TOKEN_LABELS),
        "anonymous_visible": sum(1 for v in visits if _anon_visible(v)),
        "visits": len(visits),
    }
    (out / "lab.json").write_text(json.dumps(meta, indent=1))
    return {"meta": meta, "visits": visits, "tokens": tokens, "bundles": bundles}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path, default=GEN)
    ap.add_argument("--takeover", action="store_true", help="add run T's CNAMEs to the lab zone")
    ap.add_argument("--dns-only", action="store_true", help="rewrite generated/dns only")
    ap.add_argument("--no-certs", action="store_true")
    a = ap.parse_args()
    if a.dns_only:
        compose_dns(a.out, a.takeover)
        print(f"[+] {a.out / 'dns'} written (takeover CNAMEs {'on' if a.takeover else 'off'})")
        return 0
    if a.out.exists() and (a.out / "tokens.json").exists():
        # New tokens make every earlier run's evidence unreadable: keep the old
        # folder aside rather than mixing generations.
        stamp = time.strftime("%Y%m%d-%H%M%S")
        shutil.move(str(a.out), str(a.out.with_name(f"{a.out.name}.old-{stamp}")))
        print(f"[*] previous generation moved to {a.out.name}.old-{stamp}/")
    lab = write_lab(a.out, takeover=a.takeover, certs=not a.no_certs)
    problems = check_page_signals(lab["visits"])
    for p in problems:
        print(f"[!] {p}")
    meta = lab["meta"]
    print(f"[+] {meta['visits']} visits ({meta['anonymous_visible']} visible without a key), "
          f"tokens {', '.join(TOKEN_LABELS)} (values in {a.out.name}/tokens.json only)")
    print(f"[+] bundles: " + ", ".join(f"{k} {b['name']}" for k, b in meta["bundles"].items()))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

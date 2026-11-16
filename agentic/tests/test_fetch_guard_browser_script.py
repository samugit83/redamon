"""The guarded browser script's options (T3.2): with no option it is byte for byte the script
1.x tradecraft has always sent; ``clean`` runs the EX-2 cleaning (inline scripts and styles
emptied, svg/noscript/template removed, every detection marker and link kept, R-197) before the
page is cut at ``max_chars``; ``wait_for`` waits for an element; and every variant keeps the
address checks, with the cleaning and the print only on a page that passed them.

The script runs in the sandbox browser, which no unit test has: the tests read the script's
source and AST, and apply the cleaning's own selectors (parsed from the JavaScript) with
BeautifulSoup to the marker pages EX-2 measured.
"""

from __future__ import annotations

import ast
import itertools
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator_helpers import fetch_guard  # noqa: E402
from orchestrator_helpers.web_sources import BeautifulSoup  # noqa: E402

URL = "https://docs.example.test/guide/"

# The script 1.x sent before T3.2 (``fetch_guard.py`` at the plan's base commit), with its two
# inserted values left as markers.
TODAY = '''\
import ipaddress as _rd_ipaddress
import socket as _rd_socket
import urllib.parse as _rd_urlparse
_rd_blocked_names = {blocked_names}
_rd_cgnat = _rd_ipaddress.ip_network("100.64.0.0/10")
_rd_verdicts = {}
def _rd_host_public(host):
    if host in _rd_blocked_names:
        return False
    try:
        infos = _rd_socket.getaddrinfo(host, None)
    except OSError:
        return False
    for info in infos:
        ip = _rd_ipaddress.ip_address(info[4][0].split("%")[0])
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified or ip in _rd_cgnat):
            return False
    return True
def _rd_public(url):
    parts = _rd_urlparse.urlsplit(url)
    if parts.scheme in ("data", "blob"):
        return True
    host = (parts.hostname or "").lower().rstrip(".")
    if parts.scheme not in ("http", "https") or not host:
        return False
    if host not in _rd_verdicts:
        _rd_verdicts[host] = _rd_host_public(host)
    return _rd_verdicts[host]
def _rd_route(route):
    if _rd_public(route.request.url):
        route.continue_()
    else:
        route.abort("blockedbyclient")
page.route("**/*", _rd_route)
try:
    _rd_resp = page.goto({url}, wait_until="networkidle", timeout=30000)
except Exception as _rd_exc:
    print("[ERROR] Navigation failed: " + str(_rd_exc).splitlines()[0])
else:
    _rd_hops = [page.url]
    _rd_req = _rd_resp.request if _rd_resp is not None else None
    while _rd_req is not None:
        _rd_hops.append(_rd_req.url)
        _rd_req = _rd_req.redirected_from
    _rd_bad = [h for h in _rd_hops if not _rd_public(h)]
    if _rd_bad:
        print("[BLOCKED] navigation reached a non-public address: " + _rd_bad[0])
    else:
        print(page.content()[:40000])
'''


def today(url: str = URL) -> str:
    return TODAY.replace("{url}", ascii(url)).replace(
        "{blocked_names}", ascii(frozenset(fetch_guard._BLOCKED_HOSTNAMES)))


VARIANTS = [
    dict(zip(("timeout_ms", "wait_until", "max_chars", "clean", "wait_for"), combo))
    for combo in itertools.product((30000, 5000, 50000), ("networkidle", "load", "domcontentloaded"),
                                   (40000, 500000, 1000000), (False, True), (None, "#article .content"))
]


def test_defaults_byte_identical():
    assert fetch_guard.guarded_browser_script(URL) == today()
    explicit = fetch_guard.guarded_browser_script(URL, timeout_ms=30000, wait_until="networkidle", max_chars=40000,
                                                  clean=False, wait_for=None)
    assert explicit == today()
    hostile = "https://docs.example.test/');import os;os.system('id');(' é"
    assert fetch_guard.guarded_browser_script(hostile) == today(hostile)


def test_1x_callers_send_the_default_script():
    """The 1.x tradecraft modules call the script with the URL alone, so they keep today's script."""
    root = Path(fetch_guard.__file__).resolve().parent
    calls = []
    for name in ("tradecraft_lookup.py", "tradecraft_crawl.py"):
        tree = ast.parse((root / name).read_text(encoding="utf-8"))
        calls += [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                  and getattr(n.func, "id", getattr(n.func, "attr", "")) == "guarded_browser_script"]
    assert len(calls) == 2
    assert all(len(c.args) == 1 and not c.keywords for c in calls)


def _clean_selectors():
    """(selector, action) pairs of the cleaning JavaScript, read from its source."""
    pairs = re.findall(r"querySelectorAll\('([^']+)'\)\) (?:s|n)(\.textContent = ''|\.remove\(\))", fetch_guard._CLEAN_JS)
    return [(sel, "empty" if "textContent" in act else "remove") for sel, act in pairs]


def clean_like_the_browser(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for selector, action in _clean_selectors():
        for el in soup.select(selector):
            if action == "empty":
                el.string = ""
            else:
                el.decompose()
    return str(soup)


def detection_markers(html: str) -> set:
    """What type detection reads: meta, link and script[src] elements by their attributes, and
    the comments (BeautifulSoup reorders attributes when it prints; the browser does not)."""
    from bs4 import Comment

    soup = BeautifulSoup(html, "html.parser")
    found = {(el.name, tuple(sorted((k, str(v)) for k, v in el.attrs.items())))
             for el in soup.find_all(["meta", "link", "script"]) if el.name != "script" or el.get("src")}
    return found | {("comment", str(c)) for c in soup.find_all(string=lambda t: isinstance(t, Comment))}


MARKER_PAGES = {
    "mkdocs": ('<meta name="generator" content="mkdocs-1.5">', 'name="generator" content="mkdocs'),
    "docusaurus": ('<meta name="generator" content="Docusaurus v3">', 'name="generator" content="docusaurus'),
    "gitbook": ('<meta name="generator" content="GitBook"><script src="https://static.gitbook.com/x.js"></script>',
                "static.gitbook.com"),
    "sphinx": ('<meta name="generator" content="Docutils 0.20"><script src="_static/searchindex.js"></script>',
               "_static/searchindex.js"),
    "mdbook": ("<!-- Book generated using mdBook --><script src=\"mdbook.js\"></script>", "mdbook.js"),
}


@pytest.mark.parametrize("kind", sorted(MARKER_PAGES))
def test_clean_keeps_markers(kind):
    head, marker = MARKER_PAGES[kind]
    page = (f"<html><head>{head}<link rel=\"stylesheet\" href=\"/s.css\"><style>{'b{x:y}' * 5000}</style>"
            f"<script>{'var a=1;' * 5000}</script></head><body><svg><path d=\"M0\"/></svg><noscript>enable js</noscript>"
            f"<template><p>t</p></template><article><p>Article text.</p><a href=\"/next/\">next</a></article></body></html>")
    cleaned = clean_like_the_browser(page)
    assert detection_markers(cleaned) == detection_markers(page)
    assert marker.split('"')[-1].lower() in cleaned.lower()
    assert '<link href="/s.css" rel="stylesheet"/>' in cleaned and '<a href="/next/">next</a>' in cleaned
    assert "Article text." in cleaned
    assert "var a=1" not in cleaned and "b{x:y}" not in cleaned
    assert "<svg" not in cleaned and "<noscript" not in cleaned and "<template" not in cleaned
    assert "<script" in cleaned and "<style" in cleaned  # the elements stay, only their text goes
    assert len(cleaned) < len(page) / 20
    # The script carries exactly this JavaScript, and only when asked to clean.
    assert ascii(fetch_guard._CLEAN_JS) in fetch_guard.guarded_browser_script(URL, clean=True)
    assert "page.evaluate" not in fetch_guard.guarded_browser_script(URL)
    assert _clean_selectors() == [("script:not([src])", "empty"), ("style", "empty"), ("svg, noscript, template", "remove")]


def test_max_chars_applied():
    assert "print(page.content()[:40000])" in fetch_guard.guarded_browser_script(URL)
    assert "print(page.content()[:500000])" in fetch_guard.guarded_browser_script(URL, max_chars=500000, clean=True)
    assert "print(page.content()[:1000000])" in fetch_guard.guarded_browser_script(URL, max_chars=1000000)
    script = fetch_guard.guarded_browser_script(URL, timeout_ms=12000, wait_until="load")
    assert 'page.goto(' in script and 'wait_until="load", timeout=12000)' in script


def _body_after_hop_check(tree):
    """The statements run when no hop was refused: the ``else`` of ``if _rd_bad``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and getattr(node.test, "id", "") == "_rd_bad":
            return node.orelse
    raise AssertionError("no hop check")


@pytest.mark.parametrize("options", VARIANTS, ids=lambda o: "-".join(str(v) for v in o.values()))
def test_guard_lines_present_in_every_variant(options):
    script = fetch_guard.guarded_browser_script(URL, **options)
    base = today()
    # Every line of today's script that guards the page is there unchanged.
    for line in base.splitlines():
        if line.startswith(("import ", "_rd_", "def _rd_", "    ", "page.route(")) and "page.goto(" not in line \
                and "page.content()" not in line:
            assert line in script.splitlines(), line
    tree = ast.parse(script)
    after = _body_after_hop_check(tree)
    after_src = "\n".join(ast.unparse(n) for n in after)
    # Nothing is read, cleaned or printed before the hops were judged.
    assert "page.content()" in after_src and script.count("page.content()") == 1
    if options["clean"]:
        assert after_src.index("page.evaluate(") < after_src.index("page.content()")
    if options["wait_for"]:
        wait = script.index("page.wait_for_selector(")
        assert script.index("page.goto(") < wait < script.index("_rd_hops = [page.url]")
        waits = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "wait_for_selector"]
        timeout = waits[0].keywords[0].value.value
        assert 1000 <= timeout <= max(1000, 55000 - options["timeout_ms"])
    # The script survives the MCP script-mode wrapper (8-space indent, sync API only).
    body = "\n".join(("        " + ln) if ln.strip() else "" for ln in script.splitlines())
    compile("with ctx:\n    try:\n" + body + "\n    finally:\n        pass\n", "<wrapped>", "exec")
    for pattern in (r"(?<![A-Za-z0-9_])await\s", r"(?<![A-Za-z0-9_])async\s+def\b", r"(?m)^\s*import\s+asyncio\b"):
        assert re.search(pattern, script) is None, pattern


def test_selector_is_one_inert_literal():
    hostile = "#a'), __import__('os').system('id'), ('\n#b"
    script = fetch_guard.guarded_browser_script(URL, wait_for=hostile)
    waits = [n for n in ast.walk(ast.parse(script)) if isinstance(n, ast.Call)
             and getattr(n.func, "attr", "") == "wait_for_selector"]
    assert len(waits) == 1 and isinstance(waits[0].args[0], ast.Constant) and waits[0].args[0].value == hostile
    assert "__import__" not in [getattr(n.func, "id", "") for n in ast.walk(ast.parse(script)) if isinstance(n, ast.Call)]


@pytest.mark.parametrize("bad", [
    {"wait_until": "networkidle0"}, {"wait_until": "load\nimport os"}, {"timeout_ms": 0}, {"max_chars": 0},
    {"max_chars": "40000; import os"},
])
def test_options_outside_the_script_are_refused(bad):
    with pytest.raises(ValueError):
        fetch_guard.guarded_browser_script(URL, **bad)

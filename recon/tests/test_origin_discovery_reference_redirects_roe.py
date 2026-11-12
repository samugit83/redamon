"""Origin discovery's reference fetch never follows a redirect into a host the
Rules of Engagement exclude (R-2).

The reference fetch is the one request of the module that follows redirects
(a canonical apex->www or http->https 301 must not empty the page every
candidate is compared with). requests followed every hop unchecked, so a
fronted host answering 302 into an excluded host had that host requested.
Under RoE exclusions each hop, the first URL included, now passes
hop_guard's check before it is sent; a refused hop leaves the host without a
reference, which keeps its earlier origin findings (not fully checked). With
no exclusion in force the fetch is the one sent before.

IP mode never reaches it: origin discovery returns before selecting a host
(B-08), pinned by test_ip_mode_builders.py::test_origin_discovery_never_runs_in_ip_mode,
test_regression_ip_mode_scope_leaks.py::test_origin_discovery_skips_ip_mode,
and, for partial recon, test_partial_ip_mode_scope.py (OriginDiscovery is
refused in IP mode).

Real servers on 127.0.0.1 (the fronted host) and 127.0.0.2 (the excluded one);
nothing else is faked.
"""
from __future__ import annotations

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import circuit_breaker  # noqa: E402
from recon.main_recon_modules import origin_discovery as od  # noqa: E402

FRONTED, EXCLUDED = "127.0.0.1", "127.0.0.2"


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


def _serve(address: str, handler_cls):
    server = ThreadingHTTPServer((address, 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def servers():
    """The fronted host answers / with 302 to the excluded host and /same with
    302 to its own /landing; the excluded host records every request."""
    hits = []

    class Excluded(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            body = b"<html><title>excluded</title></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_a):
            pass

    excluded = _serve(EXCLUDED, Excluded)
    port = excluded.server_address[1]

    class Fronted(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/landing":
                body = b"<html><title>fronted</title><script src='/app.js'></script></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(302)
            target = "/landing" if self.path == "/same" else f"http://{EXCLUDED}:{port}/"
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_a):
            pass

    fronted = _serve(FRONTED, Fronted)
    yield {"fronted": f"{FRONTED}:{fronted.server_address[1]}", "hits": hits}
    fronted.shutdown()
    excluded.shutdown()


def _ctx(**settings):
    return od._RunCtx(dict({"ORIGIN_DISCOVERY_TIMEOUT": 3}, **settings))


@pytest.mark.parametrize("entry", [EXCLUDED, f"{EXCLUDED}/32", "127.0.0.2/31"])
def test_reference_fetch_never_follows_into_an_excluded_host(servers, capsys, entry):
    ctx = _ctx(ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=[entry])
    assert od._reference(servers["fronted"], ctx) is None
    assert servers["hits"] == []
    assert "[-][RoE] origin_discovery: not sent to" in capsys.readouterr().out


def test_reference_fetch_follows_a_same_host_redirect_under_exclusions(servers):
    ctx = _ctx(ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=[EXCLUDED])
    ref = od._reference(f"{servers['fronted']}/same", ctx)
    assert ref is not None and ref["status"] == 200
    assert ref["final_url"] == f"http://{servers['fronted']}/landing"
    assert "/app.js" in ref["html"]
    assert servers["hits"] == []


@pytest.mark.parametrize("settings", [{}, {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": []},
                                      {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [EXCLUDED]}])
def test_reference_fetch_unchanged_without_an_exclusion(servers, settings):
    ref = od._reference(servers["fronted"], _ctx(**settings))
    assert ref is not None and ref["status"] == 200
    assert ref["final_url"].startswith(f"http://{EXCLUDED}:")
    assert servers["hits"] == ["/"]


def test_a_refused_reference_keeps_the_hosts_findings(servers, monkeypatch):
    """No reference: the host is recorded as not fully checked, so the prune
    keeps its earlier origin findings."""
    ctx = _ctx(ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=[EXCLUDED])
    monkeypatch.setattr(od, "_gather_candidates", lambda *a, **k: [("203.0.113.9", "shodan_ssl")])
    monkeypatch.setattr(od, "_dedup_and_filter", lambda cands, *a, **k: cands)
    confirmed, meta = od._process_host(servers["fronted"], {}, ctx)
    assert confirmed == []
    assert meta["unchecked"] == od._CUT_REFERENCE
    assert servers["hits"] == []

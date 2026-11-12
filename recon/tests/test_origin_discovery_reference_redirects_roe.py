"""Origin discovery's reference fetch never follows a redirect into a host the
Rules of Engagement exclude, nor, in any mode, into an unsafe address (R-2).

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


# --------------------------------------------------------------------------
# The SSRF guard of the reference fetch, in every mode (R-2 follow-up)
# --------------------------------------------------------------------------
# Recon containers run with host networking, so a fronted host whose 302
# names cloud metadata or an internal address made the recon container fetch
# it: requests followed every hop unchecked, with or without RoE exclusions.
# A hop to another host now has to pass the attacker-influenced URL rule
# (is_url_safe_to_probe: public addresses only), unless the operator typed
# that host; the fronted host's own redirects are followed as before.

METADATA_URL = "http://169.254.169.254/latest/meta-data/"
PUBLIC_NAME, PUBLIC_ADDRESS = "public.example.test", "203.0.113.20"


@pytest.fixture
def wire(monkeypatch):
    """Every TCP connect requests makes. A connect to an address the test has
    no server for is refused here, so nothing leaves the container; the
    public test name resolves to an RFC 5737 address for the guard and is
    connected to the 127.0.0.2 server."""
    import socket as real_socket
    import urllib3.util.connection as u3conn
    connects = []
    real_connect = u3conn.create_connection
    real_getaddrinfo = real_socket.getaddrinfo

    def getaddrinfo(host, *args, **kwargs):
        if host == PUBLIC_NAME:
            return [(real_socket.AF_INET, real_socket.SOCK_STREAM, 6, "", (PUBLIC_ADDRESS, 0))]
        return real_getaddrinfo(host, *args, **kwargs)

    def create_connection(address, *args, **kwargs):
        host, port = address[0], address[1]
        connects.append(host)
        if host == PUBLIC_NAME:
            return real_connect((EXCLUDED, port), *args, **kwargs)
        if host not in (FRONTED, EXCLUDED):
            raise ConnectionRefusedError(f"no test server for {host}")
        return real_connect(address, *args, **kwargs)

    monkeypatch.setattr(real_socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(u3conn, "create_connection", create_connection)
    # The RFC 5737 address stands in for a public one.
    from recon.main_recon_modules import ip_filter
    real_non_routable = ip_filter.is_non_routable_ip
    monkeypatch.setattr(ip_filter, "is_non_routable_ip",
                        lambda ip: False if ip == PUBLIC_ADDRESS else real_non_routable(ip))
    return connects


@pytest.fixture
def redirector():
    """127.0.0.1 answers /go?to=<url> with 302 to <url>, /set with 302 to
    /landing setting a cookie, and /landing with 200 only when the cookie
    came back; 127.0.0.2 records every request."""
    from urllib.parse import parse_qs, urlsplit
    hits = []

    class Other(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append((self.headers.get("Host"), self.path))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_a):
            pass

    other = _serve(EXCLUDED, Other)

    class Redirector(BaseHTTPRequestHandler):
        def do_GET(self):
            parts = urlsplit(self.path)
            if parts.path == "/go":
                target = parse_qs(parts.query)["to"][0].replace("PORT", str(other.server_address[1]))
                self.send_response(302)
                self.send_header("Location", target)
            elif parts.path == "/set":
                self.send_response(302)
                self.send_header("Set-Cookie", "sid=1; Path=/")
                self.send_header("Location", "/landing")
            elif "sid=1" in (self.headers.get("Cookie") or ""):
                body = b"<html><title>fronted</title></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            else:
                self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_a):
            pass

    server = _serve(FRONTED, Redirector)
    yield {"fronted": f"{FRONTED}:{server.server_address[1]}", "hits": hits}
    server.shutdown()
    other.shutdown()


@pytest.mark.parametrize("settings", [{}, {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["192.0.2.99"]}])
@pytest.mark.parametrize("to", [METADATA_URL, "http://10.0.0.5/", "http://127.0.0.2:PORT/admin",
                                "http://metadata.google.internal/computeMetadata/v1/"])
def test_reference_fetch_never_follows_into_an_unsafe_address(redirector, wire, settings, to):
    ref = od._reference(f"{redirector['fronted']}/go?to={to}", _ctx(**settings))
    assert ref is None
    assert redirector["hits"] == []
    assert not [h for h in wire if h not in (FRONTED,)]


@pytest.mark.parametrize("settings", [{}, {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": []},
                                      {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [PUBLIC_NAME]},
                                      {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["192.0.2.99"]}])
def test_reference_fetch_follows_a_public_redirect(redirector, wire, settings):
    ref = od._reference(f"{redirector['fronted']}/go?to=http://{PUBLIC_NAME}:PORT/home",
                        _ctx(**settings))
    assert ref is not None and ref["status"] == 200
    assert [path for _host, path in redirector["hits"]] == ["/home"]
    assert redirector["hits"][0][0].startswith(PUBLIC_NAME)


def test_reference_fetch_follows_an_operator_typed_internal_host(redirector, wire):
    """A host the operator typed is scanned whatever it resolves to, as every
    other caller of the address rule treats it (operator_targets)."""
    ctx = _ctx(TARGET_IPS=[f"{EXCLUDED}/32"])
    ref = od._reference(f"{redirector['fronted']}/go?to=http://{EXCLUDED}:PORT/", ctx)
    assert ref is not None and ref["status"] == 200
    assert [path for _host, path in redirector["hits"]] == ["/"]


def test_reference_fetch_keeps_a_redirects_cookie_on_the_same_host(redirector, wire):
    ref = od._reference(f"{redirector['fronted']}/set", _ctx())
    assert ref is not None and ref["status"] == 200
    assert ref["final_url"] == f"http://{redirector['fronted']}/landing"

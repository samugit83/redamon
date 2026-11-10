"""R-48: a certificate the client refuses is not a dead host.

circuit_breaker._failure_kind decides what counts against HostHealth, which
every module of the run shares. A self-signed, expired or mismatched
certificate means the host answered the TLS handshake, so it must never mark
the host down for the other modules; a handshake the host reset or cut short
still counts. GraphQL, which verifies certificates by default, keeps its own
earlier findings on such a host, since it checked nothing there.

The certificate and handshake cases run against a real local TLS server and
the real requests / urllib stacks, so the exception chains are the ones a scan
sees. The conftest autouse fixture resets HostHealth around every test.
"""
from __future__ import annotations

import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from unittest import mock

import pytest
import requests
import urllib3
from urllib3.util.ssl_match_hostname import CertificateError

from recon.graphql_scan import introspection
from recon.helpers import circuit_breaker as cb
from recon.helpers import security_checks

# About as many paths as GraphQL discovery guesses on one host.
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/graphiql", "/v1/graphql", "/v2/graphql",
                 "/query", "/gql", "/api/gql", "/graphql/console", "/playground",
                 "/api", "/altair")


@pytest.fixture(scope="module")
def self_signed(tmp_path_factory):
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not in this image")
    d = tmp_path_factory.mktemp("r48-cert")
    key, crt = d / "key.pem", d / "crt.pem"
    proc = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
         "-out", str(crt), "-days", "1", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost"],
        capture_output=True, timeout=60)
    if proc.returncode != 0:
        pytest.skip("openssl could not make a test certificate")
    return str(crt), str(key)


class _Server:
    """A loopback server that answers every connection the same way.

    tls   - completes the handshake with the self-signed certificate, then
            answers HTTP 200 (a client that verifies refuses the certificate);
    eof   - reads the ClientHello and closes cleanly (handshake cut short);
    reset - reads part of the ClientHello and resets the connection.
    """

    def __init__(self, mode: str, cert=None):
        self.mode = mode
        self.ctx = None
        if mode == "tls":
            self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ctx.load_cert_chain(*cert)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def url(self, path: str = "/") -> str:
        return f"https://localhost:{self.port}{path}"

    def _run(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            conn.settimeout(2)
            try:
                self._answer(conn)
            except Exception:  # noqa: BLE001 - a client that hangs up is expected
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    @staticmethod
    def _read_request(tls) -> None:
        """Read the whole request, body included, before answering.

        urllib3 writes a POST body after its headers, and one TLS recv returns
        one record. Closing with the body unread makes the kernel reset the
        connection, and a client that has not read the answer yet then sees a
        connection failure: three of those mark the host down.
        """
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = tls.recv(65536)
            if not chunk:
                return
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        length = 0
        for line in head.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"content-length":
                length = int(value.strip() or 0)
        while len(body) < length:
            chunk = tls.recv(65536)
            if not chunk:
                return
            body += chunk

    def _answer(self, conn):
        if self.mode == "tls":
            with self.ctx.wrap_socket(conn, server_side=True) as tls:
                self._read_request(tls)
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                            b"Connection: close\r\n\r\nok")
        elif self.mode == "eof":
            conn.recv(65536)
            time.sleep(0.05)
            conn.shutdown(socket.SHUT_RDWR)
        else:
            conn.recv(8)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))

    def close(self):
        self._stop.set()
        self.sock.close()
        self._thread.join(timeout=2)


@pytest.fixture
def tls_server(self_signed):
    srv = _Server("tls", self_signed)
    yield srv
    srv.close()


def _requests_error(url: str, **kwargs) -> BaseException:
    try:
        requests.get(url, timeout=5, **kwargs)
    except requests.RequestException as exc:
        return exc
    raise AssertionError(f"{url} answered; the test needs a failure")


def _verify_failed(detail: str = "self-signed certificate") -> ssl.SSLError:
    return ssl.SSLCertVerificationError(
        1, f"[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: {detail} (_ssl.c:1016)")


def _as_requests_raises_it(inner: BaseException, url: str = "/") -> requests.RequestException:
    """The chain requests builds: SSLError(MaxRetryError(reason=urllib3 SSLError(inner)))."""
    retry = urllib3.exceptions.MaxRetryError(None, url, reason=urllib3.exceptions.SSLError(inner))
    return requests.exceptions.SSLError(retry)


# ---------------------------------------------------------------------------
# A certificate error never marks the host down
# ---------------------------------------------------------------------------

@pytest.mark.filterwarnings("ignore::urllib3.exceptions.InsecureRequestWarning")
def test_graphql_on_a_self_signed_host_leaves_it_up_for_every_other_module(tls_server):
    for path in GRAPHQL_PATHS:
        ok, _schema, error = introspection.test_introspection(
            tls_server.url(path), {}, 5, verify_ssl=True)
        assert ok is False
        assert "CERTIFICATE_VERIFY_FAILED" in error

    url = tls_server.url("/graphql")
    assert cb.host_health.is_down(url) is False
    assert cb.host_health.allow(url) is True
    assert cb.host_health.unreachable() == []
    # The security checks still scan it: their gate passes and their requester
    # (which does not verify certificates) gets the page.
    assert security_checks._host_down("localhost:%d" % tls_server.port) is False
    resp = security_checks._hh_get(tls_server.url("/"), timeout=5, verify=False)
    assert resp.status_code == 200


def test_a_real_requests_certificate_error_does_not_count(tls_server):
    exc = _requests_error(tls_server.url("/x"))
    assert isinstance(exc, requests.exceptions.SSLError)
    assert cb.is_connection_failure(exc) is False
    scope = cb.scope((), label="Security checks", unit="host(s)")
    for _ in range(5):
        assert scope.host_failed(tls_server.url("/x"), exc) is False
        assert cb.host_health.record_failure(tls_server.url("/x"), exc) is False
    assert cb.host_health.is_down(tls_server.url("/x")) is False
    assert scope.hosts() == []


def test_a_real_urllib_certificate_error_does_not_count(tls_server):
    with pytest.raises(urllib.error.URLError) as caught:
        urllib.request.urlopen(tls_server.url("/x"), timeout=5)
    exc = caught.value
    for _ in range(5):
        assert cb.host_health.record_failure(tls_server.url("/x"), exc) is False
    assert cb.host_health.is_down(tls_server.url("/x")) is False


@pytest.mark.parametrize("exc", [
    _verify_failed(),
    _verify_failed("certificate has expired"),
    _verify_failed("unable to get local issuer certificate"),
    _verify_failed("Hostname mismatch, certificate is not valid for 'a.example.com'."),
    # An ssl.SSLError built from the OpenSSL message alone, with no reason set.
    ssl.SSLError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
                    "unable to get local issuer certificate (_ssl.c:1016)"),
    _as_requests_raises_it(_verify_failed()),
    # urllib3's own hostname matcher (assert_hostname, or an IP without check_hostname).
    _as_requests_raises_it(CertificateError("hostname 'a.example.com' doesn't match 'b.example.com'")),
    urllib.error.URLError(_verify_failed()),
], ids=["self-signed", "expired", "unknown-ca", "hostname", "ssl-message-only",
        "requests-chain", "urllib3-hostname", "urllib"])
def test_certificate_verification_failures_never_count(exc):
    url = "https://a.example.com/graphql"
    assert cb.is_connection_failure(exc) is False
    for _ in range(3):
        assert cb.host_health.record_failure(url, exc) is False
    assert cb.host_health.is_down(url) is False
    assert cb.host_health.unreachable() == []


def test_a_certificate_error_is_neither_a_failure_nor_a_response():
    url = "https://a.example.com/"
    for _ in range(2):
        cb.host_health.record_failure(url, requests.exceptions.ConnectionError("x"))
    cb.host_health.record_failure(url, _as_requests_raises_it(_verify_failed()))
    assert cb.host_health.is_down(url) is False
    cb.host_health.record_failure(url, requests.exceptions.ConnectionError("x"))
    assert cb.host_health.is_down(url) is True


# ---------------------------------------------------------------------------
# A handshake that never completes still counts, as before
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("exc", [
    requests.exceptions.ConnectionError("x"),
    ConnectionResetError(104, "Connection reset by peer"),
    ssl.SSLEOFError(8, "[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation "
                       "of protocol (_ssl.c:1016)"),
    _as_requests_raises_it(ssl.SSLEOFError(8, "[SSL: UNEXPECTED_EOF_WHILE_READING] EOF")),
    # A target-controlled path that spells the OpenSSL reason never silences a
    # real handshake failure: only the ssl error's own text is read.
    _as_requests_raises_it(ssl.SSLEOFError(8, "[SSL: UNEXPECTED_EOF_WHILE_READING] EOF"),
                           url="/CERTIFICATE_VERIFY_FAILED"),
    requests.exceptions.ConnectionError(
        "HTTPSConnectionPool(host='a.example.com', port=443): Max retries exceeded with "
        "url: /CERTIFICATE_VERIFY_FAILED (Caused by NewConnectionError('refused'))"),
    # requests' SSLError with no cause attached keeps today's rule.
    requests.exceptions.SSLError("x"),
], ids=["connection-error", "reset", "ssl-eof", "requests-ssl-eof", "token-in-url",
        "token-in-connection-error", "bare-ssl-error"])
def test_handshake_failures_still_count(exc):
    url = "https://a.example.com/graphql"
    assert cb.is_connection_failure(exc) is True
    for _ in range(3):
        assert cb.host_health.record_failure(url, exc) is True
    assert cb.host_health.is_down(url) is True
    assert cb.host_health.unreachable() == ["a.example.com:443"]


@pytest.mark.parametrize("mode", ["eof", "reset"])
def test_a_real_handshake_cut_short_still_marks_the_host_down(self_signed, mode):
    srv = _Server(mode, self_signed)
    try:
        exc = _requests_error(srv.url("/x"))
        for _ in range(3):
            assert cb.host_health.record_failure(srv.url("/x"), exc) is True
        assert cb.host_health.is_down(srv.url("/x")) is True
    finally:
        srv.close()


# ---------------------------------------------------------------------------
# GraphQL keeps its findings on a host whose certificate it refused
# ---------------------------------------------------------------------------
# GraphQL verifies certificates by default, so on such a host it checked
# nothing: its earlier graphql_scan / graphql_cop findings there must survive
# the run's prune, while every other source, which did reach the host, prunes
# as usual.

GUESSED = ("/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql")


def _gql_settings(**over):
    settings = {
        "GRAPHQL_SECURITY_ENABLED": True, "GRAPHQL_VERIFY_SSL": True,
        "GRAPHQL_INTROSPECTION_TEST": True, "GRAPHQL_TIMEOUT": 5, "GRAPHQL_RATE_LIMIT": 0,
        "GRAPHQL_CONCURRENCY": 1, "GRAPHQL_RETRY_COUNT": 0, "GRAPHQL_RETRY_BACKOFF": 0,
        "GRAPHQL_COP_ENABLED": False,
    }
    settings.update(over)
    return settings


def _run_graphql(srv, **over):
    from recon.graphql_scan import scanner
    with mock.patch.object(scanner, "discover_graphql_endpoints",
                           return_value=[srv.url(p) for p in GUESSED]):
        combined = {}
        scanner.run_graphql_scan(combined, _gql_settings(**over))
    return combined["graphql_scan"]


class _PruneGraph:
    """Records what the end-of-run prune asks Neo4j to delete."""

    def __init__(self):
        self.prunes = []

    def __call__(self, *a, **kw):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def verify_connection(self):
        return True

    def backfill_passive_cve_hosts(self, *a, **kw):
        return 0

    def prune_unseen_findings(self, user_id, project_id, sources, since, keep_hosts=(), **kw):
        self.prunes.append((tuple(sources), tuple(keep_hosts)))
        return {"pruned": 0, "stale": 0, "revived": 0}

    def keep_hosts_for(self, source):
        (keep,) = [keep for sources, keep in self.prunes if source in sources]
        return keep


@pytest.fixture
def recon_main(monkeypatch):
    stub = {
        'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False, 'TARGET_IPS': [],
        'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['domain_discovery'],
        'UPDATE_GRAPH_DB': True, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        rm._RUN_STARTED_AT = "2026-01-01T00:00:00+00:00"
        rm._COVERAGE_WRITE_FAILED = False
        graph = _PruneGraph()
        monkeypatch.setattr("graph_db.Neo4jClient", graph)
        yield rm, graph


def test_graphql_keeps_its_findings_on_a_host_whose_certificate_it_refused(
        tls_server, recon_main, capsys):
    rm, graph = recon_main
    payload = _run_graphql(tls_server)
    errors = [data.get("error") or "" for data in payload["endpoints"].values()]
    assert len(errors) == len(GUESSED)
    assert all(e.startswith(introspection.CERT_REFUSED) for e in errors)
    out = capsys.readouterr().out
    assert f"localhost:{tls_server.port}" in out and "certificate" in out.lower()

    rm._prune_recon_findings()
    assert "localhost" in graph.keep_hosts_for("graphql_scan")
    assert "localhost" in graph.keep_hosts_for("graphql_cop")
    # The other modules reached the host: their stale findings there still go.
    assert "localhost" not in graph.keep_hosts_for("security_check")
    assert "localhost" not in graph.keep_hosts_for("nuclei")
    # Recorded as a GraphQL coverage gap that names the certificate, never as
    # a host that is down.
    report = cb.coverage_report()
    (gap,) = [g for g in report.gaps if g["source"] == "graphql_scan"]
    assert "certificate" in gap["reason"].lower()
    # The Recon Delta drops a run's whole gap list over one malformed source.
    assert all(re.fullmatch(r"[a-z0-9_]{1,64}", g["source"]) for g in report.gaps)
    assert cb.host_health.unreachable() == []


@pytest.mark.filterwarnings("ignore::urllib3.exceptions.InsecureRequestWarning")
def test_graphql_that_did_not_verify_the_certificate_keeps_nothing(tls_server, recon_main):
    rm, graph = recon_main
    payload = _run_graphql(tls_server, GRAPHQL_VERIFY_SSL=False)
    # Every guessed path got the server's answer (not JSON, so not GraphQL):
    # the host was checked, and never skipped as down.
    errors = [data.get("error") for data in payload["endpoints"].values()]
    assert errors == ["Response is not valid JSON"] * len(GUESSED)
    assert cb.host_health.unreachable() == []
    rm._prune_recon_findings()
    assert "localhost" not in graph.keep_hosts_for("graphql_scan")
    assert "localhost" not in graph.keep_hosts_for("graphql_cop")
    assert [g for g in cb.coverage_report().gaps if g["source"] == "graphql_scan"] == []


@pytest.mark.parametrize("mode", ["eof", "reset"])
def test_a_handshake_failure_is_a_request_error_not_a_refused_certificate(self_signed, mode):
    srv = _Server(mode, self_signed)
    try:
        # The URL is target data: spelling the OpenSSL reason in it changes nothing.
        _ok, _schema, error = introspection.test_introspection(
            srv.url("/CERTIFICATE_VERIFY_FAILED/graphql"), {}, 5, verify_ssl=True)
    finally:
        srv.close()
    assert error.startswith("Request error")
    assert not error.startswith(introspection.CERT_REFUSED)

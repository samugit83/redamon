"""R-48: a certificate the client refuses is not a dead host.

circuit_breaker._failure_kind decides what counts against HostHealth, which
every module of the run shares. A self-signed, expired or mismatched
certificate means the host answered the TLS handshake, so it must never mark
the host down for the other modules; a handshake the host reset or cut short
still counts.

The certificate and handshake cases run against a real local TLS server and
the real requests / urllib stacks, so the exception chains are the ones a scan
sees. The conftest autouse fixture resets HostHealth around every test.
"""
from __future__ import annotations

import shutil
import socket
import ssl
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.request

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

    def _answer(self, conn):
        if self.mode == "tls":
            with self.ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(65536)
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

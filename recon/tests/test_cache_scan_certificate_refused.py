"""The cache scan names a refused TLS certificate, never "no answer" (R-48).

With WEB_CACHE_POISON_VERIFY_SSL on (the default), a host with a self-signed,
expired or mismatched certificate answers the handshake, and the cache oracle
refuses its certificate. The oracle reported that as it reports a stalled or
refused connection, so the scan noted the host "not fully tested (no answer)":
the coverage record read a live host as one that never answered. The host is
still kept for the cache scan's own sources (nothing on it was tested), but
the gap now says the certificate was refused, as GraphQL's does
(circuit_breaker.is_certificate_refused, the R-48 rule). A handshake the host
cut short is no certificate refusal and still reads "no answer".

A real loopback TLS server and the real requests stack, so the exception
chain is the one a scan sees. WCVS is stubbed.
"""
from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.cache_scan import scanner  # noqa: E402
from recon.helpers import circuit_breaker as cb  # noqa: E402

SETTINGS = {"WEB_CACHE_POISON_ENABLED": True, "WEB_CACHE_POISON_CONFIRM_WORKERS": 1,
            "WEB_CACHE_POISON_BEHAVIORAL_ORACLE": False, "WEB_CACHE_POISON_TIMEOUT": 1800,
            "WEB_CACHE_POISON_TIMEOUT_PER_REQ": 3}
CERT_REASON = "TLS certificate refused (WEB_CACHE_POISON_VERIFY_SSL on)"


@pytest.fixture(scope="module")
def self_signed(tmp_path_factory):
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not in this image")
    d = tmp_path_factory.mktemp("cache-cert")
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
    """tls: completes the handshake with the self-signed certificate and
    answers 200; eof: reads the ClientHello and closes (handshake cut short)."""

    def __init__(self, mode, cert=None):
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

    def url(self, path="/"):
        return f"https://localhost:{self.port}{path}"

    def _run(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            conn.settimeout(2)
            try:
                if self.mode == "tls":
                    with self.ctx.wrap_socket(conn, server_side=True) as tls:
                        data = b""
                        while b"\r\n\r\n" not in data:
                            chunk = tls.recv(65536)
                            if not chunk:
                                break
                            data += chunk
                        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                    b"Connection: close\r\n\r\nok")
                else:
                    conn.recv(65536)
                    time.sleep(0.05)
                    conn.shutdown(socket.SHUT_RDWR)
            except Exception:  # noqa: BLE001 - a client that hangs up is expected
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self):
        self._stop.set()
        self.sock.close()
        self._thread.join(timeout=2)


@pytest.fixture
def server(request, self_signed):
    srv = _Server(request.param, self_signed)
    yield srv
    srv.close()


@pytest.fixture(autouse=True)
def _fresh_run(monkeypatch):
    cb.reset_registry()
    monkeypatch.setattr(scanner.wcvs_runner, "run_wcvs", lambda urls, s, **k: [])
    yield
    cb.reset_registry()


def _recon(url):
    return {
        "domain": "localhost",
        "dns": {"domain": {}, "subdomains": {}},
        "http_probe": {"by_url": {url: {"url": url, "status_code": 200}}},
        "resource_enum": {"by_base_url": {}, "discovered_urls": []},
        "metadata": {"include_root_domain": True},
    }


def _cache_gap():
    gap, = [g for g in cb.coverage_report().gaps if g["source"] == "cache_poisoning"]
    assert gap["module"] == "cache_scan"
    return gap


@pytest.mark.parametrize("server", ["tls"], indirect=True)
def test_a_refused_certificate_is_named_and_the_host_kept_for_the_cache_scan_alone(server, capsys):
    url = server.url()
    out = scanner.run_cache_scan(_recon(url), SETTINGS)

    entry = out["cache_scan"]["by_target"][url]
    assert entry["unchecked"] == CERT_REASON
    assert entry["oracle"]["certificate_refused"] is True
    gap = _cache_gap()
    assert gap["reason"] == CERT_REASON
    assert "no answer" not in gap["reason"]
    # Nothing on the host was tested: the cache scan keeps its findings there,
    # for its own sources only, and no module reads the host as down.
    report = cb.coverage_report()
    assert report.keep_hostnames("cache_poisoning") == ("localhost",)
    assert report.keep_hostnames("wcvs") == ("localhost",)
    assert report.keep_hostnames("nuclei") == ()
    assert cb.host_health.unreachable() == []
    assert f"not fully tested ({CERT_REASON})" in capsys.readouterr().out


@pytest.mark.parametrize("server", ["tls"], indirect=True)
@pytest.mark.filterwarnings("ignore::urllib3.exceptions.InsecureRequestWarning")
def test_with_verify_off_the_same_host_is_tested_and_notes_nothing(server):
    url = server.url()
    out = scanner.run_cache_scan(_recon(url), {**SETTINGS, "WEB_CACHE_POISON_VERIFY_SSL": False})

    entry = out["cache_scan"]["by_target"][url]
    assert "unchecked" not in entry
    assert entry["oracle"].get("certificate_refused") is None
    assert not cb.coverage_report().degraded


@pytest.mark.parametrize("server", ["eof"], indirect=True)
def test_a_handshake_cut_short_still_reads_no_answer(server):
    url = server.url()
    out = scanner.run_cache_scan(_recon(url), SETTINGS)

    entry = out["cache_scan"]["by_target"][url]
    assert entry["unchecked"] == "no answer"
    assert entry["oracle"]["certificate_refused"] is False
    assert _cache_gap()["reason"] == "no answer"

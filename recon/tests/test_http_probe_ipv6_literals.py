"""An IPv6 literal survives http_probe's URL helpers and banner grab (L-5).

`url_port` read `https://[2001:db8::10]:8443` as port 443, so the custom-port
guard dropped it; `extract_host_from_url` cut the host at its first colon
(`[2001`); and the banner grab opened an AF_INET socket, which cannot reach an
IPv6 address. Documentation addresses only; the socket tests use loopback.
"""
from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path
from unittest import mock

import pytest

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.main_recon_modules import http_probe as hp  # noqa: E402

V6 = "2001:db8::10"


@pytest.mark.parametrize("url, port", [
    (f"https://[{V6}]:8443", 8443),
    (f"https://[{V6}]", 443),
    (f"http://[{V6}]/login", 80),
    (f"http://[{V6}]:8080/a?b=1", 8080),
    ("https://www.example.com:8443/x", 8443),
    ("HTTPS://www.example.com", 443),
    ("http://192.0.2.10:3000", 3000),
    ("  http://www.example.com  ", 80),
])
def test_url_port_reads_the_port_of_every_host_form(url, port):
    assert hp.url_port(url) == port


@pytest.mark.parametrize("url", [
    "", "www.example.com", "ftp://www.example.com", "http:///path",
    "http://www.example.com:notaport", f"https://[{V6}:8443",
])
def test_url_port_refuses_what_it_cannot_parse(url):
    assert hp.url_port(url) == -1


def test_an_ipv6_url_survives_the_custom_port_guard():
    urls = [f"https://[{V6}]:8443", f"http://[{V6}]:9000", "https://www.example.com:8443"]
    kept, dropped, ports = hp.apply_custom_port_scope(urls, {"NAABU_CUSTOM_PORTS": "8443"})
    assert kept == [f"https://[{V6}]:8443", "https://www.example.com:8443"]
    assert dropped == 1 and ports == {8443}


@pytest.mark.parametrize("url, host", [
    (f"https://[{V6}]:8443/x", V6),
    (f"http://[{V6}]", V6),
    ("https://www.example.com:8443/x", "www.example.com"),
    ("https://Mixed.Example.com/x", "Mixed.Example.com"),
    ("http://user:secret@www.example.com:8080/", "www.example.com"),
    ("http://192.0.2.10", "192.0.2.10"),
    ("", ""),
    (None, ""),
    (f"https://[{V6}:8443", ""),
])
def test_extract_host_from_url_handles_every_host_form(url, host):
    assert hp.extract_host_from_url(url) == host


def test_an_ipv6_result_is_keyed_by_its_bare_address(tmp_path):
    out = tmp_path / "httpx.jsonl"
    url = f"https://[{V6}]:8443"
    out.write_text(f'{{"url": "{url}", "input": "{url}", "status_code": 200, "host": "{V6}"}}\n')
    res = hp.parse_httpx_output(str(out), root_domain="example.com",
                                allowed_hosts=[V6], exact=True)
    assert res["by_url"][url]["host"] == V6
    assert V6 in res["by_host"]


def test_the_banner_grab_connects_to_an_ipv6_address():
    conn = mock.MagicMock()
    conn.recv.return_value = b"SSH-2.0-OpenSSH_9.6\r\n"
    with mock.patch.object(hp.socket, "create_connection", return_value=conn) as create:
        banner = hp.grab_banner(V6, 22, timeout=2.0)
    create.assert_called_once_with((V6, 22), timeout=2.0)
    assert banner == "SSH-2.0-OpenSSH_9.6"
    conn.close.assert_called_once()


def _serve_once(family, address, greeting):
    try:
        srv = socket.socket(family, socket.SOCK_STREAM)
        srv.bind((address, 0))
    except OSError:
        pytest.skip(f"no {address} loopback in this container")
    srv.listen(1)
    srv.settimeout(5)

    def accept():
        try:
            conn, _ = srv.accept()
            conn.sendall(greeting)
            conn.close()
        except OSError:
            pass
        finally:
            srv.close()

    threading.Thread(target=accept, daemon=True).start()
    return srv.getsockname()[1]


@pytest.mark.parametrize("family, address", [
    (socket.AF_INET, "127.0.0.1"),
    (socket.AF_INET6, "::1"),
], ids=["ipv4", "ipv6"])
def test_the_banner_grab_reads_a_real_greeting(family, address):
    port = _serve_once(family, address, b"220 mail.example.com ESMTP Postfix\r\n")
    assert hp.grab_banner(address, port, timeout=3.0) == "220 mail.example.com ESMTP Postfix"

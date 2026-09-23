"""Exercise the real requests/urllib3 stream without contacting any target."""
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from recon.helpers.openapi.fetch import DocumentError, Fetcher


def test_trickling_response_obeys_total_fetch_deadline():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            try:
                for _ in range(100):
                    self.wfile.write(b'x')
                    self.wfile.flush()
                    time.sleep(0.1)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    fetcher = Fetcher(timeout=1)
    base = f'http://127.0.0.1:{server.server_port}'
    started = time.monotonic()
    try:
        with pytest.raises(DocumentError, match='deadline'):
            fetcher.fetch(base + '/spec', {}, base)
        assert time.monotonic() - started < 4
    finally:
        fetcher.close()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_document_download_uses_capture_proxy(monkeypatch):
    from helpers import proxy_routing

    observed = []

    class Proxy(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            observed.append((self.path, self.headers.get('X-Redamon-Ctx')))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"openapi":"3.1.0"}')

    server = ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    monkeypatch.setattr(proxy_routing, 'get_capture_routing',
                        lambda tool: (f'http://127.0.0.1:{server.server_port}', 'fixture-tag'))
    fetcher = Fetcher()
    try:
        url, body = fetcher.fetch('http://api.example.test/spec', {}, 'http://api.example.test')
        assert url == 'http://api.example.test/spec'
        assert body == '{"openapi":"3.1.0"}'
        assert observed == [('http://api.example.test/spec', 'fixture-tag')]
    finally:
        fetcher.close()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

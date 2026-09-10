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

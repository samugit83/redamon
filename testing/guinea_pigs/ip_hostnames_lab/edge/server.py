#!/usr/bin/env python3
"""192.88.98.40: a CDN-like edge, the way a scanner sees a Cloudflare edge.

    python3 server.py --certs /certs --logs /logs [--http-port 80] [--https-port 443]

Stdlib only (python:3.12-slim). Every answer carries `Server: cloudflare` and a
`cf-ray` header, and the certificate is issued by a lab CA named after
Cloudflare (recon's cdn_from_certificate keys on the issuer). The names it
fronts (cdn1.example-a.test, cdn2.example-b.test) answer VHOST=<name>; any other
Host, an IP literal included, gets Cloudflare's "error code: 1003" 403. Recon
only treats .40 as a shared edge through REDAMON_LAB_CDN_PREFIXES, a lab-only
orchestrator hook: no real CDN publishes this prefix.

nginx cannot replace its own Server header without an extra module, hence
Python here. Each request is one JSON line in /logs/hits.jsonl, with the keys
of the nginx hosts' log (nginx/common.conf).
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONTAINER = "iphn-edge"
FRONTED = {"cdn1.example-a.test", "cdn2.example-b.test"}
_LOCK = threading.Lock()


def make_handler(log_path: str, scheme: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "cloudflare"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def version_string(self) -> str:
            return "cloudflare"

        def log_message(self, fmt, *args):
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

        def _log(self, status: int, vhost: str) -> None:
            line = {
                "ts": round(time.time(), 3), "container": CONTAINER, "client": self.client_address[0],
                "method": self.command, "scheme": scheme, "host": self.headers.get("Host", ""),
                "sni": getattr(self.connection, "lab_sni", None) or "", "vhost": vhost,
                "uri": self.path, "status": status, "ua": self.headers.get("User-Agent", ""),
            }
            with _LOCK, open(log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(line) + "\n")

        def _answer(self):
            host = (self.headers.get("Host") or "").split(":", 1)[0].strip().lower().rstrip(".")
            if host in FRONTED:
                status, body, vhost = 200, f"VHOST={host}\n", host
            else:
                status, body, vhost = 403, "error code: 1003\n", "_"
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("cf-ray", f"{uuid.uuid4().hex[:16]}-LAB")
            self.send_header("cf-cache-status", "DYNAMIC")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
            self._log(status, vhost)

        do_GET = do_POST = do_HEAD = do_OPTIONS = _answer

    return Handler


class TLSServer(ThreadingHTTPServer):
    """The handshake runs in the request thread, so a client that connects and
    never speaks TLS (a SYN-and-hold scanner) cannot block the accept loop."""

    daemon_threads = True

    def __init__(self, addr, handler, ctx: ssl.SSLContext):
        super().__init__(addr, handler)
        self.ctx = ctx

    def finish_request(self, request, client_address):
        request.settimeout(10)
        try:
            tls = self.ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        self.RequestHandlerClass(tls, client_address, self)


def tls_context(certs: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(certs, "edge.crt"), os.path.join(certs, "edge.key"))

    def remember_sni(sock, server_name, _ctx):
        sock.lab_sni = server_name

    ctx.sni_callback = remember_sni
    return ctx


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--certs", default="/certs")
    ap.add_argument("--logs", default="/logs")
    ap.add_argument("--http-port", type=int, default=80)
    ap.add_argument("--https-port", type=int, default=443)
    a = ap.parse_args()
    log_path = os.path.join(a.logs, "hits.jsonl")
    plain = ThreadingHTTPServer(("0.0.0.0", a.http_port), make_handler(log_path, "http"))
    plain.daemon_threads = True
    secure = TLSServer(("0.0.0.0", a.https_port), make_handler(log_path, "https"), tls_context(a.certs))
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    print(f"edge: HTTP {a.http_port}, HTTPS {a.https_port}, fronting {sorted(FRONTED)}", flush=True)
    secure.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

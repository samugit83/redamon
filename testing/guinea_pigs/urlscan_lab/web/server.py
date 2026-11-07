#!/usr/bin/env python3
"""One urlscan-lab web host: HTTP on 80, HTTPS on 443 with a certificate per SNI name.

    python3 server.py --site /site/site.json --certs /certs --logs /logs

Stdlib only (python:3.12-slim). The site (virtual hosts, routes, certificates)
comes from gen_lab.py's site.json, so this file holds no content. Every request
is appended to /logs/hits.jsonl: the raw request target, Host, SNI, method,
status. The validator reads those lines for the "must receive 0 requests" and
"was requested with HEAD" checks; the log has no HTTP surface, since a scan
would discover one.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

_LOCK = threading.Lock()


class Site:
    def __init__(self, spec: dict, certs_dir: str):
        self.container = spec.get("container", spec.get("role", "web"))
        self.via_edge_server = spec.get("via_edge_server")
        self.vhosts: dict[str, dict] = {}
        for vhost in spec["vhosts"]:
            for name in vhost["names"]:
                self.vhosts[name.lower()] = vhost
        self.default = self.vhosts.get("_default") or spec["vhosts"][0]
        self.certs_dir = certs_dir
        self.default_cert = spec.get("default_cert") or self.default.get("cert")

    def vhost_for(self, host: str | None) -> dict:
        name = (host or "").split(":", 1)[0].strip().lower().rstrip(".")
        return self.vhosts.get(name, self.default)

    def tls_context(self) -> ssl.SSLContext:
        contexts: dict[str, ssl.SSLContext] = {}

        def load(cert: str) -> ssl.SSLContext:
            if cert not in contexts:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(os.path.join(self.certs_dir, f"{cert}.crt"),
                                    os.path.join(self.certs_dir, f"{cert}.key"))
                contexts[cert] = ctx
            return contexts[cert]

        default = load(self.default_cert)
        by_name = {name: load(v["cert"]) for name, v in self.vhosts.items() if name != "_default"}

        def pick(sock, server_name, _ctx):
            sock.lab_sni = server_name
            if server_name and server_name.lower() in by_name:
                sock.context = by_name[server_name.lower()]

        default.sni_callback = pick
        return default


def route_for(vhost: dict, path: str) -> dict | None:
    for route in vhost["routes"]:
        if route.get("match", "exact") == "exact" and route["path"] == path:
            return route
    best = None
    for route in vhost["routes"]:
        if route.get("match") == "prefix" and path.startswith(route["path"]):
            if best is None or len(route["path"]) > len(best["path"]):
                best = route
    return best


def make_handler(site: Site, log_path: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "LabWeb/1.0"
        sys_version = ""
        scheme = "http"

        def log_message(self, fmt, *args):
            pass

        def _log(self, status: int) -> None:
            parts = urlsplit(self.path)
            entry = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "container": site.container, "client": self.client_address[0],
                "method": self.command, "scheme": self.scheme,
                "host": self.headers.get("Host", ""), "sni": getattr(self.connection, "lab_sni", None),
                "uri": self.path, "path": parts.path, "query": parts.query, "status": status,
                "ua": self.headers.get("User-Agent", ""), "range": self.headers.get("Range"),
                "via_edge": bool(self.headers.get("X-Lab-Via-Edge")),
            }
            with _LOCK, open(log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")

        def _answer(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(min(length, 1 << 20))
            vhost = site.vhost_for(self.headers.get("Host") or getattr(self.connection, "lab_sni", None))
            path = urlsplit(self.path).path or "/"
            route = route_for(vhost, path)
            if route is None:
                status, ctype = 404, "text/html; charset=utf-8"
                body = b"<!doctype html><html><head><title>404 Not Found</title></head><body>Not Found</body></html>\n"
                headers = {}
            else:
                status, ctype = route["status"], route["ctype"]
                body = base64.b64decode(route["body_b64"]) if "body_b64" in route else route["body"].encode()
                headers = route.get("headers") or {}
            server = vhost.get("server", "LabWeb/1.0")
            # The edge forwards the origin's Server header: the origin answers
            # as the CDN only when the edge relayed the request.
            if site.via_edge_server and self.headers.get("X-Lab-Via-Edge"):
                server = site.via_edge_server
            self.send_response_only(status)
            self.send_header("Server", server)
            self.send_header("Date", self.date_time_string())
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            self._log(status)

        do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _answer

    return Handler


class LabHTTPServer(ThreadingHTTPServer):
    # socketserver's default listen backlog is 5: httpx's bursts (44 threads,
    # ten JARM handshakes per URL) overflowed it and whole hosts went missing
    # from a scan at random. A real server queues far more.
    request_queue_size = 256


class TLSServer(LabHTTPServer):
    """The handshake runs in the request's own thread, so a slow or broken
    client never blocks the accept loop."""

    def __init__(self, addr, handler, ctx: ssl.SSLContext):
        super().__init__(addr, handler)
        self.ctx = ctx

    def finish_request(self, request, client_address):
        request.settimeout(15)
        try:
            tls = self.ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            self.RequestHandlerClass(tls, client_address, self)
        finally:
            try:
                tls.close()
            except OSError:
                pass


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--site", default="/site/site.json")
    ap.add_argument("--certs", default="/certs")
    ap.add_argument("--logs", default="/logs")
    ap.add_argument("--http-port", type=int, default=80)
    ap.add_argument("--https-port", type=int, default=443)
    a = ap.parse_args()
    with open(a.site, encoding="utf-8") as fh:
        site = Site(json.load(fh), a.certs)
    log_path = os.path.join(a.logs, "hits.jsonl")
    http_handler = make_handler(site, log_path)

    class HttpsHandler(http_handler):
        scheme = "https"

    plain = LabHTTPServer(("0.0.0.0", a.http_port), http_handler)
    secure = TLSServer(("0.0.0.0", a.https_port), HttpsHandler, site.tls_context())
    for srv in (plain, secure):
        srv.daemon_threads = True
    threading.Thread(target=secure.serve_forever, daemon=True).start()
    print(f"{site.container}: {len(site.vhosts)} names on :{a.http_port} and :{a.https_port}", flush=True)
    plain.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

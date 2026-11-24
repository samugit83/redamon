"""
The egress guard on the wire: a real ``mitmdump -s capture_addon.py``, started the
way the orchestrator starts it (lazy connections, raw TCP off), on loopback only.

127.0.0.2 stands for a refused address (it is the proxy's always-on denylist,
``CAPTURE_BLOCKED_IPS``, as the per-user sandbox pool is in production) and
127.0.0.1 for a target the policy allows (loopback and private are relaxed, as for
a lab). Each probe tries to reach 127.0.0.2 by naming an allowed host in the
``Host`` header, through a CONNECT tunnel, through mitmproxy's DNS layer, or with
a body large enough to be streamed before the request hook; the refused
listeners count every connection they accept, so "refused" means nothing
reached them. A Host header naming a hard-guardrail domain is refused by name,
before a large or chunked body streams and in an HTTP/2 request beside its
`:authority`; any other name in it (a vhost probe) reaches the allowed target.
A refused client's connection is closed, not left open. One client's names that
never answer delay neither an IP target nor another client's lookups.

Needs only the mitmdump binary of this section's image; skips without it.
"""
from __future__ import annotations

import datetime
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
ADDON = ROOT / "capture_addon.py"
REFUSED_IP, ALLOWED_IP = "127.0.0.2", "127.0.0.1"
VICTIM_MARK, HONEST_MARK = b"g1-victim-reached", b"g1-honest-reached"
IO_TIMEOUT = 15
LARGE_BODY = 6_000_000  # over the proxy's stream_large_bodies=5m


def _free_port(host):
    with socket.socket() as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def _server(host, port, mark, hits, posts=None):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(mark)))
            self.end_headers()
            self.wfile.write(mark)

        def do_POST(self):
            # Records what arrived: the body's size and every header name.
            left, size = int(self.headers.get("Content-Length") or 0), 0
            while left > 0:
                chunk = self.rfile.read(min(left, 1 << 16))
                if not chunk:
                    break
                left, size = left - len(chunk), size + len(chunk)
            if posts is not None:
                posts.append((size, [k.lower() for k in self.headers.keys()]))
            self.do_GET()

        def log_message(self, *_):
            pass

    class Counting(ThreadingHTTPServer):
        daemon_threads = True

        def get_request(self):
            conn = super().get_request()
            hits.append(conn[1])
            return conn

    srv = Counting((host, port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _tcp_listener(host, port, hits):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(8)

    def accept():
        while True:
            try:
                c, peer = s.accept()
            except OSError:
                return
            hits.append(peer)
            c.close()

    threading.Thread(target=accept, daemon=True).start()
    return s


def _read_all(sock):
    chunks = []
    try:
        while True:
            b = sock.recv(65536)
            if not b:
                break
            chunks.append(b)
    except OSError:  # a timeout, or the proxy reset a request it killed
        pass
    return b"".join(chunks)


def _status(raw):
    try:
        return int(raw.split(b"\r\n", 1)[0].split()[1])
    except (IndexError, ValueError):
        return None


class _ProxyOnTheWire(unittest.TestCase):
    proc = None
    MITM_SETS = ()  # extra `--set` options beyond the orchestrator's
    SCRIPTS = ()    # (file name, source) of extra addon scripts loaded after capture_addon.py
    OTHER_NETWORK = None  # a second loopback address the proxy also listens on

    @classmethod
    def setUpClass(cls):
        mitmdump = shutil.which("mitmdump")
        if not mitmdump:
            raise unittest.SkipTest("mitmdump is not installed (this test runs in the redamon-capture-proxy image)")
        cls.tmp = tempfile.mkdtemp(prefix="egress-wire-")
        cls.victim_hits, cls.honest_hits, cls.dns_hits, cls.honest_posts = [], [], [], []
        cls.servers, cls.sockets = [], []
        try:
            cls.victim_port = _free_port(REFUSED_IP)
            cls.servers.append(_server(REFUSED_IP, cls.victim_port, VICTIM_MARK, cls.victim_hits))
            cls.honest_port = _free_port(ALLOWED_IP)
            cls.servers.append(_server(ALLOWED_IP, cls.honest_port, HONEST_MARK, cls.honest_hits, cls.honest_posts))
            try:
                cls.sockets.append(_tcp_listener(REFUSED_IP, 5353, cls.dns_hits))
                cls.dns_ready = True
            except OSError:
                cls.dns_ready = False
            cls.start_upstreams()

            cls.spool = spool = os.path.join(cls.tmp, "spool")
            os.makedirs(spool)
            with open(os.path.join(spool, ".capture-config.json"), "w") as fh:
                json.dump({"egress": {"block_private": False, "block_loopback": False}}, fh)
            # The image bundles hard_guardrail.py next to the addon; do the same.
            lib = os.path.join(cls.tmp, "lib")
            os.makedirs(lib)
            shutil.copy(REPO / "recon_orchestrator" / "hard_guardrail.py", lib)
            env = dict(os.environ)
            env.update({
                "CAPTURE_SPOOL_DIR": spool,
                "CAPTURE_BODIES_DIR": os.path.join(cls.tmp, "bodies"),
                "CAPTURE_BLOCKED_IPS": f"{REFUSED_IP}/32",
                "PYTHONPATH": os.pathsep.join(p for p in (str(ROOT), str(REPO), lib, env.get("PYTHONPATH", "")) if p),
            })
            cls.proxy_port = _free_port(ALLOWED_IP)
            cls.log = open(os.path.join(cls.tmp, "mitmdump.log"), "wb")
            argv = [mitmdump, "--set", f"confdir={os.path.join(cls.tmp, 'ca')}",
                    "--set", "connection_strategy=lazy", "--set", "stream_large_bodies=5m",
                    "--set", "rawtcp=false", "-s", str(ADDON)]
            if cls.OTHER_NETWORK:
                # A second listening address stands for the proxy's address on
                # another network: the guard tells networks apart by it.
                cls.other_port = _free_port(cls.OTHER_NETWORK)
                argv += ["--mode", f"regular@{ALLOWED_IP}:{cls.proxy_port}",
                         "--mode", f"regular@{cls.OTHER_NETWORK}:{cls.other_port}"]
            else:
                argv += ["--listen-host", ALLOWED_IP, "--listen-port", str(cls.proxy_port)]
            for option in cls.MITM_SETS:
                argv += ["--set", option]
            for name, source in cls.SCRIPTS:
                path = os.path.join(cls.tmp, name)
                with open(path, "w") as fh:
                    fh.write(source)
                argv += ["-s", path]
            cls.proc = subprocess.Popen(argv, env=env, stdout=cls.log, stderr=subprocess.STDOUT)
            cls._wait_for_the_guard()
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def start_upstreams(cls):
        pass

    @classmethod
    def _wait_for_the_guard(cls):
        # Ready once the addon answers: an honest request to the refused address is
        # refused by every version of the guard.
        end = time.time() + 60
        while time.time() < end:
            if cls.proc.poll() is not None:
                raise AssertionError(f"mitmdump exited ({cls.proc.returncode}): {cls._log_tail()}")
            try:
                raw = cls._absolute(REFUSED_IP, cls.victim_port, f"{REFUSED_IP}:{cls.victim_port}")
                if _status(raw) == 403 and b"egress guard" in raw:
                    del cls.victim_hits[:]
                    return
            except OSError:
                pass
            time.sleep(0.5)
        raise AssertionError(f"the capture proxy never answered: {cls._log_tail()}")

    @classmethod
    def _log_tail(cls):
        try:
            cls.log.flush()
            with open(cls.log.name, "rb") as fh:
                return fh.read()[-2000:].decode("utf-8", "replace")
        except (OSError, AttributeError):
            return ""

    @classmethod
    def tearDownClass(cls):
        if cls.proc is not None:
            cls.proc.terminate()
            try:
                cls.proc.wait(10)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
                cls.proc.wait(10)
        for srv in getattr(cls, "servers", []):
            srv.shutdown()
            srv.server_close()
        for s in getattr(cls, "sockets", []):
            s.close()
        if getattr(cls, "log", None):
            cls.log.close()
        shutil.rmtree(getattr(cls, "tmp", ""), ignore_errors=True)

    @classmethod
    def _proxy(cls, source=ALLOWED_IP, other_network=False):
        listener = (cls.OTHER_NETWORK, cls.other_port) if other_network else (ALLOWED_IP, cls.proxy_port)
        s = socket.create_connection(listener, timeout=IO_TIMEOUT, source_address=(source, 0))
        s.settimeout(IO_TIMEOUT)
        return s

    @classmethod
    def _absolute(cls, ip, port, host_header, source=ALLOWED_IP, other_network=False, extra=""):
        with cls._proxy(source, other_network) as s:
            s.sendall(f"GET http://{ip}:{port}/ HTTP/1.1\r\nHost: {host_header}\r\n{extra}"
                      f"Connection: close\r\n\r\n".encode())
            return _read_all(s)

    def _tunnel(self, ip, port):
        s = self._proxy()
        s.sendall(f"CONNECT {ip}:{port} HTTP/1.1\r\nHost: {ip}:{port}\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head:
            b = s.recv(4096)
            if not b:
                break
            head += b
        return s, head

    def setUp(self):
        del self.victim_hits[:], self.dns_hits[:]

    def assertNothingReached(self, hits, raw):
        self.assertEqual(hits, [], f"the refused address took a connection; the proxy answered {raw[:200]!r}")

    def assertGuardRefused(self, raw):
        refused = (_status(raw) == 403 and b"egress guard" in raw) or \
                  (_status(raw) == 502 and b"Connection killed" in raw and b"egress guard" in raw)
        self.assertTrue(refused, f"not the egress guard's refusal: {raw[:300]!r}")

    @classmethod
    def _proxy_rss_mb(cls):
        with open(f"/proc/{cls.proc.pid}/status") as fh:
            return int(next(line.split()[1] for line in fh if line.startswith("VmRSS"))) // 1024

    def _push(self, s, megabytes, chunked=False):
        """Send `megabytes` of filler, as a chunked body or raw; stops when the proxy closes."""
        piece, sent = b"x" * (1 << 16), 0
        try:
            while sent < megabytes << 20:
                s.sendall(b"%x\r\n%s\r\n" % (len(piece), piece) if chunked else piece)
                sent += len(piece)
        except OSError:
            pass
        return sent

    def _large_post(self, ip, port, tag, full=False, host_headers=None, chunked=False, other_network=False):
        host_lines = "".join(f"Host: {h}\r\n" for h in (host_headers or [f"{ip}:{port}"]))
        framing = "Transfer-Encoding: chunked" if chunked else f"Content-Length: {LARGE_BODY}"
        with self._proxy(other_network=other_network) as s:
            s.sendall(f"POST http://{ip}:{port}/ HTTP/1.1\r\n{host_lines}X-Redamon-Ctx: {tag}\r\n"
                      f"{framing}\r\nConnection: close\r\n\r\n".encode())
            chunk, sent = b"x" * (1 << 16), 0
            try:
                while sent < (LARGE_BODY if full else 1 << 18):
                    piece = chunk[:LARGE_BODY - sent]
                    s.sendall(b"%x\r\n%s\r\n" % (len(piece), piece) if chunked else piece)
                    sent += len(piece)
                if chunked:
                    s.sendall(b"0\r\n\r\n")
            except OSError:
                pass  # the proxy may answer and close before the body is in
            return _read_all(s)

    def _large_post_closed_promptly(self, ip, port, tag, **post):
        # A refusal closes the client while it is still sending. mitmproxy 11.1
        # can leave that socket open, read by no one, until the client times out.
        started = time.monotonic()
        raw = self._large_post(ip, port, tag, **post)
        took = time.monotonic() - started
        self.assertLess(took, IO_TIMEOUT / 3, f"the proxy left the refused client's connection open ({took:.1f} s)")
        return raw

    def _spool_records(self, tag, wait=10.0):
        """The spool records carrying `tag`, once at least one is in (the writer
        thread publishes them a moment after the hook)."""
        end = time.time() + wait
        while True:
            found = []
            for name in os.listdir(self.spool):
                if name.endswith(".json"):
                    with open(os.path.join(self.spool, name)) as fh:
                        rec = json.load(fh)
                    if rec.get("ctx_token") == tag:
                        found.append(rec)
            if found or time.time() >= end:
                return found
            time.sleep(0.2)

    def _blocked_record(self, method, ip, port):
        end = time.time() + 10
        while time.time() < end:
            for name in os.listdir(self.spool):
                if name.endswith(".json"):
                    with open(os.path.join(self.spool, name)) as fh:
                        rec = json.load(fh)
                    if rec.get("blocked") and (rec.get("method"), rec.get("host"), rec.get("port")) == (method, ip, port):
                        return rec
            time.sleep(0.2)
        self.fail(f"no blocked {method} record for {ip}:{port} in the spool")


class EgressGuardOnTheWire(_ProxyOnTheWire):
    def test_honest_request_reaches_an_allowed_target(self):
        raw = self._absolute(ALLOWED_IP, self.honest_port, f"{ALLOWED_IP}:{self.honest_port}")
        self.assertEqual(_status(raw), 200, raw[:300])
        self.assertIn(HONEST_MARK, raw)

    def test_vhost_probe_of_an_allowed_target_passes(self):
        # A Host naming another host (here the refused address) is the tester's
        # business: the request still goes to its real, allowed target.
        raw = self._absolute(ALLOWED_IP, self.honest_port, f"{REFUSED_IP}:{self.victim_port}")
        self.assertEqual(_status(raw), 200, raw[:300])
        self.assertIn(HONEST_MARK, raw)
        self.assertNothingReached(self.victim_hits, raw)

    def test_spoofed_host_does_not_reach_a_refused_address(self):
        raw = self._absolute(REFUSED_IP, self.victim_port, f"{ALLOWED_IP}:{self.honest_port}")
        self.assertNotIn(VICTIM_MARK, raw)
        self.assertNothingReached(self.victim_hits, raw)
        self.assertEqual(_status(raw), 403, raw[:300])

    def test_connect_then_spoofed_host_does_not_reach_a_refused_address(self):
        s, head = self._tunnel(REFUSED_IP, self.victim_port)
        with s:
            if _status(head) == 200:
                s.sendall(f"GET / HTTP/1.1\r\nHost: {ALLOWED_IP}\r\nConnection: close\r\n\r\n".encode())
                raw = _read_all(s)
            else:
                raw = head
        self.assertNotIn(VICTIM_MARK, raw)
        self.assertNothingReached(self.victim_hits, raw)
        self.assertGuardRefused(raw)

    def test_large_body_does_not_reach_a_refused_address(self):
        # stream_large_bodies sends a body over 5 MB upstream before the request
        # hook runs: only the dial check stands between it and the target.
        raw = self._large_post_closed_promptly(REFUSED_IP, self.victim_port, "wire-tag-1")
        self.assertNothingReached(self.victim_hits, raw)
        self.assertGuardRefused(raw)
        record = self._blocked_record("POST", REFUSED_IP, self.victim_port)
        self.assertEqual(record["ctx_token"], "wire-tag-1")
        self.assertEqual(record["errorText"], "egress:internal-ip")

    def test_large_body_to_an_allowed_target_carries_no_tag(self):
        del self.honest_posts[:]
        raw = self._large_post(ALLOWED_IP, self.honest_port, "wire-tag-2", full=True)
        self.assertEqual(_status(raw), 200, raw[:300])
        self.assertEqual(len(self.honest_posts), 1, self.honest_posts)
        size, names = self.honest_posts[0]
        self.assertEqual(size, LARGE_BODY)
        self.assertNotIn("x-redamon-ctx", names)

    def test_hard_guardrail_name_in_the_host_header_is_refused(self):
        hits = len(self.honest_hits)
        raw = self._absolute(ALLOWED_IP, self.honest_port, "portal.rvtest.gov")
        self.assertEqual(_status(raw), 403, raw[:300])
        self.assertIn(b"egress guard", raw)
        self.assertEqual(len(self.honest_hits), hits, "the target took a connection")

    def assertRefusedByNameBeforeTheBody(self, tag, **post):
        # mitmproxy dials and streams a body over 5 MB (or a chunked one once
        # 5 MB are in) before the `request` hook: the name check must come first.
        hits = len(self.honest_hits)
        raw = self._large_post_closed_promptly(ALLOWED_IP, self.honest_port, tag, full=True, **post)
        self.assertEqual(len(self.honest_hits), hits, f"the target took the request; the proxy answered {raw[:200]!r}")
        self.assertNotIn(HONEST_MARK, raw)
        records = self._spool_records(tag)
        self.assertEqual([(r["blocked"], r["errorText"]) for r in records], [(True, "egress:hard-guardrail")])

    def test_large_body_naming_a_protected_domain_does_not_reach_the_target(self):
        self.assertRefusedByNameBeforeTheBody("wire-tag-gov-cl", host_headers=["portal.rvtest.gov"])

    def test_chunked_large_body_naming_a_protected_domain_does_not_reach_the_target(self):
        self.assertRefusedByNameBeforeTheBody("wire-tag-gov-chunked", host_headers=["portal.rvtest.gov"], chunked=True)

    def test_protected_domain_in_a_second_host_header_does_not_reach_the_target(self):
        self.assertRefusedByNameBeforeTheBody(
            "wire-tag-gov-second", host_headers=[f"{ALLOWED_IP}:{self.honest_port}", "portal.rvtest.gov"])

    def test_a_large_body_that_reached_its_target_is_recorded_as_captured(self):
        hits = len(self.honest_hits)
        raw = self._large_post(ALLOWED_IP, self.honest_port, "wire-tag-reached", full=True,
                               host_headers=["admin.example.com"])
        self.assertEqual(_status(raw), 200, raw[:300])
        self.assertEqual(len(self.honest_hits), hits + 1)
        records = self._spool_records("wire-tag-reached")
        self.assertEqual([(r["blocked"], r["statusCode"]) for r in records], [(False, 200)])

    def test_dns_layer_does_not_reach_a_refused_resolver(self):
        if not self.dns_ready:
            self.skipTest(f"{REFUSED_IP}:5353 is taken in this container")
        s, head = self._tunnel(REFUSED_IP, 5353)
        with s:
            self.assertEqual(_status(head), 200, head[:200])
            qname = b"".join(bytes([len(p)]) + p for p in b"example.com".split(b".")) + b"\x00"
            query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
            s.sendall(struct.pack("!H", len(query)) + query)
            raw = b""
            try:
                while len(raw) < 2 or len(raw) < 2 + struct.unpack("!H", raw[:2])[0]:
                    b = s.recv(4096)
                    if not b:
                        break
                    raw += b
            except socket.timeout:
                pass
            raw = raw[2:]
        self.assertNothingReached(self.dns_hits, raw)
        if len(raw) >= 4:
            self.assertEqual(raw[3] & 0x0F, 2, "the DNS layer did not answer SERVFAIL")


def _tls_context():
    """A self-signed server context that offers HTTP/1.1 only."""
    import ssl
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "upstream.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    folder = tempfile.mkdtemp(prefix="egress-wire-tls-")
    cert_path, key_path = os.path.join(folder, "c.pem"), os.path.join(folder, "k.pem")
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    ctx.set_alpn_protocols(["http/1.1"])
    shutil.rmtree(folder, ignore_errors=True)
    return ctx


def _tls_listener(host, port, serve_plain):
    """Accept TLS (HTTP/1.1 only) on host:port; serve_plain(conn) gets each wrapped connection."""
    import ssl
    ctx = _tls_context()
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(64)

    def serve(conn):
        try:
            serve_plain(ctx.wrap_socket(conn, server_side=True))
        except (OSError, ssl.SSLError):
            pass
        finally:
            conn.close()

    def accept():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=serve, args=(conn,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    return listener


def _tls_server(host, port, heads):
    """An HTTPS listener (self-signed, HTTP/1.1 only) that records every request
    head it gets; mitmproxy translates an HTTP/2 client's request for it."""
    import ssl
    ctx = _tls_context()

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(16)

    def serve(conn):
        try:
            conn = ctx.wrap_socket(conn, server_side=True)
            conn.settimeout(IO_TIMEOUT)
            buf = b""
            while b"\r\n\r\n" not in buf:
                data = conn.recv(65536)
                if not data:
                    return
                buf += data
            heads.append(buf.split(b"\r\n\r\n", 1)[0].decode("latin-1"))
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                         % (len(HONEST_MARK), HONEST_MARK))
        except (OSError, ssl.SSLError):
            pass
        finally:
            conn.close()

    def accept():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=serve, args=(conn,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    return listener


class Http2HostHeadersOnTheWire(_ProxyOnTheWire):
    """HTTP/2 inside a CONNECT tunnel: h2 checks `:authority` against the last
    Host header only, and mitmproxy forwards every Host header upstream (keeping
    Host, dropping `:authority`), so a protected name in an earlier Host header
    reached the target. ssl_insecure: the upstream's certificate is self-signed."""

    MITM_SETS = ("ssl_insecure=true",)

    @classmethod
    def start_upstreams(cls):
        try:
            import h2.connection  # noqa: F401  (a mitmproxy dependency)
        except ImportError:
            raise unittest.SkipTest("the h2 package is not installed")
        cls.tls_heads = []
        cls.tls_port = _free_port(ALLOWED_IP)
        cls.sockets.append(_tls_server(ALLOWED_IP, cls.tls_port, cls.tls_heads))

    def _h2_get(self, authority, host_headers=(), tag=None):
        import ssl
        import h2.config
        import h2.connection
        import h2.events

        s, head = self._tunnel(ALLOWED_IP, self.tls_port)
        self.assertEqual(_status(head), 200, head[:200])
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        t = ctx.wrap_socket(s, server_hostname="upstream.test")
        self.assertEqual(t.selected_alpn_protocol(), "h2")
        conn = h2.connection.H2Connection(h2.config.H2Configuration(
            client_side=True, validate_outbound_headers=False, normalize_outbound_headers=False,
            validate_inbound_headers=False))
        conn.initiate_connection()
        t.sendall(conn.data_to_send())
        headers = [(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", authority)]
        headers += [("host", h) for h in host_headers]
        if tag:
            headers.append(("x-redamon-ctx", tag))
        conn.send_headers(1, headers, end_stream=True)
        t.sendall(conn.data_to_send())
        status, body, end = None, b"", time.time() + IO_TIMEOUT
        try:
            while time.time() < end:
                data = t.recv(65536)
                if not data:
                    break
                events = conn.receive_data(data)
                for ev in events:
                    if isinstance(ev, h2.events.ResponseReceived):
                        status = dict(ev.headers).get(b":status", b"").decode()
                    elif isinstance(ev, h2.events.DataReceived):
                        body += ev.data
                        conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                t.sendall(conn.data_to_send())
                if any(isinstance(ev, (h2.events.StreamEnded, h2.events.StreamReset, h2.events.ConnectionTerminated))
                       for ev in events):
                    break
        except OSError:
            pass
        finally:
            t.close()
        return status, body

    def test_honest_http2_request_reaches_the_target(self):
        heads = len(self.tls_heads)
        status, body = self._h2_get(f"{ALLOWED_IP}:{self.tls_port}")
        self.assertEqual(status, "200")
        self.assertIn(HONEST_MARK, body)
        self.assertEqual(len(self.tls_heads), heads + 1)

    def test_protected_domain_in_an_http2_host_header_beside_the_authority_does_not_reach_the_target(self):
        heads = len(self.tls_heads)
        allowed = f"{ALLOWED_IP}:{self.tls_port}"
        status, body = self._h2_get(allowed, ["portal.rvtest.gov", allowed], tag="wire-tag-h2")
        self.assertEqual(self.tls_heads[heads:], [], f"the target got the request (client saw {status})")
        self.assertNotIn(HONEST_MARK, body)
        records = self._spool_records("wire-tag-h2")
        self.assertEqual([(r["blocked"], r["errorText"]) for r in records], [(True, "egress:hard-guardrail")])


SLOW_SECONDS, SLOWER_SECONDS, SLUGGISH_SECONDS = 3, 8, 1
# Loaded after capture_addon.py: names under .slow.test take SLOW_SECONDS to fail
# (.slower.test SLOWER_SECONDS, .sluggish.test SLUGGISH_SECONDS), .slowok.test
# answers ALLOWED_IP after 2 x SLUGGISH_SECONDS, fast.test at once. The guard looks
# names up through egress.resolve_host.
SLOW_RESOLVER = f"""
import time
import egress

_real = egress.resolve_host
_flips = []


def resolve_host(host):
    if host.endswith(".slow.test"):
        time.sleep({SLOW_SECONDS})
        return []
    if host.endswith(".slower.test"):
        time.sleep({SLOWER_SECONDS})
        return []
    if host.endswith(".sluggish.test"):
        time.sleep({SLUGGISH_SECONDS})
        return []
    if host.endswith(".slowok.test"):
        time.sleep({SLUGGISH_SECONDS} * 2)
        return ["{ALLOWED_IP}"]
    if host == "flip.test":  # allowed, then the always-on denylist, then never
        _flips.append(host)
        if len(_flips) == 1:
            return ["{ALLOWED_IP}"]
        if len(_flips) == 2:
            return ["{REFUSED_IP}"]
        time.sleep(60)
        return []
    if host.endswith(".lp.test"):
        return ["{ALLOWED_IP}"]
    if host == "fast.test":
        return ["{ALLOWED_IP}"]
    return _real(host)


egress.resolve_host = resolve_host
"""


class SlowNamesOnTheWire(_ProxyOnTheWire):
    """One proxy serves every sandbox. A target that is an IP address needs no
    lookup, and one network's names that never answer must not hold the threads
    another network's lookups need. A network is the proxy's own address the
    client came in on (127.0.0.1 here, 127.0.0.5 for the other network), so a
    container that adds addresses is still one client."""

    SCRIPTS = (("slow_resolver.py", SLOW_RESOLVER),)
    OTHER_NETWORK = "127.0.0.5"

    def _flood(self, sources, per_source, zone="slow.test"):
        flood = []
        for source in sources:
            for i in range(per_source):
                s = self._proxy(source)
                s.sendall(f"GET http://{source}-{i}-{time.time_ns()}.{zone}/ HTTP/1.1\r\n"
                          f"Host: x.{zone}\r\nConnection: close\r\n\r\n".encode())
                flood.append(s)
        return flood

    def _assert_prompt(self, calls):
        timings = {}
        for label, call in calls:
            started = time.monotonic()
            raw = call()
            timings[label] = round(time.monotonic() - started, 2)
            self.assertEqual(_status(raw), 200, f"{label}: {raw[:200]!r}")
        for label, took in timings.items():
            self.assertLess(took, SLOW_SECONDS - 1, f"{label} waited {took} s behind the slow names: {timings}")

    def test_a_body_sent_while_its_dial_waits_is_not_held_in_memory(self):
        # mitmproxy reads on while a streaming request waits for its dial and
        # queues every chunk behind it: during a slow lookup (or a target that
        # never accepts) one client grew the shared proxy until it was killed.
        before = self._proxy_rss_mb()
        with self._proxy(other_network=True) as s:
            s.sendall(b"POST http://up.slow.test/ HTTP/1.1\r\nHost: up.slow.test\r\nTransfer-Encoding: chunked\r\n\r\n")
            sent = self._push(s, 96, chunked=True)
            raw = _read_all(s)
        grew = self._proxy_rss_mb() - before
        self.assertLess(grew, 40, f"the proxy grew {grew} MB holding a body ({sent >> 20} MB sent) while its dial waited")
        self.assertIsNone(self.proc.poll(), "the proxy died")
        self.assertIn(_status(raw), (None, 502), raw[:200])

    def test_an_upload_whose_dial_is_slow_still_arrives_whole(self):
        # While the dial waits the client is not read (the kernel keeps its bytes),
        # then the whole body goes through.
        del self.honest_posts[:]
        raw = self._large_post("up.slowok.test", self.honest_port, "wire-tag-slowok", full=True,
                               host_headers=[f"up.slowok.test:{self.honest_port}"], other_network=True)
        self.assertEqual(_status(raw), 200, raw[:300])
        self.assertEqual([size for size, _ in self.honest_posts], [LARGE_BODY])

    def test_slow_names_of_one_network_delay_neither_an_ip_target_nor_another_network(self):
        flood = self._flood([ALLOWED_IP], 40)
        try:
            time.sleep(1.0)
            self._assert_prompt((
                ("the same client, an IP target",
                 lambda: self._absolute(ALLOWED_IP, self.honest_port, f"{ALLOWED_IP}:{self.honest_port}")),
                ("another network, a name",
                 lambda: self._absolute("fast.test", self.honest_port, f"fast.test:{self.honest_port}",
                                        other_network=True))))
        finally:
            for s in flood:
                s.close()

    def test_many_addresses_on_one_network_hold_no_more_than_its_line(self):
        # 20 addresses x 16 names: keyed by the client's address they took 160 of
        # the guard's threads, and another network's lookup queued behind them.
        flood = self._flood([f"127.0.0.{100 + c}" for c in range(20)], 16, zone="slower.test")
        try:
            time.sleep(1.5)
            self._assert_prompt((
                ("another network, a name",
                 lambda: self._absolute("fast.test", self.honest_port, f"fast.test:{self.honest_port}",
                                        source="127.0.0.200", other_network=True)),
                ("an IP target",
                 lambda: self._absolute(ALLOWED_IP, self.honest_port, f"{ALLOWED_IP}:{self.honest_port}",
                                        source="127.0.0.201"))))
        finally:
            for s in flood:
                s.close()


GATEWAY = "127.0.0.9"


def _host_ingress(time_limit=None):
    """Loaded after capture_addon.py: 127.0.0.0/8 is the proxy's default-route
    network and 127.0.0.9 its gateway, as pentest-net and its Docker bridge are
    for host-net recon reaching the proxy through the loopback publish."""
    return f"""
import ipaddress

from mitmproxy import ctx


class _Gateway:
    def running(self):
        addon = ctx.master.addons.get("redamoncapture")
        # mitmproxy keeps a script's module out of sys.modules: reach it by a method.
        module_globals = type(addon).__init__.__globals__
        loopback = [ipaddress.ip_network("127.0.0.0/8")]
        module_globals["_read_default_route"] = lambda *a: ("{GATEWAY}", loopback, loopback)
        addon._route_at = None
        if {time_limit!r} is not None:
            addon._run_lookups._time_limit = {time_limit!r}


addons = [_Gateway()]
"""


class HostIngressOnTheWire(_ProxyOnTheWire):
    """Host-net recon of every project and person reaches the proxy from one
    address, the gateway. Keyed on it, one run's names that never answer made
    every other run's lookups wait, then refused them for capacity."""

    SCRIPTS = (("slow_resolver.py", SLOW_RESOLVER), ("host_ingress.py", _host_ingress()))

    def test_slow_names_of_one_run_neither_refuse_nor_hold_the_others(self):
        flood = []
        try:
            for i in range(540):
                s = self._proxy(GATEWAY)
                s.sendall(f"GET http://r{i}-{time.time_ns()}.slow.test/ HTTP/1.1\r\nHost: x.slow.test\r\n"
                          f"X-Redamon-Ctx: run-a\r\nConnection: close\r\n\r\n".encode())
                flood.append(s)
            time.sleep(2.0)
            timings = {}
            for label, extra in (("another run", "X-Redamon-Ctx: run-b\r\n"), ("an untagged request", "")):
                started = time.monotonic()
                raw = self._absolute("fast.test", self.honest_port, f"fast.test:{self.honest_port}",
                                     source=GATEWAY, extra=extra)
                timings[label] = round(time.monotonic() - started, 2)
                self.assertEqual(_status(raw), 200, f"{label}: {raw[:200]!r}")
            for label, took in timings.items():
                self.assertLess(took, SLOW_SECONDS - 1, f"{label} waited {took} s behind one run's slow names")
            refused = []
            for name in os.listdir(self.spool):
                if name.endswith(".json"):
                    with open(os.path.join(self.spool, name)) as fh:
                        rec = json.load(fh)
                    if rec.get("errorText") == "egress:lookup-capacity":
                        refused.append(rec.get("ctx_token"))
            self.assertEqual(refused, [], "lookups through the host ingress were refused for capacity")
        finally:
            for s in flood:
                s.close()


def _sink(conn):
    """Read a request and its body for ever, never answer."""
    conn.settimeout(60)
    while conn.recv(1 << 20):
        pass


def _long_poll(conn):
    """Answer each request with a body that trickles and never ends."""
    conn.settimeout(60)
    buf = b""
    while b"\r\n\r\n" not in buf:
        data = conn.recv(65536)
        if not data:
            return
        buf += data
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000000\r\n\r\n")
    for _ in range(120):
        conn.sendall(b"s" * 1024)
        time.sleep(0.5)


class Http2BacklogsOnTheWire(_ProxyOnTheWire):
    """mitmproxy reads on while a streaming request waits for its dial and queues
    every chunk behind it; the addon stops reading a connection only while the
    bytes queued behind its waiting streams pass a high-water mark. Normal traffic
    never pauses, so an HTTP/2 connection whose sixth long-lived stream waits for
    mitmproxy's per-address limit keeps flowing, and a refused dial beside a
    pending one cannot lift the bound. ssl_insecure: the upstreams are self-signed."""

    MITM_SETS = ("ssl_insecure=true",)
    SCRIPTS = (("slow_resolver.py", SLOW_RESOLVER),)

    @classmethod
    def start_upstreams(cls):
        try:
            import h2.connection  # noqa: F401  (a mitmproxy dependency)
        except ImportError:
            raise unittest.SkipTest("the h2 package is not installed")
        cls.sink_port = _free_port(ALLOWED_IP)
        cls.sockets.append(_tls_listener(ALLOWED_IP, cls.sink_port, _sink))
        cls.long_poll_port = _free_port(ALLOWED_IP)
        cls.sockets.append(_tls_listener(ALLOWED_IP, cls.long_poll_port, _long_poll))

    def _h2_tunnel(self, host, port):
        import ssl
        import h2.config
        import h2.connection

        s, head = self._tunnel(host, port)
        self.assertEqual(_status(head), 200, head[:200])
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        t = ctx.wrap_socket(s, server_hostname=host)
        self.assertEqual(t.selected_alpn_protocol(), "h2")
        conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
        conn.initiate_connection()
        t.sendall(conn.data_to_send())
        return t, conn

    def test_a_refused_dial_beside_a_pending_one_keeps_memory_bounded(self):
        # Three streamed uploads on one connection; their dials: one connects, one
        # is refused (the always-on denylist), one never resolves.
        import ssl
        import h2.events
        import h2.exceptions

        t, conn = self._h2_tunnel("flip.test", self.sink_port)
        streams = []
        for i in range(3):
            sid = conn.get_next_available_stream_id()
            conn.send_headers(sid, [(":method", "POST"), (":scheme", "https"), (":authority", f"flip.test:{self.sink_port}"),
                                    (":path", f"/{i}"), ("content-length", str(600 << 20))])
            streams.append(sid)
        t.sendall(conn.data_to_send())
        before, sent, reset = self._proxy_rss_mb(), 0, set()
        t.setblocking(False)
        started = time.monotonic()
        try:
            while time.monotonic() - started < 6:
                try:
                    for ev in conn.receive_data(t.recv(1 << 16)):
                        if isinstance(ev, h2.events.StreamReset):
                            reset.add(ev.stream_id)
                except ssl.SSLWantReadError:
                    pass
                progressed = False
                for sid in streams:
                    if sid in reset:
                        continue
                    try:
                        n = min(16384, conn.local_flow_control_window(sid), conn.max_outbound_frame_size)
                        if n > 0:
                            conn.send_data(sid, b"x" * n)
                            sent, progressed = sent + n, True
                    except (h2.exceptions.ProtocolError, h2.exceptions.StreamClosedError):
                        reset.add(sid)
                out = conn.data_to_send()
                if out:
                    t.setblocking(True)
                    t.settimeout(0.5)
                    try:
                        t.sendall(out)
                    except (socket.timeout, ssl.SSLWantWriteError):
                        pass
                    t.setblocking(False)
                if not progressed:
                    time.sleep(0.01)
                if sent >> 20 > len(streams) * 8 and self._proxy_rss_mb() - before > 100:
                    break  # unbounded already; spare the test host the rest
        except OSError:
            pass
        finally:
            t.close()
        grew = self._proxy_rss_mb() - before
        self.assertLess(grew, 40, f"the proxy grew {grew} MB ({sent >> 20} MB sent) behind a dial left pending")
        self.assertIsNone(self.proc.poll(), "the proxy died")

    def test_a_long_lived_stream_beyond_the_per_address_limit_does_not_freeze_its_connection(self):
        # mitmproxy dials an HTTP/1.1 origin once per HTTP/2 stream and at most 5
        # times per address; the sixth waits for a slot after server_connect.
        import h2.events

        t, conn = self._h2_tunnel("x.lp.test", self.long_poll_port)
        for i in range(6):
            sid = conn.get_next_available_stream_id()
            conn.send_headers(sid, [(":method", "GET"), (":scheme", "https"),
                                    (":authority", f"x.lp.test:{self.long_poll_port}"), (":path", f"/{i}")],
                              end_stream=True)
        t.sendall(conn.data_to_send())
        t.settimeout(0.5)
        started, pinged, acked, heads, received = time.monotonic(), None, None, 0, 0
        try:
            while time.monotonic() - started < 8 and acked is None:
                if pinged is None and time.monotonic() - started > 2:
                    conn.ping(b"g1-s06b!")
                    t.sendall(conn.data_to_send())
                    pinged = time.monotonic()
                try:
                    data = t.recv(65536)
                except OSError:
                    continue
                if not data:
                    break
                for ev in conn.receive_data(data):
                    if isinstance(ev, h2.events.ResponseReceived):
                        heads += 1
                    elif isinstance(ev, h2.events.DataReceived):
                        received += len(ev.data)
                        conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                    elif isinstance(ev, h2.events.PingAckReceived) and pinged:
                        acked = round(time.monotonic() - pinged, 2)
                t.sendall(conn.data_to_send())
        finally:
            t.close()
        self.assertIsNotNone(acked, f"no PING answer: the connection froze ({heads} responses, {received} bytes)")
        self.assertLess(acked, 2.0)
        self.assertGreaterEqual(heads, 5)


class TimeLimitOnTheWire(_ProxyOnTheWire):
    """The lookup time limit counts the lookup, not the wait for a thread. With
    every thread of the pool taken by names that never answer, another run's
    honest name used to wait in the pool's queue past the limit and be refused
    as `lookup-timeout`. The limit is 3 s here so the test is short."""

    SCRIPTS = (("slow_resolver.py", SLOW_RESOLVER), ("host_ingress.py", _host_ingress(time_limit=3.0)))

    def test_a_flood_of_slow_names_over_many_tags_times_out_no_other_run(self):
        flood = []
        try:
            for i in range(512):
                s = self._proxy(GATEWAY)
                s.sendall(f"GET http://s{i}-{time.time_ns()}.sluggish.test/ HTTP/1.1\r\nHost: x.sluggish.test\r\n"
                          f"X-Redamon-Ctx: invented-{i % 64}\r\nConnection: close\r\n\r\n".encode())
                flood.append(s)
            time.sleep(0.5)
            started = time.monotonic()
            raw = self._absolute("fast.test", self.honest_port, f"fast.test:{self.honest_port}",
                                 source=GATEWAY, extra="X-Redamon-Ctx: honest-run\r\n")
            took = round(time.monotonic() - started, 2)
            self.assertEqual(_status(raw), 200, f"after {took} s: {raw[:200]!r}")
            self.assertEqual([r["errorText"] for r in self._spool_records("honest-run", wait=1.0)
                              if r.get("blocked")], [])
        finally:
            for s in flood:
                s.close()


class GoneClientsOnTheWire(_ProxyOnTheWire):
    """A client's checks still waiting for a lookup thread end when it
    disconnects; they used to keep their place in the line, and the same
    network's next request waited behind nobody."""

    SCRIPTS = (("slow_resolver.py", SLOW_RESOLVER),)

    def test_a_gone_clients_queue_does_not_hold_its_network(self):
        flood = [self._proxy() for _ in range(40)]
        for i, s in enumerate(flood):
            s.sendall(f"GET http://g{i}-{time.time_ns()}.slower.test/ HTTP/1.1\r\nHost: x.slower.test\r\n"
                      f"Connection: close\r\n\r\n".encode())
        time.sleep(1.0)
        for s in flood:
            s.close()
        time.sleep(0.5)
        started = time.monotonic()
        raw = self._absolute("fast.test", self.honest_port, f"fast.test:{self.honest_port}")
        took = round(time.monotonic() - started, 2)
        self.assertEqual(_status(raw), 200, f"after {took} s: {raw[:200]!r}")
        self.assertLess(took, SLOWER_SECONDS + 3, f"the network's next request waited {took} s behind a gone client")


def _head_bomb_server(host, port):
    """An upstream that answers any request with a response head that never ends."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(8)

    def serve(conn):
        try:
            conn.settimeout(IO_TIMEOUT)
            conn.recv(65536)
            conn.sendall(b"HTTP/1.1 200 OK\r\nX-Bomb: ")
            for _ in range(16):
                conn.sendall(b"x" * (1 << 16))
            time.sleep(IO_TIMEOUT)
        except OSError:
            pass
        finally:
            conn.close()

    def accept():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=serve, args=(conn,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    return listener


def _silent_server(host, port):
    """An upstream that takes a request and never answers."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(8)

    def serve(conn):
        try:
            conn.settimeout(IO_TIMEOUT)
            while conn.recv(65536):
                pass
        except OSError:
            pass
        finally:
            conn.close()

    def accept():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=serve, args=(conn,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    return listener


class HeadsAreBoundedOnTheWire(_ProxyOnTheWire):
    """mitmproxy 11.1.3 keeps a head until its blank line with no limit, and keeps
    whatever a client sends after a complete request while its answer is pending,
    so one client (or one target) could grow the proxy that every sandbox shares
    until it is killed. Past the bound the head is refused, or the connection
    closed."""

    @classmethod
    def start_upstreams(cls):
        cls.bomb_port = _free_port(ALLOWED_IP)
        cls.sockets.append(_head_bomb_server(ALLOWED_IP, cls.bomb_port))
        cls.silent_port = _free_port(ALLOWED_IP)
        cls.sockets.append(_silent_server(ALLOWED_IP, cls.silent_port))

    def test_data_sent_ahead_of_a_pending_answer_is_bounded(self):
        before = self._proxy_rss_mb()
        started = time.monotonic()
        with self._proxy() as s:
            s.sendall(f"GET http://{ALLOWED_IP}:{self.silent_port}/ HTTP/1.1\r\n"
                      f"Host: {ALLOWED_IP}:{self.silent_port}\r\n\r\n".encode())
            sent = self._push(s, 96)
            _read_all(s)
        took = time.monotonic() - started
        grew = self._proxy_rss_mb() - before
        self.assertLess(grew, 40, f"the proxy grew {grew} MB holding {sent >> 20} MB sent ahead of an answer")
        self.assertLess(sent, 32 << 20, "the proxy kept reading what was sent ahead of the answer")
        self.assertLess(took, IO_TIMEOUT / 3, f"the connection stayed open {took:.1f} s")
        self.assertIsNone(self.proc.poll(), "the proxy died")

    def test_a_request_head_that_never_ends_is_refused_431(self):
        hits = len(self.honest_hits)
        started = time.monotonic()
        with self._proxy() as s:
            s.sendall(f"GET http://{ALLOWED_IP}:{self.honest_port}/ HTTP/1.1\r\nHost: ".encode())
            try:
                for _ in range(16):
                    s.sendall(b"x" * (1 << 16))
            except OSError:
                pass  # the proxy closes once the bound is passed
            raw = _read_all(s)
        took = time.monotonic() - started
        self.assertEqual(_status(raw), 431, raw[:200])
        self.assertLess(took, IO_TIMEOUT / 3, f"the proxy kept reading the head for {took:.1f} s")
        self.assertEqual(len(self.honest_hits), hits)

    def test_a_response_head_that_never_ends_is_answered_502(self):
        started = time.monotonic()
        raw = self._absolute(ALLOWED_IP, self.bomb_port, f"{ALLOWED_IP}:{self.bomb_port}")
        took = time.monotonic() - started
        self.assertEqual(_status(raw), 502, raw[:200])
        self.assertLess(took, IO_TIMEOUT / 3, f"the proxy kept reading the response head for {took:.1f} s")


if __name__ == "__main__":
    unittest.main()

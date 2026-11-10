"""Shared helpers of the IP-hostnames lab's scripts. Stdlib only.

- Mcp: the inbound MCP server (streamable HTTP, JSON-RPC). The token is read by
  NAME from the environment or the repository's .env and never printed:
  IPHN_MCP_TOKEN_VAR names the variable (default MCP_SERVER_TOKEN). It waits out
  the token's "Try again in Ns" and reconnects after a dropped connection.
- Webapp: a signed-in REST session (UI_LOGIN_USERNAME / UI_LOGIN_PASSWORD from
  .env, never printed), for what MCP does not offer: partial recon, schedules.
- Gates: the route to the lab bridge, the lab containers, the host resolver
  (lab names AND the .gov fixture resolve to the lab, never to the public DNS),
  the orchestrator's lab hooks (names read, values compared, nothing printed).
- Evidence: the hit logs, CoreDNS's query log and the outsider's capture, each
  sliced to a run's time window; parse_pcap / parse_dns_log are plain functions
  (validate_ip_hostnames.py --self-test feeds them canned bytes).

    python3 -I iphn_lab.py pcap-count generated/pcap/outsider.pcap [--src IP] [--dst IP]
    python3 -I iphn_lab.py hits-count iphn-outsider [--client IP]
"""
from __future__ import annotations

import argparse
import http.client
import http.cookiejar
import itertools
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
GEN = HERE / "generated"
RUNS = GEN / "runs"
LOGS = GEN / "logs"
PCAP = GEN / "pcap" / "outsider.pcap"

NET = "192.88.98"
OUTSIDER = f"{NET}.99"
GATEWAY = f"{NET}.1"
LAB_NETWORK = "redamon_iphn_lab"
DNS_CONTAINER = "iphn-dns"
PCAP_CONTAINER = "iphn-pcap"
HIT_CONTAINERS = ("iphn-web", "iphn-plain", "iphn-mismatch", "iphn-split", "iphn-edge", "iphn-outsider",
                  "iphn-intra")
LAB_CONTAINERS = ("iphn-dns", "iphn-web", "iphn-plain", "iphn-mismatch", "iphn-split", "iphn-urlscan",
                  "iphn-edge", "iphn-outsider", "iphn-pcap")
ORCHESTRATOR = "redamon-recon-orchestrator"
HOOKS = ("URLSCAN_API_BASE", "REDAMON_LAB_CDN_PREFIXES", "REDAMON_LAB_PROJECT_IDS")
URLSCAN_STUB_BASE = f"http://{NET}.30/api/v1"
EDGE_PREFIX = f"{NET}.40/32"


# --------------------------------------------------------------------------- credentials

def env_value(name: str) -> str | None:
    """One value by NAME: the environment first, then the repository's .env."""
    if os.environ.get(name):
        return os.environ[name]
    env = REPO / ".env"
    if not env.is_file():
        return None
    for line in env.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith(name + "="):
            return line.split("=", 1)[1].strip().strip('"').strip("'") or None
    return None


def web_base() -> str:
    return os.environ.get("IPHN_WEB") or f"http://localhost:{env_value('WEBAPP_PORT') or '3000'}"


# --------------------------------------------------------------------------- MCP

class Mcp:
    """call() returns (result, is_error); never raises on a tool refusal."""

    def __init__(self, token_var: str | None = None):
        self.token_var = token_var or os.environ.get("IPHN_MCP_TOKEN_VAR") or "MCP_SERVER_TOKEN"
        self.url = os.environ.get("IPHN_MCP_URL") or f"{web_base()}/api/mcp-server"
        self.session: str | None = None
        self._ids = itertools.count(1)
        self._ready = False

    def _token(self) -> str:
        token = env_value(self.token_var)
        if not token:
            raise SystemExit(f"[!][Mcp] {self.token_var} is not set and not in .env")
        return token

    def _post(self, payload: dict, timeout: int = 600):
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "Authorization": f"Bearer {self._token()}"}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        req = urllib.request.Request(self.url, data=json.dumps(payload).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                sid = resp.headers.get("Mcp-Session-Id")
                if sid:
                    self.session = sid
                body = resp.read().decode()
                ctype = resp.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:
            return {"error": {"code": e.code, "message": e.read().decode(errors="replace")[:500]}}
        if "text/event-stream" in ctype:
            for line in body.splitlines():
                if line.startswith("data:"):
                    return json.loads(line[5:].strip())
            return None
        return json.loads(body) if body.strip() else None

    def init(self) -> None:
        self._post({"jsonrpc": "2.0", "id": next(self._ids), "method": "initialize",
                    "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                               "clientInfo": {"name": "redamon-iphn-lab", "version": "1"}}})
        try:
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        except (OSError, http.client.HTTPException, ValueError):
            pass
        self._ready = True

    def _once(self, tool: str, args: dict, timeout: int):
        out = self._post({"jsonrpc": "2.0", "id": next(self._ids), "method": "tools/call",
                          "params": {"name": tool, "arguments": args}}, timeout)
        if out is None:
            return {"error": "empty answer"}, True
        if "error" in out:
            err = out["error"]
            return (err.get("message") if isinstance(err, dict) else str(err)), True
        result = out.get("result") or {}
        text = "\n".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
        if result.get("structuredContent") is not None and not result.get("isError"):
            return result["structuredContent"], False
        try:
            return json.loads(text), bool(result.get("isError"))
        except ValueError:
            return text, bool(result.get("isError"))

    def call(self, tool: str, args: dict, timeout: int = 600, attempts: int = 12):
        if not self._ready:
            self.init()
        out, err = {"error": "not called"}, True
        for _ in range(attempts):
            try:
                out, err = self._once(tool, args, timeout)
            except (OSError, http.client.HTTPException, ValueError) as e:
                # The webapp restarting or a dropped connection: new session, ask again.
                print(f"[*][Mcp] {tool}: {type(e).__name__}, retrying in 15s", flush=True)
                time.sleep(15)
                self.session, self._ready = None, False
                try:
                    self.init()
                except (OSError, http.client.HTTPException, ValueError):
                    pass
                continue
            wait = re.search(r"Try again in (\d+)\s*s", json.dumps(out)) if err else None
            if not wait:
                break
            print(f"[*][Mcp] {tool} rate-limited: waiting {wait.group(1)}s", flush=True)
            time.sleep(int(wait.group(1)) + 2)
        return out, err

    def cypher(self, project_id: str, query: str) -> list:
        """The `v` column of a read-only Cypher (query_graph; the server scopes it to the project)."""
        out, err = self.call("query_graph", {"projectId": project_id, "cypher": query})
        if err:
            raise RuntimeError(f"query_graph refused: {json.dumps(out)[:300]}")
        return [row.get("v") for row in (out.get("records") or [])]


# --------------------------------------------------------------------------- webapp REST

class Webapp:
    def __init__(self):
        self.base = web_base()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        user, password = env_value("UI_LOGIN_USERNAME"), env_value("UI_LOGIN_PASSWORD")
        if not user or not password:
            raise SystemExit("[!][Webapp] UI_LOGIN_USERNAME / UI_LOGIN_PASSWORD missing from .env")
        status, _ = self.call("POST", "/api/auth/login", {"email": user, "password": password})
        if status != 200:
            raise SystemExit(f"[!][Webapp] login refused ({status})")

    def call(self, method: str, path: str, body=None, timeout: int = 120) -> tuple[int, object]:
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as e:
            raw, status = e.read(), e.code
        try:
            return status, json.loads(raw or b"{}")
        except ValueError:
            return status, {"text": raw.decode(errors="replace")[:500]}


# --------------------------------------------------------------------------- gates

def run_cmd(*cmd: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(list(cmd), capture_output=True, text=True, timeout=timeout)


def routing_gate() -> str:
    """The lab prefix is public: abort unless it routes through a docker bridge."""
    route = run_cmd("ip", "route", "get", f"{NET}.10").stdout.strip()
    if " dev br-" not in route:
        raise SystemExit(f"[!][Gate] {NET}.10 does not route through a docker bridge ({route!r}): the lab "
                         "is down and the prefix would reach the internet. Not scanning.")
    return route.splitlines()[0]


def bridge_name() -> str | None:
    out = run_cmd("docker", "network", "inspect", "-f", "{{.Id}}", LAB_NETWORK)
    return f"br-{out.stdout.strip()[:12]}" if out.returncode == 0 and out.stdout.strip() else None


def container_running(name: str) -> bool:
    out = run_cmd("docker", "inspect", "-f", "{{.State.Running}}", name)
    return out.returncode == 0 and out.stdout.strip() == "true"


def lab_container_problems(extra: tuple[str, ...] = ()) -> list[str]:
    return [f"{n} is not running" for n in LAB_CONTAINERS + extra if not container_running(n)]


def resolve_via_host(name: str) -> str:
    """resolvectl's answer for a name or an address (the path recon's
    containers take: the host's systemd-resolved stub)."""
    out = run_cmd("resolvectl", "query", name, timeout=30)
    return out.stdout if out.returncode == 0 else ""


def host_dns_problems(moved: str | None = "10") -> list[str]:
    """Stops at the first miss: the .gov fixture is asked last, and only once a
    reserved lab name has proved the host routes the lab zones to the lab DNS,
    so this check itself never asks the public DNS about it."""
    checks = [("app.example-a.test", [f"{NET}.10"]),
              (f"{NET}.10", ["web.example-a.test", "app.example-a.test"]),
              ("mismatch.example-b.test", [OUTSIDER])]
    if moved:
        checks.append(("moved.example-a.test", [f"{NET}.{moved}"]))
    # A scan that asked the public DNS about it would leave the lab.
    checks.append(("portal.lab-agency.gov", [f"{NET}.10"]))
    for name, want in checks:
        got = resolve_via_host(name)
        missing = [w for w in want if w not in got]
        if missing:
            return [f"{name} through the host resolver lacks {missing} (./host_dns_enable.sh not in force?)"]
    return []


def orchestrator_hooks() -> dict:
    """The three lab hooks as the running orchestrator sees them. Only these
    names are kept; the caller compares values and never prints them."""
    out = run_cmd("docker", "inspect", "-f", "{{json .Config.Env}}", ORCHESTRATOR)
    if out.returncode != 0:
        raise SystemExit(f"[!][Gate] cannot inspect {ORCHESTRATOR}: is the stack up?")
    found = {}
    for item in json.loads(out.stdout or "[]"):
        name, _, value = item.partition("=")
        if name in HOOKS and value.strip():
            found[name] = value.strip()
    return found


def hook_problems(project_ids: list[str], need: list[str]) -> list[str]:
    """need: "urlscan" (URLSCAN_API_BASE -> this lab's stub) and/or "cdn"
    (REDAMON_LAB_CDN_PREFIXES has .40/32); both also need every project listed."""
    if not need:
        return []
    hooks = orchestrator_hooks()
    problems = []
    if "urlscan" in need and hooks.get("URLSCAN_API_BASE") != URLSCAN_STUB_BASE:
        problems.append(f"URLSCAN_API_BASE is not {URLSCAN_STUB_BASE}")
    if "cdn" in need and EDGE_PREFIX not in hooks.get("REDAMON_LAB_CDN_PREFIXES", "").split(","):
        problems.append(f"REDAMON_LAB_CDN_PREFIXES lacks {EDGE_PREFIX}")
    listed = {p.strip() for p in hooks.get("REDAMON_LAB_PROJECT_IDS", "").split(",") if p.strip()}
    missing = [p for p in project_ids if p not in listed]
    if missing:
        problems.append(f"REDAMON_LAB_PROJECT_IDS lacks {missing}")
    return problems


def hook_command(project_ids: list[str], need: list[str]) -> str:
    env = []
    if "urlscan" in need:
        env.append(f"URLSCAN_API_BASE={URLSCAN_STUB_BASE}")
    if "cdn" in need:
        env.append(f"REDAMON_LAB_CDN_PREFIXES={EDGE_PREFIX}")
    env.append(f"REDAMON_LAB_PROJECT_IDS={','.join(project_ids)}")
    return " ".join(env) + " docker compose up -d --no-deps recon-orchestrator"


# --------------------------------------------------------------------------- outsider capture

def rotate_pcap(wait_s: int = 20) -> None:
    """Restart the capture sidecar: its command moves the old file aside and
    starts a new one, so a run's capture holds that run's packets only."""
    out = run_cmd("docker", "restart", PCAP_CONTAINER, timeout=60)
    if out.returncode != 0:
        raise SystemExit(f"[!][Pcap] cannot restart {PCAP_CONTAINER}: {out.stderr.strip()[:200]}")
    deadline = time.time() + wait_s
    while time.time() < deadline:
        if PCAP.is_file() and PCAP.stat().st_size >= 24 and container_running(PCAP_CONTAINER):
            return
        time.sleep(1)
    raise SystemExit(f"[!][Pcap] {PCAP} did not come back after the restart")


def _ip4(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def _ip6(b: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, b)


def parse_pcap(data: bytes) -> list[dict]:
    """Packets of a libpcap file (Ethernet or Linux cooked), IPv4/IPv6 headers only:
    [{ts, src, dst, proto, sport, dport, flags, length}]. ARP and other
    non-IP frames come back with proto 'other'."""
    if len(data) < 24:
        return []
    magic = data[:4]
    table = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
             b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
    if magic not in table:
        raise ValueError("not a libpcap file")
    endian, frac = table[magic]
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    out, pos = [], 24
    while pos + 16 <= len(data):
        ts_s, ts_f, incl, orig = struct.unpack(endian + "IIII", data[pos:pos + 16])
        frame = data[pos + 16:pos + 16 + incl]
        pos += 16 + incl
        pkt = {"ts": ts_s + ts_f * frac, "length": orig, "proto": "other", "src": None, "dst": None,
               "sport": None, "dport": None, "flags": None}
        if linktype == 1 and len(frame) >= 14:
            etype, off = struct.unpack(">H", frame[12:14])[0], 14
            if etype == 0x8100 and len(frame) >= 18:
                etype, off = struct.unpack(">H", frame[16:18])[0], 18
        elif linktype == 113 and len(frame) >= 16:
            etype, off = struct.unpack(">H", frame[14:16])[0], 16
        else:
            out.append(pkt)
            continue
        ip = frame[off:]
        nxt, l4 = None, b""
        if etype == 0x0800 and len(ip) >= 20:
            ihl = (ip[0] & 0x0F) * 4
            nxt, pkt["src"], pkt["dst"], l4 = ip[9], _ip4(ip[12:16]), _ip4(ip[16:20]), ip[ihl:]
        elif etype == 0x86DD and len(ip) >= 40:
            nxt, pkt["src"], pkt["dst"], l4 = ip[6], _ip6(ip[8:24]), _ip6(ip[24:40]), ip[40:]
        if nxt is None:
            out.append(pkt)
            continue
        pkt["proto"] = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp6"}.get(nxt, str(nxt))
        if nxt in (6, 17) and len(l4) >= 4:
            pkt["sport"], pkt["dport"] = struct.unpack(">HH", l4[:4])
            if nxt == 6 and len(l4) >= 14:
                f = l4[13]
                pkt["flags"] = "".join(c for bit, c in ((2, "S"), (16, "A"), (1, "F"), (4, "R"), (8, "P"))
                                       if f & bit)
        out.append(pkt)
    return out


# --------------------------------------------------------------------------- hits and DNS log

def normalise_hit(line: dict) -> dict:
    """host_name: the Host header without its port, lower-cased; empty SNI -> None."""
    hit = dict(line)
    host = str(hit.get("host") or "").strip().lower()
    if host.startswith("["):
        host = host[1:host.find("]")] if "]" in host else host
    elif host.count(":") == 1:
        host = host.split(":", 1)[0]
    hit["host_name"] = host.rstrip(".") or None
    hit["sni"] = (str(hit.get("sni") or "").strip().lower().rstrip(".") or None)
    return hit


def read_hits(path: Path, t0: float | None = None, t1: float | None = None) -> list[dict]:
    if not path.is_file():
        return []
    hits = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            line = json.loads(raw)
        except ValueError:
            continue
        ts = float(line.get("ts") or 0)
        if (t0 is None or ts >= t0) and (t1 is None or ts <= t1):
            hits.append(normalise_hit(line))
    return hits


_DNS_LINE = re.compile(
    r'^(?:(?P<time>\d{4}-\d\d-\d\dT\S+)\s+)?\[INFO\] (?P<client>\[[^\]]+\]|[^\s:]+):(?P<port>\d+) - (?P<id>\d+) '
    r'"(?P<qtype>\S+) (?P<qclass>\S+) (?P<name>\S+) (?P<proto>\S+) (?P<size>\d+) (?P<do>\S+) (?P<bufsize>\d+)" '
    r'(?P<rcode>\S+) (?P<rflags>\S+) (?P<rsize>\d+) (?P<duration>\S+)')


def parse_dns_log(text: str) -> list[dict]:
    """CoreDNS `log` lines (optionally `docker logs -t` prefixed) -> queries.
    ptr_ip is the address a PTR query asks about (in-addr.arpa reversed)."""
    out = []
    for line in text.splitlines():
        m = _DNS_LINE.match(line.strip())
        if not m:
            continue
        q = m.groupdict()
        q["client"] = q["client"].strip("[]")
        q["name"] = q["name"].lower().rstrip(".")
        q["ptr_ip"] = None
        if q["name"].endswith(".in-addr.arpa"):
            octets = q["name"][: -len(".in-addr.arpa")].split(".")
            if len(octets) == 4:
                q["ptr_ip"] = ".".join(reversed(octets))
        out.append(q)
    return out


def dns_log_between(t0: float, t1: float) -> str:
    out = run_cmd("docker", "logs", "-t", "--since", f"{t0:.3f}", "--until", f"{t1:.3f}", DNS_CONTAINER,
                  timeout=120)
    return out.stdout + out.stderr


# --------------------------------------------------------------------------- CLI (up.sh smoke checks)

def main() -> int:
    ap = argparse.ArgumentParser(description="Lab evidence counters for up.sh")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pcap-count")
    p.add_argument("file", type=Path)
    p.add_argument("--src")
    p.add_argument("--dst")
    h = sub.add_parser("hits-count")
    h.add_argument("container")
    h.add_argument("--client")
    a = ap.parse_args()
    if a.cmd == "pcap-count":
        pkts = parse_pcap(a.file.read_bytes()) if a.file.is_file() else []
        n = sum(1 for x in pkts if (not a.src or x["src"] == a.src) and (not a.dst or x["dst"] == a.dst))
    else:
        n = sum(1 for x in read_hits(LOGS / a.container / "hits.jsonl") if not a.client or x.get("client") == a.client)
    print(n)
    return 0


if __name__ == "__main__":
    sys.exit(main())

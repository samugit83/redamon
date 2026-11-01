#!/usr/bin/env python3
"""The lab canary: a TCP sink on redamon-trufflehog-net, and its report.

    python3 canary_report.py --since 2026-11-01T10:00:00Z   # count connections since then
    python3 canary_report.py --since <t> --include-gateway  # also count the host side
    python3 canary_report.py --serve                        # inside the canary container (compose)

The report counts the connections the canary logged whose source address is in
redamon-trufflehog-net's subnet (read with `docker network inspect`): what a
TruffleHog sidecar on that bridge dialed. Connections from the bridge's
gateway are the HOST side (a recon container on host networking, a curl from
the host) and are listed apart, not counted, unless --include-gateway. Exit 0.

The canary only accepts and closes: it never reads what a client sends.
"""
import argparse
import collections
import ipaddress
import json
import re
import subprocess
import sys
from datetime import datetime, timezone

CANARY = "jslab-canary"
NETWORK = "redamon-trufflehog-net"
PORTS = (21, 80, 389, 443, 1433, 3306, 5432, 6379, 8080, 27017)
LINE = re.compile(r"^CONN ts=(\S+) src=(\S+) sport=(\d+) port=(\d+)$")


def serve():
    import selectors
    import socket

    sel = selectors.DefaultSelector()
    for port in PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.listen(128)
        sock.setblocking(False)
        sel.register(sock, selectors.EVENT_READ, port)
    print(f"[*] canary listening on {', '.join(map(str, PORTS))}", flush=True)
    while True:
        for key, _ in sel.select():
            try:
                conn, (src, sport) = key.fileobj.accept()
            except OSError:
                continue
            ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            print(f"CONN ts={ts} src={src} sport={sport} port={key.data}", flush=True)
            conn.close()


def parse_time(text):
    when = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return when if when.tzinfo else when.astimezone()


def network():
    out = subprocess.run(["docker", "network", "inspect", NETWORK], capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"[!] docker network inspect {NETWORK} failed: {out.stderr.strip()[:200]}")
    cfg = (json.loads(out.stdout)[0].get("IPAM") or {}).get("Config") or []
    subnets = [ipaddress.ip_network(c["Subnet"]) for c in cfg if c.get("Subnet")]
    gateways = {c["Gateway"] for c in cfg if c.get("Gateway")}
    if not subnets:
        raise SystemExit(f"[!] {NETWORK} has no subnet in its IPAM config")
    return subnets, gateways


def report(since, include_gateway, as_json):
    subnets, gateways = network()
    out = subprocess.run(["docker", "logs", CANARY], capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"[!] docker logs {CANARY} failed: {out.stderr.strip()[:200]}")
    counted, gateway, outside = [], [], 0
    for line in (out.stdout + "\n" + out.stderr).splitlines():
        m = LINE.match(line.strip())
        if not m:
            continue
        ts, src, port = parse_time(m.group(1)), m.group(2), int(m.group(4))
        if since and ts < since:
            continue
        addr = ipaddress.ip_address(src)
        if not any(addr in net for net in subnets):
            outside += 1
        elif src in gateways and not include_gateway:
            gateway.append((src, port))
        else:
            counted.append((src, port))
    by_port = collections.Counter(p for _, p in counted)
    by_src = collections.Counter(s for s, _ in counted)
    result = {"since": since.isoformat() if since else None, "network": NETWORK,
              "subnets": [str(n) for n in subnets], "count": len(counted),
              "by_port": dict(sorted(by_port.items())), "by_source": dict(sorted(by_src.items())),
              "gateway_not_counted": len(gateway), "outside_subnet_ignored": outside}
    if as_json:
        print(json.dumps(result, indent=1))
        return
    print(f"canary connections from {NETWORK} ({', '.join(result['subnets'])})"
          f"{' since ' + result['since'] if since else ''}: {len(counted)}")
    for port, n in sorted(by_port.items()):
        print(f"  port {port:>5}: {n}")
    for src, n in sorted(by_src.items()):
        print(f"  from {src}: {n}")
    if gateway:
        ports = collections.Counter(p for _, p in gateway)
        print(f"  not counted, from the gateway (host side): {len(gateway)} "
              f"({', '.join(f'{p}x{n}' for p, n in sorted(ports.items()))})")
    if outside:
        print(f"  ignored, outside the subnet: {outside}")


def main():
    ap = argparse.ArgumentParser(description="The js_secret_lab canary and its connection report.")
    ap.add_argument("--serve", action="store_true", help="run the sink (inside the canary container)")
    ap.add_argument("--since", help="ISO time; a time without a zone is local")
    ap.add_argument("--include-gateway", action="store_true", help="count the bridge gateway's connections too")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if args.serve:
        serve()
        return
    since = parse_time(args.since) if args.since else None
    report(since, args.include_gateway, args.json)
    sys.exit(0)


if __name__ == "__main__":
    main()

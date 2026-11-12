#!/usr/bin/env python3
"""What the lab hosts received during one run: the E2E-B traffic assertions.

    check_lab_traffic.py --since <UTC ISO> [--until <UTC ISO>] --expect excluded|control
                         [--recon-log <docker logs --timestamps of the recon container>]

Reads web1..web6's access logs (`docker logs`, one line per request with its
Host and SNI) and the pcap1..pcap5 captures (every IPv4 packet web1..web5
received; a port probe or a TLS handshake leaves no log line). Prints PASS or
FAIL per row and exits 1 on any FAIL.

--expect excluded: the run excluded 192.88.99.62/32 and shop.nwlab.test (the
FULL scenario). Nothing may reach web3; no name with an excluded address
(edge, mixed) or excluded name (shop) is sent anywhere; plain gets its :80
checks and no :443 connect; redirect hops onto a name outside the run are
never sent; the banner on 21 is read on Y only.
--expect control: the same hosts with no exclusion. The must-fire half: web3
and mixed are reached, which proves the capture and the logs see this traffic.

A kernel connect() SYN carries TCP timestamps; the raw SYNs of a port scanner
(naabu, nmap -sS) do not. That is how a probe of a closed port by a check is
told from the port scan's own probe of it. Other modules connect to closed
ports by design (httpx -jarm, vhost/SNI's default 80/443, nmap's NSE), so
with --recon-log the two closed-port rows judge only the module they are
about: a connect inside the security checks' window (plain :443) or the
banner grab's (X :21). Every connect is listed with the phase it fell in.
`mixed` sent to its allowed address (web2) is reported, not failed: only
web3 must stay silent (B-FD2: "mixed scanned only on its allowed address").
Stdlib only; nothing is printed that the lab did not log.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from datetime import datetime, timezone

WEB3, WEB2, WEB4, WEB5 = "192.88.99.62", "192.88.99.61", "192.88.99.63", "192.88.99.64"
_PKT = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) IP (\S+) > (\S+): (.*)$")


def _ts(text: str) -> datetime:
    text = text.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(text.replace(" ", "T"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def access_log(web: str, since: datetime, until: datetime | None) -> list[str]:
    out = subprocess.run(["docker", "logs", "--since", since.strftime("%Y-%m-%dT%H:%M:%SZ"),
                          f"redamon-nwlab-{web}"], capture_output=True, text=True)
    lines = []
    for line in (out.stdout + out.stderr).splitlines():
        m = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d) (\S+) ", line)
        if not m or m.group(2) == "127.0.0.1":
            continue  # nginx's own notices; the container healthcheck
        when = _ts(m.group(1))
        if when >= since and (until is None or when <= until):
            lines.append(line)
    return lines


def packets(cap: str, bpf: str, since: datetime, until: datetime | None, payload=False) -> list[str]:
    """Each packet as its header line (+ its ASCII payload with payload=True)."""
    cmd = ["docker", "exec", f"redamon-nwlab-pcap{cap[-1]}", "tcpdump", "-nn", "-tttt", "-v"]
    if payload:
        cmd.append("-A")
    cmd += ["-r", f"/pcap/{cap}.pcap", bpf]
    out = subprocess.run(cmd, capture_output=True, text=True, errors="replace").stdout
    pkts, cur = [], None
    for line in out.splitlines():
        if re.match(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+ ", line):
            if cur:
                pkts.append(cur)
            cur = [line]
        elif cur is not None:
            cur.append(line)
    if cur:
        pkts.append(cur)
    keep = []
    for p in pkts:
        when = _ts(p[0][:26])
        if when >= since and (until is None or when <= until):
            keep.append("\n".join(p))
    return keep


def kernel_syns(pkts: list[str]) -> list[str]:
    return [p for p in pkts if "Flags [S]" in p and "TS val" in p]


def recon_phases(path: str | None) -> list[tuple[datetime, str]]:
    """(time, line) of each timestamped recon log line (docker logs --timestamps)."""
    if not path:
        return []
    rows = []
    for line in open(path, errors="replace"):
        stamp, _, rest = line.partition(" ")
        try:
            rows.append((_ts(stamp[:26] + "+00:00"), rest.rstrip()))
        except ValueError:
            continue
    return rows


def window(rows, start_marker: str, end_marker: str | None = None, slack_s: float = 5.0):
    """[first line with start_marker, last line with end_marker (or start_marker)] + slack."""
    starts = [t for t, l in rows if start_marker in l]
    ends = [t for t, l in rows if (end_marker or start_marker) in l]
    if not starts or not ends:
        return None
    from datetime import timedelta
    return starts[0], max(ends) + timedelta(seconds=slack_s)


def phase_of(rows, when: datetime) -> str:
    last = "before the run"
    for t, l in rows:
        if t > when:
            break
        if "[Pipeline] GROUP" in l:
            last = l.split("[Pipeline] ", 1)[1][:60]
    return last


def syn_time(p: str) -> datetime:
    return _ts(p[:26])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--since", required=True)
    ap.add_argument("--until")
    ap.add_argument("--expect", required=True, choices=["excluded", "control"])
    ap.add_argument("--recon-log")
    a = ap.parse_args()
    phases = recon_phases(a.recon_log)
    since, until = _ts(a.since), (_ts(a.until) if a.until else None)

    web1 = access_log("web1", since, until)
    web2 = access_log("web2", since, until)
    web3 = access_log("web3", since, until)
    web4 = access_log("web4", since, until)
    web6 = access_log("web6", since, until)
    p3 = packets("web3", f"ip and dst host {WEB3}", since, until)
    p2_443 = packets("web2", f"ip and dst host {WEB2} and tcp port 443", since, until, payload=True)
    p4_443 = packets("web4", f"ip and dst host {WEB4} and tcp dst port 443", since, until)
    p5_21 = packets("web5", f"ip and dst host {WEB5} and tcp dst port 21", since, until)

    def hosts(lines, name):
        return [l for l in lines if f" host={name} " in l]

    def sni_or_host(lines, name):
        return [l for l in lines if f" host={name} " in l or f" sni={name} " in l]

    mixed_wire = [p for p in p2_443 if "mixed.nwlab.test" in p]
    rows: list[tuple[str, bool, str]] = []
    if a.expect == "excluded":
        k443 = kernel_syns(p4_443)
        k21 = kernel_syns(p5_21)
        secchk = window(phases, "[SecurityCheck]")
        banner = window(phases, "Banner grabbing for non-HTTP ports", "Banner grab complete")

        def inside(pkts, win):
            return pkts if win is None else [p for p in pkts if win[0] <= syn_time(p) <= win[1]]

        def where(pkts):
            return [f"{p[11:23]} ({phase_of(phases, syn_time(p))})" for p in pkts] if phases else len(pkts)

        mixed_web2 = hosts(web2, "mixed.nwlab.test")
        rows += [
            ("web3_received_no_packet", not p3, f"packets={len(p3)} first={p3[:1]}"),
            ("web3_logged_no_request", not web3, f"lines={len(web3)} first={web3[:1]}"),
            ("mixed_never_sent_to_web3", not sni_or_host(web3, "mixed.nwlab.test"),
             f"lines={len(sni_or_host(web3, 'mixed.nwlab.test'))}"),
            ("shop_never_requested", not sni_or_host(web1, "shop.nwlab.test"),
             f"lines={sni_or_host(web1, 'shop.nwlab.test')[:2]}"),
            ("web1_bare_ip_still_checked", bool(hosts(web1, "192.88.99.60")),
             f"lines={len(hosts(web1, '192.88.99.60'))}"),
            ("plain_checked_on_80", bool(hosts(web4, "plain.nwlab.test")),
             f"lines={len(hosts(web4, 'plain.nwlab.test'))}"),
            ("plain_no_443_connect_by_the_security_checks", not inside(k443, secchk),
             f"window={'whole run' if secchk is None else 'security checks'}; kernel connects to :443: {where(k443)}"),
            ("redirect_off_run_not_followed", not hosts(web2, "www.nwlab-two.test"),
             f"lines={hosts(web2, 'www.nwlab-two.test')[:2]}"),
            ("banner_21_read_on_Y", any(" :21 stream" in l for l in web6),
             f"Y_21_connects={sum(' :21 stream' in l for l in web6)}"),
            ("banner_21_never_tried_on_X", not inside(k21, banner),
             f"window={'whole run' if banner is None else 'banner grab'}; kernel connects to X:21: {where(k21)}"),
        ]
        print(f"INFO  traffic.mixed_on_its_allowed_address  web2 log={len(mixed_web2)} sni_on_wire={len(mixed_wire)} "
              f"ua={sorted({l.split('ua=', 1)[-1] for l in mixed_web2})[:3]}")
    else:
        rows += [
            ("web3_reached_when_not_excluded", bool(p3) and bool(web3), f"packets={len(p3)} lines={len(web3)}"),
            ("mixed_reached_when_not_excluded",
             bool(hosts(web2, "mixed.nwlab.test") or mixed_wire or hosts(web3, "mixed.nwlab.test")),
             f"web2_log={len(hosts(web2, 'mixed.nwlab.test'))} web2_sni={len(mixed_wire)} "
             f"web3_log={len(hosts(web3, 'mixed.nwlab.test'))}"),
            ("edge_requested_when_not_excluded", bool(sni_or_host(web3, "edge.nwlab.test")),
             f"lines={len(sni_or_host(web3, 'edge.nwlab.test'))}"),
        ]
    failed = 0
    for name, ok, detail in rows:
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  traffic.{name}  {detail}")
    print(f"\ntraffic ({a.expect}): {'PASS' if not failed else f'{failed} FAIL'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

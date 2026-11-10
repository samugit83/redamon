#!/usr/bin/env python3
"""Render the IP-hostnames lab's content into generated/ (stdlib + host openssl).

    python3 -I gen_lab.py                      # certificates (once), zones, urlscan fixtures
    python3 -I gen_lab.py --dns-only --moved 99 --intra-ip <addr>   # re-render the zones only
    python3 -I gen_lab.py --regen-certs        # new CA and certificates

State kept in generated/lab.json: where moved.example-a.test points (10 or 99),
the intra container's address on redamon-network (read by up.sh, never
hard-coded), and the last SOA serial. CoreDNS's file plugin reloads a zone
only when its serial grows, so every render takes a serial above the last one.

The urlscan stub (.30) is urlscan_lab's fake urlscan, mounted read-only; this
script only writes its fixtures: two visits under example-a.test, hidden (on
.10) and gone (on .99).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
GEN = HERE / "generated"
STATE = GEN / "lab.json"
NET = "192.88.98"

ZONES = ("example-a.test", "example-b.test", "lab-c.example", "lab-agency.gov", "98.88.192.in-addr.arpa")

# .10's default certificate: what a scanner sees on https://192.88.98.10/
# without SNI. hidden.example-a.test is deliberately absent (only the urlscan
# stub names it); *.wild is a wildcard SAN that must never become a name.
WEB_DEFAULT_SANS = [
    "web.example-a.test", "app.example-a.test", "shop.example-b.test", "api.lab-c.example",
    "moved.example-a.test", "outside.example-b.test", "nodns.example-a.test",
    "portal.lab-agency.gov", "*.wild.example-a.test",
]
WEB_VHOSTS = [
    "web.example-a.test", "app.example-a.test", "shop.example-b.test", "api.lab-c.example",
    "hidden.example-a.test", "portal.lab-agency.gov", "moved.example-a.test",
]
EDGE_SANS = ["cdn1.example-a.test", "cdn2.example-b.test"]
OUTSIDER_SANS = ["outside.example-b.test", "mismatch.example-b.test", "split.example-a.test",
                 "gone.example-a.test"]

LAB_CA_SUBJ = "/O=RedAmon guinea pig/CN=IPHN Lab Root CA"
# recon's cdn_from_certificate() keys on "cloudflare" in the ISSUER; the leaf's
# own subject carries the organisation too, as a real edge certificate does.
EDGE_CA_SUBJ = "/C=US/O=Cloudflare, Inc./CN=Cloudflare Inc ECC CA-3 (iphn lab)"
EDGE_SUBJ = "/C=US/O=Cloudflare, Inc./CN=cdn1.example-a.test"


def _openssl(*args: str) -> None:
    out = subprocess.run(["openssl", *args], capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"[!][GenLab] openssl {args[0]} failed: {out.stderr.strip()[:400]}")


def _ca(certs: Path, name: str, subj: str) -> None:
    _openssl("req", "-x509", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
             "-keyout", str(certs / f"{name}.key"), "-out", str(certs / f"{name}.crt"), "-days", "3650",
             "-subj", subj, "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign")


def _leaf(certs: Path, name: str, subj: str, sans: list[str], ca: str) -> None:
    key, csr, crt = certs / f"{name}.key", certs / f"{name}.csr", certs / f"{name}.crt"
    _openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
             "-keyout", str(key), "-out", str(csr), "-subj", subj)
    with tempfile.NamedTemporaryFile("w", suffix=".ext", dir=certs, delete=False) as ext:
        ext.write("basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n"
                  "subjectAltName=" + ",".join(f"DNS:{s}" for s in sans) + "\n")
    try:
        _openssl("x509", "-req", "-in", str(csr), "-CA", str(certs / f"{ca}.crt"),
                 "-CAkey", str(certs / f"{ca}.key"), "-set_serial", "0x" + secrets.token_hex(8),
                 "-days", "825", "-extfile", ext.name, "-out", str(crt))
    finally:
        os.unlink(ext.name)
        csr.unlink(missing_ok=True)


def build_certs(certs: Path) -> list[str]:
    certs.mkdir(parents=True, exist_ok=True)
    _ca(certs, "lab-ca", LAB_CA_SUBJ)
    _ca(certs, "edge-ca", EDGE_CA_SUBJ)
    built = []
    _leaf(certs, "web-default", "/CN=web.example-a.test", WEB_DEFAULT_SANS, "lab-ca")
    built.append("web-default")
    for name in WEB_VHOSTS + ["split.example-a.test", "intra.example-a.test"]:
        _leaf(certs, name, f"/CN={name}", [name], "lab-ca")
        built.append(name)
    _leaf(certs, "outsider", "/CN=outside.example-b.test", OUTSIDER_SANS, "lab-ca")
    _leaf(certs, "edge", EDGE_SUBJ, EDGE_SANS, "edge-ca")
    built += ["outsider", "edge"]
    # The servers run as the invoking user (python) or as root (nginx): both
    # read the keys, nobody else needs to.
    for key in certs.glob("*.key"):
        key.chmod(0o600)
    return built


def certs_complete(certs: Path) -> bool:
    names = ["lab-ca", "edge-ca", "web-default", "outsider", "edge", "split.example-a.test",
             "intra.example-a.test", *WEB_VHOSTS]
    return all((certs / f"{n}.crt").is_file() and (certs / f"{n}.key").is_file() for n in names)


def load_state() -> dict:
    return json.loads(STATE.read_text()) if STATE.is_file() else {}


def render_zones(state: dict) -> None:
    dns = GEN / "dns"
    dns.mkdir(parents=True, exist_ok=True)
    moved_ip = f"{NET}.{state['moved']}"
    intra = state.get("intra_ip")
    intra_record = (f"intra    IN A   {intra}\n" if intra else
                    "; intra: no record (iphn-intra is not running on redamon-network)\n")
    for zone in ZONES:
        text = (HERE / "dns" / f"{zone}.db").read_text()
        text = (text.replace("@SERIAL@", str(state["serial"])).replace("@MOVED_IP@", moved_ip)
                .replace("@INTRA_RECORD@", intra_record))
        # Written beside, then renamed: CoreDNS polls the file and must never
        # read a half-written zone.
        tmp = dns / f".{zone}.db.tmp"
        tmp.write_text(text)
        tmp.replace(dns / f"{zone}.db")
    (dns / "Corefile").write_text((HERE / "dns" / "Corefile").read_text())


def _visit(name: str, ip: str, age_days: float) -> dict:
    uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"iphn-lab-visit.{name}"))
    url = f"https://{name}/"
    return {
        "submitter": {},
        "canonical": {"task": {"url": name}, "page": {"url": name}},
        "task": {"visibility": "public", "method": "api", "domain": name, "apexDomain": "example-a.test",
                 "uuid": uid, "url": url},
        "stats": {"uniqIPs": 1, "uniqCountries": 1, "dataLength": 1200, "encodedDataLength": 1000,
                  "requests": 1},
        "page": {"url": url, "domain": name, "apexDomain": "example-a.test", "ip": ip, "asn": "AS64500",
                 "asnname": "LAB-NET - IPHN Lab Network, ZZ", "country": "ZZ", "server": "nginx",
                 "status": "200", "title": f"VHOST={name}", "mimeType": "text/plain", "language": "en",
                 "tlsIssuer": "IPHN Lab Root CA", "tlsValidDays": 825, "tlsAgeDays": 10,
                 "domainAgeDays": 400, "apexDomainAgeDays": 400},
        "labels": [],
        "age_days": age_days,
        "touched_domains": [name],
        "files": [],
        "lab_id": name.split(".", 1)[0],
        "group": "iphn",
    }


def write_fixtures() -> None:
    out = GEN / "fixtures"
    out.mkdir(parents=True, exist_ok=True)
    # Ages inside urlscan's 30-day anonymous window: the stub returns both with
    # or without a key.
    visits = [_visit("hidden.example-a.test", f"{NET}.10", 3.0), _visit("gone.example-a.test", f"{NET}.99", 5.0)]
    (out / "visits.json").write_text(json.dumps({"generated_at": int(time.time()), "visits": visits}, indent=1))
    # Read by urlscan_lab's check_fixtures.py (--meta): which domain the main
    # search asks for, and how many visits it must return without a key.
    (out / "meta.json").write_text(json.dumps({"domain": "example-a.test", "anonymous_visible": 2}))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dns-only", action="store_true", help="re-render the zones; touch nothing else")
    ap.add_argument("--moved", choices=("10", "99"), help="where moved.example-a.test points")
    ap.add_argument("--intra-ip", help="iphn-intra's address on redamon-network ('' removes the record)")
    ap.add_argument("--regen-certs", action="store_true")
    a = ap.parse_args()

    GEN.mkdir(exist_ok=True)
    state = load_state()
    state.setdefault("moved", "10")
    if a.moved:
        state["moved"] = a.moved
    if a.intra_ip is not None:
        if a.intra_ip:
            addr = ipaddress.ip_address(a.intra_ip)
            # E10's point is a PRIVATE target: anything else is a wiring mistake.
            if not addr.is_private or str(addr).startswith(f"{NET}."):
                raise SystemExit(f"[!][GenLab] {a.intra_ip} is not a private redamon-network address")
            state["intra_ip"] = str(addr)
        else:
            state.pop("intra_ip", None)
    state["serial"] = max(int(time.time()), int(state.get("serial", 0)) + 1)

    if not a.dns_only:
        certs = GEN / "certs"
        if a.regen_certs or not certs_complete(certs):
            built = build_certs(certs)
            state["certs_generated_at"] = int(time.time())
            print(f"[+][GenLab] {len(built)} certificates in {certs.relative_to(HERE)}")
        else:
            print("[*][GenLab] certificates exist (use --regen-certs for new ones)")
        write_fixtures()
        print("[+][GenLab] urlscan stub fixtures: hidden.example-a.test (.10), gone.example-a.test (.99)")
        for sub in ("iphn-web", "iphn-plain", "iphn-mismatch", "iphn-split", "iphn-outsider", "iphn-edge",
                    "iphn-urlscan", "iphn-intra"):
            (GEN / "logs" / sub).mkdir(parents=True, exist_ok=True)
        (GEN / "pcap").mkdir(exist_ok=True)

    render_zones(state)
    STATE.write_text(json.dumps(state, indent=1))
    print(f"[+][GenLab] zones rendered: serial {state['serial']}, moved -> {NET}.{state['moved']}, "
          f"intra -> {state.get('intra_ip') or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

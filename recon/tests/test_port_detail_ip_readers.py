"""The banner grab and tlsx's port enrichment read each port detail's own address.

A domain run's name on two addresses holds both addresses' ports in one
by_host entry, each detail naming its address (S-20). run_banner_grab paired
the entry's first address with every port, so it connected to 192.0.2.10 on a
port only 192.0.2.20 has, and wrote one address's banner onto both details of
a port the two share. tls_scan._enrich_port_details looked a detail's TLS
posture up under the entry's first address the same way.

Both now use the detail's `ip`. A detail with none (IP mode, older rows) keeps
the entry's address, as before.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
for _p in (str(PROJECT_ROOT), str(PROJECT_ROOT / "recon")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.main_recon_modules import http_probe, tls_scan  # noqa: E402

IP_A, IP_B, IP_C = "192.0.2.10", "192.0.2.20", "192.0.2.30"
WWW, LEGACY = "www.example.com", "legacy.example.com"


def _d(port, ip=None):
    detail = {"port": port, "protocol": "tcp", "service": "unknown"}
    if ip:
        detail["ip"] = ip
    return detail


def _recon():
    return {"metadata": {"ip_mode": False}, "port_scan": {"by_host": {
        WWW: {"host": WWW, "ip": IP_A, "ports": [22, 2222],
              "port_details": [_d(22, IP_A), _d(22, IP_B), _d(2222, IP_B)]},
        LEGACY: {"host": LEGACY, "ip": IP_C, "ports": [22], "port_details": [_d(22)]},
    }}}


def _grab(recon):
    grabbed = []

    def grab(target, *_a, **_k):
        grabbed.append(target)
        address, port, host = target
        return {"host": host, "ip": address if address != host else None, "port": port,
                "banner": f"SSH-2.0-{address}", "service": "ssh", "version": f"v-{address}"}

    with mock.patch.object(http_probe, "grab_banner_for_target", side_effect=grab):
        http_probe.run_banner_grab(recon, {"BANNER_GRAB_THREADS": 1})
    return sorted(grabbed)


def test_the_banner_grab_connects_to_the_address_each_port_is_on():
    assert _grab(_recon()) == [(IP_A, 22, WWW), (IP_B, 22, WWW), (IP_B, 2222, WWW),
                               (IP_C, 22, LEGACY)]


def test_each_detail_takes_its_own_addresss_banner():
    recon = _recon()
    _grab(recon)
    banners = {(d.get("ip"), d["port"]): d.get("banner")
               for e in recon["port_scan"]["by_host"].values() for d in e["port_details"]}
    assert banners == {(IP_A, 22): f"SSH-2.0-{IP_A}", (IP_B, 22): f"SSH-2.0-{IP_B}",
                       (IP_B, 2222): f"SSH-2.0-{IP_B}", (None, 22): f"SSH-2.0-{IP_C}"}


def _cert(cn):
    return {"probe_status": True, "tls_version": "tls13", "cipher": "TLS_AES_128_GCM_SHA256",
            "subject_cn": cn, "issuer_cn": "Lab CA", "expired": False, "self_signed": False,
            "mismatched": False}


def test_tls_posture_is_read_under_the_details_address():
    combined = {"port_scan": {"by_host": {
        WWW: {"host": WWW, "ip": IP_A, "port_details": [_d(443, IP_A), _d(443, IP_B)]},
        LEGACY: {"host": LEGACY, "ip": IP_C, "port_details": [_d(443)]},
    }}}
    tls_scan._enrich_port_details(combined, {f"{IP_A}:443": _cert("a.example.com"),
                                             f"{IP_B}:443": _cert("b.example.com"),
                                             f"{IP_C}:443": _cert("c.example.com")})
    seen = {(d.get("ip"), d["port"]): d["tls"]["subject_cn"]
            for e in combined["port_scan"]["by_host"].values() for d in e["port_details"]}
    assert seen == {(IP_A, 443): "a.example.com", (IP_B, 443): "b.example.com",
                    (None, 443): "c.example.com"}

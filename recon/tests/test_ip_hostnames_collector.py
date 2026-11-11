"""The hostname collector of an IP-mode run (P3, design §3 and §5.2).

Every source that sees a name on a target address becomes one candidate per
name, bound to the target IPs it was observed on (`ips_seen`, one entry per
name across IPs: B-27), normalised by the selection rule's own check 1,
with `cert_covers` (a live certificate on a target IP covers the name) and
`org_domain` (its registrable domain). A wildcard SAN is never a name: it only
covers the names under it. An address outside the target list binds nothing.

Pure data in, data out: no DNS, no network. Documentation ranges (RFC 5737 /
RFC 3849) and reserved names only.
"""
from __future__ import annotations

import pytest

from recon.helpers import ip_hostnames as ih

T1, T2, V6, FOREIGN = "203.0.113.10", "203.0.113.11", "2001:db8::10", "198.51.100.7"


def _recon(**parts):
    return {"metadata": {"ip_mode": True, "expanded_ips": [T1, T2, V6]}, **parts}


def _names(candidates):
    return sorted(candidates)


# ---------------------------------------------------------------------------
# One test per source
# ---------------------------------------------------------------------------

def test_ptr_answers_from_group_1():
    got = ih.collect(_recon(ip_hostnames={"ptr": {T1: ["web.example.com", "app.example.com"]}}))
    assert _names(got) == ["app.example.com", "web.example.com"]
    assert got["web.example.com"]["ips_seen"] == [T1]
    assert got["web.example.com"]["sources"] == ["ptr"]
    assert got["web.example.com"]["seen_on"][T1]["sources"] == ["ptr"]


def test_shodan_reverse_dns_and_internetdb_hostnames():
    got = ih.collect(_recon(shodan={
        "reverse_dns": {T1: ["rdns.example.com"]},
        "hosts": [{"ip": T2, "hostnames": ["idb.example.net"], "source": "internetdb"},
                  {"ip": T1, "source": "shodan_api"}, "not a host"],
    }))
    assert got["rdns.example.com"]["sources"] == ["shodan_rdns"]
    assert got["idb.example.net"]["sources"] == ["shodan_hostnames"]
    assert got["idb.example.net"]["ips_seen"] == [T2]


def test_otx_passive_dns_keeps_first_and_last():
    got = ih.collect(_recon(otx={"ip_reports": [
        {"ip": T1, "passive_dns": [
            {"hostname": "old.example.com", "first": "2025-02-01T10:00:00", "last": "2026-10-30T08:00:00"},
            "junk"]},
        {"ip": T2, "passive_dns_hostnames": ["legacy.example.com"]},
        "junk",
    ]}))
    old = got["old.example.com"]
    assert old["sources"] == ["otx_passive_dns"]
    assert (old["first_seen"], old["last_seen"]) == ("2025-02-01", "2026-10-30")
    assert old["seen_on"][T1]["first_seen"] == "2025-02-01"
    assert got["legacy.example.com"]["first_seen"] is None


def test_censys_reverse_dns_and_certificate_names():
    got = ih.collect(_recon(censys={"hosts": [{
        "ip": T1, "last_updated": "2026-09-01T00:00:00Z",
        "reverse_dns_names": ["c-rdns.example.com"],
        "services": [{"port": 443, "tls": {"subject_cn": "cn.example.com",
                                           "san": ["cn.example.com", "*.wild.example.com"]}},
                     {"port": 80}, "junk"],
    }]}))
    assert got["c-rdns.example.com"]["sources"] == ["censys_rdns"]
    assert got["c-rdns.example.com"]["last_seen"] == "2026-09-01"
    assert got["cn.example.com"]["sources"] == ["censys_cert"]
    assert "wild.example.com" not in got


def test_fofa_host_domain_cname_and_certificate_cn():
    got = ih.collect(_recon(fofa={"results": [{
        "ip": T1, "host": "https://shop.example.org:8443", "domain": "example.org",
        "cname": "edge.cdn.example.net", "certs_subject_cn": "shop.example.org",
        "lastupdatetime": "2026-08-01 12:00:00"}, "junk"]}))
    assert got["shop.example.org"]["sources"] == ["fofa_cert", "fofa_host"]
    assert got["example.org"]["sources"] == ["fofa_domain"]
    assert got["edge.cdn.example.net"]["sources"] == ["fofa_cname"]
    assert got["example.org"]["last_seen"] == "2026-08-01"


def test_netlas_host_that_is_a_name():
    got = ih.collect(_recon(netlas={"results": [
        {"ip": T1, "host": "netlas.example.com"},
        {"ip": T1, "host": T1},           # an address is no name
    ]}))
    assert _names(got) == ["netlas.example.com"]
    assert got["netlas.example.com"]["sources"] == ["netlas_host"]


def test_zoomeye_hostname_and_rdns():
    got = ih.collect(_recon(zoomeye={"results": [
        {"ip": T2, "hostname": "ze.example.com", "rdns": "ze-rdns.example.com",
         "update_time": "2026-03-01T12:00:00"}]}))
    assert got["ze.example.com"]["sources"] == ["zoomeye_hostname"]
    assert got["ze-rdns.example.com"]["sources"] == ["zoomeye_rdns"]
    assert got["ze.example.com"]["last_seen"] == "2026-03-01"


def test_tlsx_certificate_on_the_scanned_ip():
    got = ih.collect(_recon(tlsx={"by_target": {
        f"{T1}:443": {"scanned_ip": T1, "subject_cn": "tls.example.com",
                      "san": ["tls.example.com", "wild.example.com"],
                      "san_raw": ["tls.example.com", "*.wild.example.com"]},
        f"{T2}:993": {"ip": T2, "san": ["mail.example.com"]},
        "junk": "junk",
    }}))
    assert got["tls.example.com"]["sources"] == ["tlsx_cn", "tlsx_san"]
    # tlsx strips the wildcard from `san`; the raw list says it was one.
    assert "wild.example.com" not in got
    assert got["mail.example.com"]["ips_seen"] == [T2]


def test_httpx_certificate_and_redirects():
    got = ih.collect(_recon(http_probe={
        "by_url": {
            f"https://{T1}": {"host": T1, "ip": T1, "tls": {"certificate": {
                "subject_cn": "h.example.com", "san": ["h.example.com", "h2.example.com"]}}},
            f"http://{T2}": {"host": T2, "ip": None, "final_url": "https://moved.example.com/x",
                             "redirected_off_host": True},
            f"http://{T2}:8080": {"host": T2, "final_url": f"http://{T2}:8080/",
                                  "redirected_off_host": False},
            "junk": "junk",
        },
        "external_domains": [
            {"domain": "idp.example.net", "source": "http_probe_redirect",
             "redirect_from_url": f"https://{T1}/login"},
            {"domain": "far.example.net", "redirect_from_url": f"https://{FOREIGN}/"},
            {"domain": "nofrom.example.net"},
            "junk",
        ],
    }))
    assert got["h.example.com"]["sources"] == ["httpx_cn", "httpx_san"]
    assert got["h2.example.com"]["sources"] == ["httpx_san"]
    assert got["moved.example.com"]["sources"] == ["http_redirect"]
    assert got["moved.example.com"]["ips_seen"] == [T2]
    assert got["idp.example.net"]["ips_seen"] == [T1]
    assert "far.example.net" not in got and "nofrom.example.net" not in got


def test_ip_attribution_default_certificate():
    got = ih.collect(_recon(ip_attribution={"by_ip": {
        T1: {"ownership": "unknown", "default_cert_names": ["default.example.com", "*.example.com"]},
        T2: {"ownership": "unknown"}, "junk": "junk"}}))
    assert _names(got) == ["default.example.com"]
    assert got["default.example.com"]["sources"] == ["attribution_cert"]


# ---------------------------------------------------------------------------
# Binding, normalisation, dedupe
# ---------------------------------------------------------------------------

def test_a_name_seen_on_an_address_outside_the_targets_is_not_a_candidate():
    got = ih.collect(_recon(shodan={"reverse_dns": {FOREIGN: ["foreign.example.com"],
                                                    T1: ["here.example.com"]}}))
    assert _names(got) == ["here.example.com"]


def test_a_certificate_on_an_address_outside_the_targets_names_and_covers_nothing():
    got = ih.collect(_recon(
        ip_hostnames={"ptr": {T1: ["x.example.com"]}},
        tlsx={"by_target": {f"{FOREIGN}:443": {"scanned_ip": FOREIGN, "subject_cn": "x.example.com",
                                               "san_raw": ["foreign.example.com"]}}},
    ))
    assert _names(got) == ["x.example.com"]
    assert got["x.example.com"]["cert_covers"] is False


def test_an_address_in_any_spelling_binds_to_the_listed_target():
    got = ih.collect(_recon(shodan={"reverse_dns": {"2001:DB8:0::10": ["v6.example.com"],
                                                    f"[{V6}]": ["v6b.example.com"]}}))
    assert got["v6.example.com"]["ips_seen"] == [V6]
    assert got["v6b.example.com"]["ips_seen"] == [V6]


def test_a_run_without_a_target_list_binds_nothing():
    got = ih.collect({"metadata": {"ip_mode": True},
                      "shodan": {"reverse_dns": {T1: ["here.example.com"]}}})
    assert got == {}


@pytest.mark.parametrize("raw, expected", [
    ("WWW.Example.COM.", "www.example.com"),
    ("https://www.example.com:8443/path", "www.example.com"),
    ("  app.example.com  ", "app.example.com"),
    ("*.example.com", None),
    ("*example.com", None),
    ("203.0.113.10", None),
    ("2001:db8::10", None),
    ("203-0-113-10", None),
    ("ip-targets.cmabcdefghijklmn", None),
    ("localhost", None),
    ("under_score.example.com", None),
    ("mail@example.com", None),
    ("", None),
    (None, None),
    (42, None),
])
def test_candidate_name_normalises_like_the_rule(raw, expected):
    assert ih.candidate_name(raw) == expected


def test_one_candidate_per_name_across_ips_and_sources():
    got = ih.collect(_recon(
        ip_hostnames={"ptr": {T1: ["shared.example.com"], T2: ["SHARED.example.com."]}},
        shodan={"reverse_dns": {T1: ["shared.example.com"]}},
    ))
    shared = got["shared.example.com"]
    assert shared["ips_seen"] == [T1, T2]
    assert shared["sources"] == ["ptr", "shodan_rdns"]
    assert shared["seen_on"][T1]["sources"] == ["ptr", "shodan_rdns"]
    assert shared["seen_on"][T2]["sources"] == ["ptr"]


def test_dates_widen_across_sources_and_ips():
    got = ih.collect(_recon(otx={"ip_reports": [
        {"ip": T1, "passive_dns": [{"hostname": "d.example.com", "first": "2024-01-02", "last": "2024-05-01"}]},
        {"ip": T1, "passive_dns": [{"hostname": "d.example.com", "first": "2023-06-07", "last": "2025-01-01"}]},
        {"ip": T2, "passive_dns": [{"hostname": "d.example.com", "first": "not a date", "last": ""}]},
    ]}))
    d = got["d.example.com"]
    assert (d["first_seen"], d["last_seen"]) == ("2023-06-07", "2025-01-01")
    assert d["seen_on"][T2]["first_seen"] is None


# ---------------------------------------------------------------------------
# org_domain and cert_covers
# ---------------------------------------------------------------------------

def test_org_domain_is_the_registrable_domain():
    got = ih.collect(_recon(ip_hostnames={"ptr": {T1: ["a.b.example.co.uk", "shop.example.com"]}}))
    assert got["a.b.example.co.uk"]["org_domain"] == "example.co.uk"
    assert got["shop.example.com"]["org_domain"] == "example.com"


def test_a_public_suffix_has_no_org_domain():
    got = ih.collect(_recon(ip_hostnames={"ptr": {T1: ["co.uk"]}}))
    assert got["co.uk"]["org_domain"] is None


def test_cert_covers_by_exact_name_and_by_one_wildcard_level():
    got = ih.collect(_recon(
        ip_hostnames={"ptr": {T1: ["exact.example.com", "x.wild.example.com", "y.x.wild.example.com"],
                              T2: ["exact.example.com"]}},
        tlsx={"by_target": {f"{T1}:443": {"scanned_ip": T1, "subject_cn": "exact.example.com",
                                          "san_raw": ["*.wild.example.com"]}}},
    ))
    exact = got["exact.example.com"]
    assert exact["cert_covers"] is True
    assert exact["seen_on"][T1]["cert_covers"] is True
    # The certificate is on T1: T2 shows the name but no certificate for it.
    assert exact["seen_on"][T2]["cert_covers"] is False
    assert got["x.wild.example.com"]["cert_covers"] is True
    assert got["y.x.wild.example.com"]["cert_covers"] is False


def test_only_live_certificates_cover_a_name():
    # Censys saw this certificate on the IP once; nothing shows it is served now.
    got = ih.collect(_recon(
        ip_hostnames={"ptr": {T1: ["c.example.com"]}},
        censys={"hosts": [{"ip": T1, "services": [{"tls": {"subject_cn": "c.example.com"}}]}]},
    ))
    assert got["c.example.com"]["cert_covers"] is False


def test_httpx_and_attribution_certificates_cover_names():
    got = ih.collect(_recon(
        ip_hostnames={"ptr": {T1: ["one.example.com"], T2: ["two.example.com"]}},
        http_probe={"by_url": {f"https://{T1}": {"ip": T1, "tls": {"certificate": {"san": ["one.example.com"]}}}}},
        ip_attribution={"by_ip": {T2: {"default_cert_names": ["*.example.com"]}}},
    ))
    assert got["one.example.com"]["cert_covers"] is True
    assert got["two.example.com"]["cert_covers"] is True


def test_the_sources_lists_are_sorted_and_json_ready():
    got = ih.collect(_recon(ip_hostnames={"ptr": {T2: ["n.example.com"], T1: ["n.example.com"]}}))
    n = got["n.example.com"]
    assert n["ips_seen"] == [T1, T2]
    assert list(n["seen_on"]) == [T1, T2]
    assert all(isinstance(v, list) for v in (n["sources"], n["ips_seen"]))

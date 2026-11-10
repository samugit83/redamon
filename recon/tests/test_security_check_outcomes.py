"""A security check that reached no verdict keeps its finding (R-24, R-36, R-37).

A DNS, Redis or SMTP check that times out has learned nothing, yet it used to
return "no finding", so the end-of-run prune deleted the real finding with its
triage. Each of these checks now ends in a finding, clean, or unknown, and
records the hosts it reached a verdict on for its own finding type
(`circuit_breaker.note_checked`, design decision D1). The prune deletes a stale
finding of that type only on those hosts; every other security_check type
prunes exactly as before, and a check switched off by configuration is pruned
normally (README "Degraded vs. switched off").

DNS, sockets and the graph are mocked. `FakeGraph` records the prune calls and
`_survivors` applies them to a few stored findings the way
`prune_unseen_findings` does (the Cypher itself is proven in
tests/test_positive_prune_graph_live.py). Names are example.com / .test and
addresses RFC 5737.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import dns.resolver
import dns.xfr
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from graph_db.mixins import base_mixin  # noqa: E402
from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers import org_work  # noqa: E402
from recon.helpers import security_checks as sc  # noqa: E402

ORG = "example.com"
ORG2 = "example.org"
NS_IP = "192.0.2.53"
REDIS_IP = "198.51.100.10"
SMTP_IP = "198.51.100.25"
DNS_ON = {"spf_missing": True, "dmarc_missing": True, "dnssec_missing": True,
          "zone_transfer": True}


# ---------------------------------------------------------------------------
# The stored findings and what the prune does to them
# ---------------------------------------------------------------------------

def _dns_finding(check, org=ORG):
    # What the security_check writer stores for a domain-level finding.
    return {"source": "security_check", "type": check, "url": "", "matched_at": "",
            "domain": org}


HEADER = {"source": "security_check", "type": "missing_coop",
          "url": f"https://www.{ORG}", "matched_at": f"https://www.{ORG}"}
REDIS = {"source": "security_check", "type": "redis_no_auth", "url": "",
         "matched_ip": REDIS_IP, "matched_at": f"{REDIS_IP}:6379"}
SMTP = {"source": "security_check", "type": "smtp_open_relay", "url": "",
        "matched_ip": SMTP_IP, "matched_at": f"{SMTP_IP}:25"}


def _hostnames(finding):
    names = set()
    for field in base_mixin._KEEP_HOST_FIELDS:
        value = str(finding.get(field) or "").lower()
        if "://" in value:
            value = value.split("://", 1)[1]
        value = value.split("/", 1)[0]
        if value:
            names.add(cb.hostname_of(value))
    return names


def _prunes(call, finding):
    if finding["source"] not in call["sources"]:
        return False
    if call.get("types") is not None and finding["type"] not in call["types"]:
        return False
    if call.get("exclude_types") is not None and finding["type"] in call["exclude_types"]:
        return False
    names = _hostnames(finding)
    if names & set(call.get("keep_hosts") or ()):
        return False
    if call.get("only_hosts") is not None and not names & set(call["only_hosts"]):
        return False
    return True


class FakeGraph:
    def __init__(self):
        self.prunes = []

    def __call__(self, *a, **kw):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def verify_connection(self):
        return True

    def backfill_passive_cve_hosts(self, user_id, project_id):
        return 0

    def backfill_security_check_domains(self, user_id, project_id):
        return 0

    def prune_unseen_findings(self, user_id, project_id, sources, since, **kwargs):
        self.prunes.append({"sources": list(sources), **kwargs})
        return {"pruned": 0, "stale": 0, "revived": 0}


@pytest.fixture
def recon_main(monkeypatch):
    stub = {
        'TARGET_DOMAIN': ORG, 'SUBDOMAIN_LIST': [], 'IP_MODE': False, 'TARGET_IPS': [],
        'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['domain_discovery', 'vuln_scan'],
        'UPDATE_GRAPH_DB': True, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        rm._RUN_STARTED_AT = "2026-01-01T00:00:00+00:00"
        rm._COVERAGE_WRITE_FAILED = False
        rm._RUN_ORGS.clear()
        yield rm
        rm._RUN_ORGS.clear()


@pytest.fixture
def graph(monkeypatch):
    fake = FakeGraph()
    monkeypatch.setattr("graph_db.Neo4jClient", fake)
    return fake


def _survivors(recon_main, graph, *findings):
    recon_main._prune_recon_findings()
    assert graph.prunes, "the prune ran"
    return [f for f in findings if not any(_prunes(c, f) for c in graph.prunes)]


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

class _Rdata:
    def __init__(self, text):
        self.text = text
        self.target = text
        self.address = text

    def __str__(self):
        return self.text

    def to_text(self):
        return self.text


def _timeout():
    return dns.resolver.LifetimeTimeout(timeout=5.0, errors=[])


def _resolver(table):
    """dns.resolver.resolve stand-in: a list of answers, or an exception to
    raise; a name and type not in the table does not exist."""
    asked = []

    def resolve(name, rtype, *a, **k):
        asked.append((str(name), rtype))
        outcome = table.get((str(name), rtype), dns.resolver.NXDOMAIN)
        if isinstance(outcome, BaseException):
            raise outcome
        if isinstance(outcome, type) and issubclass(outcome, BaseException):
            raise outcome()
        return [_Rdata(t) for t in outcome]

    return resolve, asked


def _clean_zone(org=ORG, override=None):
    table = {
        (org, "TXT"): ['"v=spf1 -all"'],
        (f"_dmarc.{org}", "TXT"): ['"v=DMARC1; p=reject"'],
        (org, "DNSKEY"): ["257 3 13 AAAA"],
        (org, "NS"): dns.resolver.NoAnswer,
    }
    table.update(override or {})
    return table


def _dns_run(monkeypatch, table, enabled=None, org=ORG, **kwargs):
    resolve, asked = _resolver(table)
    monkeypatch.setattr(sc.dns.resolver, "resolve", resolve)
    return sc.run_dns_checks(org, dict(enabled or DNS_ON), timeout=1, **kwargs), asked


class TestDnsOutcomes:
    def test_a_dmarc_timeout_keeps_the_org_s_dmarc_finding(self, monkeypatch, recon_main, graph):
        findings, _ = _dns_run(monkeypatch, _clean_zone(override={(f"_dmarc.{ORG}", "TXT"): _timeout()}))
        assert findings == []
        stale_spf = _dns_finding("spf_missing")
        dmarc = _dns_finding("dmarc_missing")
        assert _survivors(recon_main, graph, dmarc, stale_spf, HEADER) == [dmarc], (
            "the timed-out check keeps its finding; SPF answered and the header "
            "finding was not reported, so both prune")

    def test_no_nameservers_is_no_verdict_either(self, monkeypatch, recon_main, graph):
        _dns_run(monkeypatch, _clean_zone(override={(ORG, "TXT"): dns.resolver.NoNameservers()}))
        spf = _dns_finding("spf_missing")
        assert _survivors(recon_main, graph, spf) == [spf]

    def test_nxdomain_on_dmarc_is_a_finding(self, monkeypatch):
        findings, _ = _dns_run(monkeypatch, _clean_zone(override={(f"_dmarc.{ORG}", "TXT"): dns.resolver.NXDOMAIN}))
        assert [f["type"] for f in findings] == ["dmarc_missing"]
        assert findings[0]["domain"] == ORG

    def test_a_clean_answer_prunes_the_stale_finding_on_that_org_only(self, monkeypatch, recon_main, graph):
        _dns_run(monkeypatch, _clean_zone())
        here, elsewhere = _dns_finding("dmarc_missing"), _dns_finding("dmarc_missing", ORG2)
        assert _survivors(recon_main, graph, here, elsewhere) == [elsewhere], (
            "only the org the run checked is pruned")

    def test_the_timeout_is_a_coverage_gap(self, monkeypatch):
        _dns_run(monkeypatch, _clean_zone(override={(f"_dmarc.{ORG}", "TXT"): _timeout()}))
        report = cb.coverage_report()
        (gap,) = report.gaps
        assert gap["source"] == "security_check"
        assert "dmarc_missing" in gap["reason"] and ORG in gap["reason"]
        assert "security_check" not in report.degraded_sources
        assert report.checked_hostnames("security_check", "dmarc_missing") == ()
        assert report.checked_hostnames("security_check", "spf_missing") == (ORG,)

    def test_a_switched_off_check_prunes_as_before(self, monkeypatch, recon_main, graph):
        _dns_run(monkeypatch, _clean_zone(), enabled={**DNS_ON, "dnssec_missing": False})
        dnssec = _dns_finding("dnssec_missing")
        assert _survivors(recon_main, graph, dnssec, HEADER) == []


# ---------------------------------------------------------------------------
# Redis and SMTP
# ---------------------------------------------------------------------------

class _Sock:
    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = []

    def recv(self, _n):
        reply = self.replies.pop(0) if self.replies else b""
        if isinstance(reply, BaseException):
            raise reply
        return reply

    def send(self, data):
        self.sent.append(data)
        return len(data)

    def sendall(self, data):
        self.sent.append(data)

    def settimeout(self, _t):
        pass

    def close(self):
        pass


#: An absent check defaults to on; database_exposed would also fire on 6379.
PORT_CHECKS_UNDER_TEST = {"redis_no_auth": True, "smtp_open_relay": True,
                          "admin_port_exposed": False, "database_exposed": False,
                          "kubernetes_api_exposed": False}


def _ports_run(by_port, ip, ports, enabled=None):
    def connect(address, timeout=None, *a, **k):
        replies = by_port.get(address[1])
        if isinstance(replies, BaseException):
            raise replies
        if replies is None:
            raise ConnectionRefusedError("refused")
        return _Sock(replies)

    port_scan = {"by_ip": {ip: {"ip": ip, "hostnames": [], "ports": list(ports)}}}
    with mock.patch.object(sc.socket, "create_connection", side_effect=connect):
        return sc.run_port_service_checks(
            {"port_scan": port_scan},
            enabled or PORT_CHECKS_UNDER_TEST,
            timeout=1, max_workers=1)


class TestPortOutcomes:
    def test_a_redis_reply_timeout_keeps_its_finding(self, recon_main, graph):
        assert _ports_run({6379: [TimeoutError("timed out")]}, REDIS_IP, [6379]) == []
        assert _survivors(recon_main, graph, REDIS, HEADER) == [REDIS]

    def test_a_redis_connect_timeout_keeps_its_finding(self, recon_main, graph):
        _ports_run({6379: TimeoutError("timed out")}, REDIS_IP, [6379])
        assert _survivors(recon_main, graph, REDIS) == [REDIS]

    def test_a_refused_redis_connection_is_clean(self, recon_main, graph):
        assert _ports_run({}, REDIS_IP, [6379]) == []
        assert _survivors(recon_main, graph, REDIS) == []

    def test_redis_asking_for_auth_is_clean(self, recon_main, graph):
        _ports_run({6379: [b"-NOAUTH Authentication required.\r\n"]}, REDIS_IP, [6379])
        assert _survivors(recon_main, graph, REDIS) == []

    def test_redis_answering_pong_is_a_finding(self):
        (finding,) = _ports_run({6379: [b"+PONG\r\n"]}, REDIS_IP, [6379])
        assert finding["type"] == "redis_no_auth" and finding["ip"] == REDIS_IP

    def test_an_smtp_timeout_keeps_its_finding(self, recon_main, graph):
        _ports_run({25: [b"220 mx ESMTP\r\n", b"250 hello\r\n", TimeoutError("timed out")]},
                   SMTP_IP, [25])
        assert _survivors(recon_main, graph, SMTP) == [SMTP]

    def test_an_smtp_temporary_refusal_keeps_its_finding(self, recon_main, graph):
        _ports_run({25: [b"220 mx ESMTP\r\n", b"250 hello\r\n", b"250 ok\r\n",
                         b"451 4.7.1 greylisted, try again later\r\n"]}, SMTP_IP, [25])
        assert _survivors(recon_main, graph, SMTP) == [SMTP]

    def test_an_smtp_relay_denied_is_clean(self, recon_main, graph):
        _ports_run({25: [b"220 mx ESMTP\r\n", b"250 hello\r\n", b"250 ok\r\n",
                         b"554 5.7.1 relay access denied\r\n"]}, SMTP_IP, [25])
        assert _survivors(recon_main, graph, SMTP) == []

    def test_an_smtp_open_relay_is_a_finding(self):
        (finding,) = _ports_run({25: [b"220 mx ESMTP\r\n", b"250 hello\r\n", b"250 ok\r\n",
                                      b"250 accepted\r\n"]}, SMTP_IP, [25])
        assert finding["type"] == "smtp_open_relay"


class TestPortCoverage:
    def test_a_port_the_scan_found_closed_is_clean(self, recon_main, graph):
        """The probe needs the port open; the scan saw the IP without it."""
        _ports_run({}, REDIS_IP, [22])
        assert _survivors(recon_main, graph, REDIS) == []

    def test_an_ip_the_run_did_not_reach_keeps_its_finding(self, recon_main, graph):
        _ports_run({6379: [b"-NOAUTH Authentication required.\r\n"]}, "198.51.100.99", [6379])
        assert _survivors(recon_main, graph, REDIS) == [REDIS]

    def test_a_cdn_edge_ip_is_not_checked(self, recon_main, graph):
        port_scan = {"by_ip": {REDIS_IP: {"ip": REDIS_IP, "ports": [6379]}}}
        with mock.patch.object(sc.socket, "create_connection") as connect:
            sc.run_port_service_checks({"port_scan": port_scan}, PORT_CHECKS_UNDER_TEST,
                                       timeout=1, max_workers=1, cdn_ips={REDIS_IP})
        connect.assert_not_called()
        assert _survivors(recon_main, graph, REDIS) == [REDIS]

    def test_a_switched_off_probe_prunes_as_before(self, recon_main, graph):
        _ports_run({}, REDIS_IP, [6379], enabled={**PORT_CHECKS_UNDER_TEST, "redis_no_auth": False})
        assert _survivors(recon_main, graph, REDIS, SMTP) == [SMTP]


class TestThePruneCalls:
    def test_the_other_security_check_types_get_one_source_level_call(self, recon_main, graph):
        cb.note_checked("security_check", hosts=[ORG], checks=["spf_missing", "dmarc_missing"])
        recon_main._prune_recon_findings()
        remainder = [p for p in graph.prunes if "exclude_types" in p]
        assert remainder == [{"sources": ["security_check"], "keep_hosts": (),
                              "exclude_types": ("dmarc_missing", "spf_missing")}]
        assert not any("security_check" in p["sources"] for p in graph.prunes
                       if "only_hosts" not in p and "exclude_types" not in p)

    def test_a_whole_source_record_needs_no_remainder(self, recon_main, graph):
        cb.note_checked("nuclei", hosts=[ORG])
        recon_main._prune_recon_findings()
        assert not [p for p in graph.prunes if "exclude_types" in p]

    def test_a_failed_org_backfill_prunes_no_dns_type(self, recon_main, graph, monkeypatch, capsys):
        def boom(*a):
            raise RuntimeError("backfill failed")
        monkeypatch.setattr(graph, "backfill_security_check_domains", boom)
        cb.note_checked("security_check", hosts=[ORG], checks=["spf_missing"])
        cb.note_checked("security_check", hosts=[REDIS_IP], checks=["redis_no_auth"])
        spf = _dns_finding("spf_missing")
        assert _survivors(recon_main, graph, spf, REDIS, HEADER) == [spf]
        assert "DNS security findings are not pruned this run" in capsys.readouterr().out

    def test_the_backfill_runs_only_for_a_dns_prune(self, recon_main, graph, monkeypatch):
        called = []
        monkeypatch.setattr(graph, "backfill_security_check_domains", lambda *a: called.append(a))
        cb.note_checked("security_check", hosts=[REDIS_IP], checks=["redis_no_auth"])
        recon_main._prune_recon_findings()
        assert called == []
        cb.note_checked("security_check", hosts=[ORG], checks=["dmarc_missing"])
        recon_main._prune_recon_findings()
        assert called == [("u1", "p1")]

    def test_a_no_verdict_gap_is_a_valid_coverage_token(self, monkeypatch):
        import re
        _dns_run(monkeypatch, _clean_zone(override={(ORG, "DNSKEY"): _timeout()}))
        (gap,) = cb.coverage_report().gaps
        assert re.fullmatch(r"[a-z0-9_]{1,64}", gap["source"])
        assert gap["module"] == "security_checks" and gap["skipped"] == 1


# ---------------------------------------------------------------------------
# R-37: an org whose DNS checks ran in no group
# ---------------------------------------------------------------------------

class TestAnOrgNoGroupChecked:
    def test_dns_checks_switched_off_cut_nothing(self, recon_main, graph, monkeypatch):
        monkeypatch.setitem(recon_main._settings, "SECURITY_CHECK_SPF_MISSING", False)
        monkeypatch.setitem(recon_main._settings, "SECURITY_CHECK_DMARC_MISSING", False)
        monkeypatch.setitem(recon_main._settings, "SECURITY_CHECK_DNSSEC_MISSING", False)
        monkeypatch.setitem(recon_main._settings, "SECURITY_CHECK_ZONE_TRANSFER", False)
        recon_main._note_run_org(ORG)
        dmarc = _dns_finding("dmarc_missing")
        assert _survivors(recon_main, graph, dmarc, HEADER) == []
        assert "security_check" not in cb.coverage_report().degraded_sources

    def test_only_the_unchecked_org_keeps_its_dns_findings(self, recon_main, graph, monkeypatch):
        recon_main._note_run_org(ORG)
        recon_main._note_run_org(ORG2)
        assert sc._dns_check_claims([ORG2], None) == [ORG2]
        _dns_run(monkeypatch, _clean_zone(ORG2), org=ORG2)
        kept, checked = _dns_finding("dmarc_missing"), _dns_finding("dmarc_missing", ORG2)
        assert _survivors(recon_main, graph, kept, checked, HEADER) == [kept]
        assert "security_check" not in cb.coverage_report().degraded_sources


# ---------------------------------------------------------------------------
# R-36: the zone transfer reaches the nameserver's address
# ---------------------------------------------------------------------------

class _Zone:
    nodes = {"@": 1, "www": 1, "mail": 1}


def _xfr_run(monkeypatch, outcome_by_address, table=None, **kwargs):
    sent = []

    def xfr(where, zone, *a, **k):
        sent.append((where, str(zone)))
        return where

    def from_xfr(where, *a, **k):
        outcome = outcome_by_address.get(where, dns.xfr.TransferError(5))
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(sc.dns.query, "xfr", xfr)
    monkeypatch.setattr(sc.dns.zone, "from_xfr", from_xfr)
    zone = _clean_zone(override={(ORG, "NS"): [f"ns1.{ORG}."], (f"ns1.{ORG}", "A"): [NS_IP],
                                 (f"ns1.{ORG}", "AAAA"): dns.resolver.NoAnswer})
    zone.update(table or {})
    findings, asked = _dns_run(monkeypatch, zone, enabled={"zone_transfer": True,
                                                            "spf_missing": False,
                                                            "dmarc_missing": False,
                                                            "dnssec_missing": False}, **kwargs)
    return findings, sent, asked


class TestZoneTransfer:
    def test_the_transfer_is_sent_to_the_nameserver_s_address(self, monkeypatch):
        findings, sent, _ = _xfr_run(monkeypatch, {NS_IP: _Zone()})
        assert sent == [(NS_IP, ORG)]
        (finding,) = findings
        assert finding["type"] == "zone_transfer" and finding["domain"] == ORG
        assert finding["nameserver"] == f"ns1.{ORG}"

    def test_a_refused_transfer_is_clean(self, monkeypatch, recon_main, graph):
        findings, sent, _ = _xfr_run(monkeypatch, {NS_IP: dns.xfr.TransferError(5)})
        assert findings == [] and sent == [(NS_IP, ORG)]
        assert _survivors(recon_main, graph, _dns_finding("zone_transfer")) == []

    def test_a_transfer_timeout_keeps_the_finding(self, monkeypatch, recon_main, graph):
        findings, _, _ = _xfr_run(monkeypatch, {NS_IP: dns.exception.Timeout()})
        assert findings == []
        axfr = _dns_finding("zone_transfer")
        assert _survivors(recon_main, graph, axfr) == [axfr]

    def test_an_roe_excluded_nameserver_address_is_never_sent_a_packet(self, monkeypatch):
        findings, sent, _ = _xfr_run(monkeypatch, {NS_IP: _Zone()},
                                     roe_excluded_hosts=["192.0.2.0/24"])
        assert sent == [] and findings == []

    def test_an_roe_excluded_nameserver_name_is_not_even_resolved(self, monkeypatch):
        findings, sent, asked = _xfr_run(monkeypatch, {NS_IP: _Zone()},
                                         roe_excluded_hosts=[f"ns1.{ORG}"])
        assert sent == [] and findings == []
        assert not [q for q in asked if q[0] == f"ns1.{ORG}"]

    def test_stealth_mode_turns_the_check_off(self):
        from recon.project_settings import apply_stealth_overrides
        settings = apply_stealth_overrides({"STEALTH_MODE": True, "SECURITY_CHECK_ZONE_TRANSFER": True})
        assert settings["SECURITY_CHECK_ZONE_TRANSFER"] is False

    def test_the_second_nameserver_is_asked_when_the_first_refuses(self, monkeypatch):
        ns2_ip = "192.0.2.54"
        findings, sent, _ = _xfr_run(
            monkeypatch, {NS_IP: dns.xfr.TransferError(5), ns2_ip: _Zone()},
            table={(ORG, "NS"): [f"ns1.{ORG}.", f"ns2.{ORG}.", f"ns3.{ORG}."],
                   (f"ns2.{ORG}", "A"): [ns2_ip], (f"ns2.{ORG}", "AAAA"): dns.resolver.NoAnswer,
                   (f"ns3.{ORG}", "A"): [NS_IP], (f"ns3.{ORG}", "AAAA"): dns.resolver.NoAnswer})
        assert sent == [(NS_IP, ORG), (ns2_ip, ORG)], "an address two names share is asked once"
        assert findings[0]["nameserver"] == f"ns2.{ORG}"

    def test_a_nameserver_that_does_not_resolve_is_no_verdict(self, monkeypatch, recon_main, graph):
        findings, sent, _ = _xfr_run(monkeypatch, {}, table={(f"ns1.{ORG}", "A"): _timeout()})
        assert findings == [] and sent == []
        axfr = _dns_finding("zone_transfer")
        assert _survivors(recon_main, graph, axfr) == [axfr]

    def test_an_ns_lookup_timeout_is_no_verdict(self, monkeypatch, recon_main, graph):
        _xfr_run(monkeypatch, {}, table={(ORG, "NS"): _timeout()})
        axfr = _dns_finding("zone_transfer")
        assert _survivors(recon_main, graph, axfr) == [axfr]

    def test_an_org_with_no_nameserver_is_clean(self, monkeypatch, recon_main, graph):
        findings, sent, _ = _xfr_run(monkeypatch, {}, table={(ORG, "NS"): dns.resolver.NoAnswer})
        assert findings == [] and sent == []
        assert _survivors(recon_main, graph, _dns_finding("zone_transfer")) == []

    def test_the_run_s_roe_list_reaches_the_transfer(self, monkeypatch):
        """run_security_checks hands its RoE list to the DNS checks."""
        sent = []
        monkeypatch.setattr(sc.dns.query, "xfr", lambda where, *a, **k: sent.append(where))
        monkeypatch.setattr(sc.dns.zone, "from_xfr", lambda *a, **k: _Zone())
        resolve, _ = _resolver(_clean_zone(override={
            (ORG, "NS"): [f"ns1.{ORG}."], (f"ns1.{ORG}", "A"): [NS_IP],
            (f"ns1.{ORG}", "AAAA"): dns.resolver.NoAnswer}))
        monkeypatch.setattr(sc.dns.resolver, "resolve", resolve)
        out = sc.run_security_checks({"domain": ORG, "dns": {"domain": {}, "subdomains": {}}},
                                     {"zone_transfer": True}, timeout=1,
                                     roe_excluded_hosts=["192.0.2.0/24"])
        assert sent == []
        assert out["security_checks"]["findings"] == []

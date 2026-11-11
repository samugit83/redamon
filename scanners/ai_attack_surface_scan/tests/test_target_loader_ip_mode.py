"""AI attack surface: IP-mode admission of the attack targets (P4, design §11).

The scanner attacks graph Endpoints by URL. In an IP-mode project an Endpoint
is a target only when its host is one of the project's target addresses (after
the RoE), or a hostname the run's selection rule scanned
(`Subdomain {source: 'ip_hostname_selection', ip_hostname_reason: 'scanned'}`)
that the project's CURRENT policy still admits (a narrowing, a restored
version or a failed marker leave such a name in the graph) and whose live
A/AAAA answer is still on the targets alone (recon_settings.ip_hostnames
address_verdict). A recorded name (an ExternalDomain) is never one. The run
config carries the project's IP mode, targets, RoE and policy; a config that
does not say, for a project whose graph is IP mode, is refused (fail closed).

The graph session and the resolver are fakes. Documentation ranges and
reserved names only.
"""
from __future__ import annotations

import json
import os
import socket
import unittest
from unittest.mock import MagicMock, patch

import config as cfgmod
import target_loader as tl
from config import RunConfig
from target_loader import Target

T1, T2, PRIV = "203.0.113.10", "203.0.113.11", "10.0.0.5"
APP, NARROWED, MOVED, OLD = "app.example.com", "legacy.example.net", "moved.example.com", "old.example.com"


class _Rows(list):
    def single(self):
        return self[0] if self else None


class _Row(dict):
    def data(self):
        return dict(self)


class _Session:
    """Answers the two scope queries and the Endpoint reads."""

    def __init__(self, scanned=(), ip_mode_root=True, endpoints=()):
        self.scanned, self.ip_mode_root, self.endpoints = list(scanned), ip_mode_root, list(endpoints)
        self.queries = []

    def run(self, cypher, **params):
        self.queries.append((cypher, params))
        if "is_mock" in cypher:
            return _Rows([_Row(n=1 if self.ip_mode_root else 0)])
        if "ip_hostname_selection" in cypher:
            return _Rows([_Row(name=n) for n in self.scanned])
        return _Rows([_Row(e) for e in self.endpoints])


def _endpoint(baseurl, path="/v1/chat"):
    return {"baseurl": baseurl, "path": path, "method": "POST", "ai_interface_type": "llm-chat",
            "ai_model_family_guess": None, "ai_model_ids": None, "ai_supports_tools": None,
            "ai_supports_streaming": None}


def _cfg(**over):
    base = dict(project_id="p1", user_id="u1", roe_confirmed=True, ip_mode=True,
                target_ips=["203.0.113.0/24", PRIV], roe_excluded_hosts=[],
                ip_hostname_mode="record_filter", ip_hostname_include=["*.example.com"],
                ip_hostname_exclude=[])
    base.update(over)
    return RunConfig(**base)


def _resolver(table):
    def getaddrinfo(host, *_a, **_k):
        if host not in table:
            raise socket.gaierror("no such name")
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))
                for ip in table[host]]
    return getaddrinfo


DNS = {APP: [T1], NARROWED: [T2], MOVED: ["198.51.100.7"], OLD: [T1]}
_ROE = "excluded by the rules of engagement"


class TestRunConfig(unittest.TestCase):
    def test_the_ip_mode_fields_are_parsed(self):
        data = {"ip_mode": True, "target_ips": ["203.0.113.0/24"], "roe_excluded_hosts": [T2],
                "ip_hostname_policy": {"mode": "scan_all", "include": [], "exclude": ["x.example.com"]}}
        with patch.dict(os.environ, {"AI_ATTACK_CONFIG_JSON": json.dumps(data)}, clear=False):
            cfg = cfgmod.load_config()
        self.assertIs(cfg.ip_mode, True)
        self.assertEqual(cfg.target_ips, ["203.0.113.0/24"])
        self.assertEqual(cfg.roe_excluded_hosts, [T2])
        self.assertEqual((cfg.ip_hostname_mode, cfg.ip_hostname_include, cfg.ip_hostname_exclude),
                         ("scan_all", [], ["x.example.com"]))

    def test_an_absent_or_unreadable_ip_mode_is_unknown(self):
        for data in ({}, {"ip_mode": "yes"}):
            with patch.dict(os.environ, {"AI_ATTACK_CONFIG_JSON": json.dumps(data)}, clear=False):
                self.assertIsNone(cfgmod.load_config().ip_mode)

    def test_unreadable_lists_are_empty_and_a_missing_policy_is_ip_only(self):
        data = {"ip_mode": False, "target_ips": "203.0.113.10", "ip_hostname_policy": "x"}
        with patch.dict(os.environ, {"AI_ATTACK_CONFIG_JSON": json.dumps(data)}, clear=False):
            cfg = cfgmod.load_config()
        self.assertEqual((cfg.target_ips, cfg.ip_hostname_mode), ([], "ip_only"))
        self.assertIsNone(cfg.ip_hostname_include)


class TestScopeFromTheRunConfig(unittest.TestCase):
    def test_a_domain_project_has_no_ip_mode_scope(self):
        self.assertIsNone(tl.ip_mode_scope(_Session(ip_mode_root=False), _cfg(ip_mode=None)))
        self.assertIsNone(tl.ip_mode_scope(_Session(), _cfg(ip_mode=False)))

    def test_an_ip_mode_project_without_the_fields_is_refused(self):
        with self.assertRaises(tl.ScopeRefused):
            tl.ip_mode_scope(_Session(ip_mode_root=True), _cfg(ip_mode=None))

    def test_an_ip_mode_config_without_targets_is_refused(self):
        with self.assertRaises(tl.ScopeRefused):
            tl.ip_mode_scope(_Session(), _cfg(target_ips=[]))

    def test_a_graph_that_cannot_say_is_refused_too(self):
        session = MagicMock()
        session.run.return_value.single.return_value = {"n": None}
        with self.assertRaises(tl.ScopeRefused):
            tl.ip_mode_scope(session, _cfg(ip_mode=None))
        session.run.return_value.single.return_value = None
        self.assertIsNone(tl.ip_mode_scope(session, _cfg(ip_mode=None)))

    def test_the_run_stops_before_any_target_on_a_refused_scope(self):
        import main
        driver = MagicMock()
        driver.session.return_value.__enter__.return_value = _Session(ip_mode_root=True)
        driver.session.return_value.__exit__.return_value = False
        from config import Bounds
        with patch.object(main, "load_config", return_value=_cfg(ip_mode=None, bounds=Bounds(judge_model="m"))), \
                patch.object(main, "make_driver", return_value=driver), \
                patch.object(main, "verify_connection", return_value=True), \
                patch.object(main, "load_targets") as load, patch("builtins.print"):
            self.assertEqual(main.run(), 1)
        load.assert_not_called()

    def test_the_scanned_names_are_read_tenant_scoped_with_the_reason(self):
        session = _Session(scanned=[APP])
        tl.ip_mode_scope(session, _cfg())
        cypher, params = next(q for q in session.queries if "ip_hostname_selection" in q[0])
        self.assertIn("Subdomain {user_id: $uid, project_id: $pid, source: 'ip_hostname_selection'}", cypher)
        self.assertIn("ip_hostname_reason = 'scanned'", cypher)
        self.assertEqual((params["uid"], params["pid"]), ("u1", "p1"))


class TestAdmission(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(socket, "getaddrinfo", side_effect=_resolver(DNS))
        patcher.start()
        self.addCleanup(patcher.stop)

    def _verdict(self, url, cfg=None, scanned=(APP, NARROWED, MOVED)):
        scope = tl.ip_mode_scope(_Session(scanned=scanned), cfg or _cfg())
        return scope.refusal(Target(baseurl=url, path="/v1/chat"))

    def test_a_target_address_is_admitted(self):
        self.assertIsNone(self._verdict(f"http://{T1}:8080"))
        self.assertIsNone(self._verdict(f"http://{PRIV}"))

    def test_an_address_outside_the_targets_or_excluded_is_refused(self):
        self.assertEqual(self._verdict("http://198.51.100.7"), "outside the target IPs")
        self.assertEqual(self._verdict(f"http://{T2}", _cfg(roe_excluded_hosts=["203.0.113.11/32"])),
                         "excluded by the rules of engagement")

    def test_a_scanned_name_the_current_policy_admits_is_admitted(self):
        self.assertIsNone(self._verdict(f"https://{APP}"))

    def test_a_recorded_name_is_never_loaded(self):
        self.assertEqual(self._verdict(f"https://{OLD}"), "not a hostname this project scans")

    def test_a_name_the_current_policy_no_longer_admits_is_refused(self):
        self.assertEqual(self._verdict(f"https://{NARROWED}"), "not a hostname this project scans")
        self.assertEqual(self._verdict(f"https://{APP}", _cfg(ip_hostname_mode="record_only")),
                         "not a hostname this project scans")
        self.assertEqual(self._verdict(f"https://{APP}", _cfg(ip_hostname_exclude=[APP])),
                         "not a hostname this project scans")

    def test_scan_all_admits_every_scanned_name(self):
        self.assertIsNone(self._verdict(f"https://{NARROWED}", _cfg(ip_hostname_mode="scan_all")))

    def test_an_unreadable_filter_admits_no_name(self):
        self.assertEqual(self._verdict(f"https://{APP}", _cfg(ip_hostname_exclude=["**.x"])),
                         "not a hostname this project scans")
        self.assertEqual(self._verdict(f"https://{APP}", _cfg(ip_hostname_include=None)),
                         "not a hostname this project scans")

    def test_a_scanned_name_whose_dns_moved_is_refused(self):
        self.assertEqual(self._verdict(f"https://{MOVED}", _cfg(ip_hostname_mode="scan_all")),
                         "resolves_outside_targets")

    def test_a_scanned_name_that_no_longer_resolves_is_refused(self):
        self.assertEqual(self._verdict("https://gone.example.com", _cfg(ip_hostname_mode="scan_all"),
                                       scanned=["gone.example.com"]), "no_current_resolution")

    def test_roe_entries_read_as_the_recon_matcher_reads_them(self):
        # The raw roeExcludedHosts the start route sends: scheme, port, path and
        # brackets are ignored, as everywhere else (roe_exclusion_vectors.json).
        for entry in ("203.0.113.11/", "203.0.113.11/admin", "http://203.0.113.11:8080/x"):
            self.assertEqual(self._verdict(f"http://{T2}", _cfg(roe_excluded_hosts=[entry])), _ROE, entry)
        for entry in (f"https://{APP}/", f"{APP}:443", "*.example.com/admin"):
            self.assertEqual(self._verdict(f"https://{APP}", _cfg(roe_excluded_hosts=[entry])), _ROE, entry)

    def test_the_roe_and_the_guardrail_apply_to_names(self):
        self.assertEqual(self._verdict(f"https://{APP}", _cfg(roe_excluded_hosts=["example.com"])),
                         "excluded by the rules of engagement")
        with patch.object(tl, "is_hard_blocked", return_value=(True, "gov")):
            self.assertEqual(self._verdict(f"https://{APP}"), "a protected government or public domain")

    def test_an_unparseable_url_is_refused(self):
        self.assertEqual(self._verdict("not a url"), "no host")


class TestLoadTargets(unittest.TestCase):
    def test_refused_endpoints_are_dropped_and_listed(self):
        session = _Session(scanned=[APP], endpoints=[_endpoint(f"https://{APP}"), _endpoint(f"https://{OLD}"),
                                                     _endpoint(f"http://{T1}")])
        with patch.object(socket, "getaddrinfo", side_effect=_resolver(DNS)), \
                patch("builtins.print") as printed:
            scope = tl.ip_mode_scope(session, _cfg())
            targets = tl.load_targets(session, "u1", "p1", scope=scope)
        self.assertEqual(sorted(t.baseurl for t in targets), [f"http://{T1}", f"https://{APP}"])
        lines = [c.args[0] for c in printed.call_args_list]
        self.assertIn(f"    [-] refused https://{OLD}/v1/chat: not a hostname this project scans", lines)

    def test_a_typed_custom_target_goes_through_the_same_admission(self):
        session = _Session(scanned=[APP])
        with patch.object(socket, "getaddrinfo", side_effect=_resolver(DNS)):
            scope = tl.ip_mode_scope(session, _cfg())
            targets = tl.load_targets(session, "u1", "p1", scope=scope, selected=[
                {"baseurl": "https://198.51.100.9", "path": "/chat", "custom": True},
                {"baseurl": f"https://{APP}", "path": "/chat", "custom": True}])
        self.assertEqual([t.baseurl for t in targets], [f"https://{APP}"])

    def test_without_a_scope_nothing_is_filtered(self):
        session = _Session(endpoints=[_endpoint("https://www.example.org")])
        self.assertEqual(len(tl.load_targets(session, "u1", "p1")), 1)


if __name__ == "__main__":
    unittest.main()

"""G-05: the AI attack-surface scanner never attacks the Kali sandbox pool.

The scanner runs on the host network, which reaches every per-user sandbox
bridge (10.214.0.0/16). A target there, typed as a custom URL or loaded from
the graph, is another person's sandbox: refused in a domain-mode run (which had
no target gate at all) and in an IP-mode run even when the project lists the
address. The graph session and the resolver are fakes. Documentation ranges and
reserved names only.
"""
from __future__ import annotations

import socket
import unittest
from unittest.mock import patch

import target_loader as tl
from config import RunConfig

POOL_IP, PUBLIC_IP = "10.214.0.4", "203.0.113.10"
SANDBOX_NAME, APP = "sbx.example.com", "app.example.com"
DNS = {SANDBOX_NAME: [POOL_IP], APP: [PUBLIC_IP]}


class _Rows(list):
    def single(self):
        return self[0] if self else None


class _Row(dict):
    def data(self):
        return dict(self)


class _Session:
    def __init__(self, scanned=(), endpoints=()):
        self.scanned, self.endpoints = list(scanned), list(endpoints)

    def run(self, cypher, **params):
        if "is_mock" in cypher:
            return _Rows([_Row(n=1)])
        if "ip_hostname_selection" in cypher:
            return _Rows([_Row(name=n) for n in self.scanned])
        if "baseurl: $baseurl" in cypher:
            return _Rows([])
        return _Rows([_Row(e) for e in self.endpoints])


def _endpoint(baseurl):
    return {"baseurl": baseurl, "path": "/v1/chat", "method": "POST", "ai_interface_type": "llm-chat",
            "ai_model_family_guess": None, "ai_model_ids": None, "ai_supports_tools": None,
            "ai_supports_streaming": None}


def _getaddrinfo(host, *_a, **_k):
    if host not in DNS:
        raise socket.gaierror("no such name")
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in DNS[host]]


class TestSandboxPool(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(socket, "getaddrinfo", side_effect=_getaddrinfo)
        patcher.start()
        self.addCleanup(patcher.stop)
        printer = patch("builtins.print")
        self.printed = printer.start()
        self.addCleanup(printer.stop)

    def test_a_domain_run_refuses_a_typed_pool_address_and_a_name_resolving_there(self):
        targets = tl.load_targets(_Session(), "u1", "p1", selected=[
            {"baseurl": f"http://{POOL_IP}:8000", "path": "/chat", "custom": True},
            {"baseurl": f"https://{SANDBOX_NAME}", "path": "/chat", "custom": True},
            {"baseurl": f"https://{APP}", "path": "/chat", "custom": True},
            {"baseurl": "https://gone.example.com", "path": "/chat", "custom": True}])
        self.assertEqual([t.baseurl for t in targets], [f"https://{APP}", "https://gone.example.com"])
        lines = " ".join(c.args[0] for c in self.printed.call_args_list)
        self.assertIn("Kali sandbox address pool", lines)

    def test_a_domain_run_refuses_graph_endpoints_in_the_pool(self):
        session = _Session(endpoints=[_endpoint(f"http://{POOL_IP}"), _endpoint(f"https://{APP}")])
        self.assertEqual([t.baseurl for t in tl.load_targets(session, "u1", "p1")], [f"https://{APP}"])

    def test_an_ip_mode_run_refuses_a_pool_address_its_project_lists(self):
        cfg = RunConfig(project_id="p1", user_id="u1", roe_confirmed=True, ip_mode=True,
                        target_ips=["10.214.0.0/24", "203.0.113.0/24"], roe_excluded_hosts=[],
                        ip_hostname_mode="ip_only", ip_hostname_include=None, ip_hostname_exclude=None)
        session = _Session(endpoints=[_endpoint(f"http://{POOL_IP}"), _endpoint(f"http://{PUBLIC_IP}")])
        scope = tl.ip_mode_scope(session, cfg)
        self.assertIsNotNone(scope._address_refusal(POOL_IP))
        targets = tl.load_targets(session, "u1", "p1", scope=scope)
        self.assertEqual([t.baseurl for t in targets], [f"http://{PUBLIC_IP}"])


if __name__ == "__main__":
    unittest.main()

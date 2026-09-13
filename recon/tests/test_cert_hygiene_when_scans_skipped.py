"""H2: certificate hygiene must survive the active-scan skip.

`should_skip_active_scans` returns True as soon as httpx found no live URL, and
it gates the entire vuln_scan module -- which is where `run_security_checks`,
and therefore every TLS-hygiene check, lives. A host serving TLS only on a
non-HTTP port (993/636) trips that skip by construction, so its certificates
were grabbed, stored, and then never evaluated. That is precisely the target
class tlsx was added for, so the most relevant case produced zero findings.

These tests pin both halves: the skip still fires (it must, nuclei and katana
have nothing to crawl), and the certificate-data checks run anyway.

Run: python -m pytest recon/tests/test_cert_hygiene_when_scans_skipped.py
"""

import json
import os
import sys
import unittest
from unittest.mock import patch

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)


def _tlsx_payload():
    """The lab's two certificates, through the real parser.

    993: self-signed + hostname mismatch. 636: expired. Nothing serves HTTP.
    """
    from recon.main_recon_modules.tls_scan import _parse_tlsx_output
    lines = [
        json.dumps({
            "host": "mail.tlslab.test", "ip": "192.88.98.10", "port": "993",
            "probe_status": True, "tls_version": "tls13",
            "subject_cn": "mail.tlslab.test", "subject_dn": "CN=mail.tlslab.test",
            "subject_an": ["mail.tlslab.test", "imap.tlslab.test"],
            "self_signed": True, "mismatched": True,
            "issuer_cn": "mail.tlslab.test",
            "fingerprint_hash": {"sha256": "aa11"},
            "not_after": "2027-01-01T00:00:00Z",
        }),
        json.dumps({
            "host": "ldap.tlslab.test", "ip": "192.88.98.10", "port": "636",
            "probe_status": True, "tls_version": "tls13",
            "subject_cn": "ldap.tlslab.test", "subject_dn": "CN=ldap.tlslab.test",
            "subject_an": ["ldap.tlslab.test"],
            "expired": True, "self_signed": True,
            "issuer_cn": "ldap.tlslab.test",
            "fingerprint_hash": {"sha256": "bb22"},
            "not_after": "2024-02-01T00:00:00Z",
        }),
    ]
    by_target = {}
    by_target.update(_parse_tlsx_output(lines[0], {"mail.tlslab.test:993": "192.88.98.10"}))
    by_target.update(_parse_tlsx_output(lines[1], {"ldap.tlslab.test:636": "192.88.98.10"}))
    return by_target


def _recon_no_http():
    """What the tls_target lab actually produces: certs, and httpx found nothing."""
    return {
        "metadata": {},
        "tlsx": {"by_target": _tlsx_payload()},
        "http_probe": {"by_url": {}, "summary": {"live_urls": 0, "total_hosts": 0}},
    }


_ALL_TLS_ON = {
    "SECURITY_CHECK_ENABLED": True,
    "SECURITY_CHECK_TLS_EXPIRED": True,
    "SECURITY_CHECK_TLS_SELF_SIGNED": True,
    "SECURITY_CHECK_TLS_HOSTNAME_MISMATCH": True,
    "SECURITY_CHECK_TLS_WEAK_VERSION": True,
    "SECURITY_CHECK_TLS_WEAK_CIPHER": True,
    "SECURITY_CHECK_TLS_WILDCARD_OVERBROAD": True,
}


class TheSkipStillFires(unittest.TestCase):
    """The skip itself is correct and must stay: there is nothing to crawl."""

    def test_a_target_with_no_http_skips_the_active_scans(self):
        from recon.main import should_skip_active_scans
        skip, reason = should_skip_active_scans(_recon_no_http())
        self.assertTrue(skip)
        self.assertIn("No live URLs", reason)


class TheHookIsWiredIntoEverySkipBranch(unittest.TestCase):
    """A correct helper nobody calls fixes nothing.

    There are three `if skip_active_scans:` branches in main.py (IP mode, domain
    mode, and the domain-discovery-skipped path) and they are easy to add a
    fourth to. Asserting on the parse tree rather than on text so reformatting
    does not break it, and so a new branch that forgets the hook fails here.
    """

    def _skip_branches(self):
        import ast
        path = os.path.join(_REPO, "recon", "main.py")
        with open(path) as fh:
            tree = ast.parse(fh.read())
        return [node for node in ast.walk(tree)
                if isinstance(node, ast.If)
                and isinstance(node.test, ast.Name)
                and node.test.id == "skip_active_scans"]

    def test_all_three_skip_branches_exist(self):
        self.assertEqual(len(self._skip_branches()), 3,
                         "the number of skip branches changed; check each one "
                         "still runs the certificate hygiene hook")

    def test_every_skip_branch_runs_the_cert_hygiene_hook(self):
        import ast
        for branch in self._skip_branches():
            called = {
                node.func.id for node in ast.walk(ast.Module(body=branch.body, type_ignores=[]))
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            }
            self.assertIn(
                "_maybe_run_cert_hygiene", called,
                f"the skip branch at line {branch.lineno} drops certificate "
                f"hygiene: certs are stored and never evaluated (H2)")


class CertHygieneRunsAnyway(unittest.TestCase):
    def _run(self, settings=None, scan_modules=("port_scan", "http_probe", "vuln_scan")):
        import recon.main as main
        result = _recon_no_http()
        graph_calls = []
        with patch.object(main, "SCAN_MODULES", list(scan_modules)), \
             patch.object(main, "save_recon_file", lambda *a, **k: None), \
             patch.object(main, "_graph_update_bg",
                          lambda method, *a, **k: graph_calls.append(method)):
            out = main._maybe_run_cert_hygiene(
                result, dict(settings if settings is not None else _ALL_TLS_ON), None)
        return out, graph_calls

    def test_findings_are_produced_even_though_no_url_was_live(self):
        out, _ = self._run()
        findings = out.get("vuln_scan", {}).get("security_checks", {}).get("findings", [])
        types = sorted({f["type"] for f in findings})
        self.assertIn("tls_expired", types,
                      "the expired certificate produced no finding; H2 is back")
        self.assertIn("tls_self_signed", types)
        self.assertIn("tls_hostname_mismatch", types)

    def test_the_expired_certificate_is_high_severity(self):
        out, _ = self._run()
        findings = out["vuln_scan"]["security_checks"]["findings"]
        expired = [f for f in findings if f["type"] == "tls_expired"]
        self.assertTrue(expired)
        self.assertEqual(expired[0]["severity"], "high")

    def test_the_graph_write_is_triggered_so_findings_are_not_json_only(self):
        _, graph_calls = self._run()
        self.assertIn("update_graph_from_vuln_scan", graph_calls)

    def test_no_network_target_is_probed(self):
        """The subset that runs here reads memory only. If a future edit routes
        the full run_security_checks through this path, these counters go up and
        the active-scan skip has been quietly defeated."""
        out, _ = self._run()
        targets = out["vuln_scan"]["security_checks"]["targets_checked"]
        self.assertEqual(targets, {"hostnames": 0, "ips": 0})

    def test_the_envelope_matches_a_full_security_check_run(self):
        """Downstream (graph writer, report) cannot tell a partial run apart."""
        from recon.helpers.security_checks import run_security_checks
        out, _ = self._run()
        partial = out["vuln_scan"]["security_checks"]
        full = run_security_checks(recon_data={"metadata": {}}, enabled_checks={})["security_checks"]
        self.assertEqual(sorted(partial.keys()), sorted(full.keys()))

    # -- the three ways an operator can legitimately turn this off ----------
    def test_it_respects_the_vuln_scan_module_being_disabled(self):
        out, graph_calls = self._run(scan_modules=("port_scan", "http_probe"))
        self.assertNotIn("vuln_scan", out)
        self.assertEqual(graph_calls, [])

    def test_it_respects_the_global_security_check_switch(self):
        settings = dict(_ALL_TLS_ON, SECURITY_CHECK_ENABLED=False)
        out, graph_calls = self._run(settings=settings)
        self.assertNotIn("vuln_scan", out)
        self.assertEqual(graph_calls, [])

    def test_it_does_nothing_when_every_tls_check_is_off(self):
        settings = {k: (False if k != "SECURITY_CHECK_ENABLED" else True)
                    for k in _ALL_TLS_ON}
        out, graph_calls = self._run(settings=settings)
        self.assertNotIn("vuln_scan", out)
        self.assertEqual(graph_calls, [])

    def test_it_does_nothing_when_there_is_no_certificate_data_at_all(self):
        import recon.main as main
        with patch.object(main, "SCAN_MODULES", ["vuln_scan"]), \
             patch.object(main, "save_recon_file", lambda *a, **k: None), \
             patch.object(main, "_graph_update_bg", lambda *a, **k: None):
            out = main._maybe_run_cert_hygiene({"metadata": {}}, dict(_ALL_TLS_ON), None)
        self.assertNotIn("vuln_scan", out)

    def test_a_failure_records_a_phase_error_and_does_not_raise(self):
        import recon.main as main
        with patch.object(main, "SCAN_MODULES", ["vuln_scan"]), \
             patch.object(main, "save_recon_file", lambda *a, **k: None), \
             patch.object(main, "_graph_update_bg", lambda *a, **k: None), \
             patch("recon.helpers.run_cert_hygiene_checks_only",
                   side_effect=RuntimeError("boom")):
            out = main._maybe_run_cert_hygiene(_recon_no_http(), dict(_ALL_TLS_ON), None)
        self.assertIn("cert_hygiene", out["metadata"]["phase_errors"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

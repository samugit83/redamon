"""Agent-side auth_profile builder: modes, sanitizing, scope gating."""

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import auth_profile as ap  # noqa: E402


class TestBuild(unittest.TestCase):
    def test_modes(self):
        self.assertEqual(ap.build_auth_headers({"authType": "bearer", "authValue": "t"}),
                         {"Authorization": "Bearer t"})
        self.assertEqual(ap.build_auth_headers({"authType": "bearer", "authValue": "Bearer t"}),
                         {"Authorization": "Bearer t"})
        self.assertEqual(ap.build_auth_headers({"authType": "cookie", "authValue": "sid=a"}),
                         {"Cookie": "sid=a"})
        self.assertEqual(ap.build_auth_headers({"authType": "basic", "authValue": "u:p"}),
                         {"Authorization": "Basic " + base64.b64encode(b"u:p").decode()})
        self.assertEqual(ap.build_auth_headers({"authType": "header", "authValue": "v"}),
                         {"X-Auth-Token": "v"})

    def test_extras_and_precedence(self):
        h = ap.build_auth_headers({"authType": "cookie", "authValue": "sid=a",
                                   "extraHeaders": {"X-CSRF": "c", "cookie": "evil"}})
        self.assertEqual(h, {"Cookie": "sid=a", "X-CSRF": "c"})

    def test_sanitizing(self):
        self.assertEqual(ap.build_auth_headers({"authType": "cookie", "authValue": "a\r\nX: 1"}), {})
        self.assertEqual(ap.build_auth_headers({"authType": "cookie", "authValue": "a;;b"}), {})
        self.assertEqual(ap.build_auth_headers({"authType": "header", "authValue": "v",
                                                "authHeaderName": "x-redamon-ctx"}), {})
        self.assertEqual(ap.build_auth_headers(None), {})


class TestScope(unittest.TestCase):
    PROFILE = {"authType": "cookie", "authValue": "sid=a"}

    def test_in_scope_uses_target_domains(self):
        h = ap.auth_headers_for_host(self.PROFILE, "app.target.test", ["target.test", "app.target.test"])
        self.assertEqual(h, {"Cookie": "sid=a"})

    def test_out_of_scope_returns_empty(self):
        self.assertEqual(ap.auth_headers_for_host(self.PROFILE, "evil.test", ["target.test"]), {})

    def test_explicit_scope_hosts_win(self):
        prof = {**self.PROFILE, "scopeHosts": ["*.target.test"]}
        self.assertEqual(ap.auth_headers_for_host(prof, "a.b.target.test", ["ignored.test"]),
                         {"Cookie": "sid=a"})
        self.assertEqual(ap.auth_headers_for_host(prof, "target.test", ["ignored.test"]), {})

    def test_empty_scope_fails_closed(self):
        self.assertEqual(ap.auth_headers_for_host(self.PROFILE, "target.test", []), {})

    def test_no_profile(self):
        self.assertEqual(ap.auth_headers_for_host(None, "target.test", ["target.test"]), {})

    def test_agent_gate_off_suppresses_auth(self):
        # Independent agent consumer gate: off => the agent sends anonymous even
        # for an in-scope host with a valid profile.
        prof = {**self.PROFILE, "agentEnabled": False}
        self.assertEqual(ap.auth_headers_for_host(prof, "target.test", ["target.test"]), {})
        self.assertFalse(ap.agent_enabled(prof))

    def test_agent_gate_on_or_absent_attaches(self):
        prof_on = {**self.PROFILE, "agentEnabled": True}
        self.assertEqual(ap.auth_headers_for_host(prof_on, "target.test", ["target.test"]),
                         {"Cookie": "sid=a"})
        # Absent key defaults on.
        self.assertTrue(ap.agent_enabled(self.PROFILE))
        self.assertEqual(ap.auth_headers_for_host(self.PROFILE, "target.test", ["target.test"]),
                         {"Cookie": "sid=a"})

    def test_cidr_scope(self):
        self.assertTrue(ap.host_in_scope("10.0.0.9", ["10.0.0.0/24"]))
        self.assertFalse(ap.host_in_scope("10.0.1.9", ["10.0.0.0/24"]))

    def test_host_normalization(self):
        self.assertTrue(ap.host_in_scope("HTTPS://Target.test:8443/x", ["target.test"]))


if __name__ == "__main__":
    unittest.main()

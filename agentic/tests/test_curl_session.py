"""Agent-side opt-in session attach for execute_curl (tools._maybe_attach_curl_session).

The LLM sets use_session=true; the executor resolves the profile from project
settings and appends the auth header to the curl args HERE, so the raw value
never reaches the model. It attaches only for an in-scope host, and only when
asked — an anonymous request is the default, because access-control / IDOR tests
need the logged-out view.
"""
import os
import shlex
import sys
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tools  # noqa: E402

PROFILE = {"authType": "cookie", "authValue": "sid=SECRET"}


def _attach(args, use_session=True, profile=PROFILE, roots=("target.test",)):
    with mock.patch.object(tools, "get_setting",
                           side_effect=lambda k, d=None: profile if k == "AUTH_PROFILE" else d), \
         mock.patch("project_settings.target_scope_domains", return_value=list(roots)):
        return tools._maybe_attach_curl_session({"args": args, "use_session": use_session})


def _cookies(out_args):
    toks = shlex.split(out_args)
    return [toks[i + 1] for i, t in enumerate(toks) if t == "-H"]


class TestCurlHost:
    def test_extracts_host_from_full_url(self):
        assert tools._curl_target_host("-s -i http://app.target.test/admin") == "app.target.test"

    def test_bare_host_returns_none(self):
        assert tools._curl_target_host("-s target.test/x") is None

    def test_no_url_returns_none(self):
        assert tools._curl_target_host("-s -I") is None


class TestAttach:
    def test_in_scope_apex_gets_the_session(self):
        out = _attach("-s -i http://target.test/dash")
        assert "Cookie: sid=SECRET" in _cookies(out["args"])

    def test_in_scope_subdomain_gets_the_session(self):
        # Subdomains are in scope via *.root, mirroring recon — the whole point.
        out = _attach("-s -i http://app.target.test/dash")
        assert "Cookie: sid=SECRET" in _cookies(out["args"])

    def test_out_of_scope_host_gets_nothing(self):
        out = _attach("-s -i http://evil.example.test/x")
        assert "-H" not in out["args"]
        assert out["args"] == "-s -i http://evil.example.test/x"

    def test_default_is_anonymous(self):
        out = _attach("-s -i http://target.test/x", use_session=False)
        assert out["args"] == "-s -i http://target.test/x"

    def test_no_profile_no_attach(self):
        out = _attach("-s -i http://target.test/x", profile=None)
        assert out["args"] == "-s -i http://target.test/x"

    def test_bare_host_fails_closed(self):
        out = _attach("-s target.test/x")
        assert "-H" not in out["args"]

    def test_explicit_scope_hosts_override(self):
        prof = {**PROFILE, "scopeHosts": ["only.target.test"]}
        assert "Cookie: sid=SECRET" in _cookies(_attach("http://only.target.test/x", profile=prof)["args"])
        assert "-H" not in _attach("http://other.target.test/x", profile=prof)["args"]

    def test_injected_value_is_shell_quoted(self):
        # A profile value with a space must not split into extra curl args.
        prof = {"authType": "cookie", "authValue": "sid=a b; k=v"}
        out = _attach("http://target.test/x", profile=prof)
        # The whole cookie survives as ONE -H value (space did not split the arg).
        assert "Cookie: sid=a b; k=v" in _cookies(out["args"])

    def test_bearer_mode(self):
        out = _attach("http://target.test/x", profile={"authType": "bearer", "authValue": "tok"})
        assert "Authorization: Bearer tok" in _cookies(out["args"])

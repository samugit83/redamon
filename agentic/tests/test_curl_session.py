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


def _attach(args, use_session=True, profile=PROFILE, patterns=("*.target.test", "target.test"), roe=None):
    values = {"AUTH_PROFILE": profile, "ROE_ENABLED": bool(roe), "ROE_EXCLUDED_HOSTS": roe or []}
    with mock.patch.object(tools, "get_setting", side_effect=lambda k, d=None: values.get(k, d)), \
         mock.patch("project_settings.auth_scope_patterns", return_value=list(patterns)):
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
        assert "_session_note" not in out

    def test_the_apex_of_an_enumerated_root_needs_root_on(self):
        out = _attach("-s -i http://target.test/dash", patterns=("*.target.test",))
        assert "-H" not in out["args"]

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

    def test_explicit_scope_hosts_narrow(self):
        prof = {**PROFILE, "scopeHosts": ["only.target.test"]}
        assert "Cookie: sid=SECRET" in _cookies(_attach("http://only.target.test/x", profile=prof)["args"])
        assert "-H" not in _attach("http://other.target.test/x", profile=prof)["args"]

    def test_explicit_scope_hosts_never_widen(self):
        # D-22: an explicit host the project does not admit gets nothing.
        prof = {**PROFILE, "scopeHosts": ["*.target.test", "evil.test"]}
        assert "-H" not in _attach("http://evil.test/x", profile=prof)["args"]
        out = _attach("http://www.target.test/x", profile=prof, patterns=("www.target.test",))
        assert "Cookie: sid=SECRET" in _cookies(out["args"])
        assert "-H" not in _attach("http://app.target.test/x", profile=prof, patterns=("www.target.test",))["args"]

    def test_an_roe_excluded_host_under_an_allowed_pattern_gets_nothing(self):
        out = _attach("http://admin.target.test/x", roe=["admin.target.test"])
        assert "-H" not in out["args"]
        assert "NOT attached" in out["_session_note"]
        assert "Cookie: sid=SECRET" in _cookies(_attach("http://app.target.test/x", roe=["admin.target.test"])["args"])

    def test_injected_value_is_shell_quoted(self):
        # A profile value with a space must not split into extra curl args.
        prof = {"authType": "cookie", "authValue": "sid=a b; k=v"}
        out = _attach("http://target.test/x", profile=prof)
        # The whole cookie survives as ONE -H value (space did not split the arg).
        assert "Cookie: sid=a b; k=v" in _cookies(out["args"])

    def test_bearer_mode(self):
        out = _attach("http://target.test/x", profile={"authType": "bearer", "authValue": "tok"})
        assert "Authorization: Bearer tok" in _cookies(out["args"])


class TestOneRequestOnly:
    """AGT-02: `-H` applies to every request a curl command makes, so the session
    rides only a command that makes one request to one http(s) URL."""

    REFUSED = [
        "http://app.target.test/ http://evil.test/",
        "http://app.target.test/ evil.test",
        "--resolve app.target.test:80:192.0.2.66 http://app.target.test/",
        "--connect-to app.target.test:80:evil.test:80 http://app.target.test/",
        "-x http://proxy.test:8080 http://app.target.test/",
        "--proxy http://proxy.test:8080 http://app.target.test/",
        "--proxy-header 'X: y' http://app.target.test/",
        "--socks5-hostname proxy.test:1080 http://app.target.test/",
        "-L http://app.target.test/",
        "-sSL http://app.target.test/",
        "--location-trusted http://app.target.test/",
        "-K /tmp/extra.cfg http://app.target.test/",
        "--config /tmp/extra.cfg http://app.target.test/",
        "http://app.target.test/ --next http://evil.test/",
        "http://app.target.test/ -: http://evil.test/",
        "--url http://evil.test/ http://app.target.test/",
        "'http://{app,evil}.target.test/'",
        "'http://app.target.test[1-2]/'",
        "--unix-socket /tmp/s http://app.target.test/",
        "'http://app.target.test",
    ]

    def test_refused_shapes_run_without_the_session_and_say_so(self):
        for args in self.REFUSED:
            out = _attach(args)
            assert "Cookie" not in out["args"], args
            assert out["args"] == args, args
            assert "NOT attached" in out["_session_note"], args

    def test_a_single_in_scope_url_with_ordinary_options_gets_the_session(self):
        for args in [
            "-s -i http://app.target.test/a",
            "-sk -X POST -H 'Content-Type: application/json' -d '{\"a\": 1}' https://app.target.test/api",
            "-sXPOST https://app.target.test/api",
            "--max-time 10 -o /dev/null -w '%{http_code}' https://app.target.test/",
            "-e https://app.target.test/ref https://app.target.test/",
            "http://[2001:db8::1]:8080/x",
        ]:
            patterns = ("*.target.test", "2001:db8::1")
            assert "Cookie: sid=SECRET" in _cookies(_attach(args, patterns=patterns)["args"]), args

    def test_userinfo_does_not_disguise_the_real_host(self):
        out = _attach("http://app.target.test@evil.test/")
        assert "Cookie" not in out["args"]

    def test_the_note_reaches_the_tool_output_and_not_the_tool(self):
        import asyncio

        seen = {}

        class _Tool:
            async def ainvoke(self, args):
                seen.update(args)
                return "HTTP/1.1 200 OK"

        executor = tools.PhaseAwareToolExecutor.__new__(tools.PhaseAwareToolExecutor)
        executor._all_tools = {"execute_curl": _Tool()}
        executor._mcp_tool_names = set()
        values = {"AUTH_PROFILE": PROFILE}
        # The shared sandbox's path: shared mode is named, since the default is
        # per_user and no gateway answers here.
        with mock.patch.object(tools.sandbox_router, "_last_mode", tools.sandbox_contract.MODE_SHARED), \
             mock.patch.object(tools, "get_setting", side_effect=lambda k, d=None: values.get(k, d)), \
             mock.patch("project_settings.auth_scope_patterns", return_value=["*.target.test"]), \
             mock.patch.object(tools.output_offload, "maybe_offload", side_effect=lambda pid, name, out, **kw: out):
            result = asyncio.run(executor.execute(
                "execute_curl", {"args": "-L http://app.target.test/", "use_session": True},
                "informational", skip_phase_check=True))
        assert "_session_note" not in seen
        assert seen["args"] == "-L http://app.target.test/"
        assert result["output"].startswith("[session] Auth headers NOT attached: it uses -L")
        assert result["output"].endswith("HTTP/1.1 200 OK")

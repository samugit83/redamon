"""R-19: the Nuclei false-positive filter must not drop real findings for an everyday phrase.

`is_false_positive` dropped every finding whose captured response contained
"please wait", "rate limit", "try again later" and the like anywhere, for every
template. An exposed `/.git/config` on a site whose page says "Loading, please
wait..." was never reported, and the prune then deleted the earlier finding.

The rate-limit rule exists for time-based and blind templates, whose timing a
throttled server makes meaningless. It now needs the server to have said so in
the response head (status 429 or 503, or a `Retry-After` header) and applies to
those templates only. Nuclei's JSONL has no status field, so the status and the
headers are read from the raw `response`. The WAF-block rule is unchanged.

Run: ./redamon.sh test unit   (recon section)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import nuclei_helpers as nh  # noqa: E402
from recon.main_recon_modules import vuln_scan as vs  # noqa: E402

GIT_CONFIG_BODY = (
    "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
    '[remote "origin"]\n\turl = https://git.example.com/acme/site.git\n'
)


@pytest.fixture(autouse=True)
def _static_filter_only():
    nh.set_fp_ai_ctx(False, "", "", "")
    yield
    nh.set_fp_ai_ctx(False, "", "", "")


def _raw(head: str, body: str = "") -> str:
    return head.replace("\n", "\r\n") + "\r\n\r\n" + body


def _git_config(response) -> dict:
    return {
        "template-id": "git-config",
        "matched-at": "https://www.example.com/.git/config",
        "host": "https://www.example.com",
        "info": {"name": "Git Config - Detect", "severity": "medium",
                 "tags": ["config", "git", "exposure"]},
        "response": response,
    }


def _time_based(response, template_id="time-based-sqli",
                tags=("sqli", "time-based-sqli", "dast")) -> dict:
    return {
        "template-id": template_id,
        "matched-at": "https://www.example.com/item?id=1",
        "host": "https://www.example.com",
        "info": {"name": "Time-Based Blind SQL Injection", "severity": "critical",
                 "tags": list(tags)},
        "response": response,
    }


PAGE_200_PLEASE_WAIT = _raw(
    "HTTP/1.1 200 OK\nContent-Type: text/plain",
    GIT_CONFIG_BODY + "\n<!-- Loading, please wait... -->\n",
)


class TestEverydayPhrasesKeepRealFindings:
    def test_git_config_200_with_please_wait_is_kept(self):
        assert nh.is_false_positive(_git_config(PAGE_200_PLEASE_WAIT)) == (False, None)

    @pytest.mark.parametrize("phrase", [
        "Our API has a rate limit of 100 calls per hour.",
        "Too many attempts? Reset your password.",
        "Something went wrong, try again later.",
        "Request blocked? Contact support.",
        "Accounts are temporarily blocked after five failures.",
        "Too Many Requests is the name of our band.",
    ])
    def test_a_200_page_quoting_a_rate_limit_phrase_is_kept(self, phrase):
        response = _raw("HTTP/1.1 200 OK\nContent-Type: text/html",
                        GIT_CONFIG_BODY + f"<footer>{phrase}</footer>")
        assert nh.is_false_positive(_git_config(response)) == (False, None)

    def test_a_time_based_match_on_a_200_page_saying_please_wait_is_kept(self):
        # A 200 is a served page, not a throttle: the template's timing stands.
        response = _raw("HTTP/1.1 200 OK", "<p>Loading, please wait...</p>")
        assert nh.is_false_positive(_time_based(response)) == (False, None)

    def test_retry_after_in_the_body_is_not_a_header(self):
        response = _raw("HTTP/1.1 200 OK", "Retry-After: 30\nplease wait")
        assert nh.is_false_positive(_time_based(response)) == (False, None)

    def test_a_429_on_a_template_that_does_not_time_the_server_is_kept(self):
        response = _raw("HTTP/1.1 429 Too Many Requests\nRetry-After: 60",
                        GIT_CONFIG_BODY + "rate limit exceeded")
        assert nh.is_false_positive(_git_config(response)) == (False, None)

    @pytest.mark.parametrize("template_id", ["uptime-kuma-panel", "datetime-picker-xss",
                                             "runtime-config-exposure"])
    def test_time_inside_another_word_does_not_make_a_template_time_based(self, template_id):
        response = _raw("HTTP/1.1 503 Service Unavailable\nRetry-After: 120",
                        "Maintenance, please wait")
        finding = _time_based(response, template_id=template_id, tags=("panel",))
        assert nh.is_false_positive(finding) == (False, None)

    @pytest.mark.parametrize("response", [None, "", "   "])
    def test_no_captured_response_never_drops(self, response):
        assert nh.is_false_positive(_time_based(response)) == (False, None)

    def test_a_non_http_response_is_not_a_rate_limit_page(self):
        # DNS and network templates carry a protocol dump, not an HTTP head.
        dns = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR\nTXT \"rate limit please wait\""
        assert nh.is_false_positive(_time_based(dns, tags=("blind",))) == (False, None)


class TestRateLimitedTimingIsStillDropped:
    def test_a_429_time_based_match_is_dropped(self):
        response = _raw("HTTP/1.1 429 Too Many Requests\nContent-Type: text/html",
                        "<h1>Too Many Requests</h1>")
        is_fp, reason = nh.is_false_positive(_time_based(response))
        assert is_fp is True
        assert "Rate limiting detected" in reason
        assert "time-based" in reason

    @pytest.mark.parametrize("status_line", ["HTTP/2 429", "HTTP/2.0 429", "HTTP/1.0 429"])
    def test_the_status_is_read_whatever_the_http_version(self, status_line):
        response = _raw(f"{status_line}\ncontent-type: text/html", "slow down")
        is_fp, reason = nh.is_false_positive(_time_based(response))
        assert is_fp is True
        assert "429" in reason

    def test_a_503_with_a_throttle_phrase_on_a_blind_template_is_dropped(self):
        response = _raw("HTTP/1.1 503 Service Unavailable", "Please wait and try again later.")
        finding = _time_based(response, template_id="blind-ssrf-probe", tags=("ssrf", "blind"))
        is_fp, reason = nh.is_false_positive(finding)
        assert is_fp is True
        assert "please wait" in reason.lower() or "try again later" in reason.lower()

    def test_a_retry_after_header_with_a_throttle_phrase_is_dropped(self):
        response = _raw("HTTP/1.1 200 OK\nretry-after: 30", "rate limit reached, please wait")
        is_fp, reason = nh.is_false_positive(_time_based(response))
        assert is_fp is True
        assert "Rate limiting detected" in reason

    def test_a_503_without_any_throttle_marker_is_kept(self):
        # 503 alone is an outage, not a throttle; nothing says the timing was cut.
        response = _raw("HTTP/1.1 503 Service Unavailable", "<h1>Upstream down</h1>")
        assert nh.is_false_positive(_time_based(response)) == (False, None)


class TestWafBlockRuleUnchanged:
    def test_a_403_sqli_match_with_access_denied_is_dropped(self):
        finding = {
            "template-id": "error-based-sqli",
            "info": {"tags": ["sqli", "injection"]},
            "response": _raw("HTTP/1.1 403 Forbidden", "Access Denied"),
        }
        is_fp, reason = nh.is_false_positive(finding)
        assert is_fp is True
        assert "WAF/Firewall block detected" in reason


class TestTheNucleiPassKeepsTheFinding:
    """The real JSONL reader in vuln_scan: kept lines become findings, dropped
    lines are listed in false_positives with their reason."""

    class _Proc:
        returncode = 0

        def __init__(self):
            self.stdout = iter(["[INF] Templates loaded for current scan: 2\n"])

        def wait(self):
            return 0

    def test_git_config_survives_and_the_throttled_timing_match_is_listed(self, monkeypatch,
                                                                         tmp_path):
        throttled = _time_based(_raw("HTTP/1.1 429 Too Many Requests\nRetry-After: 60",
                                     "please wait"))
        out = tmp_path / "nuclei_detection.jsonl"
        out.write_text(json.dumps(_git_config(PAGE_200_PLEASE_WAIT)) + "\n"
                       + json.dumps(throttled) + "\n")
        monkeypatch.setattr(vs.subprocess, "Popen", lambda *a, **k: self._Proc())

        findings, false_positives, _, rc = vs._execute_nuclei_pass(
            ["docker", "run"], str(out), label="DETECTION")

        assert rc == 0
        assert [f["template_id"] for f in findings] == ["git-config"]
        assert findings[0]["matched_at"] == "https://www.example.com/.git/config"
        assert [fp["template_id"] for fp in false_positives] == ["time-based-sqli"]
        assert "Rate limiting detected" in false_positives[0]["reason"]

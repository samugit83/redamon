"""R-41: the takeover AI probe judges the first response and never follows it.

A takeover candidate is a host someone else may control, so its redirect must
not choose where the recon container sends the next request (cloud metadata,
the stack's own services, an RoE-excluded host). Only the transport
(HTTPAdapter.send) is replaced: the real `requests` redirect machinery runs, so
a probe that follows redirects shows up here as a second request.
"""
import sys
from pathlib import Path
from unittest import mock

import pytest
import requests
from requests.adapters import HTTPAdapter
from requests.models import Response
from requests.structures import CaseInsensitiveDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.ai_planner import takeover_classifier as tc  # noqa: E402
from recon.main_recon_modules import subdomain_takeover as st  # noqa: E402

CANDIDATE = "dangling.example.com"
FIRST_BODY = "<html><body>Moved</body></html>"
# Anything reached past the first hop answers with this, so a followed redirect
# also changes what the probe returns.
INTERNAL_BODY = "ami-id\ninstance-id\niam/security-credentials/"


class _Network:
    """Records every request the probe puts on the wire."""

    def __init__(self, routes):
        self.routes = routes
        self.sent = []

    def send(self, adapter, request, **kwargs):
        self.sent.append((request.url, kwargs))
        outcome = self.routes.get(request.url)
        if isinstance(outcome, Exception):
            raise outcome
        status, headers, body = outcome or (200, {"Content-Type": "text/plain"}, INTERNAL_BODY)
        resp = Response()
        resp.status_code = status
        resp.headers = CaseInsensitiveDict(headers)
        resp._content = body.encode()
        resp.encoding = "utf-8"
        resp.url = request.url
        resp.request = request
        resp.reason = "test"
        return resp

    def urls(self):
        return [url for url, _ in self.sent]


def _probe(routes, timeout=3):
    net = _Network(routes)

    def fake_send(adapter, request, **kwargs):
        return net.send(adapter, request, **kwargs)

    with mock.patch.object(HTTPAdapter, "send", fake_send):
        result = st._probe_for_ai_disambiguation(CANDIDATE, timeout=timeout)
    return result, net


@pytest.mark.parametrize("location", [
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata
    "http://127.0.0.1:7474/db/neo4j/tx",           # the stack's own service
    "http://agent:8090/llm/takeover-classify",     # a compose-network name
    "https://excluded.example.org/",               # an RoE-excluded host
    "/login",                                      # same host, still a second request
])
def test_https_redirect_is_returned_not_followed(location):
    (status, headers, body), net = _probe({
        f"https://{CANDIDATE}/": (302, {"Location": location, "Server": "nginx"}, FIRST_BODY),
    })

    assert net.urls() == [f"https://{CANDIDATE}/"]
    assert status == 302
    assert headers.get("Location") == location
    assert body == FIRST_BODY


def test_http_fallback_redirect_is_returned_not_followed():
    location = "http://169.254.169.254/latest/meta-data/iam/"
    (status, headers, body), net = _probe({
        f"https://{CANDIDATE}/": requests.exceptions.SSLError("handshake failed"),
        f"http://{CANDIDATE}/": (301, {"Location": location}, FIRST_BODY),
    })

    assert net.urls() == [f"https://{CANDIDATE}/", f"http://{CANDIDATE}/"]
    assert status == 301
    assert headers.get("Location") == location
    assert body == FIRST_BODY


def test_the_request_built_targets_only_the_candidate():
    _, net = _probe({
        f"https://{CANDIDATE}/": (302, {"Location": "http://169.254.169.254/"}, FIRST_BODY),
    }, timeout=4)

    assert len(net.sent) == 1
    url, kwargs = net.sent[0]
    assert url == f"https://{CANDIDATE}/"
    assert kwargs["timeout"] == 4
    assert kwargs["verify"] is False


def test_a_direct_answer_is_judged_as_before():
    unclaimed = "<h1>There's nothing here, yet.</h1>"
    (status, headers, body), net = _probe({
        f"https://{CANDIDATE}/": (404, {"Server": "Cowboy"}, unclaimed),
    })

    assert net.urls() == [f"https://{CANDIDATE}/"]
    assert (status, headers.get("Server"), body) == (404, "Cowboy", unclaimed)


def test_classifier_gets_the_first_response_with_location_as_data():
    location = "http://169.254.169.254/latest/meta-data/"
    findings = [{"hostname": CANDIDATE, "takeover_provider": "heroku"}]
    net = _Network({
        f"https://{CANDIDATE}/": (302, {"Location": location}, FIRST_BODY),
    })

    def fake_send(adapter, request, **kwargs):
        return net.send(adapter, request, **kwargs)

    verdict = {"is_waf_block": False, "confidence": 20, "reason": "r", "source": "ai_classifier"}
    with mock.patch.object(HTTPAdapter, "send", fake_send), \
         mock.patch("recon.helpers.ai_planner.takeover_classifier.classify_takeover_response",
                    return_value=verdict) as classify:
        st._apply_ai_waf_disambiguation(findings, model="m", user_id="u", project_id="p")

    assert net.urls() == [f"https://{CANDIDATE}/"]
    kwargs = classify.call_args.kwargs
    assert kwargs["hostname"] == CANDIDATE
    assert kwargs["status_code"] == 302
    assert kwargs["headers"].get("Location") == location
    assert kwargs["response_text"] == FIRST_BODY
    assert INTERNAL_BODY not in kwargs["response_text"]
    assert "ai_waf_likely" not in findings[0]


def _disambiguate_through_the_real_classifier(routes, findings):
    """Real probe and real classifier: only the transport, the agent POST and
    the process-wide breaker are stood in for."""
    net = _Network(routes)

    def fake_send(adapter, request, **kwargs):
        return net.send(adapter, request, **kwargs)

    gate = mock.MagicMock(allowed=True)
    reply = mock.MagicMock(status_code=200)
    reply.json.return_value = {"is_waf_block": False, "confidence": 30, "reason": "redirect only"}
    with mock.patch.object(HTTPAdapter, "send", fake_send), \
         mock.patch.object(tc, "agent_llm_gate", return_value=gate), \
         mock.patch.object(tc.requests, "post", return_value=reply) as post:
        st._apply_ai_waf_disambiguation(findings, model="m", user_id="u", project_id="p")
    return net, post


def test_location_reaches_the_classifier_payload_as_data():
    location = "https://dangling.example.com/cdn-cgi/challenge-platform/h/b"
    findings = [{"hostname": CANDIDATE, "takeover_provider": "heroku"}]
    net, post = _disambiguate_through_the_real_classifier({
        f"https://{CANDIDATE}/": (302, {
            "Location": location,
            "Server": "nginx",
            "Date": "Thu, 01 Jan 2026 00:00:00 GMT",
        }, FIRST_BODY),
    }, findings)

    assert net.urls() == [f"https://{CANDIDATE}/"]
    assert post.call_count == 1
    assert post.call_args.args[0].endswith("/llm/takeover-classify")
    payload = post.call_args.kwargs["json"]
    assert payload["status_code"] == 302
    assert payload["headers"]["Location"] == location
    assert payload["headers"]["Server"] == "nginx"
    assert "Date" not in payload["headers"]
    assert payload["response_sample"] == FIRST_BODY
    assert "ai_waf_likely" not in findings[0]


def test_redirect_with_an_empty_body_still_skips_the_llm():
    findings = [{"hostname": CANDIDATE, "takeover_provider": "heroku"}]
    net, post = _disambiguate_through_the_real_classifier({
        f"https://{CANDIDATE}/": (301, {"Location": "http://169.254.169.254/"}, ""),
    }, findings)

    assert net.urls() == [f"https://{CANDIDATE}/"]
    post.assert_not_called()
    assert "ai_waf_likely" not in findings[0]

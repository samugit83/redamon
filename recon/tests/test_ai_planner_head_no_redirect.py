"""The AI planners' header probes never follow a redirect (R-2).

Nuclei's tag planner (an empty fingerprint) and FFuf's extension planner send
a HEAD to a target URL and read only its Server and X-Powered-By headers.
They followed redirects with requests' default handling: no Rules of
Engagement check, no SSRF guard, no pacer on the hop, so a target answering
302 into an RoE-excluded host (or anywhere else) had that host probed. The
first answer's headers are the target's own, so the probe now reads them and
follows nothing, in every mode; both planners keep their never-raise
fallback.

Real servers on 127.0.0.1 (the target, every path 302s to the other host)
and 127.0.0.2 (the other host, which records each request); the agent's
/llm endpoint is unreachable, as when the agent is down.
"""
from __future__ import annotations

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import circuit_breaker  # noqa: E402

TARGET, OTHER = "127.0.0.1", "127.0.0.2"


@pytest.fixture(autouse=True)
def _fresh_run(monkeypatch):
    circuit_breaker.reset_registry()
    # Nothing listens there: the planner's POST fails and it falls back.
    monkeypatch.setenv("AGENT_API_URL", "http://127.0.0.1:9")
    yield
    circuit_breaker.reset_registry()


def _serve(address: str, handler_cls):
    server = ThreadingHTTPServer((address, 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def target():
    hits = []

    class Other(BaseHTTPRequestHandler):
        def _answer(self):
            hits.append((self.command, self.path))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_GET = do_HEAD = _answer

        def version_string(self):
            return "other-host/1.0"

        def log_message(self, *_a):
            pass

    other = _serve(OTHER, Other)

    class Target(BaseHTTPRequestHandler):
        def _answer(self):
            self.send_response(302)
            self.send_header("X-Powered-By", "PHP/8.2")
            self.send_header("Location", f"http://{OTHER}:{other.server_address[1]}/")
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_GET = do_HEAD = _answer

        def version_string(self):
            return "nginx/1.25"

        def log_message(self, *_a):
            pass

    server = _serve(TARGET, Target)
    yield {"url": f"http://{TARGET}:{server.server_address[1]}", "hits": hits}
    server.shutdown()
    other.shutdown()


def test_nuclei_tag_planner_reads_the_targets_own_headers(target, capsys):
    from recon.helpers.ai_planner.nuclei_tags import get_ai_tags
    tags = get_ai_tags({}, ["cve", "xss"], "gpt-test", fallback_urls=[target["url"] + "/"])
    assert tags == ["cve", "xss"]
    assert target["hits"] == []
    out = capsys.readouterr().out
    assert "servers=['nginx']" in out and "techs=['php/8.2']" in out


def test_ffuf_extension_planner_reads_the_targets_own_headers(target, capsys):
    from recon.helpers.ai_planner.ffuf_extensions import SAFE_FALLBACK, get_ai_extensions
    extensions = get_ai_extensions(target["url"] + "/FUZZ", "gpt-test", cache={})
    assert extensions == SAFE_FALLBACK[:6]
    assert target["hits"] == []
    assert "Server='nginx/1.25' X-Powered-By='PHP/8.2'" in capsys.readouterr().out

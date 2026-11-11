"""False-positive regressions for the VHost & SNI enumerator.

A field report muted ~2,200 vhost findings on shared CDN IPs. Every fixture
here is a synthetic replica of one of those failure modes, driven through the
REAL ``_curl_probe`` (only ``subprocess.run`` is faked), so the canonical
fingerprint, the control filter, the stability re-probe and the scope filter
are all exercised together:

- a Fastly-style "unknown domain" page that echoes the probed hostname twice,
  so its size is ``246 + 2 * len(hostname)`` and its raw hash differs per name;
- a Cloudflare-style 403 that carries a fresh Ray ID on every request;
- a provider redirect to ``https://<probed host>/`` with an empty body;
- a third-party CNAME target (an identity-provider tenant) offered as a
  candidate.

Each negative has a positive twin that must still be reported: a hidden app
whose content really differs from the unknown-host page.
"""

from __future__ import annotations

import itertools
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import vhost_sni_enum as vsm
from recon.main_recon_modules.vhost_sni_enum import (
    _PROBE_META_SENTINEL,
    _CandidateScope,
    _build_candidate_scope,
    _canonical_fingerprint,
    _candidate_in_scope,
    _classify_severity,
    _control_hostnames,
    _curl_probe,
    _detect_noisy_frontend,
    _matches_any_control,
    _same_response,
    run_vhost_sni_enrichment,
)

IP = "203.0.113.10"
APEX = "example.com"


# ---------------------------------------------------------------------------
# Fake curl: parses the command the real _curl_probe builds and answers with
# body + sentinel + "status\tsize\tredirect\tcontent-type", exactly the shape
# curl's --write-out produces.
# ---------------------------------------------------------------------------
def _proc(status: int, body: bytes = b"", redirect: str = "", ctype: str = "text/html; charset=utf-8"):
    proc = MagicMock()
    meta = f"{status}\t{len(body)}\t{redirect}\t{ctype}".encode()
    proc.stdout = body + _PROBE_META_SENTINEL + meta
    proc.stderr = b""
    proc.returncode = 0
    return proc


def _probed_name(cmd: list[str]) -> tuple[str | None, str]:
    """(hostname, layer) for a curl command; layer is baseline, L7 or L4."""
    if "--resolve" in cmd:
        return cmd[cmd.index("--resolve") + 1].split(":", 1)[0], "L4"
    if "-H" in cmd:
        return cmd[cmd.index("-H") + 1].split(":", 1)[1].strip(), "L7"
    return None, "baseline"


class FakeCurl:
    """``responder(host, layer, attempt)`` -> proc. Records every probe."""

    def __init__(self, responder):
        self.responder = responder
        self.calls: list[tuple[str | None, str]] = []
        self._attempts: dict[tuple, int] = {}

    def __call__(self, cmd, **kwargs):
        host, layer = _probed_name(cmd)
        self.calls.append((host, layer))
        key = (host, layer)
        self._attempts[key] = self._attempts.get(key, 0) + 1
        return self.responder(host, layer, self._attempts[key])

    def probed_hosts(self) -> set[str]:
        return {h for h, _ in self.calls if h}


_ray = itertools.count(0x8C1F2E3D4A5B6C00)


def fastly_unknown_domain(host: str) -> bytes:
    # 246 bytes of template + the hostname twice: the field report's arithmetic.
    head = b"<html><body><h1>Fastly error: unknown domain: "
    mid = b"</h1><p>Please check that this domain has been added to a service. Requested host: "
    tail = b"</p><p>Details: cache-fra-etou8220036-FRA</p></body></html>"
    pad = b" " * (246 - len(head) - len(mid) - len(tail))
    return head + host.encode() + mid + host.encode() + tail + pad


def cloudflare_block(host: str) -> bytes:
    ray = f"{next(_ray):016x}"
    return (
        f"<html><head><title>Attention Required! | Cloudflare</title></head><body>"
        f"<h1>Sorry, you have been blocked</h1><p>You are unable to access {host}</p>"
        f"<span>Cloudflare Ray ID: <strong class=\"font-semibold\">{ray}</strong></span>"
        f"<span>2026-10-06 12:{next(_ray) % 60:02d}:07 UTC</span></body></html>"
    ).encode()


ADMIN_APP = b'{"service":"admin-api","version":"3.2.1","endpoints":["/users","/audit"]}'


def _settings(words, **extra):
    s = {
        "VHOST_SNI_ENABLED": True,
        "VHOST_SNI_TEST_L7": True,
        "VHOST_SNI_TEST_L4": True,
        "VHOST_SNI_TIMEOUT": 1,
        "VHOST_SNI_CONCURRENCY": 4,
        "VHOST_SNI_BASELINE_SIZE_TOLERANCE": 50,
        "VHOST_SNI_USE_DEFAULT_WORDLIST": False,
        "VHOST_SNI_USE_GRAPH_CANDIDATES": False,
        "VHOST_SNI_INJECT_DISCOVERED": False,
        "VHOST_SNI_CUSTOM_WORDLIST": "\n".join(words),
        "VHOST_SNI_MAX_CANDIDATES_PER_IP": 5000,
    }
    s.update(extra)
    return s


def _recon(**extra):
    r = {
        "domain": APEX,
        "metadata": {"target": APEX},
        "port_scan": {"by_host": {IP: {"ip": IP, "ports": [{"port": 443, "scheme": "https"}]}}},
    }
    r.update(extra)
    return r


# Names of every length the default wordlist spans, so a size-bucketed guard
# would scatter them across many buckets.
WORDS = [
    "admin", "dev", "staging", "jenkins", "portal-internal", "qa", "grafana", "vpn",
    "api-gateway", "kibana", "ci", "sso", "monitoring", "backoffice", "uat", "x1",
    "preprod-eu-west", "status", "mail", "intranet",
]


def _run(responder, words=WORDS, recon=None, **settings):
    fake = FakeCurl(responder)
    cr = recon or _recon()
    with patch.object(vsm, "_is_curl_available", return_value=True), \
         patch("subprocess.run", side_effect=fake):
        run_vhost_sni_enrichment(cr, settings=_settings(words, **settings))
    return cr["vhost_sni"], fake


# ===========================================================================
# 1. Canonical fingerprint
# ===========================================================================
class TestCanonicalFingerprint:
    def test_fastly_template_is_one_fingerprint_for_every_hostname(self):
        hosts = ["admin.example.com", "a.example.com", "vhostsni-ctrl-0123456789-2.invalid"]
        sizes = {len(fastly_unknown_domain(h)) for h in hosts}
        assert len(sizes) == 3, "fixture must reproduce the per-hostname size drift"
        fps = {
            _canonical_fingerprint(500, "", "text/html", fastly_unknown_domain(h), [h]) for h in hosts
        }
        assert len(fps) == 1

    def test_fastly_template_size_matches_the_field_arithmetic(self):
        for h in ("admin.example.com", "preprod-eu-west.example.com"):
            assert len(fastly_unknown_domain(h)) - 2 * len(h) == 246

    def test_cloudflare_ray_id_and_timestamp_normalise_away(self):
        a = cloudflare_block("admin.example.com")
        b = cloudflare_block("admin.example.com")
        assert a != b, "fixture must carry a per-request Ray ID"
        assert _canonical_fingerprint(403, "", "text/html", a, ["admin.example.com"]) == \
            _canonical_fingerprint(403, "", "text/html", b, ["admin.example.com"])

    def test_redirect_to_the_probed_host_matches_across_hosts(self):
        fa = _canonical_fingerprint(301, "https://admin.example.com/", "", b"", ["admin.example.com"])
        fb = _canonical_fingerprint(301, "https://zz.example.com/", "", b"", ["zz.example.com"])
        assert fa == fb

    def test_redirect_to_a_distinct_path_stays_distinct(self):
        fa = _canonical_fingerprint(302, "https://admin.example.com/login", "", b"", ["admin.example.com"])
        fb = _canonical_fingerprint(302, "https://zz.example.com/", "", b"", ["zz.example.com"])
        assert fa != fb

    def test_hostname_match_is_case_insensitive_and_covers_entity_dots(self):
        a = b"Unknown host ADMIN.EXAMPLE.COM (admin&#46;example&#46;com)"
        b = b"Unknown host zz.example.com (zz&#46;example&#46;com)"
        assert _canonical_fingerprint(404, "", "", a, ["admin.example.com"]) == \
            _canonical_fingerprint(404, "", "", b, ["zz.example.com"])

    def test_common_request_ids_normalise_away(self):
        bodies = []
        for i in range(2):
            bodies.append((
                f"Request ID: {i}f0e9d8c-1b2a-4c3d-8e9f-0a1b2c3d4e5f "
                f"Reference #18.{i}a2b3c4d.172838888{i}.1a2b3c{i} "
                f"XID: 98765432{i} cf-ray {i}a1b2c3d4e5f60718-FRA "
                f"cloudfront: Hd8kQ{i}xYzAbCdEfGhIjKlMnOpQrStUvWxYz012345=="
            ).encode())
        assert _canonical_fingerprint(503, "", "", bodies[0], []) == \
            _canonical_fingerprint(503, "", "", bodies[1], [])

    def test_distinct_application_content_stays_distinct(self):
        err = fastly_unknown_domain("admin.example.com")
        assert _canonical_fingerprint(200, "", "application/json", ADMIN_APP, ["admin.example.com"]) != \
            _canonical_fingerprint(500, "", "text/html", err, ["admin.example.com"])

    def test_status_and_mime_are_part_of_the_fingerprint(self):
        body = b"<h1>Not found</h1>"
        assert _canonical_fingerprint(404, "", "text/html", body, []) != \
            _canonical_fingerprint(410, "", "text/html", body, [])
        assert _canonical_fingerprint(404, "", "text/html", body, []) != \
            _canonical_fingerprint(404, "", "application/json", body, [])

    def test_charset_parameter_is_ignored(self):
        body = b"<h1>Not found</h1>"
        assert _canonical_fingerprint(404, "", "text/html; charset=utf-8", body, []) == \
            _canonical_fingerprint(404, "", "TEXT/HTML", body, [])


# ===========================================================================
# 2. _curl_probe output parsing
# ===========================================================================
class TestCurlProbeParsing:
    def test_write_out_asks_for_redirect_and_content_type(self):
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return _proc(200, b"x")

        with patch("subprocess.run", side_effect=fake_run):
            _curl_probe("https", "admin.example.com", None, IP, 443, 1)
        fmt = captured["cmd"][captured["cmd"].index("-w") + 1]
        assert fmt.endswith("%{http_code}\t%{size_download}\t%{redirect_url}\t%{content_type}")

    def test_fingerprint_uses_the_probed_hostname(self):
        with patch("subprocess.run", return_value=_proc(500, fastly_unknown_domain("admin.example.com"))):
            a = _curl_probe("https", "admin.example.com", None, IP, 443, 1)
        with patch("subprocess.run", return_value=_proc(500, fastly_unknown_domain("zz.example.com"))):
            b = _curl_probe("https", None, "zz.example.com", IP, 443, 1)
        assert a["body_hash"] != b["body_hash"]
        assert a["canon_hash"] and a["canon_hash"] == b["canon_hash"]

    def test_redirect_and_content_type_are_parsed(self):
        with patch("subprocess.run", return_value=_proc(301, b"", "https://admin.example.com/", "")):
            r = _curl_probe("https", "admin.example.com", None, IP, 443, 1)
        assert r["status"] == 301 and r["size"] == 0
        with patch("subprocess.run", return_value=_proc(301, b"", "https://zz.example.com/", "")):
            z = _curl_probe("https", "zz.example.com", None, IP, 443, 1)
        assert r["canon_hash"] == z["canon_hash"]

    def test_legacy_space_separated_meta_still_parses_without_fingerprint(self):
        proc = MagicMock(stdout=b"200 4823", stderr=b"", returncode=0)
        with patch("subprocess.run", return_value=proc):
            r = _curl_probe("https", None, None, IP, 443, 1)
        assert (r["status"], r["size"], r["canon_hash"]) == (200, 4823, "")


# ===========================================================================
# 3. Control names, matching, stability helpers, severity
# ===========================================================================
class TestControlsAndMatching:
    def test_two_controls_sit_under_the_apex_and_one_under_invalid(self):
        names = _control_hostnames(APEX)
        assert len(names) == 3
        assert sum(n.endswith(f".{APEX}") for n in names) == 2
        assert sum(n.endswith(".invalid") for n in names) == 1
        assert all(n.startswith(vsm._CONTROL_LABEL_PREFIX) for n in names)
        assert len(set(names)) == 3

    def test_without_an_apex_every_control_is_invalid(self):
        assert all(n.endswith(".invalid") for n in _control_hostnames(None))

    def test_canonical_match_suppresses_despite_different_raw_hash(self):
        probe = {"status": 500, "size": 280, "body_hash": "a", "canon_hash": "same"}
        ctrls = [{"status": 500, "size": 314, "body_hash": "b", "canon_hash": "same"}]
        assert _matches_any_control(probe, ctrls) is True

    def test_canonical_match_still_requires_the_same_status(self):
        probe = {"status": 200, "size": 280, "body_hash": "a", "canon_hash": "same"}
        ctrls = [{"status": 500, "size": 280, "body_hash": "a", "canon_hash": "same"}]
        assert _matches_any_control(probe, ctrls) is False

    def test_empty_body_redirects_match_on_fingerprint(self):
        probe = {"status": 301, "size": 0, "body_hash": "", "canon_hash": "redir"}
        ctrls = [{"status": 301, "size": 0, "body_hash": "", "canon_hash": "redir"}]
        assert _matches_any_control(probe, ctrls) is True

    def test_same_response_prefers_fingerprint_over_size(self):
        assert _same_response(
            {"status": 200, "size": 100, "canon_hash": "x"},
            {"status": 200, "size": 116, "canon_hash": "x"},
        )
        assert not _same_response(
            {"status": 200, "size": 100, "canon_hash": "x"},
            {"status": 200, "size": 100, "canon_hash": "y"},
        )

    def test_l7_l4_differing_only_by_normalised_bytes_is_not_high(self):
        l7 = {"status": 200, "size": 5400, "canon_hash": "app"}
        l4 = {"status": 200, "size": 5401, "canon_hash": "app"}
        sev = _classify_severity("blog.example.com", "both", {"status": 421, "size": 291}, l4, l7, l4)
        assert sev == "low"

    def test_l7_l4_serving_different_pages_is_still_high(self):
        l7 = {"status": 200, "size": 5400, "canon_hash": "public"}
        l4 = {"status": 200, "size": 5400, "canon_hash": "internal"}
        sev = _classify_severity("blog.example.com", "both", {"status": 421, "size": 291}, l4, l7, l4)
        assert sev == "high"

    def test_dynamic_page_on_both_layers_is_the_same_page(self):
        # A live app's response time changes the bytes, not the page.
        l7 = {"status": 200, "size": 5400, "canon_hash": "a", "title": "Wiki"}
        l4 = {"status": 200, "size": 5402, "canon_hash": "b", "title": "Wiki"}
        sev = _classify_severity("blog.example.com", "both", {"status": 421, "size": 291}, l4, l7, l4, size_tolerance=50)
        assert sev == "low"

    def test_two_apps_of_similar_size_are_still_different_pages(self):
        l7 = {"status": 200, "size": 5400, "canon_hash": "a", "title": "Public site"}
        l4 = {"status": 200, "size": 5410, "canon_hash": "b", "title": "Admin console"}
        sev = _classify_severity("blog.example.com", "both", {"status": 421, "size": 291}, l4, l7, l4, size_tolerance=50)
        assert sev == "high"

    def test_noisy_frontend_buckets_on_fingerprint_not_size(self):
        anomalies = [
            {"observed_status": 500, "observed_size": 246 + 2 * n, "observed_fingerprint": "tpl"}
            for n in range(8, 28)
        ]
        kept, noisy = _detect_noisy_frontend(anomalies, candidates_count=20)
        assert noisy is True and kept == []


# ===========================================================================
# 4. End-to-end: the field report's failure modes, through the real probe
# ===========================================================================
class TestFastlySharedEdge:
    @staticmethod
    def responder(host, layer, attempt):
        if layer == "baseline":
            return _proc(421, b"<h1>Misdirected Request</h1>" + b" " * 263)
        return _proc(500, fastly_unknown_domain(host))

    def test_no_finding_for_any_wordlist_name(self):
        out, fake = _run(self.responder)
        assert out["findings"] == []
        ip = out["by_ip"][IP]
        assert ip["suppressed_by_control"] == len(WORDS)
        # Every candidate was really probed: suppression, not a skipped scan.
        assert {f"{w}.{APEX}" for w in WORDS} <= fake.probed_hosts()

    def test_a_real_hidden_app_on_the_same_edge_is_still_reported(self):
        def responder(host, layer, attempt):
            if host == f"admin.{APEX}" and layer != "baseline":
                return _proc(200, ADMIN_APP, ctype="application/json")
            return self.responder(host, layer, attempt)

        out, _ = _run(responder)
        assert [f["hostname"] for f in out["findings"]] == [f"admin.{APEX}"]
        f = out["findings"][0]
        assert f["layer"] == "both"
        assert f["severity"] == "medium"  # internal keyword, same page on L7 and L4
        # Both layers reach the same app: a hidden vhost, not a routing split.
        assert f["name"] == f"Hidden Virtual Host: admin.{APEX}"
        assert f["type"] == "hidden_vhost"
        assert out["by_ip"][IP]["suppressed_by_control"] == len(WORDS) - 1

    def test_l7_and_l4_reaching_different_apps_is_a_routing_inconsistency(self):
        def responder(host, layer, attempt):
            if host == f"admin.{APEX}" and layer == "L7":
                return _proc(200, ADMIN_APP, ctype="application/json")
            if host == f"admin.{APEX}" and layer == "L4":
                return _proc(200, b'{"service":"billing","version":"1.0"}', ctype="application/json")
            return self.responder(host, layer, attempt)

        out, _ = _run(responder)
        f = out["findings"][0]
        assert f["layer"] == "both" and f["severity"] == "high"
        assert f["name"] == f"Routing Inconsistency (L7 vs L4): admin.{APEX}"
        assert f["type"] == "host_header_bypass"


class TestCloudflareBlockPage:
    @staticmethod
    def responder(host, layer, attempt):
        if layer == "baseline":
            return _proc(400, b"<h1>400 Bad Request</h1><p>Plain HTTP request sent to HTTPS port</p>")
        return _proc(403, cloudflare_block(host))

    def test_fresh_ray_ids_do_not_turn_every_name_into_a_vhost(self):
        out, _ = _run(self.responder)
        assert out["findings"] == []
        assert out["summary"]["high_severity"] == 0
        # The control filter, not the re-probe, must be what recognises the
        # block page; the re-probe is a second line of defence.
        assert out["by_ip"][IP]["suppressed_by_control"] == len(WORDS)
        assert out["by_ip"][IP]["suppressed_unstable"] == 0

    def test_controls_failing_still_leaves_the_noisy_guard(self):
        # Controls time out (status 0), so only the noisy-frontend guard
        # stands between the run and 20 findings; it must bucket by
        # fingerprint, because every echoed hostname has its own length.
        def responder(host, layer, attempt):
            if host and host.startswith(vsm._CONTROL_LABEL_PREFIX):
                return _proc(0)
            return self.responder(host, layer, attempt)

        out, _ = _run(responder)
        assert out["findings"] == []
        assert out["by_ip"][IP]["is_permissive_frontend"] is True


class TestProviderRedirect:
    def test_redirect_to_the_probed_host_is_the_default_route(self):
        def responder(host, layer, attempt):
            if layer == "baseline":
                return _proc(404, b"")
            return _proc(301, b"", f"https://{host}/", "")

        out, _ = _run(responder)
        assert out["findings"] == []


class TestStabilityReprobe:
    def test_a_one_off_distinct_answer_is_dropped(self):
        # First probe of `status` hits a different backend; the second probe
        # gets the provider page every other name gets.
        def responder(host, layer, attempt):
            if layer == "baseline":
                return _proc(421, b"<h1>Misdirected Request</h1>")
            if host == f"status.{APEX}" and attempt == 1:
                return _proc(200, b"<html><title>Status</title>all systems operational</html>")
            return _proc(500, fastly_unknown_domain(host))

        out, fake = _run(responder)
        assert out["findings"] == []
        assert out["by_ip"][IP]["suppressed_unstable"] == 1
        assert sum(1 for h, l in fake.calls if h == f"status.{APEX}") == 4  # L7+L4, twice

    def test_a_live_app_whose_page_changes_every_request_survives(self):
        # Response time and a short counter change on each request; no
        # normalisation rule strips them, and the app is still real.
        def responder(host, layer, attempt):
            if layer == "baseline":
                return _proc(421, b"<h1>Misdirected Request</h1>")
            if host == f"wiki.{APEX}":
                return _proc(200, f"<html><title>Internal Wiki</title>served in 0.{attempt}2s hits={attempt * 7}</html>".encode())
            return _proc(500, fastly_unknown_domain(host))

        out, _ = _run(responder, words=WORDS + ["wiki"])
        assert [f["hostname"] for f in out["findings"]] == [f"wiki.{APEX}"]
        assert out["by_ip"][IP]["suppressed_unstable"] == 0

    def test_a_stable_hidden_app_survives_the_reprobe(self):
        def responder(host, layer, attempt):
            if layer == "baseline":
                return _proc(421, b"<h1>Misdirected Request</h1>")
            if host == f"status.{APEX}":
                return _proc(200, f"<html><title>Status</title>req {next(_ray):016x}</html>".encode())
            return _proc(500, fastly_unknown_domain(host))

        out, _ = _run(responder)
        assert [f["hostname"] for f in out["findings"]] == [f"status.{APEX}"]
        assert out["by_ip"][IP]["suppressed_unstable"] == 0
        assert out["findings"][0]["severity"] == "low"  # same page on both layers


class TestDeepReviewRegressions:
    """Cases an adversarial review showed the first version got wrong."""

    @staticmethod
    def fastly_default(host, layer, attempt):
        if layer == "baseline":
            return _proc(421, b"<h1>Misdirected Request</h1>")
        return _proc(500, fastly_unknown_domain(host))

    def test_a_rate_limited_second_probe_keeps_the_finding(self):
        def responder(host, layer, attempt):
            if host == f"admin.{APEX}" and layer != "baseline":
                return _proc(200, ADMIN_APP, ctype="application/json") if attempt == 1 else _proc(429, b"slow down")
            return self.fastly_default(host, layer, attempt)

        out, _ = _run(responder)
        assert [f["hostname"] for f in out["findings"]] == [f"admin.{APEX}"]
        assert out["by_ip"][IP]["suppressed_unstable"] == 0

    def test_a_steady_rate_limiter_is_not_a_vhost(self):
        limited = set(WORDS[::3])

        def responder(host, layer, attempt):
            if host and host.split(".")[0] in limited and layer != "baseline":
                return _proc(429, b"<h1>Too Many Requests</h1>")
            return self.fastly_default(host, layer, attempt)

        out, _ = _run(responder)
        assert out["findings"] == []

    def test_a_both_layer_finding_keeps_its_stable_layer(self):
        def responder(host, layer, attempt):
            if host == f"admin.{APEX}" and layer == "L4":
                return _proc(200, b'{"service":"sni-only-console"}', ctype="application/json")
            if host == f"admin.{APEX}" and layer == "L7" and attempt == 1:
                return _proc(200, ADMIN_APP, ctype="application/json")
            return self.fastly_default(host, layer, attempt)

        out, _ = _run(responder)
        [f] = out["findings"]
        assert (f["hostname"], f["layer"]) == (f"admin.{APEX}", "L4")

    def test_title_less_pages_on_l7_and_l4_that_differ_are_still_high(self):
        l7 = {"status": 200, "size": 40, "canon_hash": "a", "title": None}
        l4 = {"status": 200, "size": 60, "canon_hash": "b", "title": None}
        sev = _classify_severity("blog.example.com", "both", {"status": 421, "size": 291}, l4, l7, l4, size_tolerance=50)
        assert sev == "high"

    def test_constant_size_template_with_an_unknown_token_is_still_noise(self):
        # Every unknown name gets the same-size page with a token no rule knows
        # (lower-case letters, no digit), so each fingerprint is unique: the
        # size grouping is what recognises the catch-all.
        import random
        import string

        def responder(host, layer, attempt):
            if layer == "baseline":
                return _proc(404, b"<h1>not found</h1>")
            token = "".join(random.choice(string.ascii_lowercase) for _ in range(12))
            return _proc(403, f"<Error><Code>AccessDenied</Code><Nonce>{token}</Nonce></Error>".encode())

        out, _ = _run(responder)
        assert out["findings"] == []
        assert out["by_ip"][IP]["is_permissive_frontend"] is True

    def test_akamai_reference_in_its_errors_link_normalises_away(self):
        def page(host, ref):
            return (f"<H1>Access Denied</H1>You don't have permission to access http://{host}/ on this server."
                    f"<P>Reference&#32;&#35;18&#46;{ref}&#46;1696512345&#46;1a2b3c4d</P>"
                    f"<P>https&#58;&#47;&#47;errors&#46;edgesuite&#46;net&#47;18&#46;{ref}&#46;1696512345&#46;1a2b3c4d</P>").encode()
        a = _canonical_fingerprint(403, "", "text/html", page("admin.example.com", "6bd3c917"), ["admin.example.com"])
        b = _canonical_fingerprint(403, "", "text/html", page("zz.example.com", "9a1e04c2"), ["zz.example.com"])
        assert a == b

    def test_s3_request_id_and_azure_front_door_refs_normalise_away(self):
        s3 = "<Error><Code>NoSuchBucket</Code><RequestId>{rid}</RequestId></Error>"
        afd = "<p>Ref A: {a}</p><p>Ref B: AMS04EDGE0315</p><p>Ref C: 2026-10-06T12:00:00Z</p>"
        assert _canonical_fingerprint(404, "", "", s3.format(rid="7Q2X9F4K1M3N8P6R").encode(), []) == \
            _canonical_fingerprint(404, "", "", s3.format(rid="B8C1D2E3F4A5G6H7").encode(), [])
        assert _canonical_fingerprint(400, "", "", afd.format(a="0E5A2C").encode(), []) == \
            _canonical_fingerprint(400, "", "", afd.format(a="9F11BD").encode(), [])

    def test_ipv6_targets_are_bracketed_in_the_url_and_resolve(self):
        captured = []

        def fake_run(cmd, **kw):
            captured.append(cmd)
            return _proc(200, b"x")

        with patch("subprocess.run", side_effect=fake_run):
            _curl_probe("https", "admin.example.com", None, "2001:db8::10", 443, 1)
            _curl_probe("https", None, "admin.example.com", "2001:db8::10", 443, 1)
        assert "https://[2001:db8::10]:443/" in captured[0]
        assert captured[1][captured[1].index("--resolve") + 1] == "admin.example.com:443:[2001:db8::10]"


# ===========================================================================
# 5. Scope: third-party graph names are never probed
# ===========================================================================
class TestCandidateScope:
    def _graph_recon(self, **extra):
        # The PTR name sits in the dns block with its address, as IP mode
        # records it.
        return _recon(
            dns={"subdomains": {
                f"login.{APEX}": {
                    "ips": {"ipv4": [IP], "ipv6": []},
                    "records": {"CNAME": ["example-tenant.idp-provider.test."]},
                },
                "edge-203-0-113-10.cdn-provider.test": {"ips": {"ipv4": [IP], "ipv6": []}},
            }},
            **extra,
        )

    @staticmethod
    def responder(host, layer, attempt):
        if layer == "baseline":
            return _proc(404, b"<h1>no route</h1>")
        return _proc(404, b"<h1>no route</h1>")

    def test_third_party_cname_and_ptr_names_are_not_probed(self):
        out, fake = _run(self.responder, words=["admin"], recon=self._graph_recon(),
                         VHOST_SNI_USE_GRAPH_CANDIDATES=True)
        probed = fake.probed_hosts()
        assert "example-tenant.idp-provider.test" not in probed
        assert "edge-203-0-113-10.cdn-provider.test" not in probed
        assert f"login.{APEX}" in probed
        assert out["by_ip"][IP]["out_of_scope_skipped"] == 2

    def test_ip_mode_keeps_ptr_names(self):
        recon = self._graph_recon()
        recon["domain"] = "ip-targets.proj1"
        # An IP-mode run always declares its targets; without them nothing is admitted.
        recon["metadata"] = {"target": "ip-targets.proj1", "ip_mode": True, "expanded_ips": [IP]}
        out, fake = _run(self.responder, words=[], recon=recon, VHOST_SNI_USE_GRAPH_CANDIDATES=True)
        assert "edge-203-0-113-10.cdn-provider.test" in fake.probed_hosts()
        assert out["by_ip"][IP]["out_of_scope_skipped"] == 0

    def test_roe_exclusion_removes_even_a_wordlist_name(self):
        out, fake = _run(self.responder, words=["admin", "payments"],
                         ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=[f"payments.{APEX}"])
        assert f"payments.{APEX}" not in fake.probed_hosts()
        assert f"admin.{APEX}" in fake.probed_hosts()
        assert out["by_ip"][IP]["out_of_scope_skipped"] == 1

    def test_roe_entries_are_case_and_dot_insensitive(self):
        _, fake = _run(self.responder, words=["admin", "payments"],
                       ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=[f"Payments.{APEX.upper()}."])
        assert f"payments.{APEX}" not in fake.probed_hosts()

    def test_a_name_both_graph_sourced_and_roe_excluded_is_counted_once(self):
        recon = _recon(dns={"subdomains": {f"payments.{APEX}": {"ips": {"ipv4": [IP], "ipv6": []}}}})
        out, _ = _run(self.responder, words=["payments"], recon=recon, VHOST_SNI_USE_GRAPH_CANDIDATES=True,
                      ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=[f"payments.{APEX}"])
        assert out["by_ip"][IP]["out_of_scope_skipped"] == 1

    def test_roe_is_ignored_when_roe_is_off(self):
        _, fake = _run(self.responder, words=["payments"],
                       ROE_ENABLED=False, ROE_EXCLUDED_HOSTS=[f"payments.{APEX}"])
        assert f"payments.{APEX}" in fake.probed_hosts()

    def test_multi_root_scope(self):
        scope = _build_candidate_scope({"domains": ["example.com", "Example.org."]}, {})
        assert scope.roots == ("example.com", "example.org")
        assert _candidate_in_scope("a.example.org", scope)
        assert _candidate_in_scope("example.com", scope)
        assert not _candidate_in_scope("example.com.attacker.test", scope)
        assert not _candidate_in_scope("notexample.com", scope)

    def test_scope_without_roots_admits_everything_but_roe(self):
        scope = _CandidateScope(roots=(), roe_excluded=("blocked.test",))
        assert _candidate_in_scope("anything.test", scope)
        assert not _candidate_in_scope("blocked.test", scope)


# ===========================================================================
# 6. The probe sends no request to a name it did not need to
# ===========================================================================
def test_controls_use_the_apex_so_a_zone_routed_cdn_is_calibrated():
    seen = []

    def responder(host, layer, attempt):
        seen.append(host)
        return _proc(404, b"x")

    _run(responder, words=["admin"])
    ctrl = [h for h in seen if h and h.startswith(vsm._CONTROL_LABEL_PREFIX)]
    assert any(re.fullmatch(rf"{vsm._CONTROL_LABEL_PREFIX}[0-9a-f]{{10}}-\d\.{re.escape(APEX)}", h) for h in ctrl)
    assert any(h.endswith(".invalid") for h in ctrl)


# ===========================================================================
# 7. A name public DNS already points at this IP is never a hidden vhost
# ===========================================================================
DNS_KNOWN = [f"www.{APEX}", f"shop.{APEX}", f"blog.{APEX}"]


def _site(host: str) -> bytes:
    return f"<html><head><title>{host.split('.')[0]} site</title></head><body>{host} home</body></html>".encode()


class _OnlyHttps(FakeCurl):
    """The DNS block gives every IP a default port 80; keep these cases to 443."""

    def __call__(self, cmd, **kwargs):
        if any(arg.startswith("http://") for arg in cmd):
            self.calls.append((None, "dead"))
            return _proc(0)
        return super().__call__(cmd, **kwargs)


def _shared_ip_recon(extra_dns=None):
    subs = {h: {"ips": {"ipv4": [IP], "ipv6": []}} for h in DNS_KNOWN}
    subs.update(extra_dns or {})
    return _recon(dns={"subdomains": subs})


def _shared_ip_responder(served: dict):
    def responder(host, layer, attempt):
        if layer == "baseline" or host not in served:
            return _proc(404, b"<h1>no route</h1>")
        return served[host](layer)
    return responder


def _run_https(responder, words, recon, **settings):
    fake = _OnlyHttps(responder)
    with patch.object(vsm, "_is_curl_available", return_value=True), \
         patch("subprocess.run", side_effect=fake):
        run_vhost_sni_enrichment(recon, settings=_settings(words, **settings))
    return recon["vhost_sni"], fake


def _same_page(host):
    return lambda layer: _proc(200, _site(host))


class TestDnsKnownNamesAreNotHidden:
    def test_three_dns_known_sites_on_a_shared_ip_are_not_hidden(self):
        served = {h: _same_page(h) for h in DNS_KNOWN}
        out, fake = _run_https(_shared_ip_responder(served), [], _shared_ip_recon(),
                               VHOST_SNI_USE_GRAPH_CANDIDATES=True)
        assert out["findings"] == []
        # Still probed: a routing check needs the request.
        assert set(DNS_KNOWN) <= fake.probed_hosts()
        assert out["by_ip"][IP]["suppressed_dns_known"] == 3

    def test_a_name_with_no_dns_here_is_still_a_hidden_vhost(self):
        served = {h: _same_page(h) for h in DNS_KNOWN + [f"intranet.{APEX}"]}
        out, _ = _run_https(_shared_ip_responder(served), ["intranet"], _shared_ip_recon(),
                            VHOST_SNI_USE_GRAPH_CANDIDATES=True)
        assert [f["hostname"] for f in out["findings"]] == [f"intranet.{APEX}"]
        assert out["findings"][0]["dns_known"] is False
        assert out["findings"][0]["name"] == f"Hidden Virtual Host: intranet.{APEX}"

    def test_a_name_whose_dns_points_elsewhere_is_still_reported(self):
        elsewhere = f"legacy.{APEX}"
        recon = _shared_ip_recon({elsewhere: {"ips": {"ipv4": ["198.51.100.7"], "ipv6": []}}})
        served = {h: _same_page(h) for h in DNS_KNOWN + [elsewhere]}
        out, _ = _run_https(_shared_ip_responder(served), [elsewhere], recon,
                            VHOST_SNI_USE_GRAPH_CANDIDATES=True)
        assert [f["hostname"] for f in out["findings"]] == [elsewhere]

    def test_dns_known_names_are_never_injected_as_baseurls(self):
        served = {h: _same_page(h) for h in DNS_KNOWN + [f"intranet.{APEX}"]}
        recon = _shared_ip_recon()
        out, _ = _run_https(_shared_ip_responder(served), ["intranet"], recon,
                            VHOST_SNI_USE_GRAPH_CANDIDATES=True, VHOST_SNI_INJECT_DISCOVERED=True)
        assert out["discovered_baseurls"] == [f"https://intranet.{APEX}"]
        injected = set((recon.get("http_probe") or {}).get("by_url") or {})
        assert injected == {f"https://intranet.{APEX}"}

    def test_a_dns_known_name_whose_layers_disagree_is_a_routing_finding(self):
        # Host header and SNI reach different backends: that is a routing
        # inconsistency whatever DNS says, so it stays, flagged dns_known.
        host = f"shop.{APEX}"

        def split(layer):
            if layer == "L7":
                return _proc(200, _site(host))
            return _proc(200, b"<html><head><title>internal admin</title></head><body>panel</body></html>")

        served = {h: _same_page(h) for h in DNS_KNOWN}
        served[host] = split
        out, _ = _run_https(_shared_ip_responder(served), [], _shared_ip_recon(),
                            VHOST_SNI_USE_GRAPH_CANDIDATES=True, VHOST_SNI_INJECT_DISCOVERED=True)
        assert [f["hostname"] for f in out["findings"]] == [host]
        f = out["findings"][0]
        assert f["type"] == "host_header_bypass" and f["layer"] == "both"
        assert f["dns_known"] is True
        assert out["discovered_baseurls"] == []

    def test_the_apex_resolving_here_is_dns_known(self):
        recon = _recon(dns={"domain": {"ips": {"ipv4": [IP], "ipv6": []}}, "subdomains": {}})
        out, _ = _run_https(_shared_ip_responder({APEX: _same_page(APEX)}), [APEX], recon)
        assert out["findings"] == []
        assert out["by_ip"][IP]["suppressed_dns_known"] == 1

    def test_a_name_merged_without_addresses_counts_once_httpx_resolved_it_here(self):
        # A certificate-SAN or JS name is merged into the dns block with no
        # addresses; httpx resolves it later in the same run.
        san = f"shop.{APEX}"
        recon = _recon(
            dns={"subdomains": {san: {"has_records": True, "source": "certificate_san"}}},
            http_probe={"by_url": {f"https://{san}": {"url": f"https://{san}", "host": san, "ip": IP}}},
        )
        out, fake = _run_https(_shared_ip_responder({san: _same_page(san)}), [san], recon)
        assert san in fake.probed_hosts()
        assert out["findings"] == []
        assert out["by_ip"][IP]["suppressed_dns_known"] == 1

    def test_httpx_resolving_a_name_elsewhere_does_not_make_it_known_here(self):
        name = f"legacy.{APEX}"
        recon = _recon(http_probe={"by_url": {f"https://{name}": {"url": f"https://{name}", "host": name,
                                                                  "ip": "198.51.100.7"}}})
        out, _ = _run_https(_shared_ip_responder({name: _same_page(name)}), [name], recon)
        assert [f["hostname"] for f in out["findings"]] == [name]

    def test_dns_known_set_reads_the_current_resolution_only(self):
        recon = {"domain": APEX, "dns": {
            "domain": {"ips": {"ipv4": ["198.51.100.1"], "ipv6": []}},
            "subdomains": {
                f"www.{APEX}": {"ips": {"ipv4": [IP], "ipv6": []}},
                f"v6.{APEX}": {"ips": {"ipv4": [], "ipv6": ["2001:db8::1"]}},
                f"gone.{APEX}": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
            }}}
        assert vsm._dns_known_names(recon, IP) == {f"www.{APEX}"}
        assert vsm._dns_known_names(recon, "2001:db8::1") == {f"v6.{APEX}"}
        assert vsm._dns_known_names(recon, "198.51.100.1") == {APEX}


# ===========================================================================
# 8. The default wordlist is not brute-forced against a shared CDN edge
# ===========================================================================
EDGE_WORDS = ["admin", "dev", "jenkins"]


def _edge_recon(cdn="cloudflare", is_cdn=True):
    r = _recon()
    r["port_scan"]["by_ip"] = {IP: {"ip": IP, "is_cdn": is_cdn, "cdn": cdn}}
    return r


def _run_wordlist(recon, words=EDGE_WORDS, **settings):
    def responder(host, layer, attempt):
        return _proc(404, b"<h1>no route</h1>")

    fake = FakeCurl(responder)
    with patch.object(vsm, "_is_curl_available", return_value=True), \
         patch.object(vsm, "_load_default_wordlist", return_value=list(words)), \
         patch("subprocess.run", side_effect=fake):
        run_vhost_sni_enrichment(recon, settings=_settings([], VHOST_SNI_USE_DEFAULT_WORDLIST=True,
                                                           **settings))
    return recon["vhost_sni"], fake


def _wordlist_gaps():
    from recon.helpers import circuit_breaker as cb
    return [g for g in cb.coverage_report().gaps if g["source"] == "vhost_sni_wordlist"]


class TestNoWordlistOnCdnEdges:
    def test_an_edge_ip_gets_no_wordlist_name(self):
        out, fake = _run_wordlist(_edge_recon())
        assert not ({f"{w}.{APEX}" for w in EDGE_WORDS} & fake.probed_hosts())
        assert out["scan_metadata"]["wordlist_skipped_edge_ips"] == [IP]

    def test_a_non_edge_ip_still_gets_the_wordlist(self):
        out, fake = _run_wordlist(_recon())
        assert {f"{w}.{APEX}" for w in EDGE_WORDS} <= fake.probed_hosts()
        assert out["scan_metadata"]["wordlist_skipped_edge_ips"] == []
        assert _wordlist_gaps() == []

    def test_plain_cloud_hosting_is_not_an_edge(self):
        # httpx/naabu flag aws/azure/gcp as CDN too, but such an IP serves the
        # application itself, often behind a Kubernetes ingress with real
        # hidden vhosts: the wordlist must still run there.
        _out, fake = _run_wordlist(_edge_recon(cdn="aws"))
        assert {f"{w}.{APEX}" for w in EDGE_WORDS} <= fake.probed_hosts()

    def test_graph_candidates_and_custom_lines_are_still_probed_on_an_edge(self):
        recon = _edge_recon()
        recon["http_probe"] = {"by_url": {f"https://{IP}": {
            "host": IP, "tls": {"certificate": {"san": [f"staging.{APEX}"]}}}}}
        _out, fake = _run_wordlist(recon, VHOST_SNI_USE_GRAPH_CANDIDATES=True,
                                   VHOST_SNI_CUSTOM_WORDLIST="payments")
        assert f"staging.{APEX}" in fake.probed_hosts()
        assert f"payments.{APEX}" in fake.probed_hosts()
        assert f"admin.{APEX}" not in fake.probed_hosts()

    def test_the_skip_is_a_coverage_note_with_no_prune_effect(self):
        from recon.helpers import circuit_breaker as cb
        _run_wordlist(_edge_recon())
        gaps = _wordlist_gaps()
        assert len(gaps) == 1
        assert gaps[0]["reason"] == "shared CDN edge" and gaps[0]["skipped"] == 1
        assert re.fullmatch(r"[a-z0-9_]{1,64}", gaps[0]["source"])
        assert re.fullmatch(r"[a-z0-9_]{1,64}", gaps[0]["module"])
        report = cb.coverage_report()
        assert "vhost_sni_wordlist" not in report.degraded_sources
        assert "vhost_sni_enum" not in report.degraded_sources

    def test_no_note_when_the_wordlist_is_off_anyway(self):
        recon = _edge_recon()
        fake = FakeCurl(lambda h, l, a: _proc(404, b"x"))
        with patch.object(vsm, "_is_curl_available", return_value=True), \
             patch("subprocess.run", side_effect=fake):
            run_vhost_sni_enrichment(recon, settings=_settings(["admin"]))
        assert _wordlist_gaps() == []
        assert recon["vhost_sni"]["scan_metadata"]["wordlist_skipped_edge_ips"] == []


# ===========================================================================
# 9. IP mode: a PTR name is a DNS name of its IP, never a hidden vhost
# ===========================================================================
def test_ip_mode_ptr_name_serving_its_site_is_not_hidden():
    ptr = "web-7.hosting-provider.test"
    recon = _recon(dns={"subdomains": {ptr: {"ips": {"ipv4": [IP], "ipv6": []}}}})
    recon["domain"] = "ip-targets.proj1"
    # An IP-mode run always declares its targets; without them nothing is admitted.
    recon["metadata"] = {"target": "ip-targets.proj1", "ip_mode": True, "expanded_ips": [IP]}
    out, fake = _run_https(_shared_ip_responder({ptr: _same_page(ptr)}), [], recon,
                           VHOST_SNI_USE_GRAPH_CANDIDATES=True)
    assert ptr in fake.probed_hosts()
    assert out["findings"] == []
    assert out["by_ip"][IP]["suppressed_dns_known"] == 1

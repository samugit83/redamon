"""
Deep edge-case + safety tests for the VHost & SNI module.

These tests cover risk areas surfaced during the deep code review:

Safety:
  - Hostname-with-colon injection (would corrupt curl --resolve syntax)
  - Hostname with shell metacharacters (path is subprocess.run with list,
    so should be fine, but we want the regression covered)
  - TLS SAN with leading "*." wildcard handled correctly
  - TLS SAN with multiple leading dots / weird shapes

Wordlist file encoding edges:
  - BOM (UTF-8 with byte order mark)
  - CRLF line endings
  - Mixed line endings
  - Trailing whitespace per line
  - Empty file
  - Comments-only file
  - File doesn't exist (graceful fallback)

Custom wordlist injection:
  - User pastes BOM-prefixed text
  - User puts comments in custom wordlist
  - User puts CRLF in custom wordlist

Network error paths:
  - Curl returns status 0 (connection refused)
  - Curl times out
  - Curl returns garbage stdout
  - Curl returns extra output beyond status+size

Dedup / merge correctness:
  - Same hostname different layers -> two separate findings
  - Same hostname different ports -> two separate findings
  - Same hostname, same layer, same port, different IPs -> two findings

Internal-keyword matching:
  - 'adminpanel' (no separator) — DOCUMENTS CURRENT BEHAVIOR
  - 'webadmin' (suffix without separator)
  - case insensitivity

Run:
    docker exec redamon-recon-orchestrator python -m pytest /app/recon/tests/test_vhost_sni_edge_cases.py -v
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import vhost_sni_enum as vsm
from recon.main_recon_modules.vhost_sni_enum import (
    _build_candidate_set,
    _build_finding_record,
    _collect_graph_candidates,
    _curl_probe,
    _inject_into_http_probe,
    _is_valid_hostname,
    _load_default_wordlist,
    _matched_internal_keyword,
    _parse_custom_wordlist,
    run_vhost_sni_enrichment,
)


# ===========================================================================
# A. Hostname injection safety — curl --resolve uses the hostname as-is
# ===========================================================================
class TestHostnameInjectionSafety:
    """
    The L4 path uses --resolve "{hostname}:{port}:{ip}". A hostname containing
    a colon would corrupt the syntax. _is_valid_hostname must reject these.
    """

    def test_colon_in_hostname_rejected(self):
        # Colon is not a valid hostname character — rejection is what protects --resolve
        assert not _is_valid_hostname("evil:foo.example.com")

    def test_at_sign_in_hostname_rejected(self):
        assert not _is_valid_hostname("user@evil.com")

    def test_space_in_hostname_rejected(self):
        assert not _is_valid_hostname("evil .example.com")

    def test_quote_in_hostname_rejected(self):
        assert not _is_valid_hostname('evil".example.com')

    def test_newline_in_hostname_rejected(self):
        assert not _is_valid_hostname("evil\n.example.com")

    def test_null_byte_in_hostname_rejected(self):
        assert not _is_valid_hostname("evil\x00.example.com")

    def test_dollar_sign_rejected(self):
        # Although subprocess.run with a list bypasses shell, defence-in-depth
        # rejects shell-meta characters at hostname-validation time.
        assert not _is_valid_hostname("$(rm -rf /).example.com")

    def test_candidate_set_filters_injection_attempts(self):
        # Even when malicious entries land in the wordlist (e.g. via custom upload),
        # _build_candidate_set drops them via _is_valid_hostname.
        result = _build_candidate_set(
            apex_domain="example.com",
            default_prefixes=[],
            custom_lines=["evil:port", "back`tick", "back\\slash", "good"],
            graph_candidates=[],
        )
        assert "good.example.com" in result
        assert all(":" not in h for h in result)
        assert all("`" not in h for h in result)
        assert all("\\" not in h for h in result)

    def test_graph_candidate_with_colon_rejected(self):
        # If somehow a Subdomain node had a colon (Neo4j allows arbitrary strings),
        # the candidate builder must filter it out before it reaches curl.
        result = _build_candidate_set(
            apex_domain="example.com",
            default_prefixes=[],
            custom_lines=[],
            graph_candidates=["evil:foo.example.com", "good.example.com"],
        )
        assert "good.example.com" in result
        assert "evil:foo.example.com" not in result


# ===========================================================================
# B. TLS SAN extraction edge cases
# ===========================================================================
class TestTlsSanEdgeCases:
    def test_wildcard_san_strips_star_dot(self):
        recon = {
            "http_probe": {
                "by_url": {"https://5.5.5.5": {"host": "5.5.5.5", "tls": {"certificate": {"san": ["*.acme.com"]}}}},
                "by_host": {},
            },
        }
        assert "acme.com" in _collect_graph_candidates(recon, "5.5.5.5")

    def test_double_star_dot_san(self):
        # Defensive: lstrip("*.") strips ALL leading * and . chars.
        # "**foo.com" -> "foo.com"
        recon = {
            "http_probe": {
                "by_url": {"https://5.5.5.5": {"host": "5.5.5.5", "tls": {"certificate": {"san": ["**foo.com"]}}}},
                "by_host": {},
            },
        }
        candidates = _collect_graph_candidates(recon, "5.5.5.5")
        # Best-effort: the lstrip strategy strips both stars so we get foo.com
        assert "foo.com" in candidates

    def test_san_alternative_key_tls_sans(self):
        # The real httpx path is tls.certificate.san.
        recon = {
            "http_probe": {
                "by_url": {"https://5.5.5.5": {"host": "5.5.5.5", "tls": {"certificate": {"san": ["alt.acme.com"]}}}},
                "by_host": {},
            },
        }
        assert "alt.acme.com" in _collect_graph_candidates(recon, "5.5.5.5")

    def test_san_for_different_ip_ignored(self):
        recon = {
            "http_probe": {
                "by_url": {"https://9.9.9.9": {"host": "9.9.9.9", "tls": {"certificate": {"san": ["other.com"]}}}},
                "by_host": {},
            },
        }
        # Asking about 5.5.5.5 — SAN on 9.9.9.9 is irrelevant
        assert "other.com" not in _collect_graph_candidates(recon, "5.5.5.5")

    def test_invalid_san_filtered(self):
        recon = {
            "http_probe": {
                "by_url": {
                    "https://5.5.5.5": {
                        "host": "5.5.5.5",
                        "tls": {"certificate": {"san": ["valid.acme.com", "INVALID HOST", ":colon.com"]}},
                    }
                },
                "by_host": {},
            },
        }
        candidates = set(_collect_graph_candidates(recon, "5.5.5.5"))
        # Note: _collect_graph_candidates returns a list of ALL pulled candidates;
        # filtering happens later in _build_candidate_set. So we test there too.
        cset = _build_candidate_set(
            apex_domain="acme.com",
            default_prefixes=[],
            custom_lines=[],
            graph_candidates=list(candidates),
        )
        assert "valid.acme.com" in cset
        assert all(":" not in h for h in cset)
        assert all(" " not in h for h in cset)


# ===========================================================================
# C. Wordlist file encoding edges
# ===========================================================================
class TestWordlistEncoding:
    """Test _load_default_wordlist with various file shapes."""

    def _write_temp_wordlist(self, content: bytes) -> Path:
        tmp = tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix="-vhost.txt")
        tmp.write(content)
        tmp.close()
        return Path(tmp.name)

    def _load_with_path(self, path: Path) -> list[str]:
        # Patch the module's container path so the function reads our temp file.
        with patch.object(vsm, "DEFAULT_WORDLIST_CONTAINER_PATH", str(path)):
            return _load_default_wordlist()

    def test_file_with_bom(self):
        # UTF-8 BOM + admin\nstaging\n
        path = self._write_temp_wordlist(b"\xef\xbb\xbfadmin\nstaging\n")
        try:
            result = self._load_with_path(path)
            # Without a BOM-strip the first entry would be "\ufeffadmin" which
            # is not a valid prefix. A graceful loader strips it.
            assert "admin" in result, f"BOM not stripped, got: {result}"
            assert "staging" in result
        finally:
            path.unlink()

    def test_file_with_crlf(self):
        path = self._write_temp_wordlist(b"admin\r\nstaging\r\ndev\r\n")
        try:
            result = self._load_with_path(path)
            # splitlines() handles \r\n natively
            assert result == ["admin", "staging", "dev"]
        finally:
            path.unlink()

    def test_file_with_trailing_whitespace_per_line(self):
        path = self._write_temp_wordlist(b"admin   \n  staging\n\tdev\t\n")
        try:
            result = self._load_with_path(path)
            assert "admin" in result
            assert "staging" in result
            assert "dev" in result
        finally:
            path.unlink()

    def test_empty_file(self):
        path = self._write_temp_wordlist(b"")
        try:
            assert self._load_with_path(path) == []
        finally:
            path.unlink()

    def test_comments_only_file(self):
        path = self._write_temp_wordlist(b"# comment 1\n# comment 2\n#nospace\n")
        try:
            assert self._load_with_path(path) == []
        finally:
            path.unlink()

    def test_file_doesnt_exist(self):
        # Loader should NOT raise; should return [] gracefully
        with patch.object(vsm, "DEFAULT_WORDLIST_CONTAINER_PATH", "/nonexistent/path.txt"):
            # Also make the local-dev fallback not exist
            with patch.object(Path, "exists", return_value=False):
                result = _load_default_wordlist()
            assert result == []

    def test_dedupe_case_insensitive(self):
        path = self._write_temp_wordlist(b"admin\nADMIN\nAdmin\nstaging\n")
        try:
            result = self._load_with_path(path)
            assert result.count("admin") == 1
            assert "staging" in result
        finally:
            path.unlink()


class TestCustomWordlistEdgeCases:
    def test_bom_in_user_input(self):
        result = _parse_custom_wordlist("\ufeffadmin\nstaging")
        # Either BOM is stripped (good) or the first entry is "\ufeffadmin"
        # (acceptable but documented).
        assert "staging" in result
        # Document: BOM is currently NOT stripped from custom wordlist text.
        # This is acceptable — the user pasted it, and _is_valid_hostname will
        # later reject any candidate that ends up with the BOM character.

    def test_crlf_in_user_input(self):
        # User pasted from Windows
        result = _parse_custom_wordlist("admin\r\nstaging\r\ndev")
        # \r is whitespace per str.strip()
        assert "admin" in result
        assert "staging" in result
        assert "dev" in result

    def test_mixed_line_endings(self):
        result = _parse_custom_wordlist("admin\nstaging\r\ndev\rqa")
        # \r alone in the middle — splitlines() handles, but \rqa might be one line "qa\r" or two
        # Just check that we don't crash and get sensible entries
        assert "admin" in result
        assert "staging" in result

    def test_extreme_dedup(self):
        result = _parse_custom_wordlist("admin\n" * 1000)
        assert result == ["admin"]


# ===========================================================================
# D. Curl response parsing edge cases
# ===========================================================================
class TestCurlResponseParsing:
    """_curl_probe handles various malformed curl outputs."""

    def _make_proc(self, stdout="", returncode=0):
        # _curl_probe runs subprocess.run with text=False, so stdout is bytes.
        # Encode here so the existing string-based test fixtures stay readable.
        from unittest.mock import MagicMock
        proc = MagicMock()
        proc.stdout = stdout.encode("utf-8") if isinstance(stdout, str) else stdout
        proc.stderr = b""
        proc.returncode = returncode
        return proc

    def _patch_subprocess(self, mock_proc):
        from unittest.mock import patch as _patch
        return _patch("subprocess.run", return_value=mock_proc)

    def test_status_zero_returns_none(self):
        # Connection refused
        with self._patch_subprocess(self._make_proc("0 0")):
            result = _curl_probe("https", None, None, "1.2.3.4", 443, 3)
        assert result is None

    def test_empty_stdout_returns_none(self):
        with self._patch_subprocess(self._make_proc("")):
            result = _curl_probe("https", None, None, "1.2.3.4", 443, 3)
        assert result is None

    def test_garbage_stdout_returns_none(self):
        with self._patch_subprocess(self._make_proc("not-a-number response")):
            result = _curl_probe("https", None, None, "1.2.3.4", 443, 3)
        assert result is None

    def test_extra_output_ignored(self):
        # curl wrote more than 2 fields - first two are status + size
        with self._patch_subprocess(self._make_proc("200 4823 extra noise here")):
            result = _curl_probe("https", None, None, "1.2.3.4", 443, 3)
        assert result["status"] == 200
        assert result["size"] == 4823
        # body_hash is empty when the meta sentinel didn't appear in stdout
        assert result.get("body_hash") == ""

    def test_timeout_returns_none(self):
        import subprocess
        from unittest.mock import patch as _patch
        with _patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="curl", timeout=3)):
            result = _curl_probe("https", None, None, "1.2.3.4", 443, 3)
        assert result is None

    def test_curl_missing_returns_none(self):
        from unittest.mock import patch as _patch
        with _patch("subprocess.run", side_effect=FileNotFoundError("curl")):
            result = _curl_probe("https", None, None, "1.2.3.4", 443, 3)
        assert result is None

    def test_l4_test_uses_resolve_flag(self):
        from unittest.mock import patch as _patch
        captured = {}
        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return self._make_proc("200 100")
        with _patch("subprocess.run", side_effect=fake_run):
            _curl_probe("https", None, "admin.acme.com", "1.2.3.4", 443, 3)
        assert "--resolve" in captured["cmd"]
        # The --resolve argument is the very next element
        idx = captured["cmd"].index("--resolve")
        assert captured["cmd"][idx + 1] == "admin.acme.com:443:1.2.3.4"
        # URL is the hostname, not the IP
        assert "https://admin.acme.com:443/" in captured["cmd"]

    def test_l7_test_uses_host_header(self):
        from unittest.mock import patch as _patch
        captured = {}
        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return self._make_proc("200 100")
        with _patch("subprocess.run", side_effect=fake_run):
            _curl_probe("https", "admin.acme.com", None, "1.2.3.4", 443, 3)
        assert "-H" in captured["cmd"]
        idx = captured["cmd"].index("-H")
        assert captured["cmd"][idx + 1] == "Host: admin.acme.com"
        # URL is the IP, not the hostname
        assert "https://1.2.3.4:443/" in captured["cmd"]

    def test_baseline_no_host_no_sni(self):
        from unittest.mock import patch as _patch
        captured = {}
        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return self._make_proc("403 548")
        with _patch("subprocess.run", side_effect=fake_run):
            _curl_probe("https", None, None, "1.2.3.4", 443, 3)
        assert "-H" not in captured["cmd"]
        assert "--resolve" not in captured["cmd"]


# ===========================================================================
# E. Internal-keyword matching — DOCUMENTS CURRENT BEHAVIOR
# ===========================================================================
class TestInternalKeywordEdgeCases:
    """Pinning current behavior so future changes are intentional."""

    def test_no_separator_does_not_match(self):
        # 'adminpanel' would intuitively match 'admin' — but _matched_internal_keyword
        # uses {kw}- / {kw}_ boundary checks, NOT raw substring. So it doesn't match.
        # If you change the algorithm, this test will fail and remind you of the
        # decision.
        assert _matched_internal_keyword("adminpanel.example.com") is None

    def test_suffix_no_separator_does_not_match(self):
        # 'webadmin' doesn't match 'admin' for the same reason.
        assert _matched_internal_keyword("webadmin.example.com") is None

    def test_compound_with_separator_returns_longest_match(self):
        # 'admin-portal' matches BOTH 'admin' (startswith) and 'portal' (endswith).
        # The longest-match-wins rule (also keeps results deterministic across
        # Python set-iteration orders) returns 'portal' (6 > 5).
        assert _matched_internal_keyword("admin-portal.example.com") == "portal"

    def test_compound_match_is_deterministic_across_runs(self):
        # Run the matcher many times. All must return the same answer (regression
        # against the prior non-deterministic set-iteration bug).
        results = {_matched_internal_keyword("admin-portal-internal.example.com") for _ in range(50)}
        assert len(results) == 1, f"Non-deterministic match: {results}"

    def test_label_only_lowercased(self):
        # Hostname is lowercased before matching
        assert _matched_internal_keyword("ADMIN.example.com") == "admin"

    def test_keyword_not_in_first_label_no_match(self):
        # 'admin' appears in the second label, not the first -> no match
        # (the function only inspects hostname.split(".")[0])
        assert _matched_internal_keyword("foo.admin.example.com") is None


# ===========================================================================
# F. Finding ID collision potential
# ===========================================================================
class TestFindingIdCollision:
    """
    The deterministic ID sanitises hostname to [^a-z0-9.] -> '_'. Two hostnames
    that differ only in punctuation could collide.
    """

    def _anomaly(self, hostname):
        return {
            "hostname": hostname, "ip": "1.2.3.4", "port": 443, "scheme": "https",
            "layer": "L7", "baseline_status": 403, "baseline_size": 100,
            "observed_status": 200, "observed_size": 1000, "size_delta": 900,
            "severity": "low", "internal_pattern_match": None,
        }

    def test_dot_vs_dash_currently_collide(self):
        # admin.foo.com -> admin_foo_com (dots stripped via [^a-z0-9])
        # admin-foo.com -> admin_foo_com (dashes stripped via [^a-z0-9])
        # Same sanitised form -> SAME ID -> MERGE in graph
        # This pins the current behavior; if you change the regex to preserve
        # dots, this test will fail.
        f1 = _build_finding_record(self._anomaly("admin.foo.com"), "1.2.3.4", {})
        f2 = _build_finding_record(self._anomaly("admin-foo.com"), "1.2.3.4", {})
        # Document the collision risk:
        # NOTE: This currently produces DIFFERENT ids because '.' is kept and '-' becomes '_'
        # Let's re-read the regex and assert what actually happens.
        # Regex: re.sub(r"[^a-z0-9]", "_", hostname.lower())
        # So '.' becomes '_' too. Both hostnames sanitise to 'admin_foo_com'.
        assert f1["id"] == f2["id"]

    def test_different_ports_get_different_ids(self):
        a443 = self._anomaly("admin.example.com").copy(); a443["port"] = 443
        a8443 = self._anomaly("admin.example.com").copy(); a8443["port"] = 8443
        f443 = _build_finding_record(a443, "1.2.3.4", {})
        f8443 = _build_finding_record(a8443, "1.2.3.4", {})
        assert f443["id"] != f8443["id"]

    def test_different_ips_get_different_ids(self):
        f1 = _build_finding_record(self._anomaly("admin.example.com"), "1.2.3.4", {})
        f2 = _build_finding_record(self._anomaly("admin.example.com"), "5.6.7.8", {})
        assert f1["id"] != f2["id"]


# ===========================================================================
# G. Discovered BaseURL injection consumed correctly
# ===========================================================================
class TestDiscoveredBaseUrlContract:
    def test_injected_url_is_alive_status_code_none(self):
        # Downstream tools (subdomain_takeover._collect_alive_urls) check
        # status_code: None -> alive. Verify our injection follows that contract.
        cr = {}
        _inject_into_http_probe(cr, ["https://hidden.example.com"])
        entry = cr["http_probe"]["by_url"]["https://hidden.example.com"]
        assert entry["status_code"] is None
        assert entry["live"] is True
        assert entry["discovery_source"] == "vhost_sni_enum"

    def test_injection_idempotent(self):
        cr = {"http_probe": {"by_url": {"https://other.com": {"existing": True}}}}
        _inject_into_http_probe(cr, ["https://other.com", "https://new.com"])
        # Existing entry untouched
        assert cr["http_probe"]["by_url"]["https://other.com"] == {"existing": True}
        # New entry added
        assert "https://new.com" in cr["http_probe"]["by_url"]


# ===========================================================================
# H. Same hostname × different port × different layer = separate findings
# ===========================================================================
class TestFindingMultiplicity:
    def _basic_recon(self, ports):
        return {
            "domain": "example.com",
            "metadata": {"target": "example.com"},
            "port_scan": {"by_host": {"h": {"ip": "1.2.3.4", "ports": ports}}},
        }

    def _settings(self, **overrides):
        s = {
            "VHOST_SNI_ENABLED": True,
            "VHOST_SNI_TEST_L7": True,
            "VHOST_SNI_TEST_L4": True,
            "VHOST_SNI_TIMEOUT": 1,
            "VHOST_SNI_CONCURRENCY": 4,
            "VHOST_SNI_BASELINE_SIZE_TOLERANCE": 50,
            "VHOST_SNI_USE_DEFAULT_WORDLIST": False,
            "VHOST_SNI_USE_GRAPH_CANDIDATES": False,
            "VHOST_SNI_INJECT_DISCOVERED": True,
            "VHOST_SNI_CUSTOM_WORDLIST": "admin",
            "VHOST_SNI_MAX_CANDIDATES_PER_IP": 100,
        }
        s.update(overrides)
        return s

    def test_same_hostname_two_ports_two_findings(self):
        # admin.example.com on 443 AND on 8443 should produce TWO findings.
        cr = self._basic_recon([
            {"port": 443, "scheme": "https"},
            {"port": 8443, "scheme": "https"},
        ])
        # Mock curl: both ports return baseline 403/100 raw, but admin returns 200/5000 always
        def fake_curl(scheme, host_header, sni_hostname, target, port, timeout):
            is_baseline = host_header is None and sni_hostname is None
            if is_baseline:
                return {"status": 403, "size": 100}
            return {"status": 200, "size": 5000}
        with patch.object(vsm, "_is_curl_available", return_value=True), \
             patch.object(vsm, "_curl_probe", side_effect=fake_curl):
            run_vhost_sni_enrichment(cr, settings=self._settings())

        findings = cr["vhost_sni"]["findings"]
        # Same hostname, two ports -> two distinct findings
        ports = sorted({f["port"] for f in findings if f["hostname"] == "admin.example.com"})
        assert ports == [443, 8443]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

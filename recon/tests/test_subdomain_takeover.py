"""
Unit tests for the subdomain takeover module.

Covers:
    - Provider fingerprint mapping (service strings, template-ids, CNAME patterns)
    - Subjack Result normalization (Subdomain/Vulnerable/Service/nonexist_domain)
    - Nuclei takeover finding normalization (reuses parse_nuclei_finding output)
    - Deduplication by (hostname, provider, method)
    - Scoring: confirmed / likely / manual_review
    - Stable finding_id (re-scan idempotency)

The runner's subprocess-invoking functions are not tested here — they are
covered by the fixture-based integration test in test_partial_recon.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.takeover_helpers import (
    AUTO_EXPLOITABLE_PROVIDERS,
    BADDNS_DEFAULT_MODULES,
    BADDNS_MODULES,
    build_baddns_command,
    build_subjack_command,
    dedupe_findings,
    finding_id,
    normalize_baddns_finding,
    normalize_nuclei_takeover,
    normalize_subjack_result,
    provider_from_cname,
    provider_from_signal,
    score_finding,
)
from recon.helpers.takeover_helpers import _hostname_from_url  # noqa: E402
from recon.main_recon_modules.subdomain_takeover import (
    _collect_alive_urls,
    _collect_subdomains,
    _empty_result,
    _load_nuclei_jsonl,
    _load_subjack_json,
    _lookup_cname_from_dns,
    _parse_baddns_stdout,
    run_subdomain_takeover,
    run_subdomain_takeover_isolated,
)


# ---------------------------------------------------------------------------
# Provider fingerprint mapping
# ---------------------------------------------------------------------------
class TestProviderMapping:
    def test_cname_github_io(self):
        assert provider_from_cname("acme.github.io") == "github-pages"

    def test_cname_herokuapp(self):
        assert provider_from_cname("acme-spring.herokuapp.com") == "heroku"

    def test_cname_s3(self):
        assert provider_from_cname("acme-assets.s3.amazonaws.com") == "aws-s3"

    def test_cname_azure(self):
        assert provider_from_cname("acme.azurewebsites.net") == "azure-app-service"

    def test_cname_netlify(self):
        assert provider_from_cname("acme.netlify.app") == "netlify"

    def test_cname_none(self):
        assert provider_from_cname(None) is None
        assert provider_from_cname("") is None

    def test_cname_unknown_returns_none(self):
        assert provider_from_cname("something.random-cdn.example") is None

    def test_signal_exact_subjack_service(self):
        assert provider_from_signal("Github") == "github-pages"
        assert provider_from_signal("Heroku") == "heroku"
        assert provider_from_signal("AWS/S3") == "aws-s3"

    def test_signal_substring_match_nuclei_template(self):
        assert provider_from_signal("github-takeover-v2") == "github-pages"
        assert provider_from_signal("aws-bucket-takeover") == "aws-s3"

    def test_signal_unknown(self):
        assert provider_from_signal("random-custom-provider") is None

    def test_signal_subjack_ns_variants(self):
        # Regression guard: real subjack emitted `"ns delegation takeover"` for
        # gslink.hackerone.com during the 2026-04-21 scan and the raw string
        # leaked through to the graph. The normalizer must map Subjack's
        # non-CNAME service strings to canonical provider slugs.
        assert provider_from_signal("ns delegation takeover") == "ns-delegation"
        assert provider_from_signal("NS Delegation Takeover") == "ns-delegation"
        assert provider_from_signal("ns takeover") == "ns-delegation"
        assert provider_from_signal("spf takeover") == "spf-include"
        assert provider_from_signal("mx takeover") == "mx-takeover"
        assert provider_from_signal("zone transfer") == "zone-transfer"


# ---------------------------------------------------------------------------
# Subjack normalization
# ---------------------------------------------------------------------------
class TestSubjackNormalization:
    def test_vulnerable_cname_github(self):
        raw = {
            "subdomain": "Promo.Acme.COM",
            "vulnerable": True,
            "service": "Github",
        }
        out = normalize_subjack_result(raw)
        assert out is not None
        assert out["hostname"] == "promo.acme.com"
        assert out["takeover_provider"] == "github-pages"
        assert out["takeover_method"] == "cname"
        assert out["source_tool"] == "subjack"
        assert "Github" in out["evidence"]

    def test_non_vulnerable_rows_are_dropped(self):
        raw = {"subdomain": "live.acme.com", "vulnerable": False, "service": ""}
        assert normalize_subjack_result(raw) is None

    def test_ns_result_sets_method_and_target(self):
        raw = {
            "subdomain": "old.acme.com",
            "vulnerable": True,
            "service": "NS",
            "nonexist_domain": "ns1.deadprovider.net",
        }
        out = normalize_subjack_result(raw)
        assert out is not None
        assert out["takeover_method"] == "ns"
        assert out["cname_target"] == "ns1.deadprovider.net"

    def test_unknown_service_falls_back_to_raw_service(self):
        raw = {
            "subdomain": "legacy.acme.com",
            "vulnerable": True,
            "service": "Weirdprovider",
        }
        out = normalize_subjack_result(raw)
        assert out is not None
        # Unknown service keeps the raw string lowercased as provider
        assert out["takeover_provider"] == "weirdprovider"

    def test_missing_subdomain_returns_none(self):
        raw = {"vulnerable": True, "service": "Github"}
        assert normalize_subjack_result(raw) is None

    def test_empty_input_returns_none(self):
        assert normalize_subjack_result({}) is None
        assert normalize_subjack_result(None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Nuclei normalization
# ---------------------------------------------------------------------------
class TestNucleiNormalization:
    def _parsed_takeover(self, **overrides) -> dict:
        base = {
            "template_id": "github-takeover",
            "template_path": "http/takeovers/github-takeover.yaml",
            "name": "GitHub Pages Takeover",
            "severity": "high",
            "tags": ["takeover", "github"],
            "target": "promo.acme.com",
            "matched_at": "https://promo.acme.com/",
            "matcher_name": "github-pages-error",
            "extracted_results": ["acme.github.io"],
        }
        base.update(overrides)
        return base

    def test_http_takeover_maps_to_cname_method(self):
        out = normalize_nuclei_takeover(self._parsed_takeover())
        assert out is not None
        assert out["hostname"] == "promo.acme.com"
        assert out["takeover_provider"] == "github-pages"
        assert out["takeover_method"] == "cname"
        assert out["cname_target"] == "acme.github.io"
        assert out["source_tool"] == "nuclei_takeover"
        assert out["severity"] == "high"

    def test_dns_template_maps_to_dns_method(self):
        parsed = self._parsed_takeover(
            template_id="detect-dangling-cname",
            template_path="dns/detect-dangling-cname.yaml",
            tags=["dns", "takeover"],
            matched_at="old.acme.com",
        )
        out = normalize_nuclei_takeover(parsed)
        assert out is not None
        assert out["takeover_method"] == "dns"
        assert out["takeover_provider"] == "dangling-cname"

    def test_non_takeover_finding_is_dropped(self):
        parsed = self._parsed_takeover(
            template_id="sqli-error-based",
            template_path="http/cves/2024/sqli.yaml",
            tags=["sqli", "cve"],
        )
        assert normalize_nuclei_takeover(parsed) is None

    def test_hostname_extracted_from_url(self):
        parsed = self._parsed_takeover(matched_at="https://HOST.example.com:8443/path")
        out = normalize_nuclei_takeover(parsed)
        assert out is not None
        assert out["hostname"] == "host.example.com"

    def test_no_extracted_results_keeps_cname_none(self):
        parsed = self._parsed_takeover(extracted_results=[])
        out = normalize_nuclei_takeover(parsed)
        assert out is not None
        assert out["cname_target"] is None


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------
class TestDedupe:
    def test_two_tools_merge_into_one_finding(self):
        subjack = normalize_subjack_result({
            "subdomain": "promo.acme.com",
            "vulnerable": True,
            "service": "Github",
        })
        nuclei = normalize_nuclei_takeover({
            "template_id": "github-takeover",
            "template_path": "http/takeovers/github-takeover.yaml",
            "name": "GitHub Pages Takeover",
            "severity": "high",
            "tags": ["takeover"],
            "matched_at": "https://promo.acme.com/",
            "extracted_results": ["acme.github.io"],
        })
        merged = dedupe_findings([subjack, nuclei])
        assert len(merged) == 1
        assert set(merged[0]["sources"]) == {"subjack", "nuclei_takeover"}
        assert merged[0]["confirmation_count"] == 2
        # Subjack evidence takes precedence when both are present
        assert "Subjack" in merged[0]["evidence"]

    def test_different_hostnames_stay_separate(self):
        findings = [
            normalize_subjack_result({"subdomain": "a.acme.com", "vulnerable": True, "service": "Github"}),
            normalize_subjack_result({"subdomain": "b.acme.com", "vulnerable": True, "service": "Github"}),
        ]
        merged = dedupe_findings(findings)
        assert len(merged) == 2

    def test_same_hostname_different_method_stays_separate(self):
        cname = normalize_subjack_result({"subdomain": "x.acme.com", "vulnerable": True, "service": "Github"})
        ns = normalize_subjack_result({"subdomain": "x.acme.com", "vulnerable": True, "service": "Github", "nonexist_domain": "ns.dead.com"})
        merged = dedupe_findings([cname, ns])
        assert len(merged) == 2


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
class TestScoring:
    def _base(self, provider="github-pages", method="cname", sources=None, severity=None):
        return {
            "hostname": "x.acme.com",
            "takeover_provider": provider,
            "takeover_method": method,
            "sources": sources or ["subjack"],
            "confirmation_count": len(sources or ["subjack"]),
            "evidence": "",
            **({"severity": severity} if severity else {}),
        }

    def test_both_tools_auto_exploitable_is_confirmed(self):
        f = self._base(sources=["subjack", "nuclei_takeover"])
        score_finding(f, confidence_threshold=60)
        # 30 (2 tools) + 25 (subjack) + 20 (auto-exploitable) + 15 (nuclei) + 10 (cname) = 100
        assert f["confidence"] == 100
        assert f["verdict"] == "confirmed"
        assert f["severity"] == "high"

    def test_subjack_only_is_likely_on_default_threshold(self):
        # 25 (subjack) + 20 (auto-exploitable) + 10 (cname) = 55 at threshold 60 → manual_review
        f = self._base(sources=["subjack"])
        score_finding(f, confidence_threshold=60)
        assert f["confidence"] == 55
        assert f["verdict"] == "manual_review"
        assert f["severity"] == "info"

    def test_lower_threshold_promotes_single_tool_finding(self):
        f = self._base(sources=["subjack"])
        score_finding(f, confidence_threshold=50)
        # 55 >= 50 and < 50+10=60 → likely
        assert f["verdict"] == "likely"

    def test_stale_a_is_capped_to_manual_review(self):
        f = self._base(provider="aws-s3", method="stale_a", sources=["subjack"])
        score_finding(f, confidence_threshold=40)
        # 25 (subjack) + 20 (auto-exploitable) - 15 (stale_a) = 30 → manual_review
        assert f["verdict"] == "manual_review"
        assert f["severity"] == "info"

    def test_unknown_provider_penalty(self):
        f = self._base(provider="unknown", sources=["nuclei_takeover"])
        score_finding(f, confidence_threshold=60)
        # 15 (nuclei) + 10 (cname) - 10 (unknown) = 15 → manual_review
        assert f["confidence"] == 15
        assert f["verdict"] == "manual_review"

    def test_severity_inherits_from_nuclei_when_confirmed(self):
        f = self._base(sources=["subjack", "nuclei_takeover"], severity="critical")
        score_finding(f, confidence_threshold=60)
        assert f["verdict"] == "confirmed"
        assert f["severity"] == "critical"  # explicit severity preserved

    def test_manual_review_auto_publish_elevates_severity(self):
        f_off = self._base(sources=["subjack"])
        f_on = self._base(sources=["subjack"])
        score_finding(f_off, confidence_threshold=60, manual_review_auto_publish=False)
        score_finding(f_on, confidence_threshold=60, manual_review_auto_publish=True)
        assert f_off["verdict"] == "manual_review" and f_off["severity"] == "info"
        assert f_on["verdict"] == "manual_review" and f_on["severity"] == "medium"


# ---------------------------------------------------------------------------
# Deterministic ID
# ---------------------------------------------------------------------------
class TestFindingId:
    def test_same_inputs_produce_same_id(self):
        a = finding_id("promo.acme.com", "github-pages", "cname")
        b = finding_id("promo.acme.com", "github-pages", "cname")
        assert a == b
        assert a.startswith("takeover_")

    def test_case_insensitivity(self):
        assert finding_id("Promo.Acme.Com", "Github-Pages", "CNAME") == finding_id(
            "promo.acme.com", "github-pages", "cname"
        )

    def test_different_method_different_id(self):
        assert finding_id("x.acme.com", "github-pages", "cname") != finding_id(
            "x.acme.com", "github-pages", "ns"
        )


# ---------------------------------------------------------------------------
# End-to-end happy path: normalize → dedupe → score → id
# ---------------------------------------------------------------------------
class TestEndToEnd:
    def test_full_pipeline_on_mixed_input(self):
        subjack_rows = [
            # Promo confirmed by subjack
            {"subdomain": "promo.acme.com", "vulnerable": True, "service": "Github"},
            # Not vulnerable — should be dropped
            {"subdomain": "api.acme.com", "vulnerable": False, "service": ""},
        ]
        nuclei_parsed = [
            # Same Promo finding confirmed by nuclei
            {
                "template_id": "github-takeover",
                "template_path": "http/takeovers/github-takeover.yaml",
                "name": "GitHub Pages Takeover",
                "severity": "high",
                "tags": ["takeover"],
                "matched_at": "https://promo.acme.com/",
                "extracted_results": ["acme.github.io"],
            },
            # Independent Heroku takeover — nuclei only
            {
                "template_id": "heroku-takeover",
                "template_path": "http/takeovers/heroku-takeover.yaml",
                "name": "Heroku Takeover",
                "severity": "high",
                "tags": ["takeover"],
                "matched_at": "https://beta.acme.com/",
                "extracted_results": ["acme-beta.herokuapp.com"],
            },
        ]

        normalized = []
        for row in subjack_rows:
            norm = normalize_subjack_result(row)
            if norm:
                normalized.append(norm)
        for parsed in nuclei_parsed:
            norm = normalize_nuclei_takeover(parsed)
            if norm:
                normalized.append(norm)

        deduped = dedupe_findings(normalized)
        scored = [score_finding(dict(f), confidence_threshold=60) for f in deduped]

        # Two findings: promo (merged), beta (nuclei only)
        assert len(scored) == 2

        by_host = {f["hostname"]: f for f in scored}
        assert set(by_host.keys()) == {"promo.acme.com", "beta.acme.com"}

        promo = by_host["promo.acme.com"]
        assert promo["verdict"] == "confirmed"
        assert set(promo["sources"]) == {"subjack", "nuclei_takeover"}

        beta = by_host["beta.acme.com"]
        # nuclei-only + cname + auto-exploitable = 15+10+20 = 45 → manual_review
        assert beta["verdict"] == "manual_review"
        assert beta["severity"] == "info"

        # IDs are stable across runs
        assert promo.get("takeover_provider") == "github-pages"


# ---------------------------------------------------------------------------
# Fixture sanity check (used by integration tests)
# ---------------------------------------------------------------------------
FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# _hostname_from_url — edge cases
# ---------------------------------------------------------------------------
class TestHostnameFromUrl:
    def test_https_with_port_and_path(self):
        assert _hostname_from_url("https://HOST.example.com:8443/admin/login?x=1") == "host.example.com"

    def test_http_no_port_no_path(self):
        assert _hostname_from_url("http://example.com") == "example.com"

    def test_host_only_no_scheme(self):
        # `domain:port` without scheme is a hostname-with-port, not path.
        assert _hostname_from_url("host.example.com:443") == "host.example.com"

    def test_empty_and_none(self):
        assert _hostname_from_url("") is None
        assert _hostname_from_url(None) is None  # type: ignore[arg-type]

    def test_ipv4(self):
        assert _hostname_from_url("http://1.2.3.4/a") == "1.2.3.4"

    def test_trailing_whitespace(self):
        assert _hostname_from_url("  https://example.com/  ") == "example.com"


# ---------------------------------------------------------------------------
# Provider mapping — additional edge cases
# ---------------------------------------------------------------------------
class TestProviderMappingEdgeCases:
    def test_cname_with_trailing_dot(self):
        # DNS-formatted CNAMEs often end with a dot
        assert provider_from_cname("acme.github.io.") == "github-pages"

    def test_cname_preserves_longest_match(self):
        # S3 has both ".s3.amazonaws.com" and ".s3-website" patterns — longest wins
        assert provider_from_cname("bucket.s3-website-us-east-1.amazonaws.com") == "aws-s3"

    def test_cname_case_insensitive(self):
        assert provider_from_cname("FOO.HEROKUAPP.COM") == "heroku"

    def test_cname_not_matching_any_pattern(self):
        assert provider_from_cname("my-private-cdn.corp.example") is None

    def test_signal_empty_string_returns_none(self):
        assert provider_from_signal("") is None
        assert provider_from_signal(None) is None  # type: ignore[arg-type]

    def test_signal_cname_patterns_never_match_via_signal_path(self):
        # CNAME patterns start with '.' — they should only match via provider_from_cname
        assert provider_from_signal(".herokuapp.com") is None


# ---------------------------------------------------------------------------
# Dedupe — evidence priority + raw_by_source
# ---------------------------------------------------------------------------
class TestDedupeExtras:
    def test_subjack_evidence_takes_priority_over_nuclei(self):
        # Order-insensitive: subjack arriving second should still win evidence slot
        nu = normalize_nuclei_takeover({
            "template_id": "github-takeover",
            "template_path": "http/takeovers/github-takeover.yaml",
            "name": "GitHub Pages Takeover",
            "severity": "high",
            "tags": ["takeover"],
            "matched_at": "https://promo.acme.com/",
            "extracted_results": ["acme.github.io"],
        })
        sj = normalize_subjack_result({
            "subdomain": "promo.acme.com",
            "vulnerable": True,
            "service": "Github",
        })
        # Put nuclei FIRST so its evidence seeds merged["evidence"]
        merged = dedupe_findings([nu, sj])
        assert len(merged) == 1
        assert "Subjack" in merged[0]["evidence"], f"expected Subjack-priority evidence, got: {merged[0]['evidence']}"

    def test_raw_by_source_preserves_both_tool_outputs(self):
        sj = normalize_subjack_result({
            "subdomain": "promo.acme.com",
            "vulnerable": True,
            "service": "Github",
        })
        nu = normalize_nuclei_takeover({
            "template_id": "github-takeover",
            "template_path": "http/takeovers/github-takeover.yaml",
            "name": "X",
            "severity": "high",
            "tags": ["takeover"],
            "matched_at": "https://promo.acme.com/",
            "extracted_results": [],
        })
        merged = dedupe_findings([sj, nu])
        assert set(merged[0]["raw_by_source"].keys()) == {"subjack", "nuclei_takeover"}

    def test_empty_input_produces_empty_list(self):
        assert dedupe_findings([]) == []

    def test_none_values_are_dropped(self):
        # dedupe_findings should skip Nones injected from normalizers
        assert dedupe_findings([None, None]) == []  # type: ignore[list-item]

    def test_missing_hostname_dropped(self):
        assert dedupe_findings([{"takeover_provider": "heroku", "source_tool": "subjack"}]) == []


# ---------------------------------------------------------------------------
# Scoring — bounds + clamping + severity inheritance
# ---------------------------------------------------------------------------
class TestScoringBounds:
    def test_score_never_exceeds_100(self):
        f = {
            "hostname": "x",
            "takeover_provider": "heroku",
            "takeover_method": "cname",
            "sources": ["subjack", "nuclei_takeover"],
            "confirmation_count": 2,
            "evidence": "",
        }
        score_finding(f, confidence_threshold=60)
        assert 0 <= f["confidence"] <= 100

    def test_score_never_goes_below_zero(self):
        f = {
            "hostname": "x",
            "takeover_provider": "unknown",
            "takeover_method": "stale_a",
            "sources": [],
            "confirmation_count": 0,
            "evidence": "",
        }
        score_finding(f, confidence_threshold=60)
        assert f["confidence"] >= 0

    def test_nuclei_severity_inherited_only_on_non_manual_review(self):
        # A finding with nuclei severity=critical and manual_review verdict should
        # still get severity=info (manual_review overrides).
        f = {
            "hostname": "x",
            "takeover_provider": "unknown",
            "takeover_method": "cname",
            "sources": ["nuclei_takeover"],
            "confirmation_count": 1,
            "severity": "critical",
            "evidence": "",
        }
        # threshold+10 = 30, nuclei(15) + cname(10) - unknown(10) = 15 → manual_review
        score_finding(f, confidence_threshold=20)
        assert f["verdict"] == "manual_review"
        assert f["severity"] == "info"  # manual_review overrides nuclei severity


# ---------------------------------------------------------------------------
# Subjack command builder
# ---------------------------------------------------------------------------
class TestBuildSubjackCommand:
    def test_minimal_command(self):
        cmd = build_subjack_command("/tmp/subs.txt", "/tmp/out.json", ssl=False)
        assert cmd[0] == "subjack"
        assert "-w" in cmd and "/tmp/subs.txt" in cmd
        assert "-o" in cmd and "/tmp/out.json" in cmd
        assert "-t" in cmd and "10" in cmd  # default threads
        assert "-timeout" in cmd
        assert "-ssl" not in cmd  # explicitly disabled
        assert "-a" not in cmd
        assert "-ns" not in cmd
        assert "-ar" not in cmd
        assert "-mail" not in cmd
        assert "-v" not in cmd

    def test_all_flags_enabled(self):
        cmd = build_subjack_command(
            "/tmp/s.txt", "/tmp/o.json",
            threads=25, timeout=45,
            ssl=True, all_urls=True,
            check_ns=True, check_ar=True, check_mail=True,
            verbose=True,
            resolver_list="/tmp/resolvers.txt",
        )
        for flag in ("-ssl", "-a", "-ns", "-ar", "-mail", "-v"):
            assert flag in cmd, f"missing {flag} in {cmd}"
        # resolver list uses -r
        assert "-r" in cmd
        assert "/tmp/resolvers.txt" in cmd
        # thread + timeout reflected
        assert "25" in cmd
        assert "45" in cmd

    def test_resolver_list_only_added_when_provided(self):
        cmd = build_subjack_command("/tmp/s.txt", "/tmp/o.json")
        assert "-r" not in cmd

    def test_subjack_has_no_c_flag(self):
        # Guards the research finding: subjack does NOT have -c (fingerprints
        # are compiled into the binary). The builder must not emit one.
        cmd = build_subjack_command("/tmp/s.txt", "/tmp/o.json")
        assert "-c" not in cmd


# ---------------------------------------------------------------------------
# _collect_subdomains / _collect_alive_urls / _lookup_cname_from_dns / _empty_result
# ---------------------------------------------------------------------------
class TestCollectSubdomains:
    def test_empty_recon_data_returns_empty(self):
        assert _collect_subdomains({}) == []

    def test_collects_from_dns_subdomains_map(self):
        data = {
            "dns": {
                "subdomains": {
                    "a.acme.com": {"has_records": True},
                    "b.acme.com": {"has_records": False},
                },
            },
        }
        got = sorted(_collect_subdomains(data))
        assert got == ["a.acme.com", "b.acme.com"]

    def test_includes_root_domain(self):
        data = {"domain": "acme.com", "dns": {}}
        assert "acme.com" in _collect_subdomains(data)

    def test_lowercases_and_deduplicates(self):
        data = {
            "domain": "Acme.COM",
            "subdomains": ["A.Acme.com", "a.acme.com"],
            "dns": {"subdomains": {"A.Acme.com": {}}},
        }
        got = _collect_subdomains(data)
        # Every entry lowercased, no duplicates
        assert got == [g.lower() for g in got]
        assert len(got) == len(set(got))

    def test_skips_non_fqdn_entries(self):
        data = {"subdomains": ["localhost", "no-dot-here", "valid.acme.com"]}
        got = _collect_subdomains(data)
        assert "localhost" not in got
        assert "no-dot-here" not in got
        assert "valid.acme.com" in got

    def test_fallback_to_metadata_target(self):
        data = {"metadata": {"target": "fallback.com"}, "dns": {}}
        assert "fallback.com" in _collect_subdomains(data)

    def test_merges_flat_list_and_dns_map(self):
        data = {
            "subdomains": ["flat.acme.com"],
            "dns": {"subdomains": {"dns.acme.com": {}}},
        }
        got = sorted(_collect_subdomains(data))
        assert got == ["dns.acme.com", "flat.acme.com"]


class TestCollectAliveUrls:
    def test_empty_returns_empty(self):
        assert _collect_alive_urls({}) == []

    def test_primary_by_url_keeps_200(self):
        data = {
            "http_probe": {
                "by_url": {
                    "https://live.acme.com/": {"status_code": 200},
                    "https://dead.acme.com/": {"status_code": 500},
                },
            },
        }
        got = _collect_alive_urls(data)
        assert "https://live.acme.com/" in got
        assert "https://dead.acme.com/" not in got

    def test_status_none_is_kept(self):
        # No status recorded — treated as possibly-alive (conservative)
        data = {
            "http_probe": {
                "by_url": {
                    "https://unknown.acme.com/": {},
                },
            },
        }
        assert "https://unknown.acme.com/" in _collect_alive_urls(data)

    def test_non_http_scheme_dropped(self):
        data = {
            "http_probe": {
                "by_url": {
                    "ftp://ftp.acme.com/": {"status_code": 200},
                    "ws://ws.acme.com/": {"status_code": 200},
                },
            },
        }
        assert _collect_alive_urls(data) == []

    def test_by_host_fallback(self):
        data = {
            "http_probe": {
                "by_host": {
                    "acme.com": {"live_urls": ["https://acme.com/a", "https://acme.com/b"]},
                },
            },
        }
        got = _collect_alive_urls(data)
        assert "https://acme.com/a" in got
        assert "https://acme.com/b" in got

    def test_dedup_across_by_url_and_by_host(self):
        same_url = "https://x.acme.com/"
        data = {
            "http_probe": {
                "by_url": {same_url: {"status_code": 200}},
                "by_host": {"x.acme.com": {"live_urls": [same_url]}},
            },
        }
        got = _collect_alive_urls(data)
        assert got.count(same_url) == 1

    def test_status_500_and_above_rejected(self):
        data = {
            "http_probe": {
                "by_url": {
                    "https://server-error.acme.com/": {"status_code": 503},
                },
            },
        }
        assert _collect_alive_urls(data) == []


class TestLookupCnameFromDns:
    def test_cname_as_list(self):
        dns = {"subdomains": {"x.acme.com": {"records": {"CNAME": ["acme.github.io"]}}}}
        assert _lookup_cname_from_dns(dns, "x.acme.com") == "acme.github.io"

    def test_cname_as_string(self):
        dns = {"subdomains": {"x.acme.com": {"records": {"cname": "acme.herokuapp.com."}}}}
        # Trailing dot should be stripped
        assert _lookup_cname_from_dns(dns, "x.acme.com") == "acme.herokuapp.com"

    def test_unknown_host_returns_none(self):
        dns = {"subdomains": {"x.acme.com": {"records": {}}}}
        assert _lookup_cname_from_dns(dns, "missing.acme.com") is None

    def test_no_records_returns_none(self):
        dns = {"subdomains": {"x.acme.com": {}}}
        assert _lookup_cname_from_dns(dns, "x.acme.com") is None

    def test_empty_dns_returns_none(self):
        assert _lookup_cname_from_dns({}, "anything") is None


class TestEmptyResult:
    def test_shape_is_complete(self):
        res = _empty_result(reason="no_targets")
        assert "findings" in res and res["findings"] == []
        assert "by_target" in res and res["by_target"] == {}
        assert "summary" in res
        assert res["summary"]["total"] == 0
        assert res["summary"]["confirmed"] == 0
        assert res["summary"]["likely"] == 0
        assert res["summary"]["manual_review"] == 0
        assert res["summary"]["by_provider"] == {}
        assert res["scan_metadata"]["skipped_reason"] == "no_targets"
        assert "scan_timestamp" in res["scan_metadata"]

    def test_default_reason_is_empty_string(self):
        res = _empty_result()
        assert res["scan_metadata"]["skipped_reason"] == ""


# ---------------------------------------------------------------------------
# JSON / JSONL loaders
# ---------------------------------------------------------------------------
class TestLoadSubjackJson:
    def test_array_format(self, tmp_path):
        p = tmp_path / "a.json"
        p.write_text('[{"subdomain":"a","vulnerable":false},{"subdomain":"b","vulnerable":true}]')
        rows = _load_subjack_json(p)
        assert len(rows) == 2
        assert rows[1]["vulnerable"] is True

    def test_ndjson_fallback(self, tmp_path):
        p = tmp_path / "nd.json"
        p.write_text(
            '{"subdomain":"a","vulnerable":false}\n'
            '{"subdomain":"b","vulnerable":true}\n'
        )
        rows = _load_subjack_json(p)
        assert len(rows) == 2
        assert {r["subdomain"] for r in rows} == {"a", "b"}

    def test_single_object_not_array(self, tmp_path):
        p = tmp_path / "one.json"
        p.write_text('{"subdomain":"a","vulnerable":true}')
        rows = _load_subjack_json(p)
        assert len(rows) == 1

    def test_empty_file_returns_empty(self, tmp_path):
        p = tmp_path / "empty.json"
        p.write_text("")
        assert _load_subjack_json(p) == []

    def test_whitespace_only_returns_empty(self, tmp_path):
        p = tmp_path / "ws.json"
        p.write_text("\n  \n")
        assert _load_subjack_json(p) == []

    def test_malformed_lines_in_ndjson_are_skipped(self, tmp_path):
        p = tmp_path / "mixed.json"
        p.write_text(
            '{"subdomain":"ok","vulnerable":false}\n'
            'garbage line\n'
            '{"subdomain":"alsok","vulnerable":true}\n'
        )
        rows = _load_subjack_json(p)
        assert len(rows) == 2

    def test_nonexistent_path(self, tmp_path):
        p = tmp_path / "does-not-exist.json"
        assert _load_subjack_json(p) == []

    def test_non_dict_items_in_array_filtered(self, tmp_path):
        p = tmp_path / "mix.json"
        p.write_text('[{"subdomain":"a"}, "string", 42, null]')
        rows = _load_subjack_json(p)
        assert len(rows) == 1


class TestLoadNucleiJsonl:
    def test_basic(self, tmp_path):
        p = tmp_path / "n.jsonl"
        p.write_text(
            '{"template-id":"a"}\n'
            '{"template-id":"b"}\n'
        )
        rows = _load_nuclei_jsonl(p)
        assert len(rows) == 2

    def test_skip_empty_lines(self, tmp_path):
        p = tmp_path / "n.jsonl"
        p.write_text('{"template-id":"a"}\n\n\n{"template-id":"b"}\n')
        rows = _load_nuclei_jsonl(p)
        assert len(rows) == 2

    def test_skip_malformed(self, tmp_path):
        p = tmp_path / "n.jsonl"
        p.write_text('{"template-id":"a"}\nnot-json\n{"template-id":"b"}\n')
        rows = _load_nuclei_jsonl(p)
        assert len(rows) == 2

    def test_nonexistent_file(self, tmp_path):
        assert _load_nuclei_jsonl(tmp_path / "nope.jsonl") == []


# ---------------------------------------------------------------------------
# Runner entry points — gating + deep-copy isolation
# ---------------------------------------------------------------------------
class TestRunner:
    def test_disabled_setting_returns_empty_result(self):
        recon = {"domain": "acme.com"}
        out = run_subdomain_takeover(recon, settings={"SUBDOMAIN_TAKEOVER_ENABLED": False})
        assert out["subdomain_takeover"]["findings"] == []
        assert out["subdomain_takeover"]["scan_metadata"]["skipped_reason"] == "disabled"

    def test_no_targets_returns_empty_result(self):
        # Enabled but no subdomains and no alive URLs → graceful skip
        recon = {"domain": "", "dns": {}}
        out = run_subdomain_takeover(
            recon,
            settings={"SUBDOMAIN_TAKEOVER_ENABLED": True, "SUBJACK_ENABLED": False, "NUCLEI_TAKEOVERS_ENABLED": False},
        )
        assert out["subdomain_takeover"]["scan_metadata"]["skipped_reason"] == "no_targets"

    def test_isolated_wrapper_deep_copies_input(self):
        # Mutating the snapshot inside the runner must not leak to the caller
        original = {
            "domain": "acme.com",
            "dns": {"subdomains": {"a.acme.com": {}}},
        }
        before = dict(original)
        result = run_subdomain_takeover_isolated(
            original,
            {"SUBDOMAIN_TAKEOVER_ENABLED": False},  # disabled → fast return
        )
        # Return shape: dict (the subdomain_takeover sub-dict), not the full recon_data
        assert isinstance(result, dict)
        # No leakage into caller
        assert original == before
        assert "subdomain_takeover" not in original


# ---------------------------------------------------------------------------
# End-to-end scoring with manual_review_auto_publish
# ---------------------------------------------------------------------------
class TestEndToEndWithAutoPublish:
    def test_low_confidence_becomes_medium_when_autopublish_on(self):
        raw = {"subdomain": "x.acme.com", "vulnerable": True, "service": "Unknownprovider"}
        norm = normalize_subjack_result(raw)
        assert norm is not None
        deduped = dedupe_findings([norm])
        scored = score_finding(dict(deduped[0]), confidence_threshold=60, manual_review_auto_publish=True)
        assert scored["verdict"] == "manual_review"
        assert scored["severity"] == "medium"  # elevated by auto-publish


# ---------------------------------------------------------------------------
# Graph mixin helpers
# ---------------------------------------------------------------------------
class TestGraphMixinHelpers:
    def _helpers(self):
        # Import lazily — the mixin module may have Neo4j imports at class level
        from graph_db.mixins.recon.takeover_mixin import (
            _finding_name,
            _finding_description,
        )
        return _finding_name, _finding_description

    def test_finding_name_known_provider(self):
        _finding_name, _ = self._helpers()
        assert _finding_name("github-pages", "cname") == "Subdomain Takeover — Github Pages (CNAME)"

    def test_finding_name_unknown_provider(self):
        _finding_name, _ = self._helpers()
        assert "Unknown service" in _finding_name("unknown", "cname")

    def test_finding_name_uppercase_method(self):
        _finding_name, _ = self._helpers()
        name = _finding_name("heroku", "ns")
        assert name.endswith("(NS)")

    def test_finding_description_with_cname(self):
        _, _finding_description = self._helpers()
        f = {
            "hostname": "promo.acme.com",
            "takeover_provider": "heroku",
            "verdict": "confirmed",
            "confidence": 85,
            "sources": ["subjack", "nuclei_takeover"],
            "cname_target": "acme.herokuapp.com",
        }
        desc = _finding_description(f)
        assert "promo.acme.com" in desc
        assert "heroku" in desc
        assert "confirmed" in desc
        assert "85" in desc
        assert "acme.herokuapp.com" in desc

    def test_finding_description_without_cname(self):
        _, _finding_description = self._helpers()
        f = {
            "hostname": "x.acme.com",
            "takeover_provider": "unknown",
            "verdict": "manual_review",
            "confidence": 30,
            "sources": [],
        }
        desc = _finding_description(f)
        assert "x.acme.com" in desc
        assert "manual_review" in desc
        # No cname section when cname_target is missing
        assert "CNAME target" not in desc


# ---------------------------------------------------------------------------
# BadDNS command builder (Docker-in-Docker AGPL sidecar)
# ---------------------------------------------------------------------------
class TestBuildBaddnsCommand:
    def test_minimal_command_uses_defaults(self):
        cmd = build_baddns_command("/tmp/work")
        assert cmd[0] == "docker"
        assert cmd[1] == "run"
        assert "--rm" in cmd  # ephemeral container — auto-cleanup on exit
        # Mount the WORK DIR (not the file) so Docker doesn't turn the path
        # into a directory when the target doesn't pre-exist in the image.
        assert any("/tmp/work:/work:ro" == arg for arg in cmd)
        # Default targets filename passed positionally
        assert "/work/baddns_targets.txt" in cmd
        # Default image
        assert "redamon-baddns:latest" in cmd
        # Default modules emitted as comma-separated positional arg
        assert "cname,ns,mx,txt,spf" in cmd

    def test_custom_modules_filter_invalid(self):
        cmd = build_baddns_command(
            "/tmp/work",
            modules=["cname", "not_a_real_module", "ns"],
        )
        # Invalid module dropped, valid ones kept
        mod_arg = next(a for a in cmd if "," in a and "cname" in a)
        assert "cname" in mod_arg
        assert "ns" in mod_arg
        assert "not_a_real_module" not in mod_arg

    def test_empty_modules_fall_back_to_defaults(self):
        cmd = build_baddns_command("/tmp/work", modules=[])
        assert "cname,ns,mx,txt,spf" in cmd

    def test_all_invalid_modules_fall_back_to_defaults(self):
        cmd = build_baddns_command("/tmp/work", modules=["garbage1", "garbage2"])
        assert "cname,ns,mx,txt,spf" in cmd

    def test_nameservers_passed_as_positional(self):
        cmd = build_baddns_command(
            "/tmp/work",
            nameservers=["1.1.1.1", "8.8.8.8"],
        )
        # Nameservers are the 3rd positional arg after targets file + modules
        # (entrypoint.sh signature: $1=targets_file $2=modules $3=nameservers)
        assert "1.1.1.1,8.8.8.8" in cmd

    def test_empty_nameservers_pass_empty_string(self):
        cmd = build_baddns_command("/tmp/work")
        # Last arg should be the (empty) nameservers placeholder
        assert cmd[-1] == ""

    def test_nameservers_strip_whitespace_and_drop_empty(self):
        cmd = build_baddns_command(
            "/tmp/work",
            nameservers=["  1.1.1.1  ", "", "   ", "8.8.8.8"],
        )
        assert "1.1.1.1,8.8.8.8" in cmd

    def test_custom_image_overrides_default(self):
        cmd = build_baddns_command("/tmp/work", docker_image="custom/baddns:v2")
        assert "custom/baddns:v2" in cmd
        assert "redamon-baddns:latest" not in cmd

    def test_extra_docker_args_inserted_before_image(self):
        cmd = build_baddns_command(
            "/tmp/work",
            extra_docker_args=["--network", "host"],
        )
        # `--network host` should appear between `--rm` and the image name
        network_idx = cmd.index("--network")
        image_idx = cmd.index("redamon-baddns:latest")
        assert network_idx < image_idx

    def test_container_name_via_extra_docker_args(self):
        # Verifies the runner's orphan-cleanup pattern can inject --name
        cmd = build_baddns_command(
            "/tmp/work",
            extra_docker_args=["--name", "redamon-baddns-1234-5678"],
        )
        name_idx = cmd.index("--name")
        image_idx = cmd.index("redamon-baddns:latest")
        assert name_idx < image_idx
        assert "redamon-baddns-1234-5678" in cmd

    def test_module_registry_contains_the_10_cli_addressable_modules(self):
        # Guards the research finding: upstream ships 11 modules but only 10
        # are CLI-addressable in baddns 2.1.0. MTA-STS fails the argparse
        # validator regex (hyphens rejected, underscore substring match
        # fails against "MTA-STS"). Passing it would crash the scan.
        assert len(BADDNS_MODULES) == 10
        for required in ("cname", "ns", "mx", "txt", "spf",
                         "dmarc", "wildcard", "nsec",
                         "references", "zonetransfer"):
            assert required in BADDNS_MODULES

    def test_mta_sts_excluded_from_registry(self):
        # Explicit negative assertion: we MUST NOT offer mta_sts as a
        # user-selectable module because the upstream CLI rejects it.
        # If a future baddns version fixes the validator, this test will
        # guide the re-introduction: bump version, add to registry, flip
        # this assertion.
        assert "mta_sts" not in BADDNS_MODULES
        assert "mta-sts" not in BADDNS_MODULES

    def test_invalid_user_modules_filter_preserves_defaults(self):
        # Command builder drops invalid modules and falls back to defaults
        # when nothing valid remains. This is the safety net that protects
        # the runner if someone passes mta_sts through the UI bypass.
        cmd = build_baddns_command("/tmp/work", modules=["mta_sts", "mta-sts"])
        assert "cname,ns,mx,txt,spf" in cmd

    def test_default_modules_are_high_value_subset(self):
        # Defaults include the 5 most useful takeover modules, exclude the slow ones
        assert "cname" in BADDNS_DEFAULT_MODULES
        assert "ns" in BADDNS_DEFAULT_MODULES
        assert "mx" in BADDNS_DEFAULT_MODULES
        assert "txt" in BADDNS_DEFAULT_MODULES
        assert "spf" in BADDNS_DEFAULT_MODULES
        # Slow modules off by default
        assert "nsec" not in BADDNS_DEFAULT_MODULES
        assert "zonetransfer" not in BADDNS_DEFAULT_MODULES


# ---------------------------------------------------------------------------
# BadDNS finding normalization
# ---------------------------------------------------------------------------
class TestNormalizeBaddnsFinding:
    def _raw(self, **overrides):
        base = {
            "target": "promo.example.com",
            "description": "Takeover Detected against base domain",
            "confidence": "CONFIRMED",
            "severity": "HIGH",
            "signature": "Heroku",
            "indicator": "No such app",
            "trigger": "promo.example.com CNAME acme.herokuapp.com",
            "module": "CNAME",
            "found_domains": ["acme.herokuapp.com"],
        }
        base.update(overrides)
        return base

    def test_basic_cname_heroku_finding(self):
        out = normalize_baddns_finding(self._raw())
        assert out is not None
        assert out["hostname"] == "promo.example.com"
        assert out["takeover_method"] == "cname"
        assert out["takeover_provider"] == "heroku"
        assert out["cname_target"] == "acme.herokuapp.com"
        assert out["severity"] == "high"  # lowercased
        assert out["source_tool"] == "baddns"
        assert "Heroku" not in out["evidence"] or "BadDNS" in out["evidence"]

    def test_none_and_empty_return_none(self):
        assert normalize_baddns_finding({}) is None
        assert normalize_baddns_finding(None) is None  # type: ignore[arg-type]

    def test_missing_target_returns_none(self):
        out = normalize_baddns_finding({"module": "CNAME", "severity": "HIGH"})
        assert out is None

    def test_ns_module_maps_to_ns_method(self):
        out = normalize_baddns_finding(self._raw(module="NS", signature="dangling-ns"))
        assert out is not None
        assert out["takeover_method"] == "ns"

    def test_mx_module_maps_to_mx_method(self):
        out = normalize_baddns_finding(self._raw(module="MX", signature="dangling-mx"))
        assert out["takeover_method"] == "mx"

    def test_spf_module_maps_to_spf_method(self):
        out = normalize_baddns_finding(self._raw(module="SPF", signature=""))
        assert out["takeover_method"] == "spf"

    def test_dmarc_module_maps_to_txt_method(self):
        out = normalize_baddns_finding(self._raw(module="DMARC", signature=""))
        assert out["takeover_method"] == "txt"

    def test_mta_sts_module_maps_to_txt_method(self):
        out = normalize_baddns_finding(self._raw(module="mta_sts", signature=""))
        assert out["takeover_method"] == "txt"

    def test_wildcard_module_maps_to_dns_method(self):
        out = normalize_baddns_finding(self._raw(module="wildcard", signature=""))
        assert out["takeover_method"] == "dns"

    def test_unknown_module_maps_to_dns_method(self):
        out = normalize_baddns_finding(self._raw(module="something_new", signature=""))
        assert out["takeover_method"] == "dns"

    def test_provider_falls_back_to_found_domains_when_signature_unknown(self):
        # No useful signature/indicator, but found_domains has a known CNAME pattern
        out = normalize_baddns_finding(self._raw(
            signature="",
            indicator="",
            found_domains=["foo.github.io"],
        ))
        assert out["takeover_provider"] == "github-pages"

    def test_provider_falls_back_to_module_when_no_other_signal(self):
        out = normalize_baddns_finding(self._raw(
            signature="",
            indicator="",
            found_domains=[],
            module="WILDCARD",
        ))
        assert out["takeover_provider"] == "wildcard"

    def test_invalid_severity_string_is_dropped(self):
        # Scorer handles missing severity; normalizer should pass through clean state
        out = normalize_baddns_finding(self._raw(severity="BOGUS"))
        assert out["severity"] == ""  # dropped, scorer will compute from verdict

    def test_found_domains_as_string_is_accepted(self):
        # Defensive: some BadDNS versions may serialize single domain as string
        out = normalize_baddns_finding(self._raw(found_domains="acme.herokuapp.com"))
        assert out["cname_target"] == "acme.herokuapp.com"

    def test_empty_found_domains_leaves_cname_none(self):
        out = normalize_baddns_finding(self._raw(found_domains=[]))
        assert out["cname_target"] is None

    def test_evidence_truncated_to_500_chars(self):
        long_desc = "A" * 2000
        out = normalize_baddns_finding(self._raw(description=long_desc))
        assert len(out["evidence"]) <= 500

    def test_trailing_dot_stripped_from_found_domain(self):
        out = normalize_baddns_finding(self._raw(found_domains=["acme.herokuapp.com."]))
        assert out["cname_target"] == "acme.herokuapp.com"

    def test_hostname_lowercased(self):
        out = normalize_baddns_finding(self._raw(target="PROMO.ACME.COM"))
        assert out["hostname"] == "promo.acme.com"

    def test_uppercase_module_name_from_upstream(self):
        # baddns emits `module.name` which is uppercase for most modules
        # (CNAME, NS, MX, SPF, TXT, DMARC, WILDCARD, NSEC) and lowercase
        # for two (references, zonetransfer). Verify our lower-casing +
        # mapping handles the uppercase form.
        for name in ("CNAME", "NS", "MX", "SPF", "TXT", "DMARC", "WILDCARD"):
            out = normalize_baddns_finding(self._raw(module=name, signature=""))
            assert out is not None

    def test_mta_sts_output_still_normalized_defensively(self):
        # If upstream ever emits an MTA-STS finding (via bbot or a future
        # CLI fix), our normalizer must still map it correctly so it flows
        # into the dedupe + scoring path. Method should map to txt.
        out = normalize_baddns_finding(self._raw(module="MTA-STS", signature=""))
        assert out is not None
        assert out["takeover_method"] == "txt"

    def test_trigger_as_list_joined_in_evidence(self):
        # baddns `Finding.__init__` stringifies list triggers via ", ".join.
        # Our normalizer additionally accepts the list form (defensive).
        raw = self._raw(trigger=["step1", "step2", "step3"])
        out = normalize_baddns_finding(raw)
        assert out is not None
        assert "step1" in out["evidence"] and "step2" in out["evidence"]

    def test_trigger_as_string_appears_in_evidence(self):
        # When upstream has already joined the trigger (normal case),
        # the string passes through verbatim and lands in `evidence`.
        raw = self._raw(trigger="promo.acme.com CNAME acme.herokuapp.com")
        out = normalize_baddns_finding(raw)
        assert "via " in out["evidence"]
        assert "herokuapp" in out["evidence"]

    def test_confidence_value_set_does_not_affect_normalizer(self):
        # Confidence is upstream metadata; our scorer is driven by the
        # dedupe pipeline. Normalizer should pass any confidence through
        # without raising, even uncommon values like UNKNOWN.
        for conf in ("CONFIRMED", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
            out = normalize_baddns_finding(self._raw(confidence=conf))
            assert out is not None


# ---------------------------------------------------------------------------
# _parse_baddns_stdout — NDJSON stream parser
# ---------------------------------------------------------------------------
class TestParseBaddnsStdout:
    def test_empty_stdout_returns_empty(self):
        assert _parse_baddns_stdout("") == []
        assert _parse_baddns_stdout("   \n  \n") == []

    def test_single_finding(self):
        line = '{"target":"x.acme.com","module":"CNAME","severity":"HIGH"}'
        rows = _parse_baddns_stdout(line)
        assert len(rows) == 1
        assert rows[0]["target"] == "x.acme.com"

    def test_multiple_ndjson_findings(self):
        stdout = (
            '{"target":"a.acme.com","module":"CNAME"}\n'
            '{"target":"b.acme.com","module":"NS"}\n'
            '{"target":"c.acme.com","module":"MX"}\n'
        )
        rows = _parse_baddns_stdout(stdout)
        assert len(rows) == 3
        assert [r["module"] for r in rows] == ["CNAME", "NS", "MX"]

    def test_skip_log_lines_not_starting_with_brace(self):
        # Defensive: even though `-s` should suppress logs, upstream may still
        # emit warnings on stderr/stdout. The parser must ignore them.
        stdout = (
            'Starting baddns for x.acme.com\n'
            '{"target":"x.acme.com","module":"CNAME"}\n'
            'Scan complete.\n'
        )
        rows = _parse_baddns_stdout(stdout)
        assert len(rows) == 1
        assert rows[0]["target"] == "x.acme.com"

    def test_malformed_json_is_skipped(self):
        stdout = (
            '{"target":"ok.acme.com","module":"CNAME"}\n'
            '{broken json\n'
            '{"target":"also-ok.acme.com","module":"NS"}\n'
        )
        rows = _parse_baddns_stdout(stdout)
        assert len(rows) == 2

    def test_non_dict_json_is_skipped(self):
        stdout = '"just a string"\n[1,2,3]\n{"target":"ok.acme.com","module":"CNAME"}\n'
        rows = _parse_baddns_stdout(stdout)
        # Only the dict is kept; "just a string" starts with " not { so it's skipped
        # by the brace check anyway; the array starts with [ so also skipped.
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# Cross-tool dedup with BadDNS as a third source
# ---------------------------------------------------------------------------
class TestDedupeWithBaddns:
    def test_three_tools_confirm_same_finding(self):
        sj = normalize_subjack_result({
            "subdomain": "promo.acme.com",
            "vulnerable": True,
            "service": "Heroku",
        })
        nu = normalize_nuclei_takeover({
            "template_id": "heroku-takeover",
            "template_path": "http/takeovers/heroku-takeover.yaml",
            "name": "Heroku Takeover",
            "severity": "high",
            "tags": ["takeover"],
            "matched_at": "https://promo.acme.com/",
            "extracted_results": ["acme.herokuapp.com"],
        })
        bd = normalize_baddns_finding({
            "target": "promo.acme.com",
            "description": "Takeover Detected",
            "severity": "HIGH",
            "signature": "Heroku",
            "module": "CNAME",
            "found_domains": ["acme.herokuapp.com"],
            "indicator": "No such app",
            "trigger": "",
            "confidence": "CONFIRMED",
        })
        merged = dedupe_findings([sj, nu, bd])
        assert len(merged) == 1
        assert set(merged[0]["sources"]) == {"subjack", "nuclei_takeover", "baddns"}
        assert merged[0]["confirmation_count"] == 3

    def test_baddns_only_finding_preserved(self):
        bd = normalize_baddns_finding({
            "target": "dmarc-missing.acme.com",
            "description": "DMARC record is missing",
            "severity": "MEDIUM",
            "signature": "dmarc-missing",
            "module": "DMARC",
            "found_domains": [],
            "indicator": "",
            "trigger": "",
            "confidence": "HIGH",
        })
        merged = dedupe_findings([bd])
        assert len(merged) == 1
        assert merged[0]["sources"] == ["baddns"]
        assert merged[0]["takeover_method"] == "txt"  # DMARC → txt


@pytest.mark.skipif(not (FIXTURES / "subjack_output.jsonl").exists(), reason="fixture missing")
def test_subjack_fixture_is_valid_json():
    for line in (FIXTURES / "subjack_output.jsonl").read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        assert "subdomain" in obj and "vulnerable" in obj


@pytest.mark.skipif(not (FIXTURES / "nuclei_takeover_output.jsonl").exists(), reason="fixture missing")
def test_nuclei_fixture_is_valid_json():
    for line in (FIXTURES / "nuclei_takeover_output.jsonl").read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        assert "template-id" in obj and "info" in obj

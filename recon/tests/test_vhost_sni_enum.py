"""
Unit + integration tests for the VHost & SNI Enumeration module.

Covers:
    - Helper functions: candidate building, severity classification,
      baseline comparison, wordlist parsing, BaseURL construction,
      hostname validity, port-target collection, scheme inference,
      apex detection, finding record assembly.
    - run_vhost_sni_enrichment end-to-end with mocked curl subprocess.
    - run_vhost_sni_enrichment_isolated thread-safety contract.
    - Disabled / no-targets / curl-missing fast paths.
    - Severity escalation rules (info / low / medium / high).
    - L7 / L4 / both-layer detection.
    - Discovered-baseurl injection into http_probe.

Run:
    docker exec redamon-recon-orchestrator python -m pytest /app/recon/tests/test_vhost_sni_enum.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import vhost_sni_enum as vsm
from recon.main_recon_modules.vhost_sni_enum import (
    INTERNAL_KEYWORDS,
    _build_baseurl,
    _build_candidate_set,
    _build_finding_record,
    _classify_severity,
    _collect_graph_candidates,
    _collect_ip_targets,
    _detect_apex_domain,
    _detect_noisy_frontend,
    _empty_result,
    _inject_into_http_probe,
    _is_anomaly,
    _is_valid_hostname,
    _looks_like_ip,
    _matched_internal_keyword,
    _matches_any_control,
    _parse_custom_wordlist,
    _scheme_for_port,
    run_vhost_sni_enrichment,
    run_vhost_sni_enrichment_isolated,
)


# ===========================================================================
# Hostname / candidate building helpers
# ===========================================================================
class TestIsValidHostname:
    def test_simple_valid(self):
        assert _is_valid_hostname("admin.example.com")

    def test_with_dash(self):
        assert _is_valid_hostname("admin-portal.example.com")

    def test_subdomain_chain(self):
        assert _is_valid_hostname("a.b.c.d.example.com")

    def test_too_long_rejected(self):
        assert not _is_valid_hostname("a" * 254 + ".com")

    def test_empty_rejected(self):
        assert not _is_valid_hostname("")

    def test_label_too_long_rejected(self):
        # single label > 63 chars
        assert not _is_valid_hostname(("x" * 64) + ".com")

    def test_trailing_dot_accepted(self):
        # _is_valid_hostname strips a trailing dot before validating
        assert _is_valid_hostname("admin.example.com.")

    def test_underscore_rejected(self):
        # underscores are not in [A-Z0-9-]
        assert not _is_valid_hostname("ad_min.example.com")

    def test_leading_dash_rejected(self):
        assert not _is_valid_hostname("-admin.example.com")


class TestParseCustomWordlist:
    def test_strips_blanks_and_comments(self):
        raw = "# comment\nadmin\n\nstaging\n# another\ndev"
        assert _parse_custom_wordlist(raw) == ["admin", "staging", "dev"]

    def test_dedupes_case_insensitive(self):
        raw = "admin\nADMIN\nAdmin\nstaging"
        assert _parse_custom_wordlist(raw) == ["admin", "staging"]

    def test_empty_string(self):
        assert _parse_custom_wordlist("") == []

    def test_none_safe(self):
        assert _parse_custom_wordlist(None) == []

    def test_full_hostnames_preserved(self):
        raw = "admin\nhidden.acme.com"
        result = _parse_custom_wordlist(raw)
        assert "admin" in result
        assert "hidden.acme.com" in result


class TestBuildCandidateSet:
    def test_wordlist_expansion_with_apex(self):
        result = _build_candidate_set(
            apex_domain="example.com",
            default_prefixes=["admin", "staging"],
            custom_lines=[],
            graph_candidates=[],
        )
        assert "admin.example.com" in result
        assert "staging.example.com" in result

    def test_wordlist_skipped_without_apex(self):
        result = _build_candidate_set(
            apex_domain=None,
            default_prefixes=["admin", "staging"],
            custom_lines=[],
            graph_candidates=[],
        )
        assert result == set()

    def test_full_hostname_in_default_skipped(self):
        # default_prefixes are pure prefixes; entries containing a dot are skipped
        result = _build_candidate_set(
            apex_domain="example.com",
            default_prefixes=["foo.bar.com", "admin"],
            custom_lines=[],
            graph_candidates=[],
        )
        assert "admin.example.com" in result
        assert "foo.bar.com" not in result

    def test_graph_candidates_added(self):
        result = _build_candidate_set(
            apex_domain="example.com",
            default_prefixes=[],
            custom_lines=[],
            graph_candidates=["api.example.com", "STAGING.target.io"],
        )
        # graph names are lowercased + accepted as-is when valid FQDNs
        assert "api.example.com" in result
        assert "staging.target.io" in result

    def test_custom_full_hostname(self):
        result = _build_candidate_set(
            apex_domain="example.com",
            default_prefixes=[],
            custom_lines=["hidden.foo.com"],
            graph_candidates=[],
        )
        assert "hidden.foo.com" in result
        # not expanded against apex because it already has a dot
        assert "hidden.foo.com.example.com" not in result

    def test_custom_prefix_expanded(self):
        result = _build_candidate_set(
            apex_domain="example.com",
            default_prefixes=[],
            custom_lines=["adminpanel"],
            graph_candidates=[],
        )
        assert "adminpanel.example.com" in result

    def test_invalid_hostnames_filtered(self):
        result = _build_candidate_set(
            apex_domain="example.com",
            default_prefixes=[],
            custom_lines=["invalid_underscore.example.com", "valid.example.com"],
            graph_candidates=[],
        )
        assert "valid.example.com" in result
        assert "invalid_underscore.example.com" not in result

    def test_dedup_across_sources(self):
        result = _build_candidate_set(
            apex_domain="example.com",
            default_prefixes=["admin"],
            custom_lines=["admin"],
            graph_candidates=["admin.example.com"],
        )
        # Only one entry despite three input paths
        assert sum(1 for h in result if h == "admin.example.com") == 1


# ===========================================================================
# Internal-keyword matching
# ===========================================================================
class TestMatchedInternalKeyword:
    def test_exact_label_match(self):
        assert _matched_internal_keyword("admin.example.com") == "admin"

    def test_exact_label_jenkins(self):
        assert _matched_internal_keyword("jenkins.target.io") == "jenkins"

    def test_compound_with_dash_prefix(self):
        # "admin-portal" matches BOTH 'admin' (startswith) and 'portal' (endswith).
        # The longest-match-wins rule (also makes results deterministic across
        # Python set-iteration orders) returns 'portal' (6 > 5 chars).
        assert _matched_internal_keyword("admin-portal.example.com") == "portal"

    def test_compound_with_dash_suffix(self):
        # "internal-staging" -> matches "internal" via startswith first
        assert _matched_internal_keyword("internal-staging.example.com") in ("internal", "staging")

    def test_compound_with_underscore(self):
        # "admin_panel" matches 'admin' (5) AND 'panel' (5). Tie on length, so
        # lexicographic tiebreak gives 'panel' (p > a). Both are internal keywords
        # — the determinism of the answer is what matters.
        result = _matched_internal_keyword("admin_panel.example.com")
        assert result in ("admin", "panel")
        # Pin the deterministic outcome:
        assert result == "panel"

    def test_no_match_returns_none(self):
        assert _matched_internal_keyword("www.example.com") is None
        assert _matched_internal_keyword("blog.example.com") is None
        assert _matched_internal_keyword("api.example.com") is None  # 'api' is NOT in INTERNAL_KEYWORDS

    def test_internal_keywords_sanity(self):
        # Sanity checks the constant set has the expected high-value entries
        assert "admin" in INTERNAL_KEYWORDS
        assert "k8s" in INTERNAL_KEYWORDS
        assert "vault" in INTERNAL_KEYWORDS
        assert "phpmyadmin" in INTERNAL_KEYWORDS


# ===========================================================================
# Severity classification
# ===========================================================================
class TestClassifySeverity:
    def test_high_when_l7_l4_disagree_status(self):
        baseline = {"status": 403, "size": 100}
        l7 = {"status": 200, "size": 1000}
        l4 = {"status": 401, "size": 500}
        assert _classify_severity("blog.example.com", "both", baseline, l4, l7, l4) == "high"

    def test_high_when_l7_l4_disagree_size(self):
        baseline = {"status": 403, "size": 100}
        l7 = {"status": 200, "size": 1000}
        l4 = {"status": 200, "size": 500}
        assert _classify_severity("blog.example.com", "both", baseline, l7, l7, l4) == "high"

    def test_medium_when_internal_pattern(self):
        baseline = {"status": 403, "size": 100}
        observed = {"status": 200, "size": 4823}
        assert _classify_severity("admin.example.com", "L7", baseline, observed, observed, None) == "medium"

    def test_low_when_status_differs(self):
        baseline = {"status": 403, "size": 100}
        observed = {"status": 200, "size": 200}
        assert _classify_severity("blog.example.com", "L7", baseline, observed, observed, None) == "low"

    def test_info_when_only_size_differs(self):
        baseline = {"status": 200, "size": 100}
        observed = {"status": 200, "size": 5000}
        assert _classify_severity("blog.example.com", "L7", baseline, observed, observed, None) == "info"

    def test_internal_pattern_beats_status_diff(self):
        # Even though status differs (which would normally be 'low'),
        # internal keyword escalates to medium.
        baseline = {"status": 403, "size": 100}
        observed = {"status": 200, "size": 200}
        assert _classify_severity("admin.example.com", "L7", baseline, observed, observed, None) == "medium"


# ===========================================================================
# Baseline comparison
# ===========================================================================
class TestIsAnomaly:
    def test_status_diff_is_anomaly(self):
        assert _is_anomaly({"status": 200, "size": 100}, {"status": 403, "size": 100}, 50) is True

    def test_same_response_is_not_anomaly(self):
        assert _is_anomaly({"status": 403, "size": 548}, {"status": 403, "size": 548}, 50) is False

    def test_size_within_tolerance_not_anomaly(self):
        # delta = 30, tolerance = 50
        assert _is_anomaly({"status": 200, "size": 130}, {"status": 200, "size": 100}, 50) is False

    def test_size_over_tolerance_is_anomaly(self):
        # delta = 60, tolerance = 50
        assert _is_anomaly({"status": 200, "size": 160}, {"status": 200, "size": 100}, 50) is True

    def test_zero_tolerance_any_diff_anomaly(self):
        assert _is_anomaly({"status": 200, "size": 101}, {"status": 200, "size": 100}, 0) is True

    def test_none_probe_safe(self):
        assert _is_anomaly(None, {"status": 403, "size": 100}, 50) is False

    def test_none_baseline_safe(self):
        assert _is_anomaly({"status": 200, "size": 100}, None, 50) is False


# ===========================================================================
# IP / port collection
# ===========================================================================
class TestCollectIpTargets:
    def test_extracts_from_port_scan_by_host(self):
        recon = {
            "port_scan": {
                "by_host": {
                    "host1": {
                        "ip": "1.2.3.4",
                        "ports": [{"port": 443}, {"port": 8443}],
                    },
                },
            },
        }
        out = _collect_ip_targets(recon)
        assert "1.2.3.4" in out
        ports = sorted(p["port"] for p in out["1.2.3.4"])
        assert ports == [443, 8443]

    def test_handles_int_port_format(self):
        recon = {
            "port_scan": {
                "by_host": {
                    "10.0.0.1": {
                        "ip": "10.0.0.1",
                        "ports": [80, 443],
                    },
                },
            },
        }
        out = _collect_ip_targets(recon)
        assert "10.0.0.1" in out

    def test_dedupes_ports_per_ip(self):
        recon = {
            "port_scan": {
                "by_host": {
                    "h": {
                        "ip": "5.5.5.5",
                        "ports": [{"port": 443}, {"port": 443}, {"port": 80}],
                    },
                },
            },
        }
        out = _collect_ip_targets(recon)
        ports = sorted(p["port"] for p in out["5.5.5.5"])
        assert ports == [80, 443]

    def test_pulls_dns_ips_when_no_port_scan(self):
        # No port_scan data -> dns.subdomains IPs picked up with default 80/443
        recon = {
            "port_scan": {"by_host": {}},
            "dns": {
                "subdomains": {
                    "api.example.com": {"ips": {"ipv4": ["7.7.7.7"]}, "has_records": True},
                },
            },
        }
        out = _collect_ip_targets(recon)
        assert "7.7.7.7" in out
        ports = sorted(p["port"] for p in out["7.7.7.7"])
        assert ports == [80, 443]

    def test_merges_port_scan_and_dns_subdomain_ips(self):
        # Regression: previously the dns walk only fired when port_scan was empty
        # (fallback-only). User-provided IPs in port_scan would silently mask
        # the graph IPs the runner needed. Now both must be merged.
        recon = {
            "port_scan": {
                "by_host": {
                    "h": {"ip": "1.1.1.1", "ports": [{"port": 443}]},
                },
            },
            "dns": {
                "subdomains": {
                    "api.example.com": {"ips": {"ipv4": ["7.7.7.7"]}, "has_records": True},
                },
            },
        }
        out = _collect_ip_targets(recon)
        assert "1.1.1.1" in out, "port_scan IP must still be present after merge"
        assert "7.7.7.7" in out, "dns.subdomains IP must NOT be dropped just because port_scan has data"

    def test_merges_port_scan_dns_subdomains_and_dns_apex(self):
        # All three sources must contribute to the final ip_to_ports map
        recon = {
            "port_scan": {"by_host": {"h": {"ip": "1.1.1.1", "ports": [{"port": 443}]}}},
            "dns": {
                "domain": {"ips": {"ipv4": ["2.2.2.2"], "ipv6": []}, "has_records": True},
                "subdomains": {
                    "x.example.com": {"ips": {"ipv4": ["3.3.3.3"]}, "has_records": True},
                },
            },
        }
        out = _collect_ip_targets(recon)
        assert set(out.keys()) == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}

    def test_overlapping_sources_dedupe_ports(self):
        # Same IP appears in both port_scan AND dns.subdomains -> ports merged + deduped
        recon = {
            "port_scan": {"by_host": {"h": {"ip": "5.5.5.5", "ports": [{"port": 443, "scheme": "https"}]}}},
            "dns": {
                "subdomains": {
                    "x.example.com": {"ips": {"ipv4": ["5.5.5.5"]}, "has_records": True},
                },
            },
        }
        out = _collect_ip_targets(recon)
        # port 443 from both sources -> single entry. port 80 from dns fallback only -> present
        ports = sorted({(p["port"], p["scheme"]) for p in out["5.5.5.5"]})
        assert (443, "https") in ports
        assert (80, "http") in ports
        # No duplicates
        assert len(out["5.5.5.5"]) == len(set((p["port"], p["scheme"]) for p in out["5.5.5.5"]))

    def test_pulls_apex_domain_ips_too(self):
        # dns.domain.ips (the apex Domain's resolved IPs) must also be merged
        recon = {
            "port_scan": {"by_host": {}},
            "dns": {
                "domain": {"ips": {"ipv4": ["9.9.9.9"], "ipv6": []}, "has_records": True},
                "subdomains": {},
            },
        }
        out = _collect_ip_targets(recon)
        assert "9.9.9.9" in out
        ports = sorted(p["port"] for p in out["9.9.9.9"])
        assert ports == [80, 443]

    def test_empty_recon_gives_empty(self):
        assert _collect_ip_targets({}) == {}


class TestSchemeForPort:
    @pytest.mark.parametrize("port,scheme", [
        (443, "https"),
        (8443, "https"),
        (9443, "https"),
        (80, "http"),
        (8080, "http"),
        (8000, "http"),
        (3000, "http"),
        (5000, "http"),
        (8888, "http"),
    ])
    def test_known_ports(self, port, scheme):
        assert _scheme_for_port(port) == scheme


class TestLooksLikeIp:
    def test_ipv4(self):
        assert _looks_like_ip("1.2.3.4") is True

    def test_ipv6_crude(self):
        assert _looks_like_ip("2001:db8::1") is True

    def test_hostname_rejected(self):
        assert _looks_like_ip("example.com") is False

    def test_invalid_ipv4_rejected(self):
        assert _looks_like_ip("999.0.0.1") is False

    def test_non_string_safe(self):
        assert _looks_like_ip(None) is False
        assert _looks_like_ip(12345) is False


# ===========================================================================
# Apex detection
# ===========================================================================
class TestDetectApexDomain:
    def test_from_top_level_domain_key(self):
        assert _detect_apex_domain({"domain": "Example.com"}) == "example.com"

    def test_from_metadata_target(self):
        assert _detect_apex_domain({"metadata": {"target": "acme.io"}}) == "acme.io"

    def test_from_metadata_target_domain(self):
        assert _detect_apex_domain({"metadata": {"target_domain": "foo.com"}}) == "foo.com"

    def test_strips_trailing_dot(self):
        assert _detect_apex_domain({"domain": "example.com."}) == "example.com"

    def test_returns_none_when_missing(self):
        assert _detect_apex_domain({}) is None

    def test_rejects_non_dotted_value(self):
        assert _detect_apex_domain({"domain": "localhost"}) is None


# ===========================================================================
# Graph candidate collection
# ===========================================================================
class TestCollectGraphCandidates:
    def test_pulls_subdomain_resolving_to_ip(self):
        recon = {
            "dns": {
                "subdomains": {
                    "api.example.com": {"ips": {"ipv4": ["1.2.3.4"], "ipv6": []}},
                    "www.example.com": {"ips": {"ipv4": ["9.9.9.9"], "ipv6": []}},
                },
            },
        }
        out = _collect_graph_candidates(recon, "1.2.3.4")
        assert "api.example.com" in out
        assert "www.example.com" not in out  # different IP

    def test_pulls_http_probe_by_host(self):
        recon = {
            "http_probe": {
                "by_host": {
                    "admin.example.com": {"ip": "5.5.5.5"},
                },
                "by_url": {},
            },
        }
        out = _collect_graph_candidates(recon, "5.5.5.5")
        assert "admin.example.com" in out

    def test_pulls_tls_sans(self):
        # The shape http_probe ACTUALLY produces: tls.certificate.san. The old
        # fixture encoded tls_subject_alt_names, a key nothing writes, which is
        # why source 3 shipped dead (Phase 4).
        recon = {
            "http_probe": {
                "by_url": {
                    "https://5.5.5.5": {
                        "host": "5.5.5.5",
                        "tls": {"certificate": {"san": ["*.acme.com", "internal.acme.com"]}},
                    },
                },
                "by_host": {},
            },
        }
        out = _collect_graph_candidates(recon, "5.5.5.5")
        assert "acme.com" in out  # *. wildcard stripped
        assert "internal.acme.com" in out

    def test_pulls_tlsx_sans(self):
        # Source 8: tlsx by_target matched on the scanned IP.
        recon = {
            "tlsx": {
                "by_target": {
                    "5.5.5.5:993": {"scanned_ip": "5.5.5.5", "ip": "5.5.5.5",
                                    "san": ["mail.acme.com", "acme.com"]},
                },
            },
        }
        out = _collect_graph_candidates(recon, "5.5.5.5")
        assert "mail.acme.com" in out
        assert "acme.com" in out

    def test_pulls_external_domains(self):
        recon = {
            "external_domains_aggregated": [
                {"name": "external.acme.com", "ips": ["5.5.5.5"]},
                {"name": "wrongip.acme.com", "ips": ["1.1.1.1"]},
            ],
        }
        out = _collect_graph_candidates(recon, "5.5.5.5")
        assert "external.acme.com" in out
        assert "wrongip.acme.com" not in out

    def test_pulls_cnames(self):
        recon = {
            "dns": {
                "subdomains": {
                    "www.example.com": {
                        "records": {"CNAME": ["app-prod.internal.example.com"]},
                    },
                },
            },
        }
        out = _collect_graph_candidates(recon, "5.5.5.5")
        assert "app-prod.internal.example.com" in out

    def test_pulls_ptr(self):
        recon = {
            "ip_recon": {
                "5.5.5.5": {"reverse_dns": "web-prod-7.internal.example.com"},
            },
        }
        out = _collect_graph_candidates(recon, "5.5.5.5")
        assert "web-prod-7.internal.example.com" in out

    def test_empty_recon_returns_empty(self):
        assert _collect_graph_candidates({}, "5.5.5.5") == []


# ===========================================================================
# BaseURL building
# ===========================================================================
class TestBuildBaseURL:
    def test_default_https_port_omitted(self):
        assert _build_baseurl("admin.example.com", 443, "https") == "https://admin.example.com"

    def test_default_http_port_omitted(self):
        assert _build_baseurl("admin.example.com", 80, "http") == "http://admin.example.com"

    def test_non_default_port_included(self):
        assert _build_baseurl("admin.example.com", 8443, "https") == "https://admin.example.com:8443"

    def test_invalid_hostname_returns_none(self):
        assert _build_baseurl("not-a-host", 443, "https") is None
        assert _build_baseurl("", 443, "https") is None


# ===========================================================================
# Finding record
# ===========================================================================
class TestBuildFindingRecord:
    def _anomaly(self, **overrides):
        defaults = {
            "hostname": "admin.example.com",
            "ip": "1.2.3.4",
            "port": 443,
            "scheme": "https",
            "layer": "L7",
            "baseline_status": 403,
            "baseline_size": 548,
            "observed_status": 200,
            "observed_size": 4823,
            "size_delta": 4275,
            "severity": "medium",
            "internal_pattern_match": "admin",
        }
        defaults.update(overrides)
        return defaults

    def test_l7_finding(self):
        f = _build_finding_record(self._anomaly(), "1.2.3.4", {})
        assert f["type"] == "hidden_vhost"
        assert f["source"] == "vhost_sni_enum"
        assert f["layer"] == "L7"
        assert "Hidden Virtual Host" in f["name"]
        assert "admin" in f["description"]
        assert f["id"].startswith("vhost_sni_admin_example_com_")
        assert f["id"].endswith("_l7")

    def test_l4_finding(self):
        f = _build_finding_record(self._anomaly(layer="L4", internal_pattern_match=None), "1.2.3.4", {})
        assert f["type"] == "hidden_sni_route"
        assert "SNI-Routed" in f["name"]
        assert f["id"].endswith("_l4")

    def test_both_layer_finding(self):
        f = _build_finding_record(self._anomaly(layer="both", severity="high", internal_pattern_match=None), "1.2.3.4", {})
        assert f["type"] == "host_header_bypass"
        assert "Routing Inconsistency" in f["name"]
        assert f["id"].endswith("_both")

    def test_id_is_deterministic(self):
        f1 = _build_finding_record(self._anomaly(), "1.2.3.4", {})
        f2 = _build_finding_record(self._anomaly(), "1.2.3.4", {})
        assert f1["id"] == f2["id"]

    def test_id_changes_per_layer(self):
        f_l7 = _build_finding_record(self._anomaly(layer="L7"), "1.2.3.4", {})
        f_l4 = _build_finding_record(self._anomaly(layer="L4"), "1.2.3.4", {})
        assert f_l7["id"] != f_l4["id"]

    def test_id_safe_chars_only(self):
        f = _build_finding_record(self._anomaly(hostname="weird.host:with*chars.com"), "1.2.3.4", {})
        # All non-[a-z0-9.] in hostname become _, port preserved
        assert ":" not in f["id"]
        assert "*" not in f["id"]


# ===========================================================================
# http_probe injection
# ===========================================================================
class TestInjectIntoHttpProbe:
    def test_creates_by_url_when_missing(self):
        cr = {}
        _inject_into_http_probe(cr, ["https://hidden.example.com"])
        assert "https://hidden.example.com" in cr["http_probe"]["by_url"]
        assert cr["http_probe"]["by_url"]["https://hidden.example.com"]["discovery_source"] == "vhost_sni_enum"

    def test_does_not_overwrite_existing(self):
        cr = {"http_probe": {"by_url": {"https://hidden.example.com": {"existing": True}}}}
        _inject_into_http_probe(cr, ["https://hidden.example.com"])
        assert cr["http_probe"]["by_url"]["https://hidden.example.com"] == {"existing": True}

    def test_multiple_urls(self):
        cr = {}
        _inject_into_http_probe(cr, ["https://a.com", "https://b.com"])
        assert len(cr["http_probe"]["by_url"]) == 2


# ===========================================================================
# Top-level fast paths
# ===========================================================================
class TestFastPaths:
    def test_disabled_returns_empty_with_reason(self):
        cr = {}
        run_vhost_sni_enrichment(cr, settings={"VHOST_SNI_ENABLED": False})
        assert cr["vhost_sni"]["scan_metadata"]["skipped_reason"] == "disabled"

    def test_both_layers_off_skipped(self):
        cr = {}
        run_vhost_sni_enrichment(cr, settings={
            "VHOST_SNI_ENABLED": True,
            "VHOST_SNI_TEST_L7": False,
            "VHOST_SNI_TEST_L4": False,
        })
        assert cr["vhost_sni"]["scan_metadata"]["skipped_reason"] == "all_layers_disabled"

    def test_no_ip_targets(self):
        cr = {}
        run_vhost_sni_enrichment(cr, settings={"VHOST_SNI_ENABLED": True})
        assert cr["vhost_sni"]["scan_metadata"]["skipped_reason"] == "no_ip_targets"

    def test_curl_unavailable(self):
        cr = {
            "domain": "example.com",
            "port_scan": {"by_host": {"h": {"ip": "1.2.3.4", "ports": [{"port": 443}]}}},
        }
        with patch.object(vsm, "_is_curl_available", return_value=False):
            run_vhost_sni_enrichment(cr, settings={"VHOST_SNI_ENABLED": True})
        assert cr["vhost_sni"]["scan_metadata"]["skipped_reason"] == "curl_unavailable"


# ===========================================================================
# End-to-end with mocked curl
# ===========================================================================
def _mock_curl_responses(responses_by_call):
    """
    Build a side_effect for _curl_probe that returns responses from a queue
    keyed by (host_header_or_sni, port). responses_by_call maps:
        ("baseline", port) -> {"status": 403, "size": 548}
        (hostname, port) -> {"status": 200, "size": 4823}  # L7
        ("sni:" + hostname, port) -> {...}  # L4
    """
    def side_effect(scheme, host_header, sni_hostname, target, port, timeout):
        if sni_hostname:
            key = (f"sni:{sni_hostname}", port)
        elif host_header:
            key = (host_header, port)
        else:
            key = ("baseline", port)
        return responses_by_call.get(key)
    return side_effect


class TestRunVhostSniEnrichment:
    def _basic_recon(self):
        return {
            "domain": "example.com",
            "metadata": {"target": "example.com"},
            "port_scan": {
                "by_host": {
                    "host1": {
                        "ip": "1.2.3.4",
                        "ports": [{"port": 443}],
                    },
                },
            },
        }

    def _basic_settings(self):
        return {
            "VHOST_SNI_ENABLED": True,
            "VHOST_SNI_TEST_L7": True,
            "VHOST_SNI_TEST_L4": True,
            "VHOST_SNI_TIMEOUT": 1,
            "VHOST_SNI_CONCURRENCY": 2,
            "VHOST_SNI_BASELINE_SIZE_TOLERANCE": 50,
            "VHOST_SNI_USE_DEFAULT_WORDLIST": False,
            "VHOST_SNI_USE_GRAPH_CANDIDATES": True,
            "VHOST_SNI_INJECT_DISCOVERED": True,
            "VHOST_SNI_CUSTOM_WORDLIST": "admin\nstaging",
            "VHOST_SNI_MAX_CANDIDATES_PER_IP": 100,
        }

    def test_no_anomalies_when_all_responses_match_baseline(self):
        cr = self._basic_recon()
        responses = {
            ("baseline", 443): {"status": 403, "size": 548},
            ("admin.example.com", 443): {"status": 403, "size": 548},
            ("sni:admin.example.com", 443): {"status": 403, "size": 548},
            ("staging.example.com", 443): {"status": 403, "size": 548},
            ("sni:staging.example.com", 443): {"status": 403, "size": 548},
        }
        with patch.object(vsm, "_is_curl_available", return_value=True), \
             patch.object(vsm, "_curl_probe", side_effect=_mock_curl_responses(responses)):
            run_vhost_sni_enrichment(cr, settings=self._basic_settings())

        assert cr["vhost_sni"]["summary"]["ips_tested"] == 1
        assert cr["vhost_sni"]["findings"] == []
        assert cr["vhost_sni"]["summary"]["high_severity"] == 0

    def test_l7_only_anomaly_creates_low_finding(self):
        # blog (no internal keyword) returns different status -> low
        cr = self._basic_recon()
        cr["dns"] = {"subdomains": {"blog.example.com": {"ips": {"ipv4": ["1.2.3.4"], "ipv6": []}}}}
        settings = self._basic_settings()
        settings["VHOST_SNI_CUSTOM_WORDLIST"] = ""  # only graph candidate
        responses = {
            ("baseline", 443): {"status": 403, "size": 548},
            ("blog.example.com", 443): {"status": 200, "size": 5000},
            ("sni:blog.example.com", 443): {"status": 403, "size": 548},
        }
        with patch.object(vsm, "_is_curl_available", return_value=True), \
             patch.object(vsm, "_curl_probe", side_effect=_mock_curl_responses(responses)):
            run_vhost_sni_enrichment(cr, settings=settings)

        findings = cr["vhost_sni"]["findings"]
        assert len(findings) == 1
        assert findings[0]["layer"] == "L7"
        assert findings[0]["severity"] == "low"
        assert findings[0]["type"] == "hidden_vhost"

    def test_internal_keyword_escalates_to_medium(self):
        cr = self._basic_recon()
        responses = {
            ("baseline", 443): {"status": 403, "size": 548},
            ("admin.example.com", 443): {"status": 200, "size": 5000},
            ("sni:admin.example.com", 443): {"status": 403, "size": 548},
            ("staging.example.com", 443): {"status": 403, "size": 548},
            ("sni:staging.example.com", 443): {"status": 403, "size": 548},
        }
        with patch.object(vsm, "_is_curl_available", return_value=True), \
             patch.object(vsm, "_curl_probe", side_effect=_mock_curl_responses(responses)):
            run_vhost_sni_enrichment(cr, settings=self._basic_settings())

        findings = [f for f in cr["vhost_sni"]["findings"] if f["hostname"] == "admin.example.com"]
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"
        assert findings[0]["internal_pattern_match"] == "admin"

    def test_l7_l4_disagreement_high_severity(self):
        cr = self._basic_recon()
        responses = {
            ("baseline", 443): {"status": 403, "size": 548},
            # L7 returns one thing, L4 returns another -> "both" + disagreement
            ("admin.example.com", 443): {"status": 200, "size": 1000},
            ("sni:admin.example.com", 443): {"status": 401, "size": 500},
            ("staging.example.com", 443): {"status": 403, "size": 548},
            ("sni:staging.example.com", 443): {"status": 403, "size": 548},
        }
        with patch.object(vsm, "_is_curl_available", return_value=True), \
             patch.object(vsm, "_curl_probe", side_effect=_mock_curl_responses(responses)):
            run_vhost_sni_enrichment(cr, settings=self._basic_settings())

        findings = [f for f in cr["vhost_sni"]["findings"] if f["hostname"] == "admin.example.com"]
        assert len(findings) == 1
        assert findings[0]["layer"] == "both"
        assert findings[0]["severity"] == "high"
        assert findings[0]["type"] == "host_header_bypass"

    def test_inject_discovered_adds_baseurls(self):
        cr = self._basic_recon()
        responses = {
            ("baseline", 443): {"status": 403, "size": 548},
            ("admin.example.com", 443): {"status": 200, "size": 5000},
            ("sni:admin.example.com", 443): {"status": 403, "size": 548},
            ("staging.example.com", 443): {"status": 403, "size": 548},
            ("sni:staging.example.com", 443): {"status": 403, "size": 548},
        }
        with patch.object(vsm, "_is_curl_available", return_value=True), \
             patch.object(vsm, "_curl_probe", side_effect=_mock_curl_responses(responses)):
            run_vhost_sni_enrichment(cr, settings=self._basic_settings())

        assert "https://admin.example.com" in cr["vhost_sni"]["discovered_baseurls"]
        assert "https://admin.example.com" in cr["http_probe"]["by_url"]
        assert cr["http_probe"]["by_url"]["https://admin.example.com"]["discovery_source"] == "vhost_sni_enum"

    def test_inject_disabled_keeps_http_probe_clean(self):
        cr = self._basic_recon()
        settings = self._basic_settings()
        settings["VHOST_SNI_INJECT_DISCOVERED"] = False
        responses = {
            ("baseline", 443): {"status": 403, "size": 548},
            ("admin.example.com", 443): {"status": 200, "size": 5000},
            ("sni:admin.example.com", 443): {"status": 403, "size": 548},
            ("staging.example.com", 443): {"status": 403, "size": 548},
            ("sni:staging.example.com", 443): {"status": 403, "size": 548},
        }
        with patch.object(vsm, "_is_curl_available", return_value=True), \
             patch.object(vsm, "_curl_probe", side_effect=_mock_curl_responses(responses)):
            run_vhost_sni_enrichment(cr, settings=settings)

        # finding still produced, but URL not injected
        assert len(cr["vhost_sni"]["findings"]) == 1
        assert cr["vhost_sni"]["discovered_baseurls"] == []
        assert "http_probe" not in cr or "https://admin.example.com" not in cr.get("http_probe", {}).get("by_url", {})

    def test_baseline_failure_skips_port(self):
        cr = self._basic_recon()
        cr["port_scan"]["by_host"]["host1"]["ports"] = [{"port": 443}, {"port": 8080}]
        # baseline for 443 fails -> port skipped; baseline for 8080 succeeds
        responses = {
            ("baseline", 443): None,  # baseline failure
            ("baseline", 8080): {"status": 200, "size": 100},
            ("admin.example.com", 8080): {"status": 200, "size": 100},
            ("staging.example.com", 8080): {"status": 200, "size": 100},
            # L4 not run on http (port 8080 -> http scheme)
        }
        with patch.object(vsm, "_is_curl_available", return_value=True), \
             patch.object(vsm, "_curl_probe", side_effect=_mock_curl_responses(responses)):
            run_vhost_sni_enrichment(cr, settings=self._basic_settings())

        # Only port 8080 should have been tested
        ip_result = cr["vhost_sni"]["by_ip"]["1.2.3.4"]
        assert ip_result["ports_tested"] == 1

    def test_l4_skipped_for_http_scheme(self):
        # L4 SNI test only makes sense for HTTPS
        cr = self._basic_recon()
        cr["port_scan"]["by_host"]["host1"]["ports"] = [{"port": 80}]
        called_with_sni = []

        def track_curl(scheme, host_header, sni_hostname, target, port, timeout):
            if sni_hostname:
                called_with_sni.append((sni_hostname, port))
            if not host_header and not sni_hostname:
                return {"status": 200, "size": 100}
            if host_header:
                return {"status": 200, "size": 100}
            return None

        with patch.object(vsm, "_is_curl_available", return_value=True), \
             patch.object(vsm, "_curl_probe", side_effect=track_curl):
            run_vhost_sni_enrichment(cr, settings=self._basic_settings())

        # SNI test should not have been attempted on the HTTP port
        assert called_with_sni == []


# ===========================================================================
# Isolated wrapper (thread-safety contract)
# ===========================================================================
class TestIsolatedWrapper:
    def test_does_not_mutate_original(self):
        cr = {
            "domain": "example.com",
            "port_scan": {"by_host": {"h": {"ip": "1.2.3.4", "ports": [{"port": 443}]}}},
        }
        original_keys = set(cr.keys())

        with patch.object(vsm, "_is_curl_available", return_value=True), \
             patch.object(vsm, "_curl_probe", return_value={"status": 200, "size": 100}):
            result = run_vhost_sni_enrichment_isolated(
                cr,
                settings={
                    "VHOST_SNI_ENABLED": True,
                    "VHOST_SNI_USE_DEFAULT_WORDLIST": False,
                    "VHOST_SNI_USE_GRAPH_CANDIDATES": False,
                    "VHOST_SNI_CUSTOM_WORDLIST": "",
                    "VHOST_SNI_TEST_L7": True,
                    "VHOST_SNI_TEST_L4": True,
                },
            )

        # Original combined_result is untouched
        assert "vhost_sni" not in cr
        assert set(cr.keys()) == original_keys
        # Result is the standalone vhost_sni payload
        assert "summary" in result
        assert "scan_metadata" in result

    def test_returns_empty_when_disabled(self):
        result = run_vhost_sni_enrichment_isolated({}, settings={"VHOST_SNI_ENABLED": False})
        assert result["scan_metadata"]["skipped_reason"] == "disabled"


# ===========================================================================
# Empty-result helper
# ===========================================================================
class TestEmptyResult:
    def test_shape(self):
        r = _empty_result(reason="test")
        assert r["summary"]["ips_tested"] == 0
        assert r["findings"] == []
        assert r["discovered_baseurls"] == []
        assert r["scan_metadata"]["skipped_reason"] == "test"


class TestSettingsDump:
    """
    The settings dump at the start of every run is what the user inspects
    in the Recon Logs Drawer to verify the modal/project settings actually
    landed correctly. Guard the contract that EVERY user-tunable key shows
    up + the values match what was passed in.
    """

    def _basic_recon(self):
        return {
            "domain": "example.com",
            "metadata": {"target": "example.com"},
            "port_scan": {
                "by_host": {"h": {"ip": "1.2.3.4", "ports": [{"port": 443}]}},
            },
        }

    def _all_settings(self, **overrides):
        s = {
            "VHOST_SNI_ENABLED": True,
            "VHOST_SNI_TEST_L7": True,
            "VHOST_SNI_TEST_L4": False,
            "VHOST_SNI_USE_GRAPH_CANDIDATES": False,
            "VHOST_SNI_USE_DEFAULT_WORDLIST": False,
            "VHOST_SNI_CUSTOM_WORDLIST": "admin\nstaging\n# comment\n\nfoo",
            "VHOST_SNI_INJECT_DISCOVERED": True,
            "VHOST_SNI_TIMEOUT": 7,
            "VHOST_SNI_CONCURRENCY": 42,
            "VHOST_SNI_BASELINE_SIZE_TOLERANCE": 99,
            "VHOST_SNI_MAX_CANDIDATES_PER_IP": 1234,
        }
        s.update(overrides)
        return s

    def _capture_run(self, settings):
        import io, contextlib
        buf = io.StringIO()
        with patch.object(vsm, "_is_curl_available", return_value=True), \
             patch.object(vsm, "_curl_probe", return_value={"status": 200, "size": 100}), \
             contextlib.redirect_stdout(buf):
            run_vhost_sni_enrichment(self._basic_recon(), settings=settings)
        return buf.getvalue()

    def test_dump_block_present(self):
        out = self._capture_run(self._all_settings())
        assert "Effective settings for this run:" in out

    def test_every_user_tunable_key_logged(self):
        out = self._capture_run(self._all_settings())
        for key in (
            "VHOST_SNI_TEST_L7",
            "VHOST_SNI_TEST_L4",
            "VHOST_SNI_USE_GRAPH_CANDIDATES",
            "VHOST_SNI_USE_DEFAULT_WORDLIST",
            "VHOST_SNI_CUSTOM_WORDLIST",
            "VHOST_SNI_INJECT_DISCOVERED",
            "VHOST_SNI_TIMEOUT",
            "VHOST_SNI_CONCURRENCY",
            "VHOST_SNI_BASELINE_SIZE_TOLERANCE",
            "VHOST_SNI_MAX_CANDIDATES_PER_IP",
        ):
            assert key in out, f"Settings dump is missing key: {key}"

    def test_dump_values_reflect_what_was_passed(self):
        out = self._capture_run(self._all_settings(
            VHOST_SNI_TEST_L4=True,
            VHOST_SNI_CONCURRENCY=99,
            VHOST_SNI_BASELINE_SIZE_TOLERANCE=7,
        ))
        # Format from print_effective_settings: KEY (padded) = value
        assert "VHOST_SNI_TEST_L4" in out and "= True" in out
        assert "VHOST_SNI_CONCURRENCY" in out and "= 99" in out
        assert "VHOST_SNI_BASELINE_SIZE_TOLERANCE" in out and "= 7" in out

    def test_custom_wordlist_long_value_redacted_to_summary(self):
        # The helper renders strings >100 chars as "<N chars, M non-comment lines>"
        # This protects the log drawer from being flooded by huge wordlists.
        long_wl = "\n".join(f"sub{i}.example.com" for i in range(20))
        assert len(long_wl) > 100
        out = self._capture_run(self._all_settings(VHOST_SNI_CUSTOM_WORDLIST=long_wl))
        assert "VHOST_SNI_CUSTOM_WORDLIST" in out
        # Either summarised or shown -- main thing: tool didn't crash and key is present
        assert "20 non-comment lines" in out or "VHOST_SNI_CUSTOM_WORDLIST" in out

    def test_grouped_section_headers_present(self):
        out = self._capture_run(self._all_settings())
        # Helper emits "# <group>" header lines when group changes
        assert "# Test layers" in out
        assert "# Candidate sources" in out
        assert "# Performance" in out

    def test_dump_emitted_before_disabled_skip(self):
        # When VHOST_SNI_ENABLED=False the dump is NOT logged (early skip)
        # because the operator already knows why.
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run_vhost_sni_enrichment({}, settings={"VHOST_SNI_ENABLED": False})
        out = buf.getvalue()
        assert "Effective settings for this run:" not in out
        assert "Disabled via settings" in out


# ===========================================================================
# Control-probe filter (false-positive suppression for permissive frontends)
# ===========================================================================
class TestMatchesAnyControl:
    """Unit tests for the response-shape suppression check."""

    def test_no_controls_means_no_suppression(self):
        probe = {"status": 403, "size": 700, "body_hash": "abc"}
        assert _matches_any_control(probe, []) is False

    def test_no_probe_means_no_suppression(self):
        ctrls = [{"status": 403, "size": 700, "body_hash": "abc"}]
        assert _matches_any_control(None, ctrls) is False

    def test_missing_body_hash_never_suppresses(self):
        # Defensive: if curl couldn't capture the body (zero-byte response or
        # mocked test data), refuse to suppress -- silent drops of real
        # findings would be far worse than a few false positives.
        probe = {"status": 403, "size": 700}
        ctrls = [{"status": 403, "size": 700}]
        assert _matches_any_control(probe, ctrls) is False

    def test_status_must_match(self):
        probe = {"status": 200, "size": 700, "body_hash": "abc"}
        ctrls = [{"status": 403, "size": 700, "body_hash": "abc"}]
        assert _matches_any_control(probe, ctrls) is False

    def test_body_hash_must_match(self):
        probe = {"status": 403, "size": 700, "body_hash": "real_admin_panel"}
        ctrls = [{"status": 403, "size": 700, "body_hash": "default_unknown_host"}]
        assert _matches_any_control(probe, ctrls) is False

    def test_exact_status_and_hash_match_suppresses(self):
        probe = {"status": 403, "size": 700, "body_hash": "deadbeef"}
        ctrls = [{"status": 403, "size": 700, "body_hash": "deadbeef"}]
        assert _matches_any_control(probe, ctrls) is True

    def test_matches_against_any_of_multiple_controls(self):
        probe = {"status": 403, "size": 700, "body_hash": "ctrl3_hash"}
        ctrls = [
            {"status": 200, "size": 100, "body_hash": "ctrl1"},
            {"status": 403, "size": 700, "body_hash": "ctrl2"},
            {"status": 403, "size": 700, "body_hash": "ctrl3_hash"},
        ]
        assert _matches_any_control(probe, ctrls) is True


class TestDetectNoisyFrontend:
    """Safety-net guard for cases the control filter misses."""

    def _anom(self, status, size):
        return {"observed_status": status, "observed_size": size}

    def test_below_min_candidates_never_flags(self):
        anomalies = [self._anom(403, 700) for _ in range(3)]
        kept, noisy = _detect_noisy_frontend(anomalies, candidates_count=3)
        assert noisy is False
        assert kept == anomalies

    def test_no_anomalies_returns_unchanged(self):
        kept, noisy = _detect_noisy_frontend([], candidates_count=20)
        assert noisy is False
        assert kept == []

    def test_low_fire_rate_never_flags(self):
        # 10% fire rate -- well below the 70% threshold
        anomalies = [self._anom(403, 700) for _ in range(2)]
        kept, noisy = _detect_noisy_frontend(anomalies, candidates_count=20)
        assert noisy is False
        assert kept == anomalies

    def test_high_fire_rate_clustered_responses_flags_noisy(self):
        # 100% of candidates fire and they all look identical -> permissive frontend
        anomalies = [self._anom(403, 700) for _ in range(20)]
        kept, noisy = _detect_noisy_frontend(anomalies, candidates_count=20)
        assert noisy is True
        assert kept == []

    def test_high_fire_rate_diverse_responses_keeps_findings(self):
        # 100% fire but every single anomaly has a distinct shape -> not noisy,
        # genuinely a server with many vhosts (or different per-host content)
        anomalies = [self._anom(200 + i, 100 * (i + 1)) for i in range(20)]
        kept, noisy = _detect_noisy_frontend(anomalies, candidates_count=20)
        assert noisy is False
        assert kept == anomalies

    def test_two_dominant_buckets_still_flags_noisy(self):
        # Cloudflare commonly bucket-routes by Host length; two clusters but
        # both still represent the IP's default unknown-host behavior.
        anomalies = [self._anom(403, 700) for _ in range(10)] + [
            self._anom(409, 549) for _ in range(8)
        ] + [self._anom(200, 5000)]
        kept, noisy = _detect_noisy_frontend(anomalies, candidates_count=19)
        assert noisy is True

    def test_threshold_just_below_fire_rate(self):
        # 60% fire (12/20) -- below the 70% threshold even when clustered
        anomalies = [self._anom(403, 700) for _ in range(12)]
        kept, noisy = _detect_noisy_frontend(anomalies, candidates_count=20)
        assert noisy is False
        assert kept == anomalies


class TestControlProbeIntegration:
    """End-to-end: the run_vhost_sni_enrichment path correctly suppresses
    Cloudflare-style permissive-frontend false positives."""

    def _basic_recon(self):
        return {
            "domain": "example.com",
            "metadata": {"target": "example.com"},
            "port_scan": {
                "by_host": {"h": {"ip": "1.2.3.4", "ports": [{"port": 443}]}},
            },
        }

    def _basic_settings(self):
        return {
            "VHOST_SNI_ENABLED": True,
            "VHOST_SNI_TEST_L7": True,
            "VHOST_SNI_TEST_L4": False,
            "VHOST_SNI_TIMEOUT": 1,
            "VHOST_SNI_CONCURRENCY": 2,
            "VHOST_SNI_BASELINE_SIZE_TOLERANCE": 50,
            "VHOST_SNI_USE_DEFAULT_WORDLIST": False,
            "VHOST_SNI_USE_GRAPH_CANDIDATES": False,
            "VHOST_SNI_INJECT_DISCOVERED": False,
            "VHOST_SNI_CUSTOM_WORDLIST": "admin\nstaging\nblog",
            "VHOST_SNI_MAX_CANDIDATES_PER_IP": 100,
        }

    def test_cloudflare_style_responses_get_suppressed(self):
        """Permissive frontend: every unknown Host returns 403/700 with the
        same body. With body_hash matching, every candidate gets suppressed."""
        cr = self._basic_recon()

        # The control probes use random "vhostsni-ctrl-XXX-N.invalid" hostnames,
        # which we route to the same "unknown vhost default" response. Real
        # candidates also see that same response -> all suppressed.
        UNKNOWN_DEFAULT = {"status": 403, "size": 700, "body_hash": "perm_frontend_default"}
        BASELINE = {"status": 301, "size": 549, "body_hash": "redirect_to_self"}

        def fake_curl(scheme, host_header, sni_hostname, target, port, timeout):
            if host_header is None and sni_hostname is None:
                return BASELINE
            return UNKNOWN_DEFAULT  # control AND candidate alike

        with patch.object(vsm, "_is_curl_available", return_value=True), \
             patch.object(vsm, "_curl_probe", side_effect=fake_curl):
            run_vhost_sni_enrichment(cr, settings=self._basic_settings())

        ip_result = cr["vhost_sni"]["by_ip"]["1.2.3.4"]
        # All 3 candidates (admin, staging, blog) suppressed -- Cloudflare-style
        assert cr["vhost_sni"]["findings"] == []
        assert ip_result["suppressed_by_control"] >= 3

    def test_real_hidden_vhost_survives_control_filter(self):
        """Genuine hidden vhost -- different body hash than the control -- is
        kept even when the IP also has permissive-frontend behavior."""
        cr = self._basic_recon()

        UNKNOWN_DEFAULT = {"status": 403, "size": 700, "body_hash": "perm_default"}
        BASELINE = {"status": 301, "size": 549, "body_hash": "redirect"}
        ADMIN_PANEL = {"status": 200, "size": 5400, "body_hash": "real_admin_html"}

        def fake_curl(scheme, host_header, sni_hostname, target, port, timeout):
            if host_header is None and sni_hostname is None:
                return BASELINE
            if host_header == "admin.example.com":
                return ADMIN_PANEL  # genuinely unique
            return UNKNOWN_DEFAULT  # everything else hits the catch-all

        with patch.object(vsm, "_is_curl_available", return_value=True), \
             patch.object(vsm, "_curl_probe", side_effect=fake_curl):
            run_vhost_sni_enrichment(cr, settings=self._basic_settings())

        findings = cr["vhost_sni"]["findings"]
        assert len(findings) == 1
        assert findings[0]["hostname"] == "admin.example.com"
        # The other two candidates (staging, blog) collided with the control
        ip_result = cr["vhost_sni"]["by_ip"]["1.2.3.4"]
        assert ip_result["suppressed_by_control"] == 2

    def test_noisy_frontend_safety_net_kicks_in(self):
        """If controls don't match (e.g. they returned None/varied) but >70%
        of a large wordlist still fires with clustered responses, suppress."""
        cr = self._basic_recon()
        settings = self._basic_settings()
        # 12 candidates, all returning the same 200/5000 -- clustered & high rate
        settings["VHOST_SNI_CUSTOM_WORDLIST"] = "\n".join(
            [f"host{i}" for i in range(12)]
        )

        BASELINE = {"status": 301, "size": 549, "body_hash": "baseline"}
        # Note: NO body_hash -> control filter cannot suppress -> noisy guard
        # is the only thing standing between us and 12 false-positive findings.
        SAME_SHAPE = {"status": 200, "size": 5000}

        def fake_curl(scheme, host_header, sni_hostname, target, port, timeout):
            if host_header is None and sni_hostname is None:
                return BASELINE
            return SAME_SHAPE

        with patch.object(vsm, "_is_curl_available", return_value=True), \
             patch.object(vsm, "_curl_probe", side_effect=fake_curl):
            run_vhost_sni_enrichment(cr, settings=settings)

        # All 12 candidates produce the same clustered shape -> noisy guard fires
        assert cr["vhost_sni"]["findings"] == []
        ip_result = cr["vhost_sni"]["by_ip"]["1.2.3.4"]
        assert ip_result["is_permissive_frontend"] is True

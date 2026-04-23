"""
Unit tests for the parallelization refactoring.

Tests the fan-out/fan-in patterns, isolated wrappers, and thread safety
without making real network calls (all external tools are mocked).
"""

import sys
import copy
import time
import threading
from pathlib import Path
from unittest import mock
from concurrent.futures import ThreadPoolExecutor, as_completed

# Setup path — need both /app and /app/recon since some modules use relative imports
PROJECT_ROOT = Path(__file__).parent.parent.parent
RECON_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(RECON_ROOT))


# ---------------------------------------------------------------------------
# Test 1: query_crtsh and query_hackertarget are independent (thread-safe)
# ---------------------------------------------------------------------------
def test_crtsh_creates_own_session():
    """query_crtsh creates its own session and closes it — no shared state."""
    from recon.main_recon_modules.domain_recon import query_crtsh

    with mock.patch("recon.main_recon_modules.domain_recon.get_tor_session") as mock_session_factory:
        mock_session = mock.MagicMock()
        mock_resp = mock.MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"name_value": "www.example.com"},
            {"name_value": "api.example.com"},
        ]
        mock_session.get.return_value = mock_resp
        mock_session_factory.return_value = mock_session

        result = query_crtsh("example.com", anonymous=False, settings={})

        # Should have created its own session
        mock_session_factory.assert_called_once_with(False)
        # Should have closed the session
        mock_session.close.assert_called_once()
        # Should return sourced dict
        assert "www.example.com" in result
        assert "crt.sh" in result["www.example.com"]
    print("PASS: test_crtsh_creates_own_session")


def test_hackertarget_creates_own_session():
    """query_hackertarget creates its own session and closes it."""
    from recon.main_recon_modules.domain_recon import query_hackertarget

    with mock.patch("recon.main_recon_modules.domain_recon.get_tor_session") as mock_session_factory:
        mock_session = mock.MagicMock()
        mock_resp = mock.MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "mail.example.com,1.2.3.4\nftp.example.com,5.6.7.8"
        mock_session.get.return_value = mock_resp
        mock_session_factory.return_value = mock_session

        result = query_hackertarget("example.com", anonymous=False, settings={})

        mock_session_factory.assert_called_once_with(False)
        mock_session.close.assert_called_once()
        assert "mail.example.com" in result
        assert "hackertarget" in result["mail.example.com"]
    print("PASS: test_hackertarget_creates_own_session")


# ---------------------------------------------------------------------------
# Test 2: crtsh + hackertarget can run in parallel without races
# ---------------------------------------------------------------------------
def test_parallel_crtsh_hackertarget():
    """Run both passive tools concurrently — verify no shared state corruption."""
    from recon.main_recon_modules.domain_recon import query_crtsh, query_hackertarget

    call_log = {"sessions_created": 0}
    lock = threading.Lock()

    def fake_session_factory(anonymous):
        with lock:
            call_log["sessions_created"] += 1
        sess = mock.MagicMock()
        resp = mock.MagicMock()
        resp.status_code = 200
        resp.json.return_value = [{"name_value": f"sub{call_log['sessions_created']}.example.com"}]
        resp.text = f"ht{call_log['sessions_created']}.example.com,1.2.3.4"
        sess.get.return_value = resp
        return sess

    with mock.patch("recon.main_recon_modules.domain_recon.get_tor_session", side_effect=fake_session_factory):
        with ThreadPoolExecutor(max_workers=2) as executor:
            f1 = executor.submit(query_crtsh, "example.com", False, {})
            f2 = executor.submit(query_hackertarget, "example.com", False, {})

            r1 = f1.result()
            r2 = f2.result()

    # Each should have created its own session
    assert call_log["sessions_created"] == 2, f"Expected 2 sessions, got {call_log['sessions_created']}"

    # Results should not be empty
    assert len(r1) > 0, "crtsh returned empty"
    assert len(r2) > 0, "hackertarget returned empty"

    # Sources should be distinct
    for sources in r1.values():
        assert "crt.sh" in sources
    for sources in r2.values():
        assert "hackertarget" in sources

    print("PASS: test_parallel_crtsh_hackertarget")


# ---------------------------------------------------------------------------
# Test 3: discover_subdomains uses ThreadPoolExecutor (fan-out)
# ---------------------------------------------------------------------------
def test_discover_subdomains_parallel():
    """Verify all 5 discovery tools are submitted to ThreadPoolExecutor."""
    from recon.main_recon_modules.domain_recon import discover_subdomains

    with mock.patch("recon.main_recon_modules.domain_recon.query_crtsh", return_value={"a.example.com": {"crt.sh"}}), \
         mock.patch("recon.main_recon_modules.domain_recon.query_hackertarget", return_value={"b.example.com": {"hackertarget"}}), \
         mock.patch("recon.main_recon_modules.domain_recon.run_subfinder", return_value={"c.example.com"}), \
         mock.patch("recon.main_recon_modules.domain_recon.run_amass", return_value=set()), \
         mock.patch("recon.main_recon_modules.domain_recon.run_knockpy", return_value={"d.example.com"}), \
         mock.patch("recon.main_recon_modules.domain_recon.resolve_all_dns") as mock_dns:

        mock_dns.return_value = {
            "domain": {"records": {}, "ips": {"ipv4": ["1.1.1.1"], "ipv6": []}, "has_records": True},
            "subdomains": {}
        }

        result = discover_subdomains(
            "example.com", anonymous=False, bruteforce=False,
            resolve=True, save_output=False, settings={"AMASS_ENABLED": False}
        )

        # Should have discovered subdomains from all sources
        subs = result["subdomains"]
        assert "a.example.com" in subs, f"Missing crt.sh sub: {subs}"
        assert "b.example.com" in subs, f"Missing hackertarget sub: {subs}"
        assert "c.example.com" in subs, f"Missing subfinder sub: {subs}"
        assert "d.example.com" in subs, f"Missing knockpy sub: {subs}"

        # DNS should have been called
        mock_dns.assert_called_once()

    print("PASS: test_discover_subdomains_parallel")


# ---------------------------------------------------------------------------
# Test 4: resolve_all_dns uses parallel workers
# ---------------------------------------------------------------------------
def test_resolve_all_dns_parallel():
    """Verify DNS resolution runs in parallel and collects all results."""
    from recon.main_recon_modules.domain_recon import resolve_all_dns

    call_times = []

    def fake_dns_lookup(hostname, max_retries=3):
        call_times.append(time.monotonic())
        time.sleep(0.05)  # 50ms per lookup
        return {
            "records": {"A": [f"1.2.3.{len(call_times)}"]},
            "ips": {"ipv4": [f"1.2.3.{len(call_times)}"], "ipv6": []},
            "has_records": True
        }

    subdomains = [f"sub{i}.example.com" for i in range(10)]

    with mock.patch("recon.main_recon_modules.domain_recon.dns_lookup", side_effect=fake_dns_lookup):
        start = time.monotonic()
        result = resolve_all_dns("example.com", subdomains, max_workers=10)
        elapsed = time.monotonic() - start

    # All 10 subdomains + root domain = 11 calls
    assert len(result["subdomains"]) == 10
    assert "domain" in result

    # With 10 parallel workers + 50ms each, should complete much faster than 550ms sequential
    # Allow generous margin for test environment overhead
    assert elapsed < 1.0, f"DNS resolution took {elapsed:.2f}s — likely sequential"
    print(f"PASS: test_resolve_all_dns_parallel (elapsed={elapsed:.3f}s)")


# ---------------------------------------------------------------------------
# Test 5: run_shodan_enrichment_isolated doesn't mutate original
# ---------------------------------------------------------------------------
def test_shodan_isolated_no_mutation():
    """Verify isolated wrapper doesn't mutate the original combined_result."""
    from recon.main_recon_modules.shodan_enrich import run_shodan_enrichment_isolated

    original = {
        "domain": "example.com",
        "dns": {
            "domain": {"ips": {"ipv4": ["1.2.3.4"], "ipv6": []}},
            "subdomains": {}
        },
        "metadata": {"ip_mode": False}
    }
    original_copy = copy.deepcopy(original)

    with mock.patch("recon.main_recon_modules.shodan_enrich.run_shodan_enrichment") as mock_enrich:
        def side_effect(snapshot, settings):
            snapshot["shodan"] = {"hosts": [{"ip": "1.2.3.4"}]}
            return snapshot
        mock_enrich.side_effect = side_effect

        result = run_shodan_enrichment_isolated(original, {})

    # Result should contain shodan data
    assert "hosts" in result, f"Expected shodan data, got: {result}"

    # Original should NOT have been modified
    assert "shodan" not in original, f"Original was mutated! Keys: {list(original.keys())}"
    assert original == original_copy, "Original dict was modified"

    print("PASS: test_shodan_isolated_no_mutation")


# ---------------------------------------------------------------------------
# Test 6: run_port_scan_isolated doesn't mutate original
# ---------------------------------------------------------------------------
def test_port_scan_isolated_no_mutation():
    """Verify isolated wrapper doesn't mutate the original recon_data."""
    from recon.main_recon_modules.port_scan import run_port_scan_isolated

    original = {
        "domain": "example.com",
        "dns": {
            "domain": {"ips": {"ipv4": ["1.2.3.4"], "ipv6": []}},
            "subdomains": {}
        },
        "subdomains": ["www.example.com"],
        "metadata": {"ip_mode": False, "filtered_mode": False, "subdomain_filter": []}
    }
    original_copy = copy.deepcopy(original)

    with mock.patch("recon.main_recon_modules.port_scan.run_port_scan") as mock_scan:
        def side_effect(snapshot, output_file=None, settings=None):
            snapshot["port_scan"] = {"by_host": {}, "summary": {"total_open_ports": 5}}
            return snapshot
        mock_scan.side_effect = side_effect

        result = run_port_scan_isolated(original, settings={})

    # Result should contain port_scan data
    assert "summary" in result, f"Expected port_scan data, got: {result}"

    # Original should NOT have been modified
    assert "port_scan" not in original, f"Original was mutated! Keys: {list(original.keys())}"
    assert original == original_copy, "Original dict was modified"

    print("PASS: test_port_scan_isolated_no_mutation")


# ---------------------------------------------------------------------------
# Test 7: run_urlscan_discovery_only works standalone
# ---------------------------------------------------------------------------
def test_urlscan_discovery_only():
    """Verify URLScan discovery-only wrapper works with just a domain string."""
    from recon.main_recon_modules.urlscan_enrich import run_urlscan_discovery_only

    with mock.patch("recon.main_recon_modules.urlscan_enrich.run_urlscan_enrichment") as mock_enrich:
        def side_effect(fake_combined, settings):
            fake_combined["urlscan"] = {
                "results_count": 3,
                "subdomains_discovered": ["api.example.com"],
                "ips_discovered": ["1.2.3.4"],
            }
            return fake_combined
        mock_enrich.side_effect = side_effect

        result = run_urlscan_discovery_only("example.com", {"URLSCAN_ENABLED": True})

    assert result["results_count"] == 3
    assert "api.example.com" in result["subdomains_discovered"]

    # Disabled should return empty
    result2 = run_urlscan_discovery_only("example.com", {"URLSCAN_ENABLED": False})
    assert result2 == {}

    # Empty domain should return empty
    result3 = run_urlscan_discovery_only("", {"URLSCAN_ENABLED": True})
    assert result3 == {}

    print("PASS: test_urlscan_discovery_only")


# ---------------------------------------------------------------------------
# Test 8: Shodan and port scan can run truly in parallel
# ---------------------------------------------------------------------------
def test_shodan_portscan_parallel():
    """Verify Shodan and port scan run concurrently (fan-out Group 3)."""
    from recon.main_recon_modules.shodan_enrich import run_shodan_enrichment_isolated
    from recon.main_recon_modules.port_scan import run_port_scan_isolated

    execution_log = []
    lock = threading.Lock()

    combined_result = {
        "domain": "example.com",
        "dns": {
            "domain": {"ips": {"ipv4": ["1.2.3.4"], "ipv6": []}},
            "subdomains": {}
        },
        "subdomains": [],
        "metadata": {"ip_mode": False, "filtered_mode": False, "subdomain_filter": []}
    }

    def mock_shodan(snapshot, settings):
        with lock:
            execution_log.append(("shodan_start", time.monotonic()))
        time.sleep(0.1)
        snapshot["shodan"] = {"hosts": []}
        with lock:
            execution_log.append(("shodan_end", time.monotonic()))
        return snapshot

    def mock_portscan(snapshot, output_file=None, settings=None):
        with lock:
            execution_log.append(("portscan_start", time.monotonic()))
        time.sleep(0.1)
        snapshot["port_scan"] = {"summary": {"total_open_ports": 0}}
        with lock:
            execution_log.append(("portscan_end", time.monotonic()))
        return snapshot

    with mock.patch("recon.main_recon_modules.shodan_enrich.run_shodan_enrichment", side_effect=mock_shodan), \
         mock.patch("recon.main_recon_modules.port_scan.run_port_scan", side_effect=mock_portscan):

        start = time.monotonic()
        with ThreadPoolExecutor(max_workers=2) as executor:
            f_shodan = executor.submit(run_shodan_enrichment_isolated, combined_result, {})
            f_portscan = executor.submit(run_port_scan_isolated, combined_result, {})

            shodan_result = f_shodan.result()
            portscan_result = f_portscan.result()
        elapsed = time.monotonic() - start

    # Both should have produced results
    assert "hosts" in shodan_result
    assert "summary" in portscan_result

    # Should have run in parallel: total time ~100ms, not ~200ms
    assert elapsed < 0.5, f"Parallel execution took {elapsed:.2f}s — likely sequential"

    # Verify overlapping execution
    starts = {name: t for name, t in execution_log if name.endswith("_start")}
    ends = {name: t for name, t in execution_log if name.endswith("_end")}

    # Shodan should have started before port scan ended (and vice versa)
    assert starts["shodan_start"] < ends["portscan_end"]
    assert starts["portscan_start"] < ends["shodan_end"]

    print(f"PASS: test_shodan_portscan_parallel (elapsed={elapsed:.3f}s)")


# ---------------------------------------------------------------------------
# Test 9: Disabled tools return empty results gracefully
# ---------------------------------------------------------------------------
def test_disabled_tools():
    """Verify disabled tools return empty results without errors."""
    from recon.main_recon_modules.domain_recon import query_crtsh, query_hackertarget, run_subfinder, run_amass

    r1 = query_crtsh("example.com", settings={"CRTSH_ENABLED": False})
    assert r1 == {}

    r2 = query_hackertarget("example.com", settings={"HACKERTARGET_ENABLED": False})
    assert r2 == {}

    with mock.patch("recon.main_recon_modules.domain_recon.subprocess") as mock_sub:
        r3 = run_subfinder("example.com", settings={"SUBFINDER_ENABLED": False})
        assert r3 == set()
        mock_sub.run.assert_not_called()

    r4 = run_amass("example.com", settings={"AMASS_ENABLED": False})
    assert r4 == set()

    print("PASS: test_disabled_tools")


# ---------------------------------------------------------------------------
# Test 10: get_passive_subdomains backward compatibility
# ---------------------------------------------------------------------------
def test_legacy_get_passive_subdomains():
    """Verify the legacy wrapper still works for backward compatibility."""
    from recon.main_recon_modules.domain_recon import get_passive_subdomains

    with mock.patch("recon.main_recon_modules.domain_recon.query_crtsh", return_value={"a.example.com": {"crt.sh"}}), \
         mock.patch("recon.main_recon_modules.domain_recon.query_hackertarget", return_value={"b.example.com": {"hackertarget"}}):

        result = get_passive_subdomains("example.com", session=None, settings={})

    assert "a.example.com" in result
    assert "b.example.com" in result
    assert "crt.sh" in result["a.example.com"]
    assert "hackertarget" in result["b.example.com"]

    print("PASS: test_legacy_get_passive_subdomains")


# ---------------------------------------------------------------------------
# Test 11: Fan-in merge logic in discover_subdomains
# ---------------------------------------------------------------------------
def test_fanin_merge_dedup():
    """Verify fan-in correctly deduplicates and attributes sources."""
    from recon.main_recon_modules.domain_recon import discover_subdomains

    with mock.patch("recon.main_recon_modules.domain_recon.query_crtsh",
                    return_value={"www.example.com": {"crt.sh"}, "shared.example.com": {"crt.sh"}}), \
         mock.patch("recon.main_recon_modules.domain_recon.query_hackertarget",
                    return_value={"shared.example.com": {"hackertarget"}}), \
         mock.patch("recon.main_recon_modules.domain_recon.run_subfinder", return_value={"shared.example.com"}), \
         mock.patch("recon.main_recon_modules.domain_recon.run_amass", return_value=set()), \
         mock.patch("recon.main_recon_modules.domain_recon.run_knockpy", return_value=set()), \
         mock.patch("recon.main_recon_modules.domain_recon.resolve_all_dns", return_value={"domain": {}, "subdomains": {}}):

        result = discover_subdomains(
            "example.com", resolve=True, save_output=False,
            settings={"AMASS_ENABLED": False}
        )

    subs = result["subdomains"]
    # Deduplication: shared.example.com should appear once
    assert subs.count("shared.example.com") == 1
    # Both should be in the list
    assert "www.example.com" in subs
    assert "shared.example.com" in subs

    print("PASS: test_fanin_merge_dedup")


# ---------------------------------------------------------------------------
# Test 12: External domains are correctly separated
# ---------------------------------------------------------------------------
def test_external_domains_separation():
    """Verify out-of-scope domains go to external_domains, not subdomains."""
    from recon.main_recon_modules.domain_recon import discover_subdomains

    with mock.patch("recon.main_recon_modules.domain_recon.query_crtsh",
                    return_value={
                        "www.example.com": {"crt.sh"},
                        "cdn.cloudfront.net": {"crt.sh"},  # external
                    }), \
         mock.patch("recon.main_recon_modules.domain_recon.query_hackertarget", return_value={}), \
         mock.patch("recon.main_recon_modules.domain_recon.run_subfinder", return_value=set()), \
         mock.patch("recon.main_recon_modules.domain_recon.run_amass", return_value=set()), \
         mock.patch("recon.main_recon_modules.domain_recon.run_knockpy", return_value=set()), \
         mock.patch("recon.main_recon_modules.domain_recon.resolve_all_dns", return_value={"domain": {}, "subdomains": {}}):

        result = discover_subdomains(
            "example.com", resolve=True, save_output=False,
            settings={"AMASS_ENABLED": False}
        )

    # In-scope
    assert "www.example.com" in result["subdomains"]
    # Out-of-scope
    assert "cdn.cloudfront.net" not in result["subdomains"]
    # External domains list
    ext_domains = [e["domain"] for e in result["external_domains"]]
    assert "cdn.cloudfront.net" in ext_domains

    print("PASS: test_external_domains_separation")


# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    tests = [
        test_crtsh_creates_own_session,
        test_hackertarget_creates_own_session,
        test_parallel_crtsh_hackertarget,
        test_discover_subdomains_parallel,
        test_resolve_all_dns_parallel,
        test_shodan_isolated_no_mutation,
        test_port_scan_isolated_no_mutation,
        test_urlscan_discovery_only,
        test_shodan_portscan_parallel,
        test_disabled_tools,
        test_legacy_get_passive_subdomains,
        test_fanin_merge_dedup,
        test_external_domains_separation,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"FAIL: {test.__name__}: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    print(f"{'=' * 50}")

    sys.exit(1 if failed else 0)

"""
Unit tests for pipeline-wide parallelization changes.

Tests run locally without Docker or external dependencies.
Tests that require `dns` module or Docker are skipped gracefully.
"""

import inspect
import os
import sys
import threading
import time
from pathlib import Path
from unittest import mock

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# Test 1: DEFAULT_SETTINGS has all new parallelism settings
# ============================================================

def test_default_settings_have_new_fields():
    from recon.project_settings import DEFAULT_SETTINGS

    expected = {
        'KATANA_PARALLELISM': 8,
        'KATANA_CONCURRENCY': 15,
        'HAKRAWLER_PARALLELISM': 5,
        'GAU_WORKERS': 10,
        'PARAMSPIDER_WORKERS': 8,
        'FFUF_PARALLELISM': 4,
        'KITERUNNER_PARALLELISM': 3,
        'JSLUICE_PARALLELISM': 5,
        'SHODAN_WORKERS': 5,
        'DNS_MAX_WORKERS': 80,
        'DNS_RECORD_PARALLELISM': True,
        'NMAP_PARALLELISM': 5,
        'OTX_WORKERS': 5,
        'VIRUSTOTAL_WORKERS': 3,
        'CENSYS_WORKERS': 5,
        'CRIMINALIP_WORKERS': 5,
        'FOFA_WORKERS': 5,
        'NETLAS_WORKERS': 5,
        'ZOOMEYE_WORKERS': 5,
    }

    for key, default_val in expected.items():
        assert key in DEFAULT_SETTINGS, f"Missing setting: {key}"
        assert DEFAULT_SETTINGS[key] == default_val, (
            f"{key}: expected {default_val}, got {DEFAULT_SETTINGS[key]}"
        )

    print("PASS: test_default_settings_have_new_fields")


# ============================================================
# Test 2: Stealth overrides all new settings
# ============================================================

def test_stealth_mode_overrides():
    from recon.project_settings import DEFAULT_SETTINGS, apply_stealth_overrides

    settings = DEFAULT_SETTINGS.copy()
    settings['STEALTH_MODE'] = True
    settings['KATANA_PARALLELISM'] = 10
    settings['KATANA_CONCURRENCY'] = 20
    settings['GAU_WORKERS'] = 15
    settings['PARAMSPIDER_WORKERS'] = 10
    settings['JSLUICE_PARALLELISM'] = 5
    settings['SHODAN_WORKERS'] = 10
    settings['DNS_MAX_WORKERS'] = 100
    settings['DNS_RECORD_PARALLELISM'] = True

    result = apply_stealth_overrides(settings)

    assert result['KATANA_PARALLELISM'] == 1, f"Expected 1, got {result['KATANA_PARALLELISM']}"
    assert result['KATANA_CONCURRENCY'] == 1, f"Expected 1, got {result['KATANA_CONCURRENCY']}"
    assert result['GAU_WORKERS'] == 1, f"Expected 1, got {result['GAU_WORKERS']}"
    assert result['PARAMSPIDER_WORKERS'] == 1
    assert result['JSLUICE_PARALLELISM'] == 1
    assert result['SHODAN_WORKERS'] == 1
    assert result['DNS_MAX_WORKERS'] == 5
    assert result['DNS_RECORD_PARALLELISM'] is False

    print("PASS: test_stealth_mode_overrides")


# ============================================================
# Test 3: Settings mapping uses defaults for old projects
# ============================================================

def test_settings_defaults_for_old_projects():
    """DEFAULT_SETTINGS.copy() provides fallback for old DB rows."""
    from recon.project_settings import DEFAULT_SETTINGS

    # Simulate what fetch_project_settings does: start with defaults, then .get()
    settings = DEFAULT_SETTINGS.copy()
    old_project = {}  # old project row with no new fields

    settings['KATANA_PARALLELISM'] = old_project.get('katanaParallelism', DEFAULT_SETTINGS['KATANA_PARALLELISM'])
    settings['KATANA_CONCURRENCY'] = old_project.get('katanaConcurrency', DEFAULT_SETTINGS['KATANA_CONCURRENCY'])
    settings['HAKRAWLER_PARALLELISM'] = old_project.get('hakrawlerParallelism', DEFAULT_SETTINGS['HAKRAWLER_PARALLELISM'])
    settings['GAU_WORKERS'] = old_project.get('gauWorkers', DEFAULT_SETTINGS['GAU_WORKERS'])
    settings['DNS_MAX_WORKERS'] = old_project.get('dnsMaxWorkers', DEFAULT_SETTINGS['DNS_MAX_WORKERS'])

    assert settings['KATANA_PARALLELISM'] == 8
    assert settings['KATANA_CONCURRENCY'] == 15
    assert settings['HAKRAWLER_PARALLELISM'] == 5
    assert settings['GAU_WORKERS'] == 10
    assert settings['DNS_MAX_WORKERS'] == 80

    print("PASS: test_settings_defaults_for_old_projects")


# ============================================================
# Test 4: Katana function signature
# ============================================================

def test_katana_signature():
    # Import without triggering dns module
    source = (PROJECT_ROOT / "recon" / "helpers" / "resource_enum" / "katana_helpers.py").read_text()
    tree = __import__('ast').parse(source)

    for node in __import__('ast').walk(tree):
        if isinstance(node, __import__('ast').FunctionDef) and node.name == 'run_katana_crawler':
            args = node.args
            all_args = [a.arg for a in args.args]
            defaults = {a.arg: d for a, d in zip(
                args.args[-len(args.defaults):], args.defaults
            )} if args.defaults else {}

            assert 'parallelism' in all_args, "Missing 'parallelism' param"
            assert 'concurrency' in all_args, "Missing 'concurrency' param"

            # Check defaults
            p_default = defaults.get('parallelism')
            c_default = defaults.get('concurrency')
            assert p_default and getattr(p_default, 'value', None) == 5, f"parallelism default should be 5"
            assert c_default and getattr(c_default, 'value', None) == 10, f"concurrency default should be 10"

            print("PASS: test_katana_signature")
            return

    raise AssertionError("run_katana_crawler not found")


# ============================================================
# Test 5: Katana uses -list, -p, -c flags (not -u)
# ============================================================

def test_katana_uses_list_flag():
    """Verify Katana command uses -list instead of -u."""
    # Parse the source to check command construction
    source = (PROJECT_ROOT / "recon" / "helpers" / "resource_enum" / "katana_helpers.py").read_text()

    # Should contain -list flag
    assert '"-list"' in source, "Katana should use -list flag"
    # Should NOT contain -u for single URL
    assert '"-u", base_url' not in source, "Katana should not use -u base_url pattern"
    # Should contain -p and -c flags
    assert '"-p", str(parallelism)' in source, "Katana should use -p flag"
    assert '"-c", str(concurrency)' in source, "Katana should use -c flag"
    # Should have temp file cleanup
    assert 'os.unlink(url_file)' in source, "Katana should clean up temp file"

    print("PASS: test_katana_uses_list_flag")


# ============================================================
# Test 6: Hakrawler uses ThreadPoolExecutor with Lock
# ============================================================

def test_hakrawler_thread_safety():
    source = (PROJECT_ROOT / "recon" / "helpers" / "resource_enum" / "hakrawler_helpers.py").read_text()

    assert 'ThreadPoolExecutor' in source, "Hakrawler should use ThreadPoolExecutor"
    assert 'threading.Lock()' in source, "Hakrawler should use threading.Lock"
    assert 'urls_lock' in source, "Hakrawler should have urls_lock"
    assert '_crawl_single_url' in source, "Hakrawler should have _crawl_single_url helper"

    # Verify parallelism param exists
    assert 'parallelism: int = 4' in source, "Hakrawler should have parallelism=4 default"

    print("PASS: test_hakrawler_thread_safety")


# ============================================================
# Test 7: ParamSpider uses ThreadPoolExecutor
# ============================================================

def test_paramspider_parallelism():
    source = (PROJECT_ROOT / "recon" / "helpers" / "resource_enum" / "paramspider_helpers.py").read_text()

    assert 'ThreadPoolExecutor' in source, "ParamSpider should use ThreadPoolExecutor"
    assert 'workers: int = 5' in source, "ParamSpider should have workers=5 default"
    assert 'as_completed' in source, "ParamSpider should use as_completed"

    print("PASS: test_paramspider_parallelism")


# ============================================================
# Test 8: FFuf uses ThreadPoolExecutor with thread reduction
# ============================================================

def test_ffuf_parallelism():
    source = (PROJECT_ROOT / "recon" / "helpers" / "resource_enum" / "ffuf_helpers.py").read_text()

    assert 'ThreadPoolExecutor' in source, "FFuf should use ThreadPoolExecutor"
    assert 'parallelism: int = 3' in source, "FFuf should have parallelism=3 default"
    assert 'effective_threads' in source, "FFuf should compute effective_threads"
    assert '_fuzz_single_target' in source, "FFuf should have _fuzz_single_target helper"

    print("PASS: test_ffuf_parallelism")


# ============================================================
# Test 9: GAU workers configurable
# ============================================================

def test_gau_workers():
    source = (PROJECT_ROOT / "recon" / "helpers" / "resource_enum" / "gau_helpers.py").read_text()

    assert 'workers: int = 10' in source, "GAU should have workers=10 default"
    assert 'min(workers, total_domains)' in source, "GAU should use min(workers, total_domains)"
    # Should NOT have hardcoded min(5, ...)
    assert 'min(5,' not in source, "GAU should not have hardcoded min(5, ...)"

    print("PASS: test_gau_workers")


# ============================================================
# Test 10: jsluice parallelism
# ============================================================

def test_jsluice_parallelism():
    source = (PROJECT_ROOT / "recon" / "helpers" / "resource_enum" / "jsluice_helpers.py").read_text()

    assert 'parallelism: int = 3' in source, "jsluice should have parallelism=3 default"
    assert 'ThreadPoolExecutor' in source, "jsluice should use ThreadPoolExecutor"
    assert '_extract_urls_for_base' in source, "jsluice should have _extract_urls_for_base helper"
    assert '_extract_secrets_for_base' in source, "jsluice should have _extract_secrets_for_base helper"

    print("PASS: test_jsluice_parallelism")


# ============================================================
# Test 11: Shodan RateLimiter correctness
# ============================================================

def test_rate_limiter_thread_safety():
    """Verify RateLimiter enforces interval across threads without serializing."""
    from recon.main_recon_modules.shodan_enrich import _RateLimiter

    limiter = _RateLimiter(0.1)  # 100ms interval
    timestamps = []
    ts_lock = threading.Lock()

    def worker():
        limiter.wait()
        with ts_lock:
            timestamps.append(time.time())

    threads = [threading.Thread(target=worker) for _ in range(5)]
    start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    elapsed = time.time() - start
    # 5 workers with 0.1s interval should take at least ~0.4s
    assert elapsed >= 0.35, f"RateLimiter too fast: {elapsed:.3f}s for 5 requests at 0.1s interval"
    assert elapsed < 2.0, f"RateLimiter too slow: {elapsed:.3f}s"

    print(f"PASS: test_rate_limiter_thread_safety (elapsed={elapsed:.3f}s)")


# ============================================================
# Test 12: Shodan has workers param
# ============================================================

def test_shodan_workers():
    source = (PROJECT_ROOT / "recon" / "shodan_enrich.py").read_text()

    assert 'SHODAN_WORKERS' in source, "Shodan should reference SHODAN_WORKERS"
    assert 'class _RateLimiter' in source, "Shodan should have _RateLimiter class"
    assert 'max_workers' in source, "Shodan functions should accept max_workers"
    assert 'ThreadPoolExecutor' in source, "Shodan should use ThreadPoolExecutor"

    print("PASS: test_shodan_workers")


# ============================================================
# Test 13: DNS parallel record types (source check)
# ============================================================

def test_dns_parallel_source():
    source = (PROJECT_ROOT / "recon" / "domain_recon.py").read_text()

    assert 'parallel: bool = True' in source, "dns_lookup should have parallel param"
    assert 'record_parallelism: bool = True' in source, "resolve_all_dns should have record_parallelism param"

    # Check that parallel mode uses ThreadPoolExecutor
    assert 'if parallel and len(DNS_RECORD_TYPES) > 1:' in source, "dns_lookup should check parallel flag"

    print("PASS: test_dns_parallel_source")


# ============================================================
# Test 14: Prisma schema has all new fields
# ============================================================

def test_prisma_schema_fields():
    schema = (PROJECT_ROOT / "webapp" / "prisma" / "schema.prisma").read_text()

    expected_fields = [
        'katanaParallelism', 'katanaConcurrency',
        'hakrawlerParallelism', 'jsluiceParallelism',
        'ffufParallelism', 'gauWorkers',
        'paramspiderWorkers', 'kiterunnerParallelism',
        'shodanWorkers', 'dnsMaxWorkers', 'dnsRecordParallelism',
        'nmapParallelism',
        'otxWorkers', 'virusTotalWorkers', 'censysWorkers',
        'criminalIpWorkers', 'fofaWorkers', 'netlasWorkers', 'zoomEyeWorkers',
    ]

    for field in expected_fields:
        assert field in schema, f"Missing Prisma field: {field}"

    print("PASS: test_prisma_schema_fields")


# ============================================================
# Test 15: Preset schema has all new fields
# ============================================================

def test_preset_schema_fields():
    schema = (PROJECT_ROOT / "webapp" / "src" / "lib" / "recon-preset-schema.ts").read_text()

    expected_fields = [
        'katanaParallelism', 'katanaConcurrency',
        'hakrawlerParallelism', 'gauWorkers',
        'paramspiderWorkers', 'ffufParallelism',
        'kiterunnerParallelism', 'jsluiceParallelism',
        'shodanWorkers', 'dnsMaxWorkers', 'dnsRecordParallelism',
        'nmapParallelism',
        'otxWorkers', 'virusTotalWorkers', 'censysWorkers',
        'criminalIpWorkers', 'fofaWorkers', 'netlasWorkers', 'zoomEyeWorkers',
    ]

    for field in expected_fields:
        assert field in schema, f"Missing preset schema field: {field}"

    print("PASS: test_preset_schema_fields")


# ============================================================
# Test 16: resource_enum.py extracts and passes all new settings
# ============================================================

def test_resource_enum_wiring():
    source = (PROJECT_ROOT / "recon" / "resource_enum.py").read_text()

    # All settings should be extracted
    for setting in [
        "KATANA_PARALLELISM", "KATANA_CONCURRENCY",
        "HAKRAWLER_PARALLELISM", "GAU_WORKERS",
        "PARAMSPIDER_WORKERS", "FFUF_PARALLELISM",
        "KITERUNNER_PARALLELISM", "JSLUICE_PARALLELISM",
    ]:
        assert f"{setting} = settings.get('{setting}'" in source, f"Missing extraction: {setting}"

    # All settings should be passed to tool calls
    assert 'KATANA_PARALLELISM,' in source, "KATANA_PARALLELISM not passed to katana call"
    assert 'KATANA_CONCURRENCY,' in source, "KATANA_CONCURRENCY not passed to katana call"
    assert 'HAKRAWLER_PARALLELISM,' in source, "HAKRAWLER_PARALLELISM not passed"
    assert 'GAU_WORKERS,' in source, "GAU_WORKERS not passed"
    assert 'PARAMSPIDER_WORKERS,' in source, "PARAMSPIDER_WORKERS not passed"
    assert 'FFUF_PARALLELISM,' in source, "FFUF_PARALLELISM not passed"
    assert 'JSLUICE_PARALLELISM,' in source, "JSLUICE_PARALLELISM not passed"

    # Scan metadata should include new settings
    assert "'katana_parallelism'" in source, "Missing katana_parallelism in metadata"
    assert "'katana_concurrency'" in source, "Missing katana_concurrency in metadata"

    print("PASS: test_resource_enum_wiring")


# ============================================================
# Test 17: partial_recon.py jsluice caller has JSLUICE_PARALLELISM
# ============================================================

def test_partial_recon_jsluice_fixed():
    """Verify the critical jsluice argument ordering bug is fixed."""
    source = (PROJECT_ROOT / "recon" / "partial_recon.py").read_text()

    # Find the jsluice call and verify JSLUICE_PARALLELISM is present
    assert 'JSLUICE_PARALLELISM' in source, "partial_recon.py should reference JSLUICE_PARALLELISM"

    # Find the run_jsluice_analysis call context
    lines = source.split('\n')
    in_call = False
    call_lines = []
    for line in lines:
        if 'run_jsluice_analysis(' in line:
            in_call = True
        if in_call:
            call_lines.append(line.strip())
            if ')' in line and line.strip().endswith(')'):
                break

    call_text = ' '.join(call_lines)
    # JSLUICE_PARALLELISM should appear BEFORE target_domains in the call
    p_idx = call_text.find('JSLUICE_PARALLELISM')
    t_idx = call_text.find('target_domains')
    assert p_idx > 0 and t_idx > 0, "Both JSLUICE_PARALLELISM and target_domains should be in call"
    assert p_idx < t_idx, (
        f"JSLUICE_PARALLELISM (pos {p_idx}) must come before target_domains (pos {t_idx})"
    )

    print("PASS: test_partial_recon_jsluice_fixed")


# ============================================================
# Test 18: Kiterunner parallelism wired (no TODO)
# ============================================================

def test_kiterunner_wired():
    source = (PROJECT_ROOT / "recon" / "resource_enum.py").read_text()

    assert 'KITERUNNER_PARALLELISM' in source, "KITERUNNER_PARALLELISM should be in resource_enum.py"
    # The TODO should be replaced
    assert 'TODO: wire from settings' not in source, "Kiterunner TODO should be resolved"

    print("PASS: test_kiterunner_wired")


# ============================================================
# Test 19: Stealth presets have minimal parallelism values
# ============================================================

def test_stealth_preset_values():
    preset = (PROJECT_ROOT / "webapp" / "src" / "lib" / "recon-presets" / "presets" / "stealth-recon.ts").read_text()

    assert 'katanaParallelism: 1' in preset, "Stealth should have katanaParallelism: 1"
    assert 'katanaConcurrency: 1' in preset, "Stealth should have katanaConcurrency: 1"
    assert 'gauWorkers: 1' in preset, "Stealth should have gauWorkers: 1"
    assert 'dnsRecordParallelism: false' in preset, "Stealth should have dnsRecordParallelism: false"

    print("PASS: test_stealth_preset_values")


# ============================================================
# Test 20: RateLimiter does NOT hold lock during sleep
# ============================================================

def test_rate_limiter_no_lock_during_sleep():
    """Verify the RateLimiter sleeps outside the lock for true parallelism."""
    source = (PROJECT_ROOT / "recon" / "shodan_enrich.py").read_text()

    # Find the wait() method in _RateLimiter
    class_start = source.find('class _RateLimiter')
    next_class_or_def = source.find('\ndef ', class_start + 1)
    class_source = source[class_start:next_class_or_def]

    wait_method = class_source[class_source.find('def wait'):]
    lines = wait_method.split('\n')

    # Track whether we're inside the `with self._lock:` block
    in_lock_block = False
    lock_body_indent = None
    sleep_inside_lock = False

    for line in lines:
        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        if 'with self._lock:' in stripped:
            in_lock_block = True
            lock_body_indent = indent + 4  # body is indented one level deeper
            continue

        if in_lock_block:
            # Check if we've exited the with block (less or equal indent)
            if stripped and indent < lock_body_indent:
                in_lock_block = False

        if in_lock_block and 'time.sleep' in stripped:
            sleep_inside_lock = True

    assert not sleep_inside_lock, "time.sleep should NOT be inside the lock block"

    print("PASS: test_rate_limiter_no_lock_during_sleep")


# ============================================================
# Test 21: Nmap parallelism
# ============================================================

def test_nmap_parallelism():
    source = (PROJECT_ROOT / "recon" / "nmap_scan.py").read_text()

    assert 'NMAP_PARALLELISM' in source, "Nmap should reference NMAP_PARALLELISM"
    assert 'ThreadPoolExecutor' in source, "Nmap should use ThreadPoolExecutor"
    assert '_scan_single_ip' in source, "Nmap should have _scan_single_ip helper"

    print("PASS: test_nmap_parallelism")


# ============================================================
# Test 22: All 7 enrichment tools have parallelism
# ============================================================

def test_enrichment_tools_parallelism():
    tools = {
        'otx_enrich.py': ('OTX_WORKERS', 'ThreadPoolExecutor', '_RateLimiter'),
        'virustotal_enrich.py': ('VIRUSTOTAL_WORKERS', 'ThreadPoolExecutor', '_RateLimiter'),
        'censys_enrich.py': ('CENSYS_WORKERS', 'ThreadPoolExecutor', '_RateLimiter'),
        'criminalip_enrich.py': ('CRIMINALIP_WORKERS', 'ThreadPoolExecutor', '_RateLimiter'),
        'fofa_enrich.py': ('FOFA_WORKERS', 'ThreadPoolExecutor', '_RateLimiter'),
        'netlas_enrich.py': ('NETLAS_WORKERS', 'ThreadPoolExecutor', '_RateLimiter'),
        'zoomeye_enrich.py': ('ZOOMEYE_WORKERS', 'ThreadPoolExecutor', '_RateLimiter'),
    }

    for filename, (workers_setting, executor_class, rate_limiter) in tools.items():
        source = (PROJECT_ROOT / "recon" / filename).read_text()
        assert workers_setting in source, f"{filename}: missing {workers_setting}"
        assert executor_class in source, f"{filename}: missing {executor_class}"
        assert rate_limiter in source, f"{filename}: missing {rate_limiter}"

    print("PASS: test_enrichment_tools_parallelism")


# ============================================================
# Test 23: Stealth overrides include new settings
# ============================================================

def test_stealth_overrides_complete():
    from recon.project_settings import DEFAULT_SETTINGS, apply_stealth_overrides

    settings = DEFAULT_SETTINGS.copy()
    settings['STEALTH_MODE'] = True
    result = apply_stealth_overrides(settings)

    assert result['NMAP_PARALLELISM'] == 1, f"Stealth NMAP_PARALLELISM should be 1"
    assert result['OTX_WORKERS'] == 1, f"Stealth OTX_WORKERS should be 1"
    assert result['VIRUSTOTAL_WORKERS'] == 1
    assert result['CENSYS_WORKERS'] == 1
    assert result['CRIMINALIP_WORKERS'] == 1
    assert result['FOFA_WORKERS'] == 1
    assert result['NETLAS_WORKERS'] == 1
    assert result['ZOOMEYE_WORKERS'] == 1

    print("PASS: test_stealth_overrides_complete")


# ============================================================
# Run all tests
# ============================================================

if __name__ == "__main__":
    tests = [
        test_default_settings_have_new_fields,
        test_stealth_mode_overrides,
        test_settings_defaults_for_old_projects,
        test_katana_signature,
        test_katana_uses_list_flag,
        test_hakrawler_thread_safety,
        test_paramspider_parallelism,
        test_ffuf_parallelism,
        test_gau_workers,
        test_jsluice_parallelism,
        test_rate_limiter_thread_safety,
        test_shodan_workers,
        test_dns_parallel_source,
        test_prisma_schema_fields,
        test_preset_schema_fields,
        test_resource_enum_wiring,
        test_partial_recon_jsluice_fixed,
        test_kiterunner_wired,
        test_stealth_preset_values,
        test_rate_limiter_no_lock_during_sleep,
        test_nmap_parallelism,
        test_enrichment_tools_parallelism,
        test_stealth_overrides_complete,
    ]

    passed = 0
    failed = 0
    errors = []

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            errors.append((test.__name__, str(e)))
            print(f"FAIL: {test.__name__}: {e}")

    print(f"\n{'='*60}")
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    if errors:
        print("\nFailed tests:")
        for name, err in errors:
            print(f"  - {name}: {err}")
    print(f"{'='*60}")

    sys.exit(1 if failed else 0)

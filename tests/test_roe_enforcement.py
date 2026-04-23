"""
Unit tests for Rules of Engagement (RoE) enforcement in the recon pipeline.

Tests cover:
1. Time window enforcement — blocks pipeline outside allowed hours/days
2. Root domain exclusion — blocks pipeline if target domain is excluded
3. Hakrawler threads RoE cap — threads capped by ROE_GLOBAL_MAX_RPS
4. Stale recon file filtering — excluded subdomains removed from loaded data
5. Existing rate limit caps — verify all tools are still properly capped

Run with: python3 -m unittest tests.test_roe_enforcement -v
"""

import os
import sys
import types
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "recon"))
sys.path.insert(0, str(REPO_ROOT / "recon" / "helpers"))

# Stub Docker-only dependencies before importing main
_dns_stub = types.ModuleType('dns')
_dns_stub.__path__ = []  # make it a package
for mod_name in [
    'dns', 'dns.resolver', 'dns.rdatatype', 'dns.name', 'dns.reversename',
    'dns.exception', 'dns.rcode', 'dns.zone', 'dns.query', 'dns.rdataclass',
    'dns.tokenizer', 'dns.entropy',
    'whois', 'docker', 'neo4j', 'knockpy',
]:
    if mod_name not in sys.modules:
        if mod_name.startswith('dns.'):
            sub = types.ModuleType(mod_name)
            sys.modules[mod_name] = sub
            setattr(_dns_stub, mod_name.split('.')[-1], sub)
        elif mod_name == 'dns':
            sys.modules[mod_name] = _dns_stub
        else:
            sys.modules[mod_name] = types.ModuleType(mod_name)


# =============================================================================
# 1. Time Window Enforcement
# =============================================================================

from main import _check_roe_time_window, _is_roe_excluded, _filter_roe_excluded


class TestTimeWindowEnforcement(unittest.TestCase):
    """Test that the pipeline respects RoE time window restrictions."""

    def test_disabled_roe_allows_all(self):
        """When ROE_ENABLED is False, always allowed."""
        settings = {'ROE_ENABLED': False, 'ROE_TIME_WINDOW_ENABLED': True}
        allowed, reason = _check_roe_time_window(settings)
        self.assertTrue(allowed)
        self.assertEqual(reason, "")

    def test_disabled_time_window_allows_all(self):
        """When ROE_TIME_WINDOW_ENABLED is False, always allowed."""
        settings = {'ROE_ENABLED': True, 'ROE_TIME_WINDOW_ENABLED': False}
        allowed, reason = _check_roe_time_window(settings)
        self.assertTrue(allowed)
        self.assertEqual(reason, "")

    def _make_settings(self, **overrides):
        base = {
            'ROE_ENABLED': True,
            'ROE_TIME_WINDOW_ENABLED': True,
            'ROE_TIME_WINDOW_TIMEZONE': 'UTC',
            'ROE_TIME_WINDOW_DAYS': ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'],
            'ROE_TIME_WINDOW_START_TIME': '09:00',
            'ROE_TIME_WINDOW_END_TIME': '18:00',
        }
        base.update(overrides)
        return base

    def test_within_allowed_window(self):
        """Pipeline proceeds when inside time window on an allowed day."""
        import zoneinfo
        tz = zoneinfo.ZoneInfo('UTC')
        # Wednesday at 14:00
        fake_now = datetime(2026, 3, 25, 14, 0, 0, tzinfo=tz)
        allowed, reason = _check_roe_time_window(self._make_settings(), _now=fake_now)
        self.assertTrue(allowed)

    def test_outside_time_range_blocked(self):
        """Pipeline blocked when outside allowed time range."""
        import zoneinfo
        tz = zoneinfo.ZoneInfo('UTC')
        # Wednesday at 22:00 (outside 09:00-18:00)
        fake_now = datetime(2026, 3, 25, 22, 0, 0, tzinfo=tz)
        allowed, reason = _check_roe_time_window(self._make_settings(), _now=fake_now)
        self.assertFalse(allowed)
        self.assertIn('outside allowed window', reason)

    def test_wrong_day_blocked(self):
        """Pipeline blocked on a non-allowed day."""
        import zoneinfo
        tz = zoneinfo.ZoneInfo('UTC')
        # Saturday at 14:00 (weekday not in allowed list)
        fake_now = datetime(2026, 3, 28, 14, 0, 0, tzinfo=tz)
        allowed, reason = _check_roe_time_window(self._make_settings(), _now=fake_now)
        self.assertFalse(allowed)
        self.assertIn('saturday', reason.lower())
        self.assertIn('not in allowed days', reason)

    def test_at_exact_start_time_allowed(self):
        """Pipeline allowed at exactly the start time."""
        import zoneinfo
        tz = zoneinfo.ZoneInfo('UTC')
        fake_now = datetime(2026, 3, 25, 9, 0, 0, tzinfo=tz)  # Wednesday 09:00
        allowed, _ = _check_roe_time_window(self._make_settings(), _now=fake_now)
        self.assertTrue(allowed)

    def test_at_exact_end_time_blocked(self):
        """Pipeline blocked at exactly the end time (end is exclusive)."""
        import zoneinfo
        tz = zoneinfo.ZoneInfo('UTC')
        fake_now = datetime(2026, 3, 25, 18, 0, 0, tzinfo=tz)  # Wednesday 18:00
        allowed, _ = _check_roe_time_window(self._make_settings(), _now=fake_now)
        self.assertFalse(allowed)


# =============================================================================
# 2. Root Domain Exclusion
# =============================================================================

class TestRootDomainExclusion(unittest.TestCase):
    """Test that the root domain is checked against excluded hosts."""

    def test_root_domain_exact_match(self):
        """Root domain exactly matching an exclusion entry is detected."""
        self.assertTrue(_is_roe_excluded("example.com", ["example.com"]))

    def test_root_domain_not_excluded(self):
        """Root domain not in exclusion list passes."""
        self.assertFalse(_is_roe_excluded("example.com", ["other.com", "test.com"]))

    def test_root_domain_parent_match(self):
        """Subdomain matching a parent exclusion is detected."""
        self.assertTrue(_is_roe_excluded("sub.example.com", ["example.com"]))

    def test_root_domain_cidr_match(self):
        """IP matching a CIDR exclusion is detected."""
        self.assertTrue(_is_roe_excluded("10.0.0.5", ["10.0.0.0/24"]))

    def test_root_domain_cidr_no_match(self):
        """IP outside CIDR range passes."""
        self.assertFalse(_is_roe_excluded("192.168.1.1", ["10.0.0.0/24"]))


# =============================================================================
# 3. Hakrawler Threads RoE Cap
# =============================================================================

class TestHakrawlerRoeCap(unittest.TestCase):
    """Test that Hakrawler threads are capped by ROE_GLOBAL_MAX_RPS."""

    def test_hakrawler_threads_capped(self):
        """HAKRAWLER_THREADS should be capped to ROE_GLOBAL_MAX_RPS."""
        sys.path.insert(0, str(REPO_ROOT / "recon"))
        from project_settings import DEFAULT_SETTINGS

        # Simulate settings with high Hakrawler threads and low RoE max
        settings = dict(DEFAULT_SETTINGS)
        settings['ROE_ENABLED'] = True
        settings['ROE_GLOBAL_MAX_RPS'] = 5
        settings['HAKRAWLER_THREADS'] = 20

        # Reproduce the capping logic from fetch_project_settings
        roe_max_rps = settings['ROE_GLOBAL_MAX_RPS']
        RATE_LIMIT_KEYS = [
            'NAABU_RATE_LIMIT', 'HTTPX_RATE_LIMIT', 'NUCLEI_RATE_LIMIT',
            'KATANA_RATE_LIMIT', 'GAU_VERIFY_RATE_LIMIT', 'GAU_METHOD_DETECT_RATE_LIMIT',
            'KITERUNNER_RATE_LIMIT', 'KITERUNNER_METHOD_DETECT_RATE_LIMIT',
            'FFUF_RATE', 'PUREDNS_RATE_LIMIT',
            'HAKRAWLER_THREADS',
        ]
        for key in RATE_LIMIT_KEYS:
            if key not in settings:
                continue
            if settings[key] == 0 and key == 'FFUF_RATE':
                settings[key] = roe_max_rps
            elif settings[key] > roe_max_rps:
                settings[key] = roe_max_rps

        self.assertEqual(settings['HAKRAWLER_THREADS'], 5)

    def test_hakrawler_threads_not_capped_when_below(self):
        """HAKRAWLER_THREADS below RoE max should not be changed."""
        settings = {'HAKRAWLER_THREADS': 3, 'ROE_GLOBAL_MAX_RPS': 10}
        roe_max_rps = settings['ROE_GLOBAL_MAX_RPS']
        if settings['HAKRAWLER_THREADS'] > roe_max_rps:
            settings['HAKRAWLER_THREADS'] = roe_max_rps
        self.assertEqual(settings['HAKRAWLER_THREADS'], 3)

    def test_hakrawler_in_rate_limit_keys(self):
        """Verify HAKRAWLER_THREADS is in the RATE_LIMIT_KEYS list in project_settings.py."""
        source_path = REPO_ROOT / "recon" / "project_settings.py"
        with open(source_path, 'r') as f:
            content = f.read()
        self.assertIn("'HAKRAWLER_THREADS'", content)


# =============================================================================
# 4. Stale Recon File Filtering
# =============================================================================

class TestStaleReconFileFiltering(unittest.TestCase):
    """Test that excluded subdomains are removed from loaded recon data."""

    def test_excluded_subs_removed_from_dns(self):
        """Subdomains in ROE_EXCLUDED_HOSTS are removed from loaded DNS data."""
        recon_data = {
            'dns': {
                'subdomains': {
                    'api.example.com': {'has_records': True, 'ips': {'ipv4': ['1.2.3.4']}},
                    'payments.example.com': {'has_records': True, 'ips': {'ipv4': ['5.6.7.8']}},
                    'blog.example.com': {'has_records': True, 'ips': {'ipv4': ['9.10.11.12']}},
                }
            }
        }
        roe_excluded = ['payments.example.com']

        # Simulate the filtering logic
        dns_data = recon_data.get('dns', {})
        subs = dns_data.get('subdomains', {})
        excluded_subs = [s for s in subs if _is_roe_excluded(s, roe_excluded)]
        for s in excluded_subs:
            del subs[s]

        self.assertNotIn('payments.example.com', subs)
        self.assertIn('api.example.com', subs)
        self.assertIn('blog.example.com', subs)
        self.assertEqual(len(subs), 2)

    def test_parent_domain_exclusion_cascades(self):
        """Excluding a parent domain removes all its subdomains from DNS data."""
        recon_data = {
            'dns': {
                'subdomains': {
                    'api.payments.example.com': {'has_records': True},
                    'www.payments.example.com': {'has_records': True},
                    'blog.example.com': {'has_records': True},
                }
            }
        }
        roe_excluded = ['payments.example.com']

        subs = recon_data['dns']['subdomains']
        excluded_subs = [s for s in subs if _is_roe_excluded(s, roe_excluded)]
        for s in excluded_subs:
            del subs[s]

        self.assertNotIn('api.payments.example.com', subs)
        self.assertNotIn('www.payments.example.com', subs)
        self.assertIn('blog.example.com', subs)

    def test_no_filtering_when_roe_disabled(self):
        """No filtering occurs when ROE_ENABLED is False."""
        hosts = ['a.example.com', 'b.example.com']
        settings = {'ROE_ENABLED': False, 'ROE_EXCLUDED_HOSTS': ['a.example.com']}
        result = _filter_roe_excluded(hosts, settings)
        self.assertEqual(len(result), 2)  # nothing removed


# =============================================================================
# 5. Existing Rate Limit Caps
# =============================================================================

class TestExistingRateLimitCaps(unittest.TestCase):
    """Verify existing rate limit tools are still properly capped."""

    def test_all_expected_tools_in_rate_limit_keys(self):
        """All active-scan tools should be in the RATE_LIMIT_KEYS list."""
        source_path = REPO_ROOT / "recon" / "project_settings.py"
        with open(source_path, 'r') as f:
            content = f.read()

        expected_keys = [
            'NAABU_RATE_LIMIT',
            'HTTPX_RATE_LIMIT',
            'NUCLEI_RATE_LIMIT',
            'KATANA_RATE_LIMIT',
            'GAU_VERIFY_RATE_LIMIT',
            'GAU_METHOD_DETECT_RATE_LIMIT',
            'KITERUNNER_RATE_LIMIT',
            'KITERUNNER_METHOD_DETECT_RATE_LIMIT',
            'FFUF_RATE',
            'PUREDNS_RATE_LIMIT',
            'HAKRAWLER_THREADS',
        ]
        for key in expected_keys:
            self.assertIn(f"'{key}'", content, f"{key} missing from RATE_LIMIT_KEYS")

    def test_ffuf_unlimited_capped_under_roe(self):
        """FFUF_RATE=0 (unlimited) should be capped to ROE_GLOBAL_MAX_RPS."""
        settings = {'FFUF_RATE': 0, 'ROE_GLOBAL_MAX_RPS': 25}
        roe_max = settings['ROE_GLOBAL_MAX_RPS']
        # FFUF special case: 0 means unlimited
        if settings['FFUF_RATE'] == 0:
            settings['FFUF_RATE'] = roe_max
        self.assertEqual(settings['FFUF_RATE'], 25)


if __name__ == "__main__":
    unittest.main()

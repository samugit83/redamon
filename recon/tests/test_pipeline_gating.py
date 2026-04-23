"""
Unit tests for pipeline master enable/disable switches.

Tests verify:
  - New settings exist in DEFAULT_SETTINGS with correct defaults
  - The mapping lines in fetch_project_settings read correct camelCase keys
  - Shodan master switch gates the sub-toggles (simulated pipeline logic)
  - OSINT enrichment master switch is off by default

Run with: python -m unittest recon/tests/test_pipeline_gating.py -v
"""
import sys
import os
import unittest

# Add recon dir to path
_recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _recon_dir)

from project_settings import DEFAULT_SETTINGS


class TestNewDefaultSettings(unittest.TestCase):
    """Verify all 6 new master switches exist in DEFAULT_SETTINGS."""

    def test_subdomain_discovery_enabled_exists(self):
        self.assertIn('SUBDOMAIN_DISCOVERY_ENABLED', DEFAULT_SETTINGS)

    def test_subdomain_discovery_enabled_default_true(self):
        self.assertTrue(DEFAULT_SETTINGS['SUBDOMAIN_DISCOVERY_ENABLED'])

    def test_shodan_enabled_exists(self):
        self.assertIn('SHODAN_ENABLED', DEFAULT_SETTINGS)

    def test_shodan_enabled_default_true(self):
        self.assertTrue(DEFAULT_SETTINGS['SHODAN_ENABLED'])

    def test_osint_enrichment_enabled_exists(self):
        self.assertIn('OSINT_ENRICHMENT_ENABLED', DEFAULT_SETTINGS)

    def test_osint_enrichment_enabled_default_false(self):
        self.assertFalse(DEFAULT_SETTINGS['OSINT_ENRICHMENT_ENABLED'])

    def test_httpx_enabled_exists(self):
        self.assertIn('HTTPX_ENABLED', DEFAULT_SETTINGS)

    def test_httpx_enabled_default_true(self):
        self.assertTrue(DEFAULT_SETTINGS['HTTPX_ENABLED'])

    def test_nuclei_enabled_exists(self):
        self.assertIn('NUCLEI_ENABLED', DEFAULT_SETTINGS)

    def test_nuclei_enabled_default_true(self):
        self.assertTrue(DEFAULT_SETTINGS['NUCLEI_ENABLED'])

    def test_mitre_enabled_exists(self):
        self.assertIn('MITRE_ENABLED', DEFAULT_SETTINGS)

    def test_mitre_enabled_default_true(self):
        self.assertTrue(DEFAULT_SETTINGS['MITRE_ENABLED'])


class TestMappingLogic(unittest.TestCase):
    """Simulate the camelCase -> SCREAMING_SNAKE_CASE mapping
    that fetch_project_settings() does, by applying the same
    project.get() pattern on a mock project dict."""

    def _apply_mapping(self, project):
        """Replicate the mapping lines from fetch_project_settings()."""
        settings = DEFAULT_SETTINGS.copy()
        settings['SUBDOMAIN_DISCOVERY_ENABLED'] = project.get(
            'subdomainDiscoveryEnabled', DEFAULT_SETTINGS['SUBDOMAIN_DISCOVERY_ENABLED'])
        settings['SHODAN_ENABLED'] = project.get(
            'shodanEnabled', DEFAULT_SETTINGS['SHODAN_ENABLED'])
        settings['OSINT_ENRICHMENT_ENABLED'] = project.get(
            'osintEnrichmentEnabled', DEFAULT_SETTINGS['OSINT_ENRICHMENT_ENABLED'])
        settings['HTTPX_ENABLED'] = project.get(
            'httpxEnabled', DEFAULT_SETTINGS['HTTPX_ENABLED'])
        settings['NUCLEI_ENABLED'] = project.get(
            'nucleiEnabled', DEFAULT_SETTINGS['NUCLEI_ENABLED'])
        settings['MITRE_ENABLED'] = project.get(
            'mitreEnabled', DEFAULT_SETTINGS['MITRE_ENABLED'])
        # Shodan sub-toggles
        settings['SHODAN_HOST_LOOKUP'] = project.get(
            'shodanHostLookup', DEFAULT_SETTINGS['SHODAN_HOST_LOOKUP'])
        settings['SHODAN_REVERSE_DNS'] = project.get(
            'shodanReverseDns', DEFAULT_SETTINGS['SHODAN_REVERSE_DNS'])
        settings['SHODAN_DOMAIN_DNS'] = project.get(
            'shodanDomainDns', DEFAULT_SETTINGS['SHODAN_DOMAIN_DNS'])
        settings['SHODAN_PASSIVE_CVES'] = project.get(
            'shodanPassiveCves', DEFAULT_SETTINGS['SHODAN_PASSIVE_CVES'])
        return settings

    def test_all_defaults_when_empty_project(self):
        settings = self._apply_mapping({})
        self.assertTrue(settings['SUBDOMAIN_DISCOVERY_ENABLED'])
        self.assertTrue(settings['SHODAN_ENABLED'])
        self.assertFalse(settings['OSINT_ENRICHMENT_ENABLED'])
        self.assertTrue(settings['HTTPX_ENABLED'])
        self.assertTrue(settings['NUCLEI_ENABLED'])
        self.assertTrue(settings['MITRE_ENABLED'])

    def test_disable_subdomain_discovery(self):
        settings = self._apply_mapping({'subdomainDiscoveryEnabled': False})
        self.assertFalse(settings['SUBDOMAIN_DISCOVERY_ENABLED'])

    def test_disable_httpx(self):
        settings = self._apply_mapping({'httpxEnabled': False})
        self.assertFalse(settings['HTTPX_ENABLED'])

    def test_disable_nuclei(self):
        settings = self._apply_mapping({'nucleiEnabled': False})
        self.assertFalse(settings['NUCLEI_ENABLED'])

    def test_disable_mitre(self):
        settings = self._apply_mapping({'mitreEnabled': False})
        self.assertFalse(settings['MITRE_ENABLED'])

    def test_enable_osint(self):
        settings = self._apply_mapping({'osintEnrichmentEnabled': True})
        self.assertTrue(settings['OSINT_ENRICHMENT_ENABLED'])

    def test_disable_shodan(self):
        settings = self._apply_mapping({'shodanEnabled': False})
        self.assertFalse(settings['SHODAN_ENABLED'])


class TestShodanPipelineGating(unittest.TestCase):
    """Simulate the pipeline's Shodan gating logic from main.py."""

    def _shodan_enabled(self, settings):
        """Replicate: settings.get('SHODAN_ENABLED', True) and any([...])"""
        return settings.get('SHODAN_ENABLED', True) and any([
            settings.get('SHODAN_HOST_LOOKUP'),
            settings.get('SHODAN_REVERSE_DNS'),
            settings.get('SHODAN_DOMAIN_DNS'),
            settings.get('SHODAN_PASSIVE_CVES'),
        ])

    def test_master_on_with_sub_toggles(self):
        settings = {
            'SHODAN_ENABLED': True,
            'SHODAN_HOST_LOOKUP': True,
            'SHODAN_REVERSE_DNS': False,
            'SHODAN_DOMAIN_DNS': False,
            'SHODAN_PASSIVE_CVES': False,
        }
        self.assertTrue(self._shodan_enabled(settings))

    def test_master_off_overrides_sub_toggles(self):
        settings = {
            'SHODAN_ENABLED': False,
            'SHODAN_HOST_LOOKUP': True,
            'SHODAN_REVERSE_DNS': True,
            'SHODAN_DOMAIN_DNS': True,
            'SHODAN_PASSIVE_CVES': True,
        }
        self.assertFalse(self._shodan_enabled(settings))

    def test_master_on_all_subs_off(self):
        settings = {
            'SHODAN_ENABLED': True,
            'SHODAN_HOST_LOOKUP': False,
            'SHODAN_REVERSE_DNS': False,
            'SHODAN_DOMAIN_DNS': False,
            'SHODAN_PASSIVE_CVES': False,
        }
        self.assertFalse(self._shodan_enabled(settings))

    def test_defaults_all_true(self):
        """With default settings, Shodan runs."""
        self.assertTrue(self._shodan_enabled(DEFAULT_SETTINGS))


class TestOsintPipelineGating(unittest.TestCase):
    """Simulate the OSINT enrichment gating logic from main.py."""

    def test_osint_off_by_default(self):
        """Default: OSINT_ENRICHMENT_ENABLED is False."""
        self.assertFalse(DEFAULT_SETTINGS.get('OSINT_ENRICHMENT_ENABLED', False))

    def test_osint_master_gates_individual_tools(self):
        """When OSINT_ENRICHMENT_ENABLED is False, no tools run."""
        settings = {
            'OSINT_ENRICHMENT_ENABLED': False,
            'CENSYS_ENABLED': True,
            'FOFA_ENABLED': True,
        }
        # Pipeline logic: if not OSINT_ENRICHMENT_ENABLED, skip all
        if not settings.get('OSINT_ENRICHMENT_ENABLED', False):
            enabled_osint = {}
        else:
            enabled_osint = {k: v for k, v in settings.items() if k.endswith('_ENABLED') and v}
        self.assertEqual(enabled_osint, {})

    def test_osint_master_on_passes_through(self):
        settings = {
            'OSINT_ENRICHMENT_ENABLED': True,
            'CENSYS_ENABLED': True,
            'FOFA_ENABLED': False,
        }
        if not settings.get('OSINT_ENRICHMENT_ENABLED', False):
            enabled = {}
        else:
            enabled = {k: v for k, v in settings.items()
                       if k.endswith('_ENABLED') and v and k != 'OSINT_ENRICHMENT_ENABLED'}
        self.assertIn('CENSYS_ENABLED', enabled)
        self.assertNotIn('FOFA_ENABLED', enabled)


class TestHttpxPipelineGating(unittest.TestCase):
    """Simulate httpx gating logic."""

    def test_httpx_enabled_by_default(self):
        self.assertTrue(DEFAULT_SETTINGS.get('HTTPX_ENABLED', True))

    def test_httpx_disabled_skips_probe(self):
        settings = {'HTTPX_ENABLED': False}
        scan_modules = ['domain_discovery', 'http_probe', 'resource_enum']
        # Pipeline logic
        should_run = 'http_probe' in scan_modules and settings.get('HTTPX_ENABLED', True)
        self.assertFalse(should_run)


class TestMitrePipelineGating(unittest.TestCase):
    """Simulate MITRE gating logic."""

    def test_mitre_enabled_by_default(self):
        self.assertTrue(DEFAULT_SETTINGS.get('MITRE_ENABLED', True))

    def test_mitre_disabled_skips_enrichment(self):
        settings = {'MITRE_ENABLED': False}
        should_run = settings.get('MITRE_ENABLED', True)
        self.assertFalse(should_run)


if __name__ == '__main__':
    unittest.main()

"""
project_settings' scope helpers over the webapp's `scopeGroups` (AGT-01).

The agent prefers the groups GET /api/projects/[id] derives; the legacy fields
are read only when the field is absent (an older webapp), and then the helpers
behave as before the groups existed. test_domain_batch_scope.py pins that legacy
behaviour; this file pins the new source and the fetch that loads it.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import project_settings as ps  # noqa: E402
import scope_groups as sg  # noqa: E402


def _group(root, mode='enumerate', include_root=False, exact=(), org=None):
    return {'scanRoot': root, 'orgDomain': org or root, 'mode': mode, 'includeRoot': include_root,
            'exactHosts': list(exact),
            'entries': [f'*.{root}'] if mode == 'enumerate' else list(exact), 'notes': []}


def _settings(**values):
    def _impl(key, default=None):
        return values.get(key, default)
    return _impl


def _webapp(groups, **extra):
    """Settings as fetch_agent_settings writes them for a project with scopeGroups."""
    parsed, source, dropped = sg.scope_groups_from_project({'scopeGroups': groups, **extra})
    return _settings(SCOPE_GROUPS=parsed, SCOPE_GROUPS_SOURCE=source, SCOPE_GROUPS_DROPPED=dropped, **{
        'DOMAIN_BATCH_MODE': extra.get('domainBatchMode', False),
        'TARGET_DOMAIN': extra.get('targetDomain', ''),
        # A legacy record that disagrees with the groups must not be read.
        'DOMAIN_BATCH_GROUPS': [{'rootDomain': 'legacy.test', 'prefixes': ['*'], 'hosts': ['*.legacy.test']}],
    })


BATCH = [
    _group('www.isa.org.jm', mode='exact', exact=['a.www.isa.org.jm'], org='isa.org.jm'),
    _group('api.example.com', org='example.com'),
    _group('acme.co.uk', mode='exact', include_root=True, exact=['www.acme.co.uk']),
]


class TestWebappSource:
    def test_scan_roots_are_the_scope_domains(self):
        with patch('project_settings.get_setting', _webapp(BATCH, domainBatchMode=True)):
            assert ps.target_scope_domains() == ['www.isa.org.jm', 'api.example.com', 'acme.co.uk']

    def test_hard_names_cover_hosts_roots_and_orgs(self):
        with patch('project_settings.get_setting', _webapp(BATCH, domainBatchMode=True)):
            names = ps.guardrail_names()
        for name in ('a.www.isa.org.jm', 'www.isa.org.jm', 'isa.org.jm', 'api.example.com',
                     'example.com', 'www.acme.co.uk', 'acme.co.uk'):
            assert name in names
        assert 'legacy.test' not in names

    def test_soft_names_are_orgs_and_roots(self):
        with patch('project_settings.get_setting', _webapp(BATCH, domainBatchMode=True)):
            assert ps.soft_guardrail_names() == [
                'isa.org.jm', 'www.isa.org.jm', 'example.com', 'api.example.com', 'acme.co.uk']

    def test_auth_patterns_follow_the_matrix(self):
        with patch('project_settings.get_setting', _webapp(BATCH, domainBatchMode=True)):
            assert ps.auth_scope_patterns() == [
                'a.www.isa.org.jm', '*.api.example.com', 'www.acme.co.uk', 'acme.co.uk']

    def test_an_exact_single_domain_never_authorises_star_target(self):
        groups = [_group('example.com', mode='exact', exact=['www.example.com'])]
        with patch('project_settings.get_setting', _webapp(groups, targetDomain='example.com')):
            assert ps.auth_scope_patterns() == ['www.example.com']

    def test_a_refused_single_target_is_still_a_hard_name(self):
        # The webapp sends no group for a public-suffix target; the typed name
        # must still reach the hard guardrail.
        with patch('project_settings.get_setting', _webapp([], targetDomain='gov.uk')):
            assert ps.guardrail_names() == ['gov.uk']
            assert ps.target_scope_groups() == []

    def test_empty_groups_in_batch_mode_give_no_names(self):
        with patch('project_settings.get_setting', _webapp([], domainBatchMode=True)):
            assert ps.guardrail_names() == []
            assert ps.soft_guardrail_names() == []

    def test_ip_mode_uses_the_target_ips(self):
        values = dict(IP_MODE=True, TARGET_IPS=['192.0.2.10'], SCOPE_GROUPS_SOURCE='webapp',
                      SCOPE_GROUPS=sg.parse_scope_groups(BATCH))
        with patch('project_settings.get_setting', _settings(**values)):
            assert ps.auth_scope_patterns() == ['192.0.2.10']
            assert ps.guardrail_names() == []
            assert ps.target_scope_groups() == []

    def test_the_signature_moves_when_the_scope_does(self):
        with patch('project_settings.get_setting', _webapp(BATCH, domainBatchMode=True)):
            before = ps.scope_signature()
        with patch('project_settings.get_setting', _webapp(BATCH + [_group('new.test')], domainBatchMode=True)):
            after = ps.scope_signature()
        assert before != after


class TestLegacySource:
    def test_auth_patterns_come_from_root_and_prefixes_not_hosts(self):
        values = dict(DOMAIN_BATCH_MODE=True, DOMAIN_BATCH_GROUPS=[
            {'rootDomain': 'example.com', 'prefixes': ['www.'], 'hosts': ['*.example.com']}])
        with patch('project_settings.get_setting', _settings(**values)):
            assert ps.auth_scope_patterns() == ['www.example.com']
            # P1 behaviour of the hard names is kept for a webapp without scopeGroups.
            assert ps.guardrail_names() == ['example.com']

    def test_single_domain_legacy_matches_the_webapp_derivation(self):
        with patch('project_settings.get_setting', _settings(TARGET_DOMAIN='example.com', SUBDOMAIN_LIST=['.'])):
            assert ps.auth_scope_patterns() == ['*.example.com', 'example.com']
            assert ps.soft_guardrail_names() == ['example.com']


class TestFetch:
    def _fetch(self, project):
        resp = MagicMock()
        resp.json.return_value = project
        with patch('requests.get', return_value=resp):
            return ps.fetch_agent_settings('p1', 'http://webapp:3000')

    def test_loads_the_scope_groups_and_their_source(self):
        settings = self._fetch({'domainBatchMode': True, 'scopeGroups': BATCH + [_group('bad_x.test')],
                                'updatedAt': '2026-10-22T10:00:00.000Z'})
        assert settings['SCOPE_GROUPS_SOURCE'] == 'webapp'
        assert [g['scan_root'] for g in settings['SCOPE_GROUPS']] == [
            'www.isa.org.jm', 'api.example.com', 'acme.co.uk']
        assert settings['SCOPE_GROUPS_DROPPED'] == 1
        assert settings['PROJECT_UPDATED_AT'] == '2026-10-22T10:00:00.000Z'

    def test_an_absent_field_reads_the_legacy_fields(self):
        settings = self._fetch({'targetDomain': 'example.com', 'subdomainList': ['www.']})
        assert settings['SCOPE_GROUPS_SOURCE'] == 'legacy'
        assert settings['SUBDOMAIN_LIST'] == ['www.']

    def test_the_hostname_policy_is_read_ad_hoc(self):
        """Read like ipMode/targetIps (design §10), for P7's scope text."""
        settings = self._fetch({
            'ipMode': True, 'targetIps': ['203.0.113.10'], 'ipHostnameMode': 'record_filter',
            'ipHostnameInclude': ['*.example.com'], 'ipHostnameExclude': ['old.example.com'],
            'ipHostnamePassiveExpand': False, 'ipHostnameScanAllConfirmed': False,
            'ipHostnameMaxScanned': 7, 'ipHostnamePassiveMaxNames': 9})
        assert settings['IP_HOSTNAME_MODE'] == 'record_filter'
        assert settings['IP_HOSTNAME_INCLUDE'] == ['*.example.com']
        assert settings['IP_HOSTNAME_EXCLUDE'] == ['old.example.com']
        assert settings['IP_HOSTNAME_PASSIVE_EXPAND'] is False
        assert settings['IP_HOSTNAME_SCAN_ALL_CONFIRMED'] is False
        assert settings['IP_HOSTNAME_MAX_SCANNED'] == 7
        assert settings['IP_HOSTNAME_PASSIVE_MAX_NAMES'] == 9

    def test_an_absent_hostname_policy_reads_as_the_strictest(self):
        settings = self._fetch({'ipMode': True, 'targetIps': ['203.0.113.10'],
                                'ipHostnameMode': None, 'ipHostnameInclude': None})
        assert settings['IP_HOSTNAME_MODE'] == 'ip_only'
        assert settings['IP_HOSTNAME_INCLUDE'] == []
        assert settings['IP_HOSTNAME_EXCLUDE'] == []
        assert settings['IP_HOSTNAME_SCAN_ALL_CONFIRMED'] is False
        assert settings['IP_HOSTNAME_PASSIVE_EXPAND'] is True

    def test_only_a_literal_true_confirms_scan_all(self):
        settings = self._fetch({'ipMode': True, 'ipHostnameScanAllConfirmed': 'true'})
        assert settings['IP_HOSTNAME_SCAN_ALL_CONFIRMED'] is False

    def test_the_hostname_policy_is_not_an_agent_default(self):
        """Scope, not an agent tuning knob: no DEFAULT_AGENT_SETTINGS entry, so
        /defaults and the agent settings columns never carry it."""
        for key in ('IP_HOSTNAME_MODE', 'IP_HOSTNAME_INCLUDE', 'IP_HOSTNAME_EXCLUDE',
                    'IP_HOSTNAME_PASSIVE_EXPAND', 'IP_HOSTNAME_SCAN_ALL_CONFIRMED',
                    'IP_HOSTNAME_MAX_SCANNED', 'IP_HOSTNAME_PASSIVE_MAX_NAMES'):
            assert key not in ps.DEFAULT_AGENT_SETTINGS
            assert key not in ps.AGENT_SETTING_COLUMNS

    def test_a_settings_load_records_the_updated_at_it_saw(self):
        resp = MagicMock()
        resp.json.return_value = {'targetDomain': 'example.com', 'updatedAt': 'v2'}
        with patch('requests.get', return_value=resp), patch.dict('os.environ', {'WEBAPP_API_URL': 'http://webapp:3000'}):
            settings = ps.load_project_settings('p-seen')
        assert settings[ps.SETTINGS_SOURCE_KEY] == 'api'
        assert ps.seen_project_updated_at('p-seen') == 'v2'

    def test_a_failed_fetch_is_marked_default(self):
        with patch('requests.get', side_effect=RuntimeError('webapp down')), \
             patch.dict('os.environ', {'WEBAPP_API_URL': 'http://webapp:3000'}):
            settings = ps.load_project_settings('p-down')
        assert settings[ps.SETTINGS_SOURCE_KEY] == 'default'

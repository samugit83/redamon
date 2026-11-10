"""
Org-level work (plan §4.9, release D): the work keyed on a registrable domain
runs once per run, for the first eligible group of that org, and lands on the
org; a refused group never triggers it.
"""
import json
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import recon.main as main  # noqa: E402
from recon.helpers import circuit_breaker, org_work, security_checks as sc  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    main._RUN_ORGS.clear()
    yield
    circuit_breaker.reset_registry()
    main._RUN_ORGS.clear()


def _group(root, org=None, mode='enumerate', include_root=False, exact=()):
    return {'scanRoot': root, 'orgDomain': org or root, 'mode': mode,
            'includeRoot': include_root, 'exactHosts': list(exact)}


class TestOncePerOrg:
    def test_whois_runs_once_per_org_and_each_group_gets_a_copy(self, monkeypatch):
        calls = []
        monkeypatch.setattr(main, 'whois_lookup', lambda d, **k: calls.append(d) or {
            'whois_data': {'registrar': 'R', 'domain': d}})
        a = main._org_whois('example.com')
        b = main._org_whois('example.com')
        main._org_whois('other.test')
        assert calls == ['example.com', 'other.test']
        assert a == b and a is not b

    def test_a_failed_whois_is_asked_again(self, monkeypatch):
        calls = []
        monkeypatch.setattr(main, 'whois_lookup', lambda d, **k: calls.append(d) or {'whois_data': {}})
        main._org_whois('example.com')
        main._org_whois('example.com')
        assert calls == ['example.com', 'example.com']

    def test_the_org_of_a_group_file(self):
        assert org_work.org_of({'domain': 'api.example.com',
                                'metadata': {'org_domain': 'Example.com'}}) == 'example.com'
        # A file written before scope groups keeps its own domain.
        assert org_work.org_of({'domain': 'api.example.com', 'metadata': {}}) == 'api.example.com'

    def test_virustotal_asks_the_org_once(self, monkeypatch):
        from recon.main_recon_modules import virustotal_enrich as vt
        asked = []

        def fake_call(path, keys, admitted=False):
            asked.append(path)
            return mock.Mock(ok=False, data=None)
        monkeypatch.setattr(vt, '_vt_call', fake_call)
        monkeypatch.setattr(vt, '_parse_domain_attrs', lambda data: {
            k: None for k in ('reputation', 'analysis_stats', 'categories', 'registrar', 'total_votes',
                              'tags', 'last_analysis_date', 'jarm', 'popularity_alexa',
                              'popularity_umbrella', 'last_dns_records_date',
                              'last_https_certificate_date')})
        monkeypatch.setattr(vt.time, 'sleep', lambda s: None)
        settings = {'VIRUSTOTAL_ENABLED': True, 'VIRUSTOTAL_API_KEY': 'k', 'VIRUSTOTAL_MAX_TARGETS': 0}
        for root in ('api.example.com', 'www.example.com'):
            recon = {'domain': root, 'metadata': {'org_domain': 'example.com'}, 'dns': {}}
            out = vt.run_virustotal_enrichment(recon, settings)
            assert out['virustotal']['domain_report']['domain'] == 'example.com'
        assert asked == ['domains/example.com']


class TestDnsChecksOnTheOrg:
    def test_the_check_names_the_org_of_the_group(self):
        recon = {'domain': 'api.example.com', 'metadata': {'org_domain': 'example.com'}}
        assert sc._dns_check_domains(recon) == ['example.com']

    def test_a_partial_run_maps_each_root_to_its_org(self):
        recon = {'domain': 'api.example.com', 'domains': ['api.example.com', 'www.example.com', 'b.test'],
                 'scope_groups': [{'scan_root': 'api.example.com', 'org_domain': 'example.com'},
                                  {'scan_root': 'www.example.com', 'org_domain': 'example.com'},
                                  {'scan_root': 'b.test', 'org_domain': 'b.test'}]}
        assert sc._dns_check_domains(recon) == ['example.com', 'b.test']

    def test_the_first_group_of_an_org_checks_it_later_ones_do_not(self):
        assert sc._dns_check_claims(['example.com'], None) == ['example.com']
        assert sc._dns_check_claims(['example.com', 'b.test'], None) == ['b.test']

    def test_an_roe_excluded_org_is_never_checked(self):
        assert sc._dns_check_claims(['example.com'], ['example.com']) == []
        assert org_work.claimed_orgs('dns_checks') == []

    def test_an_org_no_group_checked_keeps_only_its_dns_findings(self, monkeypatch):
        """Not the whole security_check source (R-37): the enabled DNS types
        are recorded on no host, so only the orgs that ran prune them, and
        every header, TLS or port finding prunes as usual."""
        monkeypatch.setattr(main, 'SCAN_MODULES', ['domain_discovery', 'vuln_scan'])
        monkeypatch.setattr(main, '_settings', {'SECURITY_CHECK_ZONE_TRANSFER': False})
        main._note_run_org('example.com')
        main._note_run_org('b.test')
        sc._dns_check_claims(['b.test'], None)
        main._note_unchecked_dns_orgs()
        report = circuit_breaker.coverage_report()
        assert report.degraded_sources == frozenset()
        assert report.checked_types('security_check') == (
            'dmarc_missing', 'dnssec_missing', 'spf_missing')
        assert {report.checked_hostnames('security_check', t)
                for t in report.checked_types('security_check')} == {()}

    @pytest.mark.parametrize('modules, settings', [
        (['domain_discovery'], {}),
        (['domain_discovery', 'vuln_scan'], {'SECURITY_CHECK_ENABLED': False}),
        (['domain_discovery', 'vuln_scan'], {f'SECURITY_CHECK_{t.upper()}': False
                                             for t in sc.DNS_CHECK_TYPES}),
    ])
    def test_dns_checks_switched_off_record_nothing(self, monkeypatch, modules, settings):
        """Switched off is pruned normally (README "Degraded vs. switched off")."""
        monkeypatch.setattr(main, 'SCAN_MODULES', modules)
        monkeypatch.setattr(main, '_settings', settings)
        main._note_run_org('example.com')
        main._note_unchecked_dns_orgs()
        report = circuit_breaker.coverage_report()
        assert report.degraded_sources == frozenset()
        assert report.positive_sources == frozenset()

    def test_every_org_checked_records_nothing_more(self, monkeypatch):
        monkeypatch.setattr(main, 'SCAN_MODULES', ['vuln_scan'])
        monkeypatch.setattr(main, '_settings', {})
        main._note_run_org('example.com')
        sc._dns_check_claims(['example.com'], None)
        main._note_unchecked_dns_orgs()
        assert circuit_breaker.coverage_report().positive_sources == frozenset()

    def test_a_refused_group_never_triggers_org_work(self, monkeypatch):
        monkeypatch.setattr(main, '_settings', {'ROE_ENABLED': True, 'ROE_EXCLUDED_HOSTS': ['api.example.com']})
        assert main.run_domain_group(_group('api.example.com', 'example.com')) == 1
        assert main._RUN_ORGS == []


class TestCoverageOnTheOrg:
    def test_the_record_names_the_org_the_root_and_the_run(self, monkeypatch):
        client = mock.MagicMock()
        client.__enter__.return_value = client
        client.verify_connection.return_value = True
        client.update_graph_coverage.return_value = 1
        monkeypatch.setitem(sys.modules, 'graph_db', mock.MagicMock(Neo4jClient=mock.MagicMock(return_value=client)))
        monkeypatch.setattr(main, 'UPDATE_GRAPH_DB', True)
        monkeypatch.setattr(main, '_RUN_STARTED_AT', '2026-10-22T10:00:00')
        monkeypatch.setattr(main, '_settings', {'SCOPE_GROUPS': [_group('api.example.com', 'example.com')]})
        report = mock.Mock(gaps_json=lambda: json.dumps([{'module': 'naabu'}]),
                           stored_skipped_hosts=lambda: [], nuclei_truncated=False)
        group = mock.Mock(report=lambda: report)
        assert main._write_coverage_record('api.example.com', group) is True
        args, kwargs = client.update_graph_coverage.call_args
        assert args[2] == 'api.example.com'
        record = args[3]
        assert record['org_domain'] == 'example.com'
        assert json.loads(record['gaps_json']) == [{'module': 'naabu', 'root': 'api.example.com'}]
        assert kwargs == {'run_started_at': '2026-10-22T10:00:00'}

    def test_ip_mode_stamps_the_mock_root(self, monkeypatch):
        monkeypatch.setattr(main, '_settings', {'IP_MODE': True})
        assert main._org_for_root('ip-targets.p1') == 'ip-targets.p1'


class TestOriginCandidateKey:
    def _rule(self, root, org, groups):
        from recon.main_recon_modules import origin_discovery as od
        return od._candidate_key_rule({'domain': root, 'scope_groups': groups,
                                       'metadata': {'root_domain': root, 'org_domain': org}})

    def test_the_org_when_a_group_has_it_as_its_scan_root(self):
        groups = [{'scan_root': 'api.example.com'}, {'scan_root': 'example.com'}]
        assert self._rule('api.example.com', 'example.com', groups)('x.api.example.com') == 'example.com'

    def test_the_scan_root_when_the_org_is_not_in_scope(self, capsys):
        key = self._rule('api.example.com', 'example.com', [{'scan_root': 'api.example.com'}])
        assert key('x.api.example.com') == 'api.example.com'
        assert key('192.0.2.1') is None
        assert 'candidate key: api.example.com (org not in scope)' in capsys.readouterr().out

    def test_ownership_proven_at_the_org_puts_it_in_scope(self):
        org_work.note_ownership_proven('example.com')
        key = self._rule('api.example.com', 'example.com', [{'scan_root': 'api.example.com'}])
        assert key('x.api.example.com') == 'example.com'

    def test_a_legacy_file_keeps_the_registrable_domain(self):
        from recon.main_recon_modules import origin_discovery as od
        rule = od._candidate_key_rule({'domain': 'api.example.com', 'metadata': {}})
        assert rule('x.api.example.com') == 'example.com'

    def test_one_context_per_run(self):
        from recon.main_recon_modules import origin_discovery as od
        assert od._run_ctx({}) is od._run_ctx({})


class TestUncoverOrgResults:
    def test_a_deeper_enumerate_group_adds_no_expanded_ips(self, monkeypatch):
        from recon.main_recon_modules import uncover_enrich as ue
        monkeypatch.setattr('recon.helpers.target_helpers._resolves_to_routable', lambda h: True)
        recon = {'domain': 'api.example.com', 'dns': {'domain': {}, 'subdomains': {}},
                 'metadata': {'root_domain': 'api.example.com', 'org_domain': 'example.com',
                              'scope_mode': 'enumerate', 'include_root_domain': False}}
        ue.merge_uncover_into_pipeline(recon, {'hosts': [], 'ips': ['192.0.2.9'], 'ip_ports': {}},
                                       'api.example.com', {})
        assert recon['metadata'].get('expanded_ips') in (None, [])

    def test_the_org_group_adds_them(self):
        from recon.main_recon_modules import uncover_enrich as ue
        recon = {'domain': 'example.com', 'dns': {'domain': {}, 'subdomains': {}},
                 'metadata': {'root_domain': 'example.com', 'org_domain': 'example.com',
                              'scope_mode': 'enumerate', 'include_root_domain': False}}
        ue.merge_uncover_into_pipeline(recon, {'hosts': [], 'ips': ['192.0.2.9'], 'ip_ports': {}},
                                       'example.com', {})
        assert recon['metadata']['expanded_ips'] == ['192.0.2.9']

    def test_only_the_org_group_asks_the_registrant_query(self):
        from recon.main_recon_modules import uncover_enrich as ue
        deeper = {'metadata': {'root_domain': 'api.example.com', 'org_domain': 'example.com',
                               'scope_mode': 'enumerate'}, 'domain': 'api.example.com'}
        own = {'metadata': {'root_domain': 'example.com', 'org_domain': 'example.com',
                            'scope_mode': 'enumerate'}, 'domain': 'example.com'}
        assert not ue._owns_its_org(deeper) and ue._owns_its_org(own)


class TestCrtNameOnTheOrg:
    def test_the_org_is_asked_once_and_each_root_keeps_its_names(self, monkeypatch):
        from recon.main_recon_modules import domain_recon as dr
        asked = []
        monkeypatch.setattr(dr, '_crtname_fetch', lambda d: asked.append(d) or (
            ['a.api.example.com', 'www.example.com', 'api.example.com'], False))
        monkeypatch.setattr(dr, '_source_skipped', lambda *a: False)
        api = dr._query_crtname('api.example.com', {})
        www = dr._query_crtname('www.example.com', {})
        assert asked == ['example.com']
        assert sorted(api) == ['a.api.example.com', 'api.example.com']
        assert list(www) == ['www.example.com']


class TestShodanDomainDns:
    def test_the_answer_names_the_domain_asked(self, monkeypatch):
        from recon.main_recon_modules import shodan_enrich as se
        monkeypatch.setattr(se, '_shodan_get', lambda path, key, key_rotator=None: {
            'subdomains': ['mail'], 'data': [{'subdomain': 'mail', 'type': 'A', 'value': '192.0.2.1'}]})
        out = se._run_domain_dns('example.com', 'k')
        assert out['domain'] == 'example.com'
        assert out['records'][0]['subdomain'] == 'mail'

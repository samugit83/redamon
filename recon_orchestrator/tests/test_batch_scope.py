"""
Domain batch: the guardrail target list used by POST /recon/{id}/start.

This decides what the hard guardrail actually checks before a scan container is
spawned. The guardrail is the one control an operator cannot switch off, and a
Domain-batch project has an EMPTY targetDomain, so a check written against
targetDomain alone would wave every batch target through. These cases guard that.

The module is standalone (not in api.py) precisely so this runs in the unit tier
without FastAPI or the Docker client.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from batch_scope import batch_guardrail_targets, guardrail_targets  # noqa: E402


class TestGuardrailTargetsByMode:
    def test_single_domain_project_returns_its_target(self):
        assert guardrail_targets({'targetDomain': 'example.com'}) == ['example.com']

    def test_ip_mode_has_no_domain_targets(self):
        # IPs are not hard-blocked; is_hard_blocked() documents that contract.
        assert guardrail_targets({'ipMode': True, 'targetIps': ['10.0.0.1']}) == []

    def test_batch_mode_returns_group_roots_although_target_domain_is_empty(self):
        project = {
            'targetDomain': '',
            'domainBatchMode': True,
            'domainBatchGroups': [
                {'rootDomain': 'domain1.com', 'prefixes': ['sub1.']},
                {'rootDomain': 'domain2.it', 'prefixes': ['sub2.']},
            ],
        }
        assert guardrail_targets(project) == ['domain1.com', 'domain2.it']

    def test_batch_mode_ignores_a_stale_target_domain(self):
        # A project switched into batch mode keeps no single target; if a stale
        # value lingered, scanning it would be out of scope.
        project = {
            'targetDomain': 'stale.example.com',
            'domainBatchMode': True,
            'domainBatchGroups': [{'rootDomain': 'real.com', 'prefixes': ['.']}],
        }
        assert guardrail_targets(project) == ['real.com']

    def test_a_blocked_domain_buried_mid_list_is_still_returned(self):
        project = {
            'domainBatchMode': True,
            'domainBatchGroups': [
                {'rootDomain': 'ok.com', 'prefixes': ['.']},
                {'rootDomain': 'whitehouse.gov', 'prefixes': ['.']},
                {'rootDomain': 'also-ok.com', 'prefixes': ['.']},
            ],
        }
        assert 'whitehouse.gov' in guardrail_targets(project)


class TestBatchTargetsFailClosed:
    """An empty list in batch mode means "scope unknown". The caller turns that
    into a 400; it must never read as "nothing to guard"."""

    def test_missing_groups_yield_nothing_to_check(self):
        assert batch_guardrail_targets({}) == []
        assert guardrail_targets({'domainBatchMode': True}) == []

    def test_a_non_list_groups_value_yields_nothing(self):
        for groups in (None, {}, 'example.com', 7):
            assert batch_guardrail_targets({'domainBatchGroups': groups}) == []

    def test_drops_a_root_outside_the_hostname_charset(self):
        for root in ('../../etc', 'evil.com/x', 'evil.com;whoami', 'ev il.com',
                     "evil.com'})--", 'a..b'):
            got = batch_guardrail_targets({'domainBatchGroups': [{'rootDomain': root}]})
            assert got == [], f'accepted {root!r}'

    def test_drops_a_non_dict_entry(self):
        assert batch_guardrail_targets({'domainBatchGroups': ['example.com']}) == []

    def test_one_bad_root_does_not_hide_the_others_from_the_guardrail(self):
        project = {'domainBatchGroups': [
            {'rootDomain': '../bad'},
            {'rootDomain': 'whitehouse.gov'},
        ]}
        assert batch_guardrail_targets(project) == ['whitehouse.gov']

    def test_normalizes_case_so_the_guardrail_match_is_stable(self):
        got = batch_guardrail_targets({'domainBatchGroups': [{'rootDomain': ' WhiteHouse.GOV '}]})
        assert got == ['whitehouse.gov']

    def test_deduplicates(self):
        project = {'domainBatchGroups': [
            {'rootDomain': 'dup.com'}, {'rootDomain': 'dup.com'},
        ]}
        assert batch_guardrail_targets(project) == ['dup.com']


class TestGuardrailNamesIncludeEveryHost:
    """The hard guardrail checks every listed host, not only the group roots: a
    host under a multi-label government name groups under a root no rule names."""

    def test_batch_hosts_come_first_then_the_roots(self):
        project = {'domainBatchMode': True, 'domainBatchGroups': [
            {'rootDomain': 'example.com', 'prefixes': ['*', 'www.'], 'hosts': ['*.example.com', 'www.example.com']},
            {'rootDomain': 'org.jm', 'prefixes': ['www.isa.'], 'hosts': ['www.isa.org.jm']},
        ]}
        assert guardrail_targets(project) == ['example.com', 'www.example.com', 'www.isa.org.jm', 'org.jm']

    def test_a_host_with_an_embedded_star_or_bad_charset_is_dropped(self):
        project = {'domainBatchMode': True, 'domainBatchGroups': [
            {'rootDomain': 'example.com', 'prefixes': ['.'], 'hosts': ['a*b.example.com', 'bad host', 'example.com']},
        ]}
        assert guardrail_targets(project) == ['example.com']

    def test_single_domain_adds_its_prefix_hosts(self):
        project = {'targetDomain': 'org.jm', 'subdomainList': ['isa.', '.', '*']}
        assert guardrail_targets(project) == ['org.jm', 'isa.org.jm']

    def test_the_first_blocked_name_is_the_listed_host(self):
        from hard_guardrail import first_hard_blocked
        project = {'domainBatchMode': True, 'domainBatchGroups': [
            {'rootDomain': 'gov.uk', 'prefixes': ['www.agency.'], 'hosts': ['www.agency.gov.uk']},
        ]}
        assert first_hard_blocked(guardrail_targets(project))[0] == 'www.agency.gov.uk'


class TestScopeGroupsFromTheWebapp:
    """The webapp's derived `scopeGroups` is the scope; it is re-validated here
    because it crosses a trust boundary, and dropped (never repaired) when bad."""

    GOOD = {'scanRoot': 'api.example.com', 'orgDomain': 'example.com', 'mode': 'enumerate',
            'includeRoot': True, 'exactHosts': ['v1.api.example.com'], 'entries': ['*.api.example.com']}

    def test_a_valid_group_is_kept(self):
        from batch_scope import scope_groups
        assert scope_groups({'domainBatchMode': True, 'scopeGroups': [self.GOOD]})[0]['scanRoot'] == 'api.example.com'

    def test_malformed_groups_are_dropped(self):
        from batch_scope import scope_groups
        bad = [
            {**self.GOOD, 'mode': 'everything'},
            {**self.GOOD, 'scanRoot': 'api.example.com;rm'},
            {**self.GOOD, 'orgDomain': 'other.com'},                    # root not under its org
            {**self.GOOD, 'exactHosts': ['v1.elsewhere.com']},          # host outside the root
            {**self.GOOD, 'exactHosts': ['*.api.example.com']},
            {**self.GOOD, 'mode': 'exact', 'scanRoot': 'example.com', 'exactHosts': [], 'includeRoot': False},
            'not a dict',
        ]
        assert scope_groups({'domainBatchMode': True, 'scopeGroups': bad}) == []

    def test_an_absent_field_falls_back_to_the_legacy_record(self):
        from batch_scope import scope_groups
        groups = scope_groups({'domainBatchMode': True, 'domainBatchGroups': [
            {'rootDomain': 'example.com', 'prefixes': ['*', '.', 'v1.']}]})
        assert groups == [{'scanRoot': 'example.com', 'orgDomain': 'example.com', 'mode': 'enumerate',
                           'includeRoot': True, 'exactHosts': ['v1.example.com'], 'entries': []}]

    def test_guardrail_names_are_the_union_of_both_sources(self):
        project = {'targetDomain': 'org.jm', 'subdomainList': ['isa.'], 'scopeGroups': []}
        # The webapp refused org.jm (a public suffix): its prefix host is still named.
        assert guardrail_targets(project) == ['org.jm', 'isa.org.jm']


class TestPartialUserInput:
    PROJECT = {'domainBatchMode': True, 'scopeGroups': [
        {'scanRoot': 'api.example.com', 'orgDomain': 'example.com', 'mode': 'enumerate',
         'includeRoot': False, 'exactHosts': [], 'entries': ['*.api.example.com']},
        {'scanRoot': 'example.com', 'orgDomain': 'example.com', 'mode': 'exact',
         'includeRoot': False, 'exactHosts': ['www.example.com'], 'entries': ['www.example.com']},
    ]}

    def _filter(self, roots, inputs=None, targets=None, project=None):
        from batch_scope import filter_partial_user_input
        return filter_partial_user_input(project or self.PROJECT, roots, inputs or [], targets)

    def test_the_partial_rule_per_group(self):
        from batch_scope import admits_partial_host, scope_groups
        groups = scope_groups(self.PROJECT)
        assert admits_partial_host(groups, 'x.v1.api.example.com')
        assert not admits_partial_host(groups, 'api.example.com')      # root off
        assert admits_partial_host(groups, 'www.example.com')
        assert not admits_partial_host(groups, 'mail.example.com')     # not in the exact list

    def test_an_out_of_scope_url_host_is_dropped(self):
        _, targets, refused = self._filter(['example.com', 'api.example.com'], targets={
            'urls': ['https://www.example.com/a', 'https://cdn.example.com/x']})
        assert targets['urls'] == ['https://www.example.com/a']
        assert refused == ["url 'https://cdn.example.com/x'"]

    def test_a_host_outside_the_runs_roots_is_dropped(self):
        inputs, _, refused = self._filter(['example.com'], inputs=['v2.api.example.com'])
        assert inputs == [] and refused

    def test_a_government_host_is_refused_even_inside_a_wildcard_scope(self):
        project = {'domainBatchMode': True, 'scopeGroups': [
            {'scanRoot': 'example.gov', 'orgDomain': 'example.gov', 'mode': 'enumerate',
             'includeRoot': False, 'exactHosts': [], 'entries': []}]}
        inputs, _, _ = self._filter(['example.gov'], inputs=['www.example.gov'], project=project)
        assert inputs == []

    def test_cidr_limits_match_the_modal(self):
        _, targets, refused = self._filter(['example.com'], targets={
            'ips': ['192.0.2.10', '192.0.2.0/24', '0.0.0.0/0', '10.0.0.0/8', '2001:db8::/120', '2001:db8::/64', 'x']})
        assert targets['ips'] == ['192.0.2.10', '192.0.2.0/24', '2001:db8::/120']
        assert len(refused) == 4

    def test_ip_mode_url_hosts_must_be_the_projects_addresses(self):
        project = {'ipMode': True, 'targetIps': ['192.0.2.10']}
        _, targets, _ = self._filter(['ip-targets.p1'], project=project, targets={
            'urls': ['http://192.0.2.10:8080/', 'http://192.0.2.99/']})
        assert targets['urls'] == ['http://192.0.2.10:8080/']

    def test_url_attach_to_is_a_base_url_judged_by_its_host(self):
        _, targets, refused = self._filter(['example.com'], targets={
            'urls': ['https://www.example.com/a'], 'url_attach_to': 'https://www.example.com'})
        assert targets['url_attach_to'] == 'https://www.example.com' and not refused
        _, targets, refused = self._filter(['example.com'], targets={
            'urls': [], 'url_attach_to': 'https://evil.test'})
        assert targets['url_attach_to'] is None and refused == ["url_attach_to 'https://evil.test'"]

    def test_ip_attach_to_names_a_subdomain_in_scope(self):
        _, targets, _ = self._filter(['example.com'], targets={'ips': ['192.0.2.1'], 'ip_attach_to': 'www.example.com'})
        assert targets['ip_attach_to'] == 'www.example.com'
        _, targets, _ = self._filter(['example.com'], targets={'ips': ['192.0.2.1'], 'ip_attach_to': 'mail.example.com'})
        assert targets['ip_attach_to'] is None

    def test_ip_mode_attaches_typed_ips_to_a_targets_own_label_only(self):
        # B-20: the attach is written as a source-less RESOLVES_TO that later
        # partial runs read as forward DNS, so a name may never take one.
        project = {'ipMode': True, 'targetIps': ['192.0.2.8/30']}
        _, targets, refused = self._filter(['ip-targets.p1'], project=project, targets={
            'ips': ['192.0.2.10'], 'ip_attach_to': '192-0-2-9'})
        assert targets['ip_attach_to'] == '192-0-2-9' and not refused
        for name in ('192-0-2-10.ip-targets.p1', 'www.example.com', '198-51-100-7', '192-0-2-8'):
            _, targets, refused = self._filter(['ip-targets.p1'], project=project, targets={
                'ips': ['192.0.2.10'], 'ip_attach_to': name})
            assert targets['ip_attach_to'] is None, name
            assert refused == [f"ip_attach_to {name!r} (not a target's own label)"]


class TestIpModeTypedHostnames:
    """A name typed for an IP-mode partial run, per hostname mode.

    ip_only / record_only refuse every typed name; record_filter takes one its
    include entries admit and no exclude entry names; scan_all any name; the
    hard guardrail refuses a blocked one in every mode. Only the pattern half
    runs here: the container keeps a name only when every address it resolves
    to is a target. The job queue and the scheduler start partial runs
    through webapp/src/lib/startScan.ts without the modal, so the last case
    sends that body's shape.
    """
    IP = {'ipMode': True, 'targetIps': ['192.0.2.10', '192.0.2.11'],
          'ipHostnameInclude': ['*.example.com'], 'ipHostnameExclude': ['old.example.com']}

    def _filter(self, mode, inputs=None, targets=None, **project):
        from batch_scope import filter_partial_user_input
        row = {**self.IP, 'ipHostnameMode': mode, **project}
        return filter_partial_user_input(row, ['ip-targets.p1'], inputs or [], targets)

    def test_the_recording_modes_refuse_every_typed_name(self):
        for mode in ('ip_only', 'record_only', None, 'bogus'):
            inputs, targets, refused = self._filter(mode, ['app.example.com'], {
                'subdomains': ['app.example.com'], 'urls': ['https://app.example.com/', 'http://192.0.2.10/']})
            assert inputs == [] and targets['subdomains'] == [], mode
            assert targets['urls'] == ['http://192.0.2.10/'], mode
            assert len(refused) == 3 and all('no typed hostname is scanned' in r for r in refused), mode

    def test_record_filter_matches_the_include_and_exclude_entries(self):
        inputs, targets, refused = self._filter('record_filter', ['App.Example.com.'], {
            'subdomains': ['api.example.com', 'old.example.com', 'shop.example.net'],
            'urls': ['https://api.example.com/x', 'https://shop.example.net/']})
        assert inputs == ['app.example.com']
        assert targets['subdomains'] == ['api.example.com']
        assert targets['urls'] == ['https://api.example.com/x']
        assert sorted(refused) == sorted([
            "subdomain 'old.example.com' (matches an exclude entry of the hostname filter: old.example.com)",
            "subdomain 'shop.example.net' (matches no include entry of the hostname filter)",
            "url 'https://shop.example.net/' (matches no include entry of the hostname filter)",
        ])

    def test_record_filter_with_an_unreadable_filter_admits_no_name(self):
        for bad in ({'ipHostnameInclude': None}, {'ipHostnameExclude': 'x'}, {'ipHostnameInclude': ['*.*']}):
            _, targets, refused = self._filter('record_filter', targets={'subdomains': ['app.example.com']}, **bad)
            assert targets['subdomains'] == [], bad
            assert refused == ["subdomain 'app.example.com' (the hostname filter cannot be read)"], bad

    def test_scan_all_takes_any_name(self):
        _, targets, refused = self._filter('scan_all', targets={'subdomains': ['shop.example.net', 'not a name']})
        assert targets['subdomains'] == ['shop.example.net']
        assert refused == ["subdomain 'not a name' (not a hostname)"]

    def test_the_hard_guardrail_refuses_a_blocked_name_in_every_selecting_mode(self):
        for mode, name in (('scan_all', 'www.example.gov'), ('record_filter', 'portal.example.com')):
            extra = {'ipHostnameInclude': ['*.example.com', 'portal.example.com']} if mode == 'record_filter' else {}
            from unittest import mock
            with mock.patch('hard_guardrail.is_hard_blocked',
                            side_effect=lambda n: (n in ('www.example.gov', 'portal.example.com'), f'{n} blocked')):
                _, targets, refused = self._filter(mode, targets={'subdomains': [name]}, **extra)
            assert targets['subdomains'] == [], mode
            assert refused == [f"subdomain {name!r} (hard guardrail: {name} blocked)"], mode
        # The real guardrail, unpatched, blocks a government name.
        _, targets, refused = self._filter('scan_all', targets={'urls': ['https://www.example.gov/']})
        assert targets['urls'] == [] and 'hard guardrail' in refused[0]

    def test_the_roe_refuses_a_typed_name_it_excludes_without_resolving_it(self):
        from unittest import mock
        with mock.patch('socket.getaddrinfo', side_effect=AssertionError('resolved')):
            _, targets, refused = self._filter('record_filter', targets={'subdomains': ['app.example.com']},
                                               roeEnabled=True, roeExcludedHosts=['app.example.com', '192.0.2.0/24'])
        assert targets['subdomains'] == []
        assert refused == ["subdomain 'app.example.com' (excluded by the Rules of Engagement)"]

    def test_a_typed_address_and_the_label_attach_are_unchanged(self):
        _, targets, refused = self._filter('scan_all', targets={
            'ips': ['192.0.2.10', '192.0.2.99'], 'ip_attach_to': 'app.example.com'})
        assert targets['ips'] == ['192.0.2.10'] and targets['ip_attach_to'] is None
        assert len(refused) == 2

    def test_a_start_scan_shaped_request_gets_the_same_refusals_as_the_modal(self):
        # The body webapp/src/lib/startScan.ts posts for a queued or scheduled
        # partial run: user_inputs as a list, user_targets with every key the
        # modal can fill, and nothing the modal checked first.
        body = {
            'tool_id': 'Httpx', 'graph_inputs': {}, 'include_graph_targets': True, 'settings_overrides': {},
            'user_inputs': ['shop.example.net', 'app.example.com'],
            'user_targets': {'subdomains': ['old.example.com', 'api.example.com', 'www.example.gov'],
                             'ips': ['192.0.2.11', '198.51.100.7'], 'ports': [443, 70000],
                             'urls': ['https://api.example.com/', 'https://shop.example.net/'],
                             'ip_attach_to': 'api.example.com', 'url_attach_to': None},
        }
        for mode, kept_inputs, kept_subs in (
                ('record_only', [], []),
                ('record_filter', ['app.example.com'], ['api.example.com']),
                ('scan_all', ['shop.example.net', 'app.example.com'], ['old.example.com', 'api.example.com'])):
            inputs, targets, refused = self._filter(mode, body['user_inputs'], body['user_targets'])
            assert inputs == kept_inputs, mode
            assert targets['subdomains'] == kept_subs, mode
            assert targets['ips'] == ['192.0.2.11'] and targets['ports'] == [443], mode
            assert targets['ip_attach_to'] is None, mode
            assert any("'www.example.gov'" in r for r in refused), mode
            assert not any('192.0.2.11' in r for r in refused), mode

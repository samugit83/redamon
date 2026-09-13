"""Unit tests for recon/helpers/auth_profile.py: header modes, sanitizing, scope."""

import base64
from unittest import mock

from recon.helpers.auth_profile import (
    MAX_HEADER_VALUE_LEN,
    auth_header_lines,
    build_auth_headers,
    default_scope_hosts,
    host_in_scope,
    mask_auth_value,
    merge_auth_headers,
    profile_from_settings,
    resolve_scope_hosts,
)

SETTINGS = {'TARGET_DOMAIN': 'example.test', 'SUBDOMAIN_LIST': ['app.', '.'], 'IP_MODE': False}


def _profile(**kw):
    base = {'authType': 'cookie', 'authValue': 'sid=abc123', 'authHeaderName': '', 'extraHeaders': {}}
    base.update(kw)
    return base


class TestModes:
    def test_bearer(self):
        assert build_auth_headers(_profile(authType='bearer', authValue='tok')) == {'Authorization': 'Bearer tok'}

    def test_bearer_scheme_not_doubled_for_recorded_header(self):
        h = build_auth_headers(_profile(authType='bearer', authValue='Bearer tok'))
        assert h == {'Authorization': 'Bearer tok'}

    def test_cookie(self):
        assert build_auth_headers(_profile()) == {'Cookie': 'sid=abc123'}

    def test_header_uses_given_name(self):
        h = build_auth_headers(_profile(authType='header', authValue='v', authHeaderName='X-Session'))
        assert h == {'X-Session': 'v'}

    def test_header_and_apikey_default_names(self):
        assert build_auth_headers(_profile(authType='header', authValue='v')) == {'X-Auth-Token': 'v'}
        assert build_auth_headers(_profile(authType='apikey', authValue='v')) == {'X-API-Key': 'v'}

    def test_basic(self):
        h = build_auth_headers(_profile(authType='basic', authValue='user:pw'))
        assert h == {'Authorization': 'Basic ' + base64.b64encode(b'user:pw').decode()}

    def test_basic_without_colon_is_dropped(self):
        assert build_auth_headers(_profile(authType='basic', authValue='nocolon')) == {}

    def test_none_unknown_and_empty(self):
        assert build_auth_headers(_profile(authType='none')) == {}
        assert build_auth_headers(_profile(authType='kerberos')) == {}
        assert build_auth_headers(_profile(authValue='')) == {}
        assert build_auth_headers(None) == {}

    def test_type_is_case_insensitive(self):
        assert build_auth_headers(_profile(authType='COOKIE')) == {'Cookie': 'sid=abc123'}

    def test_extra_headers_added_but_never_override_primary(self):
        h = build_auth_headers(_profile(extraHeaders={'X-CSRF-Token': 'c1', 'cookie': 'evil=1'}))
        assert h == {'Cookie': 'sid=abc123', 'X-CSRF-Token': 'c1'}

    def test_extras_only_profile(self):
        h = build_auth_headers(_profile(authType='none', authValue='', extraHeaders={'X-Tenant': 't1'}))
        assert h == {'X-Tenant': 't1'}


class TestSanitizing:
    def test_crlf_in_value_rejects_the_header(self):
        assert build_auth_headers(_profile(authValue='sid=a\r\nX-Injected: 1')) == {}

    def test_bare_lf_rejected_so_arjun_join_cannot_split(self):
        assert build_auth_headers(_profile(authValue='sid=a\nX-Redamon-Ctx: forged')) == {}

    def test_hakrawler_join_delimiter_rejected(self):
        assert build_auth_headers(_profile(authValue='sid=a;;X-Redamon-Ctx: forged')) == {}

    def test_nul_rejected_tab_allowed(self):
        assert build_auth_headers(_profile(authValue='sid=a\x00b')) == {}
        assert build_auth_headers(_profile(authValue='sid=a\tb')) == {'Cookie': 'sid=a\tb'}

    def test_overlong_value_rejected(self):
        assert build_auth_headers(_profile(authValue='a' * (MAX_HEADER_VALUE_LEN + 1))) == {}
        assert build_auth_headers(_profile(authValue='a' * MAX_HEADER_VALUE_LEN)) != {}

    def test_invalid_header_name_refused_not_renamed(self):
        for bad in ('X Bad', 'X-A\r\nX-B', 'X:Y'):
            assert build_auth_headers(_profile(authType='header', authValue='v', authHeaderName=bad)) == {}

    def test_internal_ctx_header_cannot_be_spoofed(self):
        assert build_auth_headers(_profile(authType='header', authValue='v', authHeaderName='x-redamon-ctx')) == {}
        h = build_auth_headers(_profile(extraHeaders={'X-Redamon-Ctx': 'forged'}))
        assert h == {'Cookie': 'sid=abc123'}

    def test_bad_extra_dropped_good_extra_kept(self):
        h = build_auth_headers(_profile(extraHeaders={'X-Ok': 'fine', 'X-Bad': 'a\r\nb', 'Bad Name': 'v'}))
        assert h == {'Cookie': 'sid=abc123', 'X-Ok': 'fine'}

    def test_no_line_ever_carries_a_delimiter(self):
        nasty = _profile(authValue='a;;b', extraHeaders={'X-A': 'x\ny', 'X-B': 'ok'})
        for line in auth_header_lines(nasty, 'example.test', SETTINGS):
            assert ';;' not in line and '\n' not in line and '\r' not in line


class TestScope:
    def test_default_scope_is_root_plus_wildcard_plus_prefixes(self):
        assert default_scope_hosts(SETTINGS) == ['example.test', '*.example.test', 'app.example.test']

    def test_default_scope_covers_discovered_subdomains(self):
        # The whole point of the feature: recon discovers subdomains that are NOT
        # in SUBDOMAIN_LIST (the default is full discovery, an EMPTY list). An
        # apex-only default scope made merge_auth_headers refuse on the first
        # discovered host, so every authenticated scan silently ran logged-out.
        scope = default_scope_hosts({'TARGET_DOMAIN': 'example.test', 'SUBDOMAIN_LIST': []})
        assert host_in_scope('cdn.example.test', scope)
        assert host_in_scope('deep.nested.example.test', scope)
        assert host_in_scope('example.test', scope)

    def test_default_scope_still_excludes_foreign_hosts(self):
        scope = default_scope_hosts(SETTINGS)
        assert not host_in_scope('third-party.test', scope)
        assert not host_in_scope('notexample.test', scope)
        # A look-alike that merely ends with the root string is not a subdomain.
        assert not host_in_scope('evilexample.test', scope)

    def test_domain_batch_roots_are_in_scope(self):
        # A batch project leaves TARGET_DOMAIN empty; without the group roots it
        # would have no scope at all and never attach auth.
        scope = default_scope_hosts({
            'TARGET_DOMAIN': '',
            'DOMAIN_BATCH_GROUPS': [{'rootDomain': 'a.test'}, {'rootDomain': 'b.test'}],
        })
        assert host_in_scope('app.a.test', scope)
        assert host_in_scope('b.test', scope)
        assert not host_in_scope('c.test', scope)

    def test_default_scope_ip_mode(self):
        s = {'IP_MODE': True, 'TARGET_IPS': ['10.0.0.5', '10.1.0.0/24'], 'TARGET_DOMAIN': 'ignored.test'}
        scope = default_scope_hosts(s)
        assert host_in_scope('10.0.0.5', scope)
        assert host_in_scope('10.1.0.77', scope)
        assert not host_in_scope('ignored.test', scope)

    def test_default_scope_adds_known_hosts_minus_roe(self):
        s = dict(SETTINGS, ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=['pay.example.test'])
        scope = default_scope_hosts(s, extra_hosts=['api.example.test', 'pay.example.test'])
        assert 'api.example.test' in scope and 'pay.example.test' not in scope

    def test_empty_settings_fail_closed(self):
        assert default_scope_hosts({}) == []
        assert auth_header_lines(_profile(), 'anything.test', {}) == []

    def test_explicit_scope_overrides_default(self):
        p = _profile(scopeHosts=['*.other.test'])
        assert resolve_scope_hosts(p, SETTINGS) == ['*.other.test']

    def test_wildcard_matches_subdomains_not_apex(self):
        assert host_in_scope('a.b.other.test', ['*.other.test'])
        assert not host_in_scope('other.test', ['*.other.test'])
        assert not host_in_scope('evilother.test', ['*.other.test'])

    def test_host_normalization(self):
        scope = ['example.test']
        for h in ('EXAMPLE.test', 'example.test:8443', 'https://example.test/login?x=1', 'example.test.'):
            assert host_in_scope(h, scope), h
        assert host_in_scope('[::1]:8080', ['::1'])
        assert host_in_scope('::1', ['::1'])

    def test_lines_in_scope(self):
        p = _profile(extraHeaders={'X-CSRF-Token': 'c1'})
        assert auth_header_lines(p, 'app.example.test', SETTINGS) == ['Cookie: sid=abc123', 'X-CSRF-Token: c1']

    def test_no_lines_out_of_scope(self):
        assert auth_header_lines(_profile(), 'third-party.test', SETTINGS) == []

    def test_roe_exclusion_beats_explicit_scope(self):
        s = dict(SETTINGS, ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=['example.test'])
        p = _profile(scopeHosts=['sub.example.test'])
        # RoE suffix-matches the excluded parent domain.
        assert auth_header_lines(p, 'sub.example.test', s) == []

    def test_explicit_scope_hosts_argument(self):
        assert auth_header_lines(_profile(), 'x.test', scope_hosts=['x.test']) == ['Cookie: sid=abc123']


class TestMergeAuthHeaders:
    SETTINGS = dict(SETTINGS, AUTH_PROFILE={'authType': 'cookie', 'authValue': 'sid=abc123', 'extraHeaders': {}})

    def test_prepended_when_all_hosts_in_scope(self):
        out = merge_auth_headers(['X-Tool: 1'], self.SETTINGS, ['example.test', 'app.example.test'])
        assert out == ['Cookie: sid=abc123', 'X-Tool: 1']

    def test_auth_lines_come_before_tool_headers(self):
        # hakrawler/arjun pack these into one delimited arg; the tag is appended
        # after, so auth must lead.
        out = merge_auth_headers(['X-A: 1', 'X-B: 2'], self.SETTINGS, ['example.test'])
        assert out[0] == 'Cookie: sid=abc123'

    def test_no_auth_when_any_host_out_of_scope(self):
        out = merge_auth_headers(['X-Tool: 1'], self.SETTINGS, ['example.test', 'third-party.test'])
        assert out == ['X-Tool: 1']

    def test_auth_attached_to_discovered_subdomains(self):
        # Regression: the crawl hosts are whatever recon discovered, which is NOT
        # the configured SUBDOMAIN_LIST. These must be authenticated.
        s = dict(SETTINGS, SUBDOMAIN_LIST=[],
                 AUTH_PROFILE={'authType': 'cookie', 'authValue': 'sid=abc123'})
        out = merge_auth_headers([], s, ['example.test', 'api.example.test', 'cdn.example.test'])
        assert out == ['Cookie: sid=abc123']

    def test_no_auth_when_no_hosts(self):
        assert merge_auth_headers(['X-Tool: 1'], self.SETTINGS, []) == ['X-Tool: 1']

    def test_no_profile_passthrough(self):
        assert merge_auth_headers(['X-Tool: 1'], SETTINGS, ['example.test']) == ['X-Tool: 1']

    def test_none_type_without_extras_is_no_profile(self):
        s = dict(SETTINGS, AUTH_PROFILE={'authType': 'none', 'authValue': '', 'extraHeaders': {}})
        assert profile_from_settings(s) is None
        assert merge_auth_headers([], s, ['example.test']) == []

    def test_extras_only_profile_is_usable(self):
        s = dict(SETTINGS, AUTH_PROFILE={'authType': 'none', 'extraHeaders': {'X-Tenant': 't1'}})
        assert merge_auth_headers([], s, ['example.test']) == ['X-Tenant: t1']

    def test_profile_overrides_duplicate_tool_header(self):
        out = merge_auth_headers(['cookie: stale=1', 'X-Keep: 2'], self.SETTINGS, ['example.test'])
        assert out == ['Cookie: sid=abc123', 'X-Keep: 2']

    def test_roe_excluded_host_blocks_auth(self):
        s = dict(self.SETTINGS, ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=['example.test'])
        assert merge_auth_headers([], s, ['app.example.test']) == []

    def test_injection_value_never_reaches_output(self):
        s = dict(SETTINGS, AUTH_PROFILE={'authType': 'cookie', 'authValue': 'sid=a;;evil'})
        assert merge_auth_headers([], s, ['example.test']) == []

    def test_recon_gate_off_suppresses_auth(self):
        # The independent recon consumer gate: off => recon runs anonymous even
        # though a valid profile is present.
        s = dict(self.SETTINGS)
        s['AUTH_PROFILE'] = {**s['AUTH_PROFILE'], 'reconEnabled': False}
        assert merge_auth_headers([], s, ['example.test']) == []
        assert profile_from_settings(s) is None

    def test_recon_gate_on_or_absent_attaches(self):
        s_on = dict(self.SETTINGS)
        s_on['AUTH_PROFILE'] = {**s_on['AUTH_PROFILE'], 'reconEnabled': True}
        assert merge_auth_headers([], s_on, ['example.test']) == ['Cookie: sid=abc123']
        # Absent key defaults on (older row).
        assert merge_auth_headers([], self.SETTINGS, ['example.test']) == ['Cookie: sid=abc123']

    def test_recon_gate_off_also_suppresses_auth_header_lines(self):
        # ai_surface_recon / graphql call auth_header_lines directly.
        p = {'authType': 'cookie', 'authValue': 'sid=abc123', 'reconEnabled': False}
        assert auth_header_lines(p, 'example.test', SETTINGS) == []


class TestHttpxScopeUsesRealProbeHosts:
    """httpx applies ONE -H set to the whole targets file, so the scope check must
    run against the hosts actually in that file — not the configured scope."""

    def _settings(self, **kw):
        from recon.project_settings import DEFAULT_SETTINGS
        s = dict(DEFAULT_SETTINGS)
        s.update({'TARGET_DOMAIN': 'example.test', 'SUBDOMAIN_LIST': [],
                  'HTTPX_CUSTOM_HEADERS': [],
                  'AUTH_PROFILE': {'authType': 'cookie', 'authValue': 'sid=abc123'}})
        s.update(kw)
        return s

    def _cmd(self, probe_hosts):
        from recon.main_recon_modules.http_probe import build_httpx_command
        return build_httpx_command('/tmp/t.txt', '/tmp/o.json', self._settings(),
                                   probe_hosts=probe_hosts)

    def test_auth_attached_for_in_scope_probe_hosts(self):
        cmd = self._cmd(['example.test', 'api.example.test'])
        assert 'Cookie: sid=abc123' in cmd

    def test_no_auth_when_the_targets_file_holds_a_foreign_host(self):
        # The leak this guards: httpx would otherwise send the session cookie to
        # every URL in targets.txt, including a subdomain CNAME'd off-site.
        cmd = self._cmd(['example.test', 'third-party.test'])
        assert 'Cookie: sid=abc123' not in cmd

    def test_no_probe_hosts_means_no_auth(self):
        assert 'Cookie: sid=abc123' not in self._cmd(None)


def test_mask_auth_value():
    assert mask_auth_value('') == ''
    assert mask_auth_value('abc') == '***'
    assert mask_auth_value('abcde') == 'ab***'
    assert mask_auth_value('abcdefghijklmnop') == 'abcd...mnop'
    assert mask_auth_value('user:password', 'basic') == 'user:***'


class _StopProbe(BaseException):
    """Stops run_http_probe at the command-build seam (BaseException so the
    function's own `except Exception` cannot swallow it)."""


class TestHttpxCallerPassesRealProbeHosts:
    """Row 3: the caller must hand build_httpx_command the hosts that are really
    in targets.txt. Scope-checking the CONFIGURED list instead meant httpx sent
    the session cookie to every discovered host, including out-of-scope ones."""

    RECON_DATA = {
        'domain': 'example.test',
        'metadata': {'target': 'example.test'},
        'dns': {
            'domain': {'ips': {'ipv4': ['1.2.3.4'], 'ipv6': []}},
            'subdomains': {
                'api.example.test': {'has_records': True, 'ips': {'ipv4': ['1.2.3.5'], 'ipv6': []}},
                'cdn.example.test': {'has_records': True, 'ips': {'ipv4': ['1.2.3.6'], 'ipv6': []}},
            },
        },
    }

    def _capture_probe_hosts(self):
        import recon.main_recon_modules.http_probe as hp
        from recon.project_settings import DEFAULT_SETTINGS

        captured = {}

        def _fake_build(targets_file, output_file, settings, probe_hosts=None):
            captured['hosts'] = probe_hosts
            raise _StopProbe()

        settings = dict(DEFAULT_SETTINGS)
        settings.update({'TARGET_DOMAIN': 'example.test', 'SUBDOMAIN_LIST': []})

        with mock.patch.object(hp, 'is_docker_installed', return_value=True), \
             mock.patch.object(hp, 'is_docker_running', return_value=True), \
             mock.patch.object(hp, 'pull_httpx_docker_image', return_value=True), \
             mock.patch.object(hp, 'build_httpx_command', side_effect=_fake_build):
            try:
                hp.run_http_probe(dict(self.RECON_DATA), None, settings)
            except _StopProbe:
                pass
        return captured.get('hosts')

    def test_probe_hosts_are_the_discovered_targets_not_the_configured_scope(self):
        hosts = self._capture_probe_hosts()
        assert hosts is not None, 'build_httpx_command was never reached'
        assert 'example.test' in hosts
        # Discovered subdomains: absent from SUBDOMAIN_LIST, present in targets.txt.
        assert 'api.example.test' in hosts
        assert 'cdn.example.test' in hosts


def test_graphql_delegates_to_shared_builder():
    from recon.graphql_scan.auth import build_auth_headers as gql_build

    assert gql_build({'GRAPHQL_AUTH_TYPE': 'cookie', 'GRAPHQL_AUTH_VALUE': 'a\r\nb'}) == {}
    # An empty GRAPHQL_AUTH_HEADER used to produce a header with an empty name.
    assert gql_build({'GRAPHQL_AUTH_TYPE': 'header', 'GRAPHQL_AUTH_VALUE': 'v',
                      'GRAPHQL_AUTH_HEADER': ''}) == {'X-Auth-Token': 'v'}

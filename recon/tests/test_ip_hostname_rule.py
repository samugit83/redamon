"""recon_settings/ip_hostnames.py: the hostname selection rule of IP-mode projects.

The shared vectors (test_ip_hostname_vectors.py) pin the behaviour the webapp
mirror must reproduce. This file pins what only the Python rule does: the
never-scannable predicate against the pipeline's original, address by address;
the target set; the resolve budget; determinism under shuffled input; the pinned
answer; parallel resolution; and the import boundary that keeps the module
usable in the recon, orchestrator and agent images.
"""
import ast
import ipaddress
import json
import random
import sys
import threading
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from recon.main_recon_modules.ip_filter import is_never_scannable_ip as pipeline_never_scannable  # noqa: E402
from recon_settings import ip_hostnames as ih  # noqa: E402

MODULE = _REPO / 'recon_settings' / 'ip_hostnames.py'
VECTORS = json.loads((_REPO / 'tests' / 'fixtures' / 'ip_hostname_vectors.json').read_text(encoding='utf-8'))
NET = ['203.0.113.0/24']
APP = 'app.example.com'


def _cand(ips=('203.0.113.10',), org='example.com'):
    return {'ips_seen': list(ips), 'org_domain': org}


def _eval(candidates, **kw):
    """evaluate() with permissive defaults; each test overrides what it pins."""
    args = dict(mode='record_filter', include=['*.example.com'], exclude=[],
                targets=ih.TargetSet.from_entries(NET), shared_edge=set(), attribution_failed=(), wildcard_zone=(),
                hard_blocked=lambda _: False, roe_excluded=lambda _: False,
                resolve=lambda _: ['203.0.113.10'], dns_enabled=True, resolver_up=True, cap=100)
    args.update(kw)
    return ih.evaluate(candidates, **args)


# --------------------------------------------------------------------------
# The never-scannable predicate: a stdlib copy of ip_filter.is_never_scannable_ip
# --------------------------------------------------------------------------

def _sample_addresses():
    special = ['127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4', '0.0.0.0/8', '10.0.0.0/8',
               '100.64.0.0/10', '192.168.0.0/16', '203.0.113.0/24', '198.51.100.0/24', '192.0.2.0/24',
               '240.0.0.0/4', '::1/128', 'fe80::/10', 'ff00::/8', 'fc00::/7', '2001:db8::/32', '::ffff:0:0/96']
    out = ['0.0.0.0', '::', '255.255.255.255', '::ffff:127.0.0.1', '::ffff:169.254.169.254',
           '::ffff:203.0.113.10', '::ffff:224.0.0.1', '::ffff:0.0.0.0', '64:ff9b::7f00:1',
           '2002:7f00:1::', 'fe80::1%eth0', '', ' ', 'not-an-address', '203.0.113.10 ', '01.02.03.04',
           '1.2.3', '256.0.0.1', '[::1]', '127.1', None, 42, 0]
    for cidr in special:
        net = ipaddress.ip_network(cidr)
        out += [str(net.network_address), str(net.network_address + 1), str(net.broadcast_address),
                str(net.network_address + net.num_addresses // 2)]
    for table in ('address',):
        for v in VECTORS[table]:
            out += v['addresses'] + v['targets']
    for v in VECTORS['evaluate']:
        for answers in v.get('dns', {}).values():
            out += answers
    return out


@pytest.mark.parametrize('address', _sample_addresses(), ids=repr)
def test_the_never_scannable_copy_answers_like_the_pipeline(address):
    assert ih.is_never_scannable_ip(address) is pipeline_never_scannable(address)


def test_private_and_documentation_addresses_are_scannable():
    for address in ('10.0.0.5', '192.168.1.1', '100.64.0.1', '203.0.113.10', '2001:db8::1', 'fd00::1'):
        assert ih.is_never_scannable_ip(address) is False


# --------------------------------------------------------------------------
# Normalisation, mirroring webapp normalizeHost / splitWildcard
# --------------------------------------------------------------------------

@pytest.mark.parametrize('raw, expected', [
    ('https://u:p@API.Example.com:8443/x?y#z', 'api.example.com'),
    ('[2001:DB8::1]:443', '2001:db8::1'),
    ('[2001:db8::1', '2001:db8::1'),
    ('2001:DB8::1', '2001:db8::1'),
    ('api.example.com...', 'api.example.com'),
    ('﻿ app.example.com ', 'app.example.com'),
    ('', ''),
    ('   ', ''),
    (None, ''),
    (42, '42'),
])
def test_normalize_host(raw, expected):
    assert ih.normalize_host(raw) == expected


def test_normalize_host_trims_like_javascript_not_like_python():
    # str.strip() would also eat \x1c (a separator JavaScript's trim keeps), so
    # the rule would accept an entry the form refuses.
    assert ih.normalize_host('\x1capp.example.com') == '\x1capp.example.com'


@pytest.mark.parametrize('host, expected', [
    ('*.example.com', (True, 'example.com')),
    ('*example.com', (True, 'example.com')),
    ('**.example.com', (True, '*.example.com')),
    ('example.com', (False, 'example.com')),
    ('', (False, '')),
])
def test_split_wildcard(host, expected):
    assert ih.split_wildcard(host) == expected


@pytest.mark.parametrize('raw, expected', [
    ('app.example.com', 'app.example.com'),
    ('APP.example.com.', 'app.example.com'),
    ('https://app.example.com:443/', 'app.example.com'),
    ('co.uk', 'co.uk'),
    ('203.0.113.10', None),
    ('2001:db8::1', None),
    ('203-0-113-10', None),
    ('*.example.com', None),
    ('_srv.example.com', None),
    ('intranet', None),
    ('a' * 64 + '.example.com', None),
    ('.'.join(['a' * 60] * 5) + '.example.com', None),
    ('', None),
    (None, None),
    (42, None),
])
def test_normalize_name(raw, expected):
    assert ih.normalize_name(raw) == expected


# --------------------------------------------------------------------------
# parse_entries / matches
# --------------------------------------------------------------------------

def test_parse_entries_returns_patterns_and_refusals_in_order():
    patterns, invalid = ih.parse_entries(['*.example.com', '203.0.113.10', 'shop.example.net', '**x.example.org'])
    assert patterns == [ih.Pattern('example.com', True), ih.Pattern('shop.example.net', False)]
    assert invalid == [ih.Invalid('203.0.113.10', 'ip_literal'), ih.Invalid('**x.example.org', 'malformed_wildcard')]


def test_parse_entries_accepts_none_and_any_iterable():
    assert ih.parse_entries(None) == ([], [])
    assert ih.parse_entries(e for e in ['app.example.com']) == ([ih.Pattern('app.example.com', False)], [])


def test_a_pattern_token_is_its_canonical_spelling():
    assert ih.Pattern('example.com', True).token == '*.example.com'
    assert ih.Pattern('example.com', False).token == 'example.com'


def test_matches_returns_the_deciding_entry():
    include, _ = ih.parse_entries(['*.example.com', 'example.com'])
    exclude, _ = ih.parse_entries(['old.example.com'])
    assert ih.matches('OLD.example.com.', include, exclude) == ih.MatchResult(False, True, 'old.example.com')
    assert ih.matches('example.com', include, exclude) == ih.MatchResult(True, False, 'example.com')
    assert ih.matches('example.net', include, exclude) == ih.MatchResult(False, False, None)


# --------------------------------------------------------------------------
# TargetSet / address_verdict
# --------------------------------------------------------------------------

def test_target_set_mirrors_the_pipeline_cidr_expansion():
    targets = ih.TargetSet.from_entries(['203.0.113.0/24', '198.51.100.7/32', '2001:db8::/120', '2001:db8:1::5/128'])
    assert '203.0.113.1' in targets and '203.0.113.254' in targets
    assert '203.0.113.0' not in targets and '203.0.113.255' not in targets
    assert '198.51.100.7' in targets
    assert '2001:db8::ff' in targets and '2001:db8::' not in targets
    assert '2001:DB8:1:0::5' in targets


def test_a_large_range_stays_a_range_with_the_same_membership():
    targets = ih.TargetSet.from_entries(['10.0.0.0/8', '2001:db8::/104'])
    assert targets._addresses == set()
    assert '10.1.2.3' in targets and '10.255.255.254' in targets
    assert '10.0.0.0' not in targets and '10.255.255.255' not in targets
    assert '2001:db8::ab:10' in targets and '2001:db8::' not in targets
    assert '11.0.0.1' not in targets and '2001:db9::1' not in targets
    assert '203.0.113.10' not in targets


def test_target_set_accepts_address_objects_and_refuses_garbage():
    targets = ih.TargetSet.from_entries(['203.0.113.10'])
    assert ipaddress.ip_address('203.0.113.10') in targets
    assert 'not-an-address' not in targets
    assert '' not in targets
    assert None not in targets


# Anything but a TargetSet: on a str `in` is a substring test, on a list or set
# an exact string match that ignores CIDRs and canonical spellings.
_NOT_A_TARGET_SET = ['203.0.113.200', ['203.0.113.0/24'], {'203.0.113.10'}, frozenset(), None]


@pytest.mark.parametrize('targets', _NOT_A_TARGET_SET, ids=repr)
def test_address_verdict_takes_only_a_target_set(targets):
    with pytest.raises(TypeError, match='TargetSet'):
        ih.address_verdict(['3.0.113.2'], targets)


@pytest.mark.parametrize('targets', _NOT_A_TARGET_SET, ids=repr)
def test_post_probe_verdict_takes_only_a_target_set(targets):
    with pytest.raises(TypeError, match='TargetSet'):
        ih.post_probe_verdict('3.0.113.2', targets)


@pytest.mark.parametrize('targets', _NOT_A_TARGET_SET, ids=repr)
def test_evaluate_takes_only_a_target_set_and_refuses_before_any_check(targets):
    called = []

    def record(result):
        return lambda name: called.append(name) or result
    with pytest.raises(TypeError, match='TargetSet'):
        _eval({APP: _cand()}, targets=targets, hard_blocked=record(False), roe_excluded=record(False),
              resolve=record(['3.0.113.2']))
    with pytest.raises(TypeError, match='TargetSet'):
        _eval({APP: _cand()}, targets=targets, mode='ip_only')
    assert called == []


def test_the_substring_trap_is_closed():
    """'3.0.113.2' in '203.0.113.200' is True for a str; never a scan."""
    with pytest.raises(TypeError):
        _eval({APP: _cand()}, targets='203.0.113.200', resolve=lambda _: ['3.0.113.2'])
    with pytest.raises(TypeError):
        ih.post_probe_verdict('3.0.113.2', '203.0.113.200')
    assert _eval({APP: _cand()}, targets=ih.TargetSet.from_entries(['203.0.113.200']),
                 resolve=lambda _: ['3.0.113.2']).reasons == {APP: 'resolves_outside_targets'}


def test_unreadable_target_entries_add_nothing_and_are_kept_for_the_log():
    targets = ih.TargetSet.from_entries(['bogus', '203.0.113.10', '', '  ', '203.0.113.0/33', None])
    assert targets.invalid == ('bogus', '203.0.113.0/33')
    assert '203.0.113.10' in targets
    assert ih.TargetSet.from_entries(None).invalid == ()


@pytest.mark.parametrize('addresses, verdict', [
    (['203.0.113.10'], None),
    ([], 'no_current_resolution'),
    (None, 'no_current_resolution'),
    (['127.0.0.1'], 'never_scannable_address'),
    (['198.51.100.7'], 'resolves_outside_targets'),
    (['198.51.100.7', '::1'], 'never_scannable_address'),
])
def test_address_verdict(addresses, verdict):
    assert ih.address_verdict(addresses, ih.TargetSet.from_entries(NET)) == verdict


# --------------------------------------------------------------------------
# evaluate: order, cap, budget, determinism, the pinned answer
# --------------------------------------------------------------------------

def test_check_order_one_name_per_stage():
    """Each name is stopped by a later check than the one before it.

    The refused names sort first and the cap leaves room for all of them inside
    the 2 x cap resolve budget, so checks 12-16 all run in one evaluation.
    """
    refused = {
        'Bad.example.com': _cand(),                      # 1
        'a-blocked.example.com': _cand(),                # 2 (also RoE-excluded: 2 wins)
        'a-roe.example.com': _cand(),                    # 3
        'a-old.example.com': _cand(),                    # 5
        'a-blog.example.net': _cand(org='example.net'),  # 6
        'a-nopsl.example.com': _cand(org=None),          # 7
        'b-gone.example.com': _cand(),                   # 12
        'b-loop.example.com': _cand(),                   # 13
        'b-away.example.com': _cand(),                   # 14
        'b-wild.example.com': _cand(),                   # 15
    }
    selectable = {f'c{i}.example.com': _cand() for i in range(6)}
    answers = {'b-gone.example.com': [], 'b-loop.example.com': ['127.0.0.1'],
               'b-away.example.com': ['198.51.100.7']}
    result = _eval({**selectable, **refused}, exclude=['a-old.example.com'], cap=5,
                   hard_blocked={'a-blocked.example.com'}.__contains__,
                   roe_excluded={'a-roe.example.com', 'a-blocked.example.com'}.__contains__,
                   resolve=lambda n: answers.get(n, ['203.0.113.10']),
                   wildcard_zone=['b-wild.example.com'])
    assert result.reasons == {
        'Bad.example.com': 'invalid_name', 'a-blocked.example.com': 'hard_blocked',
        'a-roe.example.com': 'roe_excluded', 'a-old.example.com': 'filter_excluded',
        'a-blog.example.net': 'filter_no_match', 'a-nopsl.example.com': 'no_registrable_domain',
        'b-gone.example.com': 'no_current_resolution', 'b-loop.example.com': 'never_scannable_address',
        'b-away.example.com': 'resolves_outside_targets', 'b-wild.example.com': 'wildcard_zone',
        **{f'c{i}.example.com': 'scanned' for i in range(5)}, 'c5.example.com': 'cap_reached'}
    assert list(result.reasons) == sorted(result.reasons)
    assert set(result.resolved) == {n for n in result.reasons if n.startswith(('b-', 'c'))}


def test_scan_all_order_attribution_then_edge_then_dns():
    names = {'a.example.com': _cand(['203.0.113.11']), 'b.example.com': _cand(['203.0.113.20']),
             'c.example.com': _cand(['203.0.113.10'])}
    result = _eval(names, mode='scan_all', shared_edge={'203.0.113.20'}, attribution_failed=['203.0.113.11'],
                   dns_enabled=False)
    assert result.reasons == {'a.example.com': 'attribution_unavailable', 'b.example.com': 'shared_edge_ip',
                              'c.example.com': 'dns_disabled'}


def test_attribution_and_edge_ips_compare_canonically():
    names = {'a.example.com': _cand(['2001:db8::11']), 'b.example.com': _cand(['2001:DB8:0::20'])}
    result = _eval(names, mode='scan_all', shared_edge={'2001:db8::20'}, attribution_failed=['2001:DB8::0:11'],
                   targets=ih.TargetSet.from_entries(['2001:db8::/120']))
    assert result.reasons == {'a.example.com': 'attribution_unavailable', 'b.example.com': 'shared_edge_ip'}


def test_scan_all_refuses_every_name_when_failed_attribution_is_unknown():
    """A caller that omits attribution_failed must not skip the per-IP half of check 8."""
    args = dict(mode='scan_all', include=[], exclude=[], targets=ih.TargetSet.from_entries(NET), wildcard_zone=(),
                shared_edge=set(), hard_blocked=lambda _: False, roe_excluded=lambda _: False,
                resolve=lambda _: ['203.0.113.10'], dns_enabled=True, resolver_up=True, cap=10)
    names = {APP: _cand(), 'www.example.com': _cand()}
    assert ih.evaluate(names, **args).reasons == {APP: 'attribution_unavailable',
                                                   'www.example.com': 'attribution_unavailable'}
    assert ih.evaluate(names, **args, attribution_failed=None) == ih.evaluate(names, **args)
    assert ih.evaluate(names, **args, attribution_failed=[]).selected == [APP, 'www.example.com']


def test_unknown_failed_attribution_is_irrelevant_outside_scan_all():
    assert _eval({APP: _cand()}, attribution_failed=None).reasons == {APP: 'scanned'}
    assert _eval({APP: _cand()}, mode='record_only', attribution_failed=None).reasons == {APP: 'record_only'}


def test_post_probe_takes_one_address_or_several():
    targets = ih.TargetSet.from_entries(NET)
    assert ih.post_probe_verdict('203.0.113.10', targets) is None
    assert ih.post_probe_verdict(('203.0.113.10', '198.51.100.7'), targets) == 'moved_during_scan'
    assert ih.post_probe_verdict(iter(['203.0.113.11']), targets) is None


@pytest.mark.parametrize('observed', [None, [], (), iter([]), ''])
def test_a_probe_that_reported_no_address_fails_closed(observed):
    assert ih.post_probe_verdict(observed, ih.TargetSet.from_entries(NET)) == 'moved_during_scan'


def test_a_candidate_without_evidence_reads_as_none():
    assert _eval({APP: None}).reasons == {APP: 'no_registrable_domain'}
    # scan_all: seen on no target IP means no IP to attribute the name to.
    assert _eval({APP: {'org_domain': 'example.com'}}, mode='scan_all').reasons == {APP: 'attribution_unavailable'}
    assert _eval({APP: _cand([])}, mode='scan_all').reasons == {APP: 'attribution_unavailable'}
    assert _eval({APP: _cand([])}).reasons == {APP: 'scanned'}


@pytest.mark.parametrize('org', [None, '', 42, ['example.com']])
def test_an_org_domain_that_is_not_a_name_is_unknown(org):
    assert _eval({APP: _cand(org=org)}).reasons == {APP: 'no_registrable_domain'}


def test_a_non_string_key_is_an_invalid_name_and_sorts_without_error():
    result = _eval({5: _cand(), APP: _cand()})
    assert result.reasons == {5: 'invalid_name', APP: 'scanned'}


@pytest.mark.parametrize('mode', ['ip_only', 'everything', '', None])
def test_only_a_recording_mode_evaluates(mode):
    with pytest.raises(ValueError, match='recording mode'):
        _eval({APP: _cand()}, mode=mode)


def _raises(_):
    raise RuntimeError('guardrail unavailable')


# Only a literal False passes. A guardrail copy's own (False, '') is a tuple, so
# callers wrap it (`lambda n: is_hard_blocked(n)[0]`); unwrapped it refuses.
_NOT_FALSE = [True, None, 0, '', 'no', (False, ''), (True, 'reason'), [], 1]


@pytest.mark.parametrize('verdict', _NOT_FALSE, ids=repr)
def test_hard_blocked_passes_only_on_a_literal_false(verdict):
    assert _eval({APP: _cand()}, hard_blocked=lambda _: verdict).reasons == {APP: 'hard_blocked'}


@pytest.mark.parametrize('verdict', _NOT_FALSE, ids=repr)
def test_roe_excluded_passes_only_on_a_literal_false(verdict):
    assert _eval({APP: _cand()}, roe_excluded=lambda _: verdict).reasons == {APP: 'roe_excluded'}


def test_a_check_that_raises_refuses_the_name_and_the_run_goes_on():
    names = {APP: _cand(), 'www.example.com': _cand()}
    assert _eval(names, hard_blocked=_raises).reasons == {APP: 'hard_blocked', 'www.example.com': 'hard_blocked'}
    assert _eval(names, roe_excluded=_raises).reasons == {APP: 'roe_excluded', 'www.example.com': 'roe_excluded'}
    assert _eval(names, hard_blocked=None).reasons == {APP: 'hard_blocked', 'www.example.com': 'hard_blocked'}


def test_a_literal_false_from_both_checks_lets_the_name_through():
    assert _eval({APP: _cand()}, hard_blocked=lambda _: False, roe_excluded=lambda _: False).reasons == {
        APP: 'scanned'}


def test_wildcard_zone_cannot_be_omitted():
    with pytest.raises(TypeError, match='wildcard_zone'):
        ih.evaluate({APP: _cand()}, mode='record_filter', include=['*.example.com'], exclude=[],
                    targets=ih.TargetSet.from_entries(NET), shared_edge=set(), hard_blocked=lambda _: False,
                    roe_excluded=lambda _: False, resolve=lambda _: ['203.0.113.10'], dns_enabled=True,
                    resolver_up=True, cap=1)


def test_unknown_wildcard_control_refuses_record_filter_names_only():
    assert _eval({APP: _cand()}, wildcard_zone=None).reasons == {APP: 'wildcard_zone'}
    assert _eval({APP: _cand()}, wildcard_zone=None, mode='scan_all').reasons == {APP: 'scanned'}
    assert _eval({APP: _cand()}, wildcard_zone=APP).reasons == {APP: 'wildcard_zone'}


@pytest.mark.parametrize('include, exclude', [(None, []), (['*.example.com'], None), (None, None)])
def test_an_unknown_filter_list_is_an_invalid_filter(include, exclude):
    assert _eval({APP: _cand()}, include=include, exclude=exclude).reasons == {APP: 'invalid_filter'}
    assert _eval({APP: _cand()}, include=include, exclude=exclude, mode='scan_all').reasons == {APP: 'scanned'}


def test_a_non_string_filter_entry_is_refused_not_skipped():
    patterns, invalid = ih.parse_entries(['*.example.com', None, 42])
    assert patterns == [ih.Pattern('example.com', True)]
    assert invalid == [ih.Invalid(ih.NOT_A_STRING, 'not_hostname')]
    assert _eval({'old.example.com': _cand()}, exclude=[None, 'old.example.com']).reasons == {
        'old.example.com': 'invalid_filter'}


def test_a_single_address_is_not_read_as_its_characters():
    edge = _eval({APP: _cand(['203.0.113.20'])}, mode='scan_all', shared_edge='203.0.113.20')
    failed = _eval({APP: _cand(['203.0.113.20'])}, mode='scan_all', attribution_failed='203.0.113.20')
    seen = _eval({APP: {'ips_seen': '203.0.113.20', 'org_domain': 'example.com'}}, mode='scan_all',
                 shared_edge=['203.0.113.20'])
    assert (edge.reasons, failed.reasons, seen.reasons) == (
        {APP: 'shared_edge_ip'}, {APP: 'attribution_unavailable'}, {APP: 'shared_edge_ip'})


@pytest.mark.parametrize('flag', [None, 'true', 1, 'yes', []])
def test_dns_and_resolver_flags_pass_only_on_a_literal_true(flag):
    assert _eval({APP: _cand()}, dns_enabled=flag).reasons == {APP: 'dns_disabled'}
    assert _eval({APP: _cand()}, resolver_up=flag).reasons == {APP: 'resolver_unavailable'}


@pytest.mark.parametrize('cap', [None, 'lots', '1', True, float('nan'), float('inf'), object()], ids=repr)
def test_anything_but_a_finite_number_cap_scans_nothing(cap):
    assert _eval({APP: _cand()}, cap=cap).reasons == {APP: 'cap_reached'}


def test_a_fractional_cap_is_truncated():
    assert _eval({APP: _cand(), 'www.example.com': _cand()}, cap=1.9).selected == [APP]


@pytest.mark.parametrize('field', ['shared_edge', 'attribution_failed'])
def test_an_unreadable_entry_makes_an_ip_list_unknown(field):
    assert _eval({APP: _cand()}, mode='scan_all', **{field: ['203.0.113.20', None]}).reasons == {
        APP: 'attribution_unavailable'}
    assert _eval({APP: _cand()}, mode='scan_all', **{field: [ipaddress.ip_address('203.0.113.20')]}).reasons == {
        APP: 'attribution_unavailable'}


def test_an_unreadable_seen_on_ip_cannot_be_attributed():
    assert _eval({APP: _cand(['203.0.113.10', 42])}, mode='scan_all').reasons == {APP: 'attribution_unavailable'}


def _names(n):
    return {f'n{i:03d}.example.com': _cand() for i in range(n)}


@pytest.mark.parametrize('n, cap, selected', [(5, 4, 4), (5, 5, 5), (5, 6, 5), (5, 0, 0), (5, -3, 0)])
def test_cap_boundary(n, cap, selected):
    result = _eval(_names(n), cap=cap)
    assert len(result.selected) == selected
    assert sum(r == 'cap_reached' for r in result.reasons.values()) == n - selected
    assert result.selected == sorted(_names(n))[:selected]


def test_the_resolve_budget_is_twice_the_cap_and_only_survivors_are_resolved():
    names = _names(10)
    names['other.example.net'] = _cand(org='example.net')
    asked = []
    result = _eval(names, cap=3, resolve=lambda n: asked.append(n) or ['198.51.100.7'])
    assert asked == sorted(_names(10))[:6]
    assert set(result.resolved) == set(asked)
    assert [result.reasons[n] for n in sorted(_names(10))] == ['resolves_outside_targets'] * 6 + ['cap_reached'] * 4
    assert result.reasons['other.example.net'] == 'filter_no_match'


def test_no_lookup_when_dns_is_off_or_the_resolver_is_down():
    def boom(_):
        raise AssertionError('must not resolve')
    assert _eval({APP: _cand()}, dns_enabled=False, resolve=boom).reasons == {APP: 'dns_disabled'}
    assert _eval({APP: _cand()}, resolver_up=False, resolve=boom).reasons == {APP: 'resolver_unavailable'}
    assert _eval({APP: _cand()}, mode='record_only', resolve=boom).reasons == {APP: 'record_only'}


def test_the_output_does_not_depend_on_input_order():
    base = {**_names(12), 'away.example.com': _cand(), 'blog.example.net': _cand(org='example.net')}
    answers = {'away.example.com': ['198.51.100.7']}
    rng = random.Random(1234)
    results = []
    for _ in range(8):
        keys = list(base)
        rng.shuffle(keys)
        results.append(_eval({k: base[k] for k in keys}, cap=5,
                             resolve=lambda n: answers.get(n, ['203.0.113.10'])))
    assert all(r == results[0] for r in results)
    assert list(results[0].reasons) == sorted(results[0].reasons)


def test_resolved_is_the_answer_the_verdict_used():
    """One lookup per name: a second, different answer could never reach a scanner."""
    answers = {APP: [['203.0.113.10'], ['198.51.100.7']]}
    asked = []

    def flapping(name):
        asked.append(name)
        return answers[name].pop(0)
    result = _eval({APP: _cand()}, resolve=flapping)
    assert asked == [APP]
    assert result.reasons == {APP: 'scanned'} and result.resolved == {APP: ['203.0.113.10']}


def test_the_pinned_answer_is_canonical_sorted_and_deduplicated():
    result = _eval({APP: _cand()}, targets=ih.TargetSet.from_entries(NET + ['2001:db8::/120']),
                   resolve=lambda _: [' 203.0.113.10', '2001:DB8::0:10', '203.0.113.10', '2001:db8::10'])
    assert result.resolved == {APP: ['2001:db8::10', '203.0.113.10']}


def test_an_unparsable_answer_is_pinned_as_given_and_never_scanned():
    result = _eval({APP: _cand()}, resolve=lambda _: ['203.0.113.10', ' not-an-address '])
    assert result.reasons == {APP: 'never_scannable_address'}
    assert result.resolved == {APP: ['203.0.113.10', 'not-an-address']}


def test_a_resolver_that_returns_none_means_no_address():
    result = _eval({APP: _cand()}, resolve=lambda _: None)
    assert result.reasons == {APP: 'no_current_resolution'} and result.resolved == {APP: []}


@pytest.mark.parametrize('error', [OSError('timeout'), RuntimeError('breaker'), KeyError('x')])
def test_a_resolver_error_fails_closed_for_that_name_only(error):
    def resolve(name):
        if name == APP:
            raise error
        return ['203.0.113.10']
    result = _eval({APP: _cand(), 'www.example.com': _cand()}, resolve=resolve)
    assert result.reasons == {APP: 'resolver_unavailable', 'www.example.com': 'scanned'}
    assert APP not in result.resolved


def test_a_base_exception_is_not_swallowed():
    def resolve(_):
        raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        _eval({APP: _cand()}, resolve=resolve)


def test_parallel_resolution_gives_the_sequential_answer():
    names = {**_names(30), 'away.example.com': _cand()}
    seen_threads = set()
    barrier = threading.Barrier(2, timeout=5)

    def resolve(name):
        seen_threads.add(threading.get_ident())
        if name in ('n000.example.com', 'n001.example.com'):
            barrier.wait()  # proves two lookups were in flight at once
        return ['198.51.100.7'] if name == 'away.example.com' else ['203.0.113.10']
    parallel = _eval(names, cap=10, workers=8, resolve=resolve)
    sequential = _eval(names, cap=10,
                       resolve=lambda n: ['198.51.100.7'] if n == 'away.example.com' else ['203.0.113.10'])
    assert parallel == sequential
    assert len(seen_threads) > 1


def test_workers_with_a_single_lookup_stays_on_the_caller_thread():
    caller = threading.get_ident()
    threads = []
    _eval({APP: _cand()}, workers=8, resolve=lambda _: threads.append(threading.get_ident()) or ['203.0.113.10'])
    assert threads == [caller]


def test_no_candidates_no_work():
    assert _eval({}) == ih.Evaluation(selected=[], reasons={}, resolved={})


# --------------------------------------------------------------------------
# Vocabulary and the import boundary
# --------------------------------------------------------------------------

def test_reason_codes_are_unique_and_scanned_is_one_of_them():
    assert len(set(ih.REASON_CODES)) == len(ih.REASON_CODES)
    assert ih.SCANNED in ih.REASON_CODES


def _imports(path: Path):
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom):
            yield '.' * node.level + (node.module or '').split('.')[0]


def test_the_module_imports_only_the_standard_library():
    # Mounted into scan containers, the orchestrator and the agent: only recon
    # ships publicsuffixlist, and recon.* is absent from the other two images.
    allowed = set(sys.stdlib_module_names) | {'__future__'}
    assert sorted(m for m in _imports(MODULE) if m not in allowed) == []

"""
An IP-mode project's scope signature covers its hostname policy and the names
it scanned (design §10).

A running session re-runs its guardrails only when the signature moves
(initialize_node._scope_gate). It used to be the target IPs alone, so a
policy edit mid-session (M3 -> M4, a new include entry, a raised cap) or a scan
that selected new names kept the approval given to the old scope.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import project_settings as ps  # noqa: E402
import scope_groups as sg  # noqa: E402

BASE = {'IP_MODE': True, 'TARGET_IPS': ['203.0.113.0/24'], 'IP_HOSTNAME_MODE': 'record_filter',
        'IP_HOSTNAME_INCLUDE': ['*.example.com'], 'IP_HOSTNAME_EXCLUDE': ['old.example.com'],
        'IP_HOSTNAME_PASSIVE_EXPAND': True, 'IP_HOSTNAME_SCAN_ALL_CONFIRMED': False,
        'IP_HOSTNAME_MAX_SCANNED': 100, 'IP_HOSTNAME_PASSIVE_MAX_NAMES': 500}
SCANNED = ['app.example.com', 'shop.example.com']


def _signature(scanned=SCANNED, **changes):
    token = ps._settings_ctx.set({**BASE, **changes})
    try:
        ps.bind_ip_hostnames_scanned(scanned)
        return ps.scope_signature()
    finally:
        ps._settings_ctx.reset(token)


@pytest.mark.parametrize('change', [
    {'IP_HOSTNAME_MODE': 'scan_all'},
    {'IP_HOSTNAME_MODE': 'record_only'},
    {'IP_HOSTNAME_INCLUDE': ['*.example.com', '*.example.de']},
    {'IP_HOSTNAME_EXCLUDE': []},
    {'IP_HOSTNAME_MAX_SCANNED': 10},
    {'IP_HOSTNAME_PASSIVE_MAX_NAMES': 50},
    {'IP_HOSTNAME_PASSIVE_EXPAND': False},
    {'IP_HOSTNAME_SCAN_ALL_CONFIRMED': True},
    {'TARGET_IPS': ['203.0.113.0/25']},
], ids=lambda c: next(iter(c)))
def test_the_signature_moves_with_every_policy_field(change):
    assert _signature(**change) != _signature()


def test_the_signature_moves_when_the_scanned_set_does():
    assert _signature(scanned=SCANNED + ['new.example.com']) != _signature()
    assert _signature(scanned=['app.example.com']) != _signature()


def test_a_name_the_policy_no_longer_admits_does_not_move_it():
    # out of the policy is out of the scope: the same scope, the same signature
    assert _signature(scanned=SCANNED + ['www.example.org']) == _signature()


def test_order_and_spelling_do_not_move_it():
    assert _signature(scanned=list(reversed(SCANNED))) == _signature()
    assert _signature(IP_HOSTNAME_INCLUDE=['*.example.com', '*.example.de']) == \
        _signature(IP_HOSTNAME_INCLUDE=['*.example.de', '*.example.com'])


def test_an_ip_only_project_is_stable_across_turns():
    assert _signature(scanned=[], IP_HOSTNAME_MODE='ip_only') == _signature(scanned=[], IP_HOSTNAME_MODE='ip_only')


def test_the_pure_signature_keeps_its_old_form_without_a_policy():
    # Callers that pass no policy (none in the agent today) keep the IP-list form.
    assert sg.scope_signature([], True, ['192.0.2.2', '192.0.2.1']) == 'ip|192.0.2.1,192.0.2.2'
    with_policy = sg.scope_signature([], True, ['192.0.2.1'], ip_hostname_policy={'mode': 'ip_only'})
    assert with_policy.startswith('ip|192.0.2.1|') and with_policy != 'ip|192.0.2.1'


def test_domain_mode_ignores_the_hostname_fields():
    groups = [{'scanRoot': 'example.com', 'orgDomain': 'example.com', 'mode': 'enumerate',
               'includeRoot': False, 'exactHosts': [], 'entries': ['*.example.com'], 'notes': []}]
    domain = {'IP_MODE': False, 'SCOPE_GROUPS_SOURCE': 'webapp', 'SCOPE_GROUPS': sg.parse_scope_groups(groups)}
    assert _signature(**domain) == _signature(**domain, IP_HOSTNAME_MODE='scan_all') == 'enum|example.com'

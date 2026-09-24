"""Shared engagement matching preserves OpenAPI's restricted target selection."""
import pytest

from graph_db.mixins.recon.openapi_scope import Scope
from recon.helpers.roe_scope import _is_roe_excluded


@pytest.mark.parametrize('host,entry,expected', [
    ('API.Example.Test.', 'example.test', True),
    ('api.example.test', '*.EXAMPLE.TEST.', True),
    ('example.test', '*.example.test', False),
    ('evil-example.test', '*.example.test', False),
    ('a.private.example.test', 'private.example.test', True),
    ('192.0.2.7', '192.0.2.0/24', True),
    ('192.0.3.7', '192.0.2.0/24', False),
    ('2001:db8::1', '2001:DB8:0:0:0:0:0:1', True),
    ('2001:db8::1', '2001:db8::/32', True),
])
def test_shared_roe_exclusions(host, entry, expected):
    assert _is_roe_excluded(host, [entry]) is expected


def payload(**changes):
    return {'root': 'example.test', 'hosts': [], 'include_subdomains': True,
            'include_root': False, 'ip_networks': [], 'excluded_hosts': [], **changes}


def test_wildcard_exclusions_preserve_valid_scope_and_roundtrip():
    scope = Scope.from_payload(payload(excluded_hosts=['*.CORP.example.test.']))
    assert scope.is_valid
    assert scope.allows('https://corp.example.test/spec')
    assert not scope.allows('https://api.corp.example.test/spec')
    assert scope.allows('https://api.example.test/spec')
    restored = Scope.from_payload(scope.to_payload())
    assert restored.to_payload() == scope.to_payload()
    assert not restored.allows('https://api.corp.example.test/spec')


def test_filtered_subdomains_do_not_expand_to_children_or_siblings():
    scope = Scope.from_payload(payload(hosts=['api.example.test'], include_subdomains=False))
    assert scope.allows('https://api.example.test/spec')
    assert not scope.allows('https://child.api.example.test/spec')
    assert not scope.allows('https://other.example.test/spec')
    assert not scope.allows('https://example.test/spec')


def test_ip_literal_requires_ip_network_scope():
    scope = Scope.from_payload(payload(root='192.0.2.1', include_root=True))
    assert not scope.allows('https://192.0.2.1/spec')


@pytest.mark.parametrize('entry', ['*example.test', '*.*.example.test', '*.https://example.test', '*.192.0.2.1'])
def test_invalid_exclusion_payload_still_fails_closed(entry):
    scope = Scope.from_payload(payload(excluded_hosts=[entry]))
    assert not scope.is_valid
    assert not scope.allows('https://api.example.test/spec')

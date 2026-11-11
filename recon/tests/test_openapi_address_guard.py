"""D14: the address guard on OpenAPI document fetches.

Recon runs on the host network, and the agent API there serves /openapi.json,
one of the default discovery paths. A discovered name that resolves to the
recon host, to cloud metadata or to nothing must not be fetched; a host the
operator typed is fetched whatever it resolves to, as the pipeline does for
operator-supplied hosts. ``socket.getaddrinfo`` is patched: no DNS is used.
"""
from __future__ import annotations

import ipaddress
import json
import socket

import pytest

from recon.helpers.openapi.fetch import DocumentError, Fetcher, RequestPacer
from recon.main_recon_modules.ip_filter import is_address_safe_to_scan


def _resolver(table):
    def getaddrinfo(host, *args, **kwargs):
        if host not in table:
            raise socket.gaierror('unresolvable')
        return [(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 0))
                for ip in table[host]]
    return getaddrinfo


@pytest.fixture
def dns(monkeypatch):
    table = {}
    monkeypatch.setattr(socket, 'getaddrinfo', _resolver(table))
    return table


@pytest.mark.parametrize('addresses', [['127.0.0.1'], ['169.254.169.254'], ['::ffff:127.0.0.1'],
                                       ['198.51.100.7', '127.0.0.1'], ['0.0.0.0'], ['224.0.0.1']])
def test_a_discovered_name_resolving_to_a_never_scannable_address_is_refused(dns, addresses):
    dns['api.example.com'] = addresses
    assert is_address_safe_to_scan('api.example.com') is False


def test_private_addresses_stay_allowed(dns):
    dns['intranet.example.com'] = ['10.0.0.5']
    assert is_address_safe_to_scan('intranet.example.com') is True


def test_a_public_address_is_allowed(dns):
    dns['api.example.com'] = ['198.51.100.7']
    assert is_address_safe_to_scan('api.example.com') is True


def test_an_unresolvable_name_is_refused(dns):
    assert is_address_safe_to_scan('gone.example.com') is False


def test_metadata_hostnames_are_refused_without_resolution(dns):
    dns['metadata.google.internal'] = ['198.51.100.7']
    assert is_address_safe_to_scan('metadata.google.internal') is False


def test_operator_hosts_and_networks_are_exempt(dns):
    dns['localhost.example.com'] = ['127.0.0.1']
    assert is_address_safe_to_scan('localhost.example.com', {'localhost.example.com'}) is True
    # IP mode: the operator's own target, even on loopback.
    assert is_address_safe_to_scan('127.0.0.1', set(), [ipaddress.ip_network('127.0.0.1/32')]) is True
    assert is_address_safe_to_scan('127.0.0.1') is False
    assert is_address_safe_to_scan('[::1]') is False


class _Response:
    def __init__(self, status=200, body='{}', headers=None):
        self.status_code = status
        self.headers = headers or {}
        self.content = body.encode()

    def iter_content(self, chunk_size):
        yield self.content

    def close(self):
        pass


def _fetcher(monkeypatch, routes, guard):
    sent = []

    def get(self, url, **kwargs):
        sent.append(url)
        return routes[url]

    monkeypatch.setattr('requests.Session.get', get)
    return Fetcher(5, pacer=RequestPacer(0), address_guard=guard), sent


def test_a_redirect_hop_to_a_loopback_name_is_refused_before_the_request(monkeypatch, dns):
    dns['docs.example.com'] = ['198.51.100.7']
    routes = {'https://docs.example.com/spec.json': _Response(302, headers={'Location': '/next.json'}),
              'https://docs.example.com/next.json': _Response(200, json.dumps({'openapi': '3.0.0'}))}
    fetcher, sent = _fetcher(monkeypatch, routes, is_address_safe_to_scan)
    final, _ = fetcher.fetch('https://docs.example.com/spec.json', {}, 'https://docs.example.com')
    assert final == 'https://docs.example.com/next.json'
    assert sent == list(routes)

    # Same origin, but the name now resolves inward between hops (rebinding).
    dns['docs.example.com'] = ['127.0.0.1']
    fetcher, sent = _fetcher(monkeypatch, {
        'https://docs.example.com/a.json': _Response(302, headers={'Location': '/b.json'})},
        is_address_safe_to_scan)
    calls = {'n': 0}

    def flip(host):
        calls['n'] += 1
        return calls['n'] == 1  # allowed on the first hop, refused on the second

    fetcher.address_guard = flip
    with pytest.raises(DocumentError) as refused:
        fetcher.fetch('https://docs.example.com/a.json', {}, 'https://docs.example.com')
    assert refused.value.code == 'blocked_address'
    assert sent == ['https://docs.example.com/a.json']
    assert fetcher.count == 1  # the refused hop is not counted as a request


def test_a_refused_host_gets_no_request(monkeypatch, dns):
    dns['api.example.com'] = ['127.0.0.1']
    fetcher, sent = _fetcher(monkeypatch, {}, is_address_safe_to_scan)
    with pytest.raises(DocumentError) as refused:
        fetcher.fetch('https://api.example.com/openapi.json', {}, 'https://api.example.com')
    assert refused.value.code == 'blocked_address'
    assert sent == [] and fetcher.count == 0


def _engine(monkeypatch, settings, data):
    from recon.helpers.openapi.discovery import _reset_pacer, run_openapi_discovery
    sent = []

    def get(self, url, **kwargs):
        sent.append(url)
        return _Response(404, '')

    monkeypatch.setattr('requests.Session.get', get)
    _reset_pacer()
    base = {'OPENAPI_AUTO_DISCOVER': True, 'OPENAPI_SOURCES': [], 'OPENAPI_DISCOVERY_PATHS': ['/openapi.json']}
    seeds = list(data['http_probe']['by_url'])
    return run_openapi_discovery(data, {**base, **settings}, seeds), sent


def test_a_discovered_origin_resolving_to_loopback_gets_no_request(monkeypatch, dns):
    dns['agent.example.com'] = ['127.0.0.1']
    dns['www.example.com'] = ['198.51.100.7']
    result, sent = _engine(monkeypatch, {'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': []},
                           {'http_probe': {'by_url': {'https://agent.example.com': {}, 'https://www.example.com': {}}}})
    assert sent == ['https://www.example.com/openapi.json']
    assert [d['code'] for d in result['diagnostics']] == ['blocked_address']


def test_an_ip_mode_target_on_loopback_is_the_operators_choice(monkeypatch, dns):
    result, sent = _engine(monkeypatch, {'IP_MODE': True, 'TARGET_IPS': ['127.0.0.1']},
                           {'http_probe': {'by_url': {'http://127.0.0.1:8080': {}}}})
    assert sent == ['http://127.0.0.1:8080/openapi.json']
    assert not any(d['code'] == 'blocked_address' for d in result['diagnostics'])


# P4: an IP-mode run's scope is its target addresses plus the hostnames its
# selection rule scanned (metadata.ip_mode_hosts); a recorded name is no target.

def test_ip_mode_scope_payload_names_the_selected_hostnames():
    from recon.helpers.openapi.discovery import scope_payload
    from recon.helpers.openapi.scope import Scope
    settings = {'IP_MODE': True, 'TARGET_IPS': ['203.0.113.0/24']}
    payload = scope_payload(settings, ip_mode_hosts={'app.example.com': 'example.com', 'API.example.net.': 'x'})
    assert payload['hosts'] == ['api.example.net', 'app.example.com']
    scope = Scope.from_payload(payload)
    assert scope.is_valid
    assert scope.allows('https://app.example.com/openapi.json')
    assert scope.allows('http://203.0.113.10:8080/openapi.json')
    assert not scope.allows('https://old.example.com/openapi.json')
    assert not scope.allows('https://www.app.example.com/openapi.json')
    assert scope_payload(settings)['hosts'] == []
    # Domain mode never reads the IP-mode list.
    assert scope_payload({'TARGET_DOMAIN': 'example.org'}, ip_mode_hosts={'app.example.com': 'x'})['hosts'] == []


def test_ip_mode_a_payload_naming_an_address_outside_its_networks_stays_invalid():
    from recon.helpers.openapi.scope import Scope
    payload = {'root': '', 'hosts': ['198.51.100.7'], 'include_subdomains': False, 'include_root': False,
               'ip_networks': ['203.0.113.0/24'], 'excluded_hosts': []}
    assert not Scope.from_payload(payload).is_valid


def test_ip_mode_discovery_fetches_a_selected_name_and_not_a_recorded_one(monkeypatch, dns):
    dns['app.example.com'] = ['203.0.113.10']
    dns['old.example.com'] = ['203.0.113.10']
    data = {'metadata': {'ip_mode': True, 'ip_mode_hosts': {'app.example.com': 'example.com'}},
            'http_probe': {'by_url': {'https://app.example.com': {}, 'https://old.example.com': {}}}}
    result, sent = _engine(monkeypatch, {'IP_MODE': True, 'TARGET_IPS': ['203.0.113.0/24']}, data)
    assert sent == ['https://app.example.com/openapi.json']

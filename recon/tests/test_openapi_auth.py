"""OpenAPI downloads use the scoped project session, never legacy Project headers."""
import json

import pytest

from recon.main_recon_modules.openapi_recon import run_openapi_recon


class Response:
    status_code = 200
    headers = {}

    def __init__(self, body):
        self.body = json.dumps(body).encode()

    def iter_content(self, chunk_size):
        yield self.body

    def close(self):
        pass


@pytest.mark.parametrize('discovery', [False, True])
def test_profile_authenticates_sources_discovery_and_references(monkeypatch, discovery):
    calls = []
    document = {'openapi': '3.0.3', 'info': {'title': 'Fixture', 'version': '1'},
                'paths': {'/widgets': {'get': {
        'parameters': [{'$ref': '/params#/id'}], 'responses': {}}}}}

    def get(self, url, **kwargs):
        calls.append((url, kwargs['headers']))
        return Response({'id': {'name': 'id', 'in': 'query'}} if url.endswith('/params') else document)

    monkeypatch.setattr('requests.Session.get', get)
    result = run_openapi_recon({'http_probe': {'by_url': {'https://api.example.com': {}}}}, {
        'TARGET_DOMAIN': 'example.com', 'OPENAPI_AUTO_DISCOVER': discovery,
        'OPENAPI_DISCOVERY_PATHS': ['/spec'],
        'OPENAPI_SOURCES': [] if discovery else [{'url': 'https://api.example.com/spec'}],
        'AUTH_PROFILE': {'authType': 'bearer', 'authValue': 'fixture-session',
                         'extraHeaders': {'X-Tenant': 'fixture-tenant'}},
    })['openapi']
    assert len(result['operations']) == 1
    assert [url for url, _ in calls] == ['https://api.example.com/spec', 'https://api.example.com/params']
    assert all(headers == {'Authorization': 'Bearer fixture-session', 'X-Tenant': 'fixture-tenant'}
               for _, headers in calls)
    assert 'fixture-session' not in json.dumps(result)


@pytest.mark.parametrize('profile', [None,
    {'authType': 'bearer', 'authValue': 'fixture-session', 'reconEnabled': False},
    {'authType': 'bearer', 'authValue': 'fixture-session', 'scopeHosts': ['other.example.com']},
])
def test_anonymous_fetch_ignores_legacy_headers(monkeypatch, profile):
    calls = []
    monkeypatch.setattr('requests.Session.get', lambda self, url, **kw:
                        calls.append(kw['headers']) or Response({'openapi': '3.0.3', 'paths': {}}))
    run_openapi_recon({'http_probe': {'by_url': {'https://api.example.com': {}}}}, {
        'TARGET_DOMAIN': 'example.com', 'OPENAPI_AUTO_DISCOVER': True,
        'OPENAPI_DISCOVERY_PATHS': ['/discovered'],
        'OPENAPI_SOURCES': [{'url': 'https://api.example.com/spec',
                             'headers': ['Authorization: Bearer legacy-source']}],
        'OPENAPI_DISCOVERY_HEADERS': [{'origin': 'https://api.example.com',
                                      'headers': ['Authorization: Bearer legacy-discovery']}],
        'AUTH_PROFILE': profile,
    })
    assert calls == [{}, {}]

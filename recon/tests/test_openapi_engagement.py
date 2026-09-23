"""Engagement controls apply to every OpenAPI document request."""
import json

import pytest

from helpers import proxy_routing
from recon.helpers.openapi.fetch import Fetcher, DocumentError
from recon.main_recon_modules.openapi_recon import run_openapi_recon


class Response:
    def __init__(self, body='{}', status=200, headers=None):
        self.status_code = status
        self.headers = headers or {}
        self.body = body.encode()

    def iter_content(self, chunk_size):
        yield self.body

    def close(self):
        pass


@pytest.mark.parametrize('url,extra', [
    ('http://127.0.0.1/spec', {}),
    ('http://169.254.169.254/spec', {}),
    ('https://third-party.test/spec', {}),
    ('https://blocked.example.com/spec?token=fixture-secret',
     {'ROE_ENABLED': True, 'ROE_EXCLUDED_HOSTS': ['blocked.example.com']}),
])
def test_configured_sources_cannot_escape_scope(monkeypatch, url, extra):
    calls = []
    monkeypatch.setattr('requests.Session.get', lambda *a, **kw: calls.append(a) or Response())
    data = run_openapi_recon({}, {
        'TARGET_DOMAIN': 'example.com', 'OPENAPI_AUTO_DISCOVER': False,
        'OPENAPI_SOURCES': [{'url': url}], **extra,
    })['openapi']
    assert calls == []
    assert data['documents'] == []
    assert data['diagnostics'][0]['code'] == 'out_of_scope'
    assert 'fixture-secret' not in json.dumps(data)


def test_omitted_auto_discovery_setting_sends_no_probes(monkeypatch):
    calls = []
    monkeypatch.setattr('requests.Session.get', lambda *a, **kw: calls.append(a) or Response())
    run_openapi_recon({'http_probe': {'by_url': {'https://api.example.com': {}}}},
                      {'TARGET_DOMAIN': 'example.com'})
    assert calls == []


def test_stealth_blocks_even_explicit_sources(monkeypatch):
    calls = []
    monkeypatch.setattr('requests.Session.get', lambda *a, **kw: calls.append(a) or Response())
    run_openapi_recon({}, {'TARGET_DOMAIN': 'example.com', 'STEALTH_MODE': True,
                          'OPENAPI_ENABLED': True, 'OPENAPI_AUTO_DISCOVER': True,
                          'OPENAPI_SOURCES': [{'url': 'https://api.example.com/spec'}]})
    assert calls == []


def test_rate_ceiling_covers_redirects_references_and_separate_documents(monkeypatch):
    now = [100.0]
    calls = []
    monkeypatch.setattr('recon.helpers.openapi.fetch.time.monotonic', lambda: now[0])
    monkeypatch.setattr('recon.helpers.openapi.fetch.time.sleep', lambda seconds: now.__setitem__(0, now[0] + seconds))
    doc = {'openapi': '3.1.0', 'info': {'title': 'Fixture', 'version': '1'},
           'paths': {'/widgets': {'get': {'parameters': [{'$ref': '/ref#/id'}],
                                        'responses': {'200': {'description': 'OK'}}}}}}
    responses = {
        'https://api.example.com/start': Response(status=302, headers={'Location': '/spec'}),
        'https://api.example.com/spec': Response(json.dumps(doc)),
        'https://api.example.com/ref': Response(json.dumps({'id': {'name': 'id', 'in': 'query'}})),
        'https://api.example.com/second': Response(json.dumps(doc)),
    }
    def get(self, url, **kwargs):
        calls.append((url, now[0]))
        return responses[url]
    monkeypatch.setattr('requests.Session.get', get)
    output = run_openapi_recon({}, {'TARGET_DOMAIN': 'example.com',
        'ROE_GLOBAL_MAX_RPS': 2, 'ROE_ENABLED': False, 'OPENAPI_AUTO_DISCOVER': False,
        'OPENAPI_SOURCES': [{'url': 'https://api.example.com/start'},
                            {'url': 'https://api.example.com/second'}]})['openapi']
    assert len(output['documents']) == 2
    assert [url for url, _ in calls] == list(responses)
    assert [stamp for _, stamp in calls] == [100.0, 100.5, 101.0, 101.5]


def test_proxy_tag_is_sent_only_with_capture_proxy(monkeypatch):
    routing = iter([('http://127.0.0.1:8888', 'signed-fixture-tag'), (None, None)])
    monkeypatch.setattr(proxy_routing, 'get_capture_routing', lambda tool: next(routing))
    calls = []
    monkeypatch.setattr('requests.Session.get', lambda self, url, **kw: calls.append(kw) or Response())
    fetcher = Fetcher()
    headers = {'Authorization': 'Bearer fixture', 'x-redamon-ctx': 'untrusted-tag'}
    try:
        fetcher.fetch('https://api.example.com/one', headers, 'https://api.example.com')
        fetcher.fetch('https://api.example.com/two', headers, 'https://api.example.com')
    finally:
        fetcher.close()
    assert calls[0]['proxies'] == {'http': 'http://127.0.0.1:8888', 'https': 'http://127.0.0.1:8888'}
    assert calls[0]['headers']['X-Redamon-Ctx'] == 'signed-fixture-tag'
    assert calls[0]['verify'] is False
    assert calls[1]['proxies'] == {}
    assert calls[1]['verify'] is True
    assert not any(k.lower() == 'x-redamon-ctx' for k in calls[1]['headers'])
    assert headers['x-redamon-ctx'] == 'untrusted-tag'
    assert all(call['headers']['Authorization'] == 'Bearer fixture' for call in calls)


def test_rate_wait_cannot_exceed_document_deadline(monkeypatch):
    now = [100.0]
    monkeypatch.setattr('recon.helpers.openapi.fetch.time.monotonic', lambda: now[0])
    monkeypatch.setattr('recon.helpers.openapi.fetch.time.sleep', lambda seconds: now.__setitem__(0, now[0] + seconds))
    calls = []
    monkeypatch.setattr('requests.Session.get', lambda *a, **kw: calls.append(a) or Response())
    fetcher = Fetcher(timeout=1, max_rps=0.1)
    try:
        fetcher.fetch('https://api.example.com/one', {}, 'https://api.example.com')
        with pytest.raises(DocumentError, match='deadline'):
            fetcher.fetch('https://api.example.com/two', {}, 'https://api.example.com')
    finally:
        fetcher.close()
    assert len(calls) == 1
    assert now[0] == 100.0

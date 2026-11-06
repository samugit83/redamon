"""D15: a path known only from an API specification gets GET or HEAD requests only.

Each consumer enforces it with its own methods:
- tools that issue GET read graph Endpoints minus declared-only non-GET ones;
- partial Arjun sends ARJUN_METHODS, not the Endpoint's, so with anything but
  GET configured it reads no declared-only path at all;
- AI Surface's chat-shape probe POSTs, so it skips declared-only paths;
- nuclei takes declared-only paths only when they declare GET or HEAD, and at
  most MAX_DECLARED_NUCLEI_URLS of them.
A node an earlier release declared (openapi_declared, no flag) counts as
declared-only. The predicate's behaviour in a real graph is pinned by
test_declared_only_predicate_integration.py.
"""
from __future__ import annotations

import re
from pathlib import Path
from unittest import mock

import pytest

from recon.helpers.target_helpers import MAX_DECLARED_NUCLEI_URLS, build_target_urls_from_resource_enum
from recon.partial_recon_modules import graph_builders
from recon.partial_recon_modules.graph_builders import declared_only, declared_only_unsafe, quarantined

UNSAFE = "(coalesce(e.openapi_declared_only, e.openapi_declared, false) AND NOT e.method IN ['GET','HEAD'])"
MODULES = Path(graph_builders.__file__).parent


def test_the_predicates():
    assert declared_only('e') == 'coalesce(e.openapi_declared_only, e.openapi_declared, false)'
    assert declared_only_unsafe('e') == UNSAFE
    assert declared_only_unsafe('ep') == UNSAFE.replace('e.', 'ep.')


# -- graph readers ------------------------------------------------------------

class _FakeClient:
    def __init__(self, queries):
        self.queries = queries
        self.driver = self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def verify_connection(self):
        return True

    def session(self):
        return self

    def run(self, query, **params):
        self.queries.append(' '.join(query.split()))
        return _Rows()


class _Rows(list):
    def single(self):
        return None


def _builder_queries(builder):
    queries = []
    with mock.patch('graph_db.Neo4jClient', return_value=_FakeClient(queries)), \
         mock.patch.object(graph_builders, 'graph_url_scope', return_value=lambda host: True):
        builder(['example.com'], 'u1', 'p1')
    return queries


@pytest.mark.parametrize('builder,markers', [
    # nuclei's partial run: parameterised URLs for DAST and the main pass.
    (graph_builders._build_vuln_scan_data_from_graph, ["WHERE p.position = 'query'"]),
    # cache poisoning and the GraphQL scanner (which takes the POST ones).
    (graph_builders._build_graphql_data_from_graph, ["OPTIONAL MATCH (e)-[:HAS_PARAMETER]->(p:Parameter)"]),
    (graph_builders._build_serialized_data_from_graph, ["collect(DISTINCT {name: p.name, sample_values"]),
    # the route exposure scan: every route it reads it requests with GET.
    (graph_builders._build_route_exposure_data_from_graph, ["openapi_security AS openapi_security"]),
])
def test_graph_builders_leave_declared_only_non_get_endpoints_out(builder, markers):
    queries = _builder_queries(builder)
    for marker in markers:
        query = next(q for q in queries if marker in q)
        assert f'NOT {UNSAFE}' in query, marker


@pytest.mark.parametrize('module,count', [('web_crawling.py', 3), ('js_analysis.py', 1), ('supply_chain.py', 1)])
def test_get_consumers_read_endpoints_through_the_predicate(module, count):
    source = (MODULES / module).read_text(encoding='utf-8')
    reads = [m.start() for m in re.finditer(r'MATCH \(e:Endpoint \{user_id: ?\$uid, project_id: ?\$pid\}\)', source)]
    assert len(reads) == count
    for start in reads:
        assert 'WHERE NOT ' in source[start:start + 200] and 'declared_only_unsafe("e")' in source[start:start + 200]


def _arjun_endpoint_query(methods):
    from recon.partial_recon_modules import parameter_discovery as pd
    queries = []
    with mock.patch.object(pd, 'partial_settings', return_value={'ARJUN_METHODS': methods}), \
         mock.patch('recon.helpers.resource_enum.arjun_helpers.arjun_binary_check', return_value=True), \
         mock.patch('graph_db.Neo4jClient', return_value=_FakeClient(queries)), \
         mock.patch.object(pd, 'graph_url_scope', return_value=lambda host: True), \
         pytest.raises(SystemExit):
        pd.run_arjun({'domains': ['example.com']})
    return next(q for q in queries if 'MATCH (e:Endpoint' in q)


def test_arjun_posting_reads_no_declared_only_path():
    query = _arjun_endpoint_query(['GET', 'POST'])
    assert f"WHERE NOT {declared_only('e')} AND NOT {quarantined('e')} RETURN" in query


def test_arjun_with_get_only_reads_declared_get_paths():
    query = _arjun_endpoint_query(['GET'])
    assert f'WHERE NOT {UNSAFE} AND NOT {quarantined("e")} RETURN' in query


def test_partial_ai_surface_marks_a_path_declared_only_while_every_node_is():
    from recon.main_recon_modules import ai_surface_recon as full
    from recon.partial_recon_modules import ai_surface_recon as partial
    rows = [
        {'base_url': 'https://api.example.com', 'path': '/v1/chat', 'method': 'POST',
         'iface': 'llm-chat', 'ai_fw': False, 'declared_only': True},
        {'base_url': 'https://api.example.com', 'path': '/v2/chat', 'method': 'POST',
         'iface': 'llm-chat', 'ai_fw': False, 'declared_only': True},
        {'base_url': 'https://api.example.com', 'path': '/v2/chat', 'method': 'GET',
         'iface': 'llm-chat', 'ai_fw': False, 'declared_only': False},
    ]
    seen = {}

    class Client(_FakeClient):
        def run(self, query, **params):
            self.queries.append(' '.join(query.split()))
            return _Rows(rows if 'AS declared_only' in query else [])

    queries = []
    with mock.patch('graph_db.neo4j_client.Neo4jClient', return_value=Client(queries)), \
         mock.patch.object(partial, 'partial_settings', return_value={}), \
         mock.patch.object(partial, 'graph_url_scope', return_value=lambda host: True), \
         mock.patch.object(full, 'run_ai_surface_recon', side_effect=lambda data, *a, **k: seen.update(data) or data), \
         mock.patch.dict('os.environ', {'USER_ID': 'u1', 'PROJECT_ID': 'p1'}):
        try:
            partial.run_ai_surface_recon({'domains': ['example.com']})
        except Exception:  # noqa: BLE001 - only the data handed to the probes matters here
            pass
    endpoints = seen['resource_enum']['by_base_url']['https://api.example.com']['endpoints']
    assert endpoints['/v1/chat']['declared_only'] is True
    assert endpoints['/v2/chat']['declared_only'] is False


# -- AI Surface's POST probe ---------------------------------------------------

def _posted_paths(cand):
    from recon.main_recon_modules import ai_surface_recon as ais
    session = mock.MagicMock()
    session.post.side_effect = __import__('requests').ConnectionError('offline')
    ais._probe_chat('https://api.example.com', cand, session, 1.0, False)
    return [c.args[0].replace('https://api.example.com', '') for c in session.post.call_args_list]


def test_the_chat_probe_never_posts_to_a_declared_only_path():
    cand = {'host_is_ai': False, 'endpoints': [
        {'path': '/v1/chat', 'method': 'POST', 'iface': 'llm-chat', 'declared_only': True},
        {'path': '/v2/chat', 'method': 'POST', 'iface': 'llm-chat', 'declared_only': False}]}
    assert _posted_paths(cand) == ['/v2/chat']


def test_the_static_chat_paths_skip_declared_only_ones_too():
    from recon.helpers import ai_signal_catalog as cat
    static = list(cat.AI_CHAT_PROBE_PATHS)
    cand = {'host_is_ai': True, 'endpoints': [
        {'path': static[0], 'method': 'POST', 'iface': 'llm-chat', 'declared_only': True}]}
    assert _posted_paths(cand) == [p for p in static if p != static[0]][:24]


def test_candidates_carry_the_declared_only_flag():
    from recon.main_recon_modules import ai_surface_recon as ais
    data = {'resource_enum': {'by_base_url': {'https://api.example.com': {'endpoints': {
        '/v1/chat': {'methods': ['POST'], 'ai_interface_type': 'llm-chat', 'declared_only': True},
        '/v2/chat': {'methods': ['POST'], 'ai_interface_type': 'llm-chat'}}}}}}
    cands = ais._gather_candidates(data, {})
    flags = {e['path']: e['declared_only'] for e in cands['https://api.example.com']['endpoints']}
    assert flags == {'/v1/chat': True, '/v2/chat': False}


def _declared_chat_only(**extra):
    return {'resource_enum': {'by_base_url': {'https://api.example.com': {'endpoints': {
        '/v1/chat/completions': {'methods': ['POST'], 'ai_interface_type': 'llm-chat',
                                 'declared_only': True}}}}}, **extra}


def test_a_declared_only_ai_endpoint_alone_makes_no_candidate():
    # Found live: the declaration made the host a candidate, and the MCP
    # handshake and the model fingerprint then POSTed /v1/chat/completions.
    from recon.main_recon_modules import ai_surface_recon as ais
    assert ais._gather_candidates(_declared_chat_only(), {}) == {}


def test_a_host_with_its_own_ai_signal_is_probed_without_the_declared_path():
    from recon.main_recon_modules import ai_surface_recon as ais
    data = _declared_chat_only(port_scan={'by_host': {'api.example.com': {'ports': [11434]}}})
    cand = ais._gather_candidates(data, {})['https://api.example.com']
    assert cand['host_is_ai'] is True
    assert '/v1/chat/completions' not in _posted_paths(cand)


def test_no_request_reaches_a_host_known_to_serve_ai_only_from_a_specification():
    from recon.main_recon_modules import ai_surface_recon as ais
    with mock.patch('requests.Session.post') as post, mock.patch('requests.Session.get') as get, \
         mock.patch.object(ais, '_probe_julius') as julius:
        out = ais.run_ai_surface_recon(_declared_chat_only(metadata={}),
                                       settings={'AI_SURFACE_RECON_ENABLED': True})
    post.assert_not_called()
    get.assert_not_called()
    julius.assert_not_called()
    assert out['ai_surface_recon']['by_url'] == {}


# -- nuclei targets -------------------------------------------------------------

def _endpoint(methods, declared_only=None, query=()):
    entry = {'methods': list(methods),
             'parameters': {'query': [{'name': n, 'sample_values': [v] if v else []} for n, v in query],
                            'body': [], 'path': []}}
    if declared_only is not None:
        entry['declared_only'] = declared_only
    return entry


def test_templated_paths_are_never_targets():
    _, urls = build_target_urls_from_resource_enum({'by_base_url': {'https://a.example.com': {'endpoints': {
        '/users/{id}': _endpoint(['GET']), '/users/1': _endpoint(['GET'], True)}}}})
    assert urls == ['https://a.example.com/users/1']


def test_declared_only_paths_need_get_or_head_and_observed_ones_do_not():
    _, urls = build_target_urls_from_resource_enum({'by_base_url': {'https://a.example.com': {'endpoints': {
        '/orders': _endpoint(['POST'], True),
        '/health': _endpoint(['HEAD'], True),
        '/login': _endpoint(['POST'], False),
        '/search': _endpoint(['GET'], True, query=[('q', 'a%20b'), ('page', None)]),
    }}}})
    assert sorted(urls) == ['https://a.example.com/health', 'https://a.example.com/login',
                            'https://a.example.com/search?q=a%20b&page=1']


def test_the_cap_keeps_every_observed_url_and_the_first_declared_ones(capsys):
    endpoints = {f'/d{i:04d}': _endpoint(['GET'], True) for i in range(2000)}
    endpoints.update({f'/o{i}': _endpoint(['GET']) for i in range(10)})
    data = {'by_base_url': {'https://a.example.com': {'endpoints': endpoints}},
            'openapi': {'groups': [{'root': 'example.com'}]}}
    _, urls = build_target_urls_from_resource_enum(data)
    observed = [u for u in urls if '/o' in u]
    declared = [u for u in urls if '/d' in u]
    assert len(observed) == 10
    assert len(declared) == MAX_DECLARED_NUCLEI_URLS == 500
    assert declared == [f'https://a.example.com/d{i:04d}' for i in range(500)]
    assert data['openapi']['groups'][0]['declared_not_sent_to_nuclei'] == 1500
    assert '[-][OpenAPI] 1500 declared endpoints not sent to nuclei (cap 500)' in capsys.readouterr().out

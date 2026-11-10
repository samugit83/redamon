"""The hostname selection rule, as the agent image imports it.

The agent image COPY-bakes recon_settings/ (agentic/Dockerfile), and the agent
will use recon_settings/ip_hostnames.py to decide which names of an IP-mode
project are targets. This runs the shared vectors
(tests/fixtures/ip_hostname_vectors.json, also read by recon, the orchestrator
and webapp/src/lib/ipHostnameFilter.test.ts) in this image, with the agent's own
hard-guardrail copy injected.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

AGENTIC = Path(__file__).resolve().parents[1]
REPO = AGENTIC.parent
if str(REPO) not in sys.path:
    sys.path.append(str(REPO))

from recon_settings import ip_hostnames as ih  # noqa: E402

FIXTURE = REPO / 'tests' / 'fixtures' / 'ip_hostname_vectors.json'
TS_TEST = REPO / 'webapp' / 'src' / 'lib' / 'ipHostnameFilter.test.ts'
GUARDRAIL_VECTORS = REPO / 'recon_orchestrator' / 'tests' / 'fixtures' / 'hard_guardrail_vectors.json'
AGENT_GUARDRAIL = AGENTIC / 'orchestrator_helpers' / 'hard_guardrail.py'
TABLES = ('parse', 'match', 'address', 'canonical', 'evaluate', 'post_probe')

DOC = json.loads(FIXTURE.read_text(encoding='utf-8'))


def _ids(table):
    return [v['name'] for v in DOC[table]]


def test_the_table_is_a_real_set():
    names = [v['name'] for t in TABLES for v in DOC[t]]
    assert len(names) >= 80
    assert len(set(names)) == len(names)


def test_the_vocabulary_is_the_rules():
    assert list(ih.MODES) == DOC['modes']
    assert list(ih.REASON_CODES) == DOC['reason_codes']


def test_the_webapp_reads_the_same_vectors_file():
    assert "join(process.cwd(), '..', 'tests', 'fixtures', 'ip_hostname_vectors.json')" in TS_TEST.read_text(
        encoding='utf-8')


@pytest.mark.parametrize('v', DOC['parse'], ids=_ids('parse'))
def test_parse(v):
    patterns, invalid = ih.parse_entries(v['entries'])
    assert [p.token for p in patterns] == v['patterns']
    assert [[i.entry, i.reason] for i in invalid] == v['invalid']


@pytest.mark.parametrize('v', DOC['match'], ids=_ids('match'))
def test_match(v):
    include, _ = ih.parse_entries(v['include'])
    exclude, _ = ih.parse_entries(v['exclude'])
    r = ih.matches(v['host'], include, exclude)
    assert (r.included, r.excluded, r.matched_by) == (v['included'], v['excluded'], v['matched_by'])


@pytest.mark.parametrize('v', DOC['address'], ids=_ids('address'))
def test_address(v):
    assert ih.address_verdict(v['addresses'], ih.TargetSet.from_entries(v['targets'])) == v['verdict']


@pytest.mark.parametrize('v', DOC['canonical'], ids=_ids('canonical'))
def test_canonical(v):
    assert ih.canonical_ip(v['value']) == v['canonical']


@pytest.mark.parametrize('v', DOC['post_probe'], ids=_ids('post_probe'))
def test_post_probe(v):
    assert ih.post_probe_verdict(v['observed'], ih.TargetSet.from_entries(v['targets'])) == v['verdict']


def _run(vector):
    v = {**DOC['evaluate_defaults'], **vector}
    calls = []

    def resolve(name):
        calls.append(name)
        if name in v['dns_errors']:
            raise OSError('resolver failure (vector)')
        return list(v['dns'].get(name, []))

    attribution = v['attribution']
    result = ih.evaluate(
        v['candidates'], mode=v['mode'], include=v['include'], exclude=v['exclude'],
        targets=ih.TargetSet.from_entries(v['targets']),
        shared_edge=None if attribution is None else set(attribution['shared_edge']),
        attribution_failed=None if attribution is None else attribution['failed'],
        hard_blocked=set(v['hard_blocked']).__contains__,
        roe_excluded=set(v['roe_excluded']).__contains__,
        resolve=resolve, dns_enabled=v['dns_enabled'], resolver_up=v['resolver_up'],
        cap=v['cap'], wildcard_zone=v['wildcard_zone'])
    return result, calls


@pytest.mark.parametrize('v', DOC['evaluate'], ids=_ids('evaluate'))
def test_evaluate(v):
    if v['expect'].get('error'):
        with pytest.raises(ValueError):
            _run(v)
        return
    result, calls = _run(v)
    assert result.reasons == v['expect']['reasons']
    assert result.selected == v['expect']['selected']
    assert result.resolved == v['expect']['resolved']
    assert calls == v['expect']['resolve_calls']


def test_the_rule_runs_with_the_agent_guardrail_copy():
    # Loaded by path: importing the orchestrator_helpers package pulls in the
    # agent's LangChain stack, which this check does not need.
    spec = importlib.util.spec_from_file_location('_agent_hard_guardrail_ipn', AGENT_GUARDRAIL)
    guardrail = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guardrail)
    vectors = json.loads(GUARDRAIL_VECTORS.read_text(encoding='utf-8'))['vectors']
    names = {v['name']: v['blocked'] for v in vectors if ih.normalize_name(v['name']) == v['name']}
    assert any(names.values()) and not all(names.values())
    result = ih.evaluate(
        {n: {'ips_seen': [], 'org_domain': n} for n in names}, mode='record_only', include=[], exclude=[],
        targets=ih.TargetSet.from_entries([]), shared_edge=set(),
        hard_blocked=lambda n: guardrail.is_hard_blocked(n)[0],
        roe_excluded=lambda _: False, resolve=lambda _: [], dns_enabled=True, resolver_up=True, cap=1,
        wildcard_zone=())
    assert result.reasons == {n: 'hard_blocked' if blocked else 'record_only' for n, blocked in names.items()}

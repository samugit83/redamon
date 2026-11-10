"""recon_settings/ip_hostnames.py against the vectors its TypeScript mirror reads.

One selection rule decides which hostnames found on an IP-mode project's target
IPs may be scanned (invariant I-5). The webapp mirrors its non-DNS part in
webapp/src/lib/ipHostnameFilter.ts for the form preview. Both read
tests/fixtures/ip_hostname_vectors.json: a red vector here means the rule and
the table disagree; a red one in ipHostnameFilter.test.ts means the mirror does.

The same file runs in the orchestrator and agent sections (their own
test_ip_hostname_vectors.py), because the rule is imported in all three images.
This one also injects recon's own guardrail copy (recon_settings/hard_guardrail.py).
"""
import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from recon_settings import ip_hostnames as ih  # noqa: E402
from recon_settings.hard_guardrail import is_hard_blocked  # noqa: E402

FIXTURE = _REPO / 'tests' / 'fixtures' / 'ip_hostname_vectors.json'
TS_TEST = _REPO / 'webapp' / 'src' / 'lib' / 'ipHostnameFilter.test.ts'
GUARDRAIL_VECTORS = _REPO / 'recon_orchestrator' / 'tests' / 'fixtures' / 'hard_guardrail_vectors.json'
TABLES = ('parse', 'match', 'address', 'canonical', 'evaluate', 'post_probe')
_NOT_INPUT = {'name', 'why', 'expect', 'preview', 'patterns', 'invalid', 'psl',
              'included', 'excluded', 'matched_by', 'verdict', 'canonical'}

DOC = json.loads(FIXTURE.read_text(encoding='utf-8'))


def _ids(table):
    return [v['name'] for v in DOC[table]]


def test_the_table_is_a_real_set():
    names = [v['name'] for t in TABLES for v in DOC[t]]
    assert len(names) >= 80
    assert len(set(names)) == len(names)
    for table in TABLES:
        payloads = [json.dumps({k: v for k, v in vec.items() if k not in _NOT_INPUT}, sort_keys=True)
                    for vec in DOC[table]]
        assert len(set(payloads)) == len(payloads), f'{table}: two vectors share their input'


def test_the_vocabulary_is_the_rules():
    assert list(ih.MODES) == DOC['modes']
    assert list(ih.REASON_CODES) == DOC['reason_codes']


def test_every_code_the_rule_can_return_has_a_vector():
    seen = {r for v in DOC['evaluate'] for r in v['expect'].get('reasons', {}).values()}
    seen |= {v['verdict'] for v in DOC['post_probe']} - {None}
    # out_of_policy is not a check of the rule (design §4.2): the webapp's
    # narrowing marker writes it on an already scanned name (§6.3, P4), and no
    # function in recon_settings/ip_hostnames.py returns it.
    assert set(ih.REASON_CODES) - seen == {'out_of_policy'}


def test_the_webapp_reads_the_same_vectors_file():
    # describe.skipIf() in the TS suite would turn a moved fixture into a silent
    # skip there; this assertion turns it into a failure here.
    assert FIXTURE.exists()
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


def test_the_rule_runs_with_this_images_guardrail_copy():
    """The guardrail copies return (blocked, reason); the rule takes a strict bool,
    so the copy is wrapped here, at the injection point, as every caller must."""
    vectors = json.loads(GUARDRAIL_VECTORS.read_text(encoding='utf-8'))['vectors']
    names = {v['name']: v['blocked'] for v in vectors if ih.normalize_name(v['name']) == v['name']}
    assert any(names.values()) and not all(names.values())
    result = ih.evaluate(
        {n: {'ips_seen': [], 'org_domain': n} for n in names}, mode='record_only', include=[], exclude=[],
        targets=ih.TargetSet.from_entries([]), shared_edge=set(),
        hard_blocked=lambda n: is_hard_blocked(n)[0],
        roe_excluded=lambda _: False, resolve=lambda _: [], dns_enabled=True, resolver_up=True, cap=1,
        wildcard_zone=())
    assert result.reasons == {n: 'hard_blocked' if blocked else 'record_only' for n, blocked in names.items()}

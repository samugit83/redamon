"""The scan-time node-filter sweep in full and partial recon.

Pinned here:
  - it sits in a `finally` in both entry points, so an early return or an
    exception still sweeps what the run wrote;
  - it never raises and never changes the exit code (a Neo4j outage during the
    sweep must not turn a COMPLETED scan into an ERROR one);
  - with no run timestamp there is no scope, so there is no sweep;
  - the rules are fetched at SWEEP time, after the pipeline, never at scan start;
  - it is scoped to the run start and the pipeline's own finding sources.

Run: ./redamon.sh test unit   (recon section)
"""

import json
import re
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / 'recon'))

from recon.helpers import node_filter_sweep as nfs  # noqa: E402
from recon.helpers.finding_sources import RECON_FINDING_SOURCES  # noqa: E402

ARMED = {
    'mode': 'denylist', 'applyToScans': True, 'revision': 8,
    'rules': {'version': 1, 'kinds': {}},
    'exemptions': [['Vulnerability', 'v1']],
}


def _source(rel):
    return (PROJECT_ROOT / rel).read_text(encoding='utf-8')


def _function(src, name):
    start = src.index(f'def {name}(')
    rest = src[start:]
    end = re.search(r'\n(def |class |if __name__)', rest[10:])
    return rest if end is None else rest[:end.start() + 10]


class _Client:
    def __init__(self, stats=None, raises=None):
        self.stats = stats or {'ok': True, 'mode': 'denylist', 'kinds': {}, 'totals': {}}
        self.raises = raises
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def apply_node_filters(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.raises:
            raise self.raises
        return self.stats


class TestTheSweepSitsInAFinally:
    # The sweep is registered with recon/helpers/shutdown.py and run through
    # sweep_once(), so a stop's stopper thread and the normal `finally` share
    # one run of it (plan 12.3).
    def test_full_recon(self):
        main = _function(_source('recon/main.py'), 'main')
        assert '_shutdown.set_sweep(_apply_node_filters)' in main, main
        assert re.search(r'try:\s+return _run_pipeline\(\)\s+finally:\s+'
                         r'if not _shutdown\.stop_requested\(\):\s+'
                         r'_graph_wait_all\(\)\s+_shutdown\.sweep_once\(\)', main), main

    def test_full_recon_sweeps_once_per_run_not_per_group(self):
        src = _source('recon/main.py')
        assert src.count('set_sweep(') == 1
        assert src.count('sweep_once(') == 1
        for fn in ('run_domain_group', 'run_domain_batch'):
            body = _function(src, fn)
            assert '_apply_node_filters' not in body and 'sweep_once' not in body, fn

    def test_partial_recon(self):
        src = _source('recon/partial_recon.py')
        main = _function(src, 'main')
        assert 'shutdown.set_sweep(lambda: _apply_node_filters(_STARTED_AT))' in main, main
        assert re.search(r'_STARTED_AT = run_timestamp\(\)\s+try:\s+'
                         r'statuses, completed = _run_tool\(tool_id, config\)\s+'
                         r'finally:\s+shutdown\.sweep_once\(\)', main), main
        # _run_tool is the only path to the tool, so the dispatch sits inside that try.
        assert '_dispatch(tool_id, config)' in _function(src, '_run_tool')
        assert '_dispatch(' not in main


class TestTheWrappersNeverRaise:
    def test_partial_recon_survives_a_broken_sweep_import(self, monkeypatch, capsys):
        import importlib
        monkeypatch.setenv('USER_ID', 'u1')
        monkeypatch.setenv('PROJECT_ID', 'p1')
        monkeypatch.setitem(sys.modules, 'recon.helpers.node_filter_sweep', None)
        partial = importlib.import_module('recon.partial_recon')
        partial._apply_node_filters('2026-09-23T10:00:00+00:00')
        assert '[!][NODE-FILTER] sweep failed:' in capsys.readouterr().out

    def test_partial_recon_without_a_tenant_does_nothing(self, monkeypatch):
        import importlib
        monkeypatch.delenv('USER_ID', raising=False)
        monkeypatch.delenv('PROJECT_ID', raising=False)
        partial = importlib.import_module('recon.partial_recon')
        with mock.patch.object(nfs, 'run_node_filter_sweep') as sweep:
            partial._apply_node_filters('ts')
        sweep.assert_not_called()


class TestRunNodeFilterSweep:
    def test_applies_the_rules_fetched_now_to_what_the_run_wrote(self):
        client = _Client()
        fetch = mock.Mock(return_value=ARMED)
        out = nfs.run_node_filter_sweep('u1', 'p1', '2026-09-23T10:00:00+00:00', RECON_FINDING_SOURCES,
                                        fetch=fetch, client_factory=lambda: client, log=lambda *_: None)
        fetch.assert_called_once_with('p1')
        (args, kwargs), = client.calls
        assert args[:2] == ('u1', 'p1')
        assert args[2] == {'mode': 'denylist', 'rules': ARMED['rules']}
        assert kwargs['touched_since'] == '2026-09-23T10:00:00+00:00'
        assert kwargs['sources'] == list(RECON_FINDING_SOURCES)
        assert kwargs['exemptions'] == [('Vulnerability', 'v1')]
        assert out['revision'] == 8

    def test_no_run_timestamp_means_no_sweep_and_no_fetch(self):
        fetch = mock.Mock(return_value=ARMED)
        out = nfs.run_node_filter_sweep('u1', 'p1', None, RECON_FINDING_SOURCES,
                                        fetch=fetch, client_factory=mock.Mock(), log=lambda *_: None)
        assert out == {'skipped': 'no run start time'}
        fetch.assert_not_called()

    @pytest.mark.parametrize('node_filter', [None, {**ARMED, 'applyToScans': False}])
    def test_not_armed_means_no_graph_work(self, node_filter):
        factory = mock.Mock()
        out = nfs.run_node_filter_sweep('u1', 'p1', 'ts', RECON_FINDING_SOURCES,
                                        fetch=lambda _pid: node_filter, client_factory=factory,
                                        log=lambda *_: None)
        assert out == {'skipped': 'not armed'}
        factory.assert_not_called()

    @pytest.mark.parametrize('where', ['fetch', 'client', 'sweep'])
    def test_it_never_raises(self, where):
        lines = []

        def fetch(_pid):
            if where == 'fetch':
                raise ConnectionError('webapp down')
            return ARMED

        def factory():
            if where == 'client':
                raise RuntimeError('neo4j down')
            return _Client(raises=RuntimeError('lost the session') if where == 'sweep' else None)

        out = nfs.run_node_filter_sweep('u1', 'p1', 'ts', RECON_FINDING_SOURCES,
                                        fetch=fetch, client_factory=factory, log=lines.append)
        assert 'error' in out
        assert lines[-1].startswith('[!][NODE-FILTER] sweep failed:')

    def test_unusable_rules_are_recorded_as_an_error(self):
        client = _Client(stats={'ok': False, 'error': 'unreadable rules'})
        out = nfs.run_node_filter_sweep('u1', 'p1', 'ts', RECON_FINDING_SOURCES,
                                        fetch=lambda _p: ARMED, client_factory=lambda: client,
                                        log=lambda *_: None)
        assert out == {'error': 'unreadable rules', 'revision': 8}


class TestFetchNodeFilters:
    def _fetch(self, body, status=200):
        from recon import project_settings
        resp = mock.Mock(status_code=status)
        resp.json.return_value = body
        resp.raise_for_status = mock.Mock(
            side_effect=None if status == 200 else RuntimeError(f'HTTP {status}'))
        with mock.patch('requests.get', return_value=resp) as get, \
             mock.patch.dict('os.environ', {'SCANNER_API_KEY': 'scan-key'}):
            return project_settings.fetch_node_filters('p1', 'http://webapp:3000'), get

    def test_reads_the_project_with_the_scanner_key(self):
        out, get = self._fetch({'nodeFilter': ARMED})
        assert out == ARMED
        assert get.call_args[0][0] == 'http://webapp:3000/api/projects/p1'
        assert get.call_args[1]['headers'] == {'X-Internal-Key': 'scan-key'}

    def test_no_filter_row_is_none(self):
        assert self._fetch({'nodeFilter': None})[0] is None

    def test_rules_without_their_exemptions_are_refused(self):
        # Sweeping without them would re-mute what an operator unmuted.
        with pytest.raises(ValueError):
            self._fetch({'nodeFilter': {**ARMED, 'exemptions': None}})

    def test_a_failed_request_raises(self):
        with pytest.raises(RuntimeError):
            self._fetch({}, status=500)

    def test_a_refused_job_credential_is_a_sweep_error_never_no_filters(self, monkeypatch):
        # A scan paused past its job credential's 7 days resumes with an expired one:
        # the webapp answers 403, and the sweep records a failure (the mute states stay
        # as they were), never "not armed". A real Response, so raise_for_status is real.
        import requests
        refused = requests.Response()
        refused.status_code = 403
        refused.url = 'http://webapp:3000/api/projects/p1'
        refused._content = b'{"code":"job_credential_required","reason":"expired"}'
        monkeypatch.setenv('WEBAPP_API_URL', 'http://webapp:3000')
        monkeypatch.setenv('SCANNER_API_KEY', 'scan-key')
        monkeypatch.setenv('REDAMON_JOB_CREDENTIAL', 'expired.credential')
        client = _Client()
        lines = []
        with mock.patch('requests.get', return_value=refused) as get:
            out = nfs.run_node_filter_sweep('u1', 'p1', 'ts', RECON_FINDING_SOURCES,
                                            client_factory=lambda: client, log=lines.append)
        assert get.call_args[1]['headers']['X-Redamon-Job'] == 'expired.credential'
        assert 'skipped' not in out and '403' in out['error']
        assert client.calls == []
        assert lines[-1].startswith('[!][NODE-FILTER] sweep failed:')

    def test_the_webapp_body_arms_a_sweep_with_its_rules_and_exemptions(self):
        # The file is the GET body the webapp route test pins, so a shape change
        # on either side fails one of the two. Without it, a renamed field reads
        # here as "not armed" and scans stop filtering without a word.
        contract = json.loads((PROJECT_ROOT / 'webapp/src/lib/nodeFilters/contracts/project_get.json')
                              .read_text(encoding='utf-8'))
        node_filter, _get = self._fetch(contract)

        calls = []

        class Client:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def apply_node_filters(self, uid, pid, config, **kw):
                calls.append((config, kw))
                return {'ok': True, 'mode': config['mode'], 'totals': {}, 'kinds': {}}

        out = nfs.run_node_filter_sweep('u1', 'p1', '2026-09-23T10:00:00+00:00', ['nuclei'],
                                        fetch=lambda _pid: node_filter, client_factory=Client,
                                        log=lambda *_: None)
        assert 'skipped' not in out and 'error' not in out
        (config, kw), = calls
        assert kw['exemptions'] == [('Vulnerability', 'v1'), ('Secret', 's9')]

        from graph_db.node_filters.catalog import load_catalog
        from graph_db.node_filters.model import parse
        parsed = parse(config['rules'], config['mode'], load_catalog())
        assert parsed.ok and parsed.active_kinds() == ['vuln.nuclei'], parsed.errors


@pytest.fixture
def recon_main(monkeypatch, tmp_path):
    """recon.main imported with settings stubbed, as the batch tests do."""
    stub = {
        'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False, 'TARGET_IPS': [],
        'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['domain_discovery'],
        'UPDATE_GRAPH_DB': True, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        monkeypatch.setattr(rm, 'OUTPUT_DIR', tmp_path)
        yield rm


class TestFullReconMain:
    def test_a_failing_sweep_leaves_the_exit_code_at_zero(self, recon_main):
        with mock.patch.object(recon_main, '_run_pipeline', return_value=0), \
             mock.patch.object(recon_main, '_RUN_STARTED_AT', '2026-09-23T10:00:00+00:00'), \
             mock.patch.object(nfs, '_default_fetch', return_value=ARMED), \
             mock.patch.object(nfs, '_default_client', side_effect=RuntimeError('neo4j down')):
            assert recon_main.main() == 0

    def test_the_rules_are_fetched_after_the_pipeline_ran(self, recon_main):
        order = []
        with mock.patch.object(recon_main, '_run_pipeline', side_effect=lambda: order.append('pipeline') or 0), \
             mock.patch.object(recon_main, '_RUN_STARTED_AT', 'ts'), \
             mock.patch.object(nfs, '_default_fetch',
                               side_effect=lambda _p: order.append('fetch') or ARMED), \
             mock.patch.object(nfs, '_default_client', return_value=_Client()):
            recon_main.main()
        assert order == ['pipeline', 'fetch']

    def test_an_early_return_still_sweeps(self, recon_main):
        with mock.patch.object(recon_main, '_run_pipeline', return_value=1), \
             mock.patch.object(recon_main, '_apply_node_filters') as sweep:
            assert recon_main.main() == 1
        sweep.assert_called_once()

    def test_an_exception_still_sweeps_and_still_propagates(self, recon_main):
        with mock.patch.object(recon_main, '_run_pipeline', side_effect=RuntimeError('boom')), \
             mock.patch.object(recon_main, '_apply_node_filters') as sweep:
            with pytest.raises(RuntimeError):
                recon_main.main()
        sweep.assert_called_once()

    def test_no_run_timestamp_means_no_fetch(self, recon_main):
        with mock.patch.object(recon_main, '_run_pipeline', return_value=0), \
             mock.patch.object(recon_main, '_RUN_STARTED_AT', None), \
             mock.patch.object(nfs, '_default_fetch') as fetch:
            assert recon_main.main() == 0
        fetch.assert_not_called()

    def test_the_counts_land_in_the_output_metadata(self, recon_main, tmp_path):
        from helpers.output_paths import canonical_output_file
        canonical_output_file(tmp_path, 'p1').write_text(json.dumps({'metadata': {'x': 1}}))
        stats = {'ok': True, 'mode': 'denylist', 'partial': False, 'totals': {'muted': 3},
                 'kinds': {'vuln.nuclei': {'muted': 3, 'unmuted': 0, 'guarded': 1, 'exempt': 0}}}
        with mock.patch.object(recon_main, '_run_pipeline', return_value=0), \
             mock.patch.object(recon_main, '_RUN_STARTED_AT', 'ts'), \
             mock.patch.object(nfs, '_default_fetch', return_value=ARMED), \
             mock.patch.object(nfs, '_default_client', return_value=_Client(stats=stats)):
            recon_main.main()
        meta = json.loads(canonical_output_file(tmp_path, 'p1').read_text())['metadata']
        assert meta['x'] == 1
        assert meta['node_filter']['totals'] == {'muted': 3}
        assert meta['node_filter']['kinds']['vuln.nuclei']['guarded'] == 1

    def test_a_sweep_error_lands_in_the_output_metadata(self, recon_main, tmp_path):
        from helpers.output_paths import canonical_output_file
        canonical_output_file(tmp_path, 'p1').write_text('{}')
        with mock.patch.object(recon_main, '_run_pipeline', return_value=0), \
             mock.patch.object(recon_main, '_RUN_STARTED_AT', 'ts'), \
             mock.patch.object(nfs, '_default_fetch', side_effect=ConnectionError('down')):
            recon_main.main()
        meta = json.loads(canonical_output_file(tmp_path, 'p1').read_text())['metadata']
        assert 'down' in meta['node_filter']['error']

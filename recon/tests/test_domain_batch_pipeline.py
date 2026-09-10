"""
Domain batch: the loop, the once-per-run graph clear, and the output files.

The three behaviours pinned here are the ones whose failure is SILENT:

  1. the graph is cleared ONCE per run. Clearing per group would leave only the
     last domain in the graph, and the scan would still report success;
  2. a failing group does not abort the batch, and a batch only fails outright
     when every group failed;
  3. each group writes its own JSON and the canonical file is rebuilt after every
     group, because GVM, the project export and the report all read the canonical
     name and know nothing about groups.
"""

import json
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / 'recon'))

from helpers.output_paths import (  # noqa: E402
    canonical_output_file,
    clear_batch_outputs,
    group_slug,
    merge_batch_outputs,
    recon_output_file,
)


# ---------------------------------------------------------------- output paths

class TestReconOutputFile:
    def test_single_domain_keeps_todays_canonical_path(self, tmp_path):
        # Nothing about the existing two modes may change.
        assert recon_output_file(tmp_path, 'p1') == tmp_path / 'recon_p1.json'
        assert recon_output_file(tmp_path, 'p1', None) == tmp_path / 'recon_p1.json'

    def test_a_batch_group_gets_its_own_file(self, tmp_path):
        got = recon_output_file(tmp_path, 'p1', 'domain3.com')
        assert got == tmp_path / 'recon_p1__domain3.com.json'
        assert got != canonical_output_file(tmp_path, 'p1')

    def test_two_groups_never_collide(self, tmp_path):
        a = recon_output_file(tmp_path, 'p1', 'domain1.com')
        b = recon_output_file(tmp_path, 'p1', 'domain2.com')
        assert a != b

    @pytest.mark.parametrize('root', ['../../etc/passwd', 'a/b', 'evil;rm -rf', '..'])
    def test_a_hostile_root_cannot_escape_the_output_directory(self, tmp_path, root):
        path = recon_output_file(tmp_path, 'p1', root)
        assert path.parent.resolve() == tmp_path.resolve()
        assert '..' not in path.name

    def test_group_slug_never_yields_an_empty_name(self):
        assert group_slug('...') == 'group'
        assert group_slug('') == 'group'
        assert group_slug('domain3.com') == 'domain3.com'


class TestClearBatchOutputs:
    def test_removes_group_files_but_never_the_canonical_one(self, tmp_path):
        canonical = canonical_output_file(tmp_path, 'p1')
        canonical.write_text('{}')
        recon_output_file(tmp_path, 'p1', 'a.com').write_text('{}')
        recon_output_file(tmp_path, 'p1', 'b.com').write_text('{}')

        assert clear_batch_outputs(tmp_path, 'p1') == 2
        assert canonical.exists()

    def test_leaves_another_projects_files_alone(self, tmp_path):
        recon_output_file(tmp_path, 'p1', 'a.com').write_text('{}')
        other = recon_output_file(tmp_path, 'p2', 'a.com')
        other.write_text('{}')

        clear_batch_outputs(tmp_path, 'p1')
        assert other.exists()


class TestMergeBatchOutputs:
    def _write(self, tmp_path, project, root, payload):
        path = recon_output_file(tmp_path, project, root)
        path.write_text(json.dumps(payload))
        return path

    def test_merges_every_group_into_the_canonical_file(self, tmp_path):
        self._write(tmp_path, 'p1', 'a.com', {
            'metadata': {'root_domain': 'a.com'},
            'dns': {'subdomains': {'www.a.com': {}}},
        })
        self._write(tmp_path, 'p1', 'b.com', {
            'metadata': {'root_domain': 'b.com'},
            'dns': {'subdomains': {'www.b.com': {}}},
        })

        canonical = merge_batch_outputs(tmp_path, 'p1')
        data = json.loads(Path(canonical).read_text())

        # Both groups survive: this is what GVM and the export will read.
        assert set(data['dns']['subdomains']) == {'www.a.com', 'www.b.com'}

    def test_metadata_describes_the_batch_not_the_first_group(self, tmp_path):
        # A report that named one domain as the whole scope would be wrong.
        self._write(tmp_path, 'p1', 'a.com', {'metadata': {'root_domain': 'a.com'}})
        self._write(tmp_path, 'p1', 'b.com', {'metadata': {'root_domain': 'b.com'}})

        data = json.loads(Path(merge_batch_outputs(tmp_path, 'p1')).read_text())
        assert data['metadata']['domain_batch'] is True
        assert set(data['metadata']['domain_batch_groups']) == {'a.com', 'b.com'}
        assert 'a.com' in data['metadata']['target'] and 'b.com' in data['metadata']['target']

    def test_a_partial_batch_still_produces_a_usable_canonical_file(self, tmp_path):
        # The merge runs after EVERY group, so a stopped batch leaves this behind.
        self._write(tmp_path, 'p1', 'a.com', {'metadata': {'root_domain': 'a.com'}})
        canonical = merge_batch_outputs(tmp_path, 'p1')
        assert json.loads(Path(canonical).read_text())['metadata']['domain_batch_groups'] == ['a.com']

    def test_an_unreadable_group_file_does_not_lose_the_others(self, tmp_path):
        self._write(tmp_path, 'p1', 'a.com', {'metadata': {'root_domain': 'a.com'}})
        recon_output_file(tmp_path, 'p1', 'b.com').write_text('{ not json')

        data = json.loads(Path(merge_batch_outputs(tmp_path, 'p1')).read_text())
        assert data['metadata']['domain_batch_groups'] == ['a.com']

    def test_no_group_files_means_no_canonical_rewrite(self, tmp_path):
        canonical = canonical_output_file(tmp_path, 'p1')
        canonical.write_text('{"keep": true}')
        assert merge_batch_outputs(tmp_path, 'p1') is None
        assert json.loads(canonical.read_text()) == {'keep': True}


# --------------------------------------------------------------------- the loop

@pytest.fixture
def recon_main(monkeypatch):
    """Import recon.main with settings stubbed, so importing it does not try to
    reach the webapp API."""
    stub = {
        'TARGET_DOMAIN': '', 'SUBDOMAIN_LIST': [], 'IP_MODE': False, 'TARGET_IPS': [],
        'DOMAIN_BATCH_MODE': True, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['domain_discovery'],
        'UPDATE_GRAPH_DB': True, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        yield rm


class TestBatchLoop:
    def _groups(self, *roots):
        return [{'rootDomain': r, 'prefixes': ['.']} for r in roots]

    def test_runs_every_group_in_the_given_order(self, recon_main, tmp_path):
        seen = []
        with mock.patch.object(recon_main, 'run_domain_group',
                               side_effect=lambda d, p, start_time=None: seen.append(d) or 0), \
             mock.patch.object(recon_main, 'OUTPUT_DIR', tmp_path), \
             mock.patch.object(recon_main, 'merge_batch_outputs'):
            rc = recon_main.run_domain_batch(
                self._groups('a.com', 'b.com', 'c.com'), recon_main.datetime.now())

        assert seen == ['a.com', 'b.com', 'c.com']
        assert rc == 0

    def test_a_failing_group_does_not_abort_the_rest(self, recon_main, tmp_path):
        seen = []

        def _run(domain, prefixes, start_time=None):
            seen.append(domain)
            return 1 if domain == 'b.com' else 0

        with mock.patch.object(recon_main, 'run_domain_group', side_effect=_run), \
             mock.patch.object(recon_main, 'OUTPUT_DIR', tmp_path), \
             mock.patch.object(recon_main, 'merge_batch_outputs'):
            rc = recon_main.run_domain_batch(
                self._groups('a.com', 'b.com', 'c.com'), recon_main.datetime.now())

        assert seen == ['a.com', 'b.com', 'c.com']
        assert rc == 0  # 2 of 3 succeeded: not a failed run

    def test_a_raising_group_does_not_abort_the_rest(self, recon_main, tmp_path):
        seen = []

        def _run(domain, prefixes, start_time=None):
            seen.append(domain)
            if domain == 'a.com':
                raise RuntimeError('DNS exploded')
            return 0

        with mock.patch.object(recon_main, 'run_domain_group', side_effect=_run), \
             mock.patch.object(recon_main, 'OUTPUT_DIR', tmp_path), \
             mock.patch.object(recon_main, 'merge_batch_outputs'):
            rc = recon_main.run_domain_batch(
                self._groups('a.com', 'b.com'), recon_main.datetime.now())

        assert seen == ['a.com', 'b.com']
        assert rc == 0

    def test_only_a_batch_where_everything_failed_is_a_failed_run(self, recon_main, tmp_path):
        with mock.patch.object(recon_main, 'run_domain_group', return_value=1), \
             mock.patch.object(recon_main, 'OUTPUT_DIR', tmp_path), \
             mock.patch.object(recon_main, 'merge_batch_outputs'):
            rc = recon_main.run_domain_batch(
                self._groups('a.com', 'b.com'), recon_main.datetime.now())
        assert rc == 1

    def test_a_group_with_no_prefixes_is_skipped_not_scanned(self, recon_main, tmp_path):
        # An empty prefix list would fall through to FULL DISCOVERY for that
        # domain, which is exactly what batch mode promises not to do.
        seen = []
        with mock.patch.object(recon_main, 'run_domain_group',
                               side_effect=lambda d, p, start_time=None: seen.append(d) or 0), \
             mock.patch.object(recon_main, 'OUTPUT_DIR', tmp_path), \
             mock.patch.object(recon_main, 'merge_batch_outputs'):
            recon_main.run_domain_batch(
                [{'rootDomain': 'a.com', 'prefixes': []},
                 {'rootDomain': 'b.com', 'prefixes': ['.']}],
                recon_main.datetime.now())
        assert seen == ['b.com']

    def test_merges_after_every_group_not_only_at_the_end(self, recon_main, tmp_path):
        with mock.patch.object(recon_main, 'run_domain_group', return_value=0), \
             mock.patch.object(recon_main, 'OUTPUT_DIR', tmp_path), \
             mock.patch.object(recon_main, 'merge_batch_outputs') as merge:
            recon_main.run_domain_batch(
                self._groups('a.com', 'b.com', 'c.com'), recon_main.datetime.now())
        assert merge.call_count == 3

    def test_prints_the_group_marker_the_orchestrator_parses(self, recon_main, tmp_path, capsys):
        with mock.patch.object(recon_main, 'run_domain_group', return_value=0), \
             mock.patch.object(recon_main, 'OUTPUT_DIR', tmp_path), \
             mock.patch.object(recon_main, 'merge_batch_outputs'):
            recon_main.run_domain_batch(
                self._groups('a.com', 'b.com'), recon_main.datetime.now())

        out = capsys.readouterr().out
        assert '[Batch] Group 1/2: a.com' in out
        assert '[Batch] Group 2/2: b.com' in out


class TestGraphClearHappensOncePerRun:
    def test_the_batch_loop_never_clears_the_graph_itself(self, recon_main, tmp_path):
        # THE regression: a clear inside the loop leaves only the last domain in
        # the graph, and the scan still reports success.
        with mock.patch.object(recon_main, 'run_domain_group', return_value=0), \
             mock.patch.object(recon_main, 'OUTPUT_DIR', tmp_path), \
             mock.patch.object(recon_main, 'merge_batch_outputs'), \
             mock.patch.object(recon_main, '_clear_recon_graph') as clear:
            recon_main.run_domain_batch(
                [{'rootDomain': 'a.com', 'prefixes': ['.']},
                 {'rootDomain': 'b.com', 'prefixes': ['.']}],
                recon_main.datetime.now())
        clear.assert_not_called()

    def test_main_clears_once_then_delegates_to_the_batch(self, recon_main):
        with mock.patch.object(recon_main, '_clear_recon_graph') as clear, \
             mock.patch.object(recon_main, 'run_domain_batch', return_value=0) as batch, \
             mock.patch.object(recon_main, '_batch_groups',
                               return_value=[{'rootDomain': 'a.com', 'prefixes': ['.']}]), \
             mock.patch.object(recon_main, '_check_roe_time_window', return_value=(True, '')), \
             mock.patch.object(recon_main, 'IP_MODE', False):
            assert recon_main.main() == 0

        assert clear.call_count == 1
        assert batch.call_count == 1

    def test_a_single_domain_project_still_runs_one_group(self, recon_main):
        with mock.patch.object(recon_main, '_clear_recon_graph'), \
             mock.patch.object(recon_main, '_batch_groups', return_value=[]), \
             mock.patch.object(recon_main, '_check_roe_time_window', return_value=(True, '')), \
             mock.patch.object(recon_main, 'IP_MODE', False), \
             mock.patch.object(recon_main, 'TARGET_DOMAIN', 'solo.com'), \
             mock.patch.object(recon_main, 'SUBDOMAIN_LIST', ['www.']), \
             mock.patch.object(recon_main, 'run_domain_group', return_value=0) as run:
            assert recon_main.main() == 0

        run.assert_called_once()
        assert run.call_args[0][0] == 'solo.com'
        assert run.call_args[0][1] == ['www.']

    def test_the_roe_time_window_blocks_before_anything_is_cleared(self, recon_main):
        # Blocking AFTER the clear would destroy the graph for a scan that never ran.
        with mock.patch.object(recon_main, '_clear_recon_graph') as clear, \
             mock.patch.object(recon_main, '_check_roe_time_window',
                               return_value=(False, 'outside window')), \
             mock.patch.object(recon_main, 'IP_MODE', False):
            assert recon_main.main() == 1
        clear.assert_not_called()

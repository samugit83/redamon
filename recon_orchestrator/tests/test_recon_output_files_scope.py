"""
Domain batch F1: DELETE /project/{id}/files and /recon/{id}/data must only ever
touch the calling project's own recon output.

The project id is client-suppliable at creation and is interpolated straight into
this endpoint's URL path, so building a glob from it (`recon_<id>__*.json`) let an
id of `*` select every OTHER project's Domain-batch group files - and both callers
DELETE what this helper returns. The helper now matches by literal prefix.

    docker compose exec -T recon-orchestrator python -m pytest tests/test_recon_output_files_scope.py
"""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import api

VICTIM = 'cmnbt9q1c0001nq01nv1wp1si'
ATTACKER_IDS = ['*', '[a-z]*', '[!x]*', '?' * len(VICTIM), '*q1c0001nq01nv1wp1si']


class TestReconOutputFilesScope(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        # One victim project: canonical file plus two batch group files.
        (self.dir / f'recon_{VICTIM}.json').write_text(json.dumps({'secret': 'victim'}))
        (self.dir / f'recon_{VICTIM}__one.com.json').write_text(json.dumps({'secret': 'victim'}))
        (self.dir / f'recon_{VICTIM}__two.com.json').write_text(json.dumps({'secret': 'victim'}))
        # A second unrelated project.
        (self.dir / 'recon_otherproject00000000__x.com.json').write_text('{}')
        self.before = sorted(p.name for p in self.dir.iterdir())

    def tearDown(self):
        self._tmp.cleanup()

    def test_a_wildcard_id_selects_no_files_at_all(self):
        for attacker in ATTACKER_IDS:
            with self.subTest(attacker=attacker):
                self.assertEqual(api._recon_output_files(self.dir, attacker), [])

    def test_the_victims_files_survive_every_wildcard_id(self):
        for attacker in ATTACKER_IDS:
            with self.subTest(attacker=attacker):
                for path in api._recon_output_files(self.dir, attacker):
                    path.unlink()
                self.assertEqual(sorted(p.name for p in self.dir.iterdir()), self.before)

    def test_the_owner_still_gets_its_canonical_file_and_every_group_file(self):
        got = sorted(p.name for p in api._recon_output_files(self.dir, VICTIM))
        self.assertEqual(got, [
            f'recon_{VICTIM}.json',
            f'recon_{VICTIM}__one.com.json',
            f'recon_{VICTIM}__two.com.json',
        ])

    def test_it_never_returns_another_projects_group_file(self):
        names = [p.name for p in api._recon_output_files(self.dir, VICTIM)]
        self.assertNotIn('recon_otherproject00000000__x.com.json', names)

    def test_a_shorter_id_does_not_match_a_longer_ones_files(self):
        # The "recon_<id>__" separator anchors the prefix, so 'cmn' cannot reach
        # the victim's files by being a prefix of its id.
        self.assertEqual(api._recon_output_files(self.dir, 'cmn'), [])

    def test_an_id_with_a_traversal_sequence_stays_inside_the_output_dir(self):
        nested = self.dir / 'sub'
        nested.mkdir()
        (nested / 'recon_x.json').write_text('{}')
        for path in api._recon_output_files(nested, '../' + VICTIM):
            self.assertEqual(path.resolve().parent, nested.resolve())


if __name__ == '__main__':
    unittest.main()

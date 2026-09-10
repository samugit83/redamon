"""
Domain batch: turning the pipeline's group marker into live progress.

Phase numbers restart at 1 for every group, so a UI showing only "Phase 3 of 6"
cannot tell a second group beginning from the first one looping. The group marker
is what carries the outer progress, and it is a plain log line, so the pattern
here and the print in recon/main.py's run_domain_batch must stay in step.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

docker = pytest.importorskip("docker", reason="container_manager needs the docker SDK")

from container_manager import BATCH_GROUP_PATTERN  # noqa: E402


class TestBatchGroupPattern:
    def test_matches_the_line_the_pipeline_prints(self):
        # Exactly what run_domain_batch() emits.
        m = BATCH_GROUP_PATTERN.search('[Batch] Group 2/3: domain3.com')
        assert m is not None
        assert (m.group(1), m.group(2), m.group(3)) == ('2', '3', 'domain3.com')

    def test_matches_with_a_docker_timestamp_prefix(self):
        line = '2026-08-30T17:00:00.123456789Z [Batch] Group 1/5: example.com'
        m = BATCH_GROUP_PATTERN.search(line)
        assert m is not None
        assert m.group(1) == '1' and m.group(3) == 'example.com'

    def test_handles_two_digit_group_counts(self):
        m = BATCH_GROUP_PATTERN.search('[Batch] Group 12/50: a.com')
        assert (m.group(1), m.group(2)) == ('12', '50')

    @pytest.mark.parametrize('line', [
        '[*][Pipeline] TARGET_DOMAIN: example.com',
        '[Batch] DOMAIN BATCH: 3 domain group(s), sequential',
        '  [*][Batch] 1. domain1.com (2 host(s))',
        '[+][graph-db] Previous recon data cleared: 10 nodes removed',
    ])
    def test_does_not_match_other_batch_lines(self, line):
        # The summary and per-group listing lines must not be mistaken for a
        # group START, or progress would jump before any scanning happened.
        assert BATCH_GROUP_PATTERN.search(line) is None


class TestParsedLogEvent:
    def _event(self, line):
        from container_manager import ContainerManager
        # _parse_log_line touches no Docker state, so an uninitialised instance
        # is enough and keeps this in the unit tier.
        cm = ContainerManager.__new__(ContainerManager)
        return ContainerManager._parse_log_line(cm, line, None, None)

    def test_a_group_marker_carries_the_outer_progress(self):
        event = self._event('[Batch] Group 2/3: domain3.com')
        assert event.is_group_start is True
        assert event.group_number == 2
        assert event.total_groups == 3
        assert event.current_group == 'domain3.com'

    def test_an_ordinary_line_carries_no_group_progress(self):
        event = self._event('[*][httpx] probing 12 hosts')
        assert event.is_group_start is False
        assert event.group_number is None
        assert event.current_group is None

    def test_a_phase_line_still_parses_as_a_phase(self):
        # The group pattern is checked after the phase patterns precisely so it
        # cannot mask a phase change.
        event = self._event('[Phase 2] NAABU PORT SCANNER')
        assert event.is_phase_start is True
        assert event.is_group_start is False

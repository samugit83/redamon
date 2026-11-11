"""The AI scanner's RoE matcher against the table every RoE matcher reads.

The scanner image carries no recon/, and the start route hands it the project's
raw roeExcludedHosts, so target_loader keeps its own copy of
recon/helpers/roe_scope.py's matcher: it is the only RoE check between an
IP-mode project's exclusions and the AI attack. It runs the same table as recon
(recon/tests/test_roe_exclusion_vectors.py), the agent and the webapp
(drift map: "RoE exclusion matching"), so none of them can drift alone. A moved
fixture fails here rather than skipping the copy's only pin.
"""
import json
from pathlib import Path

import pytest

import target_loader as tl

FIXTURE = Path(__file__).resolve().parents[3] / 'recon' / 'tests' / 'fixtures' / 'roe_exclusion_vectors.json'


def _vectors():
    assert FIXTURE.is_file(), f'the shared RoE vectors moved: {FIXTURE}'
    return json.loads(FIXTURE.read_text(encoding='utf-8'))['vectors']


VECTORS = _vectors()


def test_the_table_is_a_real_set():
    assert len(VECTORS) >= 40
    assert len({v['name'] for v in VECTORS}) == len(VECTORS)


@pytest.mark.parametrize('v', VECTORS, ids=[v['name'] for v in VECTORS])
def test_vector(v):
    assert tl._roe_excluded(v['host'], v['excluded']) is v['result']


def test_a_non_string_entry_or_host_matches_nothing():
    assert tl._roe_excluded(None, ['203.0.113.10']) is False
    assert tl._roe_excluded('203.0.113.10', [None, 42, '']) is False

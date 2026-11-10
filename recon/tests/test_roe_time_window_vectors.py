"""recon/helpers/roe_scope.py _check_roe_time_window against the shared window vectors.

The orchestrator image cannot import recon code, so it keeps its own copy of
this check (recon_orchestrator/api.py) and the webapp a third one
(webapp/src/lib/roe/scanWindow.ts). All three run
fixtures/roe_time_window_vectors.json: the orchestrator used to accept an
overnight window that this container then refused, so every nightly run
started and exited 1 (R-32).
"""
import json
import sys
from datetime import datetime
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from recon.helpers.roe_scope import _check_roe_time_window  # noqa: E402

_VECTORS = json.loads(
    (Path(__file__).parent / 'fixtures' / 'roe_time_window_vectors.json').read_text())['vectors']


def _settings(v):
    return {
        'ROE_ENABLED': True,
        'ROE_TIME_WINDOW_ENABLED': v.get('enabled', True),
        'ROE_TIME_WINDOW_TIMEZONE': v['timezone'],
        'ROE_TIME_WINDOW_DAYS': v['days'],
        'ROE_TIME_WINDOW_START_TIME': v['start'],
        'ROE_TIME_WINDOW_END_TIME': v['end'],
    }


def test_the_table_is_a_real_set():
    assert len(_VECTORS) >= 20
    assert len({v['name'] for v in _VECTORS}) == len(_VECTORS)
    assert {v['result'] for v in _VECTORS} == {'allowed', 'refused', 'invalid_timezone'}


@pytest.mark.parametrize('v', _VECTORS, ids=[v['name'] for v in _VECTORS])
def test_vector(v):
    allowed, reason = _check_roe_time_window(_settings(v), _now=datetime.fromisoformat(v['now']))
    if v['result'] == 'allowed':
        assert (allowed, reason) == (True, '')
    elif v['result'] == 'refused':
        assert allowed is False
        assert 'timezone' not in reason
    else:
        assert allowed is False
        assert v['timezone'] in reason and 'timezone' in reason


def test_the_orchestrator_and_the_webapp_read_the_same_vectors_file():
    for copy in (_REPO / 'recon_orchestrator' / 'tests' / 'test_roe_time_window_vectors.py',
                 _REPO / 'webapp' / 'src' / 'lib' / 'roe' / 'scanWindow.vectors.test.ts'):
        if not copy.exists():
            pytest.skip(f'{copy.parent.name} source not mounted in this image')
        assert 'roe_time_window_vectors.json' in copy.read_text()

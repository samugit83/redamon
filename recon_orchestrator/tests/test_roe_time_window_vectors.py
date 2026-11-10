"""recon_orchestrator/api.py _check_roe_time_window against the shared window vectors.

This image copies only the orchestrator's own modules, so it cannot import
recon/helpers/roe_scope.py and keeps a mirror of its window check. Both run
recon/tests/fixtures/roe_time_window_vectors.json, so the orchestrator cannot
admit a start the scan container then refuses (R-32), nor the reverse.
"""
import json
from datetime import datetime
from pathlib import Path

import pytest
from fastapi import HTTPException

import api

_VECTORS_PATH = (Path(__file__).resolve().parents[2]
                 / 'recon' / 'tests' / 'fixtures' / 'roe_time_window_vectors.json')
_VECTORS = json.loads(_VECTORS_PATH.read_text())['vectors'] if _VECTORS_PATH.exists() else []


def _project(v):
    return {
        'roeTimeWindowEnabled': v.get('enabled', True),
        'roeTimeWindowTimezone': v['timezone'],
        'roeTimeWindowDays': v['days'],
        'roeTimeWindowStartTime': v['start'],
        'roeTimeWindowEndTime': v['end'],
    }


def test_the_table_is_present_and_real():
    if not _VECTORS_PATH.exists():
        pytest.skip(f'recon fixtures not mounted ({_VECTORS_PATH})')
    assert len(_VECTORS) >= 20


@pytest.mark.parametrize('v', _VECTORS, ids=[v['name'] for v in _VECTORS])
def test_vector(v):
    now = datetime.fromisoformat(v['now'])
    if v['result'] == 'allowed':
        api._check_roe_time_window(_project(v), _now=now)
        return
    with pytest.raises(HTTPException) as ei:
        api._check_roe_time_window(_project(v), _now=now)
    if v['result'] == 'refused':
        assert ei.value.status_code == 403
    else:
        assert ei.value.status_code == 400
        assert v['timezone'] in str(ei.value.detail)

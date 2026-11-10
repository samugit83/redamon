"""recon_settings/hard_guardrail.py: the recon pipeline's copy of the hard guardrail.

IP mode skips the guardrail for addresses, but the names found on target IPs can
be scanned (modes record_filter and scan_all), so every candidate name passes
the guardrail before selection (invariant I-2). The orchestrator copy is not in
the scan containers; recon_settings/ is. So this is a fourth copy (decision
D-06), held to the other three by the shared vectors
(recon_orchestrator/tests/fixtures/hard_guardrail_vectors.json) and to the two
Python copies by identity of the pattern list and the exact list.
"""
import ast
import importlib.util
import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from recon_settings import hard_guardrail as recon_copy  # noqa: E402

VECTORS = _REPO / 'recon_orchestrator' / 'tests' / 'fixtures' / 'hard_guardrail_vectors.json'
ORCH_COPY = _REPO / 'recon_orchestrator' / 'hard_guardrail.py'
AGENT_COPY = _REPO / 'agentic' / 'orchestrator_helpers' / 'hard_guardrail.py'
_VECTORS = json.loads(VECTORS.read_text(encoding='utf-8'))['vectors']


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('v', _VECTORS, ids=[v['name'] for v in _VECTORS])
def test_every_shared_vector(v):
    assert recon_copy.is_hard_blocked(v['name'])[0] is v['blocked']


@pytest.mark.parametrize('path', [ORCH_COPY, AGENT_COPY], ids=['orchestrator', 'agent'])
def test_it_blocks_exactly_what_the_other_python_copies_block(path):
    other = _load(path, f'_other_hard_guardrail_{path.parent.name}')
    assert recon_copy._TLD_PATTERNS == other._TLD_PATTERNS
    assert recon_copy._EXACT_BLOCKED_DOMAINS == other._EXACT_BLOCKED_DOMAINS


# Names come from the module's own exact list and the shared vectors, so this
# file names no protected organisation itself.
EXACT = sorted(recon_copy._EXACT_BLOCKED_DOMAINS)[0]
SUFFIX_HOST = next(
    v['name'] for v in _VECTORS
    if v['blocked'] and v['name'].count('.') >= 2
    and not any(v['name'] == e or v['name'].endswith('.' + e) for e in recon_copy._EXACT_BLOCKED_DOMAINS))


def test_an_exact_blocked_domain_names_itself():
    blocked, reason = recon_copy.is_hard_blocked(EXACT)
    assert blocked and f"'{EXACT}' is a protected" in reason


def test_a_host_under_an_exact_blocked_domain_names_its_parent():
    blocked, reason = recon_copy.is_hard_blocked(f'www.{EXACT}')
    assert blocked and f"subdomain of the protected domain '{EXACT}'" in reason


def test_a_suffix_match_names_the_host():
    blocked, reason = recon_copy.is_hard_blocked(SUFFIX_HOST)
    assert blocked and f"'{SUFFIX_HOST}' belongs to" in reason


@pytest.mark.parametrize('raw', ['', '*.', 'https://', None])
def test_nothing_to_judge_is_not_blocked(raw):
    assert recon_copy.is_hard_blocked(raw) == (False, '')


def test_a_typed_entry_is_normalised_before_the_check():
    assert recon_copy.is_hard_blocked(f'https://user@{SUFFIX_HOST.upper()}.:443/path')[0] is True
    assert recon_copy.is_hard_blocked(f'*{EXACT}')[0] is True
    assert recon_copy.is_hard_blocked('*example.com') == (False, '')


def test_first_hard_blocked_reports_the_first_blocked_name_in_order():
    assert recon_copy.first_hard_blocked(['example.com', f'www.{EXACT}', SUFFIX_HOST])[0] == f'www.{EXACT}'
    assert recon_copy.first_hard_blocked(['example.com', 'app.example.net', '']) is None


def _imports(path: Path):
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.module.split('.')[0]


def test_the_module_imports_only_the_standard_library():
    # recon_settings/ is mounted into scan containers, the orchestrator and the
    # agent: a third-party import would break whichever image lacks it.
    allowed = set(sys.stdlib_module_names) | {'__future__'}
    path = _REPO / 'recon_settings' / 'hard_guardrail.py'
    assert sorted(m for m in _imports(path) if m not in allowed) == []

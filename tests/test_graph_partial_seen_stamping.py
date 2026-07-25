import tempfile
from pathlib import Path

from graph_seen_inventory import (
    PROJECT_LABELS,
    _assert_seen_stamped,
    _is_node_write,
    _label_aliases,
    _session_run_queries,
    _unresolved_session_run_calls,
    find_seen_violations,
)


ROOT = Path(__file__).resolve().parents[1]

PARTIAL_FILES = [
    ROOT / "recon" / "partial_recon_modules" / "user_inputs.py",
    ROOT / "recon" / "partial_recon_modules" / "http_probing.py",
    ROOT / "recon" / "partial_recon_modules" / "port_scanning.py",
    ROOT / "recon" / "partial_recon_modules" / "web_crawling.py",
    ROOT / "recon" / "partial_recon_modules" / "parameter_discovery.py",
    ROOT / "recon" / "partial_recon_modules" / "js_analysis.py",
    ROOT / "recon" / "partial_recon_modules" / "osint_enrichment.py",
    ROOT / "recon" / "partial_recon_modules" / "vulnerability_scanning.py",
]

SESSION_CLIENTS = {
    "session.run(": "graph_client",
    "_s.run(": "_gc",
    "sess.run(": "gc",
}

GLOBAL_REFERENCE_LABELS = frozenset({"CVE", "MitreData", "Capec"})


def _temporary_source(source):
    directory = tempfile.TemporaryDirectory()
    path = Path(directory.name) / "inventory_subject.py"
    path.write_text(source, encoding="utf-8")
    return directory, path


def test_run_inventory_resolves_keyword_query_argument():
    directory, path = _temporary_source(
        '''
QUERY = """
MERGE (s:Subdomain {name: $name})
"""
session.run(query=QUERY, name="example.com")
'''
    )
    try:
        queries = list(_session_run_queries(path))
    finally:
        directory.cleanup()

    assert len(queries) == 1
    query, call_source, line = queries[0]
    assert "MERGE (s:Subdomain" in query
    assert _label_aliases(query, PROJECT_LABELS) == [("Subdomain", "s")]
    assert _is_node_write(query, "Subdomain", "s")
    assert "session.run(query=QUERY" in call_source
    assert line == 5


def test_run_inventory_reports_no_argument_call_as_unresolved():
    directory, path = _temporary_source("session.run()\n")
    try:
        unresolved = list(_unresolved_session_run_calls(path))
    finally:
        directory.cleanup()

    assert unresolved == [("session.run()", 1)]


def _expected_job_param_source(call_source, path, line):
    clients = {
        client
        for receiver, client in SESSION_CLIENTS.items()
        if receiver in call_source
    }
    assert len(clients) == 1, (
        f"{path}:{line} cannot resolve graph client ownership for run call"
    )
    return f"**{clients.pop()}._recon_job_params()"


def test_partial_run_query_inventory_has_no_unresolved_calls():
    unresolved = [
        f"{path}:{line}: {call_source}"
        for path in PARTIAL_FILES
        for call_source, line in _unresolved_session_run_calls(path)
    ]
    assert not unresolved, "Unresolved run query arguments:\n" + "\n".join(unresolved)


def test_partial_observable_node_writes_are_seen_stamped_per_block():
    violations = find_seen_violations(PARTIAL_FILES)
    assert not violations, "\n".join(map(str, violations))

    seen_writes = set()
    for path in PARTIAL_FILES:
        for query, call_source, line in _session_run_queries(path):
            for label, alias in _label_aliases(query, PROJECT_LABELS):
                if not _is_node_write(query, label, alias):
                    continue
                seen_writes.add((path, line, label, alias))
                _assert_seen_stamped(
                    query,
                    call_source,
                    path,
                    line,
                    label,
                    alias,
                    exact_once=True,
                )
                expected_params = _expected_job_param_source(
                    call_source, path, line
                )
                assert expected_params in call_source, (
                    f"{path}:{line} must pass {expected_params} for "
                    f"{label} alias {alias}"
                )

    assert seen_writes, "Partial recon inventory found no project-node writes"


def test_partial_global_reference_nodes_are_not_seen_stamped():
    for path in PARTIAL_FILES:
        for query, _call_source, line in _session_run_queries(path):
            for label, alias in _label_aliases(query, GLOBAL_REFERENCE_LABELS):
                if not _is_node_write(query, label, alias):
                    continue
                assert "first_seen" not in query, f"{path}:{line} stamps {label}"
                assert "last_seen" not in query, f"{path}:{line} stamps {label}"

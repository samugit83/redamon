from pathlib import Path

from graph_seen_inventory import (
    _assert_seen_stamped,
    _is_node_write,
    _label_aliases,
    _session_run_queries,
    find_seen_violations,
)


ROOT = Path(__file__).resolve().parents[1]

CORE_FILES = [
    ROOT / "graph_db" / "mixins" / "recon" / "domain_mixin.py",
    ROOT / "graph_db" / "mixins" / "recon" / "port_mixin.py",
    ROOT / "graph_db" / "mixins" / "recon" / "http_mixin.py",
    ROOT / "graph_db" / "mixins" / "recon" / "resource_mixin.py",
    ROOT / "graph_db" / "mixins" / "recon" / "js_recon_mixin.py",
    ROOT / "graph_db" / "mixins" / "recon" / "vuln_mixin.py",
]

CORE_LABELS = [
    "Domain",
    "Subdomain",
    "IP",
    "DNSRecord",
    "Port",
    "Service",
    "BaseURL",
    "Endpoint",
    "Parameter",
    "Header",
    "Certificate",
    "Technology",
    "Vulnerability",
    "Secret",
    "JsReconFinding",
]

GLOBAL_REFERENCE_LABELS = ["CVE", "MitreData", "Capec"]


def test_core_observable_node_writes_are_seen_stamped_per_block():
    violations = find_seen_violations(CORE_FILES)
    assert not violations, "\n".join(map(str, violations))

    seen_labels = set()
    for path in CORE_FILES:
        for query, call_source, line in _session_run_queries(path):
            for label, alias in _label_aliases(query, CORE_LABELS):
                seen_labels.add(label)
                if _is_node_write(query, label, alias):
                    _assert_seen_stamped(query, call_source, path, line, label, alias)

    assert seen_labels == set(CORE_LABELS)


def test_global_reference_nodes_are_not_seen_stamped():
    for path in CORE_FILES:
        for query, _call_source, line in _session_run_queries(path):
            for label, alias in _label_aliases(query, GLOBAL_REFERENCE_LABELS):
                if not _is_node_write(query, label, alias):
                    continue
                assert "first_seen" not in query, f"{path}:{line} stamps {label}"
                assert "last_seen" not in query, f"{path}:{line} stamps {label}"

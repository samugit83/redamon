from pathlib import Path

from graph_seen_inventory import (
    _assert_seen_stamped,
    _is_node_write,
    _label_aliases,
    _session_run_queries,
    find_seen_violations,
)


ROOT = Path(__file__).resolve().parents[1]

AUX_FILE_LABELS = {
    ROOT / "graph_db" / "mixins" / "osint_mixin.py": [
        "IP",
        "Port",
        "Service",
        "Subdomain",
        "DNSRecord",
        "BaseURL",
        "Endpoint",
        "Parameter",
        "Technology",
        "Certificate",
        "ExternalDomain",
        "ThreatPulse",
        "Malware",
        "Vulnerability",
    ],
    ROOT / "graph_db" / "mixins" / "graphql_mixin.py": [
        "BaseURL",
        "Endpoint",
        "Vulnerability",
    ],
    ROOT / "graph_db" / "mixins" / "recon" / "takeover_mixin.py": [
        "Domain",
        "Subdomain",
        "Vulnerability",
    ],
    ROOT / "graph_db" / "mixins" / "recon" / "vhost_sni_mixin.py": [
        "IP",
        "Subdomain",
        "BaseURL",
        "Endpoint",
        "Certificate",
        "Vulnerability",
    ],
    ROOT / "graph_db" / "mixins" / "recon" / "user_input_mixin.py": [
        "UserInput",
        "Domain",
        "Subdomain",
        "IP",
        "DNSRecord",
        "BaseURL",
        "Endpoint",
    ],
}

INTENTIONALLY_ABSENT_LABELS = {
    ROOT / "graph_db" / "mixins" / "osint_mixin.py": {
        "Technology": "OSINT mixin does not currently create or enrich Technology nodes.",
    },
    ROOT / "graph_db" / "mixins" / "recon" / "vhost_sni_mixin.py": {
        "Endpoint": "Vhost/SNI does not currently create or enrich Endpoint nodes.",
        "Certificate": "Vhost/SNI does not currently create or enrich Certificate nodes.",
    },
}

GLOBAL_REFERENCE_LABELS = ["CVE", "MitreData", "Capec"]


def test_aux_observable_node_writes_are_seen_stamped_per_block():
    violations = find_seen_violations(AUX_FILE_LABELS)
    assert not violations, "\n".join(map(str, violations))

    seen_labels_by_path = {path: set() for path in AUX_FILE_LABELS}
    for path, labels in AUX_FILE_LABELS.items():
        for query, call_source, line in _session_run_queries(path):
            for label, alias in _label_aliases(query, labels):
                seen_labels_by_path[path].add(label)
                if _is_node_write(query, label, alias):
                    _assert_seen_stamped(query, call_source, path, line, label, alias)

    for path, labels in AUX_FILE_LABELS.items():
        absent_labels = INTENTIONALLY_ABSENT_LABELS.get(path, {})
        for label in labels:
            assert label in seen_labels_by_path[path] or label in absent_labels, (
                f"{path} configured label {label} was not seen and is not documented absent"
            )
        for label, reason in absent_labels.items():
            assert label in labels, f"{path} absent label {label} is not configured"
            assert label not in seen_labels_by_path[path], (
                f"{path} documents {label} as absent ({reason}) but the label is now present"
            )


def test_aux_global_reference_nodes_are_not_seen_stamped():
    for path in AUX_FILE_LABELS:
        for query, _call_source, line in _session_run_queries(path):
            for label, alias in _label_aliases(query, GLOBAL_REFERENCE_LABELS):
                if not _is_node_write(query, label, alias):
                    continue
                assert "first_seen" not in query, f"{path}:{line} stamps {label}"
                assert "last_seen" not in query, f"{path}:{line} stamps {label}"

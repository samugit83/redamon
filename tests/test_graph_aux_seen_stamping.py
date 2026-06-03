import ast
import re
from pathlib import Path


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


def _node_pattern(keyword, alias, label):
    return re.compile(
        rf"\b{keyword}\s*\(\s*{re.escape(alias)}\s*:\s*{re.escape(label)}\b"
    )


def _alias_has_set(query, alias):
    return re.search(rf"(\bSET|,)\s+{re.escape(alias)}\.", query) is not None


def _query_constants(tree):
    constants = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            if not isinstance(node.value.value, str):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    constants[target.id] = node.value.value
    return constants


def _query_text(arg, source, constants):
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    if isinstance(arg, ast.Name):
        return constants.get(arg.id)
    if isinstance(arg, ast.JoinedStr):
        return ast.get_source_segment(source, arg)
    return None


def _session_run_queries(path):
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    constants = _query_constants(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "run":
            continue
        if not node.args:
            continue
        query = _query_text(node.args[0], source, constants)
        if query is None:
            continue
        call_source = ast.get_source_segment(source, node) or ""
        yield query, call_source, node.lineno


def _label_aliases(query, labels):
    aliases = []
    labels_pattern = "|".join(re.escape(label) for label in labels)
    pattern = re.compile(
        rf"\b(?:MERGE|MATCH|OPTIONAL MATCH)\s*\(\s*(\w+)\s*:\s*({labels_pattern})\b"
    )
    for alias, label in pattern.findall(query):
        aliases.append((label, alias))
    return aliases


def _is_node_write(query, label, alias):
    return (
        _node_pattern("MERGE", alias, label).search(query) is not None
        or _alias_has_set(query, alias)
    )


def _assert_seen_stamped(query, call_source, path, line, label, alias):
    assert (
        f"{alias}.first_seen = coalesce({alias}.first_seen, $recon_job_started_at)"
        in query
    ), f"{path}:{line} missing first_seen for {label} alias {alias}"
    assert (
        f"{alias}.first_seen_job_id = coalesce({alias}.first_seen_job_id, $recon_job_id)"
        in query
    ), f"{path}:{line} missing first_seen_job_id for {label} alias {alias}"
    assert (
        f"{alias}.last_seen = $recon_job_started_at" in query
    ), f"{path}:{line} missing last_seen for {label} alias {alias}"
    assert (
        f"{alias}.last_seen_job_id = $recon_job_id" in query
    ), f"{path}:{line} missing last_seen_job_id for {label} alias {alias}"
    assert (
        "_recon_job_params()" in call_source
    ), f"{path}:{line} does not pass recon job params for {label} alias {alias}"


def test_aux_observable_node_writes_are_seen_stamped_per_block():
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

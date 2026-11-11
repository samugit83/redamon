"""Regression guard: every recon dict partial recon builds declares IP mode.

An IP-mode partial run's one root is the synthetic ``ip-targets.<project id>``.
Every reader that keeps to the target list asks the recon dict it is handed
for ``metadata.ip_mode`` and the expanded ``metadata.expanded_ips``: the
admission gate (which fails closed on an IP-mode dict with no list), the OSINT
IP lists, the DNS-only security checks, Shodan's and urlscan's domain lookups,
build_target_urls' name source. A dict built without them reads as a domain
run and sends the project id to third parties and PTR names to the scanners
(B-19, B-23). ``helpers.ip_mode_recon`` stamps a dict, in IP mode only.

This is an AST check over recon/partial_recon_modules/ and partial_recon.py:

1. A recon-dict literal is the first argument of ``ip_mode_recon(...)``. A
   literal is a recon dict when it has a ``"domain"`` key holding a root (not
   a nested ``dns.domain`` dict) beside a recon section (``domains``, ``dns``,
   ``metadata``, ...), or when it is assigned to ``recon_data`` or
   ``combined_result``. A finding row (``{"domain": host, "url": ...}``) is none.
2. Nothing assigns ``<dict>["metadata"] = ...``: that would drop the stamp.
   Merge into it (``setdefault("metadata", {}).update(...)``).
3. Every graph builder (``_build_*_from_graph``) calls ``ip_mode_recon``.

The runtime half (each builder and each module's own dict really carries the
expanded list) is the SELF_BUILT sweep in
test_regression_partial_ip_mode_leaks.py.
"""
import ast
import sys
from pathlib import Path

import pytest

RECON = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RECON.parent))

SOURCES = sorted(RECON.joinpath("partial_recon_modules").glob("*.py")) + [RECON / "partial_recon.py"]
STAMP = "ip_mode_recon"
RECON_NAMES = {"recon_data", "combined_result"}
RECON_SECTIONS = {"domains", "dns", "metadata", "subdomains", "http_probe", "port_scan",
                  "resource_enum", "js_recon", "urlscan"}


def _is_stamp_call(node) -> bool:
    func = getattr(node, "func", None)
    return isinstance(node, ast.Call) and (
        (isinstance(func, ast.Name) and func.id == STAMP)
        or (isinstance(func, ast.Attribute) and func.attr == STAMP))


def _holds_a_root(node: ast.Dict) -> bool:
    keys = {k.value for k in node.keys if isinstance(k, ast.Constant)}
    return bool(keys & RECON_SECTIONS) and any(
        isinstance(k, ast.Constant) and k.value == "domain" and not isinstance(v, ast.Dict)
        for k, v in zip(node.keys, node.values))


def violations(source: str, filename: str) -> list:
    """Every place in ``source`` that breaks rules 1-3, as ``file:line why``."""
    tree = ast.parse(source, filename=filename)
    parent = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    name = Path(filename).name
    found = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            above = parent.get(node)
            assigned = (isinstance(above, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id in RECON_NAMES for t in above.targets)) or (
                isinstance(above, ast.AnnAssign) and isinstance(above.target, ast.Name)
                and above.target.id in RECON_NAMES)
            if (_holds_a_root(node) or assigned) and not (
                    _is_stamp_call(above) and above.args and above.args[0] is node):
                found.append(f"{name}:{node.lineno} recon dict built without {STAMP}()")
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if (isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant)
                        and target.slice.value == "metadata"):
                    found.append(f"{name}:{node.lineno} replaces metadata (drops the IP-mode stamp)")
        elif (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
              and node.name.startswith("_build_") and node.name.endswith("_from_graph")):
            if not any(_is_stamp_call(inner) for inner in ast.walk(node)):
                found.append(f"{name}:{node.lineno} builder {node.name}() never calls {STAMP}()")
    return found


def _tree_violations() -> list:
    found = []
    for path in SOURCES:
        found.extend(violations(path.read_text(), str(path)))
    return sorted(found)


def test_every_partial_recon_dict_declares_ip_mode():
    offenders = _tree_violations()
    assert not offenders, (
        "These build or reshape a recon dict a scanner or writer receives without the "
        f"IP-mode stamp (helpers.{STAMP}):\n  " + "\n  ".join(offenders))


def test_the_guard_scans_the_builders_and_the_modules():
    names = {p.name for p in SOURCES}
    assert {"graph_builders.py", "osint_enrichment.py", "web_crawling.py",
            "endpoint_ai_classification.py", "partial_recon.py"} <= names
    builders = [n.name for n in ast.walk(ast.parse((RECON / "partial_recon_modules/graph_builders.py").read_text()))
                if isinstance(n, ast.FunctionDef) and n.name.startswith("_build_") and n.name.endswith("_from_graph")]
    assert len(builders) >= 7, builders


@pytest.mark.parametrize("source, why", [
    ('def run(roots):\n    recon_data = {"domain": roots[0], "dns": {}}\n    return recon_data\n',
     "recon dict built without"),
    ('def run(x):\n    scan({"domain": x, "domains": [x]})\n', "recon dict built without"),
    ('def run(s):\n    recon_data: dict = {"http_probe": {"by_url": {}}}\n', "recon dict built without"),
    ('def run(s):\n    combined_result = {"metadata": {}}\n', "recon dict built without"),
    ('def run(s):\n    recon_data = ip_mode_recon({"domain": "r"}, s)\n    recon_data["metadata"] = {}\n',
     "replaces metadata"),
    ('def _build_x_from_graph(roots):\n    return dict(domain=roots[0])\n', "never calls"),
    ('def run(s):\n    recon_data = other({"domain": "r", "dns": {}})\n', "recon dict built without"),
])
def test_the_guard_catches_each_broken_shape(source, why):
    found = violations(source, "broken_module.py")
    assert found and all(why in f or "recon dict built without" in f for f in found), found
    assert any(why in f for f in found), found


@pytest.mark.parametrize("source", [
    'def run(roots, s):\n    recon_data = ip_mode_recon({"domain": roots[0]}, s)\n',
    'def run(roots, s):\n    return helpers.ip_mode_recon({"domain": roots[0], "dns": {"domain": {}}}, s)\n',
    # A nested dns.domain dict and a finding row are no recon dicts.
    'def run(r):\n    r.setdefault("dns", {"domain": {"ips": {}}, "subdomains": {}})\n',
    'def run(h, u):\n    rows.append({"domain": h, "source": "gau", "url": u})\n',
    'def run(r):\n    r.setdefault("metadata", {}).update({"scope_mode": "exact"})\n',
    'def _build_x_from_graph(roots, s):\n    recon_data = ip_mode_recon({"domain": roots[0]}, s)\n'
    '    recon_data["metadata"]["roe"] = {}\n    return recon_data\n',
])
def test_the_guard_accepts_a_stamped_dict(source):
    assert violations(source, "good_module.py") == []


# ---------------------------------------------------------------------------
# The stamp itself
# ---------------------------------------------------------------------------

@pytest.fixture
def helpers():
    from recon.partial_recon_modules import helpers as h
    yield h
    h.set_run_ip_targets({})


def test_the_stamp_declares_the_expanded_targets_in_ip_mode(helpers):
    settings = {"IP_MODE": True, "TARGET_IPS": ["203.0.113.0/30", "203.0.113.9", "2001:db8::1/128"]}
    data = helpers.ip_mode_recon({"domain": "ip-targets.p1", "metadata": {"roe": {}}}, settings)
    assert data["metadata"] == {"roe": {}, "ip_mode": True,
                                "expanded_ips": ["203.0.113.1", "203.0.113.2", "203.0.113.9", "2001:db8::1"]}


def test_the_stamp_leaves_a_domain_dict_untouched(helpers):
    data = {"domain": "example.com", "metadata": {"include_root_domain": True}}
    assert helpers.ip_mode_recon(data, {"IP_MODE": False, "TARGET_IPS": ["203.0.113.9"]}) is data
    assert data == {"domain": "example.com", "metadata": {"include_root_domain": True}}
    assert helpers.ip_mode_recon({"domain": "example.com"}) == {"domain": "example.com"}


def test_the_stamp_without_settings_uses_the_runs_list(helpers):
    helpers.set_run_ip_targets({"IP_MODE": True, "TARGET_IPS": ["203.0.113.9"]})
    assert helpers.ip_mode_recon({"domain": "ip-targets.p1"})["metadata"] == {
        "ip_mode": True, "expanded_ips": ["203.0.113.9"]}


def test_the_expanded_list_drops_the_roe_exclusions_and_is_built_once(helpers, monkeypatch):
    settings = {"IP_MODE": True, "TARGET_IPS": ["203.0.113.0/29", "203.0.113.2", "not-an-ip/99"],
                "ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["203.0.113.4/31", "  "]}
    first = helpers.ip_mode_target_list(settings)
    assert first == ["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.6"]
    import ipaddress
    monkeypatch.setattr(ipaddress, "ip_network", lambda *_a, **_k: pytest.fail("rebuilt"))
    assert helpers.ip_mode_target_list(dict(settings)) == first
    first.append("mutated")
    assert "mutated" not in helpers.ip_mode_target_list(settings)
    assert helpers.ip_mode_target_list({"IP_MODE": False}) is None


def test_the_expanded_list_memo_is_bounded(helpers):
    for n in range(helpers._EXPANDED_TARGETS_MAX + 3):
        helpers.ip_mode_target_list({"IP_MODE": True, "TARGET_IPS": [f"203.0.113.{n + 1}"]})
    assert len(helpers._EXPANDED_TARGETS) <= helpers._EXPANDED_TARGETS_MAX

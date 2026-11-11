"""Every `docker run` under recon/ goes through `run_tool_container` (R-9).

A `docker run` started with `subprocess.run(..., timeout=...)` or a `Popen` the
caller kills on a deadline leaves its container scanning: only the docker CLI
dies, and the daemon keeps the container. `docker_helpers.run_tool_container`
names the container and kills it by that name when the timeout fires.

This test finds every argv literal that starts with "docker", "run" in the
recon source and accepts it when the function holding it calls
`run_tool_container`, or when a function that calls `run_tool_container` also
calls it (a command builder). Everything else must be in NOT_YET_MIGRATED,
by function and with its count, so a new raw `docker run` fails here, and a
migrated one fails until its entry is removed: the list only shrinks.
"""
from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

RECON = Path(__file__).resolve().parent.parent
HELPER = "run_tool_container"

# (file under recon/, function holding the argv): how many argv literals it has.
NOT_YET_MIGRATED = {
    # The two leaks R-9 names that part A left: naabu's Popen().communicate(timeout=1800)
    # returns without a kill, and tlsx's timeout kills only the docker CLI.
    ("main_recon_modules/port_scan.py", "build_naabu_command"): 1,
    ("main_recon_modules/tls_scan.py", "build_tlsx_command"): 1,

    # Named already, and killed by that name on their own deadline.
    ("main_recon_modules/http_probe.py", "build_httpx_command"): 1,  # _stop_httpx_at_budget
    ("helpers/nuclei_helpers.py", "build_nuclei_command"): 1,  # vuln_scan._nuclei_kill_container
    ("helpers/js_recon/trufflehog_bridge.py", "build_argv"): 1,
    # Streaming loops: tool_container_name + kill_container on every stop.
    ("helpers/resource_enum/hakrawler_helpers.py", "_crawl_single_url"): 1,
    ("helpers/resource_enum/katana_helpers.py", "run_katana_crawler"): 1,
    ("helpers/takeover_helpers.py", "build_baddns_command"): 1,  # subdomain_takeover kills it
    # The `nuclei -ut` updater (named, killed) and the alpine template count (30 s, unnamed).
    ("helpers/docker_helpers.py", "ensure_templates_volume"): 2,

    # Unnamed: a timeout kills only the docker CLI.
    ("helpers/resource_enum/kiterunner_helpers.py", "detect_kiterunner_methods"): 2,
    ("main_recon_modules/uncover_enrich.py", "_run_uncover_docker"): 1,
    ("main_recon_modules/domain_recon.py", "run_subfinder"): 1,
    ("main_recon_modules/domain_recon.py", "run_amass"): 1,
    # puredns, and the alpine `rm` that cleans its root-owned files (60 s).
    ("main_recon_modules/domain_recon.py", "run_puredns_resolve"): 2,
    # The alpine `rm` that cleans nuclei's root-owned temp files, with no timeout.
    ("main_recon_modules/vuln_scan.py", "run_vuln_scan"): 1,
}


def _argv_literals(tree):
    """(function name or "<module>", line) of each list/tuple opening with "docker", "run"."""
    found = []

    def visit(node, func):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func = node.name
        if isinstance(node, (ast.List, ast.Tuple)) and len(node.elts) >= 2:
            head = [e.value if isinstance(e, ast.Constant) else None for e in node.elts[:2]]
            if head == ["docker", "run"]:
                found.append((func, node.lineno))
        for child in ast.iter_child_nodes(node):
            visit(child, func)

    visit(tree, "<module>")
    return found


def _called_names(func_node):
    names = set()
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                names.add(f.id)
            elif isinstance(f, ast.Attribute):
                names.add(f.attr)
    return names


def _recon_sources() -> dict:
    """{path under recon/: source} for the recon code, tests excluded."""
    sources = {}
    for path in sorted(RECON.rglob("*.py")):
        rel = path.relative_to(RECON).as_posix()
        if not (rel.startswith("tests/") or rel == "conftest.py"):
            sources[rel] = path.read_text(encoding="utf-8")
    return sources


def _scan(sources: dict):
    """(every argv literal as (path, func, line), the raw ones counted by (path, func))."""
    literals = []
    helper_callers = []     # (name, call names) of every function that calls the helper
    for rel, text in sources.items():
        tree = ast.parse(text, filename=rel)
        literals += [(rel, func, line) for func, line in _argv_literals(tree)]
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                calls = _called_names(node)
                if HELPER in calls:
                    helper_callers.append((node.name, calls))

    def through_helper(func):
        return any(func == name or func in calls for name, calls in helper_callers)

    raw = Counter((rel, func) for rel, func, _ in literals if not through_helper(func))
    return literals, raw


def _unlisted(literals, raw, allowed):
    lines = {}
    for rel, func, line in literals:
        lines.setdefault((rel, func), []).append(str(line))
    return [f"recon/{rel}:{','.join(lines[(rel, func)])} in {func}()"
            for (rel, func), n in sorted(raw.items()) if n > allowed.get((rel, func), 0)]


def test_the_scan_sees_every_known_docker_run():
    """Guards the scanner itself: if it went blind, every other check here would pass."""
    literals, raw = _scan(_recon_sources())
    funcs = {(rel, func) for rel, func, _ in literals}
    assert ("cache_scan/wcvs_runner.py", "build_wcvs_command") in funcs
    assert ("graphql_scan/misconfig.py", "run_graphql_cop") in funcs
    assert set(NOT_YET_MIGRATED) <= funcs
    assert len(literals) >= 25


def test_every_docker_run_goes_through_run_tool_container():
    new = _unlisted(*_scan(_recon_sources()), NOT_YET_MIGRATED)
    assert not new, (
        "a `docker run` that does not go through docker_helpers.run_tool_container: its "
        "container keeps running when the timeout kills the docker CLI (R-9). Run it with "
        "run_tool_container(cmd, tool=..., timeout=...) and parse what it returns:\n  "
        + "\n  ".join(new))


def test_the_not_yet_migrated_list_only_shrinks():
    _, raw = _scan(_recon_sources())
    stale = [f"recon/{rel} {func}(): listed {n}, found {raw.get((rel, func), 0)}"
             for (rel, func), n in sorted(NOT_YET_MIGRATED.items()) if raw.get((rel, func), 0) < n]
    assert not stale, (
        "these sites were migrated to run_tool_container or removed; lower or drop their "
        "NOT_YET_MIGRATED entry:\n  " + "\n  ".join(stale))


def test_wcvs_and_graphql_cop_go_through_the_helper():
    literals, raw = _scan(_recon_sources())
    mine = {(rel, func) for rel, func, _ in literals
            if rel in ("cache_scan/wcvs_runner.py", "graphql_scan/misconfig.py")}
    assert mine and not mine & set(raw)


# --- the checker, on code written for it ---------------------------------------------------

_BUILDER_AND_RUNNER = '''
def build_x(image):
    return ["docker", "run", "--rm", image]

def run_x(image):
    return run_tool_container(build_x(image), tool="x", timeout=5)
'''

_RAW = '''
import subprocess

def scan_y(image):
    subprocess.run(("docker", "run", "--rm", image), timeout=5)
'''


def test_a_builder_whose_command_the_helper_runs_passes():
    literals, raw = _scan({"x.py": _BUILDER_AND_RUNNER})
    assert [(f, l) for _, f, l in literals] == [("build_x", 3)] and not raw


def test_a_new_raw_docker_run_fails_and_an_extra_one_in_a_listed_function_too():
    literals, raw = _scan({"y.py": _RAW})
    assert _unlisted(literals, raw, {}) == ["recon/y.py:5 in scan_y()"]
    assert _unlisted(literals, raw, {("y.py", "scan_y"): 1}) == []
    two = _RAW + '    subprocess.run(["docker", "run", "alpine"], timeout=5)\n'
    assert _unlisted(*_scan({"y.py": two}), {("y.py", "scan_y"): 1}) == ["recon/y.py:5,6 in scan_y()"]


def test_a_docstring_or_comment_naming_docker_run_is_not_a_site():
    text = '"""subprocess.run(["docker", "run", ...])"""\n# ["docker", "run"]\nX = "docker run"\n'
    assert _scan({"z.py": text})[0] == []

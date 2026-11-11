"""Every `docker run` under recon/ goes through `run_tool_container` (R-9).

A `docker run` started with `subprocess.run(..., timeout=...)` or a `Popen` the
caller kills on a deadline leaves its container scanning: only the docker CLI
dies, and the daemon keeps the container. `docker_helpers.run_tool_container`
names the container and kills it by that name when the timeout fires.

This test finds every argv literal that starts with "docker", "run" in the
recon source and accepts it when the function holding it calls
`run_tool_container`, or when a function that calls `run_tool_container` also
calls it (a command builder).

A tool whose output is streamed (katana, hakrawler, Nuclei's passes, the
TruffleHog sidecar) or read by a `Popen` the caller times out (naabu, tlsx,
httpx) cannot use the helper, so it is accepted when it is named and killed:
the function holding the argv puts a `--name` in it (or calls
`tool_container_name`), and every function of the run that stops the docker
CLI (a `TimeoutExpired` handler, a `.kill()` or `.terminate()`) also kills the
container by name, itself or through a function it calls (`kill_container`,
or a `docker kill` argv). The run is the holding function and its callers;
the kill may sit up to two calls below them (a watchdog's helper).

Everything else must be in NOT_YET_MIGRATED, by function and with its count,
so a new raw `docker run` fails here, and a migrated one fails until its entry
is removed: the list only shrinks.
"""
from __future__ import annotations

import ast
import functools
from collections import Counter
from pathlib import Path

RECON = Path(__file__).resolve().parent.parent
HELPER = "run_tool_container"
NAMER = "tool_container_name"
KILLER = "kill_container"

# (file under recon/, function holding the argv): how many argv literals it has.
# Empty: every `docker run` under recon/ goes through the helper or is named and killed.
NOT_YET_MIGRATED: dict = {}


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


def _call_name(call) -> str:
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""


def _called_names(func_node):
    return {_call_name(node) for node in ast.walk(func_node) if isinstance(node, ast.Call)} - {""}


def _head(node, n):
    if not isinstance(node, (ast.List, ast.Tuple)):
        return []
    return [e.value if isinstance(e, ast.Constant) else None for e in node.elts[:n]]


def _names_container(func_node) -> bool:
    """The function puts a `--name` in a docker argv, or mints a run-id name."""
    for node in ast.walk(func_node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and (node.value == "--name" or node.value.startswith("--name=")):
            return True
        if isinstance(node, ast.Call) and _call_name(node) == NAMER:
            return True
    return False


def _kills_container(func_node) -> bool:
    """`kill_container(...)`, a `["docker", "kill", ...]` argv, or `["kill", ...]`
    handed to a docker CLI wrapper (trufflehog_bridge._docker)."""
    for node in ast.walk(func_node):
        if _head(node, 2) == ["docker", "kill"]:
            return True
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name == KILLER:
                return True
            if "docker" in name.lower() and node.args and _head(node.args[0], 1) == ["kill"]:
                return True
    return False


def _stops_cli(func_node) -> bool:
    """The function stops a process: it catches a `TimeoutExpired` or calls
    `.kill()` / `.terminate()` with no argument (a Popen, not `os.kill`)."""
    for node in ast.walk(func_node):
        if isinstance(node, ast.ExceptHandler) and node.type is not None:
            kinds = node.type.elts if isinstance(node.type, ast.Tuple) else [node.type]
            if any(getattr(k, "id", getattr(k, "attr", "")) == "TimeoutExpired" for k in kinds):
                return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in ("kill", "terminate") and not node.args:
            return True
    return False


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
    functions = {}          # name -> every FunctionDef of that name
    for rel, text in sources.items():
        tree = ast.parse(text, filename=rel)
        literals += [(rel, func, line) for func, line in _argv_literals(tree)]
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.setdefault(node.name, []).append(node)
    calls = {name: set().union(*(_called_names(n) for n in nodes))
             for name, nodes in functions.items()}
    called_by = {}
    for name, called in calls.items():
        for callee in called:
            called_by.setdefault(callee, []).append(name)
    kills = {name: any(_kills_container(n) for n in nodes) for name, nodes in functions.items()}

    def through_helper(func):
        return HELPER in calls.get(func, ()) or any(HELPER in calls[c]
                                                    for c in called_by.get(func, ()))

    def reaches_kill(func, depth):
        if kills.get(func):
            return True
        return depth > 0 and any(reaches_kill(c, depth - 1)
                                 for c in calls.get(func, ()) if c in functions)

    def named_and_killed(func):
        if not any(_names_container(n) for n in functions.get(func, ())):
            return False
        run = [func, *called_by.get(func, ())]
        stoppers = [f for f in run if any(_stops_cli(n) for n in functions.get(f, ()))]
        return (any(reaches_kill(f, 2) for f in run)
                and all(reaches_kill(f, 1) for f in stoppers))

    raw = Counter((rel, func) for rel, func, _ in literals
                  if not through_helper(func) and not named_and_killed(func))
    return literals, raw


@functools.lru_cache(maxsize=None)
def _repo_scan(hide_helper: bool = False):
    """`_scan` of the recon code, parsed once per process. ``hide_helper``:
    as if no function called run_tool_container, to check the other rule alone."""
    sources = _recon_sources()
    if hide_helper:
        sources = {rel: text.replace(HELPER, "_not_the_helper") for rel, text in sources.items()}
    return _scan(sources)


def _unlisted(literals, raw, allowed):
    lines = {}
    for rel, func, line in literals:
        lines.setdefault((rel, func), []).append(str(line))
    return [f"recon/{rel}:{','.join(lines[(rel, func)])} in {func}()"
            for (rel, func), n in sorted(raw.items()) if n > allowed.get((rel, func), 0)]


def test_the_scan_sees_every_known_docker_run():
    """Guards the scanner itself: if it went blind, every other check here would pass."""
    literals, raw = _repo_scan()
    funcs = {(rel, func) for rel, func, _ in literals}
    assert ("cache_scan/wcvs_runner.py", "build_wcvs_command") in funcs
    assert ("graphql_scan/misconfig.py", "run_graphql_cop") in funcs
    assert set(NOT_YET_MIGRATED) <= funcs
    assert len(literals) >= 25


def test_every_docker_run_goes_through_run_tool_container():
    new = _unlisted(*_repo_scan(), NOT_YET_MIGRATED)
    assert not new, (
        "a `docker run` that does not go through docker_helpers.run_tool_container: its "
        "container keeps running when the timeout kills the docker CLI (R-9). Run it with "
        "run_tool_container(cmd, tool=..., timeout=...) and parse what it returns; a streamed "
        "run names its container and calls kill_container(name) wherever it stops the CLI:\n  "
        + "\n  ".join(new))


def test_the_not_yet_migrated_list_only_shrinks():
    _, raw = _repo_scan()
    stale = [f"recon/{rel} {func}(): listed {n}, found {raw.get((rel, func), 0)}"
             for (rel, func), n in sorted(NOT_YET_MIGRATED.items()) if raw.get((rel, func), 0) < n]
    assert not stale, (
        "these sites were migrated to run_tool_container or removed; lower or drop their "
        "NOT_YET_MIGRATED entry:\n  " + "\n  ".join(stale))


#: The sites that cannot use the helper (their output is streamed, or read by a
#: Popen the caller times out), each named and killed by that name on its stop.
NAMED_AND_KILLED = {
    ("main_recon_modules/port_scan.py", "build_naabu_command"),
    ("main_recon_modules/tls_scan.py", "build_tlsx_command"),
    ("main_recon_modules/http_probe.py", "build_httpx_command"),
    ("helpers/resource_enum/katana_helpers.py", "run_katana_crawler"),
    ("helpers/resource_enum/hakrawler_helpers.py", "_crawl_single_url"),
    ("helpers/js_recon/trufflehog_bridge.py", "build_argv"),
}


def test_the_streamed_sites_are_named_and_killed():
    """Checked with the helper rule out of the way, so a site that lost its
    name or its kill cannot hide behind a caller that uses the helper."""
    literals, _ = _repo_scan()
    assert NAMED_AND_KILLED <= {(rel, func) for rel, func, _ in literals}
    _, raw = _repo_scan(hide_helper=True)
    assert not NAMED_AND_KILLED & set(raw), sorted(NAMED_AND_KILLED & set(raw))


def test_nucleis_streamed_passes_are_named_and_killed_too():
    """build_nuclei_command passes through the takeover's helper call; its
    vuln-scan passes stream and are killed by their name at the runtime cap."""
    _, raw = _repo_scan(hide_helper=True)
    assert ("helpers/nuclei_helpers.py", "build_nuclei_command") not in raw


def test_wcvs_and_graphql_cop_go_through_the_helper():
    literals, raw = _repo_scan()
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


_STREAMED = '''
import subprocess

def crawl(image):
    name = tool_container_name("x")
    cmd = ["docker", "run", "--rm", "--name", name, image]
    process = subprocess.Popen(cmd)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        kill_container(name)
'''

_BUILDER_AND_STOPPER = '''
import subprocess

def build_x(image, container_name=None):
    cmd = ["docker", "run", "--rm"]
    if container_name:
        cmd.extend(["--name", container_name])
    return cmd + [image]

def _stop_x(process, name):
    process.kill()
    subprocess.run(["docker", "kill", name], timeout=15)

def run_x(image):
    process = subprocess.Popen(build_x(image, container_name="x-1"))
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        _stop_x(process, "x-1")
'''


def test_a_streamed_run_named_and_killed_on_its_timeout_passes():
    literals, raw = _scan({"s.py": _STREAMED})
    assert [f for _, f, _ in literals] == ["crawl"] and not raw


def test_a_builder_whose_runner_kills_the_container_through_a_stop_helper_passes():
    literals, raw = _scan({"b.py": _BUILDER_AND_STOPPER})
    assert [f for _, f, _ in literals] == ["build_x"] and not raw


def test_a_named_run_whose_timeout_kills_only_the_cli_fails():
    text = _STREAMED.replace("        kill_container(name)\n", "")
    assert _unlisted(*_scan({"s.py": text}), {}) == ["recon/s.py:6 in crawl()"]


def test_an_unnamed_run_fails_even_when_it_kills_something():
    text = _STREAMED.replace('"--name", name, ', "")
    text = text.replace('    name = tool_container_name("x")\n', '    name = "x"\n')
    assert _unlisted(*_scan({"s.py": text}), {}) == ["recon/s.py:6 in crawl()"]


def test_a_second_caller_that_kills_only_the_cli_fails_the_builder():
    text = _BUILDER_AND_STOPPER + '''
def run_again(image):
    process = subprocess.Popen(build_x(image, container_name="x-2"))
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
'''
    assert _unlisted(*_scan({"b.py": text}), {}) == ["recon/b.py:5 in build_x()"]

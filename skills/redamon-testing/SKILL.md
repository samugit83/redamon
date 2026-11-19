---
name: redamon-testing
description: >
  How RedAmon tests actually run and how to author them: the per-file Docker
  gate, the unit/integration/live tiers, and the failure modes that make a
  green run a lie.
  Trigger: editing any test_*.py, *.test.ts(x) or tests/*.sh; a test that is
  red, skipped or xfailed; a request to "run the tests", "make it green" or
  check coverage; editing redamon.sh cmd_test, tooling/scripts/pytest_isolated.py, any
  conftest.py or any pytest.ini.
license: MIT
metadata:
  author: redamon
  version: "1.1.0"
  scope: [root]
  auto_invoke:
    - "Adding or editing a test file in any section"
    - "Investigating a red, skipped or xfailed test"
    - "Changing test tiers, conftest.py, pytest.ini, or the runner in redamon.sh"
    - "Checking or ratcheting a coverage floor"
---

## When to Use

- Writing or fixing a test anywhere in the repo, or deciding where a new test goes.
- A test is red/skipped/xfailed and you must decide whether it is real.
- You were asked to run the suite or verify a change "works".

The repo-wide rule "never validate with host `pytest`, use the Docker gate" lives
in the root [AGENTS.md](../../AGENTS.md) CRITICAL RULES; this skill is everything
*after* that: isolation, tiers, and how to write a test that asserts something.

---

## Critical Rules

- **NEVER run `pytest` across a whole tree in one process.** Many tests stub
  `langchain`/`langgraph` into `sys.modules` and bake tool objects against a fake
  `@tool` at import time, so whichever file collects first decides for all of
  them. You get **phantom failures in files you never touched** (classically
  `a coroutine was expected, got <MagicMock>`). Run `./redamon.sh test`, or one
  file / node id. The gate exists for this: [tooling/scripts/pytest_isolated.py](../../tooling/scripts/pytest_isolated.py)
  runs each FILE in its own subprocess.
- **NEVER "fix" source because a test went red in a multi-file run.** Re-run that
  one file in isolation first; if it passes alone the failure was pollution, not a bug.
- **NEVER `print("SKIP..."); return` to skip a test.** pytest records that as
  **PASSED** while asserting nothing. Use `self.skipTest(...)` inside a
  `TestCase` or `pytest.skip(...)` in a bare function.
- **NEVER read a green gate as "the live checks passed".** A self-skipping test
  that needs a service prints SKIP and exits 0, and the gate containers have no
  Neo4j, so the live-graph schema checks in
  [recon/tests/test_schema_catalog.py](../../recon/tests/test_schema_catalog.py)
  SKIP in every gate run. Their hermetic counterparts in
  [recon/tests/test_graph_writes_documented.py](../../recon/tests/test_graph_writes_documented.py)
  do run. Neither sees everything: the code scan cannot see the ~22 labels
  written with `SET n += $props` (the names are built in Python and appear in no
  file), and the live graph cannot see a feature this deployment never ran. After
  a schema change, run the live one against a stack before believing it.
- **NEVER rewrite an assertion so it passes.** If a test reveals a real bug, mark
  it `@pytest.mark.xfail(strict=True, reason=...)` and say so. Tests must not enshrine bugs.
- **NEVER put a recon test in the root [tests/](../../tests/) folder.** Root
  `tests/` runs in the **agent** image; recon files there must be listed in
  `_ROOT_RECON_TESTS` in [redamon.sh](../../redamon.sh) or they run
  against the wrong image and fail on imports. New recon tests go in [recon/tests/](../../recon/tests/).
- **NEVER add a third-party import to a test without checking it is in the section
  image.** Only `pytest`, `pytest-cov`, `pytest-xdist`, `pytest-asyncio`
  ([requirements-test.txt](../../requirements-test.txt)) are guaranteed; anything
  else errors the whole file at collection. Prefer `unittest.mock` and the stdlib.
- **ALWAYS assert behaviour, not execution.** For a tool wrapper, assert **both**
  the parsed result **and** the command that was built. Verify the patch target
  against the source (`recon/tests/test_arjun.py` broke when `subprocess.run`
  became `Popen` and the mocks kept targeting `run`).
- **ALWAYS make a test that needs a stack, binary, service or git HEAD skip
  cleanly.** A hard failure on a missing prerequisite is a bug in the test.

---

## Assert the command a wrapper BUILDS (the direction most often skipped)

```python
from recon.helpers.nuclei_helpers import build_nuclei_command   # the seam under test

cmd = build_nuclei_command(targets_file="/tmp/t.txt", output_file="/tmp/o.jsonl",
                           docker_image="projectdiscovery/nuclei:latest", dast_mode=True)
assert "-dast" in cmd            # the flag we asked for is present
assert cmd.count("-dast") == 1   # and not duplicated by a second code path
```

Reference: [recon/tests/test_nuclei_two_pass.py](../../recon/tests/test_nuclei_two_pass.py).
For a wrapper that also parses tool output, mock the tool (patch `subprocess.run`)
and assert **both** the parsed result and the command from `mock_run.call_args`.

## Where a test goes, and its tier

Tier is auto-assigned by filename in each `conftest.py` (live checked first). An
explicit `@pytest.mark.{unit,integration,live}` wins, on the file **or on a single
test** - the gate passes the tier to pytest as `-m`, so an opted-out test inside a
unit-named file really is skipped:

| Filename contains | Tier | Meaning |
| --- | --- | --- |
| `live_`, `_live`, `_smoke`, `smoke_` | live | needs a stack/service; self-skips |
| `_integration.py`, `_skill.py`, `_e2e` | integration | cross-layer / heavy deps |
| anything else | **unit** | hermetic; this is the gate |

| Testing | Put it in | Tier |
| --- | --- | --- |
| recon module / tool wrapper | `recon/tests/` | unit |
| agent graph, nodes, tools, prompts | `agentic/tests/` | unit |
| plugin runner, worker, proxy, SDK | `services/plugin_runner/tests/` (`plugin_runner` section) | unit |
| `graph_db`, `knowledge_base`, `supply_chain_*`, `mcp` | root `tests/` | unit |
| `redamon.sh` / compose / deploy shell logic | `tests/*_test.sh` | bash, **in the gate** (`shell` section) |
| webapp React/TS | next to the source `*.test.ts(x)` | vitest |

---

## Commands

```bash
./redamon.sh test                 # unit gate, every section + webapp vitest; must be 100% green
./redamon.sh test all             # unit + integration (NOT live)
./redamon.sh test coverage        # per-section floor via REDAMON_COV_FLOOR
./agentic/run_tests.sh            # agent section only; per-file isolated
./agentic/run_tests.sh tests/test_foo.py::TestX::test_y   # single node id (already isolated)
```

A section that **cannot run fails the gate** (`unit`, `all`, `coverage`): an unbuilt
image, an absent `webapp/node_modules`, no `tests/*_test.sh` at all, or a shell suite
that exits **77** because an input of its own is missing (python3, PyYAML, git). Build the image (for the
`plugin_runner` section: `docker compose --profile plugins build plugin-runner`), or opt
out on purpose with `REDAMON_TEST_ALLOW_MISSING=<section>` (for a shell suite: `shell`,
or the suite's name), which prints `SKIPPED` so the hole shows in the log. A shell suite
that skips must exit 77, never 0; only a suite that needs a live stack exits 0 on SKIP. A new section therefore breaks every session's gate until
its image exists: build it before adding the section to `_TEST_SECTIONS`.

---

## Resources

- [docs/readmes/README.TESTING.md](../../docs/readmes/README.TESTING.md) - full testing guide + coverage ratchet
- [tooling/scripts/pytest_isolated.py](../../tooling/scripts/pytest_isolated.py) - the per-file isolation gate
- [redamon.sh](../../redamon.sh) `_TEST_SECTIONS` - section/image map, shell + webapp hooks
- Related: root [AGENTS.md](../../AGENTS.md) for the host-pytest / Docker-gate rule

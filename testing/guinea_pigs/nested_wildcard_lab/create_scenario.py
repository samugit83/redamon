#!/usr/bin/env python3
"""Create one scenario's project over MCP, exactly as expected_results.yaml says.

    create_scenario.py <scenario> <name> [--set '<json settings merged on top>']

Every project is an `internal` engagement. Prints PROJECT_ID=<id>, then the
preflight_scope_check verdict (startable, scope groups, silent no-ops).
Starting the scan is run_scan.py's job, after the routing gate.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nwlab_mcp  # noqa: E402

EXPECTED = Path(__file__).resolve().parent / "expected_results.yaml"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("scenario")
    ap.add_argument("name")
    ap.add_argument("--set", default="{}")
    a = ap.parse_args()
    spec = yaml.safe_load(EXPECTED.read_text())["scenarios"][a.scenario]
    create = dict(spec["create"])
    create["settings"] = {**create.get("settings", {}), **json.loads(a.set)}
    out = nwlab_mcp.call("create_project", {
        "name": a.name, "engagementKind": "internal",
        "description": f"Guinea pig: testing/guinea_pigs/nested_wildcard_lab, scenario {a.scenario}",
        **create})
    pid = (out.get("project") or {}).get("id") or out.get("id") or out.get("projectId")
    print(f"PROJECT_ID={pid}")
    pre = nwlab_mcp.call("preflight_scope_check", {"projectId": pid})
    print(json.dumps({k: pre.get(k) for k in ("startable", "problems", "silentNoOps", "warnings")
                      if k in pre}, indent=1, default=str)[:3000])
    scope = pre.get("scope") or {}
    print(json.dumps({"scopeGroups": scope.get("scopeGroups"), "invalidEntries": scope.get("invalidEntries")},
                     indent=1, default=str)[:3000])
    return 0 if pid else 1


if __name__ == "__main__":
    sys.exit(main())

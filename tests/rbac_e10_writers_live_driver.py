"""Writer half of tests/rbac_e10_writers_live.sh (experiment E10, RBAC step 5.11). Not a pytest file.

Fed on stdin to `python3 -` inside the agent container, after the assignments the shell prepends:
MODE ('scan' or 'chain'), USER_ID, PROJECT_ID, HOSTS, STEPS. It drives the real graph writers with
synthetic input, so the two run the Cypher they run in production, on one project, at once:

- scan:  graph_db's update_graph_from_port_scan, one host per call as a scan writes as it goes
         (IP, Port, Service, HAS_PORT, RUNS_SERVICE MERGEs), HOSTS hosts with three ports each;
- chain: the agent's chain writer (orchestrator_helpers/chain_graph_writer.py): one AttackChain
         and STEPS ChainSteps, each linked to the previous one and bridged (STEP_TARGETED) to the
         IP and to every Port 80/443 of the project, which the scan is writing meanwhile.

Hosts are *.e10.rbac.test on 198.51.100.0/24 (TEST-NET-2): no real target, nothing is scanned.
Prints one line `E10_WRITER {"mode", "done", "errors": {<Neo4j code or class>: count}}`; a writer
that could not start prints `"crashed": "<class>"`. Never a credential.
"""
import collections
import json
import os
import re

URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "")
CODE = re.compile(r"Neo\.[A-Za-z]+Error\.[A-Za-z]+\.[A-Za-z]+")

errors = collections.Counter()
done = 0


def classify(item):
    """A Neo4j error code when the exception or the writer's error text carries one."""
    code = getattr(item, "code", None)
    if code:
        return str(code)
    found = CODE.search(str(item))
    if found:
        return found.group(0)
    return "writer_error" if isinstance(item, str) else type(item).__name__


def hosts():
    return [(f"h{i}.e10.rbac.test", f"198.51.100.{i + 1}") for i in range(int(HOSTS))]  # noqa: F821 (prepended)


def run_scan():
    global done
    from graph_db import Neo4jClient

    client = Neo4jClient(URI, NEO4J_USER, NEO4J_PASSWORD)
    try:
        for host, ip in hosts():
            details = [
                {"port": 80, "protocol": "tcp", "service": "http"},
                {"port": 443, "protocol": "tcp", "service": "https"},
                {"port": 8080, "protocol": "tcp", "service": "http-proxy"},
            ]
            data = {
                "metadata": {"root_domain": "e10.rbac.test"},
                "port_scan": {
                    "scan_metadata": {"scan_type": "e10"},
                    "by_ip": {ip: {"ports": [80, 443, 8080], "hostnames": [host]}},
                    "by_host": {host: {"ip": ip, "port_details": details}},
                    "summary": {"total_open_ports": 3},
                },
            }
            try:
                stats = client.update_graph_from_port_scan(data, USER_ID, PROJECT_ID)  # noqa: F821
                # The writer catches per-host failures into its stats instead of raising.
                for err in stats.get("errors", []):
                    errors[classify(err)] += 1
                done += 1
            except Exception as exc:  # noqa: BLE001 - every failure is the measurement
                errors[classify(exc)] += 1
    finally:
        client.close()


def run_chain():
    global done
    from orchestrator_helpers.chain_graph_writer import _write_attack_chain, _write_step

    chain_id = f"e10-chain-{PROJECT_ID}"  # noqa: F821
    _write_attack_chain(
        URI, NEO4J_USER, NEO4J_PASSWORD,
        chain_id=chain_id, user_id=USER_ID, project_id=PROJECT_ID,  # noqa: F821
        title="E10", objective="E10 concurrent writers", attack_path_type="cve_exploit",
        target_host=hosts()[0][1], target_port=80, target_cves=[],
    )
    targets = hosts()
    prev = None
    for i in range(int(STEPS)):  # noqa: F821
        host, ip = targets[i % len(targets)]
        step_id = f"e10-step-{PROJECT_ID}-{i}"  # noqa: F821
        try:
            _write_step(
                URI, NEO4J_USER, NEO4J_PASSWORD,
                step_id=step_id, chain_id=chain_id, prev_step_id=prev,
                user_id=USER_ID, project_id=PROJECT_ID,  # noqa: F821
                iteration=i, phase="informational", tool_name="execute_naabu",
                tool_args_summary=host, thought="", reasoning="", output_summary="", output_analysis="",
                success=True, error_message=None, duration_ms=1,
                extracted_info={"primary_target": ip, "ports": [80, 443]},
            )
            done += 1
            prev = step_id
        except Exception as exc:  # noqa: BLE001 - every failure is the measurement
            errors[classify(exc)] += 1


result = {"mode": MODE}  # noqa: F821
try:
    (run_scan if MODE == "scan" else run_chain)()  # noqa: F821
except Exception as exc:  # noqa: BLE001
    result["crashed"] = type(exc).__name__
result.update({"done": done, "errors": dict(errors)})
print("E10_WRITER " + json.dumps(result, sort_keys=True))

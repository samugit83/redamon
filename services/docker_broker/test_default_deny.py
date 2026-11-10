"""The broker refuses every Docker API call outside its allowlist (R-16, decision D4).

The broker exists for one case: a recon container compromised by the hostile
target data it parses. Before D4 it validated container creation, image pulls
and a list of verbs on existing containers, and forwarded everything else
unchecked: inspecting the orchestrator (its environment holds the master keys),
deleting infrastructure containers, re-tagging the images other projects' scans
run, building images, and the network and volume endpoints.

Every request goes through the broker's real handler to a fake daemon, so
"refused" means a 403 and that the daemon never saw the request.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import broker  # noqa: E402
from mock_daemon import INFRA, Daemon, created_id, request_bytes, run_through_broker, status_of  # noqa: E402

V = "/v1.56"
OWNED = "redamon-jsth-1a2b3c4d-5e6f7a8b"
OWNED_LABELS = {broker._OWNER_LABEL: "1"}


def _daemon():
    return Daemon({OWNED: dict(OWNED_LABELS)})


def _one(method, target, body=None, daemon=None):
    daemon = daemon or _daemon()
    [resp], daemon = run_through_broker([request_bytes(method, target, body)], daemon)
    return resp, daemon


REFUSED = [
    # a container the broker did not create
    ("GET", f"{V}/containers/{INFRA}/json", None),             # inspect: returns its environment
    ("DELETE", f"{V}/containers/{INFRA}?force=1", None),
    ("GET", f"{V}/containers/{INFRA}/export", None),
    ("GET", f"{V}/containers/{INFRA}/top", None),
    ("GET", f"{V}/containers/{INFRA}/changes", None),
    ("GET", f"{V}/containers/{INFRA}/stats?stream=0", None),
    ("POST", f"{V}/containers/{INFRA}/exec", {"Cmd": ["env"]}),
    ("GET", f"{V}/containers/{INFRA}/archive?path=/app", None),
    ("POST", f"{V}/containers/{INFRA}/kill", None),
    ("POST", f"{V}/containers/{INFRA}/stop", None),
    # images: everything but pull, list and inspect of a tool image
    ("POST", f"{V}/images/projectdiscovery/nuclei:latest/tag?repo=redamon-recon&tag=latest", None),
    ("POST", f"{V}/images/redamon-recon:latest/push", None),
    ("DELETE", f"{V}/images/redamon-recon:latest?force=1", None),
    ("GET", f"{V}/images/redamon-agent:latest/json", None),      # not a tool image
    ("POST", f"{V}/images/load", b"tarball"),
    ("GET", f"{V}/images/get?names=redamon-agent", None),
    ("POST", f"{V}/build?t=projectdiscovery/naabu:latest", b"tarball"),
    ("POST", f"{V}/commit?container={OWNED}&repo=projectdiscovery/naabu&tag=latest", None),
    # networks and volumes, beyond the names tools use
    ("GET", f"{V}/networks", None),
    ("GET", f"{V}/networks/redamon_default", None),
    ("POST", f"{V}/networks/redamon_default/connect", {"Container": OWNED}),
    ("POST", f"{V}/networks/create", {"Name": "attacker-net", "Driver": "bridge"}),
    ("GET", f"{V}/volumes", None),
    ("GET", f"{V}/volumes/redamon_postgres_data", None),
    ("DELETE", f"{V}/volumes/redamon-osv-db", None),
    ("POST", f"{V}/volumes/create", {"Name": "attacker-vol", "Driver": "local"}),
    ("POST", f"{V}/volumes/prune", None),
    # the rest of the API
    ("GET", f"{V}/events", None),
    ("GET", f"{V}/system/df", None),
    ("POST", f"{V}/containers/prune", None),
    ("POST", f"{V}/images/prune", None),
    ("POST", f"{V}/swarm/init", {}),
    ("GET", f"{V}/secrets", None),
    ("GET", f"{V}/configs", None),
    ("GET", f"{V}/plugins", None),
    ("POST", f"{V}/session", None),
    ("POST", f"{V}/auth", {"username": "x"}),
    ("GET", f"{V}/exec/0123abcd/json", None),
    ("POST", f"{V}/exec/0123abcd/start", {"Detach": False}),
    # an allowlisted path with the wrong method
    ("GET", f"{V}/containers/create", None),
    ("DELETE", f"{V}/images/create", None),
    ("PUT", f"{V}/info", None),
]


@pytest.mark.parametrize("method,target,body", REFUSED,
                         ids=[f"{m} {t.split('?')[0]}" for m, t, _ in REFUSED])
def test_a_call_outside_the_allowlist_is_refused_and_never_reaches_the_daemon(method, target, body, capsys):
    resp, daemon = _one(method, target, body)
    assert status_of(resp) == 403, resp[:200]
    assert b"denied by docker-broker" in resp
    assert not daemon.got(method, target.split("?")[0])
    log = [ln for ln in capsys.readouterr().out.splitlines() if "DENY" in ln]
    assert len(log) == 1, log
    assert method in log[0] and target.split("?")[0] in log[0]


# Verbs a tool never needs, on a container the broker DID create.
@pytest.mark.parametrize("method,verb,body", [
    ("POST", "exec", {"Cmd": ["sh"]}),
    ("POST", "update", {"Memory": 0}),             # would lift the broker's memory cap
    ("PUT", "archive?path=/", b"tar"),
    ("GET", "archive?path=/etc", None),
    ("GET", "export", None),
    ("POST", "rename?name=redamon-agent", None),
    ("POST", "restart", None),
    ("POST", "resize?h=1&w=1", None),
    ("POST", "commit", None),
])
def test_a_verb_tools_never_use_is_refused_even_on_a_broker_owned_container(method, verb, body):
    target = f"{V}/containers/{OWNED}/{verb}"
    resp, daemon = _one(method, target, body)
    assert status_of(resp) == 403
    assert not daemon.got(method, target.split("?")[0])


@pytest.mark.parametrize("method,target", [
    # an encoded "/" or ".." must not make one path look like another
    ("POST", f"{V}/containers/{OWNED}%2F..%2F{INFRA}/kill"),
    ("POST", f"{V}/containers/../containers/{INFRA}/kill"),
    ("GET", f"{V}/images/projectdiscovery/naabu:latest/../../../containers/{INFRA}/json"),
    ("GET", f"{V}/volumes/..%2Fredamon_postgres_data"),
    ("POST", f"/v1.56//containers/{INFRA}/exec"),
])
def test_path_tricks_are_refused(method, target):
    resp, daemon = _one(method, target)
    assert status_of(resp) == 403
    assert not [r for r in daemon.received if r["path"].startswith("/v1.56")]


ALLOWED = [
    ("HEAD", "/_ping"),
    ("GET", "/_ping"),
    ("GET", f"{V}/version"),
    ("GET", f"{V}/info"),
    ("GET", f"{V}/images/json?filters=%7B%22reference%22%3A%7B%22alpine%3Alatest%22%3Atrue%7D%7D"),
    ("POST", f"{V}/images/create?fromImage=docker.io%2Fprojectdiscovery%2Fnaabu&tag=latest"),
    ("GET", f"{V}/images/projectdiscovery/nuclei:latest/json"),
    ("GET", f"{V}/images/redamon-baddns:latest/json"),
    ("GET", f"{V}/volumes/nuclei-templates"),
    ("GET", f"{V}/networks/redamon-supply-chain-net"),
    ("GET", f"{V}/networks/redamon-trufflehog-net"),
    ("GET", f"{V}/containers/json?all=1"),
    ("POST", f"{V}/containers/{OWNED}/kill"),
    ("POST", f"{V}/containers/{OWNED}/stop"),
    ("POST", f"{V}/containers/{OWNED}/pause"),
    ("POST", f"{V}/containers/{OWNED}/unpause"),
    ("POST", f"{V}/containers/{OWNED}/wait?condition=removed"),
    ("POST", f"{V}/containers/{OWNED}/start"),
    ("GET", f"{V}/containers/{OWNED}/logs?stdout=1"),
    ("GET", f"{V}/containers/{OWNED}/json"),
    ("DELETE", f"{V}/containers/{OWNED}?force=1"),
]


@pytest.mark.parametrize("method,target", ALLOWED, ids=[f"{m} {t.split('?')[0]}" for m, t in ALLOWED])
def test_an_allowlisted_call_is_forwarded(method, target):
    resp, daemon = _one(method, target)
    assert status_of(resp) != 403, resp[:200]
    assert daemon.got(method, target.split("?")[0])


def test_volume_and_network_creation_only_for_the_names_tools_use():
    resp, daemon = _one("POST", f"{V}/volumes/create", {"Driver": "local", "Name": "nuclei-templates"})
    assert status_of(resp) != 403 and daemon.got("POST", f"{V}/volumes/create")
    resp, daemon = _one("POST", f"{V}/networks/create", {
        "Name": "redamon-supply-chain-net", "Driver": "bridge", "Scope": "",
        "IPAM": {"Driver": "default", "Options": {}, "Config": []}, "Internal": False,
        "Attachable": False, "Ingress": False, "ConfigOnly": False, "ConfigFrom": None,
        "Options": {}, "Labels": {}})
    assert status_of(resp) != 403 and daemon.got("POST", f"{V}/networks/create")


@pytest.mark.parametrize("body", [
    # a local volume whose options make it a bind mount of the host root,
    # under a name the broker then lets a tool mount read-write
    {"Driver": "local", "Name": "nuclei-templates",
     "DriverOpts": {"type": "none", "o": "bind", "device": "/"}},
    {"Driver": "attacker/plugin", "Name": "nuclei-templates"},
    {"Driver": "local", "Name": "redamon-osv-db"},          # read-only volumes are not created by tools
    {"Driver": "local", "Name": "nuclei-templates", "ClusterVolumeSpec": {"Group": "x"}},
    b"not json",
])
def test_a_dangerous_volume_create_is_refused(body):
    resp, daemon = _one("POST", f"{V}/volumes/create", body)
    assert status_of(resp) == 403
    assert not daemon.got("POST", f"{V}/volumes/create")


@pytest.mark.parametrize("body", [
    {"Name": "redamon-supply-chain-net", "Driver": "macvlan", "Options": {"parent": "eth0"}},
    {"Name": "redamon-supply-chain-net", "Driver": "bridge",
     "Options": {"com.docker.network.bridge.name": "docker0"}},
    {"Name": "redamon-supply-chain-net", "Driver": "bridge", "ConfigFrom": {"Network": "redamon_default"}},
    {"Name": "redamon-supply-chain-net", "Driver": "bridge", "Ingress": True},
    {"Name": "redamon-supply-chain-net", "Driver": "bridge", "Scope": "swarm"},
    b"not json",
])
def test_a_dangerous_network_create_is_refused(body):
    resp, daemon = _one("POST", f"{V}/networks/create", body)
    assert status_of(resp) == 403
    assert not daemon.got("POST", f"{V}/networks/create")


def test_a_docker_run_is_allowed_end_to_end_and_its_container_is_then_owned():
    """create -> attach -> wait -> start, the order Docker CLI 29 uses."""
    create = request_bytes("POST", f"{V}/containers/create?name=redamon-nuclei-x",
                           {"Image": "projectdiscovery/nuclei:latest", "HostConfig": {"AutoRemove": True}})
    steps = [
        request_bytes("HEAD", "/_ping"),
        create,
        lambda r: request_bytes("POST", f"{V}/containers/{created_id(r[1])}/attach?stderr=1&stdout=1&stream=1"),
        lambda r: request_bytes("POST", f"{V}/containers/{created_id(r[1])}/wait?condition=removed"),
        lambda r: request_bytes("POST", f"{V}/containers/{created_id(r[1])}/start"),
        request_bytes("POST", f"{V}/containers/redamon-nuclei-x/kill"),
    ]
    responses, daemon = run_through_broker(steps)
    assert [status_of(r) for r in responses] == [200, 201, 101, 200, 200, 200]
    assert daemon.got("POST", f"{V}/containers/redamon-nuclei-x/kill")

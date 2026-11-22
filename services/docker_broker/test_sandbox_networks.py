"""No tool container joins a per-user sandbox network (SBK round 9).

The broker refused only a `container:` network mode, so a tool container it
created (one that may get NET_RAW and NET_ADMIN) could join a sandbox network
`redamon-sbx-<key>` by name, by id or by id prefix, at create (`NetworkMode`,
an `EndpointsConfig` entry, its `NetworkID`): from there it reaches that
sandbox's listeners and can spoof the agent's link to it. And a network create
took any IPAM subnet, so a scan container could take the sandbox pool
(10.214.0.0/16) and leave no subnet for a sandbox. Now a create naming a
sandbox network, by its prefix or as the daemon resolves the reference (its
name, its `redamon.sandbox` label, a subnet in the pool), and a network create
with an address in the pool, are refused; a connect is off the allowlist.

The prefix, the label and the pool are the contract's
(recon_orchestrator/sandbox_contract.py), pinned below.
"""
import asyncio
import importlib.util
import ipaddress
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import broker  # noqa: E402
from mock_daemon import ToolDaemon, call, request_bytes, serve_broker, status_of  # noqa: E402

V = "/v1.57"
HDR = ("X-Redamon-Run: full_recon:cmprojnet0000000000:runnet",)
SBX = "redamon-sbx-0123456789abcdef"
SBX_ID = "5b" * 32
OTHER_ID = "7c" * 32
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONTRACT = os.path.join(_REPO, "recon_orchestrator", "sandbox_contract.py")


@pytest.fixture(autouse=True)
def _fresh_log_marks(monkeypatch):
    monkeypatch.setattr(broker, "_log_marks", {}, raising=False)


class NetDaemon(ToolDaemon):
    """ToolDaemon plus networks found as the daemon finds them: a full id, a
    name, then a unique id prefix."""

    def __init__(self):
        super().__init__()
        self.nets = {
            SBX_ID: {"Name": SBX, "Id": SBX_ID, "Labels": {"redamon.sandbox": "true"},
                     "IPAM": {"Config": [{"Subnet": "10.214.0.16/28", "Gateway": "10.214.0.17"}]}},
            OTHER_ID: {"Name": "redamon-trufflehog-net", "Id": OTHER_ID, "Labels": {},
                       "IPAM": {"Config": [{"Subnet": "172.30.0.0/16"}]}},
            "6d" * 32: {"Name": "redamon-supply-chain-net", "Id": "6d" * 32, "Labels": {},
                        "IPAM": {"Config": [{"Subnet": "10.214.4.0/24"}]}},       # an old net in the pool
            "8e" * 32: {"Name": "unlabelled-net", "Id": "8e" * 32, "Labels": {},
                        "IPAM": {"Config": [{"Subnet": "10.214.9.0/28"}]}},
        }

    def net(self, ref):
        if ref in self.nets:
            return self.nets[ref]
        named = [n for n in self.nets.values() if n["Name"] == ref]
        if named:
            return named[0]
        hits = [n for i, n in self.nets.items() if i.startswith(ref)]
        return hits[0] if len(hits) == 1 else None

    async def _answer(self, reader, writer, method, path, query, body):
        if method == "GET" and path.split("/")[-2:-1] == ["networks"] or \
                method == "GET" and path.startswith("/networks/"):
            doc = self.net(path.rsplit("/", 1)[-1])
            return self._send(writer, 404, {"message": "network not found"}) if doc is None else \
                self._send(writer, 200, doc)
        return await super()._answer(reader, writer, method, path, query, body)


def _send(daemon, raw):
    async def go():
        sock, close = await serve_broker(daemon)
        try:
            return await call(sock, raw)
        finally:
            await close()
    return asyncio.run(asyncio.wait_for(go(), 30))


def _create(hc=None, net=None, image="alpine"):
    body = {"Image": image, "HostConfig": hc or {}}
    if net is not None:
        body["NetworkingConfig"] = {"EndpointsConfig": net}
    return request_bytes("POST", f"{V}/containers/create", body, headers=HDR)


SANDBOX_REFS = [
    ({"NetworkMode": SBX}, None),
    ({"NetworkMode": SBX_ID}, None),
    ({"NetworkMode": SBX_ID[:12]}, None),
    ({"NetworkMode": "redamon-sbx-ffffffffffffffff"}, None),          # by the prefix, before it exists
    ({}, {SBX: {}}),
    ({"NetworkMode": "default"}, {"default": {}, SBX_ID[:12]: {}}),
    ({"NetworkMode": "default"}, {"default": {"NetworkID": SBX_ID}}),
    ({"NetworkMode": "unlabelled-net"}, None),                          # a subnet in the pool
    ({"NetworkMode": "redamon-supply-chain-net"}, None),                # a tool net someone put in the pool
    ({"NetworkMode": "no-such-net"}, None),                             # nothing the daemon knows
    ({"NetworkMode": "a/../b"}, None),                                  # not a network reference at all
    ({"networkmode": SBX}, None),                                       # the key in another case
]


@pytest.mark.parametrize("hc,net", SANDBOX_REFS, ids=[str(i) for i in range(len(SANDBOX_REFS))])
def test_a_create_that_names_a_sandbox_network_is_refused(hc, net):
    daemon = NetDaemon()
    out = _send(daemon, _create(hc, net))
    assert status_of(out) == 403, out[:300]
    assert not daemon.got("POST", f"{V}/containers/create")


@pytest.mark.parametrize("hc,net", [
    ({"NetworkMode": "host"}, None), ({"NetworkMode": "none"}, None), ({"NetworkMode": "default"}, {"default": {}}),
    ({"NetworkMode": "bridge"}, None), ({}, None),
    ({"NetworkMode": "redamon-trufflehog-net"}, None), ({"NetworkMode": OTHER_ID}, None),
    ({"NetworkMode": "default"}, {"default": {}, "redamon-trufflehog-net": {}}),
], ids=["host", "none", "default", "bridge", "unset", "trufflehog-net", "by-full-id", "two-entries"])
def test_the_networks_tools_use_still_go_through(hc, net):
    daemon = NetDaemon()
    out = _send(daemon, _create(hc, net))
    assert status_of(out) == 201, out[:300]


def test_a_connect_to_a_sandbox_network_is_refused():
    daemon = NetDaemon()
    out = _send(daemon, request_bytes("POST", f"{V}/networks/{SBX}/connect", {"Container": "x"}, headers=HDR))
    assert status_of(out) == 403, out[:300]
    assert not daemon.got("POST", f"{V}/networks/{SBX}/connect")


def _netcreate(name="redamon-trufflehog-net", config=None):
    body = {"Name": name, "Driver": "bridge", "IPAM": {"Driver": "default", "Options": {}, "Config": config or []}}
    return request_bytes("POST", f"{V}/networks/create", body, headers=HDR)


@pytest.mark.parametrize("config", [
    [{"Subnet": "10.214.0.0/16"}], [{"Subnet": "10.214.255.240/28"}], [{"Subnet": "10.0.0.0/8"}],
    [{"Subnet": "172.30.0.0/16", "IPRange": "10.214.0.0/24"}], [{"Subnet": "172.30.0.0/16", "Gateway": "10.214.0.1"}],
    [{"Subnet": "172.30.0.0/16", "AuxiliaryAddresses": {"x": "10.214.3.3"}}], [{"Subnet": "not-a-subnet"}],
    [{"Subnet": "172.30.0.0/16"}, {"Subnet": "10.214.7.0/28"}],
], ids=["pool", "pool-top", "covers-pool", "iprange", "gateway", "aux", "garbage", "second"])
def test_a_network_create_with_an_address_in_the_sandbox_pool_is_refused(config):
    daemon = NetDaemon()
    out = _send(daemon, _netcreate(config=config))
    assert status_of(out) == 403, out[:300]
    assert not daemon.got("POST", f"{V}/networks/create")


@pytest.mark.parametrize("config", [[], [{"Subnet": "172.30.0.0/16", "Gateway": "172.30.0.1"}],
                                    [{"Subnet": "fd00:214::/64"}]], ids=["none", "outside", "ipv6"])
def test_a_network_create_outside_the_pool_still_goes_through(config):
    daemon = NetDaemon()
    out = _send(daemon, _netcreate(config=config))
    assert status_of(out) != 403, out[:300]


def test_an_operator_cannot_allowlist_a_sandbox_network(monkeypatch):
    monkeypatch.setattr(broker, "ALLOWED_NETWORKS", broker.ALLOWED_NETWORKS | {SBX})
    daemon = NetDaemon()
    out = _send(daemon, _netcreate(name=SBX))
    assert status_of(out) == 403, out[:300]


def _load_contract():
    spec = importlib.util.spec_from_file_location("sandbox_contract_pin", CONTRACT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module          # its dataclasses look their module up there
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[spec.name]
    return module


@pytest.mark.skipif(not os.path.isfile(CONTRACT), reason="recon_orchestrator/ is not in this checkout")
def test_the_sandbox_names_label_and_pool_are_the_contracts():
    contract = _load_contract()
    name = contract.network_name("cmuser000000000000000000", contract.VIEW_OWN)
    assert name.startswith(broker.SANDBOX_NETWORK_PREFIX) and len(name) > len(broker.SANDBOX_NETWORK_PREFIX)
    assert contract.network_labels("cmuser000000000000000000", contract.VIEW_OWN)[broker.SANDBOX_LABEL]
    assert ipaddress.ip_network(contract.SUBNET_POOL) == broker.SANDBOX_SUBNET_POOL
    assert ipaddress.ip_network(contract.allocate_subnet([])).subnet_of(broker.SANDBOX_SUBNET_POOL)



# ---------------------------------------------------------------------------
# Round 10. N9-1: an IPv4-mapped IPv6 subnet (`::ffff:10.214.255.224/124`) is
# stored by the daemon as the IPv4 /28 it maps, so it took a sandbox's subnet;
# N9-2: a network create carrying the sandbox label made the tool network one
# every tool container is then refused on; N9-3: the daemon keeps an id prefix
# as given and resolves it again at start, so a reference must be an exact
# name or a full id; N9-4: a create could name hundreds of endpoints, each
# one or two network inspects.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("config", [
    [{"Subnet": "::ffff:10.214.255.224/124"}], [{"Subnet": "::ffff:10.214.0.0/112"}],
    [{"Subnet": "::ffff:0:0/96"}], [{"Subnet": "::/0"}], [{"Subnet": "::ffff:a:0/96"}],
    [{"Subnet": "fd00::/64", "Gateway": "::ffff:10.214.0.1"}],
    [{"Subnet": "fd00::/64", "IPRange": "::ffff:10.214.3.0/120"}],
    [{"Subnet": "fd00::/64", "AuxiliaryAddresses": {"x": "::ffff:10.214.3.3"}}],
], ids=["mapped-28", "mapped-pool", "mapped-all", "everything", "mapped-all-spelt", "gateway", "iprange", "aux"])
def test_an_ipv4_mapped_address_in_the_pool_is_refused(config):
    daemon = NetDaemon()
    out = _send(daemon, _netcreate(config=config))
    assert status_of(out) == 403, out[:300]
    assert not daemon.got("POST", f"{V}/networks/create")


@pytest.mark.parametrize("config", [[{"Subnet": "::ffff:172.30.0.0/112"}], [{"Subnet": "fd00:214::/64"}]],
                         ids=["mapped-outside", "plain-ipv6"])
def test_an_ipv6_subnet_outside_the_pool_still_goes_through(config):
    daemon = NetDaemon()
    assert status_of(_send(daemon, _netcreate(config=config))) != 403


@pytest.mark.parametrize("labels", [{"redamon.sandbox": "true"}, {"Redamon.Sandbox": "x"},
                                    {"redamon.sandbox.user": "u"}, {"com.example": "x"}],
                         ids=["sandbox", "sandbox-case", "sandbox-user", "any"])
def test_a_network_create_with_labels_is_refused(labels):
    daemon = NetDaemon()
    body = {"Name": "redamon-trufflehog-net", "Driver": "bridge", "Labels": labels,
            "IPAM": {"Driver": "default", "Options": {}, "Config": []}}
    out = _send(daemon, request_bytes("POST", f"{V}/networks/create", body, headers=HDR))
    assert status_of(out) == 403, out[:300]
    assert not daemon.got("POST", f"{V}/networks/create")


def test_the_cli_network_create_without_labels_still_goes_through():
    daemon = NetDaemon()
    for labels in ({}, None):
        body = {"Name": "redamon-trufflehog-net", "Driver": "bridge", "Scope": "", "Labels": labels,
                "IPAM": {"Driver": "default", "Options": {}, "Config": []}, "Internal": False, "Attachable": False,
                "Ingress": False, "ConfigOnly": False, "ConfigFrom": None, "Options": {}}
        assert status_of(_send(daemon, request_bytes("POST", f"{V}/networks/create", body, headers=HDR))) != 403


@pytest.mark.parametrize("hc,net", [
    ({"NetworkMode": OTHER_ID[:12]}, None),
    ({"NetworkMode": "default"}, {"default": {}, OTHER_ID[:12]: {}}),
    ({"NetworkMode": "default"}, {"redamon-trufflehog-net": {"NetworkID": OTHER_ID[:12]}}),
    ({"NetworkMode": "default"}, {"default": {"NetworkID": OTHER_ID[:3]}}),
], ids=["mode", "key", "networkid", "networkid-3"])
def test_an_id_prefix_is_refused_even_for_a_tool_network(hc, net):
    daemon = NetDaemon()
    out = _send(daemon, _create(hc, net))
    assert status_of(out) == 403, out[:300]
    assert not daemon.got("POST", f"{V}/containers/create")


def test_a_full_network_id_still_goes_through_in_every_place():
    daemon = NetDaemon()
    out = _send(daemon, _create({"NetworkMode": OTHER_ID}, {OTHER_ID: {"NetworkID": OTHER_ID}}))
    assert status_of(out) == 201, out[:300]


def test_too_many_endpoints_are_refused_before_any_inspect():
    daemon = NetDaemon()
    entries = {f"net{i}": {} for i in range(broker.MAX_ENDPOINTS + 1)}
    out = _send(daemon, _create({"NetworkMode": "default"}, entries))
    assert status_of(out) == 403, out[:300]
    assert not [r for r in daemon.received if "/networks/" in r["path"]]
    assert broker.MAX_ENDPOINTS >= 2


@pytest.mark.parametrize("nid", [["x"], {"a": 1}, 7, True], ids=["list", "object", "number", "bool"])
def test_a_network_id_of_another_shape_is_refused_with_a_deny_line(nid, capsys):
    daemon = NetDaemon()
    out = _send(daemon, _create({"NetworkMode": "default"}, {"default": {"NetworkID": nid}}))
    assert status_of(out) == 403, out[:300]
    log = capsys.readouterr().out
    assert "DENY" in log and "error:" not in log

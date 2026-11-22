"""The broker and the daemon must read a request the same way.

The daemon decodes a body with Go's encoding/json: an object key matches a
struct field whatever its case (U+017F long s also folds to "s", the Kelvin
sign to "k"), and every key that names one field is applied in turn, objects
merged and the last scalar winning; map keys (Labels, Tmpfs...) stay exact. The
broker checks exact keys. Now a lone case variant of a field is renamed to the
API's spelling before the checks (the body is re-serialized, so the daemon reads
what was checked); two spellings of one field, a non-ASCII key in a struct, or
a key repeated exactly in any object are refused. Before this test,
`{"HostConfig": {"privileged": true, "binds": ["/etc:/hostetc:ro"]}}` passed
every check and the daemon created a privileged container with that bind,
stamped broker-owned so the caller could start it; a second "labels" emptied
the owner label; a second "image" swapped the image; a repeated "DriverOpts"
reached the daemon in a volume create the broker forwarded byte for byte.
`images/create` had the same split on its query: the daemon reads the first
of two "fromImage", and with an empty one imports the request body as any
repo:tag, e.g. over a tool image every scan runs.

Each case goes through the broker's real handler to a fake daemon, so
"refused" means a 403 and that the daemon never received the request. Every
case was reproduced on Docker Engine 29.10 (create-only, removed at once).
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import broker  # noqa: E402
from mock_daemon import request_bytes, run_through_broker, status_of  # noqa: E402

V = "/v1.57"
CREATE = f"{V}/containers/create"
VOLUME = f"{V}/volumes/create"
NETWORK = f"{V}/networks/create"
PULL = f"{V}/images/create"


def _send(method, target, body):
    [resp], daemon = run_through_broker([request_bytes(method, target, body)])
    return resp, daemon


def _assert_refused(method, target, body):
    resp, daemon = _send(method, target, body)
    assert status_of(resp) == 403, resp[:300]
    assert b"denied by docker-broker" in resp
    assert not daemon.got(method, target.split("?")[0]), "the daemon received a refused request"
    return resp


def _raw(text: str) -> bytes:
    """A body exactly as written: json.dumps could not repeat a key."""
    return text.encode()


@pytest.fixture(autouse=True)
def _fresh_log_limits(monkeypatch):
    # The broker rate-limits its DENY lines per kind of call; each test starts
    # with a fresh allowance so its own refusal is logged.
    monkeypatch.setattr(broker, "_log_marks", {}, raising=False)


# ---------------------------------------------------------------------------
# Container create
# ---------------------------------------------------------------------------

def test_lowercase_privileged_and_binds_are_refused():
    resp = _assert_refused("POST", CREATE, _raw(
        '{"Image":"alpine","HostConfig":{"privileged":true,"binds":["/etc:/hostetc:ro"]}}'))
    assert b"Privileged=true denied" in resp


@pytest.mark.parametrize("host_config", [
    {"privileged": True},
    {"binds": ["/etc:/hostetc:ro"]},
    {"Binds": [], "binds": ["/:/host"]},
    {"CAPADD": ["SYS_ADMIN"]},
    {"pidmode": "host"},
    {"IPCMode": "host"},
    {"usernsmode": "host"},
    {"cgroupnsMode": "host"},
    {"networkmode": "container:redamon-recon-orchestrator"},
    {"volumesFrom": ["redamon-recon-orchestrator"]},
    {"devices": [{"PathOnHost": "/dev/sda", "PathInContainer": "/dev/sda", "CgroupPermissions": "rwm"}]},
    {"maskedPaths": []},
    {"readonlypaths": []},
    {"Securityopt": ["seccomp=unconfined"]},
    {"volumedriver": "attacker/plugin"},
    {"mounts": [{"Type": "bind", "Source": "/", "Target": "/host"}]},
    {"Memory": 0, "memory": 0},
], ids=lambda hc: ",".join(hc))
def test_a_host_config_key_in_another_case_is_refused(host_config):
    _assert_refused("POST", CREATE, {"Image": "alpine", "HostConfig": host_config})


@pytest.mark.parametrize("mount", [
    {"type": "bind", "source": "/", "target": "/host"},
    {"Type": "bind", "Source": "/tmp/redamon/x", "source": "/var/run/docker.sock", "Target": "/s"},
    {"Type": "volume", "source": "redamon_postgres_data", "Target": "/d"},
    {"Type": "volume", "Source": "redamon-osv-db", "Target": "/d", "ReadOnly": True, "readOnly": False},
    {"Type": "volume", "Source": "redamon-osv-db", "Target": "/d", "ReadOnly": True,
     "volumeOptions": {"DriverConfig": {"Name": "local",
                                        "Options": {"type": "none", "o": "bind", "device": "/"}}}},
    {"Type": "volume", "Source": "redamon-osv-db", "Target": "/d", "ReadOnly": True,
     "VolumeOptions": {"driverconfig": {"Name": "local",
                                        "Options": {"type": "none", "o": "bind", "device": "/"}}}},
], ids=["type-source", "source-sock", "volume-source", "readOnly", "volumeOptions", "driverconfig"])
def test_a_mount_key_in_another_case_is_refused(mount):
    _assert_refused("POST", CREATE, {"Image": "alpine", "HostConfig": {"Mounts": [mount]}})


def test_a_second_labels_cannot_empty_the_owner_label():
    _assert_refused("POST", CREATE, _raw(
        '{"Image":"alpine","Labels":{"a":"b"},"labels":{"redamon.broker-owned":""}}'))


def test_a_second_image_cannot_swap_the_image():
    _assert_refused("POST", CREATE, _raw('{"Image":"alpine","image":"redamon-agent:latest"}'))


def test_a_second_host_config_cannot_add_to_the_checked_one():
    _assert_refused("POST", CREATE, _raw(
        '{"Image":"alpine","HostConfig":{"Binds":["/tmp/redamon/x:/x"]},"hostconfig":{"Privileged":true}}'))


@pytest.mark.parametrize("raw", [
    r'{"Image":"alpine","HostConfig":{"Bind\u017f":["/etc:/e:ro"]}}',          # long s -> Binds
    r'{"Image":"alpine","HostConfig":{"Mas\u212aedPaths":[]}}',               # Kelvin sign -> MaskedPaths
    r'{"Image":"alpine","Label\u017f":{"redamon.broker-owned":""}}',
], ids=["long-s", "kelvin", "labels-long-s"])
def test_a_non_ascii_look_alike_of_a_field_is_refused(raw):
    _assert_refused("POST", CREATE, _raw(raw))


@pytest.mark.parametrize("raw", [
    '{"Image":"alpine","HostConfig":{"Privileged":true},"HostConfig":{}}',
    '{"Image":"alpine","HostConfig":{"Binds":["/etc:/e:ro"],"Binds":[]}}',
    '{"Image":"alpine","Labels":{"x":"1"},"Labels":{"redamon.broker-owned":""}}',
    '{"Image":"alpine","Labels":{"k":"1","k":"2"}}',
], ids=["HostConfig", "Binds", "Labels", "a label"])
def test_a_repeated_key_is_refused(raw):
    resp = _assert_refused("POST", CREATE, _raw(raw))
    assert b"repeated" in resp


def test_a_host_config_field_at_the_top_level_is_refused():
    # Engines that still embed HostConfig in the create wrapper read these there.
    _assert_refused("POST", CREATE, {"Image": "alpine", "Privileged": True})
    _assert_refused("POST", CREATE, {"Image": "alpine", "VolumeDriver": "attacker/plugin", "HostConfig": {}})


# The bodies Docker CLI 29.10.0 sends, recorded off the wire. A plain
# `docker create alpine echo hi`:
CLI_PLAIN = '{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":true,"AttachStderr":true,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":null,"Cmd":["echo","hi"],"Image":"alpine","Volumes":{},"WorkingDir":"","Entrypoint":null,"Labels":{},"HostConfig":{"Binds":null,"ContainerIDFile":"","LogConfig":{"Type":"","Config":{}},"NetworkMode":"default","PortBindings":{},"RestartPolicy":{"Name":"no","MaximumRetryCount":0},"AutoRemove":false,"VolumeDriver":"","VolumesFrom":null,"ConsoleSize":[0,0],"CapAdd":null,"CapDrop":null,"CgroupnsMode":"","Dns":null,"DnsOptions":[],"DnsSearch":[],"ExtraHosts":null,"GroupAdd":null,"IpcMode":"","Cgroup":"","Links":null,"OomScoreAdj":0,"PidMode":"","Privileged":false,"PublishAllPorts":false,"ReadonlyRootfs":false,"SecurityOpt":null,"UTSMode":"","UsernsMode":"","ShmSize":0,"Isolation":"","CpuShares":0,"Memory":0,"NanoCpus":0,"CgroupParent":"","BlkioWeight":0,"BlkioWeightDevice":[],"BlkioDeviceReadBps":[],"BlkioDeviceWriteBps":[],"BlkioDeviceReadIOps":[],"BlkioDeviceWriteIOps":[],"CpuPeriod":0,"CpuQuota":0,"CpuRealtimePeriod":0,"CpuRealtimeRuntime":0,"CpusetCpus":"","CpusetMems":"","Devices":[],"DeviceCgroupRules":null,"DeviceRequests":null,"MemoryReservation":0,"MemorySwap":0,"MemorySwappiness":-1,"OomKillDisable":false,"PidsLimit":0,"Ulimits":null,"CpuCount":0,"CpuPercent":0,"IOMaximumIOps":0,"IOMaximumBandwidth":0,"MaskedPaths":null,"ReadonlyPaths":null},"NetworkingConfig":{"EndpointsConfig":{"default":{"IPAMConfig":null,"Links":null,"Aliases":null,"DriverOpts":null,"GwPriority":0,"NetworkID":"","EndpointID":"","Gateway":"","IPAddress":"","MacAddress":"","IPPrefixLen":0,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"DNSNames":null}}}}'  # noqa: E501
# And with most of the options a tool could pass (-i -v x2 --cap-add NET_RAW
# --cap-drop ALL --tmpfs -e --network host --memory --cpus --pids-limit
# --read-only --user --entrypoint -w --label --health-cmd --ulimit --mount x2
# --security-opt --dns --add-host --init --stop-signal --stop-timeout -p
# --expose --restart --log-driver --log-opt --device-read-bps --sysctl
# --shm-size --memory-swap --oom-score-adj --hostname); its third --mount, a
# tmpfs mount the broker refuses by type, is left out.
CLI_RICH = '{"Hostname":"h","Domainname":"","User":"1000","AttachStdin":true,"AttachStdout":true,"AttachStderr":true,"ExposedPorts":{"80/tcp":{},"9090/tcp":{}},"Tty":false,"OpenStdin":true,"StdinOnce":true,"Env":["A=1"],"Cmd":["echo","hi"],"Healthcheck":{"Test":["CMD-SHELL","true"]},"Image":"alpine","Volumes":{},"WorkingDir":"/w","Entrypoint":["sh"],"Labels":{"k":"v"},"StopSignal":"SIGINT","StopTimeout":5,"HostConfig":{"Binds":["nuclei-templates:/root/nuclei-templates","/tmp/redamon/x:/x:ro"],"ContainerIDFile":"","LogConfig":{"Type":"json-file","Config":{"max-size":"1m"}},"NetworkMode":"host","PortBindings":{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"8080"}]},"RestartPolicy":{"Name":"no","MaximumRetryCount":0},"AutoRemove":false,"VolumeDriver":"","VolumesFrom":null,"ConsoleSize":[0,0],"CapAdd":["CAP_NET_RAW"],"CapDrop":["ALL"],"CgroupnsMode":"","Dns":["1.1.1.1"],"DnsOptions":[],"DnsSearch":[],"ExtraHosts":["a:1.2.3.4"],"GroupAdd":null,"IpcMode":"","Cgroup":"","Links":null,"OomScoreAdj":10,"PidMode":"","Privileged":false,"PublishAllPorts":false,"ReadonlyRootfs":true,"SecurityOpt":["no-new-privileges"],"Tmpfs":{"/t":"size=1m"},"UTSMode":"","UsernsMode":"","ShmSize":67108864,"Sysctls":{"net.ipv4.ip_forward":"0"},"Isolation":"","CpuShares":0,"Memory":1073741824,"NanoCpus":1000000000,"CgroupParent":"","BlkioWeight":0,"BlkioWeightDevice":[],"BlkioDeviceReadBps":[{"Path":"/dev/null","Rate":1048576}],"BlkioDeviceWriteBps":[],"BlkioDeviceReadIOps":[],"BlkioDeviceWriteIOps":[],"CpuPeriod":0,"CpuQuota":0,"CpuRealtimePeriod":0,"CpuRealtimeRuntime":0,"CpusetCpus":"","CpusetMems":"","Devices":[],"DeviceCgroupRules":null,"DeviceRequests":null,"MemoryReservation":0,"MemorySwap":2147483648,"MemorySwappiness":-1,"OomKillDisable":false,"PidsLimit":100,"Ulimits":[{"Name":"nofile","Hard":20,"Soft":10}],"CpuCount":0,"CpuPercent":0,"IOMaximumIOps":0,"IOMaximumBandwidth":0,"Mounts":[{"Type":"volume","Source":"redamon-osv-db","Target":"/osv","ReadOnly":true,"VolumeOptions":{"NoCopy":true}},{"Type":"bind","Source":"/tmp/redamon/b","Target":"/b","BindOptions":{"Propagation":"rslave"}}],"MaskedPaths":null,"ReadonlyPaths":null,"Init":true},"NetworkingConfig":{"EndpointsConfig":{}}}'  # noqa: E501


@pytest.mark.parametrize("raw", [CLI_PLAIN, CLI_RICH], ids=["plain", "rich"])
def test_the_bodies_the_docker_cli_sends_are_still_allowed(raw):
    resp, daemon = _send("POST", f"{CREATE}?name=redamon-x&platform=linux%2Famd64", _raw(raw))
    assert status_of(resp) == 201, resp[:300]
    [sent] = [r for r in daemon.received if r["path"] == CREATE]
    forwarded = json.loads(sent["body"])
    assert forwarded["Labels"][broker._OWNER_LABEL] == "1"
    expected = json.loads(raw)
    for key in expected:
        if key not in ("Labels", "HostConfig"):
            assert forwarded[key] == expected[key], key


# ---------------------------------------------------------------------------
# Volume and network create
# ---------------------------------------------------------------------------

BIND_ROOT = {"type": "none", "o": "bind", "device": "/"}


@pytest.mark.parametrize("raw", [
    json.dumps({"Name": "nuclei-templates", "driveropts": BIND_ROOT}),
    json.dumps({"Name": "nuclei-templates", "Driver": "local", "driver": "attacker/plugin"}),
    json.dumps({"Name": "nuclei-templates", "clusterVolumeSpec": {"Group": "x"}}),
    json.dumps({"Name": "nuclei-templates", "name": "redamon_postgres_data"}),
    '{"Name":"nuclei-templates","DriverOpts":' + json.dumps(BIND_ROOT) + ',"DriverOpts":{}}',
    '{"Name":"nuclei-templates","Name":"nuclei-templates"}',
], ids=["driveropts", "driver", "clusterVolumeSpec", "name", "repeated-DriverOpts", "repeated-Name"])
def test_a_volume_create_key_in_another_case_or_repeated_is_refused(raw):
    _assert_refused("POST", VOLUME, _raw(raw))


NET = "redamon-supply-chain-net"


@pytest.mark.parametrize("raw", [
    json.dumps({"Name": NET, "options": {"com.docker.network.bridge.name": "docker0"}}),
    json.dumps({"Name": NET, "Driver": "bridge", "driver": "macvlan"}),
    json.dumps({"Name": NET, "ipam": {"Driver": "attacker/ipam"}}),
    json.dumps({"Name": NET, "IPAM": {"Driver": "default", "options": {"x": "y"}}}),
    json.dumps({"Name": NET, "configFrom": {"Network": "redamon_default"}}),
    json.dumps({"Name": NET, "ingress": True}),
    json.dumps({"Name": NET, "scope": "swarm"}),
    '{"Name":"' + NET + '","Options":{"com.docker.network.bridge.name":"docker0"},"Options":{}}',
], ids=["options", "driver", "ipam", "ipam-options", "configFrom", "ingress", "scope", "repeated-Options"])
def test_a_network_create_key_in_another_case_or_repeated_is_refused(raw):
    _assert_refused("POST", NETWORK, _raw(raw))


@pytest.mark.parametrize("target,raw", [
    (VOLUME, '{"Driver":"local","Name":"nuclei-templates"}'),
    (NETWORK, '{"Name":"redamon-trufflehog-net","Driver":"bridge","Scope":"","IPAM":{"Driver":"default",'
              '"Options":{},"Config":[]},"Internal":false,"Attachable":false,"Ingress":false,'
              '"ConfigOnly":false,"ConfigFrom":null,"Options":{},"Labels":{}}'),
], ids=["volume", "network"])
def test_the_cli_volume_and_network_creates_are_forwarded_as_checked(target, raw):
    resp, daemon = _send("POST", target, _raw(raw))
    assert status_of(resp) == 200, resp[:300]
    [sent] = [r for r in daemon.received if r["path"] == target]
    assert sent["body"] == json.dumps(json.loads(raw)).encode()


# ---------------------------------------------------------------------------
# Image pull (images/create)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("query", [
    # the daemon reads the first fromImage: empty, so it imports the body as repo:tag
    "fromImage=&fromImage=alpine&fromSrc=-&repo=projectdiscovery%2Fnaabu&tag=latest",
    "fromImage=docker.io%2Fattacker%2Fx&fromImage=alpine",
    # the daemon decodes parameter names too: this is a first fromImage
    "from%49mage=docker.io%2Fattacker%2Fx&fromImage=alpine",
    "fromImage=alpine&tag=latest&tag=evil",
    "fromImage=alpine&tag=latest&fromSrc=http%3A%2F%2Fattacker%2Fx.tar&repo=projectdiscovery%2Fnaabu",
    "fromImage=alpine&tag=latest&changes=CMD%20id",
], ids=["empty-first", "attacker-first", "encoded-name", "repeated-tag", "fromSrc", "changes"])
def test_a_pull_the_daemon_would_read_differently_is_refused(query):
    _assert_refused("POST", f"{PULL}?{query}", b"")


def test_a_pull_with_a_body_is_refused():
    # A form body is part of the daemon's parameters, and an import reads its image from the body.
    _assert_refused("POST", f"{PULL}?fromImage=alpine&tag=latest", b"fromImage=docker.io/attacker/x")


@pytest.mark.parametrize("query", [
    "fromImage=docker.io%2Fprojectdiscovery%2Fnaabu&tag=latest",
    "fromImage=docker.io%2Fprojectdiscovery%2Fnaabu&platform=linux%2Famd64&tag=latest",
    "fromImage=docker.io%2Flibrary%2Falpine&tag=latest",
])
def test_the_cli_pulls_are_still_forwarded(query):
    resp, daemon = _send("POST", f"{PULL}?{query}", None)
    assert status_of(resp) == 200, resp[:300]
    assert daemon.got("POST", PULL)


# ---------------------------------------------------------------------------
# The checks themselves
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("body", [
    {"Image": "alpine", "HostConfig": {"privileged": True}},
    {"Image": "alpine", "image": "busybox"},
    {"Image": "alpine", "HostConfig": {"Mounts": [{"type": "bind", "source": "/", "target": "/h"}]}},
    {"Image": "alpine", "NetworkingConfig": {"EndpointsConfig": {"n": {"IPAMConfig": {}, "ipamConfig": {}}}}},
    {"Image": "alpine", "Healthcheck": {"Test": ["CMD", "true"], "test": ["CMD", "id"]}},
    {"Image": "alpine", "HostConfig": {"Mounts": [{"Type": "volume", "Source": "redamon-osv-db",
                                                   "Target": "/d", "ReadOnly": True,
                                                   "Volume\u017fOptions": {}}]}},
    ["Image", "alpine"],
])
def test_validate_create_refuses_what_the_daemon_would_read_differently(body):
    ok, reason = broker.validate_create(body)
    assert ok is False, reason


def test_every_struct_the_field_catalog_names_is_in_it():
    def structs(kind):
        if isinstance(kind, tuple):
            yield from structs(kind[1])
        elif kind is not None:
            yield kind
    named = {s for fields in broker._API_FIELDS.values() for k in fields.values() for s in structs(k)}
    assert named <= set(broker._API_FIELDS)


# ---------------------------------------------------------------------------
# Keys of free maps are the daemon's own: case variants are distinct entries
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw", [
    '{"Image":"alpine","Labels":{"Foo":"1","foo":"2"}}',                       # -l Foo=1 -l foo=2
    '{"Image":"alpine","HostConfig":{"Tmpfs":{"/Data":"","/data":""}}}',      # --tmpfs /Data --tmpfs /data
    '{"Image":"alpine","Labels":{"stra\u00dfe":"1","STRASSE":"2"}}',          # str.upper folds \u00df to SS
    '{"Image":"alpine","Volumes":{"/A":{},"/a":{}},"HostConfig":{"Sysctls":{"net.X":"1","net.x":"2"},'
    '"LogConfig":{"Type":"json-file","Config":{"Max-Size":"1m","max-size":"2m"}}},'
    '"NetworkingConfig":{"EndpointsConfig":{"Net":{},"net":{}}}}',
], ids=["labels", "tmpfs", "sharp-s", "volumes-sysctls-logconfig-endpoints"])
def test_case_variants_inside_a_free_map_are_forwarded_as_distinct_keys(raw):
    resp, daemon = _send("POST", CREATE, _raw(raw))
    assert status_of(resp) == 201, resp[:300]
    [sent] = [r for r in daemon.received if r["path"] == CREATE]
    forwarded, expected = json.loads(sent["body"]), json.loads(raw)
    for top, value in expected.items():
        if isinstance(value, dict) and top != "HostConfig":
            for key in value:
                assert key in forwarded[top], (top, key)
    for key, value in expected.get("HostConfig", {}).items():
        assert forwarded["HostConfig"][key] == value


@pytest.mark.parametrize("target,raw", [
    (VOLUME, '{"Driver":"local","Name":"nuclei-templates","Labels":{"A":"1","a":"2"}}'),
    (NETWORK, '{"Name":"redamon-trufflehog-net","Driver":"bridge","Labels":{"A":"1","a":"2"}}'),
], ids=["volume", "network"])
def test_case_variants_in_volume_and_network_labels_are_forwarded(target, raw):
    resp, daemon = _send("POST", target, _raw(raw))
    assert status_of(resp) == 200, resp[:300]
    [sent] = [r for r in daemon.received if r["path"] == target]
    assert json.loads(sent["body"])["Labels"] == {"A": "1", "a": "2"}


def test_an_exact_repeat_inside_a_map_is_refused():
    with pytest.raises(ValueError, match="repeated key 'a'"):
        broker.parse_body(b'{"Labels":{"a":"1","a":"2"}}')
    assert broker.parse_body(b'{"Labels":{"a":"1","A":"2"}}') == {"Labels": {"a": "1", "A": "2"}}


# ---------------------------------------------------------------------------
# A lone case variant of a field is renamed to the API's spelling (docker-py,
# or a CLI that changes a field's case, still works) and checked as such
# ---------------------------------------------------------------------------

def test_a_lone_case_variant_is_forwarded_under_the_api_spelling():
    resp, daemon = _send("POST", CREATE, {"Image": "alpine", "HostConfig": {
        "CPURealtimePeriod": 0, "CPURealtimeRuntime": 0, "readonlyRootfs": True, "privileged": False}})
    assert status_of(resp) == 201, resp[:300]
    [sent] = [r for r in daemon.received if r["path"] == CREATE]
    hc = json.loads(sent["body"])["HostConfig"]
    assert {"CpuRealtimePeriod", "CpuRealtimeRuntime", "ReadonlyRootfs", "Privileged"} <= set(hc)
    assert not {"CPURealtimePeriod", "CPURealtimeRuntime", "readonlyRootfs", "privileged"} & set(hc)
    assert hc["ReadonlyRootfs"] is True and hc["Privileged"] is False


def test_a_renamed_field_is_checked_under_the_api_spelling():
    resp = _assert_refused("POST", CREATE, {"Image": "alpine", "HostConfig": {"cAPaDD": ["SYS_ADMIN"]}})
    assert b"capability not allowed: SYS_ADMIN" in resp


def test_a_lone_case_variant_in_a_volume_or_network_create_is_renamed():
    resp, daemon = _send("POST", VOLUME, {"driver": "local", "name": "nuclei-templates"})
    assert status_of(resp) == 200, resp[:300]
    [sent] = [r for r in daemon.received if r["path"] == VOLUME]
    assert json.loads(sent["body"]) == {"Driver": "local", "Name": "nuclei-templates"}


# ---------------------------------------------------------------------------
# HostConfig fields no tool uses and that reach the host
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("host_config", [
    {"DeviceCgroupRules": ["b *:* rwm"]},
    {"DeviceCgroupRules": ["c 1:3 rwm"]},
    {"DeviceRequests": [{"Driver": "", "Count": -1, "DeviceIDs": None, "Capabilities": [["gpu"]],
                         "Options": {}}]},
], ids=["any-block-device", "one-char-device", "gpus"])
def test_device_cgroup_rules_and_device_requests_are_refused(host_config):
    resp = _assert_refused("POST", CREATE, {"Image": "alpine", "HostConfig": host_config})
    assert b"device cgroup rules and device requests denied" in resp


@pytest.mark.parametrize("opt", [
    'seccomp={"defaultAction":"SCMP_ACT_ALLOW"}',
    "apparmor=lsb_release",
    "apparmor=docker-default",
    "label=disable",
    "label=type:spc_t",
    "systempaths=unconfined",
    "no-new-privileges=false",
    "no-new-privileges:false",
])
def test_a_security_option_other_than_no_new_privileges_is_refused(opt):
    resp = _assert_refused("POST", CREATE, {"Image": "alpine", "HostConfig": {"SecurityOpt": [opt]}})
    assert b"SecurityOpt" in resp


@pytest.mark.parametrize("opt", ["no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"])
def test_no_new_privileges_is_allowed(opt):
    ok, reason = broker.validate_create({"Image": "alpine", "HostConfig": {"SecurityOpt": [opt]}})
    assert ok, reason


# ---------------------------------------------------------------------------
# Body size and shape
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("target", [CREATE, VOLUME, NETWORK])
def test_a_body_over_the_json_cap_is_refused_before_it_is_read(target):
    # The cap is checked on the Content-Length, before a byte of the body is read or parsed.
    raw = (f"POST {target} HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\n"
           f"Content-Length: {broker.JSON_BODY_MAX + 1}\r\n\r\n").encode() + b"{}"
    [resp], daemon = run_through_broker([raw])
    assert status_of(resp) == 403, resp[:300]
    assert b"request body over" in resp
    assert not daemon.got("POST", target)


def test_a_large_body_under_the_cap_is_still_allowed():
    labels = {f"k{i}": "" for i in range(broker.JSON_BODY_MAX // 32)}
    body = json.dumps({"Image": "alpine", "Labels": labels}).encode()
    assert broker.JSON_BODY_MAX // 4 < len(body) <= broker.JSON_BODY_MAX
    resp, daemon = _send("POST", CREATE, body)
    assert status_of(resp) == 201, resp[:300]


def test_the_json_cap_is_far_above_what_the_cli_sends():
    assert broker.JSON_BODY_MAX >= 100 * len(CLI_RICH)


@pytest.mark.parametrize("raw", ["[]", '"alpine"', "null", "1"])
def test_a_create_body_that_is_not_an_object_is_refused_with_a_deny_line(raw, capsys):
    resp = _assert_refused("POST", CREATE, _raw(raw))
    assert b"not a JSON object" in resp
    out = capsys.readouterr().out
    assert "DENY POST /v1.57/containers/create" in out and "error:" not in out


# ---------------------------------------------------------------------------
# A value of the wrong shape is a refusal (403 + DENY), never a dropped
# connection with an "error:" line
# ---------------------------------------------------------------------------

NET_C = "redamon-supply-chain-net"
VOLUME_RO = {"Type": "volume", "Source": "redamon-osv-db", "Target": "/d", "ReadOnly": True}


@pytest.mark.parametrize("target,body", [
    (CREATE, {"Image": "alpine", "HostConfig": "x"}),
    (CREATE, {"Image": "alpine", "HostConfig": ["x"]}),
    (CREATE, {"Image": "alpine", "HostConfig": {"Mounts": {"Type": "bind"}}}),
    (CREATE, {"Image": "alpine", "HostConfig": {"Mounts": ["/etc:/e"]}}),
    (CREATE, {"Image": "alpine", "HostConfig": {"Mounts": [{**VOLUME_RO, "VolumeOptions": "x"}]}}),
    (CREATE, {"Image": "alpine", "HostConfig": {"CapAdd": 5}}),
    (CREATE, {"Image": "alpine", "HostConfig": {"SecurityOpt": 5}}),
    (CREATE, {"Image": "alpine", "HostConfig": {"Memory": "1"}}),
    (CREATE, {"Image": "alpine", "HostConfig": {"PidsLimit": "1"}}),
    (CREATE, {"Image": ["alpine"]}),
    (CREATE, {"Image": 5}),
    (CREATE, {"Image": "alpine", "NetworkingConfig": "x"}),
    (CREATE, {"Image": "alpine", "NetworkingConfig": {"EndpointsConfig": ["x"]}}),
    (CREATE, {"Image": "alpine", "NetworkingConfig": {"EndpointsConfig": {"n": "x"}}}),
    (CREATE, {"Image": "alpine", "Healthcheck": "x"}),
    (VOLUME, {"Name": ["nuclei-templates"]}),
    (NETWORK, {"Name": {"a": 1}}),
    (NETWORK, {"Name": NET_C, "IPAM": "x"}),
    (NETWORK, {"Name": NET_C, "IPAM": {"Config": "x"}}),
], ids=["HostConfig-string", "HostConfig-array", "Mounts-object", "Mount-string", "VolumeOptions-string",
        "CapAdd-number", "SecurityOpt-number", "Memory-string", "PidsLimit-string",
        "Image-array", "Image-number", "NetworkingConfig-string", "EndpointsConfig-array",
        "EndpointSettings-string", "Healthcheck-string", "volume-Name-array", "network-Name-object",
        "IPAM-string", "IPAM-Config-string"])
def test_a_value_of_the_wrong_shape_is_refused_with_a_deny_line(target, body, capsys):
    _assert_refused("POST", target, body)
    out = capsys.readouterr().out
    assert "DENY POST" in out and "error:" not in out


# ---------------------------------------------------------------------------
# Round 4. 3: a negative value is unlimited to the daemon, so it gets the cap;
# 4: a refusal never logs or answers more than a few hundred characters of the
# client's input, and refusals of one kind are rate-limited.
# ---------------------------------------------------------------------------

GIB = 1024 ** 3


@pytest.mark.parametrize("host_config,expected", [
    ({"PidsLimit": -1}, {"PidsLimit": 512}),
    ({"PidsLimit": 0}, {"PidsLimit": 512}),
    ({"PidsLimit": None}, {"PidsLimit": 512}),
    ({"PidsLimit": 100}, {"PidsLimit": 100}),
    ({"PidsLimit": 100000}, {"PidsLimit": 512}),
    ({"Memory": -1}, {"Memory": 2 * GIB}),
    ({"MemorySwap": -1}, {"Memory": 2 * GIB, "MemorySwap": 4 * GIB}),
    ({"MemorySwap": 64 * GIB}, {"Memory": 2 * GIB, "MemorySwap": 4 * GIB}),
    ({"Memory": GIB, "MemorySwap": -1}, {"Memory": GIB, "MemorySwap": 2 * GIB}),
    ({"MemorySwap": 0}, {"Memory": 2 * GIB, "MemorySwap": 0}),          # what the CLI sends: the daemon's default
    ({"Memory": GIB, "MemorySwap": GIB}, {"Memory": GIB, "MemorySwap": GIB}),
], ids=["pids-minus-1", "pids-0", "pids-null", "pids-lower", "pids-higher", "memory-minus-1",
        "swap-minus-1", "swap-huge", "swap-minus-1-lower-memory", "swap-0-default", "no-swap"])
def test_negative_or_unlimited_values_get_the_caps(monkeypatch, host_config, expected):
    monkeypatch.setattr(broker, "BROKER_TOOL_PIDS", 512)
    monkeypatch.setattr(broker, "BROKER_TOOL_MEM", 2 * GIB)
    resp, daemon = _send("POST", CREATE, {"Image": "alpine", "HostConfig": host_config})
    assert status_of(resp) == 201, resp[:300]
    [sent] = [r for r in daemon.received if r["path"] == CREATE]
    hc = json.loads(sent["body"])["HostConfig"]
    for key, value in expected.items():
        assert hc[key] == value, (key, hc.get(key))


def test_the_cli_body_still_gets_the_pids_cap_and_the_default_swap(monkeypatch):
    monkeypatch.setattr(broker, "BROKER_TOOL_PIDS", 512)
    monkeypatch.setattr(broker, "BROKER_TOOL_MEM", 2 * GIB)
    resp, daemon = _send("POST", CREATE, _raw(CLI_PLAIN))
    assert status_of(resp) == 201, resp[:300]
    [sent] = [r for r in daemon.received if r["path"] == CREATE]
    hc = json.loads(sent["body"])["HostConfig"]
    assert (hc["PidsLimit"], hc["Memory"], hc["MemorySwap"]) == (512, 2 * GIB, 0)


@pytest.mark.parametrize("body", [
    {"Image": "x" * 500_000},
    {"Image": "alpine", "HostConfig": {"Binds": ["/etc" + "/x" * 250_000 + ":/e"]}},
    {"Image": "alpine", "HostConfig": {"\u017f" * 60_000: 1}},     # 360 KB escaped, under the body cap
], ids=["image", "bind", "key-path"])
def test_a_refusal_echoes_at_most_a_few_hundred_characters(body, capsys):
    resp = _assert_refused("POST", CREATE, body)
    assert len(resp) < 2500, len(resp)      # ~300 echoed characters, at most 6 bytes each once JSON-escaped
    [line] = [ln for ln in capsys.readouterr().out.splitlines() if "DENY" in ln]
    assert len(line) < 1200, len(line)
    assert "characters)" in line


def test_refusals_of_one_kind_are_rate_limited(capsys):
    responses, daemon = run_through_broker(
        [request_bytes("POST", CREATE, {"Image": f"attacker/image-{i}"}) for i in range(60)])
    assert [status_of(r) for r in responses] == [403] * 60
    lines = [ln for ln in capsys.readouterr().out.splitlines() if "DENY" in ln]
    assert len(lines) == broker.DENY_BURST, len(lines)

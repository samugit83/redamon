"""What a tool container may mount, under the configuration compose ships (R-17, R-18; D4).

R-17: compose allowed read-only binds of anything under the repository root,
`.env` included, which holds the master keys the scoped scan-container key
exists to keep out of scan containers. Only the repository subdirectories the
tools really mount are allowed now, never a dot component below them; the
per-run folders under /tmp/redamon stay allowed, dot-prefixed ones included
(`.naabu_temp_*`, `.tlsx_scan_*`, ...).

R-18: the read-write gate for named volumes was off whenever its list was empty
(the shipped configuration), and the `Binds` form was never mode-checked, so a
tool could open the shared OSV database or the incident intel read-write. Named
volumes are read-only unless listed, in both forms; only nuclei-templates (the
template update writes it) is listed.

The policy is loaded from the environment compose gives the broker service, so
the compose block and the code are checked together.
"""
import contextlib
import importlib
import os
import re
import sys
from unittest import mock

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_COMPOSE = os.path.join(os.path.dirname(os.path.dirname(_HERE)), "docker-compose.yml")
sys.path.insert(0, _HERE)
import broker  # noqa: E402

REPO = "/srv/red amon"          # a space, like many real checkouts
NAABU = "projectdiscovery/naabu:latest"

if not os.path.isfile(_COMPOSE):
    pytest.skip("docker-compose.yml is not in this checkout", allow_module_level=True)


def broker_service_env(host_env: dict) -> dict:
    """The docker-broker service's `environment:` as compose would resolve it."""
    with open(_COMPOSE, encoding="utf-8") as f:
        text = f.read()
    block = re.search(r"^  docker-broker:\n(.*?)(?=^  \S)", text, re.S | re.M)
    assert block, "no docker-broker service in docker-compose.yml"
    env_block = re.search(r"^    environment:\n((?:^      .*\n|^\s*\n)+)", block.group(1), re.M)
    assert env_block, "the docker-broker service has no environment: block"
    env = {}
    for line in env_block.group(1).splitlines():
        m = re.match(r"^      ([A-Z0-9_]+):\s*(.*)$", line)
        if m:
            env[m.group(1)] = _interpolate(m.group(2).split(" #", 1)[0].strip(), host_env)
    return env


def _interpolate(value: str, host_env: dict) -> str:
    def sub(m):
        name, default = m.group(1), m.group(3) or ""
        got = host_env.get(name)
        return got if got else default
    return re.sub(r"\$\{([A-Z0-9_]+)(:-([^}]*))?\}", sub, value)


@contextlib.contextmanager
def shipped_policy(host_env=None, extra=None):
    """The broker module as compose configures it (plus `extra` variables set
    on the broker directly), restored afterwards."""
    env = {**broker_service_env({"PWD": REPO, **(host_env or {})}), **(extra or {})}
    clean = {k: v for k, v in os.environ.items() if not k.startswith("DOCKER_BROKER_")}
    try:
        with mock.patch.dict(os.environ, {**clean, **env}, clear=True):
            importlib.reload(broker)
            yield broker
    finally:
        importlib.reload(broker)


def _bind(spec):
    return {"Image": NAABU, "HostConfig": {"Binds": [spec]}}


def _mount(**m):
    return {"Image": NAABU, "HostConfig": {"Mounts": [m]}}


# ---- R-17 ------------------------------------------------------------------

@pytest.mark.parametrize("spec", [
    f"{REPO}/.env:/x:ro",
    f"{REPO}/.env.local:/x:ro",
    f"{REPO}/.git:/x:ro",
    f"{REPO}:/x:ro",                                  # the whole repository
    f"{REPO}/recon:/x:ro",                            # source, not a tool mount
    f"{REPO}/recon/project_settings.py:/x:ro",
    f"{REPO}/webapp/.env:/x:ro",
    f"{REPO}/recon/wordlists/.env:/x:ro",             # a dotfile below an allowed subdir
    f"{REPO}/recon/wordlists/../../.env:/x:ro",
    f"{REPO}/mcp/nuclei-templates/.git:/x:ro",
    f"{REPO}/recon/wordlists-evil:/x:ro",             # shares the prefix string only
    f"{REPO}/recon/output/naabu:/x:ro",               # tools keep their files in /tmp/redamon
])
def test_repository_paths_outside_the_tool_subdirectories_are_refused(spec):
    with shipped_policy() as b:
        ok, reason = b.validate_create(_bind(spec))
    assert ok is False, f"{spec} was allowed"
    assert "bind mount not allowed" in reason


@pytest.mark.parametrize("spec", [
    f"{REPO}/recon/wordlists/jhaddix-all.txt:/wordlist/jhaddix-all.txt:ro",
    f"{REPO}/mcp/nuclei-templates:/custom-templates:ro",        # HOST_CUSTOM_TEMPLATES_PATH
    f"{REPO}/scanners/supply_chain_common:/app/supply_chain_common:ro",
    "/tmp/redamon/.naabu_temp_0123456789ab:/targets:ro",
    "/tmp/redamon/.naabu_temp_0123456789ab:/output",            # scratch stays writable
    "/tmp/redamon/.tlsx_scan_17:/tmp/redamon/.tlsx_scan_17:ro",
    "/tmp/redamon/.httpx_temp_0123456789ab:/output",
    "/tmp/redamon/.amass_temp_0123456789ab:/root/.config/amass",
    "/tmp/redamon/.gau_config_01234567/.gau.toml:/root/.gau.toml:ro",
    "/tmp/redamon/.jsluice_verify_01234567:/data",
    "/tmp/redamon:/tmp/redamon",                                # katana
])
def test_every_kind_of_tool_mount_is_allowed(spec):
    with shipped_policy() as b:
        ok, reason = b.validate_create(_bind(spec))
    assert ok, reason


def test_a_tool_subdirectory_bind_must_stay_read_only():
    with shipped_policy() as b:
        ok, reason = b.validate_create(_bind(f"{REPO}/recon/wordlists/x:/w"))
    assert ok is False and "read-write" in reason


def test_the_same_rules_hold_in_the_mounts_form():
    with shipped_policy() as b:
        refused = b.validate_create(_mount(Type="bind", Source=f"{REPO}/.env", Target="/x", ReadOnly=True))
        allowed = b.validate_create(_mount(Type="bind", Source=f"{REPO}/recon/wordlists",
                                           Target="/w", ReadOnly=True))
    assert refused[0] is False
    assert allowed[0] is True, allowed[1]


def test_without_a_repository_root_no_repository_path_is_allowed():
    """PWD unset: nothing under any repository is mountable (fail closed), the
    scratch dir still is, and there is no developer path to fall back to."""
    with shipped_policy({"PWD": ""}) as b:
        assert b.validate_create(_bind(f"{REPO}/recon/wordlists/x:/x:ro"))[0] is False
        assert b.validate_create(_bind("/recon/wordlists/x:/x:ro"))[0] is False
        assert b.validate_create(_bind("/tmp/redamon/.x_1:/x"))[0] is True
        assert all(os.path.isabs(p) and os.path.normpath(p) != "/" for p in b.ALLOWED_BIND_PREFIXES)


def test_the_compose_block_names_no_developer_path():
    env = broker_service_env({})
    joined = " ".join(env.values())
    assert "/home/" not in joined
    assert not any(v.rstrip("/") == "" for k, v in env.items() if k.endswith("_PREFIXES") and v)


@pytest.mark.parametrize("prefix", ["/", "//", "relative/dir", "/tmp/.."])
def test_an_operator_prefix_that_would_open_the_host_root_is_ignored(prefix):
    with shipped_policy(extra={"DOCKER_BROKER_ALLOWED_BIND_PREFIXES": prefix}) as b:
        assert b.validate_create(_bind("/etc:/e:ro"))[0] is False
        assert b.validate_create(_bind("/home:/h:ro"))[0] is False


# ---- R-18 ------------------------------------------------------------------

@pytest.mark.parametrize("volume", ["redamon-osv-db", "redamon-sca-intel"])
def test_a_read_only_volume_cannot_be_mounted_read_write_in_either_form(volume):
    with shipped_policy() as b:
        for body in (_bind(f"{volume}:/data"), _bind(f"{volume}:/data:rw"),
                     _mount(Type="volume", Source=volume, Target="/data"),
                     _mount(Type="volume", Source=volume, Target="/data", ReadOnly=False)):
            ok, reason = b.validate_create(body)
            assert ok is False, body
            assert "read-write volume" in reason
        for body in (_bind(f"{volume}:/data:ro"),
                     _mount(Type="volume", Source=volume, Target="/data", ReadOnly=True)):
            assert b.validate_create(body)[0] is True, body


def test_nuclei_templates_is_the_one_writable_volume():
    """The template update (`nuclei -ut`) and every scan mount it read-write
    in the Binds form (recon/helpers/docker_helpers.py, nuclei_helpers.py)."""
    with shipped_policy() as b:
        assert b.ALLOWED_RW_VOLUMES == {"nuclei-templates"}
        assert b.validate_create(_bind("nuclei-templates:/root/nuclei-templates"))[0] is True
        assert b.validate_create(_mount(Type="volume", Source="nuclei-templates", Target="/t"))[0] is True


def test_an_empty_writable_list_means_none_writable():
    with shipped_policy() as b:
        b.ALLOWED_RW_VOLUMES = set()
        assert b.validate_create(_bind("nuclei-templates:/t"))[0] is False
        assert b.validate_create(_mount(Type="volume", Source="nuclei-templates", Target="/t"))[0] is False
        assert b.validate_create(_bind("nuclei-templates:/t:ro"))[0] is True


def test_volume_driver_options_are_refused():
    """A volume created on first mount with local-driver bind options is a bind
    of any host path under an allowlisted name."""
    with shipped_policy() as b:
        ok, _ = b.validate_create(_mount(
            Type="volume", Source="nuclei-templates", Target="/t",
            VolumeOptions={"DriverConfig": {"Name": "local",
                                            "Options": {"type": "none", "o": "bind", "device": "/"}}}))
        assert ok is False
        ok, _ = b.validate_create({"Image": NAABU, "HostConfig": {
            "VolumeDriver": "attacker/plugin", "Binds": ["nuclei-templates:/t:ro"]}})
        assert ok is False

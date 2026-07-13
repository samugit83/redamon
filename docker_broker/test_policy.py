#!/usr/bin/env python3
"""Unit tests for the Docker broker's security policy (V4).

These test the pure decision functions (validate_create / validate_pull / the
helpers) directly — no docker, no sockets — so they are fast and deterministic.
This is the security-critical core: it decides which container-create requests
escape to the host.

Run:  cd docker_broker && python3 test_policy.py    (or: python3 -m pytest)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import broker  # noqa: E402

PASS = 0
FAIL = 0


def check(desc, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {desc}")
    else:
        FAIL += 1
        print(f"  FAIL {desc}")


def allow(desc, body):
    ok, reason = broker.validate_create(body)
    check(f"ALLOW {desc}", ok is True)


def deny(desc, body, must_mention=None):
    ok, reason = broker.validate_create(body)
    cond = ok is False and (must_mention is None or must_mention in reason)
    check(f"DENY  {desc} (reason={reason!r})", cond)


# Make the test independent of env: pin the bind allowlist to /tmp/redamon.
broker.ALLOWED_BIND_PREFIXES = ["/tmp/redamon"]
# T1/T2: only /tmp/redamon is writable by default (source-tree binds must be ro).
broker.ALLOWED_RW_PREFIXES = ["/tmp/redamon"]

NAABU = "projectdiscovery/naabu:latest"

print("=== ALLOW: legitimate tool runs ===")
allow("plain tool image", {"Image": NAABU})
allow("net=host (needed for SYN/loopback)", {"Image": NAABU, "HostConfig": {"NetworkMode": "host"}})
allow("bind under allowed prefix", {"Image": NAABU, "HostConfig": {"Binds": ["/tmp/redamon/x:/targets:ro"]}})
allow("named volume on allowlist", {"Image": "projectdiscovery/nuclei:latest",
      "HostConfig": {"Mounts": [{"Type": "volume", "Source": "nuclei-templates", "Target": "/root/nuclei-templates"}]}})
allow("NET_RAW capability", {"Image": NAABU, "HostConfig": {"CapAdd": ["NET_RAW"]}})
allow("alpine cleanup helper", {"Image": "alpine", "HostConfig": {"Binds": ["/tmp/redamon/c:/cleanup"]}})
allow("bind via Mounts type=bind under prefix", {"Image": NAABU,
      "HostConfig": {"Mounts": [{"Type": "bind", "Source": "/tmp/redamon/o", "Target": "/output"}]}})

print("=== DENY: host-escape attempts ===")
deny("mount host root /", {"Image": NAABU, "HostConfig": {"Binds": ["/:/host"]}}, "bind")
deny("mount /etc", {"Image": NAABU, "HostConfig": {"Binds": ["/etc:/e:ro"]}}, "bind")
deny("mount docker.sock", {"Image": NAABU, "HostConfig": {"Binds": ["/var/run/docker.sock:/s"]}}, "bind")
deny("mount docker.sock via Mounts", {"Image": NAABU,
     "HostConfig": {"Mounts": [{"Type": "bind", "Source": "/var/run/docker.sock", "Target": "/s"}]}}, "bind")
deny("privileged", {"Image": NAABU, "HostConfig": {"Privileged": True}}, "Privileged")
deny("cap SYS_ADMIN", {"Image": NAABU, "HostConfig": {"CapAdd": ["SYS_ADMIN"]}}, "capability")
deny("cap ALL", {"Image": NAABU, "HostConfig": {"CapAdd": ["ALL"]}}, "capability")
deny("device passthrough", {"Image": NAABU, "HostConfig": {"Devices": [{"PathOnHost": "/dev/sda"}]}}, "device")
deny("pid=host", {"Image": NAABU, "HostConfig": {"PidMode": "host"}}, "PidMode")
deny("pid=container:other (join another ns)", {"Image": NAABU, "HostConfig": {"PidMode": "container:redamon-recon-orchestrator"}}, "PidMode")
deny("net=container:orchestrator (join its netns)", {"Image": NAABU, "HostConfig": {"NetworkMode": "container:redamon-recon-orchestrator"}}, "NetworkMode")
deny("ipc=host", {"Image": NAABU, "HostConfig": {"IpcMode": "host"}}, "IpcMode")
deny("userns=host", {"Image": NAABU, "HostConfig": {"UsernsMode": "host"}}, "UsernsMode")
deny("seccomp unconfined", {"Image": NAABU, "HostConfig": {"SecurityOpt": ["seccomp=unconfined"]}}, "SecurityOpt")
deny("non-allowlisted image", {"Image": "attacker/evil:latest"}, "allowlist")
deny("busybox not allowlisted", {"Image": "busybox"}, "allowlist")
deny("empty image", {"Image": ""}, "allowlist")
deny("tmpfs-less bind to non-allowed volume", {"Image": NAABU,
     "HostConfig": {"Mounts": [{"Type": "volume", "Source": "evil-vol", "Target": "/x"}]}}, "volume")
deny("bind sneaking root via Mounts", {"Image": NAABU,
     "HostConfig": {"Mounts": [{"Type": "bind", "Source": "/", "Target": "/host"}]}}, "bind")

print("=== BYPASS attempts (adversarial) ===")
# A. path traversal in the bind source: starts with /tmp/redamon but escapes to /
deny("traversal bind /tmp/redamon/../../etc",
     {"Image": NAABU, "HostConfig": {"Binds": ["/tmp/redamon/../../etc:/e"]}}, "bind")
deny("traversal bind /tmp/redamon/../../",
     {"Image": NAABU, "HostConfig": {"Binds": ["/tmp/redamon/../..:/host"]}}, "bind")
deny("traversal via Mounts source",
     {"Image": NAABU, "HostConfig": {"Mounts": [{"Type": "bind", "Source": "/tmp/redamon/../../", "Target": "/h"}]}}, "bind")
# B. VolumesFrom: inherit another container's mounts (e.g. the orchestrator's docker.sock)
deny("VolumesFrom inherits another container's mounts",
     {"Image": NAABU, "HostConfig": {"VolumesFrom": ["redamon-recon-orchestrator"]}}, "VolumesFrom")
# C. emptying the default masked/readonly /proc paths
deny("MaskedPaths emptied (unmask /proc)",
     {"Image": NAABU, "HostConfig": {"MaskedPaths": []}}, "MaskedPaths")

print("=== T1/T2: mount-MODE enforcement (source-tree binds must be ro) ===")
# Add the source tree ($PWD) as an allowed *read* prefix, as compose does.
broker.ALLOWED_BIND_PREFIXES = ["/tmp/redamon", "/repo"]
broker.ALLOWED_RW_PREFIXES = ["/tmp/redamon"]
# rw of the writable scratch prefix stays allowed
allow("rw bind of /tmp/redamon (explicit)", {"Image": NAABU, "HostConfig": {"Binds": ["/tmp/redamon/o:/o:rw"]}})
allow("rw bind of /tmp/redamon (default mode)", {"Image": NAABU, "HostConfig": {"Binds": ["/tmp/redamon/o:/o"]}})
# ro of the source tree is fine (tools read wordlists/templates from it)
allow("ro bind of source tree", {"Image": NAABU, "HostConfig": {"Binds": ["/repo/recon:/app/recon:ro"]}})
allow("ro source tree via Mounts (ReadOnly=true)", {"Image": NAABU,
      "HostConfig": {"Mounts": [{"Type": "bind", "Source": "/repo/agentic/skills", "Target": "/s", "ReadOnly": True}]}})
# rw of the source tree is the attack -> denied
deny("rw bind of source tree (overwrite recon/main.py)",
     {"Image": NAABU, "HostConfig": {"Binds": ["/repo/recon:/app/recon:rw"]}}, "read-write")
deny("default-mode (rw) bind of an Agent Skill file",
     {"Image": NAABU, "HostConfig": {"Binds": ["/repo/agentic/skills/x.md:/out"]}}, "read-write")
deny("rw source tree via Mounts (ReadOnly=false)",
     {"Image": NAABU, "HostConfig": {"Mounts": [{"Type": "bind", "Source": "/repo/recon", "Target": "/app/recon"}]}}, "read-write")
deny("rw source tree via Mounts (ReadOnly explicitly false)",
     {"Image": NAABU, "HostConfig": {"Mounts": [{"Type": "bind", "Source": "/repo", "Target": "/r", "ReadOnly": False}]}}, "read-write")
# restore defaults for any later tests
broker.ALLOWED_BIND_PREFIXES = ["/tmp/redamon"]
broker.ALLOWED_RW_PREFIXES = ["/tmp/redamon"]

print("=== pull policy ===")
ok, _ = broker.validate_pull("/v1.43/images/create?fromImage=projectdiscovery/naabu&tag=latest")
check("ALLOW pull allowlisted", ok is True)
ok, _ = broker.validate_pull("/v1.51/images/create?fromImage=docker.io%2Fprojectdiscovery%2Fnaabu&tag=latest")
check("ALLOW encoded Docker Hub pull", ok is True)
ok, _ = broker.validate_pull("/v1.51/images/create?fromImage=ghcr.io%2Fzaproxy%2Fzaproxy&tag=stable")
check("ALLOW encoded GHCR pull", ok is True)
ok, _ = broker.validate_pull("/v1.51/images/create?fromImage=docker.io%2Flibrary%2Falpine&tag=latest")
check("ALLOW encoded official Docker Hub pull", ok is True)
ok, _ = broker.validate_pull("/v1.43/images/create?fromImage=attacker/evil&tag=latest")
check("DENY pull non-allowlisted", ok is False)

print()
print(f"RESULT: PASS={PASS} FAIL={FAIL}")
sys.exit(0 if FAIL == 0 else 1)

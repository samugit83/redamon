"""A label-aware stand-in for the docker-py client, for the stop and pause tests.

`containers.list(filters={"label": [...]})` applies the filter the way the
daemon does (every `key=value` must match), so a test proves which containers
a stop or a pause selects, not merely that a list call was made. Every call is
recorded in `log` as (container id, verb).
"""
from __future__ import annotations

from types import SimpleNamespace

from docker.errors import NotFound

OWNER = "redamon.broker-owned"


class FakeContainer:
    def __init__(self, cid, image="projectdiscovery/naabu:latest", labels=None,
                 status="running", exit_code=0, log=None, name=None):
        self.id = cid
        self.name = name or cid
        self.image_ref = image
        self.image = SimpleNamespace(tags=[image])
        self.labels = dict(labels or {})
        self.status = status
        self.exit_code = exit_code
        self.removed = False
        self.log = log if log is not None else []

    @property
    def attrs(self):
        return {"Config": {"Image": self.image_ref, "Labels": self.labels},
                "State": {"ExitCode": self.exit_code, "Status": self.status}}

    def reload(self):
        return None

    def _record(self, verb):
        self.log.append((self.id, verb))

    def pause(self):
        self._record("pause")
        self.status = "paused"

    def unpause(self):
        self._record("unpause")
        self.status = "running"

    def kill(self, signal="SIGKILL"):
        self._record(f"kill:{signal}")
        if signal in ("SIGKILL", 9):
            self.status = "exited"
            self.exit_code = 137

    def stop(self, timeout=10):
        self._record("stop")
        self.status = "exited"

    def wait(self, timeout=None):
        self._record("wait")
        return {"StatusCode": self.exit_code}

    def remove(self, force=False, v=False):
        self._record("remove:force" if force else "remove")
        self.removed = True
        self.removed_volumes = v


class FakeContainers:
    def __init__(self, containers=()):
        self.items = {c.id: c for c in containers}
        self.list_calls = []

    def add(self, container):
        self.items[container.id] = container
        return container

    def get(self, ref):
        for c in self.items.values():
            if not c.removed and ref in (c.id, c.name):
                return c
        raise NotFound(f"no container {ref}")

    def list(self, **kwargs):
        self.list_calls.append(kwargs)
        filters = kwargs.get("filters") or {}
        wanted = filters.get("label", [])
        if isinstance(wanted, str):
            wanted = [wanted]
        statuses = filters.get("status")
        if isinstance(statuses, str):
            statuses = [statuses]
        out = []
        for c in self.items.values():
            if c.removed:
                continue
            if statuses is not None:
                if c.status not in statuses:
                    continue
            elif not kwargs.get("all") and c.status != "running":
                continue
            if all(c.labels.get(k) == v for k, _, v in (w.partition("=") for w in wanted)):
                out.append(c)
        return out


class FakeClient:
    def __init__(self, containers=()):
        self.containers = FakeContainers(containers)


def tool(cid, run_id, image="projectdiscovery/nuclei:latest", status="running",
         project="proj-a", kind="full_recon", log=None):
    """A tool container the broker created for `run_id`."""
    return FakeContainer(cid, image, {OWNER: "1", "redamon.run_id": run_id,
                                      "redamon.project_id": project,
                                      "redamon.run_kind": kind}, status=status, log=log)

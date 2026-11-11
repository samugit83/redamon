"""Who may change the agent's user MCP toolset (RBAC OQ-41, NF-06).

The agent holds ONE set of user MCP servers for the whole process: rebuilding it per
run is out of scope (T17). So a run whose owner's server set differs from the loaded
one is refused while another owner's run on a different set is live, and the reload
a member's MCP save triggers is deferred in the same case; otherwise the set is
loaded as before. Without the guard the second owner's run swapped the toolset under
the first owner's live run, and a member with no servers ran on another owner's
servers and their tokens.

Every admission and every reload request is synchronous up to the point where it
records the set, so two runs cannot both pass on different sets. The refusal reads
the live runs' sets, not the recorded one, because queued reloads apply in order
and the recorded set can lag them for a moment.
"""
import hashlib
import json
import logging
import uuid
from typing import Optional

logger = logging.getLogger(__name__)

MCP_TOOLSET_BUSY = "mcp_toolset_busy"
MCP_TOOLSET_BUSY_MESSAGE = (
    "Another user's agent run is using a different set of MCP Tool Plugins. "
    "Start again when it has finished."
)
MCP_RELOAD_DEFERRED_MESSAGE = (
    "Saved. Another user's agent run is using the agent's MCP Tool Plugins now; "
    "these load at your next run."
)


def server_set_hash(servers) -> str:
    return hashlib.sha256(
        json.dumps(servers or [], sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


class McpToolsetBusy(Exception):
    code = MCP_TOOLSET_BUSY

    def __init__(self):
        super().__init__(MCP_TOOLSET_BUSY_MESSAGE)


class McpToolsetGuard:
    def __init__(self):
        self.loaded_hash: Optional[str] = None
        self.loaded_servers: Optional[list] = None
        self._live: dict[str, tuple[Optional[str], str]] = {}

    def _held_by_another(self, owner: Optional[str], digest: str) -> bool:
        """A live run of another owner is on a set other than `digest`. An unknown
        owner (None) matches nobody, so its change waits for every such run."""
        return any(o is None or o != owner for o, h in self._live.values() if h != digest)

    def _refuse(self, owner: Optional[str], via: str) -> None:
        holders = sum(1 for o, _ in self._live.values() if o is None or o != owner)
        logger.warning(f"[rbac] mcp toolset busy owner={owner} via={via} live_runs_of_others={holders}")

    def record_loaded(self, servers, owner: Optional[str] = None) -> None:
        self.loaded_servers = list(servers or [])
        self.loaded_hash = server_set_hash(self.loaded_servers)
        if owner is not None:
            # The toolset is process-wide: the owner's other live runs now use this set.
            for lease, (o, _) in list(self._live.items()):
                if o == owner:
                    self._live[lease] = (o, self.loaded_hash)

    def admit_run(self, owner: Optional[str], servers) -> tuple[str, bool]:
        """Register a run as live on its owner's set. Returns (lease, whether that set
        must be loaded now); raises McpToolsetBusy instead of swapping the set under
        another owner's live run."""
        digest = server_set_hash(servers)
        if self._held_by_another(owner, digest):
            self._refuse(owner, "run")
            raise McpToolsetBusy()
        must_load = digest != self.loaded_hash
        if must_load:
            self.record_loaded(servers, owner)
        lease = uuid.uuid4().hex
        self._live[lease] = (owner, digest)
        return lease, must_load

    def release_run(self, lease: str) -> None:
        self._live.pop(lease, None)

    def admit_reload(self, owner: Optional[str], servers) -> bool:
        """False when the reload must wait (the saved set loads at the owner's next
        run start); True after recording `servers` as the loaded set."""
        if self._held_by_another(owner, server_set_hash(servers)):
            self._refuse(owner, "reload")
            return False
        self.record_loaded(servers, owner)
        return True


_guard = McpToolsetGuard()


def toolset_guard() -> McpToolsetGuard:
    return _guard

"""Who may change the agent's user MCP toolset (RBAC OQ-41, NF-06).

The agent holds ONE set of user MCP servers for the whole process: rebuilding it per
run is out of scope (T17). So a run whose owner's server set differs from the loaded
one is refused while another owner's run on a different set is live, and the reload
a member's MCP save triggers is deferred in the same case; otherwise the set is
loaded as before. Without the guard the second owner's run swapped the toolset under
the first owner's live run, and a member with no servers ran on another owner's
servers and their tokens.

Admission is synchronous (the check and the lease are one step for the event loop),
so two runs cannot both pass on different sets. The load itself is the
orchestrator's, serialised, and a run streams only after its owner's set loaded.
A set is recorded as loaded only once it loaded; a failed load records nothing, so
the next admission loads again. The refusal reads the live runs' sets, not the
recorded one: a run admitted but still waiting for its load is already live.
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
MCP_TOOLSET_BUSY_RESUME_MESSAGE = (
    "Another user's agent run is using a different set of MCP Tool Plugins, so your "
    "answer was not applied. Send it again when that run has finished."
)
MCP_RELOAD_DEFERRED_MESSAGE = (
    "Saved. Another user's agent run is using the agent's MCP Tool Plugins now; "
    "these load at your next run."
)


def server_set_hash(servers) -> str:
    """The identity of the toolset a server list loads. A disabled server loads no
    tool and opens no connection, so it is left out: an owner whose only server is
    disabled runs on the same toolset as an owner with none."""
    loading = [s for s in (servers or []) if not (isinstance(s, dict) and s.get("enabled") is False)]
    return hashlib.sha256(
        json.dumps(loading, sort_keys=True, default=str).encode("utf-8")
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
        """Called once `servers` really loaded, never before."""
        self.loaded_servers = list(servers or [])
        self.loaded_hash = server_set_hash(self.loaded_servers)
        if owner is not None:
            # The toolset is process-wide: the owner's other live runs now use this set.
            for lease, (o, _) in list(self._live.items()):
                if o == owner:
                    self._live[lease] = (o, self.loaded_hash)

    def clear_loaded(self) -> None:
        """A load failed: no set is known to be loaded, so the next admission loads."""
        self.loaded_servers = None
        self.loaded_hash = None

    def admit_run(self, owner: Optional[str], servers) -> str:
        """Register a run as live on its owner's set and return its lease; raises
        McpToolsetBusy instead of swapping the set under another owner's live run.
        Records nothing: the run loads its set before it streams."""
        digest = server_set_hash(servers)
        if self._held_by_another(owner, digest):
            self._refuse(owner, "run")
            raise McpToolsetBusy()
        lease = uuid.uuid4().hex
        self._live[lease] = (owner, digest)
        return lease

    def release_run(self, lease: str) -> None:
        self._live.pop(lease, None)

    def admit_reload(self, owner: Optional[str], servers, via: str = "reload") -> bool:
        """False when loading `servers` now would swap the set under another owner's
        live run (a saved set then loads at the owner's next run). Records nothing."""
        if self._held_by_another(owner, server_set_hash(servers)):
            self._refuse(owner, via)
            return False
        return True


_guard = McpToolsetGuard()


def toolset_guard() -> McpToolsetGuard:
    return _guard

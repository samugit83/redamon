"""
Docker container lifecycle management for recon processes
"""
import asyncio
import functools
import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import os
import re
import shutil
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import AsyncGenerator, Optional

import docker
from docker.errors import NotFound, APIError

import resource_governor as rg
from admission_ledger import ReservationLedger, AdmissionError
from ip_denylist import classify_host

# The TruffleHog source registry lives with the scanner and is mounted in
# (compose: ./scanners/trufflehog_scan:/app/trufflehog_scan). Imported through a
# shim that also resolves the repo-checkout path. Guarded because a missing
# mount must degrade to "TruffleHog cannot start" rather than crash-loop the
# whole orchestrator, which spawns six other scan types.
try:
    from trufflehog_registry import sources as th_sources
except ImportError as _th_exc:  # pragma: no cover - deployment misconfiguration
    th_sources = None
    _TRUFFLEHOG_REGISTRY_ERROR = str(_th_exc)
else:
    _TRUFFLEHOG_REGISTRY_ERROR = ""

from models import (
    ReconState, ReconStatus, ReconLogEvent,
    GvmState, GvmStatus, GvmLogEvent,
    GithubHuntState, GithubHuntStatus, GithubHuntLogEvent,
    TrufflehogState, TrufflehogStatus, TrufflehogLogEvent,
    SupplyChainState, SupplyChainStatus, SupplyChainLogEvent,
    PartialReconState, PartialReconStatus,
    AiAttackSurfaceState, AiAttackSurfaceStatus, AiAttackSurfaceLogEvent,
)

logger = logging.getLogger(__name__)

# ANSI escape code pattern for stripping terminal colors from logs
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*m|\033\[[0-9;]*m')


def _env_unset_if_blank(name: str, default: str) -> str:
    """os.environ.get where a BLANK value counts as unset.

    The orchestrator has no env_file, so every knob it honours must be listed in
    its compose environment block - and the pass-through idiom for an optional
    knob is ``VAR: ${VAR:-}``. That means "operator set nothing" arrives as an
    empty string, not as a missing key, and a plain .get(name, default) returns
    "" instead of the default. Mirrors supply_chain_common.analyzer_dispatch._env
    so both analyzer spawn paths agree on what "unset" means."""
    raw = os.environ.get(name)
    return raw.strip() if raw and raw.strip() else default


def sibling_host_path(host_path: str, name: str) -> str:
    """Return the sibling ``name`` of ``host_path`` on the DOCKER HOST filesystem.

    Used to derive the host path of a sibling source dir (e.g. graph_db next to
    recon) for sibling-container bind mounts. Must be robust to BOTH POSIX ('/')
    and Windows ('\\') separators regardless of the OS running this code: the
    orchestrator itself always runs Linux, but on Docker Desktop for Windows the
    ``Source`` reported by ``docker inspect`` can be a Windows path
    (``C:\\Users\\...\\recon``). ``pathlib.PurePosixPath.parent`` collapses such a
    path to ``'.'`` (backslashes are not separators to it), yielding a relative
    mount source that Docker Desktop silently materializes as an EMPTY directory,
    which breaks the mounted Python package. This stays separator-aware so the
    derived path is a real host path on every platform.

    For POSIX sources this returns exactly what ``Path(host_path).parent / name``
    would, so Linux/macOS behavior is unchanged.
    """
    p = host_path.rstrip("/\\")
    idx = max(p.rfind("/"), p.rfind("\\"))
    parent = p[:idx] if idx != -1 else p
    sep = "\\" if ("\\" in p and "/" not in p) else "/"
    return f"{parent}{sep}{name}"


def parent_host_path(host_path: str) -> str:
    """Return the parent of ``host_path`` on the DOCKER HOST filesystem.

    Separator-aware mirror of :func:`sibling_host_path` (see its docstring for why
    ``pathlib`` is avoided for host paths). Used to climb out of ``scanners/`` when
    a scanner source dir must resolve a repo-root sibling (e.g. ``graph_db``) or
    the repo-root build context.
    """
    p = host_path.rstrip("/\\")
    idx = max(p.rfind("/"), p.rfind("\\"))
    return p[:idx] if idx != -1 else p


def join_host_path(host_path: str, *names: str) -> str:
    """Join child ``names`` under ``host_path``, separator-aware.

    Companion to :func:`sibling_host_path`; used to reach a nested repo-relative
    source dir (e.g. ``scanners/supply_chain_common``) from a known host anchor
    without ``pathlib`` collapsing a Windows host path on the Linux orchestrator.
    """
    p = host_path.rstrip("/\\")
    sep = "\\" if ("\\" in p and "/" not in p) else "/"
    for name in names:
        p = f"{p}{sep}{name}"
    return p


# Maximum number of concurrent partial recon runs per project
MAX_PARALLEL_PARTIAL_RECONS = 12

# V4: recon/partial-recon containers reach the BROKER socket through this named
# volume instead of the raw host socket. The docker-broker service serves the
# filtered socket on the volume and filters container-create requests so a
# compromised worker cannot escape to the host. A named volume (not a host
# bind-mount) is used because a live unix socket cannot be shared across
# containers over the host bind bridge on Docker Desktop for Mac; the volume
# lives inside the Linux VM and works on both macOS and native Linux. Overridable
# for tests / alternate layouts.
BROKER_SOCKET_VOLUME = os.environ.get("RECON_DOCKER_BROKER_VOLUME", "redamon_broker_socket")

# Where the cypherfix-work volume is mounted INSIDE the orchestrator container.
# Used to clean up per-job worktrees (the same volume the agent clones into).
CODEFIX_WORK_CONTAINER_BASE = os.environ.get("CODEFIX_WORK_CONTAINER_BASE", "/app/codefix-work")

# Maximum number of concurrent AI Attack Surface jobs per project. The four core
# tools may run together (they share one ref-counted judge), so the cap is a
# runaway-spawn backstop, not a typical-use limit.
MAX_PARALLEL_AI_ATTACK = 6

# Sub-container images spawned by recon (Docker-in-Docker sibling containers)
SUB_CONTAINER_IMAGES = [
    "projectdiscovery/naabu",
    "projectdiscovery/httpx",
    "projectdiscovery/katana",
    "projectdiscovery/nuclei",
    "projectdiscovery/uncover",
    "sxcurity/gau",
    "frost19k/puredns",
]

# Phase patterns to detect from logs
# Order matters - more specific patterns should come first within each phase
PHASE_PATTERNS = [
    (r"\[Phase 1\]|\[PHASE 1\]|Phase 1:|WHOIS Lookup|domain.*discovery|Domain Reconnaissance", "Domain Discovery", 1),
    (r"\[Phase 2\]|\[PHASE 2\]|Phase 2:|NAABU PORT SCANNER|port.*scan", "Port Scanning", 2),
    (r"\[Phase 3\]|\[PHASE 3\]|Phase 3:|HTTPX HTTP PROBER|http.*prob", "HTTP Probing", 3),
    (r"\[Phase 4\]|\[PHASE 4\]|Phase 4:|Resource Enumeration|Katana.*GAU|resource.*enum", "Resource Enumeration", 4),
    (r"\[OpenAPI\]", "OpenAPI Ingestion", 4.25),
    (r"\[Phase 4\.5\]|\[PHASE 4\.5\]|Phase 4\.5:|AI Surface Recon|ai_surface_recon", "AI Surface Recon", 4.5),
    (r"\[Phase 5\]|\[PHASE 5\]|Phase 5:|NUCLEI|Vulnerability Scan|vuln.*scan", "Vulnerability Scanning", 5),
    (r"\[Phase 6\]|\[PHASE 6\]|Phase 6:|CVE LOOKUP|MITRE|CWE|CAPEC", "CVE & MITRE", 6),
]


# GVM phase patterns to detect from logs
GVM_PHASE_PATTERNS = [
    (r"Loading recon data", "Loading Recon Data", 1),
    (r"Connecting to GVM|Waiting for GVM to be ready", "Waiting for GVM", 2),
    (r"Connected to GVM at", "Connected to GVM", 3),
    (r"PHASE 1.*Scanning.*IP|Scanning.*IP addresses", "Scanning IPs", 4),
    (r"PHASE 2.*Scanning.*hostname|Scanning.*hostnames", "Scanning Hostnames", 5),
]


# GitHub Secret Hunt phase patterns to detect from logs
GITHUB_HUNT_PHASE_PATTERNS = [
    (r"GitHub Secret Hunter|Loading.*settings|Initializing", "Loading Settings", 1),
    (r"Scanning repository|Organization found|User found|Scanning organization", "Scanning Repositories", 2),
    (r"SCAN SUMMARY|Final results saved|Scan complete", "Complete", 3),
]

# How many times a finished run's graph ingest is retried before giving up. The
# 30 s sweep would otherwise retry a permanently-failing ingest forever, each
# attempt copying the artifact and opening a fresh Neo4j connection.
#: The non-root identity the scan image runs as
#: (scanners/trufflehog_scan/Dockerfile `useradd --uid 10001 ... trufflehog`).
#: The spawn needs it to hand the home-directory tmpfs to the right owner; if
#: the Dockerfile's user ever changes, both must move together.
TRUFFLEHOG_CONTAINER_USER = "trufflehog"
TRUFFLEHOG_CONTAINER_UID = 10001

MAX_TRUFFLEHOG_INGEST_ATTEMPTS = int(os.environ.get("TRUFFLEHOG_INGEST_ATTEMPTS", "5"))
MAX_GITHUB_HUNT_INGEST_ATTEMPTS = int(os.environ.get("GITHUB_HUNT_INGEST_ATTEMPTS", "5"))

# How long a finished run stays in the state dict before it is pruned. Must stay
# comfortably above the webapp's 90 s reconcile grace: prune sooner and a run
# whose UI was closed disappears from /all before the reconcile reads it, and its
# history row is recorded as `canceled` instead of its real outcome.
TRUFFLEHOG_TERMINAL_RETENTION_S = int(os.environ.get("TRUFFLEHOG_TERMINAL_RETENTION", "600"))

# TruffleHog Secret Scanner phase patterns to detect from logs. Matched against
# what scanners/trufflehog_scan actually prints — the container reads a job file
# now, so there is no settings-loading phase to report.
TRUFFLEHOG_PHASE_PATTERNS = [
    (r"TruffleHog Secret Scanner|\[\*\] Source:", "Preparing", 1),
    (r"\[\*\] Running: trufflehog|\[\+\] Found:", "Scanning", 2),
    (r"SCAN SUMMARY|Results saved to", "Complete", 3),
]

# AI Attack Surface phase patterns. Match ONLY the explicit [Phase N] markers
# that scanners/ai_attack_surface_scan/main.py prints (numbered in execution order).
# Bare keywords would false-match — e.g. "Attack" appears in the banner line
# "AI Attack Surface scan", which would bounce the phase back to 3.
AI_ATTACK_SURFACE_PHASE_PATTERNS = [
    (r"\[Phase 1\]", "Safety / bounds", 1),
    (r"\[Phase 2\]", "Target loading", 2),
    (r"\[Phase 3\]", "Attack", 3),
    (r"\[Phase 4\]", "Findings", 4),
]


def _env_size(name: str, default: str) -> str:
    """A Docker size from env, treating EMPTY as unset.

    compose passes these as `${VAR:-}`, so the variable is present but blank when
    nobody set it; `os.environ.get(name, default)` then returns "" rather than the
    default and Docker gets an empty mem_limit. Always resolve sizes through here.
    """
    raw = (os.environ.get(name) or "").strip()
    return raw if raw else default


class ContainerManager:
    """Manages Docker containers for recon, GVM scan, GitHub hunt, and TruffleHog processes"""

    def __init__(self, recon_image: str = "redamon-recon:latest", gvm_image: str = "redamon-vuln-scanner:latest", github_hunt_image: str = "redamon-github-hunter:latest", trufflehog_image: str = "redamon-trufflehog:latest", ai_attack_image: str = "redamon-ai-attack-surface:latest", supply_chain_image: str = "redamon-supply-chain:latest"):
        self.client = docker.from_env()
        self.recon_image = recon_image
        self.gvm_image = gvm_image
        self.github_hunt_image = github_hunt_image
        self.trufflehog_image = trufflehog_image
        self.ai_attack_image = ai_attack_image
        self.supply_chain_image = supply_chain_image
        self.running_states: dict[str, ReconState] = {}
        # Nested dict: outer key = project_id, inner key = run_id
        self.partial_recon_states: dict[str, dict[str, PartialReconState]] = {}
        self.gvm_states: dict[str, GvmState] = {}
        self.github_hunt_states: dict[str, GithubHuntState] = {}
        # Nested project_id -> source (parallel per-source runs). The inner key is
        # the SOURCE, not a uuid: that makes "one run per source, unlimited
        # distinct sources" a property of the data structure, with no counter to
        # maintain and no trufflehog-specific parallelism cap to tune.
        self.trufflehog_states: dict[str, dict[str, TrufflehogState]] = {}
        self.supply_chain_states: dict[str, SupplyChainState] = {}
        # AI Attack Surface: nested project_id -> run_id (parallel per-tool jobs).
        self.ai_attack_states: dict[str, dict[str, AiAttackSurfaceState]] = {}
        # Set by api.py after construction: the on-demand Ollama judge manager
        # (Step 1). The AI attack lifecycle ref-counts a judge lease through it.
        self.local_llm_manager = None
        # Set by api.py after construction: the AUTO-DETECTED host path of graph_db
        # (from the orchestrator's own /app/graph_db mount). Empty means it could
        # not be detected -- see _graph_db_mount for what happens then.
        self.graph_db_host_path = os.environ.get("GRAPH_DB_PATH", "").strip()
        # Set by api.py after construction, same reason as graph_db_host_path:
        # the sca-intel refresh sidecar needs supply_chain_common's host path and
        # has no recon_path in scope (it runs off the scan-spawn path, not inside
        # one). Derived from this exactly as the three spawn sites derive theirs.
        self.recon_host_path = os.environ.get("RECON_PATH", "").strip()
        self._log_tasks: dict[str, asyncio.Task] = {}

        # Two DEDICATED thread pools, deliberately NOT the default executor.
        #
        # docker-py is synchronous; the async paths offload it to threads so the
        # event loop never blocks. But a log-stream reader thread blocks on
        # container.logs(follow=True) for the WHOLE scan (hours), so each active
        # SSE stream permanently holds one worker. If short status/spawn Docker
        # calls shared that pool, enough concurrent streams would exhaust it and
        # status polls / new scan starts would queue forever -- the same freeze,
        # via pool exhaustion instead of event-loop blocking. Isolating them means
        # request-servicing Docker ops can never be starved by streaming threads.
        self._docker_op_executor = ThreadPoolExecutor(
            max_workers=16, thread_name_prefix="docker-op")      # short status/spawn calls
        self._log_stream_executor = ThreadPoolExecutor(
            max_workers=64, thread_name_prefix="log-stream")     # long-lived follow=True readers

        # CodeFix build sandboxes (T6/E10): ephemeral, hardened, secret-free
        # containers that run the UNTRUSTED clone+build+test step of the CypherFix
        # agent. job_id -> {"container_id", "created_at"}.
        self.codefix_sandbox_image = os.environ.get("CODEFIX_SANDBOX_IMAGE", "redamon-codefix-sandbox:latest")
        self.codefix_sandbox_network = os.environ.get("CODEFIX_SANDBOX_NETWORK", "redamon-codefix-net")
        self.codefix_sandbox_mem = _env_size("CODEFIX_SANDBOX_MEM", "2g")
        self.codefix_sandbox_nanocpus = int(os.environ.get("CODEFIX_SANDBOX_NANOCPUS", str(2_000_000_000)))
        self.codefix_sandbox_pids = int(os.environ.get("CODEFIX_SANDBOX_PIDS", "512"))
        # Max lifetime before the reaper force-removes a sandbox (orphaned by a
        # crashed agent). Generous because real builds can be slow.
        self.codefix_sandbox_ttl = int(os.environ.get("CODEFIX_SANDBOX_TTL", "3600"))
        # Host path of the cypherfix-work volume (set by api.py after mount
        # auto-detection) — used to bind per-job worktrees into the sandbox.
        self.codefix_work_host_base: Optional[str] = None
        self.codefix_sandboxes: dict[str, dict] = {}

        # Supply-chain DIRTY analyzer (plan section 5.2): ephemeral, hardened,
        # SECRET-FREE container that processes untrusted supply-chain input
        # (tarballs, target-served JS, manifests/SBOMs). OSV path is fully
        # network-isolated; GuardDog (opt-in) needs registry egress. Modeled on
        # the codefix sandbox, NOT on trufflehog (which holds Neo4j creds).
        #
        # Read through _env_unset_if_blank: docker-compose wires these as
        # ${VAR:-}, so an operator who set nothing still hands this constructor
        # an empty string. int("") would raise here, in __init__, crash-looping
        # the orchestrator the moment the knobs were wired into compose.
        self.supply_chain_analyzer_image = _env_unset_if_blank(
            "SUPPLY_CHAIN_ANALYZER_IMAGE", "redamon-supply-chain-analyzer:latest")
        self.supply_chain_analyzer_network = _env_unset_if_blank(
            "SUPPLY_CHAIN_ANALYZER_NETWORK", "redamon-supply-chain-net")
        self.supply_chain_analyzer_mem = _env_unset_if_blank(
            "SUPPLY_CHAIN_ANALYZER_MEM", "1500m")
        self.supply_chain_analyzer_nanocpus = int(
            _env_unset_if_blank("SUPPLY_CHAIN_ANALYZER_NANOCPUS", str(2_000_000_000)))
        self.supply_chain_analyzer_pids = int(
            _env_unset_if_blank("SUPPLY_CHAIN_ANALYZER_PIDS", "512"))
        # TruffleHog scan network. A user-defined bridge, never host: the scan
        # needs outbound internet but must not see the host's loopback stack,
        # where Neo4j (7687) and the orchestrator (8010) listen.
        self.trufflehog_network = _env_unset_if_blank(
            "TRUFFLEHOG_NETWORK", "redamon-trufflehog-net")
        # Allowlisted host paths for the `filesystem` source, keyed by the UI
        # value. Server-resolved on purpose: an operator-typed host path plus a
        # scan container is a file-disclosure primitive. Absent => not mounted,
        # so the scan finds an empty dir rather than something unintended.
        # Overwritten by api.py from the orchestrator's OWN detected mounts (the
        # repo's rule for host paths); the env vars are only the fallback for a
        # non-compose run. Absent => that root is not offered to the scan.
        # Host path of scanners/scan_targets — the ONLY directory a scan
        # container may read from disk. Overwritten by api.py from the
        # orchestrator's OWN detected mounts (the repo's rule for host paths);
        # this env var is the fallback for a non-compose run. Empty => no mount,
        # and the scan finds an empty directory rather than a guessed one.
        self.trufflehog_scan_targets = os.environ.get(
            "TRUFFLEHOG_SCAN_TARGETS_PATH", "").strip()
        # Injected by api.py when a scope/ROE loader is configured; see
        # _trufflehog_scope_check. None => no scope declared, same as other scans.
        self.trufflehog_scope_checker = None
        self.supply_chain_osv_db_volume = os.environ.get(
            "SUPPLY_CHAIN_OSV_DB_VOLUME", "redamon-osv-db")
        # Named volume shared with the webapp: the operator's uploaded SBOM/
        # lockfile lands at <volume>/<project_id>/<filename>.
        self.supply_chain_uploads_volume = os.environ.get(
            "SUPPLY_CHAIN_UPLOADS_VOLUME", "redamon_supply_chain_uploads")
        # Lazy-on-scan OSV DB refresh: hard ceiling on the sync sidecar so a slow
        # download can never stall a scan spawn (npm is ~208 MB on a cold volume).
        self.osv_db_refresh_timeout = int(
            os.environ.get("OSV_DB_REFRESH_TIMEOUT", "900"))
        # Serializes OSV DB refreshes (see ensure_osv_db_fresh): concurrent scan
        # starts must not spawn two sidecars writing the same volume.
        self._osv_db_refresh_lock = threading.Lock()
        # Supply-chain incident intel (supplychainattack.org catalog), refreshed
        # TTL-guarded on the scan-spawn path like the OSV DB above.
        self.sca_intel_volume = os.environ.get("SCA_INTEL_VOLUME", "redamon-sca-intel")
        # 120s, not the OSV path's 900s: this feed is ~5 MB, so a longer ceiling
        # would only ever mean a hung fetch sitting on the scan-spawn path.
        self.sca_intel_refresh_timeout = int(
            os.environ.get("SCA_INTEL_REFRESH_TIMEOUT", "120"))
        # A SEPARATE lock from the OSV one: different volumes, and a shared lock
        # would let either refresh silently starve the other.
        self._sca_intel_refresh_lock = threading.Lock()
        # Operator's incident-match ignore list (their own OAST providers).
        # Refreshed by api.py's capture-config reconciler and injected into the
        # recon spawn; empty means "use the shipped provider list".
        self.sca_intel_ignore_suffixes = os.environ.get(
            "CAPTURE_IOC_IGNORE_SUFFIXES", "").strip()

        # Memory governor (Part 1): reserves each scan job's expected RAM envelope
        # before spawning so concurrent scans can never sum past the host's scan
        # pool. Fail-open: with the governor disabled, try_admit always admits.
        self.ledger = ReservationLedger()
        # Reservation keys for in-flight L3 GuardDog analyzer jobs. These have no
        # state dict of their own (they are request-scoped, not scans), so they
        # are tracked here purely so _active_scan_keys can protect them from the
        # reaper for the seconds-to-minutes they run.
        self.guarddog_jobs: set = set()

    def _scan_key(self, kind: str, project_id: str, run_id: Optional[str] = None) -> str:
        """Stable reservation key for a scan job."""
        base = f"{kind}:{project_id}"
        return f"{base}:{run_id}" if run_id else base

    @staticmethod
    def _partial_kind(tool_id: Optional[str]) -> str:
        """Tool-qualified admission kind for a partial recon.

        Partial tools are not interchangeable in RAM terms: most are a single
        cheap step, but SupplyChainRecon re-runs the JS fetch AND spawns the
        dirty analyzer. resource_governor.scan_job_envelope() resolves
        "partial_recon:<tool>" and falls back to the plain "partial_recon"
        envelope for any tool without its own entry, so qualifying every tool is
        safe and keeps admission and reconcile on ONE key format. Using the plain
        kind at admission and a qualified one in _active_scan_keys (or vice
        versa) would make the reaper free a live scan's reservation."""
        return f"partial_recon:{tool_id}" if tool_id else "partial_recon"

    async def _admit_scan(self, kind: str, project_id: str, run_id: Optional[str] = None,
                          user_id: Optional[str] = None) -> str:
        """Reserve RAM for a scan of `kind`; raise AdmissionError if it doesn't fit.
        Returns the reservation key (release via reconcile / release_nowait).
        `user_id` (D3) subjects the scan to the per-user concurrent-scan ceiling."""
        key = self._scan_key(kind, project_id, run_id)
        envelope = self.ledger.envelope_for(kind)
        result = await self.ledger.try_admit(key, envelope, user_id=user_id)
        if not result.admitted:
            logger.info(f"[governor] admission denied for {key}: {result.limit_type} - {result.detail}")
            raise AdmissionError(result)
        logger.info(f"[governor] admitted {key} (envelope {envelope // (1024**2)} MB, "
                    f"committed {self.ledger.committed_bytes() // (1024**2)} MB / "
                    f"pool {self.ledger.scan_pool() // (1024**2)} MB)")
        return key

    def _active_scan_keys(self) -> set:
        """All reservation keys whose scan is genuinely still RUNNING/STARTING.
        Used by reconcile() to release reservations for finished/dead scans without
        having to hook every terminal path (leak-proof)."""
        keys = set()
        for pid, st in self.running_states.items():
            if st.status in (ReconStatus.RUNNING, ReconStatus.STARTING, ReconStatus.PAUSED):
                keys.add(self._scan_key("full_recon", pid))
        for pid, runs in self.partial_recon_states.items():
            for rid, st in runs.items():
                if st.status in (PartialReconStatus.RUNNING, PartialReconStatus.STARTING):
                    keys.add(self._scan_key(self._partial_kind(st.tool_id), pid, rid))
        for pid, runs in self.ai_attack_states.items():
            for rid, st in runs.items():
                if st.status in (AiAttackSurfaceStatus.RUNNING, AiAttackSurfaceStatus.STARTING):
                    keys.add(self._scan_key("ai_attack", pid, rid))
        # PAUSED counts as active for all pausable types: the container stays
        # resident holding RAM, and resume does not re-admit — dropping the
        # reservation here would under-count and risk OOM on the next admit.
        for pid, st in self.gvm_states.items():
            if st.status in (GvmStatus.RUNNING, GvmStatus.STARTING, GvmStatus.PAUSED):
                keys.add(self._scan_key("gvm", pid))
        for pid, st in self.github_hunt_states.items():
            if st.status in (GithubHuntStatus.RUNNING, GithubHuntStatus.STARTING, GithubHuntStatus.PAUSED):
                keys.add(self._scan_key("github_hunt", pid))
        for pid, runs in self.trufflehog_states.items():
            for source, st in runs.items():
                if st.status in (TrufflehogStatus.RUNNING, TrufflehogStatus.STARTING, TrufflehogStatus.PAUSED):
                    # MUST match the key _admit_scan built, source-qualified kind
                    # included. A mismatch makes the 30 s reaper free a live
                    # scan's reservation and the governor over-admit into OOM.
                    keys.add(self._scan_key(self._trufflehog_kind(source), pid, source))
        for pid, st in self.supply_chain_states.items():
            if st.status in (SupplyChainStatus.RUNNING, SupplyChainStatus.STARTING, SupplyChainStatus.PAUSED):
                keys.add(self._scan_key("supply_chain", pid))
        # L3 GuardDog jobs are transient (no state dict, seconds-to-minutes) but
        # they DO hold a reservation. Without them here the 30 s reaper would
        # free a live job's bytes and the ledger would under-count.
        keys |= self.guarddog_jobs
        # Phase 7: CodeFix build sandboxes hold an accounted reservation; keep it
        # until the sandbox is stopped/reaped, or the reaper would free live bytes.
        for job_id in self.codefix_sandboxes:
            keys.add(self._scan_key("codefix", job_id))
        return keys

    def active_scan_projects(self) -> set:
        """Project IDs with at least one scan container currently RUNNING/STARTING/
        PAUSED. Used by the Scan Queue reconcile (C-6) to close 'running' JobQueue
        rows whose project no longer has any live scan, even with no browser open."""
        projects = set()
        for pid, st in self.running_states.items():
            if st.status in (ReconStatus.RUNNING, ReconStatus.STARTING, ReconStatus.PAUSED):
                projects.add(pid)
        for pid, runs in self.partial_recon_states.items():
            if any(st.status in (PartialReconStatus.RUNNING, PartialReconStatus.STARTING)
                   for st in runs.values()):
                projects.add(pid)
        for pid, runs in self.ai_attack_states.items():
            if any(st.status in (AiAttackSurfaceStatus.RUNNING, AiAttackSurfaceStatus.STARTING)
                   for st in runs.values()):
                projects.add(pid)
        for pid, st in self.gvm_states.items():
            if st.status in (GvmStatus.RUNNING, GvmStatus.STARTING, GvmStatus.PAUSED):
                projects.add(pid)
        for pid, st in self.github_hunt_states.items():
            if st.status in (GithubHuntStatus.RUNNING, GithubHuntStatus.STARTING, GithubHuntStatus.PAUSED):
                projects.add(pid)
        for pid, runs in self.trufflehog_states.items():
            if any(st.status in (TrufflehogStatus.RUNNING, TrufflehogStatus.STARTING,
                                 TrufflehogStatus.PAUSED)
                   for st in runs.values()):
                projects.add(pid)
        for pid, st in self.supply_chain_states.items():
            if st.status in (SupplyChainStatus.RUNNING, SupplyChainStatus.STARTING, SupplyChainStatus.PAUSED):
                projects.add(pid)
        return projects

    async def refresh_all_scan_states(self) -> None:
        """Advance every scan's in-memory status by polling Docker, so reconcile()
        sees terminal (COMPLETED/ERROR) states even when no client is polling the
        status endpoints. Without this, a scan that finishes while its UI tab is
        closed would hold its reservation until someone polls (false denials).
        Each refresh is guarded so one failure can't abort the sweep."""
        for pid in list(self.running_states.keys()):
            try:
                await self.get_status(pid)
            except Exception:
                pass
        for pid in list(self.partial_recon_states.keys()):
            try:
                await self.get_all_partial_recon_statuses(pid)
            except Exception:
                pass
        for pid in list(self.ai_attack_states.keys()):
            try:
                await self.get_all_ai_attack_surface_statuses(pid)
            except Exception:
                pass
        for pid in list(self.gvm_states.keys()):
            try:
                await self.get_gvm_status(pid)
            except Exception:
                pass
        for pid in list(self.github_hunt_states.keys()):
            try:
                await self.get_github_hunt_status(pid)
            except Exception:
                pass
        for pid in list(self.trufflehog_states.keys()):
            try:
                await self.get_all_trufflehog_statuses(pid)
            except Exception:
                pass
        # L1-1: sweep supply-chain too, or a finished scan whose tab is closed
        # keeps its RUNNING state forever -> its 900 MB reservation never releases
        # -> governor falsely denies later scans.
        for pid in list(self.supply_chain_states.keys()):
            try:
                await self.get_supply_chain_status(pid)
            except Exception:
                pass

    def _container_mem_limit(self, kind: str) -> Optional[int]:
        """Hard per-container memory ceiling (bytes) for a spawned SCAN, sized from
        the job envelope × headroom and clamped to PER_CONTAINER_MAX so one
        container can never take the whole host. Generous backstop: it sits ABOVE
        the admission envelope so a normal peak is never killed, only a runaway.
        Returns None (no limit) only when the governor is DISABLED. Unreadable RAM
        is not a None case: the envelope x headroom is still a valid ceiling and
        only the PER_CONTAINER_MAX clamp degrades.

        The clamp itself lives in resource_governor.container_cap() because the
        recon and L1 containers spawn capped siblings too and cannot import this
        module; keeping it here is what let their caps drift into literals."""
        return rg.container_cap(self.ledger.envelope_for(kind))

    def _tool_container_mem_limit(self, tool: str, override_env: Optional[str] = None):
        """Hard ceiling for a spawned SIBLING TOOL container (the dirty analyzer),
        sized from its own tool envelope rather than from whichever scan happens
        to be dispatching it. The two are different quantities: an L3 GuardDog
        call has no scan anywhere near it, yet used to be capped by the L1 scan's
        envelope.

        Precedence MUST match supply_chain_common.analyzer_dispatch._resolve_mem:
        operator override > governor > caller default. The analyzer is spawned
        both here (Docker SDK) and there (broker socket), and the whole point of
        that module is that the two agree. Reading the override only as a
        *fallback* here meant an operator who set SUPPLY_CHAIN_ANALYZER_MEM=700m
        got 700m from recon and the governed 1.5 GB from the orchestrator — the
        same divergence, just pointing the other way.

        Read at call time, not from __init__, so a late env var still lands.
        Returns a Docker size string for an override, bytes for a governed value,
        or None when the governor is disabled (caller falls back)."""
        if override_env:
            raw = os.environ.get(override_env)
            if raw and raw.strip():
                return raw.strip()
        return rg.container_cap(rg.tool_container_envelope(tool))

    _ANALYZER_MEM_ENV = "SUPPLY_CHAIN_ANALYZER_MEM"

    def _analyzer_mem_limit(self):
        """The dirty analyzer's ceiling, one resolution for both SDK spawn sites."""
        return (self._tool_container_mem_limit("supply_chain_analyzer",
                                               self._ANALYZER_MEM_ENV)
                or self.supply_chain_analyzer_mem)

    def _analyzer_envelope(self) -> int:
        """RAM to RESERVE for one analyzer job.

        Normally the tool envelope. But an operator override raises the hard cap
        without telling the ledger, so a 4 GB override would let the container
        take 4 GB against a 1 GB reservation. Reserve the larger of the two: the
        ledger must never promise less than the container is permitted to use."""
        envelope = rg.tool_container_envelope("supply_chain_analyzer")
        raw = os.environ.get(self._ANALYZER_MEM_ENV)
        if raw and raw.strip():
            parsed = rg.parse_size(raw.strip())
            if parsed and parsed > envelope:
                return parsed
        return envelope

    def _container_cpu_limit(self) -> Optional[int]:
        """D1: hard per-container CPU ceiling (nano_cpus) for a spawned scan,
        sized PROPORTIONAL to the detected core count (CONTAINER_CPU_FRACTION of
        the host's cores), clamped to an absolute PER_CONTAINER_CPUS ceiling.
        This is the one cap that scales with the machine. Falls open (None → no
        cpu cap) when the governor is disabled or the fraction is non-positive."""
        if not rg.governor_enabled():
            return None
        fraction = rg._env_float("CONTAINER_CPU_FRACTION", 0.5)
        if fraction <= 0:
            return None
        cpus = max(1.0, rg.cpu_cores() * fraction)
        per_max = rg._env_float("PER_CONTAINER_CPUS", 0.0)
        if per_max > 0:
            cpus = min(cpus, per_max)
        return int(cpus * 1_000_000_000)

    def _container_pids_limit(self) -> Optional[int]:
        """D1: fixed generous PID ceiling for a spawned scan. Deliberately NOT
        core-proportional — a fork bomb is stopped by any finite ceiling, and
        scaling pids to core count risks under-capping on big hosts. Mirrors
        start_codefix_sandbox's pids_limit=512. Falls open when governor off."""
        if not rg.governor_enabled():
            return None
        try:
            return max(1, int(os.environ.get("CONTAINER_PIDS_MAX", "512")))
        except (TypeError, ValueError):
            return 512

    def _scanner_env(self) -> dict:
        """S3/E6: give scan spawns the SCOPED scanner token instead of the master
        INTERNAL_API_KEY, so a compromised scanner cannot mint an admin, harvest
        LLM-provider keys, or reach the control plane. Falls back to the master
        key ONLY when SCANNER_API_KEY is unset/placeholder (pre-secret installs),
        so an operator who runs `up` before `update` is never hard-broken; the
        scope closes automatically once redamon.sh generates the key."""
        scanner = os.environ.get("SCANNER_API_KEY", "")
        if scanner and scanner != "changeme":
            return {"SCANNER_API_KEY": scanner}
        return {"INTERNAL_API_KEY": os.environ.get("INTERNAL_API_KEY", "")}

    # The dirty-analyzer knobs an operator may pin in .env. They are read from
    # os.environ by BOTH spawn implementations (this module for the SDK path,
    # supply_chain_common.analyzer_dispatch for the broker path), and the whole
    # point of analyzer_dispatch is that the two agree. The dispatch copy runs
    # INSIDE the recon / L1-scan container, which inherits nothing from the
    # orchestrator, so without this passthrough an override reached only the
    # orchestrator's own spawns: a `SUPPLY_CHAIN_ANALYZER_MEM=700m` produced a
    # 700m analyzer from L3 and a governed ~1.5 GB one from every recon/L1 job.
    # Exactly the divergence the parity contract exists to prevent.
    _ANALYZER_PASSTHROUGH_ENV = (
        "SUPPLY_CHAIN_ANALYZER_IMAGE",
        "SUPPLY_CHAIN_ANALYZER_NETWORK",
        "SUPPLY_CHAIN_ANALYZER_MEM",
        "SUPPLY_CHAIN_ANALYZER_NANOCPUS",
        "SUPPLY_CHAIN_ANALYZER_PIDS",
    )

    def _analyzer_env(self) -> dict:
        """Forward the operator's analyzer overrides to a spawned scan container.

        Only keys the operator actually SET are forwarded. Passing the resolved
        values instead would be wrong: it would freeze the override precedence
        (override > governor > literal) at spawn time, so the analyzer would
        keep a stale ceiling even after the governor recalibrated, and an unset
        knob would arrive looking like an explicit operator pin."""
        return {k: os.environ[k] for k in self._ANALYZER_PASSTHROUGH_ENV
                if os.environ.get(k, "").strip()}

    def _scanner_hardening(self, drop_caps: bool = False) -> dict:
        """S3/E6 per-spawn privilege reduction (D1 pattern). Returns kwargs to
        splat into containers.run(). Kept as the single hook for future cap
        tightening; drop_caps is currently False at every call site.

        The privilege reduction is a documented RESIDUAL - the scoped
        SCANNER_API_KEY (the primary S3/E6 win) is what closes the escalation and
        it applies to every spawn. Two container-level hardenings were attempted
        and reverted because they hard-break recon on this deployment:
          - security_opt no-new-privileges: makes the recon image unable to exec
            ANY binary ("operation not permitted", even python) on this runtime -
            the image ships setuid tooling (su/mount, ping+cap).
          - cap_drop:[ALL]: strips CAP_DAC_OVERRIDE, so root-in-container can no
            longer write into the HOST-OWNED bind-mounted source tree (the recon
            entrypoint mkdir's /app/recon/data/... and writes output there) -
            container exits immediately with "Permission denied".
        Re-enabling either requires re-adding the exact caps the entrypoint needs
        (DAC_OVERRIDE/CHOWN/FOWNER/SETUID/SETGID/NET_RAW), verified per image."""
        kw: dict = {}
        if drop_caps:
            kw["cap_drop"] = ["ALL"]
        return kw

    def _graph_db_mount(self, derived: str, *, baked_into_image: bool) -> dict:
        """The ``/app/graph_db`` bind for a spawned scan container.

        Returns a volumes fragment to splat (``**``) into the mount dict - possibly
        EMPTY, which deliberately leaves the image's own copy of graph_db in place.

        Prefers ``self.graph_db_host_path``: the host path Docker itself reports for
        the orchestrator's ``/app/graph_db`` mount (resolved by api.py, GRAPH_DB_PATH
        env as override). ``derived`` is the legacy sibling-of-a-sibling GUESS
        (``sibling_host_path(recon_path, "graph_db")`` and friends) and is only a
        last resort, because the guess is wrong on any host where Docker reports a
        rewritten bind ``Source`` - Docker Desktop on Windows/WSL2 - and a wrong bind
        source is NOT an error to Docker: it silently auto-creates an empty
        root-owned directory and mounts that. The empty dir then shadows the good
        graph_db baked into the scan image, and the scan dies with

            ImportError: cannot import name 'Neo4jClient' from 'graph_db'
            (unknown location)

        ("unknown location" = Python found the directory but no ``__init__.py``, i.e.
        an empty namespace package). Full recon wraps its graph imports in
        try/except so it merely stops writing to Neo4j in silence; partial recon has
        no such net and hard-crashes. See issue #169.

        So when the image ALREADY bakes graph_db (recon, gvm, github-hunt,
        trufflehog), an unverifiable guess is strictly worse than not mounting at
        all: skip it and let the baked copy serve, at the cost of graph_db source
        hot-reload until the operator adds the compose mount. Only an image that
        does NOT bake it (supply-chain) has to gamble on the guess.
        """
        # getattr: api.py sets this AFTER construction, and the helpers are also
        # exercised on instances built without __init__.
        source = (getattr(self, "graph_db_host_path", "") or "").strip()
        if source:
            return {source: {"bind": "/app/graph_db", "mode": "ro"}}

        if baked_into_image:
            logger.warning(
                "graph_db host path not auto-detected; SKIPPING the /app/graph_db bind "
                "and using the copy baked into the scan image. Mounting the derived "
                "guess (%s) risks binding an empty auto-created dir over it. Add "
                "'./graph_db:/app/graph_db:ro' to the recon-orchestrator volumes and "
                "recreate it (or set GRAPH_DB_PATH) to restore graph_db hot-reload.",
                derived,
            )
            return {}

        derived = (derived or "").strip()
        if not derived:
            # No detected path and nothing to fall back to. An empty mount KEY would
            # make docker-py send a malformed bind, so bind nothing at all.
            logger.error(
                "graph_db host path is neither auto-detected nor derivable; the spawned "
                "container will have no /app/graph_db. Set GRAPH_DB_PATH or add "
                "'./graph_db:/app/graph_db:ro' to the recon-orchestrator volumes."
            )
            return {}

        logger.warning(
            "graph_db host path not auto-detected; falling back to the derived guess "
            "(%s) because this image does not bake graph_db. If the scan fails with "
            "\"cannot import name 'Neo4jClient' from 'graph_db' (unknown location)\", "
            "that guess is wrong on this host: add './graph_db:/app/graph_db:ro' to "
            "the recon-orchestrator volumes and recreate it (or set GRAPH_DB_PATH).",
            derived,
        )
        return {derived: {"bind": "/app/graph_db", "mode": "ro"}}

    def reconcile_reservations(self) -> int:
        """Release reservations for scans that are no longer active. Call
        periodically (reaper) so nothing leaks even if a spawn/terminal path is
        missed. Returns count released."""
        try:
            return self.ledger.reconcile(self._active_scan_keys())
        except Exception as e:
            logger.warning(f"[governor] reconcile failed: {e}")
            return 0

    def _get_container_name(self, project_id: str) -> str:
        """Generate container name for a project"""
        # Sanitize project_id for container name
        safe_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', project_id)
        return f"redamon-recon-{safe_id}"

    async def _run_blocking(self, fn, *args):
        """Run a blocking (docker-py) callable in the default thread pool so it
        never stalls the single asyncio event loop.

        docker-py is synchronous: a direct call inside an `async def` blocks the
        ONE uvicorn worker's event loop until the Docker daemon answers, so every
        other in-flight request (health checks, status polls, new scan starts)
        stalls with it. Under a busy daemon (many parallel scans + heavy log
        streaming) that starves the loop and freezes the whole orchestrator. All
        synchronous Docker I/O on the async paths must go through here."""
        loop = asyncio.get_running_loop()
        # Dedicated pool (NOT the default): never shares workers with the
        # long-lived log-stream readers, so status/spawn calls can't be starved.
        return await loop.run_in_executor(self._docker_op_executor, fn, *args)

    async def get_status(self, project_id: str) -> ReconState:
        """Get current status of a recon process.

        The Docker inspection runs off the event loop via _run_blocking so a slow
        Docker daemon can't stall the single worker and freeze every request."""
        return await self._run_blocking(self._get_status_sync, project_id)

    def _get_status_sync(self, project_id: str) -> ReconState:
        """Synchronous Docker inspection body of get_status(). Call ONLY via
        _run_blocking so it never executes directly on the event loop."""
        if project_id in self.running_states:
            state = self.running_states[project_id]

            # Check if container is still running
            if state.container_id:
                try:
                    container = self.client.containers.get(state.container_id)
                    if container.status == "paused":
                        state.status = ReconStatus.PAUSED
                    elif container.status != "running":
                        # Container stopped - check exit code
                        exit_code = container.attrs.get("State", {}).get("ExitCode", -1)
                        if exit_code == 0:
                            state.status = ReconStatus.COMPLETED
                            state.completed_at = datetime.now(timezone.utc)
                        else:
                            state.status = ReconStatus.ERROR
                            state.error = f"Container exited with code {exit_code}"
                            state.completed_at = datetime.now(timezone.utc)

                        # Auto-cleanup: remove finished container
                        try:
                            container.remove()
                            logger.info(f"Auto-removed finished container for project {project_id}")
                        except Exception as e:
                            logger.warning(f"Failed to auto-remove container: {e}")
                except NotFound:
                    # Only set error if not already in a terminal state
                    # (container may have been auto-removed after completion)
                    if state.status not in (ReconStatus.COMPLETED, ReconStatus.ERROR):
                        state.status = ReconStatus.ERROR
                        state.error = "Container not found"
                except APIError as e:
                    logger.warning(f"Docker API error checking recon container for {project_id}: {e}")
                    if state.status not in (ReconStatus.COMPLETED, ReconStatus.ERROR):
                        state.status = ReconStatus.ERROR
                        state.error = f"Docker API error: {e}"

            return state

        # Check if there's an orphan container
        container_name = self._get_container_name(project_id)
        try:
            container = self.client.containers.get(container_name)
            if container.status in ("running", "paused"):
                return ReconState(
                    project_id=project_id,
                    status=ReconStatus.PAUSED if container.status == "paused" else ReconStatus.RUNNING,
                    container_id=container.id,
                )
        except NotFound:
            pass

        return ReconState(
            project_id=project_id,
            status=ReconStatus.IDLE,
        )

    async def start_recon(
        self,
        project_id: str,
        user_id: str,
        webapp_api_url: str,
        recon_path: str,
        custom_templates_path: str = "",
        scan_mode: Optional[str] = None,
    ) -> ReconState:
        """Start a recon container for a project.

        `scan_mode` ("new" | "overwrite") is Scan Timeline telemetry: the webapp has
        already decided what happens to the outgoing graph (frozen as a saved
        version, or discarded) before calling us. It changes NOTHING about the
        pipeline — a full recon always wipes and rebuilds the live graph — it is
        only forwarded to the container as SCAN_MODE for logs/telemetry.
        """

        # Check if already running or paused
        current_state = await self.get_status(project_id)
        if current_state.status in (ReconStatus.RUNNING, ReconStatus.PAUSED):
            raise ValueError(f"Recon already active for project {project_id}")

        # Mutual exclusion: block if any partial recon is running
        if self._count_active_partial_recons(project_id) > 0:
            raise ValueError(f"Partial recon(s) running for project {project_id}. Stop them first.")

        # Memory admission (Part 1): reserve this scan's RAM envelope or reject.
        await self._admit_scan("full_recon", project_id, user_id=user_id)

        # Lazy-on-scan OSV DB refresh for the L2 supply-chain module (GROUP 5.5).
        # TTL-guarded, so this is a ~1s no-op unless the feed is >24h old, and
        # best-effort so a refresh failure never blocks recon. Runs unconditionally
        # rather than gating on supplyChainReconEnabled: the check is nearly free
        # and keeps the spawn path decoupled from a webapp settings fetch.
        await self.ensure_osv_db_fresh_async()
        # Same contract for the incident intel: TTL-guarded, best-effort, and it
        # can never block the spawn. Kept beside the OSV call so the two cannot
        # drift apart.
        await self.ensure_sca_intel_fresh_async()

        # Mint a run id for this full-recon scan. Full recon had no run id (unlike
        # partial/ai-attack); the HTTP traffic-capture layer tags every captured
        # transaction with it so the /traffic UI can group "this scan's traffic".
        recon_run_id = str(uuid.uuid4())

        # Clean up any existing container
        container_name = self._get_container_name(project_id)
        try:
            old_container = self.client.containers.get(container_name)
            old_container.remove(force=True)
            logger.info(f"Removed old container {container_name}")
        except NotFound:
            pass

        # Create new state
        state = ReconState(
            project_id=project_id,
            status=ReconStatus.STARTING,
            started_at=datetime.now(timezone.utc),
        )
        self.running_states[project_id] = state

        try:
            # Ensure recon image exists
            try:
                self.client.images.get(self.recon_image)
            except NotFound:
                logger.info(f"Building recon image from {recon_path}")
                self.client.images.build(
                    path=recon_path,
                    tag=self.recon_image,
                    rm=True,
                )

            # Start container with environment variables
            container = self.client.containers.run(
                self.recon_image,
                name=container_name,
                detach=True,
                network_mode="host",
                # Not privileged: Docker's default capability set already includes
                # NET_RAW, which is all the native masscan/nmap SYN scans need. Full
                # `privileged` (all ~40 caps + host device access + seccomp disabled +
                # /proc unmasked) was a host-escape primitive the recon container did
                # not need; dropping it leaves the benign default caps intact.
                cap_add=["NET_RAW"],
                environment={
                    "PROJECT_ID": project_id,
                    "USER_ID": user_id,
                    "WEBAPP_API_URL": webapp_api_url,
                    # V3: operator-approved extra tool images (empty = strict
                    # shipped-only allowlist). Server-controlled; forwarded to the
                    # recon pipeline so air-gapped/private-registry deployments work.
                    "RECON_EXTRA_ALLOWED_IMAGES": os.environ.get("RECON_EXTRA_ALLOWED_IMAGES", ""),
                    "RECON_RUN_ID": recon_run_id,
                    # Scan Timeline telemetry only (see start_recon docstring).
                    "SCAN_MODE": scan_mode or "",
                    "UPDATE_GRAPH_DB": "true",
                    # HOST_RECON_OUTPUT_PATH: Required for nested Docker containers (naabu, httpx, etc.)
                    # These run as sibling containers and need host paths for volume mounts
                    "HOST_RECON_OUTPUT_PATH": f"{recon_path}/output",
                    # Custom nuclei templates host path (for sibling nuclei container volume mount)
                    "HOST_CUSTOM_TEMPLATES_PATH": custom_templates_path,
                    # Forward credentials from orchestrator environment
                    "NEO4J_URI": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                    "NEO4J_USER": os.environ.get("NEO4J_USER", "neo4j"),
                    "NEO4J_PASSWORD": os.environ.get("NEO4J_PASSWORD", ""),
                    **self._scanner_env(),  # S3/E6: scoped scanner token
                    # Agent API for AI hooks (FFuf AI extensions, etc.)
                    "AGENT_API_URL": os.environ.get("AGENT_API_URL", "http://localhost:8090"),
                    # The recon CLI (docker run/pull/info) honors DOCKER_HOST, so
                    # all sibling-tool spawns flow through the broker socket served
                    # on the named volume below.
                    "DOCKER_HOST": "unix:///var/run/broker/docker.sock",
                    # supply_chain_common as the DOCKER DAEMON sees it. L2's
                    # retire.js and GuardDog legs bind-mount this into the dirty
                    # analyzer, and the daemon resolves the source on the HOST -
                    # so passing the in-container path (/app/supply_chain_common,
                    # the default) makes the broker reject the spawn with
                    # "bind mount not allowed" and the whole retire.js pass dies.
                    "SUPPLY_CHAIN_COMMON_HOST_PATH": join_host_path(parent_host_path(recon_path), "scanners", "supply_chain_common"),
                    # A2: the operator's incident-match ignore list (their own
                    # OAST providers). Sourced from the DB by api.py's
                    # capture-config reconciler; empty = shipped defaults.
                    "CAPTURE_IOC_IGNORE_SUFFIXES": getattr(self, "sca_intel_ignore_suffixes", "") or "",
                    # Operator overrides for the dirty analyzer L2 spawns itself.
                    **self._analyzer_env(),
                },
                volumes={
                    # V4: mount the BROKER's filtered socket via a named volume,
                    # NOT the raw host socket. The recon code still does `docker run`
                    # unchanged, but a compromised worker cannot mount / or run a
                    # privileged/arbitrary container; the broker rejects those.
                    BROKER_SOCKET_VOLUME: {"bind": "/var/run/broker", "mode": "rw"},
                    # Mount source code for development (no rebuild needed)
                    # Note: rw needed because output/data are subdirectories
                    f"{recon_path}": {"bind": "/app/recon", "mode": "rw"},
                    # Mount graph_db module
                    **self._graph_db_mount(sibling_host_path(recon_path, "graph_db"), baked_into_image=True),
                    # Supply-Chain recon (L2): shared runners + offline OSV DB.
                    join_host_path(parent_host_path(recon_path), "scanners", "supply_chain_common"): {"bind": "/app/supply_chain_common", "mode": "ro"},
                    self.supply_chain_osv_db_volume: {"bind": "/osv-db", "mode": "ro"},
                    # Incident intel (A2 correlation, B enrichment, D typosquats).
                    # READ-ONLY: only the refresh sidecar ever writes it.
                    self.sca_intel_volume: {"bind": "/sca-intel", "mode": "ro"},
                    # Mount /tmp for Docker-in-Docker temp files (avoids spaces in paths)
                    "/tmp/redamon": {"bind": "/tmp/redamon", "mode": "rw"},
                    # JS Recon shared volumes with webapp
                    "redamon_js_recon_uploads": {"bind": "/data/js-recon-uploads", "mode": "ro"},
                    "redamon_js_recon_custom": {"bind": "/data/js-recon-custom", "mode": "ro"},
                    # Official nuclei-templates volume (read-only) for the AI tag
                    # selector to read TEMPLATES-STATS.json. Populated by
                    # ensure_templates_volume() before any nuclei pass.
                    "nuclei-templates": {"bind": "/opt/nuclei-templates-official", "mode": "ro"},
                },
                mem_limit=self._container_mem_limit("full_recon"),  # Memory governor (Part 4c)
                pids_limit=self._container_pids_limit(),  # D1: fork-bomb ceiling
                nano_cpus=self._container_cpu_limit(),  # D1: core-proportional CPU cap
                **self._scanner_hardening(drop_caps=False),  # S3/E6: cap_drop deferred (breaks writes to host-owned source bind mount; needs CAP_DAC_OVERRIDE)
                command="python /app/recon/main.py",
            )

            state.container_id = container.id
            state.status = ReconStatus.RUNNING
            logger.info(f"Started recon container {container.id} for project {project_id}")

        except Exception as e:
            state.status = ReconStatus.ERROR
            state.error = str(e)
            logger.error(f"Failed to start recon for {project_id}: {e}")

        return state

    # =======================================================================
    # CodeFix build sandbox (T6/E10)
    #
    # Runs the UNTRUSTED clone+build+test step of the CypherFix agent in an
    # ephemeral, hardened, SECRET-FREE container so a malicious repo (poisoned
    # postinstall / prompt-injected build steps) cannot reach the platform's
    # secrets. Spawned via the orchestrator's REAL docker socket (like GVM), with
    # hardening enforced here. The agent drives it via `docker exec` (the command
    # channel is the docker control plane, NOT a shared network), so the sandbox
    # sits on codefix-net with NO RedAmon peer.
    # =======================================================================

    @staticmethod
    def _safe_job_id(job_id: str) -> str:
        # No dots: the job_id becomes a host path segment for the bind mount, so a
        # `..` would let a malicious caller mount an arbitrary host dir into the
        # sandbox. The orchestrator uses the REAL docker socket (no broker), so
        # this sanitization is the only guard.
        safe = re.sub(r'[^a-zA-Z0-9_-]', '_', job_id or "")
        return safe or "codefix"

    def _codefix_sandbox_name(self, job_id: str) -> str:
        return f"redamon-codefix-{self._safe_job_id(job_id)}"

    def _ensure_codefix_network(self) -> None:
        """Create the isolated CodeFix network if it does not exist.

        Docker Compose never creates this network: by design NO service is
        attached to it (the sandbox must have no RedAmon peer), and Compose only
        creates networks used by the services it starts. So the orchestrator owns
        its lifecycle — create-if-missing here, idempotently, before every spawn.
        """
        name = self.codefix_sandbox_network
        try:
            self.client.networks.get(name)
            return
        except NotFound:
            pass
        try:
            self.client.networks.create(name, driver="bridge", check_duplicate=True)
            logger.info(f"[codefix] created isolated network {name}")
        except APIError as e:
            # A concurrent spawn may have just created it — tolerate the race.
            logger.warning(f"[codefix] network ensure for {name}: {e}")

    def start_codefix_sandbox(self, job_id: str) -> dict:
        """Spawn a hardened, secret-free build sandbox for one CodeFix job.

        The agent has already cloned the repo into
        ``<codefix_work_host_base>/<job_id>/repo`` (shared volume). We bind that
        worktree read-write and its ``.git`` read-only (so a build cannot plant a
        commit hook or rewrite ``.git/config``). Returns the container name the
        orchestrator will ``exec`` into.
        """
        if not self.codefix_work_host_base:
            raise RuntimeError("codefix_work_host_base not configured")

        job_id = self._safe_job_id(job_id)

        # Compose does not create the isolated network (no service is attached);
        # ensure it exists before we attach the sandbox to it.
        self._ensure_codefix_network()

        # Tear down any stale sandbox for the same job first (idempotent restart).
        if job_id in self.codefix_sandboxes:
            self.stop_codefix_sandbox(job_id, remove_workdir=False)

        host_repo_path = f"{self.codefix_work_host_base}/{job_id}/repo"
        name = self._codefix_sandbox_name(job_id)

        # Best-effort: a leftover container with this name blocks the run.
        try:
            old = self.client.containers.get(name)
            old.remove(force=True)
        except NotFound:
            pass
        except APIError as e:
            logger.warning(f"[codefix] could not remove stale container {name}: {e}")

        container = self.client.containers.run(
            self.codefix_sandbox_image,
            name=name,
            detach=True,
            network=self.codefix_sandbox_network,
            # HARDENING: drop every capability and make the root fs read-only
            # (only the worktree + a tmpfs are writable). Privilege escalation is
            # blocked by stripping setuid/setgid bits in the image rather than the
            # `no-new-privileges` flag, which breaks execve for non-root users on
            # snap-Docker/AppArmor hosts.
            cap_drop=["ALL"],
            read_only=True,
            # Writable scratch for package caches ($HOME=/tmp in the image). exec is
            # allowed because some installers compile/run helpers from the cache.
            tmpfs={"/tmp": "size=1g,exec"},
            mem_limit=self.codefix_sandbox_mem,
            nano_cpus=self.codefix_sandbox_nanocpus,
            pids_limit=self.codefix_sandbox_pids,
            # CRITICAL: NO secrets. A full RCE in here finds nothing of value.
            environment={},
            volumes={
                host_repo_path: {"bind": "/work/repo", "mode": "rw"},
                f"{host_repo_path}/.git": {"bind": "/work/repo/.git", "mode": "ro"},
            },
            # Image CMD is `sleep infinity`; commands arrive via exec.
        )

        self.codefix_sandboxes[job_id] = {
            "container_id": container.id,
            "created_at": datetime.now(timezone.utc),
        }
        # Phase 7: account for the sandbox's 2 GB in the ledger (non-gating) so the
        # governor stops over-admitting scans on top of a running agent build.
        self.ledger.account(self._scan_key("codefix", job_id), self.ledger.envelope_for("codefix"))
        logger.info(f"[codefix] started sandbox {name} ({container.id[:12]}) for job {job_id}")
        return {"job_id": job_id, "container": name}

    async def exec_codefix_sandbox(self, job_id: str, command: str, timeout: int = 600) -> dict:
        """Run one shell command inside the job's sandbox via `docker exec`.

        Wrapped in `timeout` so a hung build cannot block forever. Returns merged
        stdout/stderr and the exit code (124 on timeout).
        """
        job_id = self._safe_job_id(job_id)
        entry = self.codefix_sandboxes.get(job_id)
        if not entry:
            return {"output": f"Error: no active CodeFix sandbox for job {job_id}", "exit_code": 1}

        # Clamp to a hard ceiling regardless of caller-supplied value.
        timeout = max(1, min(int(timeout), 1800))

        def _run() -> dict:
            try:
                container = self.client.containers.get(entry["container_id"])
                rc, output = container.exec_run(
                    # -k 10: if the build ignores SIGTERM, SIGKILL it 10s later.
                    ["timeout", "-k", "10", str(timeout), "bash", "-c", command],
                    workdir="/work/repo",
                    demux=False,
                )
                text = output.decode("utf-8", errors="replace") if output else ""
                if rc == 124:
                    text += f"\n\n[Command timed out after {timeout}s]"
                return {"output": text, "exit_code": rc}
            except NotFound:
                return {"output": f"Error: CodeFix sandbox for job {job_id} is gone", "exit_code": 1}
            except APIError as e:
                return {"output": f"Error executing in sandbox: {e}", "exit_code": 1}

        return await asyncio.to_thread(_run)

    def stop_codefix_sandbox(self, job_id: str, remove_workdir: bool = True) -> None:
        """Remove the sandbox container and (optionally) the per-job worktree."""
        job_id = self._safe_job_id(job_id)
        entry = self.codefix_sandboxes.pop(job_id, None)
        # Phase 7: release the sandbox's ledger reservation (accounted at spawn).
        self.ledger.release_nowait(self._scan_key("codefix", job_id))
        if entry:
            try:
                container = self.client.containers.get(entry["container_id"])
                container.remove(force=True)
                logger.info(f"[codefix] removed sandbox for job {job_id}")
            except NotFound:
                pass
            except APIError as e:
                logger.warning(f"[codefix] failed removing sandbox for job {job_id}: {e}")

        if remove_workdir:
            self._remove_codefix_workdir(job_id)

    def _remove_codefix_workdir(self, job_id: str) -> None:
        """Delete the per-job worktree via the orchestrator's own volume mount."""
        import shutil
        safe = self._safe_job_id(job_id)
        path = os.path.join(CODEFIX_WORK_CONTAINER_BASE, safe)
        # Guard against path escaping the base.
        if os.path.commonpath([os.path.abspath(path), CODEFIX_WORK_CONTAINER_BASE]) != CODEFIX_WORK_CONTAINER_BASE:
            logger.warning(f"[codefix] refusing to remove suspicious workdir: {path}")
            return
        try:
            shutil.rmtree(path, ignore_errors=True)
        except Exception as e:
            logger.warning(f"[codefix] failed removing workdir {path}: {e}")

    async def reap_codefix_sandboxes(self) -> None:
        """Remove sandboxes older than the TTL (orphaned by a crashed agent)."""
        now = datetime.now(timezone.utc)
        stale = [
            job_id for job_id, e in list(self.codefix_sandboxes.items())
            if (now - e["created_at"]).total_seconds() > self.codefix_sandbox_ttl
        ]
        for job_id in stale:
            logger.info(f"[codefix] reaping stale sandbox for job {job_id}")
            self.stop_codefix_sandbox(job_id)

    def _cleanup_sub_containers(self) -> int:
        """Stop and remove any running sub-containers (naabu, httpx, nuclei, etc.)

        Returns the count of containers cleaned up.
        """
        cleaned = 0
        try:
            # Find all running containers
            containers = self.client.containers.list(all=True)
            for container in containers:
                try:
                    # Check if container image matches any sub-container image
                    image_tags = container.image.tags if container.image.tags else []
                    image_name = container.attrs.get("Config", {}).get("Image", "")

                    for sub_image in SUB_CONTAINER_IMAGES:
                        # Match by image name or tags
                        if (sub_image in image_name or
                            any(sub_image in tag for tag in image_tags)):
                            container_name = container.name
                            container_status = container.status

                            # Stop if running or paused
                            if container_status in ("running", "paused"):
                                if container_status == "paused":
                                    logger.info(f"Unpausing sub-container before stop: {container_name} ({sub_image})")
                                    container.unpause()
                                logger.info(f"Stopping sub-container: {container_name} ({sub_image})")
                                container.stop(timeout=5)

                            # Remove container
                            logger.info(f"Removing sub-container: {container_name} ({sub_image})")
                            container.remove(force=True)
                            cleaned += 1
                            break

                except Exception as e:
                    logger.warning(f"Error cleaning up container {container.name}: {e}")

        except Exception as e:
            logger.error(f"Error listing containers for cleanup: {e}")

        return cleaned

    async def pause_recon(self, project_id: str) -> ReconState:
        """Pause a running recon process using Docker cgroups freeze"""
        state = await self.get_status(project_id)

        if state.status != ReconStatus.RUNNING:
            return state

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.pause()
                state.status = ReconStatus.PAUSED
                self.running_states[project_id] = state
                logger.info(f"Paused recon container for project {project_id}")
            except NotFound:
                state.status = ReconStatus.ERROR
                state.error = "Container not found"
            except APIError as e:
                state.status = ReconStatus.ERROR
                state.error = f"Failed to pause: {e}"

        return state

    async def resume_recon(self, project_id: str) -> ReconState:
        """Resume a paused recon process"""
        state = await self.get_status(project_id)

        if state.status != ReconStatus.PAUSED:
            return state

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.unpause()
                state.status = ReconStatus.RUNNING
                self.running_states[project_id] = state
                logger.info(f"Resumed recon container for project {project_id}")
            except NotFound:
                state.status = ReconStatus.ERROR
                state.error = "Container not found"
            except APIError as e:
                state.status = ReconStatus.ERROR
                state.error = f"Failed to resume: {e}"

        return state

    async def stop_recon(self, project_id: str, timeout: int = 10) -> ReconState:
        """Stop a running recon process"""
        state = await self.get_status(project_id)

        if state.status not in (ReconStatus.RUNNING, ReconStatus.PAUSED):
            return state

        state.status = ReconStatus.STOPPING

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                # Unpause before stopping for Docker version compatibility
                if container.status == "paused":
                    container.unpause()
                container.stop(timeout=timeout)
                container.remove()
                state.status = ReconStatus.IDLE
                state.completed_at = datetime.now(timezone.utc)
                logger.info(f"Stopped recon container for project {project_id}")
            except NotFound:
                state.status = ReconStatus.IDLE
            except Exception as e:
                state.status = ReconStatus.ERROR
                state.error = f"Failed to stop: {e}"

        # Clean up any sub-containers (naabu, httpx, nuclei, etc.)
        cleaned = self._cleanup_sub_containers()
        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} sub-container(s) for project {project_id}")

        # Clean up state
        if project_id in self.running_states:
            del self.running_states[project_id]

        return state

    # =======================================================================
    # HTTP traffic capture proxy lifecycle (Phase 1, plan §8.4 / §11)
    # A single persistent proxy + ingest pair, toggled on/off (NOT per-scan).
    # The orchestrator reconciles the desired state set by the Global Settings
    # toggle. The proxy is credential-free on pentest-net; the ingest holds the
    # scoped INSERT-only DB role on redamon-network. Both spawned via the host
    # docker daemon (like every other orchestrator-managed container).
    # =======================================================================
    CAPTURE_PROXY_NAME = "redamon-capture-proxy"
    TRAFFIC_INGEST_NAME = "redamon-traffic-ingest"
    # Compose network names: `redamon` is explicitly named "redamon-network";
    # `pentest-net` has no explicit name so Compose derives "redamon_pentest-net".
    _CAPTURE_PROXY_NETWORK = "redamon_pentest-net"
    _CAPTURE_INGEST_NETWORK = "redamon-network"

    def _capture_image(self) -> str:
        return os.environ.get("CAPTURE_PROXY_IMAGE", "redamon-capture-proxy:latest")

    def _capture_port(self) -> int:
        try:
            return int(os.environ.get("CAPTURE_PROXY_PORT", "8888"))
        except (TypeError, ValueError):
            return 8888

    def _remove_container_if_exists(self, name: str) -> None:
        try:
            self.client.containers.get(name).remove(force=True)
        except NotFound:
            pass
        except APIError as e:
            logger.warning(f"[capture] could not remove stale container {name}: {e}")

    @staticmethod
    def _bool_env(value, default: str) -> str:
        if value is None:
            return default
        return "true" if bool(value) else "false"

    def _ingest_volumes(self, spool_vols: dict) -> dict:
        """Mounts for the traffic-ingest worker, incident catalog included.

        The catalog is mounted READ-ONLY; only the sync sidecar writes it.
        `supply_chain_common` carries the matcher and is NOT baked into the
        capture image, so it must be bind-mounted the same way every other
        consumer mounts it.

        Both are added only when their source is known. A missing bind source is
        not an error to Docker - it silently creates an EMPTY directory - and an
        empty supply_chain_common would make every lookup return "no match",
        which is indistinguishable from a clean run. Better to skip the mount and
        let the worker record the catalog as unavailable (it logs that once).
        """
        vols = dict(spool_vols)
        # getattr, not attribute access: this runs inside start_capture_proxy,
        # which serves the Global Settings toggle. Raising here would fail the
        # whole toggle rather than degrade the catalog match, and a
        # partially-constructed manager (every harness that builds one via
        # __new__) would do exactly that.
        intel_volume = getattr(self, "sca_intel_volume", "") or "redamon-sca-intel"
        recon_path = getattr(self, "recon_host_path", "")
        vols[intel_volume] = {"bind": "/sca-intel", "mode": "ro"}
        if recon_path:
            sc_common = join_host_path(
                parent_host_path(recon_path), "scanners", "supply_chain_common")
            vols[sc_common] = {"bind": "/app/supply_chain_common", "mode": "ro"}
        else:
            logger.warning(
                "[capture] recon host path unknown; traffic-ingest starts WITHOUT "
                "supply_chain_common, so captured requests will not be matched "
                "against the supply-chain incident catalog")
        return vols

    async def start_capture_proxy(self, config: dict | None = None) -> dict:
        """Start (idempotently reconcile) the capture proxy + ingest pair.

        `config` (from the Global Settings toggle) may override only the spawn-baked
        knobs: `port` (proxy listen port) and `redactSecrets` (ingest env). The
        egress-guard + body-storage policy are NOT spawn env any more — they are the
        DB source of truth, hot-reloaded from /spool/.capture-config.json at runtime.
        The image is NOT overridable from the UI (it comes from the trusted
        orchestrator env) so the operator toggle can never spawn an arbitrary image.
        """
        config = config or {}
        image = self._capture_image()  # trusted env only, never from `config`
        port = int(config.get("port") or self._capture_port())
        redact = self._bool_env(config.get("redactSecrets"), os.environ.get("CAPTURE_PROXY_REDACT_SECRETS", "true"))
        blocked_ips = config.get("blockedIps") or os.environ.get("CAPTURE_BLOCKED_IPS", "")
        # NOTE: the egress-guard toggles + body-storage policy are NO LONGER injected
        # as proxy env. They are the DB single-source-of-truth (Global Settings >
        # TrafficMind), materialised to the shared /spool/.capture-config.json by
        # _capture_config_reconcile() and HOT-RELOADED by the proxy — so a settings
        # change applies without a container recreate and can never drift from env.
        # Only genuinely spawn-baked knobs remain here: the listen `port` (proxy
        # command) and `redact` (the ingest container's env). `blocked_ips` is a
        # security invariant on the proxy env, never DB-tunable.

        # Idempotent: clear any stale instances first.
        self._remove_container_if_exists(self.CAPTURE_PROXY_NAME)
        self._remove_container_if_exists(self.TRAFFIC_INGEST_NAME)

        spool_vols = {
            "redamon_capture_spool": {"bind": "/spool", "mode": "rw"},
            "redamon_capture_bodies": {"bind": "/bodies", "mode": "rw"},
        }

        # --- Proxy: pentest-net, loopback publish, NO DB creds / signing key ---
        self.client.containers.run(
            image,
            name=self.CAPTURE_PROXY_NAME,
            detach=True,
            command=["mitmdump", "--quiet", "--set", "confdir=/ca",
                     "--set", "connection_strategy=lazy",  # so the IP pin applies (§20.5)
                     "--set", "stream_large_bodies=5m",
                     "--listen-port", str(port), "-s", "/app/capture_addon.py"],
            network=self._CAPTURE_PROXY_NETWORK,
            # Loopback publish so host-net recon containers reach 127.0.0.1:<port>.
            ports={f"{port}/tcp": ("127.0.0.1", port)},
            environment={
                "CAPTURE_SPOOL_DIR": "/spool",
                "CAPTURE_BODIES_DIR": "/bodies",
                # Egress + body-storage policy come from the DB via the hot-reloaded
                # /spool/.capture-config.json, NOT env. Only the always-on service-IP
                # denylist (security invariant, never DB-tunable) stays on the env.
                "CAPTURE_BLOCKED_IPS": blocked_ips,
            },
            volumes={**spool_vols, "redamon_capture_ca": {"bind": "/ca", "mode": "rw"}},
            cap_drop=["ALL"],
            read_only=True,
            tmpfs={"/tmp": "size=64m,exec"},
            mem_limit=_env_size("CAPTURE_PROXY_MEM", "384m"),
            pids_limit=256,
            restart_policy={"Name": "unless-stopped"},
            labels={"redamon.capture": "proxy"},
        )

        # --- Ingest: redamon-network, scoped INSERT-only role + verify keys ---
        self.client.containers.run(
            image,
            name=self.TRAFFIC_INGEST_NAME,
            detach=True,
            command=["python", "/app/ingest_worker.py"],
            network=self._CAPTURE_INGEST_NETWORK,
            environment={
                "CAPTURE_SPOOL_DIR": "/spool",
                "CAPTURE_BODIES_DIR": "/bodies",
                "CAPTURE_PROXY_REDACT_SECRETS": redact,
                "CAPTURE_REDACT_SALT": os.environ.get("CAPTURE_REDACT_SALT", "redamon-capture"),
                "TRAFFIC_INGEST_DATABASE_URL": os.environ.get("TRAFFIC_INGEST_DATABASE_URL", ""),
                # Tag-verification keys: source=recon -> scanner, source=agent -> internal.
                "SCANNER_API_KEY": os.environ.get("SCANNER_API_KEY", ""),
                "INTERNAL_API_KEY": os.environ.get("INTERNAL_API_KEY", ""),
                # A1 (supply-chain incident match). These MUST be here and not
                # only in docker-compose.yml: in normal operation this pair is
                # spawned by THIS method (the Global Settings toggle calls it),
                # so the compose service definitions are used only by a manual
                # `docker compose --profile capture up`. A knob set only in
                # compose is invisible to the container users actually run, and
                # the match would silently return "no match" on every request.
                "PYTHONPATH": "/app",
                "SCA_INTEL_PATH": "/sca-intel",
                "SCA_INTEL_MATCH_ENABLED": os.environ.get("SCA_INTEL_MATCH_ENABLED", "true"),
                "CAPTURE_IOC_IGNORE_SUFFIXES": getattr(
                    self, "sca_intel_ignore_suffixes", "") or "",
            },
            volumes=self._ingest_volumes(spool_vols),
            cap_drop=["ALL"],
            read_only=True,
            tmpfs={"/tmp": "size=64m,exec"},
            mem_limit=_env_size("TRAFFIC_INGEST_MEM", "256m"),
            pids_limit=256,
            restart_policy={"Name": "unless-stopped"},
            labels={"redamon.capture": "ingest"},
        )

        logger.info(f"[capture] started proxy + ingest (port {port})")
        return await self.capture_proxy_status()

    async def stop_capture_proxy(self) -> dict:
        """Stop + remove the capture proxy and ingest (toggle off)."""
        for name in (self.CAPTURE_PROXY_NAME, self.TRAFFIC_INGEST_NAME):
            try:
                c = self.client.containers.get(name)
                c.stop(timeout=10)
                c.remove()
            except NotFound:
                pass
            except Exception as e:
                logger.warning(f"[capture] failed to stop {name}: {e}")
        logger.info("[capture] stopped proxy + ingest")
        return await self.capture_proxy_status()

    async def capture_proxy_status(self) -> dict:
        """Report the running state of the proxy + ingest."""
        def _state(name: str) -> str:
            try:
                return self.client.containers.get(name).status
            except NotFound:
                return "absent"
            except APIError:
                return "unknown"

        proxy = _state(self.CAPTURE_PROXY_NAME)
        ingest = _state(self.TRAFFIC_INGEST_NAME)
        return {
            "proxy": proxy,
            "ingest": ingest,
            "running": proxy == "running" and ingest == "running",
            "port": self._capture_port(),
        }

    def _parse_log_line(self, line: str, current_phase: Optional[str], current_phase_num: Optional[int], timestamp: Optional[datetime] = None) -> ReconLogEvent:
        """Parse a log line and detect phase changes"""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        phase = current_phase
        phase_num = current_phase_num
        is_phase_start = False
        level = "info"

        # Strip ANSI escape codes (terminal colors) from log line
        line = ANSI_ESCAPE.sub('', line)

        # Detect log level based on prefix symbols only
        # [!] = error (red), [+]/[✓] = success (green), [*] = action (blue), no symbol = info (gray)
        if "[!]" in line:
            level = "error"  # Red
        elif "[+]" in line or "[✓]" in line:
            level = "success"  # Green
        elif "[*]" in line:
            level = "action"  # Blue

        # Detect phase changes
        for pattern, phase_name, num in PHASE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                if phase_name != current_phase:
                    phase = phase_name
                    phase_num = num
                    is_phase_start = True
                break

        return ReconLogEvent(
            log=line.rstrip(),
            timestamp=timestamp,
            phase=phase,
            phase_number=phase_num,
            is_phase_start=is_phase_start,
            level=level,
        )

    async def stream_logs(self, project_id: str) -> AsyncGenerator[ReconLogEvent, None]:
        """Stream logs from a recon container"""
        state = await self.get_status(project_id)

        if not state.container_id:
            yield ReconLogEvent(
                log="No container found for this project",
                timestamp=datetime.now(timezone.utc),
                level="error",
            )
            return

        current_phase: Optional[str] = None
        current_phase_num: Optional[int] = None

        try:
            container = self.client.containers.get(state.container_id)

            # Use asyncio queue to bridge sync Docker logs to async generator
            log_queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue()

            # Capture the event loop before starting the thread
            loop = asyncio.get_running_loop()

            def read_logs():
                """Synchronous function to read logs and put them in the queue"""
                try:
                    # Throttle the per-line liveness reload() below: next allowed
                    # Docker status poll, in monotonic seconds (list = mutable box).
                    _log_status_gate = [time.monotonic() + 30.0]
                    for line in container.logs(stream=True, follow=True, timestamps=True):
                        asyncio.run_coroutine_threadsafe(
                            log_queue.put(line),
                            loop
                        ).result(timeout=5)
                        # Check if container is still running
                        # Liveness check, THROTTLED to once per ~30s. Previously
                        # reload() ran on EVERY log line -- a Docker round-trip per
                        # line. A scan emitting 100k+ lines flooded the daemon,
                        # slowing every request and starving the event loop (the
                        # parallel-scan freeze). The stream generator ending already
                        # stops the loop when a container exits, so a 30s liveness
                        # poll loses nothing but the wasted daemon load.
                        if time.monotonic() >= _log_status_gate[0]:
                            _log_status_gate[0] = time.monotonic() + 30.0
                            try:
                                container.reload()
                                if container.status not in ("running", "paused"):
                                    break
                            except Exception:
                                break
                except Exception as e:
                    logger.error(f"Error in log reader thread: {e}")
                finally:
                    # Signal end of logs
                    try:
                        asyncio.run_coroutine_threadsafe(
                            log_queue.put(None),
                            loop
                        ).result(timeout=5)
                    except Exception:
                        pass

            # Start log reader in a thread
            loop.run_in_executor(self._log_stream_executor, read_logs)

            # Process logs from queue
            while True:
                try:
                    line = await asyncio.wait_for(log_queue.get(), timeout=1.0)
                    if line is None:
                        break

                    decoded_line = line.decode("utf-8", errors="replace").rstrip()
                    if decoded_line:
                        # Parse Docker timestamp prefix (RFC3339Nano format)
                        docker_ts = None
                        log_text = decoded_line
                        # Docker timestamps look like: 2024-01-15T10:30:00.123456789Z <log line>
                        if len(decoded_line) > 30 and decoded_line[4] == '-' and decoded_line[10] == 'T':
                            space_idx = decoded_line.find(' ')
                            if space_idx > 0:
                                ts_str = decoded_line[:space_idx]
                                try:
                                    # Truncate nanoseconds to microseconds for stdlib compatibility
                                    # Docker: 2024-01-15T10:30:00.123456789Z -> 2024-01-15T10:30:00.123456+00:00
                                    ts_clean = ts_str.replace('Z', '+00:00')
                                    dot_idx = ts_clean.find('.')
                                    plus_idx = ts_clean.find('+', dot_idx) if dot_idx > 0 else -1
                                    if dot_idx > 0 and plus_idx > 0:
                                        frac = ts_clean[dot_idx + 1:plus_idx][:6]  # max 6 digits
                                        ts_clean = ts_clean[:dot_idx + 1] + frac + ts_clean[plus_idx:]
                                    docker_ts = datetime.fromisoformat(ts_clean)
                                    log_text = decoded_line[space_idx + 1:]
                                except (ValueError, OverflowError):
                                    pass

                        event = self._parse_log_line(log_text, current_phase, current_phase_num, timestamp=docker_ts)

                        # Update current phase tracking
                        if event.is_phase_start:
                            current_phase = event.phase
                            current_phase_num = event.phase_number

                            # Update state
                            if project_id in self.running_states:
                                self.running_states[project_id].current_phase = current_phase
                                self.running_states[project_id].phase_number = current_phase_num

                        yield event

                except asyncio.TimeoutError:
                    # Check if container is still running or paused
                    try:
                        container.reload()
                        if container.status not in ("running", "paused"):
                            break
                    except Exception:
                        break

        except (NotFound, APIError):
            yield ReconLogEvent(
                log="Container stopped",
                timestamp=datetime.now(timezone.utc),
                level="info",
            )
        except Exception as e:
            yield ReconLogEvent(
                log=f"Error streaming logs: {e}",
                timestamp=datetime.now(timezone.utc),
                level="error",
            )

    def get_running_count(self) -> int:
        """Get count of running recon processes"""
        return sum(1 for s in self.running_states.values() if s.status == ReconStatus.RUNNING)

    async def cleanup(self):
        """Cleanup all running containers on shutdown"""
        for project_id in list(self.running_states.keys()):
            try:
                await self.stop_recon(project_id, timeout=5)
            except Exception as e:
                logger.error(f"Error cleaning up recon {project_id}: {e}")
        for project_id, runs in list(self.partial_recon_states.items()):
            for run_id in list(runs.keys()):
                try:
                    await self.stop_partial_recon(project_id, run_id, timeout=5)
                except Exception as e:
                    logger.error(f"Error cleaning up partial recon {project_id}/{run_id}: {e}")
        for project_id in list(self.gvm_states.keys()):
            try:
                await self.stop_gvm_scan(project_id, timeout=5)
            except Exception as e:
                logger.error(f"Error cleaning up GVM {project_id}: {e}")
        for project_id in list(self.github_hunt_states.keys()):
            try:
                await self.stop_github_hunt(project_id, timeout=5)
            except Exception as e:
                logger.error(f"Error cleaning up GitHub hunt {project_id}: {e}")
        # Per SOURCE, not per project: a project-level stop would leave every
        # other source's container orphaned on shutdown, still holding RAM.
        for project_id, runs in list(self.trufflehog_states.items()):
            for source in list(runs.keys()):
                try:
                    await self.stop_trufflehog(project_id, source, timeout=5)
                except Exception as e:
                    logger.error(f"Error cleaning up TruffleHog {project_id}/{source}: {e}")
        # L1-3: stop supply-chain scans too, or a running redamon-supply-chain-<pid>
        # (holding Neo4j creds + its mem envelope) orphans on orchestrator shutdown.
        for project_id in list(self.supply_chain_states.keys()):
            try:
                await self.stop_supply_chain(project_id, timeout=5)
            except Exception as e:
                logger.error(f"Error cleaning up Supply-Chain {project_id}: {e}")
        # AI Attack Surface scan containers are spawned per-run; stop them too,
        # otherwise they orphan on orchestrator shutdown (and keep the judge lease).
        for project_id, runs in list(self.ai_attack_states.items()):
            for run_id in list(runs.keys()):
                try:
                    await self.stop_ai_attack_surface(project_id, run_id, timeout=5)
                except Exception as e:
                    logger.error(f"Error cleaning up AI attack {project_id}/{run_id}: {e}")
        # CodeFix build sandboxes (T6/E10) — ephemeral; remove any still tracked.
        for job_id in list(self.codefix_sandboxes.keys()):
            try:
                self.stop_codefix_sandbox(job_id)
            except Exception as e:
                logger.error(f"Error cleaning up CodeFix sandbox {job_id}: {e}")

    # =========================================================================
    # Partial Recon Container Lifecycle
    # =========================================================================

    def _get_partial_container_name(self, project_id: str, run_id: str) -> str:
        """Generate container name for a partial recon run"""
        safe_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', project_id)
        return f"redamon-partial-recon-{safe_id}-{run_id[:8]}"

    def _count_active_partial_recons(self, project_id: str) -> int:
        """Count the number of active (running/starting) partial recons for a project"""
        return sum(
            1 for s in self.partial_recon_states.get(project_id, {}).values()
            if s.status in (PartialReconStatus.RUNNING, PartialReconStatus.STARTING)
        )

    def _refresh_partial_recon_state(self, state: PartialReconState) -> None:
        """Refresh a partial recon state by checking its Docker container"""
        if not state.container_id:
            return
        if state.status in (PartialReconStatus.COMPLETED, PartialReconStatus.ERROR, PartialReconStatus.IDLE):
            return

        try:
            container = self.client.containers.get(state.container_id)
            if container.status != "running":
                exit_code = container.attrs.get("State", {}).get("ExitCode", -1)
                if exit_code == 0:
                    state.status = PartialReconStatus.COMPLETED
                    state.completed_at = datetime.now(timezone.utc)
                else:
                    state.status = PartialReconStatus.ERROR
                    state.error = f"Container exited with code {exit_code}"
                    state.completed_at = datetime.now(timezone.utc)
                try:
                    container.remove()
                    logger.info(f"Auto-removed partial recon container for {state.project_id}/{state.run_id}")
                except Exception as e:
                    logger.warning(f"Failed to auto-remove partial container: {e}")
        except NotFound:
            if state.status not in (PartialReconStatus.COMPLETED, PartialReconStatus.ERROR):
                state.status = PartialReconStatus.ERROR
                state.error = "Container not found"
        except APIError as e:
            logger.warning(f"Docker API error checking partial recon {state.project_id}/{state.run_id}: {e}")

    async def get_partial_recon_status(self, project_id: str, run_id: str) -> PartialReconState:
        """Get current status of a specific partial recon run"""
        runs = self.partial_recon_states.get(project_id, {})
        state = runs.get(run_id)
        if state:
            await self._run_blocking(self._refresh_partial_recon_state, state)
            return state

        return PartialReconState(
            project_id=project_id,
            run_id=run_id,
            status=PartialReconStatus.IDLE,
        )

    async def get_all_partial_recon_statuses(self, project_id: str) -> list[PartialReconState]:
        """Get all partial recon states for a project, refreshing container status.
        Auto-cleans completed/errored entries older than 60 seconds.
        """
        runs = self.partial_recon_states.get(project_id, {})
        to_remove = []

        # Refresh every run's Docker status CONCURRENTLY in the thread pool. Done
        # serially on the event loop, N parallel scans meant N blocking docker-py
        # calls back-to-back every poll (~every 5s) -- the core of the freeze that
        # blocked new scan starts once several partial recons were running.
        await asyncio.gather(*[
            self._run_blocking(self._refresh_partial_recon_state, state)
            for state in runs.values()
        ])

        for run_id, state in runs.items():
            # Auto-clean old completed/errored entries
            if state.status in (PartialReconStatus.COMPLETED, PartialReconStatus.ERROR):
                if state.completed_at and (datetime.now(timezone.utc) - state.completed_at).total_seconds() > 60:
                    to_remove.append(run_id)

        # pop(), not del: the gather above is an await point, so a concurrent
        # get_all (an HTTP poll racing the background reconcile) can clean the
        # same run first. del would then KeyError -> 500; pop is idempotent.
        for run_id in to_remove:
            runs.pop(run_id, None)
        if not runs:
            self.partial_recon_states.pop(project_id, None)

        return list(runs.values())

    async def start_partial_recon(
        self,
        project_id: str,
        tool_id: str,
        config: dict,
        recon_path: str,
        custom_templates_path: str = "",
    ) -> PartialReconState:
        """Start a partial recon container for a specific tool.

        Args:
            project_id: Project identifier
            tool_id: Tool to run (e.g., "SubdomainDiscovery")
            config: Full config dict to write as JSON for the container
            recon_path: Host path to the recon directory
            custom_templates_path: Host path to mc/nuclei-templates so the
                spawned container can sibling-mount it for nuclei. Without
                this, custom-template selection is silently ignored and
                build_nuclei_command falls back to the full ~8000-template
                pool (the bug Ritesh hit before this fix).
        """
        # Check concurrency limit
        if self._count_active_partial_recons(project_id) >= MAX_PARALLEL_PARTIAL_RECONS:
            raise ValueError(f"Maximum {MAX_PARALLEL_PARTIAL_RECONS} concurrent partial recons reached for project {project_id}")

        # Mutual exclusion with full recon
        recon_state = await self.get_status(project_id)
        if recon_state.status in (ReconStatus.RUNNING, ReconStatus.PAUSED):
            raise ValueError(f"Full recon is running for project {project_id}. Stop it first.")

        run_id = str(uuid.uuid4())
        container_name = self._get_partial_container_name(project_id, run_id)

        # Memory admission (Part 1): reserve this run's RAM envelope or reject.
        # Tool-qualified: SupplyChainRecon costs ~3x a normal partial step.
        partial_kind = self._partial_kind(tool_id)
        await self._admit_scan(partial_kind, project_id, run_id, user_id=config.get("user_id"))

        # Lazy-on-scan OSV DB refresh, but ONLY for the supply-chain partial tool -
        # other partial tools have nothing to do with the OSV feed. TTL-guarded +
        # best-effort (see ensure_osv_db_fresh).
        if tool_id == "SupplyChainRecon":
            await self.ensure_osv_db_fresh_async()
            await self.ensure_sca_intel_fresh_async()

        state = PartialReconState(
            project_id=project_id,
            run_id=run_id,
            tool_id=tool_id,
            status=PartialReconStatus.STARTING,
            started_at=datetime.now(timezone.utc),
        )
        self.partial_recon_states.setdefault(project_id, {})[run_id] = state

        try:
            # Ensure recon image exists. images.build (cold-image case) is a
            # long blocking docker-py call -- run it off the event loop so a build
            # can't stall every other request while this POST is in flight.
            def _ensure_image():
                try:
                    self.client.images.get(self.recon_image)
                except NotFound:
                    logger.info(f"Building recon image from {recon_path}")
                    self.client.images.build(path=recon_path, tag=self.recon_image, rm=True)
            await self._run_blocking(_ensure_image)

            # Write config JSON to /tmp/redamon/ (shared volume)
            import json
            config_dir = Path("/tmp/redamon")
            config_dir.mkdir(parents=True, exist_ok=True)
            config_path = config_dir / f"partial_{project_id}_{run_id}.json"
            with open(config_path, "w") as f:
                json.dump(config, f)

            # Start container with the partial_recon.py entry point. containers.run
            # is blocking; run it in the thread pool so the spawn never stalls the
            # single event loop (this is the POST the freeze bug reported hanging).
            container = await self._run_blocking(functools.partial(
                self.client.containers.run,
                self.recon_image,
                name=container_name,
                detach=True,
                network_mode="host",
                # Not privileged: Docker's default capability set already includes
                # NET_RAW, which is all the native masscan/nmap SYN scans need. Full
                # `privileged` (all ~40 caps + host device access + seccomp disabled +
                # /proc unmasked) was a host-escape primitive the recon container did
                # not need; dropping it leaves the benign default caps intact.
                cap_add=["NET_RAW"],
                environment={
                    "PROJECT_ID": project_id,
                    "USER_ID": config.get("user_id", ""),
                    "WEBAPP_API_URL": config.get("webapp_api_url", ""),
                    "PARTIAL_RECON_CONFIG": f"/tmp/redamon/partial_{project_id}_{run_id}.json",
                    "PARTIAL_RECON_RUN_ID": run_id,
                    "UPDATE_GRAPH_DB": "true",
                    "HOST_RECON_OUTPUT_PATH": f"{recon_path}/output",
                    # Required for nuclei custom-template support: build_nuclei_command
                    # uses this env var to bind-mount mcp/nuclei-templates into the
                    # sibling nuclei container. Without it, custom-template selection
                    # is silently dropped and the full built-in pool runs instead.
                    "HOST_CUSTOM_TEMPLATES_PATH": custom_templates_path,
                    "NEO4J_URI": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                    "NEO4J_USER": os.environ.get("NEO4J_USER", "neo4j"),
                    "NEO4J_PASSWORD": os.environ.get("NEO4J_PASSWORD", ""),
                    **self._scanner_env(),  # S3/E6: scoped scanner token
                    # Agent API for AI hooks (FFuf AI extensions, etc.)
                    "AGENT_API_URL": os.environ.get("AGENT_API_URL", "http://localhost:8090"),
                    # The recon CLI (docker run/pull/info) honors DOCKER_HOST, so
                    # all sibling-tool spawns flow through the broker socket served
                    # on the named volume below.
                    "DOCKER_HOST": "unix:///var/run/broker/docker.sock",
                    # supply_chain_common as the DOCKER DAEMON sees it. L2's
                    # retire.js and GuardDog legs bind-mount this into the dirty
                    # analyzer, and the daemon resolves the source on the HOST -
                    # so passing the in-container path (/app/supply_chain_common,
                    # the default) makes the broker reject the spawn with
                    # "bind mount not allowed" and the whole retire.js pass dies.
                    "SUPPLY_CHAIN_COMMON_HOST_PATH": join_host_path(parent_host_path(recon_path), "scanners", "supply_chain_common"),
                    # A2: the operator's incident-match ignore list (their own
                    # OAST providers). Sourced from the DB by api.py's
                    # capture-config reconciler; empty = shipped defaults.
                    "CAPTURE_IOC_IGNORE_SUFFIXES": getattr(self, "sca_intel_ignore_suffixes", "") or "",
                    # Operator overrides for the dirty analyzer L2 spawns itself.
                    **self._analyzer_env(),
                },
                volumes={
                    # V4: mount the BROKER's filtered socket via a named volume,
                    # NOT the raw host socket. The recon code still does `docker run`
                    # unchanged, but a compromised worker cannot mount / or run a
                    # privileged/arbitrary container; the broker rejects those.
                    BROKER_SOCKET_VOLUME: {"bind": "/var/run/broker", "mode": "rw"},
                    f"{recon_path}": {"bind": "/app/recon", "mode": "rw"},
                    **self._graph_db_mount(sibling_host_path(recon_path, "graph_db"), baked_into_image=True),
                    # Supply-Chain recon (L2): shared runners + offline OSV DB.
                    join_host_path(parent_host_path(recon_path), "scanners", "supply_chain_common"): {"bind": "/app/supply_chain_common", "mode": "ro"},
                    self.supply_chain_osv_db_volume: {"bind": "/osv-db", "mode": "ro"},
                    # Incident intel (partial-recon parity with full recon above).
                    self.sca_intel_volume: {"bind": "/sca-intel", "mode": "ro"},
                    "/tmp/redamon": {"bind": "/tmp/redamon", "mode": "rw"},
                    # JS Recon shared volumes with webapp (uploaded files + custom patterns)
                    "redamon_js_recon_uploads": {"bind": "/data/js-recon-uploads", "mode": "ro"},
                    "redamon_js_recon_custom": {"bind": "/data/js-recon-custom", "mode": "ro"},
                    # Official nuclei-templates volume (read-only) for the AI tag
                    # selector to read TEMPLATES-STATS.json.
                    "nuclei-templates": {"bind": "/opt/nuclei-templates-official", "mode": "ro"},
                },
                mem_limit=self._container_mem_limit(partial_kind),  # Memory governor (Part 4c)
                pids_limit=self._container_pids_limit(),  # D1: fork-bomb ceiling
                nano_cpus=self._container_cpu_limit(),  # D1: core-proportional CPU cap
                **self._scanner_hardening(drop_caps=False),  # S3/E6: cap_drop deferred (breaks writes to host-owned source bind mount; needs CAP_DAC_OVERRIDE)
                command="python /app/recon/partial_recon.py",
            ))

            state.container_id = container.id
            state.status = PartialReconStatus.RUNNING
            logger.info(f"Started partial recon container {container.id} for project {project_id}, tool {tool_id}, run {run_id}")

        except Exception as e:
            state.status = PartialReconStatus.ERROR
            state.error = str(e)
            logger.error(f"Failed to start partial recon for {project_id}/{run_id}: {e}")

        return state

    async def stop_partial_recon(self, project_id: str, run_id: str, timeout: int = 10) -> PartialReconState:
        """Stop a specific partial recon run"""
        state = await self.get_partial_recon_status(project_id, run_id)

        if state.status not in (PartialReconStatus.RUNNING, PartialReconStatus.STARTING):
            return state

        state.status = PartialReconStatus.STOPPING

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.stop(timeout=timeout)
                container.remove()
                state.status = PartialReconStatus.IDLE
                state.completed_at = datetime.now(timezone.utc)
                logger.info(f"Stopped partial recon container for project {project_id}, run {run_id}")
            except NotFound:
                state.status = PartialReconStatus.IDLE
            except Exception as e:
                state.status = PartialReconStatus.ERROR
                state.error = f"Failed to stop: {e}"

        # Note: sub-container cleanup is NOT done here because it would kill
        # containers from other parallel partial recons. Sub-containers are
        # short-lived and will exit naturally.

        # Remove from state dict
        runs = self.partial_recon_states.get(project_id, {})
        if run_id in runs:
            del runs[run_id]
        if not runs and project_id in self.partial_recon_states:
            del self.partial_recon_states[project_id]

        # Best-effort cleanup of config file
        try:
            config_path = Path(f"/tmp/redamon/partial_{project_id}_{run_id}.json")
            if config_path.exists():
                config_path.unlink()
        except Exception:
            pass

        return state

    async def stream_partial_logs(self, project_id: str, run_id: str) -> AsyncGenerator[ReconLogEvent, None]:
        """Stream logs from a specific partial recon container.
        Reuses the same log parsing logic as full recon.
        """
        state = await self.get_partial_recon_status(project_id, run_id)

        if not state.container_id:
            yield ReconLogEvent(
                log="No partial recon container found for this project",
                timestamp=datetime.now(timezone.utc),
                level="error",
            )
            return

        current_phase: Optional[str] = "Partial Recon"
        current_phase_num: Optional[int] = 1

        try:
            container = self.client.containers.get(state.container_id)

            log_queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue()
            loop = asyncio.get_running_loop()

            # On reconnect, resume from the last timestamp we already emitted so
            # the SSE client doesn't receive duplicate history. Docker's `since`
            # is second-granular, so advance by 1us to avoid re-emitting the
            # boundary line (timestamps we tracked are sub-second precise).
            since_ts = None
            if state.last_log_timestamp is not None:
                since_ts = state.last_log_timestamp + timedelta(microseconds=1)

            def read_logs():
                try:
                    log_stream_kwargs = {"stream": True, "follow": True, "timestamps": True}
                    if since_ts is not None:
                        log_stream_kwargs["since"] = since_ts
                    _log_status_gate = [time.monotonic() + 30.0]
                    for line in container.logs(**log_stream_kwargs):
                        asyncio.run_coroutine_threadsafe(
                            log_queue.put(line), loop
                        ).result(timeout=5)
                        # Liveness check, THROTTLED to once per ~30s. Previously
                        # reload() ran on EVERY log line -- a Docker round-trip per
                        # line. A scan emitting 100k+ lines flooded the daemon,
                        # slowing every request and starving the event loop (the
                        # parallel-scan freeze). The stream generator ending already
                        # stops the loop when a container exits, so a 30s liveness
                        # poll loses nothing but the wasted daemon load.
                        if time.monotonic() >= _log_status_gate[0]:
                            _log_status_gate[0] = time.monotonic() + 30.0
                            try:
                                container.reload()
                                if container.status not in ("running", "paused"):
                                    break
                            except Exception:
                                break
                except Exception as e:
                    logger.error(f"Error in partial recon log reader: {e}")
                finally:
                    try:
                        asyncio.run_coroutine_threadsafe(
                            log_queue.put(None), loop
                        ).result(timeout=5)
                    except Exception:
                        pass

            loop.run_in_executor(self._log_stream_executor, read_logs)

            while True:
                try:
                    line = await asyncio.wait_for(log_queue.get(), timeout=1.0)
                    if line is None:
                        break

                    decoded_line = line.decode("utf-8", errors="replace").rstrip()
                    if decoded_line:
                        # Parse Docker timestamp
                        docker_ts = None
                        log_text = decoded_line
                        if len(decoded_line) > 30 and decoded_line[4] == '-' and decoded_line[10] == 'T':
                            space_idx = decoded_line.find(' ')
                            if space_idx > 0:
                                ts_str = decoded_line[:space_idx]
                                try:
                                    ts_clean = ts_str.replace('Z', '+00:00')
                                    dot_idx = ts_clean.find('.')
                                    plus_idx = ts_clean.find('+', dot_idx) if dot_idx > 0 else -1
                                    if dot_idx > 0 and plus_idx > 0:
                                        frac = ts_clean[dot_idx + 1:plus_idx][:6]
                                        ts_clean = ts_clean[:dot_idx + 1] + frac + ts_clean[plus_idx:]
                                    docker_ts = datetime.fromisoformat(ts_clean)
                                    log_text = decoded_line[space_idx + 1:]
                                except (ValueError, OverflowError):
                                    pass

                        event = self._parse_log_line(log_text, current_phase, current_phase_num, timestamp=docker_ts)
                        # Partial recon always runs a single tool/phase, so pin
                        # phase_number to 1 regardless of which full-pipeline
                        # pattern the line happens to match (e.g. NUCLEI => 5).
                        event.phase_number = 1
                        if event.is_phase_start:
                            current_phase = event.phase
                            current_phase_num = 1
                        # Track the high-water mark so a reconnecting SSE client
                        # resumes after this line instead of replaying history.
                        if docker_ts is not None:
                            if project_id in self.partial_recon_states and run_id in self.partial_recon_states[project_id]:
                                cur = self.partial_recon_states[project_id][run_id].last_log_timestamp
                                if cur is None or docker_ts > cur:
                                    self.partial_recon_states[project_id][run_id].last_log_timestamp = docker_ts
                        yield event

                except asyncio.TimeoutError:
                    try:
                        container.reload()
                        if container.status not in ("running", "paused"):
                            break
                    except Exception:
                        break

        except (NotFound, APIError):
            yield ReconLogEvent(
                log="Partial recon container stopped",
                timestamp=datetime.now(timezone.utc),
                level="info",
            )
        except Exception as e:
            yield ReconLogEvent(
                log=f"Error streaming partial recon logs: {e}",
                timestamp=datetime.now(timezone.utc),
                level="error",
            )

    # =========================================================================
    # AI Attack Surface Container Lifecycle
    # =========================================================================

    def _get_ai_attack_container_name(self, project_id: str, run_id: str) -> str:
        """Generate container name for an AI Attack Surface run"""
        safe_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', project_id)
        return f"redamon-ai-attack-{safe_id}-{run_id[:8]}"

    def _count_active_ai_attack(self, project_id: str) -> int:
        return sum(
            1 for s in self.ai_attack_states.get(project_id, {}).values()
            if s.status in (AiAttackSurfaceStatus.RUNNING, AiAttackSurfaceStatus.STARTING)
        )

    def get_ai_attack_running_count(self) -> int:
        return sum(
            1 for runs in self.ai_attack_states.values() for s in runs.values()
            if s.status in (AiAttackSurfaceStatus.RUNNING, AiAttackSurfaceStatus.STARTING)
        )

    def _release_llm(self, state: AiAttackSurfaceState) -> None:
        """Release this job's Ollama judge lease exactly once (ref-counted).

        Guarded by state.llm_leased so a job that ends, is polled, and is then
        explicitly stopped never double-releases (which would tear the judge down
        while a sibling tool of the same scan still needs it)."""
        if state.llm_leased and self.local_llm_manager:
            try:
                self.local_llm_manager.release()
                logger.info(f"Released Ollama judge lease for {state.project_id}/{state.run_id}")
            except Exception as e:
                logger.warning(f"Failed to release Ollama lease: {e}")
        state.llm_leased = False

    def _refresh_ai_attack_state(self, state: AiAttackSurfaceState) -> None:
        """Refresh a run's state from its container; release the judge on finish."""
        if not state.container_id:
            return
        if state.status in (AiAttackSurfaceStatus.COMPLETED, AiAttackSurfaceStatus.ERROR, AiAttackSurfaceStatus.IDLE):
            return
        try:
            container = self.client.containers.get(state.container_id)
            if container.status != "running":
                exit_code = container.attrs.get("State", {}).get("ExitCode", -1)
                if exit_code == 0:
                    state.status = AiAttackSurfaceStatus.COMPLETED
                else:
                    state.status = AiAttackSurfaceStatus.ERROR
                    state.error = f"Container exited with code {exit_code}"
                state.completed_at = datetime.now(timezone.utc)
                # Job ended on its own -> free the shared judge lease.
                self._release_llm(state)
                try:
                    container.remove()
                    logger.info(f"Auto-removed AI attack container for {state.project_id}/{state.run_id}")
                except Exception as e:
                    logger.warning(f"Failed to auto-remove AI attack container: {e}")
        except NotFound:
            if state.status not in (AiAttackSurfaceStatus.COMPLETED, AiAttackSurfaceStatus.ERROR):
                state.status = AiAttackSurfaceStatus.ERROR
                state.error = "Container not found"
                self._release_llm(state)
        except APIError as e:
            logger.warning(f"Docker API error checking AI attack {state.project_id}/{state.run_id}: {e}")

    async def get_ai_attack_surface_status(self, project_id: str, run_id: str) -> AiAttackSurfaceState:
        runs = self.ai_attack_states.get(project_id, {})
        state = runs.get(run_id)
        if state:
            # _refresh does blocking Docker calls (container.stop/remove on the
            # release path) — keep them off the event loop.
            await asyncio.to_thread(self._refresh_ai_attack_state, state)
            return state
        return AiAttackSurfaceState(
            project_id=project_id, run_id=run_id, status=AiAttackSurfaceStatus.IDLE,
        )

    async def get_all_ai_attack_surface_statuses(self, project_id: str) -> list[AiAttackSurfaceState]:
        runs = self.ai_attack_states.get(project_id, {})
        to_remove = []
        for run_id, state in runs.items():
            await asyncio.to_thread(self._refresh_ai_attack_state, state)
            if state.status in (AiAttackSurfaceStatus.COMPLETED, AiAttackSurfaceStatus.ERROR):
                if state.completed_at and (datetime.now(timezone.utc) - state.completed_at).total_seconds() > 60:
                    to_remove.append(run_id)
        # pop(), not del: to_thread above is an await point, so a concurrent
        # get_all can remove the same run first (see get_all_partial_recon_statuses).
        for run_id in to_remove:
            runs.pop(run_id, None)
        if not runs:
            self.ai_attack_states.pop(project_id, None)
        return list(runs.values())

    async def start_ai_attack_surface(
        self,
        project_id: str,
        user_id: str,
        webapp_api_url: str,
        run_config: dict,
        ai_attack_path: str,
    ) -> AiAttackSurfaceState:
        """Spawn an AI Attack Surface job: ensure the Ollama judge is up
        (ref-counted), write the run config, and start the scan container.

        `run_config` is the shape ai_attack_surface_scan/config.py expects
        (tool, targets, bounds, roe_confirmed, dry_run).
        """
        import json

        # Concurrency backstop (raises before any state/container is created, so
        # the route can surface it as 409 — mirrors partial recon).
        if self._count_active_ai_attack(project_id) >= MAX_PARALLEL_AI_ATTACK:
            raise ValueError(
                f"Maximum {MAX_PARALLEL_AI_ATTACK} concurrent AI attack jobs reached "
                f"for project {project_id}"
            )

        run_id = str(uuid.uuid4())
        container_name = self._get_ai_attack_container_name(project_id, run_id)
        tool = run_config.get("tool", "skeleton")

        # Memory admission (Part 1): reserve this run's RAM envelope or reject.
        await self._admit_scan("ai_attack", project_id, run_id, user_id=user_id)

        state = AiAttackSurfaceState(
            project_id=project_id, run_id=run_id, tool=tool,
            status=AiAttackSurfaceStatus.STARTING,
            started_at=datetime.now(timezone.utc),
        )
        self.ai_attack_states.setdefault(project_id, {})[run_id] = state
        config_path = None   # set once written; may be None if we fail before that

        try:
            # Ensure the scanner image exists.
            try:
                self.client.images.get(self.ai_attack_image)
            except NotFound:
                logger.info(f"Building AI attack image from {ai_attack_path}")
                self.client.images.build(
                    path=parent_host_path(parent_host_path(ai_attack_path)),
                    dockerfile=f"{Path(ai_attack_path).name}/Dockerfile",
                    tag=self.ai_attack_image,
                    rm=True,
                )

            # Bring up the Ollama judge (ref-counted), unless this is a dry run
            # or no judge model is configured. Failure-soft: ensure_up never
            # raises; the scan degrades to no-judge.
            judge_model = (run_config.get("bounds") or {}).get("judge_model")
            if self.local_llm_manager and judge_model and not run_config.get("dry_run"):
                llm_status = await asyncio.to_thread(self.local_llm_manager.ensure_up, judge_model)
                state.llm_leased = True
                run_config["judge_base_url"] = llm_status.base_url
                if not llm_status.available:
                    logger.warning(
                        f"Ollama judge unavailable ({llm_status.warning}); "
                        f"scan will degrade to no-judge"
                    )

            # Write the run config to the shared /tmp/redamon volume.
            config_dir = Path("/tmp/redamon")
            config_dir.mkdir(parents=True, exist_ok=True)
            # Sanitize project_id for the filename (it's client-supplied via the
            # path param); run_id is a server UUID. Mirrors the container-name rule.
            safe_pid = re.sub(r'[^a-zA-Z0-9_.-]', '_', project_id)
            config_path = config_dir / f"ai_attack_{safe_pid}_{run_id}.json"
            run_config.setdefault("project_id", project_id)
            run_config.setdefault("user_id", user_id)
            run_config.setdefault("run_id", run_id)
            with open(config_path, "w") as f:
                json.dump(run_config, f)

            container = self.client.containers.run(
                self.ai_attack_image,
                mem_limit=self._container_mem_limit("ai_attack"),  # Memory governor (Part 4c)
                pids_limit=self._container_pids_limit(),  # D1: fork-bomb ceiling
                nano_cpus=self._container_cpu_limit(),  # D1: core-proportional CPU cap
                **self._scanner_hardening(drop_caps=False),  # S3/E6: cap_drop deferred (residual; not verifiable here)
                name=container_name,
                detach=True,
                network_mode="host",
                environment={
                    "PROJECT_ID": project_id,
                    "USER_ID": user_id,
                    "WEBAPP_API_URL": webapp_api_url,
                    # V3: operator-approved extra tool images (empty = strict
                    # shipped-only allowlist). Server-controlled; forwarded to the
                    # recon pipeline so air-gapped/private-registry deployments work.
                    "RECON_EXTRA_ALLOWED_IMAGES": os.environ.get("RECON_EXTRA_ALLOWED_IMAGES", ""),
                    "PYTHONUNBUFFERED": "1",
                    "AI_ATTACK_CONFIG": str(config_path),
                    "AI_ATTACK_RUN_ID": run_id,
                    "AI_ATTACK_TOOL": tool,
                    "NEO4J_URI": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                    "NEO4J_USER": os.environ.get("NEO4J_USER", "neo4j"),
                    "NEO4J_PASSWORD": os.environ.get("NEO4J_PASSWORD", ""),
                    **self._scanner_env(),  # S3/E6: scoped scanner token
                },
                volumes={
                    "/tmp/redamon": {"bind": "/tmp/redamon", "mode": "rw"},
                    # Mount source for dev (no rebuild needed), like the other scanners.
                    f"{ai_attack_path}": {"bind": "/app/ai_attack_surface_scan", "mode": "rw"},
                },
                command="python ai_attack_surface_scan/main.py",
            )

            state.container_id = container.id
            state.status = AiAttackSurfaceStatus.RUNNING
            logger.info(
                f"Started AI attack container {container.id} for project {project_id}, "
                f"tool {tool}, run {run_id}"
            )
        except Exception as e:
            state.status = AiAttackSurfaceStatus.ERROR
            state.error = str(e)
            # Mark completion so the status GC can evict this run (else it leaks in
            # ai_attack_states forever — the GC only removes runs with completed_at).
            state.completed_at = datetime.now(timezone.utc)
            # Don't leak the judge lease if the spawn failed after ensure_up.
            self._release_llm(state)
            # Don't leave the config file behind on a failed spawn.
            try:
                if config_path:
                    config_path.unlink(missing_ok=True)
            except Exception:
                pass
            logger.error(f"Failed to start AI attack surface for {project_id}/{run_id}: {e}")

        return state

    async def stop_ai_attack_surface(self, project_id: str, run_id: str, timeout: int = 2) -> AiAttackSurfaceState:
        state = await self.get_ai_attack_surface_status(project_id, run_id)

        if state.status in (AiAttackSurfaceStatus.RUNNING, AiAttackSurfaceStatus.STARTING):
            state.status = AiAttackSurfaceStatus.STOPPING
            if state.container_id:
                # Run the blocking docker stop/remove off the event loop so the
                # stop request (and concurrent status polls) stay responsive. A
                # short SIGTERM grace keeps the operator from waiting ~10s — a
                # red-team scan has no graceful-shutdown work worth waiting for.
                def _kill(cid: str):
                    container = self.client.containers.get(cid)
                    container.stop(timeout=timeout)
                    container.remove()
                try:
                    await asyncio.to_thread(_kill, state.container_id)
                    state.status = AiAttackSurfaceStatus.IDLE
                    state.completed_at = datetime.now(timezone.utc)
                    logger.info(f"Stopped AI attack container for {project_id}/{run_id}")
                except NotFound:
                    state.status = AiAttackSurfaceStatus.IDLE
                except Exception as e:
                    state.status = AiAttackSurfaceStatus.ERROR
                    state.error = f"Failed to stop: {e}"

        # Release the judge lease (idempotent) and clean up state + config file.
        self._release_llm(state)
        runs = self.ai_attack_states.get(project_id, {})
        if run_id in runs:
            del runs[run_id]
        if not runs and project_id in self.ai_attack_states:
            del self.ai_attack_states[project_id]
        try:
            cfg = Path(f"/tmp/redamon/ai_attack_{project_id}_{run_id}.json")
            if cfg.exists():
                cfg.unlink()
        except Exception:
            pass

        return state

    async def reap_ai_attack(self) -> int:
        """Refresh every AI-attack state so a job that finished while no client
        was polling still releases its Ollama judge lease and is cleaned up.

        Without this, a launch whose UI tab closed mid-run would leave the
        finished container's lease held forever (Ollama RAM never freed until the
        orchestrator restarts), because lease release is otherwise client-driven
        (only get_status / get_all / stream call _refresh). Called periodically by
        a background task in the API lifespan.
        """
        reaped = 0
        for pid in list(self.ai_attack_states.keys()):
            try:
                await self.get_all_ai_attack_surface_statuses(pid)
                reaped += 1
            except Exception as e:
                logger.warning(f"AI attack reaper error for {pid}: {e}")
        return reaped

    def _parse_ai_attack_log_line(self, line: str, current_phase: Optional[str], current_phase_num: Optional[int], timestamp: Optional[datetime] = None) -> AiAttackSurfaceLogEvent:
        """Parse an AI Attack Surface log line and detect [Phase N] changes."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        phase = current_phase
        phase_num = current_phase_num
        is_phase_start = False
        level = "info"

        line = ANSI_ESCAPE.sub('', line)
        if "[!]" in line:
            level = "error"
        elif "[+]" in line or "[✓]" in line:
            level = "success"
        elif "[*]" in line:
            level = "action"

        for pattern, phase_name, num in AI_ATTACK_SURFACE_PHASE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                if phase_name != current_phase:
                    phase = phase_name
                    phase_num = num
                    is_phase_start = True
                break

        return AiAttackSurfaceLogEvent(
            log=line.rstrip(), timestamp=timestamp, phase=phase,
            phase_number=phase_num, is_phase_start=is_phase_start, level=level,
        )

    async def stream_ai_attack_surface_logs(self, project_id: str, run_id: str) -> AsyncGenerator[AiAttackSurfaceLogEvent, None]:
        """Stream logs from an AI Attack Surface container via SSE, with phase
        detection and reconnect resume (mirrors stream_partial_logs)."""
        state = await self.get_ai_attack_surface_status(project_id, run_id)

        if not state.container_id:
            yield AiAttackSurfaceLogEvent(
                log="No AI attack container found for this run",
                timestamp=datetime.now(timezone.utc), level="error",
            )
            return

        # Start with no phase so the first [Phase 1] marker registers as a phase
        # start (initialising to phase 1 would swallow that transition).
        current_phase: Optional[str] = None
        current_phase_num: Optional[int] = None

        try:
            container = self.client.containers.get(state.container_id)
            log_queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue()
            loop = asyncio.get_running_loop()

            # Always replay from the start of the container's logs on every
            # (re)connect, so a page refresh restores the FULL status + phase +
            # log history (the client resets its log view on stream open to avoid
            # duplicates). This makes a running scan stateful across reloads.
            def read_logs():
                try:
                    log_stream_kwargs = {"stream": True, "follow": True, "timestamps": True}
                    _log_status_gate = [time.monotonic() + 30.0]
                    for line in container.logs(**log_stream_kwargs):
                        asyncio.run_coroutine_threadsafe(log_queue.put(line), loop).result(timeout=5)
                        # Liveness check, THROTTLED to once per ~30s. Previously
                        # reload() ran on EVERY log line -- a Docker round-trip per
                        # line. A scan emitting 100k+ lines flooded the daemon,
                        # slowing every request and starving the event loop (the
                        # parallel-scan freeze). The stream generator ending already
                        # stops the loop when a container exits, so a 30s liveness
                        # poll loses nothing but the wasted daemon load.
                        if time.monotonic() >= _log_status_gate[0]:
                            _log_status_gate[0] = time.monotonic() + 30.0
                            try:
                                container.reload()
                                if container.status not in ("running", "paused"):
                                    break
                            except Exception:
                                break
                except Exception as e:
                    logger.error(f"Error in AI attack log reader: {e}")
                finally:
                    try:
                        asyncio.run_coroutine_threadsafe(log_queue.put(None), loop).result(timeout=5)
                    except Exception:
                        pass

            loop.run_in_executor(self._log_stream_executor, read_logs)

            while True:
                try:
                    line = await asyncio.wait_for(log_queue.get(), timeout=1.0)
                    if line is None:
                        break
                    decoded_line = line.decode("utf-8", errors="replace").rstrip()
                    if not decoded_line:
                        continue
                    docker_ts = None
                    log_text = decoded_line
                    if len(decoded_line) > 30 and decoded_line[4] == '-' and decoded_line[10] == 'T':
                        space_idx = decoded_line.find(' ')
                        if space_idx > 0:
                            ts_str = decoded_line[:space_idx]
                            try:
                                ts_clean = ts_str.replace('Z', '+00:00')
                                dot_idx = ts_clean.find('.')
                                plus_idx = ts_clean.find('+', dot_idx) if dot_idx > 0 else -1
                                if dot_idx > 0 and plus_idx > 0:
                                    frac = ts_clean[dot_idx + 1:plus_idx][:6]
                                    ts_clean = ts_clean[:dot_idx + 1] + frac + ts_clean[plus_idx:]
                                docker_ts = datetime.fromisoformat(ts_clean)
                                log_text = decoded_line[space_idx + 1:]
                            except (ValueError, OverflowError):
                                pass

                    event = self._parse_ai_attack_log_line(log_text, current_phase, current_phase_num, timestamp=docker_ts)
                    if event.is_phase_start:
                        current_phase = event.phase
                        current_phase_num = event.phase_number
                    if docker_ts is not None:
                        runs = self.ai_attack_states.get(project_id, {})
                        if run_id in runs:
                            cur = runs[run_id].last_log_timestamp
                            if cur is None or docker_ts > cur:
                                runs[run_id].last_log_timestamp = docker_ts
                    yield event

                except asyncio.TimeoutError:
                    try:
                        container.reload()
                        if container.status not in ("running", "paused"):
                            break
                    except Exception:
                        break

        except (NotFound, APIError):
            yield AiAttackSurfaceLogEvent(
                log="AI attack container stopped",
                timestamp=datetime.now(timezone.utc), level="info",
            )
        except Exception as e:
            yield AiAttackSurfaceLogEvent(
                log=f"Error streaming AI attack logs: {e}",
                timestamp=datetime.now(timezone.utc), level="error",
            )

    # =========================================================================
    # GVM Vulnerability Scan Container Lifecycle
    # =========================================================================

    def _get_gvm_container_name(self, project_id: str) -> str:
        """Generate container name for a GVM scan"""
        safe_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', project_id)
        return f"redamon-gvm-{safe_id}"

    async def get_gvm_status(self, project_id: str) -> GvmState:
        """Get current status of a GVM scan process. Docker inspection runs off
        the event loop (_run_blocking) so a slow daemon can't stall the worker
        -- gvm status is polled on the same cadence as recon, same freeze risk."""
        return await self._run_blocking(self._get_gvm_status_sync, project_id)

    def _get_gvm_status_sync(self, project_id: str) -> GvmState:
        if project_id in self.gvm_states:
            state = self.gvm_states[project_id]

            if state.container_id:
                try:
                    container = self.client.containers.get(state.container_id)
                    if container.status == "paused":
                        state.status = GvmStatus.PAUSED
                    elif container.status != "running":
                        exit_code = container.attrs.get("State", {}).get("ExitCode", -1)
                        if exit_code == 0:
                            state.status = GvmStatus.COMPLETED
                            state.completed_at = datetime.now(timezone.utc)
                        else:
                            state.status = GvmStatus.ERROR
                            state.error = f"Container exited with code {exit_code}"
                            state.completed_at = datetime.now(timezone.utc)

                        try:
                            container.remove()
                            logger.info(f"Auto-removed finished GVM container for project {project_id}")
                        except Exception as e:
                            logger.warning(f"Failed to auto-remove GVM container: {e}")
                except NotFound:
                    if state.status not in (GvmStatus.COMPLETED, GvmStatus.ERROR):
                        state.status = GvmStatus.ERROR
                        state.error = "Container not found"
                except APIError as e:
                    logger.warning(f"Docker API error checking GVM container for {project_id}: {e}")
                    if state.status not in (GvmStatus.COMPLETED, GvmStatus.ERROR):
                        state.status = GvmStatus.ERROR
                        state.error = f"Docker API error: {e}"

            return state

        # Check if there's an orphan container
        container_name = self._get_gvm_container_name(project_id)
        try:
            container = self.client.containers.get(container_name)
            if container.status in ("running", "paused"):
                return GvmState(
                    project_id=project_id,
                    status=GvmStatus.PAUSED if container.status == "paused" else GvmStatus.RUNNING,
                    container_id=container.id,
                )
        except NotFound:
            pass

        return GvmState(
            project_id=project_id,
            status=GvmStatus.IDLE,
        )

    async def start_gvm_scan(
        self,
        project_id: str,
        user_id: str,
        webapp_api_url: str,
        recon_path: str,
        gvm_scan_path: str,
    ) -> GvmState:
        """Start a GVM vulnerability scanner container for a project"""

        # Check if already running or paused
        current_state = await self.get_gvm_status(project_id)
        if current_state.status in (GvmStatus.RUNNING, GvmStatus.PAUSED):
            raise ValueError(f"GVM scan already active for project {project_id}")

        # Memory admission (Part 1): reserve this scan's RAM envelope or reject.
        await self._admit_scan("gvm", project_id, user_id=user_id)

        # Clean up any existing container
        container_name = self._get_gvm_container_name(project_id)
        try:
            old_container = self.client.containers.get(container_name)
            old_container.remove(force=True)
            logger.info(f"Removed old GVM container {container_name}")
        except NotFound:
            pass

        # Create new state
        state = GvmState(
            project_id=project_id,
            status=GvmStatus.STARTING,
            started_at=datetime.now(timezone.utc),
        )
        self.gvm_states[project_id] = state

        try:
            # Ensure GVM scanner image exists
            try:
                self.client.images.get(self.gvm_image)
            except NotFound:
                logger.info(f"Building GVM scanner image from {gvm_scan_path}")
                self.client.images.build(
                    path=parent_host_path(parent_host_path(gvm_scan_path)),
                    dockerfile=f"{Path(gvm_scan_path).name}/Dockerfile",
                    tag=self.gvm_image,
                    rm=True,
                )

            # Start container with environment variables
            container = self.client.containers.run(
                self.gvm_image,
                mem_limit=self._container_mem_limit("gvm"),  # Memory governor (Part 4c)
                pids_limit=self._container_pids_limit(),  # D1: fork-bomb ceiling
                nano_cpus=self._container_cpu_limit(),  # D1: core-proportional CPU cap
                **self._scanner_hardening(drop_caps=False),  # S3/E6: cap_drop deferred (residual; not verifiable here)
                name=container_name,
                detach=True,
                network_mode="host",
                environment={
                    "PROJECT_ID": project_id,
                    "USER_ID": user_id,
                    "WEBAPP_API_URL": webapp_api_url,
                    # V3: operator-approved extra tool images (empty = strict
                    # shipped-only allowlist). Server-controlled; forwarded to the
                    # recon pipeline so air-gapped/private-registry deployments work.
                    "RECON_EXTRA_ALLOWED_IMAGES": os.environ.get("RECON_EXTRA_ALLOWED_IMAGES", ""),
                    "PYTHONUNBUFFERED": "1",
                    # Forward Neo4j credentials from orchestrator environment
                    "NEO4J_URI": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                    "NEO4J_USER": os.environ.get("NEO4J_USER", "neo4j"),
                    "NEO4J_PASSWORD": os.environ.get("NEO4J_PASSWORD", ""),
                    **self._scanner_env(),  # S3/E6: scoped scanner token
                    # GVM connection settings
                    # Operator pin for the stall watchdog. Forwarded ONLY when set,
                    # so an unset knob reaches the scan as "use the shipped default"
                    # rather than as an explicit empty value (issue #174).
                    **({"GVM_NO_PROGRESS_TIMEOUT": os.environ["GVM_NO_PROGRESS_TIMEOUT"]}
                       if os.environ.get("GVM_NO_PROGRESS_TIMEOUT", "").strip() else {}),
                    "GVM_SOCKET_PATH": os.environ.get("GVM_SOCKET_PATH", "/run/gvmd/gvmd.sock"),
                    "GVM_USERNAME": os.environ.get("GVM_USERNAME", "admin"),
                    "GVM_PASSWORD": os.environ.get("GVM_PASSWORD", "admin"),
                },
                volumes={
                    # GVM socket for communicating with gvmd
                    "redamon_gvmd_socket": {"bind": "/run/gvmd", "mode": "ro"},
                    # Recon output (read-only, for extracting targets)
                    f"{recon_path}/output": {"bind": "/app/recon/output", "mode": "ro"},
                    # GVM scan output (read-write, for saving results)
                    f"{gvm_scan_path}/output": {"bind": "/app/gvm_scan/output", "mode": "rw"},
                    # Mount graph_db module for Neo4j updates
                    **self._graph_db_mount(sibling_host_path(recon_path, "graph_db"), baked_into_image=True),
                    # Supply-Chain recon (L2): shared runners + offline OSV DB.
                    join_host_path(parent_host_path(recon_path), "scanners", "supply_chain_common"): {"bind": "/app/supply_chain_common", "mode": "ro"},
                    self.supply_chain_osv_db_volume: {"bind": "/osv-db", "mode": "ro"},
                    # Mount gvm_scan source for development (no rebuild needed)
                    f"{gvm_scan_path}": {"bind": "/app/gvm_scan", "mode": "rw"},
                },
                command="python gvm_scan/main.py",
            )

            state.container_id = container.id
            state.status = GvmStatus.RUNNING
            logger.info(f"Started GVM scanner container {container.id} for project {project_id}")

        except Exception as e:
            state.status = GvmStatus.ERROR
            state.error = str(e)
            logger.error(f"Failed to start GVM scan for {project_id}: {e}")

        return state

    async def pause_gvm_scan(self, project_id: str) -> GvmState:
        """Pause a running GVM scan process"""
        state = await self.get_gvm_status(project_id)

        if state.status != GvmStatus.RUNNING:
            return state

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.pause()
                state.status = GvmStatus.PAUSED
                self.gvm_states[project_id] = state
                logger.info(f"Paused GVM container for project {project_id}")
            except NotFound:
                state.status = GvmStatus.ERROR
                state.error = "Container not found"
            except APIError as e:
                state.status = GvmStatus.ERROR
                state.error = f"Failed to pause: {e}"

        return state

    async def resume_gvm_scan(self, project_id: str) -> GvmState:
        """Resume a paused GVM scan process"""
        state = await self.get_gvm_status(project_id)

        if state.status != GvmStatus.PAUSED:
            return state

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.unpause()
                state.status = GvmStatus.RUNNING
                self.gvm_states[project_id] = state
                logger.info(f"Resumed GVM container for project {project_id}")
            except NotFound:
                state.status = GvmStatus.ERROR
                state.error = "Container not found"
            except APIError as e:
                state.status = GvmStatus.ERROR
                state.error = f"Failed to resume: {e}"

        return state

    async def stop_gvm_scan(self, project_id: str, timeout: int = 10) -> GvmState:
        """Stop a running GVM scan process"""
        state = await self.get_gvm_status(project_id)

        if state.status not in (GvmStatus.RUNNING, GvmStatus.PAUSED):
            return state

        state.status = GvmStatus.STOPPING

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                if container.status == "paused":
                    container.unpause()
                container.stop(timeout=timeout)
                container.remove()
                state.status = GvmStatus.IDLE
                state.completed_at = datetime.now(timezone.utc)
                logger.info(f"Stopped GVM container for project {project_id}")
            except NotFound:
                state.status = GvmStatus.IDLE
            except Exception as e:
                state.status = GvmStatus.ERROR
                state.error = f"Failed to stop: {e}"

        if project_id in self.gvm_states:
            del self.gvm_states[project_id]

        return state

    def _parse_gvm_log_line(self, line: str, current_phase: Optional[str], current_phase_num: Optional[int], timestamp: Optional[datetime] = None) -> GvmLogEvent:
        """Parse a GVM log line and detect phase changes"""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        phase = current_phase
        phase_num = current_phase_num
        is_phase_start = False
        level = "info"

        # Strip ANSI escape codes
        line = ANSI_ESCAPE.sub('', line)

        # Detect log level
        if "[!]" in line:
            level = "error"
        elif "[+]" in line or "[✓]" in line:
            level = "success"
        elif "[*]" in line:
            level = "action"

        # Detect phase changes
        for pattern, phase_name, num in GVM_PHASE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                if phase_name != current_phase:
                    phase = phase_name
                    phase_num = num
                    is_phase_start = True
                break

        return GvmLogEvent(
            log=line.rstrip(),
            timestamp=timestamp,
            phase=phase,
            phase_number=phase_num,
            is_phase_start=is_phase_start,
            level=level,
        )

    async def stream_gvm_logs(self, project_id: str) -> AsyncGenerator[GvmLogEvent, None]:
        """Stream logs from a GVM scanner container"""
        state = await self.get_gvm_status(project_id)

        if not state.container_id:
            yield GvmLogEvent(
                log="No GVM container found for this project",
                timestamp=datetime.now(timezone.utc),
                level="error",
            )
            return

        current_phase: Optional[str] = None
        current_phase_num: Optional[int] = None

        try:
            container = self.client.containers.get(state.container_id)

            log_queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue()
            loop = asyncio.get_running_loop()

            def read_logs():
                try:
                    # Throttle the per-line liveness reload() below: next allowed
                    # Docker status poll, in monotonic seconds (list = mutable box).
                    _log_status_gate = [time.monotonic() + 30.0]
                    for line in container.logs(stream=True, follow=True, timestamps=True):
                        asyncio.run_coroutine_threadsafe(
                            log_queue.put(line),
                            loop
                        ).result(timeout=5)
                        # Liveness check, THROTTLED to once per ~30s. Previously
                        # reload() ran on EVERY log line -- a Docker round-trip per
                        # line. A scan emitting 100k+ lines flooded the daemon,
                        # slowing every request and starving the event loop (the
                        # parallel-scan freeze). The stream generator ending already
                        # stops the loop when a container exits, so a 30s liveness
                        # poll loses nothing but the wasted daemon load.
                        if time.monotonic() >= _log_status_gate[0]:
                            _log_status_gate[0] = time.monotonic() + 30.0
                            try:
                                container.reload()
                                if container.status not in ("running", "paused"):
                                    break
                            except Exception:
                                break
                except Exception as e:
                    logger.error(f"Error in GVM log reader thread: {e}")
                finally:
                    try:
                        asyncio.run_coroutine_threadsafe(
                            log_queue.put(None),
                            loop
                        ).result(timeout=5)
                    except Exception:
                        pass

            loop.run_in_executor(self._log_stream_executor, read_logs)

            while True:
                try:
                    line = await asyncio.wait_for(log_queue.get(), timeout=1.0)
                    if line is None:
                        break

                    decoded_line = line.decode("utf-8", errors="replace").rstrip()
                    if decoded_line:
                        # Parse Docker timestamp prefix
                        docker_ts = None
                        log_text = decoded_line
                        if len(decoded_line) > 30 and decoded_line[4] == '-' and decoded_line[10] == 'T':
                            space_idx = decoded_line.find(' ')
                            if space_idx > 0:
                                ts_str = decoded_line[:space_idx]
                                try:
                                    ts_clean = ts_str.replace('Z', '+00:00')
                                    dot_idx = ts_clean.find('.')
                                    plus_idx = ts_clean.find('+', dot_idx) if dot_idx > 0 else -1
                                    if dot_idx > 0 and plus_idx > 0:
                                        frac = ts_clean[dot_idx + 1:plus_idx][:6]
                                        ts_clean = ts_clean[:dot_idx + 1] + frac + ts_clean[plus_idx:]
                                    docker_ts = datetime.fromisoformat(ts_clean)
                                    log_text = decoded_line[space_idx + 1:]
                                except (ValueError, OverflowError):
                                    pass

                        event = self._parse_gvm_log_line(log_text, current_phase, current_phase_num, timestamp=docker_ts)

                        if event.is_phase_start:
                            current_phase = event.phase
                            current_phase_num = event.phase_number

                            if project_id in self.gvm_states:
                                self.gvm_states[project_id].current_phase = current_phase
                                self.gvm_states[project_id].phase_number = current_phase_num

                        yield event

                except asyncio.TimeoutError:
                    try:
                        container.reload()
                        if container.status not in ("running", "paused"):
                            break
                    except Exception:
                        break

        except (NotFound, APIError):
            yield GvmLogEvent(
                log="GVM container stopped",
                timestamp=datetime.now(timezone.utc),
                level="info",
            )
        except Exception as e:
            yield GvmLogEvent(
                log=f"Error streaming GVM logs: {e}",
                timestamp=datetime.now(timezone.utc),
                level="error",
            )

    def get_gvm_running_count(self) -> int:
        """Get count of running GVM scan processes"""
        return sum(1 for s in self.gvm_states.values() if s.status == GvmStatus.RUNNING)

    def is_gvm_available(self) -> bool:
        """Check if GVM stack is installed by looking for the gvmd container"""
        try:
            container = self.client.containers.get("redamon-gvm-gvmd")
            return container.status == "running"
        except Exception:
            return False

    # =========================================================================
    # GitHub Secret Hunt Container Lifecycle
    # =========================================================================

    def _get_github_hunt_container_name(self, project_id: str) -> str:
        """Generate container name for a GitHub hunt"""
        safe_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', project_id)
        return f"redamon-github-hunt-{safe_id}"

    async def get_github_hunt_status(self, project_id: str) -> GithubHuntState:
        """Get current status of a GitHub hunt process. Docker inspection runs
        off the event loop (_run_blocking) so a slow daemon can't stall the
        worker -- same poll cadence and freeze risk as recon."""
        return await self._run_blocking(self._get_github_hunt_status_sync, project_id)

    def _get_github_hunt_status_sync(self, project_id: str) -> GithubHuntState:
        if project_id in self.github_hunt_states:
            state = self.github_hunt_states[project_id]

            if state.container_id:
                try:
                    container = self.client.containers.get(state.container_id)
                    if container.status == "paused":
                        state.status = GithubHuntStatus.PAUSED
                    elif container.status != "running":
                        exit_code = container.attrs.get("State", {}).get("ExitCode", -1)
                        if exit_code == 0:
                            state.status = GithubHuntStatus.COMPLETED
                            state.completed_at = datetime.now(timezone.utc)
                        else:
                            state.status = GithubHuntStatus.ERROR
                            state.error = f"Container exited with code {exit_code}"
                            state.completed_at = datetime.now(timezone.utc)

                        # Both branches: a non-zero exit still leaves whatever the
                        # scan had already saved, and a SIGKILLed container exits
                        # non-zero having written nothing to the graph itself.
                        self._ingest_github_hunt(state)

                        try:
                            container.remove()
                            logger.info(f"Auto-removed finished GitHub hunt container for project {project_id}")
                        except Exception as e:
                            logger.warning(f"Failed to auto-remove GitHub hunt container: {e}")
                except NotFound:
                    if state.status not in (GithubHuntStatus.COMPLETED, GithubHuntStatus.ERROR):
                        state.status = GithubHuntStatus.ERROR
                        state.error = "Container not found"
                except APIError as e:
                    logger.warning(f"Docker API error checking GitHub hunt container for {project_id}: {e}")
                    if state.status not in (GithubHuntStatus.COMPLETED, GithubHuntStatus.ERROR):
                        state.status = GithubHuntStatus.ERROR
                        state.error = f"Docker API error: {e}"

            return state

        # Check if there's an orphan container
        container_name = self._get_github_hunt_container_name(project_id)
        try:
            container = self.client.containers.get(container_name)
            if container.status in ("running", "paused"):
                return GithubHuntState(
                    project_id=project_id,
                    status=GithubHuntStatus.PAUSED if container.status == "paused" else GithubHuntStatus.RUNNING,
                    container_id=container.id,
                )
        except NotFound:
            pass

        return GithubHuntState(
            project_id=project_id,
            status=GithubHuntStatus.IDLE,
        )

    async def start_github_hunt(
        self,
        project_id: str,
        user_id: str,
        webapp_api_url: str,
        github_hunt_path: str,
    ) -> GithubHuntState:
        """Start a GitHub secret hunt container for a project"""

        # Check if already running
        current_state = await self.get_github_hunt_status(project_id)
        if current_state.status in (GithubHuntStatus.RUNNING, GithubHuntStatus.PAUSED):
            raise ValueError(f"GitHub hunt already active for project {project_id}")

        # Memory admission (Part 1): reserve this scan's RAM envelope or reject.
        await self._admit_scan("github_hunt", project_id, user_id=user_id)

        # Clean up any existing container
        container_name = self._get_github_hunt_container_name(project_id)
        try:
            old_container = self.client.containers.get(container_name)
            old_container.remove(force=True)
            logger.info(f"Removed old GitHub hunt container {container_name}")
        except NotFound:
            pass

        # Create new state
        state = GithubHuntState(
            project_id=project_id,
            status=GithubHuntStatus.STARTING,
            started_at=datetime.now(timezone.utc),
            user_id=user_id,
        )
        self.github_hunt_states[project_id] = state

        try:
            # Ensure GitHub hunt image exists
            try:
                self.client.images.get(self.github_hunt_image)
            except NotFound:
                logger.info(f"Building GitHub hunt image from {github_hunt_path}")
                self.client.images.build(
                    path=parent_host_path(parent_host_path(github_hunt_path)),
                    dockerfile=f"{Path(github_hunt_path).name}/Dockerfile",
                    tag=self.github_hunt_image,
                    rm=True,
                )

            # Start container with environment variables
            container = self.client.containers.run(
                self.github_hunt_image,
                mem_limit=self._container_mem_limit("github_hunt"),  # Memory governor (Part 4c)
                pids_limit=self._container_pids_limit(),  # D1: fork-bomb ceiling
                nano_cpus=self._container_cpu_limit(),  # D1: core-proportional CPU cap
                **self._scanner_hardening(drop_caps=False),  # S3/E6: cap_drop deferred (residual; not verifiable here)
                name=container_name,
                detach=True,
                network_mode="host",
                environment={
                    "PROJECT_ID": project_id,
                    "USER_ID": user_id,
                    "WEBAPP_API_URL": webapp_api_url,
                    # V3: operator-approved extra tool images (empty = strict
                    # shipped-only allowlist). Server-controlled; forwarded to the
                    # recon pipeline so air-gapped/private-registry deployments work.
                    "RECON_EXTRA_ALLOWED_IMAGES": os.environ.get("RECON_EXTRA_ALLOWED_IMAGES", ""),
                    "PYTHONUNBUFFERED": "1",
                    # Forward Neo4j credentials from orchestrator environment
                    "NEO4J_URI": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                    "NEO4J_USER": os.environ.get("NEO4J_USER", "neo4j"),
                    "NEO4J_PASSWORD": os.environ.get("NEO4J_PASSWORD", ""),
                    **self._scanner_env(),  # S3/E6: scoped scanner token
                },
                volumes={
                    # GitHub hunt output (read-write, for saving results)
                    f"{github_hunt_path}/output": {"bind": "/app/github_secret_hunt/output", "mode": "rw"},
                    # Mount github_secret_hunt source for development (no rebuild needed)
                    f"{github_hunt_path}": {"bind": "/app/github_secret_hunt", "mode": "rw"},
                    # Mount graph_db module for Neo4j integration
                    **self._graph_db_mount(sibling_host_path(parent_host_path(github_hunt_path), "graph_db"), baked_into_image=True),
                },
                command="python github_secret_hunt/main.py",
            )

            state.container_id = container.id
            state.status = GithubHuntStatus.RUNNING
            logger.info(f"Started GitHub hunt container {container.id} for project {project_id}")

        except Exception as e:
            state.status = GithubHuntStatus.ERROR
            state.error = str(e)
            logger.error(f"Failed to start GitHub hunt for {project_id}: {e}")

        return state

    async def pause_github_hunt(self, project_id: str) -> GithubHuntState:
        """Pause a running GitHub hunt process"""
        state = await self.get_github_hunt_status(project_id)

        if state.status != GithubHuntStatus.RUNNING:
            return state

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.pause()
                state.status = GithubHuntStatus.PAUSED
                self.github_hunt_states[project_id] = state
                logger.info(f"Paused GitHub hunt container for project {project_id}")
            except NotFound:
                state.status = GithubHuntStatus.ERROR
                state.error = "Container not found"
            except APIError as e:
                state.status = GithubHuntStatus.ERROR
                state.error = f"Failed to pause: {e}"

        return state

    async def resume_github_hunt(self, project_id: str) -> GithubHuntState:
        """Resume a paused GitHub hunt process"""
        state = await self.get_github_hunt_status(project_id)

        if state.status != GithubHuntStatus.PAUSED:
            return state

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.unpause()
                state.status = GithubHuntStatus.RUNNING
                self.github_hunt_states[project_id] = state
                logger.info(f"Resumed GitHub hunt container for project {project_id}")
            except NotFound:
                state.status = GithubHuntStatus.ERROR
                state.error = "Container not found"
            except APIError as e:
                state.status = GithubHuntStatus.ERROR
                state.error = f"Failed to resume: {e}"

        return state

    async def stop_github_hunt(self, project_id: str, timeout: int = 10) -> GithubHuntState:
        """Stop a running GitHub hunt process"""
        state = await self.get_github_hunt_status(project_id)

        if state.status not in (GithubHuntStatus.RUNNING, GithubHuntStatus.PAUSED):
            return state

        state.status = GithubHuntStatus.STOPPING

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                if container.status == "paused":
                    container.unpause()
                container.stop(timeout=timeout)
                # BEFORE removing it: the container had `timeout` seconds to save
                # and write the graph itself. If SIGKILL came first, this is the
                # last chance to keep the run's findings.
                self._ingest_github_hunt(state)
                container.remove()
                state.status = GithubHuntStatus.IDLE
                state.completed_at = datetime.now(timezone.utc)
                logger.info(f"Stopped GitHub hunt container for project {project_id}")
            except NotFound:
                state.status = GithubHuntStatus.IDLE
            except Exception as e:
                state.status = GithubHuntStatus.ERROR
                state.error = f"Failed to stop: {e}"

        if project_id in self.github_hunt_states:
            del self.github_hunt_states[project_id]

        return state

    def _parse_github_hunt_log_line(self, line: str, current_phase: Optional[str], current_phase_num: Optional[int], timestamp: Optional[datetime] = None) -> GithubHuntLogEvent:
        """Parse a GitHub hunt log line and detect phase changes"""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        phase = current_phase
        phase_num = current_phase_num
        is_phase_start = False
        level = "info"

        # Strip ANSI escape codes
        line = ANSI_ESCAPE.sub('', line)

        # Detect log level
        if "[!]" in line or "[!!!]" in line:
            level = "error"
        elif "[+]" in line or "[✓]" in line:
            level = "success"
        elif "[*]" in line:
            level = "action"
        elif "[~]" in line:
            level = "warning"

        # Detect phase changes
        for pattern, phase_name, num in GITHUB_HUNT_PHASE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                if phase_name != current_phase:
                    phase = phase_name
                    phase_num = num
                    is_phase_start = True
                break

        return GithubHuntLogEvent(
            log=line.rstrip(),
            timestamp=timestamp,
            phase=phase,
            phase_number=phase_num,
            is_phase_start=is_phase_start,
            level=level,
        )

    async def stream_github_hunt_logs(self, project_id: str) -> AsyncGenerator[GithubHuntLogEvent, None]:
        """Stream logs from a GitHub hunt container"""
        state = await self.get_github_hunt_status(project_id)

        if not state.container_id:
            yield GithubHuntLogEvent(
                log="No GitHub hunt container found for this project",
                timestamp=datetime.now(timezone.utc),
                level="error",
            )
            return

        current_phase: Optional[str] = None
        current_phase_num: Optional[int] = None

        try:
            container = self.client.containers.get(state.container_id)

            log_queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue()
            loop = asyncio.get_running_loop()

            def read_logs():
                try:
                    # Throttle the per-line liveness reload() below: next allowed
                    # Docker status poll, in monotonic seconds (list = mutable box).
                    _log_status_gate = [time.monotonic() + 30.0]
                    for line in container.logs(stream=True, follow=True, timestamps=True):
                        asyncio.run_coroutine_threadsafe(
                            log_queue.put(line),
                            loop
                        ).result(timeout=5)
                        # Liveness check, THROTTLED to once per ~30s. Previously
                        # reload() ran on EVERY log line -- a Docker round-trip per
                        # line. A scan emitting 100k+ lines flooded the daemon,
                        # slowing every request and starving the event loop (the
                        # parallel-scan freeze). The stream generator ending already
                        # stops the loop when a container exits, so a 30s liveness
                        # poll loses nothing but the wasted daemon load.
                        if time.monotonic() >= _log_status_gate[0]:
                            _log_status_gate[0] = time.monotonic() + 30.0
                            try:
                                container.reload()
                                if container.status not in ("running", "paused"):
                                    break
                            except Exception:
                                break
                except Exception as e:
                    logger.error(f"Error in GitHub hunt log reader thread: {e}")
                finally:
                    try:
                        asyncio.run_coroutine_threadsafe(
                            log_queue.put(None),
                            loop
                        ).result(timeout=5)
                    except Exception:
                        pass

            loop.run_in_executor(self._log_stream_executor, read_logs)

            while True:
                try:
                    line = await asyncio.wait_for(log_queue.get(), timeout=1.0)
                    if line is None:
                        break

                    decoded_line = line.decode("utf-8", errors="replace").rstrip()
                    if decoded_line:
                        # Parse Docker timestamp prefix
                        docker_ts = None
                        log_text = decoded_line
                        if len(decoded_line) > 30 and decoded_line[4] == '-' and decoded_line[10] == 'T':
                            space_idx = decoded_line.find(' ')
                            if space_idx > 0:
                                ts_str = decoded_line[:space_idx]
                                try:
                                    ts_clean = ts_str.replace('Z', '+00:00')
                                    dot_idx = ts_clean.find('.')
                                    plus_idx = ts_clean.find('+', dot_idx) if dot_idx > 0 else -1
                                    if dot_idx > 0 and plus_idx > 0:
                                        frac = ts_clean[dot_idx + 1:plus_idx][:6]
                                        ts_clean = ts_clean[:dot_idx + 1] + frac + ts_clean[plus_idx:]
                                    docker_ts = datetime.fromisoformat(ts_clean)
                                    log_text = decoded_line[space_idx + 1:]
                                except (ValueError, OverflowError):
                                    pass

                        event = self._parse_github_hunt_log_line(log_text, current_phase, current_phase_num, timestamp=docker_ts)

                        if event.is_phase_start:
                            current_phase = event.phase
                            current_phase_num = event.phase_number

                            if project_id in self.github_hunt_states:
                                self.github_hunt_states[project_id].current_phase = current_phase
                                self.github_hunt_states[project_id].phase_number = current_phase_num

                        yield event

                except asyncio.TimeoutError:
                    try:
                        container.reload()
                        if container.status not in ("running", "paused"):
                            break
                    except Exception:
                        break

        except (NotFound, APIError):
            yield GithubHuntLogEvent(
                log="GitHub hunt container stopped",
                timestamp=datetime.now(timezone.utc),
                level="info",
            )
        except Exception as e:
            yield GithubHuntLogEvent(
                log=f"Error streaming GitHub hunt logs: {e}",
                timestamp=datetime.now(timezone.utc),
                level="error",
            )

    def get_github_hunt_running_count(self) -> int:
        """Get count of running GitHub hunt processes"""
        return sum(1 for s in self.github_hunt_states.values() if s.status == GithubHuntStatus.RUNNING)

    # =========================================================================
    # TruffleHog Secret Scanner Container Lifecycle
    # =========================================================================

    @staticmethod
    def _trufflehog_kind(source: str) -> str:
        """Source-qualified admission kind.

        Sources are not interchangeable in RAM terms: a git clone is a few
        hundred MB, while docker and huggingface pull and decompress remote blobs
        and peak far above that. ``scan_job_envelope`` resolves
        ``trufflehog:<source>`` and FLOORS it at the plain ``trufflehog``
        envelope, so qualifying every source is safe — a source with no entry of
        its own keeps the family envelope, and a calibrated host can never make a
        heavy source reserve less than the base.

        Same rule as ``_partial_kind``: admission and reconcile must use this
        identical key format, or the reaper frees a live scan's reservation.
        """
        return f"trufflehog:{source}" if source else "trufflehog"

    def _get_trufflehog_container_name(self, project_id: str, source: str) -> str:
        """Container name for ONE source's run. The source is part of the name,
        so starting docker does not force-remove a running huggingface scan."""
        safe_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', project_id)
        safe_source = re.sub(r'[^a-zA-Z0-9_.-]', '_', source or "unknown")
        return f"redamon-trufflehog-{safe_id}-{safe_source}"

    def _trufflehog_run_dir(self, project_id: str, source: str) -> Path:
        """Per-run scratch dir on the host: the job file in, the scan's working
        files (regex path-files, the GCP service-account blob) alongside.

        Together with the output dir this is the ENTIRE contract across the
        dirty/clean boundary. The scan container gets these two directories rw
        and nothing else writable.
        """
        safe_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', project_id)
        safe_source = re.sub(r'[^a-zA-Z0-9_.-]', '_', source or "unknown")
        return Path(f"/tmp/redamon/trufflehog_{safe_id}_{safe_source}")

    @staticmethod
    def _trufflehog_output_name(project_id: str, source: str) -> str:
        """Findings filename, per project AND source. The webapp's download route
        globs these, so the shape is part of that contract."""
        safe_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', project_id)
        safe_source = re.sub(r'[^a-zA-Z0-9_.-]', '_', source or "unknown")
        return f"trufflehog_{safe_id}_{safe_source}.json"

    def _trufflehog_output_path(self, project_id: str, source: str) -> Path:
        """Where the published findings live, as the ORCHESTRATOR sees them.
        Compose binds this dir into the webapp read-only for the JSON download."""
        return Path("/app/trufflehog_scan/output") / self._trufflehog_output_name(project_id, source)

    def _trufflehog_git_config_mount(self, run_dir: Path, scan_target_mounts: dict) -> dict:
        """A system gitconfig that lets the scan read a locally-supplied repo.

        git refuses a repository it does not own ("detected dubious ownership")
        and the clone fails outright — the fixture belongs to whoever created it
        on the host, the container runs as an unprivileged uid, and the two never
        match. The failure is silent in the worst way: the wrapper still writes an
        artifact, so it reads as a clean scan of a clean repo.

        It has to be a config FILE. git honours `safe.directory` only from
        protected configuration, deliberately, so that an untrusted repository
        cannot inject it — which rules out `-c` and the GIT_CONFIG_* env vars.

        Written into the run's own scratch dir and mounted read-only, so it lives
        and dies with the run rather than being baked into the image. Only for
        runs that actually carry the scan-targets tree; that tree is read-only and
        is the only repository this container can reach.
        """
        if not scan_target_mounts:
            return {}
        try:
            # A SIBLING of the run dir, never inside it: run_dir is bind-mounted
            # rw at /work, so a gitconfig written there would be rewritable by
            # the container through that mount and the read-only bind below would
            # promise something it does not deliver.
            cfg = run_dir.parent / f"{run_dir.name}.gitconfig"
            cfg.parent.mkdir(parents=True, exist_ok=True)
            cfg.write_text("[safe]\n\tdirectory = *\n")
        except OSError as e:
            logger.warning(f"[trufflehog] could not write gitconfig: {e}")
            return {}
        return {str(cfg): {"bind": "/etc/gitconfig", "mode": "ro"}}

    def _trufflehog_artifact_error(self, project_id: str, source: str) -> str:
        """The scan's own verdict from its artifact, or "" if it succeeded.

        The wrapper exits 0 whenever it managed to WRITE a result, including a
        result that records a failed scan, so the container exit code cannot tell
        a clean target from a target that was never reached. Unreadable or
        missing is treated as success: this decides whether to flip a run to
        ERROR, and a parse problem here must not invent a failure that the scan
        did not report.
        """
        try:
            run_dir = self._trufflehog_run_dir(project_id, source)
            out = run_dir / "out.json"
            if not out.exists():
                # The wrapper writes a result on every path it can reach,
                # including the ones that record a failure. No file at all means
                # it died before it could - reporting that as a clean scan is the
                # exact silent lie this function exists to stop.
                return "The scan exited without writing a result file"
            data = json.loads(out.read_text())
        except Exception:
            # Unreadable or half-written: cannot tell a failure from a clean run,
            # and inventing one would flip a good scan to ERROR.
            return ""
        if not isinstance(data, dict) or data.get("status") != "error":
            return ""
        err = str(data.get("error") or "").strip()
        return err or "The scan reported an error and produced no findings"

    def _publish_trufflehog_output(self, project_id: str, source: str) -> Optional[Path]:
        """Copy a finished run's findings from the scratch dir to the shared
        output dir, and return the published path.

        Done by the orchestrator, not the container: the scan runs as a non-root
        uid with every capability dropped and cannot write the host-owned output
        directory — which is precisely why it is not mounted into it.

        Returns None when the run wrote nothing (a container that died before its
        first write); the caller then has nothing to ingest.
        """
        src = self._trufflehog_run_dir(project_id, source) / "out.json"
        if not src.exists():
            return None
        dest = self._trufflehog_output_path(project_id, source)
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
            os.chmod(dest, 0o644)
            return dest
        except OSError as e:
            logger.warning(f"[trufflehog] could not publish {source} findings: {e}")
            # Fall back to the scratch copy so ingest still runs; only the
            # operator-facing download is lost.
            return src

    def _drop_trufflehog_run(self, project_id: str, source: str,
                             expected: Optional[TrufflehogState] = None) -> None:
        """Release a run slot, and prune the project entry when it empties.

        `expected` guards against dropping a DIFFERENT run that claimed the slot
        in the meantime — only the caller's own claim is removed.
        """
        runs = self.trufflehog_states.get(project_id)
        if not runs:
            return
        if expected is not None and runs.get(source) is not expected:
            return
        runs.pop(source, None)
        if not runs:
            self.trufflehog_states.pop(project_id, None)

    def _ensure_trufflehog_network(self) -> None:
        """Create the TruffleHog scan network if missing.

        A user-defined bridge, NOT ``network_mode=host``. The scan legitimately
        needs outbound internet (github.com, a docker registry, huggingface.co),
        which a bridge gives it through NAT; what it must NOT have is the host's
        own loopback stack, where Neo4j (7687) and the orchestrator (8010) live.
        On host networking a target of ``127.0.0.1:7687`` resolves straight into
        RedAmon's own graph. Compose never creates this network because no
        service is attached to it. Idempotent, tolerates the create race.
        """
        name = self.trufflehog_network
        try:
            self.client.networks.get(name)
            return
        except NotFound:
            pass
        try:
            self.client.networks.create(name, driver="bridge", check_duplicate=True)
            logger.info(f"[trufflehog] created scan network {name}")
        except APIError as e:
            logger.warning(f"[trufflehog] network ensure for {name}: {e}")

    async def get_trufflehog_status(self, project_id: str, source: str) -> TrufflehogState:
        """Status of ONE source's run. Docker inspection runs off the event loop
        (_run_blocking) so a slow daemon can't stall the worker."""
        return await self._run_blocking(self._get_trufflehog_status_sync, project_id, source)

    async def get_all_trufflehog_statuses(self, project_id: str) -> list[TrufflehogState]:
        """Every run for a project.

        The webapp reconcile, the version-save guard and the activation guard all
        read this rather than a project-level status: with N parallel runs a
        single status can only ever describe one of them, and the other N-1 look
        idle to every caller.
        """
        runs = self.trufflehog_states.get(project_id, {})
        out: list[TrufflehogState] = []
        stale: list[str] = []
        now = datetime.now(timezone.utc)
        for source in list(runs.keys()):
            state = await self.get_trufflehog_status(project_id, source)
            out.append(state)
            # Retire long-finished runs so the dict cannot grow without bound
            # across the orchestrator's lifetime. The retention window is far
            # wider than the reconcile grace, so the outcome is always observed
            # before the run disappears.
            if (state.status in (TrufflehogStatus.COMPLETED, TrufflehogStatus.ERROR)
                    and state.completed_at
                    and (now - state.completed_at).total_seconds() > TRUFFLEHOG_TERMINAL_RETENTION_S):
                stale.append(source)
        # pop(), not del: the awaits above are suspension points, so a concurrent
        # caller may already have retired the same run.
        for source in stale:
            self._drop_trufflehog_run(project_id, source)
        return out

    def _get_trufflehog_status_sync(self, project_id: str, source: str) -> TrufflehogState:
        runs = self.trufflehog_states.get(project_id, {})
        if source in runs:
            state = runs[source]

            # A finished run whose container has already been removed has nothing
            # left to learn from Docker. Without this the 30 s sweep re-inspects
            # every run ever started, for every project, forever — the same
            # daemon-flooding shape that caused the parallel-scan freeze.
            settled = (state.status in (TrufflehogStatus.COMPLETED, TrufflehogStatus.ERROR)
                       and state.container_removed)

            if state.container_id and not settled:
                try:
                    container = self.client.containers.get(state.container_id)
                    if container.status == "paused":
                        state.status = TrufflehogStatus.PAUSED
                    elif container.status != "running":
                        exit_code = container.attrs.get("State", {}).get("ExitCode", -1)
                        if exit_code == 0:
                            # A zero exit only means the WRAPPER finished. It
                            # writes an artifact and exits cleanly even when the
                            # scan itself failed — a clone that never happened
                            # then reads as a completed run with no findings,
                            # which is indistinguishable from a clean target.
                            # The artifact carries the scan's own verdict.
                            scan_error = self._trufflehog_artifact_error(
                                state.project_id, state.source)
                            if scan_error:
                                state.status = TrufflehogStatus.ERROR
                                state.error = scan_error
                            else:
                                state.status = TrufflehogStatus.COMPLETED
                            state.completed_at = datetime.now(timezone.utc)
                        else:
                            state.status = TrufflehogStatus.ERROR
                            state.error = f"Container exited with code {exit_code}"
                            state.completed_at = datetime.now(timezone.utc)

                        # The CLEAN half of the split: the dirty container held no
                        # Neo4j credentials, so the graph write happens here, once
                        # the process that parsed untrusted bytes is gone.
                        self._ingest_trufflehog(state)

                        try:
                            container.remove()
                            state.container_removed = True
                            logger.info(
                                f"Auto-removed finished TruffleHog container for {project_id}/{source}")
                        except Exception as e:
                            logger.warning(f"Failed to auto-remove TruffleHog container: {e}")
                except NotFound:
                    # Already gone (removed by a concurrent poll, or by hand).
                    state.container_removed = True
                    if state.status not in (TrufflehogStatus.COMPLETED, TrufflehogStatus.ERROR):
                        state.status = TrufflehogStatus.ERROR
                        state.error = "Container not found"
                except APIError as e:
                    logger.warning(
                        f"Docker API error checking TruffleHog container for {project_id}/{source}: {e}")
                    if state.status not in (TrufflehogStatus.COMPLETED, TrufflehogStatus.ERROR):
                        state.status = TrufflehogStatus.ERROR
                        state.error = f"Docker API error: {e}"

            # Retry a terminal run's ingest. The first attempt runs on the poll
            # that also removes the container, so without this a transient Neo4j
            # blip would lose the findings for good — the artifact is on disk but
            # nothing would ever read it again. Idempotent via state.ingested,
            # and the status sweep polls every run periodically.
            if (state.status in (TrufflehogStatus.COMPLETED, TrufflehogStatus.ERROR)
                    and not state.ingested
                    and state.ingest_attempts < MAX_TRUFFLEHOG_INGEST_ATTEMPTS):
                self._ingest_trufflehog(state)

            return state

        # An orphan container from a crashed orchestrator still owns the run key.
        container_name = self._get_trufflehog_container_name(project_id, source)
        try:
            container = self.client.containers.get(container_name)
            if container.status in ("running", "paused"):
                return TrufflehogState(
                    project_id=project_id,
                    source=source,
                    run_id=source,
                    status=TrufflehogStatus.PAUSED if container.status == "paused" else TrufflehogStatus.RUNNING,
                    container_id=container.id,
                )
        except NotFound:
            pass

        return TrufflehogState(
            project_id=project_id,
            source=source,
            run_id=source,
            status=TrufflehogStatus.IDLE,
        )

    # ------------------------------------------------------------------
    # Supply-chain DIRTY analyzer (plan Phase 0.5) - the secret-free box
    # ------------------------------------------------------------------
    def _ensure_supply_chain_network(self) -> None:
        """Create the isolated supply-chain analyzer network if missing.

        Same rationale as _ensure_codefix_network: Compose never creates it
        because no service is attached (the analyzer must have no RedAmon peer).
        The OSV verdict path needs ZERO egress; this bridge provides none of its
        own to the RedAmon services. Idempotent, tolerates the create race."""
        name = self.supply_chain_analyzer_network
        try:
            self.client.networks.get(name)
            return
        except NotFound:
            pass
        try:
            self.client.networks.create(name, driver="bridge", check_duplicate=True)
            logger.info(f"[supply-chain] created isolated network {name}")
        except APIError as e:
            logger.warning(f"[supply-chain] network ensure for {name}: {e}")

    def run_supply_chain_analyzer(
        self,
        job_scratch_host_path: str,
        sc_common_host_path: str,
        *,
        allow_registry_egress: bool = False,
        timeout: int = 600,
    ) -> dict:
        """Run ONE dirty-analyzer job to completion and return its outcome.

        The CALLER (a clean, creds-holding container or the orchestrator) has
        already written ``job.json`` and any input bytes into
        ``job_scratch_host_path`` (a shared scratch dir). We bind that dir rw at
        /work, the shared runners read-only at /app/supply_chain_common, and the
        offline OSV DB read-only at /osv-db. The analyzer writes ``out.json``.

        HARDENING (plan section 5.2): cap_drop=ALL, read_only rootfs + tmpfs
        scratch, non-root, mem/pids/cpu caps, and CRITICALLY no secrets in env
        (a full RCE in here finds no Neo4j/Internal/GitHub credential). The OSV
        path is fully network-isolated; GuardDog registry egress is opt-in and
        fails closed to the isolated net unless an egress network is configured.

        Returns {exit_code, out_path, error}. Never raises on a tool-level
        failure; the caller validates out.json via validate_artifact regardless.
        """
        self._ensure_supply_chain_network()

        network = self.supply_chain_analyzer_network
        if allow_registry_egress:
            # Opt-in GuardDog path. Fails closed: without an explicitly configured
            # egress network the analyzer stays on the isolated bridge (GuardDog
            # simply finds no registry, rather than silently getting host egress).
            network = os.environ.get("SUPPLY_CHAIN_EGRESS_NETWORK", network)

        container = None
        try:
            container = self.client.containers.run(
                self.supply_chain_analyzer_image,
                detach=True,
                network=network,
                cap_drop=["ALL"],
                read_only=True,
                tmpfs={"/tmp": "size=1g,exec"},
                mem_limit=self._analyzer_mem_limit(),
                nano_cpus=self._container_cpu_limit() or self.supply_chain_analyzer_nanocpus,
                pids_limit=self.supply_chain_analyzer_pids,
                # CRITICAL: NO secrets. Only the offline DB pointer.
                environment={
                    "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/osv-db",
                    "PYTHONUNBUFFERED": "1",
                    "PYTHONPATH": "/app",
                },
                volumes={
                    job_scratch_host_path: {"bind": "/work", "mode": "rw"},
                    sc_common_host_path: {"bind": "/app/supply_chain_common", "mode": "ro"},
                    self.supply_chain_osv_db_volume: {"bind": "/osv-db", "mode": "ro"},
                },
                command=["sc-analyze", "--job", "/work/job.json", "--out", "/work/out.json"],
            )
            result = container.wait(timeout=timeout)
            exit_code = result.get("StatusCode", -1) if isinstance(result, dict) else -1
            return {"exit_code": exit_code, "out_path": "/work/out.json", "error": None}
        except Exception as e:  # spawn/timeout/daemon error: caller falls back
            logger.error(f"[supply-chain] analyzer run failed: {e}")
            return {"exit_code": None, "out_path": "/work/out.json", "error": str(e)}
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except APIError:
                    pass

    # Ecosystems GuardDog can analyse (mirrors the tool contract). Also the
    # INJECTION GATE: the value is passed to `docker run` as an argv element, so
    # anything off this list is refused, not escaped.
    _GUARDDOG_ECOSYSTEMS = frozenset(
        {"npm", "pypi", "go", "crates", "rubygems", "github_action", "extension"})
    # Package name / version charset gate. Same posture as
    # supply_chain_common.security.sanitize_name; kept inline (this module has no
    # source mount of that package). The FIRST char must be alphanumeric or @ (npm
    # scopes): a leading '-' would otherwise let a name like "--help" reach
    # GuardDog's argv as a FLAG (there is no shell, but click/argparse would still
    # consume it). No real package name or version starts with '-'.
    _GUARDDOG_SAFE = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9._@/+-]{0,213}$")

    def run_guarddog_package(self, ecosystem: str, name: str,
                             version: str = "", *, timeout: int = 200) -> dict:
        """Behavioural (GuardDog) analysis of ONE named package.

        The L3 counterpart of the L1 deep-analysis path: an agent chat asks for
        GuardDog on a single package, and this runs it the SAME way the L1 scan
        does - inside the hardened, secret-free analyzer image, dispatched by the
        orchestrator (the trusted socket holder). The Kali worker never touches
        Docker: it cannot, and must not (it is the least-trusted, target-facing
        zone). See docs/readmes/README.TM.SYSTEM_OVERVIEW.md trust boundaries.

        GuardDog downloads the attacker-authored tarball, so the container:
          - runs on the ISOLATED analyzer bridge (internet NAT for the registry,
            but NO route to any RedAmon service),
          - drops ALL caps, read-only rootfs, exec tmpfs scratch, mem/pids caps,
          - carries ZERO secrets (a full RCE in here finds no cred).

        Returns {issues, rules_fired, errors, error}. `error` is set only on a
        dispatch/charset failure; a clean package is {issues:0, ...}.
        """
        eco = (ecosystem or "").strip().lower()
        pkg = (name or "").strip()
        ver = (version or "").strip()
        if eco not in self._GUARDDOG_ECOSYSTEMS:
            return {"error": "unsupported ecosystem: {!r}".format(ecosystem),
                    "issues": 0, "rules_fired": [], "errors": []}
        if not self._GUARDDOG_SAFE.match(pkg) or (ver and not self._GUARDDOG_SAFE.match(ver)):
            return {"error": "invalid package name/version (charset validation)",
                    "issues": 0, "rules_fired": [], "errors": []}

        self._ensure_supply_chain_network()
        # GuardDog needs registry egress; the isolated analyzer bridge provides
        # internet NAT while sharing no subnet with RedAmon services. An operator
        # may still pin a dedicated egress net.
        network = os.environ.get("SUPPLY_CHAIN_EGRESS_NETWORK",
                                 self.supply_chain_analyzer_network)

        # --no-sandbox: GuardDog 3.x tries to build its own user-namespace
        # sandbox and fails SILENTLY inside a container (exit 0, issues 0, real
        # cause buried in errors). The analyzer image IS the sandbox, so disable
        # GuardDog's inner one. Matches the former in-Kali command exactly.
        cmd = [eco, "scan", pkg, "--no-sandbox", "--output-format", "json"]
        if ver:
            cmd += ["--version", ver]

        container = None
        try:
            container = self.client.containers.run(
                self.supply_chain_analyzer_image,
                detach=True,
                network=network,
                cap_drop=["ALL"],
                read_only=True,
                tmpfs={"/tmp": "size=1g,exec"},
                mem_limit=self._analyzer_mem_limit(),
                nano_cpus=self._container_cpu_limit() or self.supply_chain_analyzer_nanocpus,
                pids_limit=self.supply_chain_analyzer_pids,
                environment={"PYTHONUNBUFFERED": "1"},
                entrypoint="guarddog",
                command=cmd,
            )
            container.wait(timeout=timeout)
            # GuardDog prints the JSON report to stdout; its own logs go to stderr.
            out = container.logs(stdout=True, stderr=False) or b""
            try:
                raw = json.loads(out.decode("utf-8", "replace") or "{}")
            except ValueError:
                return {"error": "guarddog produced non-JSON output",
                        "issues": 0, "rules_fired": [], "errors": []}
            if not isinstance(raw, dict):
                return {"error": "guarddog output was not an object",
                        "issues": 0, "rules_fired": [], "errors": []}
            fired = [r for r, v in (raw.get("results") or {}).items() if v]
            return {
                "issues": raw.get("issues", 0),
                "rules_fired": fired[:30],
                "errors": list((raw.get("errors") or {}).keys()),
                "error": None,
            }
        except Exception as e:  # dispatch/timeout/daemon error
            logger.error(f"[supply-chain] guarddog package run failed: {e}")
            return {"error": "guarddog dispatch failed: {}".format(e),
                    "issues": 0, "rules_fired": [], "errors": []}
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except APIError:
                    pass

    async def run_guarddog_package_governed(self, ecosystem: str, name: str,
                                            version: str = "") -> dict:
        """Admission-gated wrapper around run_guarddog_package (L3).

        The agent can call execute_guarddog as often as it likes, and every call
        spawns a real ~1.5 GB analyzer container. Before this gate that path
        booked nothing: the ledger reported the host idle while N analyzers ran,
        which is exactly the sum-of-envelopes guarantee the governor exists to
        provide. Now an L3 job reserves the analyzer's tool envelope like any
        other work, and a full host returns the same typed 409 a refused scan
        does instead of quietly oversubscribing RAM.

        The reservation is request-scoped: taken here, released in `finally`, and
        listed in _active_scan_keys meanwhile so the reaper cannot free it early.
        Fail-open is inherited from try_admit (governor off / RAM unreadable ->
        admitted). Raises AdmissionError, which api.py maps to a 409 payload.
        """
        key = f"supply_chain_analyzer:{uuid.uuid4()}"
        envelope = self._analyzer_envelope()
        result = await self.ledger.try_admit(key, envelope)
        if not result.admitted:
            logger.info(f"[governor] admission denied for {key}: "
                        f"{result.limit_type} - {result.detail}")
            raise AdmissionError(result)
        self.guarddog_jobs.add(key)
        try:
            # Blocking (docker run + wait) - keep it off the event loop.
            return await asyncio.to_thread(
                self.run_guarddog_package, ecosystem, name, version)
        finally:
            self.guarddog_jobs.discard(key)
            await self.ledger.release(key)

    # ------------------------------------------------------------------
    # Offline OSV database freshness (lazy-on-scan refresh)
    # ------------------------------------------------------------------
    # OSV ecosystems this sidecar knows how to seed. Also the INJECTION GATE:
    # the ecosystem string is interpolated into a shell script, so anything not
    # on this list is refused rather than escaped (same posture as sanitize_name).
    # MUST stay in step with scanners/supply_chain_common/osv_db_sync.py SEED_MANIFESTS.
    # This sidecar cannot import that module (it has no source mount), so the
    # list is duplicated - tests/test_supply_chain_osv_refresh.py asserts the
    # two never drift. Maven and NuGet were missing here, so an operator could
    # sync them by hand and then watch them silently go stale forever.
    _OSV_SYNC_ECOSYSTEMS = ("npm", "PyPI", "Go", "Maven", "crates.io",
                            "Packagist", "RubyGems", "NuGet")

    def ensure_osv_db_fresh(self, ecosystems=None, ttl_seconds=None,
                            bootstrap: bool = False) -> dict:
        """Refresh the offline OSV DB if it is older than the TTL (default 24h).

        Called on the scan-spawn path (L1 + L2) so the malicious-package feed is
        current without the operator remembering `redamon.sh supply-chain-sync`.
        OSV publishes new MAL-/CVE advisories daily, so a DB frozen at install
        time silently misses newly-published malware.

        WHY HERE: `redamon-osv-db` is mounted READ-ONLY (and non-root) into every
        scan container, so a scanner physically cannot refresh its own DB. Only
        this process holds the Docker socket, so the refresh runs as a short-lived
        root sidecar off the analyzer image writing the volume rw.

        `bootstrap=False` (the scan-path default) REFUSES to populate a cold/empty
        DB: the initial download is ~208 MB and would otherwise block the first
        recon spawn for minutes, for a feature that is OFF by default. Cold
        population stays explicit (`redamon.sh supply-chain-sync`), matching the
        documented "images are eager, the data is lazy" contract. Only an
        already-populated DB is kept fresh here.

        Cheap by design: within-TTL calls are a ~1s no-op. Best-effort - a failure
        (offline host, GCS unreachable) NEVER blocks the scan; the scan proceeds
        against the existing DB.

        Returns {"status": skipped|synced|failed|disabled, "detail": ...}.
        """
        if os.environ.get("OSV_DB_AUTO_REFRESH", "true").lower() in ("0", "false", "no"):
            return {"status": "disabled", "detail": "OSV_DB_AUTO_REFRESH is off"}

        ecos_raw = ecosystems or os.environ.get("OSV_DB_ECOSYSTEMS", "npm")
        if isinstance(ecos_raw, (list, tuple, set)):
            ecos_list = list(ecos_raw)
        else:
            ecos_list = [e.strip() for e in str(ecos_raw).replace(",", " ").split() if e.strip()]
        # Injection gate: refuse anything not on the allowlist (never escape it).
        unknown = [e for e in ecos_list if e not in self._OSV_SYNC_ECOSYSTEMS]
        if unknown:
            logger.warning(f"[osv-db] refusing unknown ecosystem(s): {unknown}")
            ecos_list = [e for e in ecos_list if e in self._OSV_SYNC_ECOSYSTEMS]
        if not ecos_list:
            return {"status": "disabled", "detail": "no valid ecosystems configured"}
        ecos = ",".join(ecos_list)
        ttl = int(ttl_seconds or os.environ.get("OSV_DB_TTL_SECONDS", 24 * 3600))

        # The sidecar shells out to the osv-scanner BINARY baked into the analyzer
        # image rather than importing supply_chain_common (that package is mounted
        # at scan-spawn time, and this sidecar has no source mount). It mirrors
        # osv_db_sync: TTL marker check -> seed manifest -> tool's own download ->
        # world-readable chmod (the DB is consumed by non-root read-only scanners).
        script = r'''
set -u
DB=/osv-db; TTL=__TTL__; RC=0; DID=0; BOOTSTRAP=__BOOTSTRAP__
mkdir -p "$DB"
# Cold-DB guard: without an existing DB tree this would be a ~208 MB first
# download on the scan-spawn path. Refuse unless explicitly bootstrapping.
if [ "$BOOTSTRAP" != "1" ] && [ ! -d "$DB/osv-scanner" ]; then
  echo "cold-db: not populated, skipping auto-refresh (run redamon.sh supply-chain-sync)"
  exit 0
fi
for ECO in $(echo "__ECOS__" | tr ',' ' '); do
  MARK="$DB/.redamon_synced_$(echo "$ECO" | tr './' '__')"
  if [ -f "$MARK" ]; then
    AGE=$(( $(date +%s) - $(stat -c %Y "$MARK" 2>/dev/null || echo 0) ))
    if [ "$AGE" -lt "$TTL" ]; then echo "skip $ECO (age ${AGE}s < ${TTL}s)"; continue; fi
  fi
  SEED=$(mktemp -d)
  case "$ECO" in
    npm)   printf '%s' '{"name":"s","version":"1.0.0","lockfileVersion":3,"packages":{"":{"dependencies":{"left-pad":"1.3.0"}},"node_modules/left-pad":{"version":"1.3.0"}}}' > "$SEED/package-lock.json"; F="$SEED/package-lock.json" ;;
    PyPI)  printf 'pip==24.0\n' > "$SEED/requirements.txt"; F="$SEED/requirements.txt" ;;
    Go)    printf 'module s\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.0\n' > "$SEED/go.mod"; F="$SEED/go.mod" ;;
    crates.io) printf '[[package]]\nname = "libc"\nversion = "0.2.150"\n' > "$SEED/Cargo.lock"; F="$SEED/Cargo.lock" ;;
    Packagist) printf '%s' '{"packages":[{"name":"monolog/monolog","version":"2.0.0"}]}' > "$SEED/composer.lock"; F="$SEED/composer.lock" ;;
    RubyGems)  printf 'GEM\n  specs:\n    rake (13.0.0)\n\nPLATFORMS\n  ruby\n' > "$SEED/Gemfile.lock"; F="$SEED/Gemfile.lock" ;;
    Maven) printf '%s' '<project><modelVersion>4.0.0</modelVersion><groupId>seed</groupId><artifactId>seed</artifactId><version>1.0.0</version><dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>30.0-jre</version></dependency></dependencies></project>' > "$SEED/pom.xml"; F="$SEED/pom.xml" ;;
    NuGet) printf '%s' '{"version":1,"dependencies":{".NETCoreApp,Version=v6.0":{"Newtonsoft.Json":{"type":"Direct","requested":"[13.0.1, )","resolved":"13.0.1"}}}}' > "$SEED/packages.lock.json"; F="$SEED/packages.lock.json" ;;
    *) echo "unknown ecosystem $ECO"; RC=1; rm -rf "$SEED"; continue ;;
  esac
  echo "sync $ECO ..."
  osv-scanner scan source --offline --download-offline-databases -L "$F" --format json >/dev/null 2>&1
  if [ -d "$DB/osv-scanner" ]; then date +%s > "$MARK"; DID=1; echo "synced $ECO"; else echo "sync $ECO produced no DB"; RC=1; fi
  rm -rf "$SEED"
done
[ "$DID" = "1" ] && chmod -R a+rX "$DB" 2>/dev/null
[ "$DID" = "1" ] && echo "__DID_SYNC__"
exit $RC
'''.replace("__TTL__", str(ttl)).replace("__ECOS__", ecos).replace(
            "__BOOTSTRAP__", "1" if bootstrap else "0")

        # Serialize refreshes: two scans starting at once would otherwise spawn two
        # sidecars writing the same volume (racing on all.zip). One orchestrator
        # process owns the socket, so a threading lock is sufficient. Non-blocking
        # acquire - if a refresh is already in flight, this caller just proceeds.
        if not self._osv_db_refresh_lock.acquire(blocking=False):
            return {"status": "skipped", "detail": "refresh already in progress"}

        container = None
        try:
            container = self.client.containers.run(
                self.supply_chain_analyzer_image,
                detach=True,
                user="root",  # the DB tree is root-owned; the sync is the one writer
                network_mode="bridge",  # needs egress to the OSV GCS bucket
                # Root is needed to write the root-owned DB tree, but no capability
                # is: drop them all so the sidecar cannot do anything but download.
                cap_drop=["ALL"],
                # Governed like every other sibling spawn; "1g" is only the
                # last resort when the governor is disabled. It was a bare
                # literal, the one spawn site that ignored the governor entirely.
                mem_limit=self._tool_container_mem_limit("osv_db_sync") or "1g",
                pids_limit=256,
                environment={
                    "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/osv-db",
                    "HOME": "/tmp",
                },
                volumes={
                    self.supply_chain_osv_db_volume: {"bind": "/osv-db", "mode": "rw"},
                },
                entrypoint="sh",
                command=["-c", script],
            )
            result = container.wait(timeout=self.osv_db_refresh_timeout)
            code = result.get("StatusCode", -1) if isinstance(result, dict) else -1
            logs = ""
            try:
                logs = container.logs().decode("utf-8", errors="replace").strip()[-500:]
            except Exception:
                pass
            if code == 0:
                # Distinguish an actual download from a TTL/cold-db no-op so logs
                # and telemetry do not claim a sync that never happened.
                did_sync = "__DID_SYNC__" in logs
                detail = logs.replace("__DID_SYNC__", "").strip()
                if did_sync:
                    logger.info(f"[osv-db] refreshed (ttl={ttl}s): {detail}")
                    return {"status": "synced", "detail": detail}
                logger.debug(f"[osv-db] no refresh needed (ttl={ttl}s): {detail}")
                return {"status": "skipped", "detail": detail}
            logger.warning(f"[osv-db] refresh exited {code}: {logs}")
            return {"status": "failed", "detail": logs}
        except Exception as e:
            # Never block a scan on a refresh failure.
            logger.warning(f"[osv-db] refresh skipped (non-fatal): {e}")
            return {"status": "failed", "detail": str(e)}
        finally:
            self._osv_db_refresh_lock.release()
            if container is not None:
                try:
                    container.remove(force=True)
                except APIError:
                    pass

    async def ensure_osv_db_fresh_async(self, ecosystems=None) -> dict:
        """Async wrapper: runs the (blocking) refresh off the event loop."""
        return await self._run_blocking(self.ensure_osv_db_fresh, ecosystems)

    def ensure_sca_intel_fresh(self, ttl_seconds=None) -> dict:
        """Refresh the supply-chain incident intel if it is past its TTL.

        Sibling of `ensure_osv_db_fresh` above, and deliberately built the same
        way: TTL-guarded, serialized, best-effort, and reporting `synced` versus
        `skipped` distinctly so a no-op is never logged as a fetch.

        TWO DELIBERATE DIFFERENCES from the OSV refresh, both because this feed is
        5.3 MB rather than 208 MB:

        1. It MAY bootstrap a cold volume on the scan path. The OSV cold guard
           exists solely because a 208 MB first download would stall the spawn for
           minutes; that reasoning does not carry here. Set
           SCA_INTEL_BOOTSTRAP_ON_SCAN=false to restore strict laziness.
        2. The timeout ceiling is 120s, not 900s.

        The TTL and retry-floor decisions live in `intel_sync` itself, so the
        sidecar makes them once and this method does not duplicate the policy.

        Returns {"status": skipped|synced|failed|disabled, "detail": ...}.
        """
        if os.environ.get("SCA_INTEL_AUTO_REFRESH", "true").lower() in ("0", "false", "no"):
            return {"status": "disabled", "detail": "SCA_INTEL_AUTO_REFRESH is off"}

        try:
            ttl = int(ttl_seconds or os.environ.get("SCA_INTEL_TTL_SECONDS", 24 * 3600))
            retry = int(os.environ.get("SCA_INTEL_RETRY_SECONDS", 3600))
        except (TypeError, ValueError):
            # A malformed knob must not abort the scan that triggered this.
            logger.warning("[sca-intel] invalid TTL/retry knob; using defaults")
            ttl, retry = 24 * 3600, 3600
        bootstrap = os.environ.get(
            "SCA_INTEL_BOOTSTRAP_ON_SCAN", "true").lower() not in ("0", "false", "no")

        # Separate lock from the OSV one ON PURPOSE: they write different volumes,
        # and sharing a lock would let either refresh silently starve the other.
        #
        # Obtained defensively: this method runs ON THE SCAN-SPAWN PATH, so any
        # exception it raises aborts a scan. A partially-constructed manager (the
        # test harnesses build one via __new__) must degrade to "no refresh", not
        # take the scan down with it.
        lock = getattr(self, "_sca_intel_refresh_lock", None)
        if lock is None:
            logger.warning("[sca-intel] refresh skipped: manager has no refresh lock")
            return {"status": "failed", "detail": "refresh lock unavailable"}
        if not lock.acquire(blocking=False):
            return {"status": "skipped", "detail": "refresh already in progress"}

        container = None
        try:
            # supply_chain_common is NOT baked into the analyzer image (only the
            # entrypoint is COPYed), and intel_sync.py lives there, so this mount
            # is mandatory - without it the sidecar dies with ModuleNotFoundError
            # and the intel silently never refreshes. This is the same failure
            # documented for cmd_supply_chain_sync in redamon.sh.
            sc_common_host = join_host_path(
                parent_host_path(self.recon_host_path), "scanners", "supply_chain_common")
            if not self.recon_host_path:
                # Without it the bind source would be a bare relative path and
                # Docker would silently create an EMPTY dir there, which reads as
                # "no module" rather than as an error. Refuse instead.
                return {"status": "failed",
                        "detail": "recon host path unknown; cannot mount supply_chain_common"}

            if not bootstrap and not self._sca_intel_volume_populated():
                return {"status": "skipped",
                        "detail": "cold volume, SCA_INTEL_BOOTSTRAP_ON_SCAN is off"}

            container = self.client.containers.run(
                self.supply_chain_analyzer_image,
                detach=True,
                user="root",  # the volume tree is root-owned; the sync is its only writer
                network_mode="bridge",  # egress to the pinned feed host, nothing else
                # Safe here (unlike the scan spawns) because this container writes
                # a NAMED VOLUME, not a host-owned source bind mount: there is no
                # CAP_DAC_OVERRIDE dependency to strip.
                cap_drop=["ALL"],
                mem_limit=self._tool_container_mem_limit("sca_intel_sync") or "512m",
                pids_limit=256,
                environment={"PYTHONPATH": "/app", "HOME": "/tmp"},
                volumes={
                    self.sca_intel_volume: {"bind": "/sca-intel", "mode": "rw"},
                    sc_common_host: {"bind": "/app/supply_chain_common", "mode": "ro"},
                },
                entrypoint="python3",
                command=["-m", "supply_chain_common.intel_sync",
                         "--out", "/sca-intel",
                         "--ttl-seconds", str(ttl),
                         "--retry-seconds", str(retry)],
            )
            result = container.wait(timeout=self.sca_intel_refresh_timeout)
            code = result.get("StatusCode", -1) if isinstance(result, dict) else -1
            logs = ""
            try:
                logs = container.logs().decode("utf-8", errors="replace").strip()[-500:]
            except Exception:
                pass
            if code == 0:
                did_sync = "__DID_SYNC__" in logs
                detail = logs.replace("__DID_SYNC__", "").strip()
                if did_sync:
                    logger.info(f"[sca-intel] refreshed (ttl={ttl}s): {detail}")
                    return {"status": "synced", "detail": detail}
                logger.debug(f"[sca-intel] no refresh needed (ttl={ttl}s): {detail}")
                return {"status": "skipped", "detail": detail}
            logger.warning(f"[sca-intel] refresh exited {code}: {logs}")
            return {"status": "failed", "detail": logs}
        except Exception as e:
            # Never block a scan on a refresh failure.
            logger.warning(f"[sca-intel] refresh skipped (non-fatal): {e}")
            return {"status": "failed", "detail": str(e)}
        finally:
            self._sca_intel_refresh_lock.release()
            if container is not None:
                try:
                    container.remove(force=True)
                except APIError:
                    pass

    def _sca_intel_volume_populated(self) -> bool:
        """True if the intel volume already holds a manifest.

        Only consulted when bootstrap-on-scan is disabled; a probe failure is
        treated as 'populated' so a Docker hiccup cannot permanently wedge the
        refresh off.
        """
        try:
            self.client.volumes.get(self.sca_intel_volume)
        except NotFound:
            return False
        except Exception:
            return True
        return True

    async def ensure_sca_intel_fresh_async(self) -> dict:
        """Async wrapper: runs the (blocking) refresh off the event loop."""
        return await self._run_blocking(self.ensure_sca_intel_fresh)

    # ------------------------------------------------------------------
    # Supply-Chain scan (L1 "Other Scans") lifecycle - the CLEAN writer.
    # Mirrors the trufflehog lifecycle: a creds-holding container that runs a
    # static OFFLINE osv-scanner pass on an uploaded SBOM/lockfile and writes
    # Package/MalPackageFinding nodes. No Docker socket, no clone, no tarball.
    # ------------------------------------------------------------------
    def _get_supply_chain_container_name(self, project_id: str) -> str:
        safe_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', project_id)
        return f"redamon-supply-chain-{safe_id}"

    async def start_supply_chain(self, project_id: str, user_id: str,
                                 webapp_api_url: str, supply_chain_path: str,
                                 repo_override_url: Optional[str] = None,
                                 repo_override_host: Optional[str] = None,
                                 repo_override_ref: Optional[str] = None,
                                 repo_override_scope: Optional[str] = None,
                                 repo_override_deep: Optional[bool] = None) -> "SupplyChainState":
        current = await self.get_supply_chain_status(project_id)
        if current.status in (SupplyChainStatus.RUNNING, SupplyChainStatus.PAUSED):
            raise ValueError(f"Supply-chain scan already active for project {project_id}")

        await self._admit_scan("supply_chain", project_id, user_id=user_id)

        # Lazy-on-scan: refresh the offline OSV DB if it is stale (TTL-guarded, so
        # this is a ~1s no-op when already fresh). Best-effort - never blocks the
        # scan. The scan container mounts the DB read-only and cannot do this itself.
        await self.ensure_osv_db_fresh_async()
        # Incident intel (B): same TTL-guarded, best-effort contract.
        await self.ensure_sca_intel_fresh_async()

        container_name = self._get_supply_chain_container_name(project_id)
        try:
            old = self.client.containers.get(container_name)
            old.remove(force=True)
        except NotFound:
            pass

        state = SupplyChainState(
            project_id=project_id, status=SupplyChainStatus.STARTING,
            started_at=datetime.now(timezone.utc))
        self.supply_chain_states[project_id] = state

        # Scan Queue Phase 6: per-repo override for an org-batch item. When set, the
        # scan container forces github input mode and scans THIS repo, overriding
        # the project's supply-chain config (see supply_chain_scan/project_settings.
        # _apply_repo_override). Absent for a normal single supply-chain scan.
        repo_override_env: dict[str, str] = {}
        if repo_override_url:
            repo_override_env["SUPPLY_CHAIN_REPO_OVERRIDE_URL"] = str(repo_override_url)
            # Empty = github.com. The container re-validates it against the host
            # the operator configured; the orchestrator only carries it.
            repo_override_env["SUPPLY_CHAIN_REPO_OVERRIDE_HOST"] = str(repo_override_host or "")
            repo_override_env["SUPPLY_CHAIN_REPO_OVERRIDE_REF"] = str(repo_override_ref or "")
            repo_override_env["SUPPLY_CHAIN_REPO_OVERRIDE_SCOPE"] = str(repo_override_scope or "")
            if repo_override_deep is not None:
                repo_override_env["SUPPLY_CHAIN_REPO_OVERRIDE_DEEP"] = "1" if repo_override_deep else "0"

        try:
            try:
                self.client.images.get(self.supply_chain_image)
            except NotFound:
                logger.info(f"Building Supply-Chain image from {supply_chain_path}")
                self.client.images.build(
                    path=parent_host_path(parent_host_path(supply_chain_path)),
                    dockerfile=f"{Path(supply_chain_path).name}/Dockerfile",
                    tag=self.supply_chain_image, rm=True)

            container = self.client.containers.run(
                self.supply_chain_image,
                mem_limit=self._container_mem_limit("supply_chain"),
                pids_limit=self._container_pids_limit(),
                nano_cpus=self._container_cpu_limit(),
                **self._scanner_hardening(drop_caps=False),
                name=container_name,
                detach=True,
                network_mode="host",  # reach Neo4j at localhost:7687 (trufflehog pattern)
                environment={
                    "PROJECT_ID": project_id,
                    "USER_ID": user_id,
                    "WEBAPP_API_URL": webapp_api_url,
                    "PYTHONUNBUFFERED": "1",
                    "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/osv-db",
                    # The scan CLI shells out to `docker` for the analyzer job;
                    # it must go through the broker, not a raw socket.
                    "DOCKER_HOST": "unix:///var/run/broker/docker.sock",
                    # supply_chain_common as the DAEMON sees it, so the analyzer
                    # can bind-mount it read-only.
                    "SUPPLY_CHAIN_COMMON_HOST_PATH": sibling_host_path(supply_chain_path, "supply_chain_common"),
                    # Per-project subdir inside the shared uploads volume.
                    "SUPPLY_CHAIN_UPLOADS_DIR": f"/data/supply-chain-uploads/{project_id}",
                    "NEO4J_URI": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                    "NEO4J_USER": os.environ.get("NEO4J_USER", "neo4j"),
                    "NEO4J_PASSWORD": os.environ.get("NEO4J_PASSWORD", ""),
                    **self._scanner_env(),
                    # Operator overrides for the dirty analyzer this scan spawns.
                    **self._analyzer_env(),
                    # Per-repo override for an org-batch item (Phase 6); empty otherwise.
                    **repo_override_env,
                },
                volumes={
                    # Shared scratch the analyzer_dispatch job.json is written to,
                    # then bind-mounted by the dirty analyzer. Recon, partial recon
                    # and AI attack all mount this; supply chain omitted it, so the
                    # analyzer read a path the scan container never wrote (L1
                    # GuardDog deep analysis broken). See Phase 0.1.
                    "/tmp/redamon": {"bind": "/tmp/redamon", "mode": "rw"},
                    f"{supply_chain_path}/output": {"bind": "/app/supply_chain_scan/output", "mode": "rw"},
                    f"{supply_chain_path}": {"bind": "/app/supply_chain_scan", "mode": "rw"},
                    **self._graph_db_mount(sibling_host_path(parent_host_path(supply_chain_path), "graph_db"), baked_into_image=False),
                    sibling_host_path(supply_chain_path, "supply_chain_common"): {"bind": "/app/supply_chain_common", "mode": "ro"},
                    # Deep analysis (GuardDog) dispatches a job to the DIRTY
                    # analyzer. Same posture the recon container already has:
                    # the BROKER socket, never the raw docker socket. The broker
                    # allowlists image + mounts, so this is a NARROWER privilege
                    # than an orchestrator API key would be, and this container
                    # already holds the Neo4j creds exactly like recon does.
                    BROKER_SOCKET_VOLUME: {"bind": "/var/run/broker", "mode": "rw"},
                    self.supply_chain_uploads_volume: {"bind": "/data/supply-chain-uploads", "mode": "ro"},
                    self.supply_chain_osv_db_volume: {"bind": "/osv-db", "mode": "ro"},
                    # Incident intel for B (L1 finding enrichment). Read-only.
                    self.sca_intel_volume: {"bind": "/sca-intel", "mode": "ro"},
                },
                command="python supply_chain_scan/main.py",
            )
            state.container_id = container.id
            state.status = SupplyChainStatus.RUNNING
            logger.info(f"Started Supply-Chain container {container.id} for project {project_id}")
        except Exception as e:
            state.status = SupplyChainStatus.ERROR
            state.error = str(e)
            logger.error(f"Failed to start Supply-Chain scan for {project_id}: {e}")

        return state

    async def get_supply_chain_status(self, project_id: str) -> "SupplyChainState":
        return await self._run_blocking(self._get_supply_chain_status_sync, project_id)

    def _get_supply_chain_status_sync(self, project_id: str) -> "SupplyChainState":
        if project_id in self.supply_chain_states:
            state = self.supply_chain_states[project_id]
            if state.container_id:
                try:
                    container = self.client.containers.get(state.container_id)
                    if container.status == "paused":
                        state.status = SupplyChainStatus.PAUSED
                    elif container.status != "running":
                        exit_code = container.attrs.get("State", {}).get("ExitCode", -1)
                        if exit_code == 0:
                            state.status = SupplyChainStatus.COMPLETED
                        else:
                            state.status = SupplyChainStatus.ERROR
                            state.error = f"Container exited with code {exit_code}"
                        state.completed_at = datetime.now(timezone.utc)
                        try:
                            container.remove()
                        except Exception as e:
                            logger.warning(f"Failed to auto-remove Supply-Chain container: {e}")
                except NotFound:
                    if state.status not in (SupplyChainStatus.COMPLETED, SupplyChainStatus.ERROR):
                        state.status = SupplyChainStatus.ERROR
                        state.error = "Container not found"
                except APIError as e:
                    logger.warning(f"Docker API error checking Supply-Chain container for {project_id}: {e}")
            return state
        return SupplyChainState(project_id=project_id, status=SupplyChainStatus.IDLE)

    async def pause_supply_chain(self, project_id: str) -> "SupplyChainState":
        state = await self.get_supply_chain_status(project_id)
        if state.status != SupplyChainStatus.RUNNING or not state.container_id:
            return state
        try:
            self.client.containers.get(state.container_id).pause()
            state.status = SupplyChainStatus.PAUSED
            self.supply_chain_states[project_id] = state
        except (NotFound, APIError) as e:
            state.status = SupplyChainStatus.ERROR
            state.error = f"Failed to pause: {e}"
        return state

    async def resume_supply_chain(self, project_id: str) -> "SupplyChainState":
        state = await self.get_supply_chain_status(project_id)
        if state.status != SupplyChainStatus.PAUSED or not state.container_id:
            return state
        try:
            self.client.containers.get(state.container_id).unpause()
            state.status = SupplyChainStatus.RUNNING
            self.supply_chain_states[project_id] = state
        except (NotFound, APIError) as e:
            state.status = SupplyChainStatus.ERROR
            state.error = f"Failed to resume: {e}"
        return state

    async def stop_supply_chain(self, project_id: str, timeout: int = 10) -> "SupplyChainState":
        state = await self.get_supply_chain_status(project_id)
        if state.status not in (SupplyChainStatus.RUNNING, SupplyChainStatus.PAUSED):
            return state
        state.status = SupplyChainStatus.STOPPING
        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                if container.status == "paused":
                    container.unpause()
                container.stop(timeout=timeout)
                container.remove()
            except NotFound:
                pass
            except Exception as e:
                logger.warning(f"Error stopping Supply-Chain container: {e}")
        state.status = SupplyChainStatus.IDLE
        state.completed_at = datetime.now(timezone.utc)
        # L1-2: DROP the state (like trufflehog) instead of leaving a stale entry
        # with a dead container_id. Otherwise the very next status poll does
        # containers.get(<gone>) -> NotFound and, since IDLE is not terminal,
        # flips a clean stop to ERROR "Container not found" permanently.
        self.supply_chain_states.pop(project_id, None)
        return state

    async def stream_supply_chain_logs(self, project_id: str) -> AsyncGenerator["SupplyChainLogEvent", None]:
        # L1-4: the blocking container.logs(follow=True) iterator must run in the
        # log-stream executor and bridge via an asyncio.Queue, or it blocks the
        # single event loop between log lines (freezing every other request -
        # the exact hazard the dual-threadpool design prevents). Mirrors
        # stream_trufflehog_logs / stream_logs.
        state = await self.get_supply_chain_status(project_id)
        if not state.container_id:
            return
        container_id = state.container_id
        loop = asyncio.get_event_loop()
        queue: asyncio.Queue = asyncio.Queue()
        _SENTINEL = object()

        def _reader():
            try:
                container = self.client.containers.get(container_id)
                for raw in container.logs(stream=True, follow=True):
                    try:
                        line = raw.decode("utf-8", errors="replace").rstrip("\n")
                    except Exception:
                        continue
                    if line:
                        loop.call_soon_threadsafe(queue.put_nowait, line)
            except (NotFound, APIError):
                pass
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(f"[supply-chain] log reader error: {exc}")
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, _SENTINEL)

        self._log_stream_executor.submit(_reader)
        while True:
            item = await queue.get()
            if item is _SENTINEL:
                break
            yield SupplyChainLogEvent(log=item, timestamp=datetime.now(timezone.utc))

    def get_supply_chain_running_count(self) -> int:
        return sum(1 for st in self.supply_chain_states.values()
                   if st.status in (SupplyChainStatus.RUNNING, SupplyChainStatus.STARTING))

    def _trufflehog_egress_check(self, source: str, config: dict) -> None:
        """Refuse a start whose target resolves to an internal address (12.4).

        Two layers, both required. This one runs orchestrator-side and fails the
        request with a 400; the second is the isolated bridge the container runs
        on, which means a TOCTOU re-resolve or an HTTP redirect to an internal
        host at scan time still has no route to the host's loopback services.

        Deny on the RESOLVED IP, not the name: `es.acme.io` pointing at
        `169.254.169.254` or `127.0.0.1:7687` reads as perfectly in-scope. Fails
        closed — unresolvable is a refusal, not a pass.
        """
        if os.environ.get("TRUFFLEHOG_EGRESS_GUARD", "").strip().lower() in ("0", "false", "off"):
            logger.warning("[trufflehog] egress guard DISABLED by TRUFFLEHOG_EGRESS_GUARD")
            return
        extra_blocked = [
            ip for ip in (os.environ.get("CAPTURE_BLOCKED_IPS", "") or "").split(",") if ip.strip()
        ]
        for host in th_sources.egress_hosts(source, config):
            allowed, _pinned, reason = classify_host(host, extra_blocked)
            if not allowed:
                raise ValueError(
                    f"Target '{host}' is not allowed ({reason}). TruffleHog sources may "
                    f"not be pointed at RedAmon-internal or private addresses."
                )

    def _trufflehog_scope_check(self, project_id: str, source: str, config: dict) -> None:
        """Refuse a target outside the project's authorised scope / ROE (12.5).

        Composes with the egress guard rather than replacing it: for a network
        source the two both apply, and for a name-only target (a docker image
        ref, a GitHub org, an HF model) this is the only check there is. The hook
        is injected by api.py, which owns the scope loader; with no checker wired
        this is a no-op, matching the other scan types' behaviour when a project
        declares no scope.
        """
        checker = getattr(self, "trufflehog_scope_checker", None)
        if checker is None:
            return
        target = th_sources.describe_target(source, config)
        if not target:
            return
        allowed, reason = checker(project_id, source, target)
        if not allowed:
            raise ValueError(f"Target '{target}' is outside the project scope ({reason})")

    def _trufflehog_tmpfs(self) -> dict:
        """Writable scratch for a scan container whose root filesystem is read-only.

        TruffleHog needs somewhere to clone into and extract archives to, and a
        tmpfs gives it that without a writable layer that could persist into a
        later run.

        The uid/gid/mode on the HOME entry are load-bearing, not tidiness.
        Docker mounts a tmpfs root-owned 0755 unless told otherwise (only /tmp
        gets the 1777 default), and this mount SHADOWS the image's
        /home/trufflehog, which `useradd --create-home` had correctly given to
        the scan uid. Without them the scan user cannot write its own home, and
        `github_experimental` dies on "failed to create .trufflehog folder in
        user's home directory" - object discovery caches repository objects
        there, which is also what its --delete-cached-data flag exists to clean
        up afterwards. No other source touches $HOME, so the missing options
        broke exactly one source and read like a scanner bug rather than a
        mount bug.
        """
        home = f"/home/{TRUFFLEHOG_CONTAINER_USER}"
        return {
            "/tmp": "size=2g,exec",
            home: (f"size=256m,uid={TRUFFLEHOG_CONTAINER_UID},"
                   f"gid={TRUFFLEHOG_CONTAINER_UID},mode=0700"),
        }

    async def start_trufflehog(
        self,
        project_id: str,
        user_id: str,
        trufflehog_path: str,
        source: str,
        config: Optional[dict] = None,
        common: Optional[dict] = None,
        secrets: Optional[dict] = None,
    ) -> TrufflehogState:
        """Start ONE TruffleHog source for a project.

        Parallelism rule (C3): a second run of the SAME source is refused; any
        number of distinct sources run at once, gated only by the fleet-wide
        memory governor and the per-user concurrency ceiling. There is
        deliberately no trufflehog-specific parallelism cap.

        The container is the DIRTY half of the split (12.3): isolated bridge,
        cap_drop=ALL, read-only root, non-root, ONE source credential in env, and
        no Neo4j credentials or scanner API key anywhere near it. Graph ingest
        happens later, in `_ingest_trufflehog`, once this process is gone.
        """
        if th_sources is None:
            raise ValueError(
                f"TruffleHog source registry not available: {_TRUFFLEHOG_REGISTRY_ERROR}. "
                "Is ./scanners/trufflehog_scan mounted into the orchestrator?"
            )

        config = dict(config or {})
        common = dict(common or {})
        secrets = secrets or {}

        # --- gates, all before any state or reservation exists so a refusal is
        # a clean 400 that leaves nothing behind -------------------------------
        try:
            src = th_sources.get_source(source)
        except KeyError as e:
            raise ValueError(str(e))
        source = src.id

        errors = th_sources.validate_config(source, config)
        if errors:
            raise ValueError("; ".join(errors))

        missing = th_sources.missing_credentials(source, config, secrets)
        if missing:
            # Re-checked here and not only in the UI: a queued job can reach
            # dispatch long after the operator cleared the key.
            names = ", ".join(c.label for c in missing)
            raise ValueError(
                f"{src.label} requires {names}. Set it in Global Settings > API Keys > TruffleHog."
            )

        self._trufflehog_egress_check(source, config)
        self._trufflehog_scope_check(project_id, source, config)

        # Refresh from Docker first, so an orphan container from a crashed
        # orchestrator is seen (this awaits, so it cannot be the claim itself).
        current_state = await self.get_trufflehog_status(project_id, source)

        # --- CLAIM THE RUN SLOT SYNCHRONOUSLY -------------------------------
        # No `await` between the check and the assignment, so the whole block is
        # atomic with respect to the event loop. With an await in between, two
        # concurrent starts for the SAME source (a double-clicked button, or the
        # queue dispatcher racing a manual start) would both pass the check, and
        # the second would force-remove the first's container while the first's
        # state object — and therefore its reservation key — was overwritten.
        target = th_sources.describe_target(source, config)
        runs = self.trufflehog_states.setdefault(project_id, {})
        claimed = runs.get(source)
        blocking = claimed.status if claimed else current_state.status
        if blocking in (TrufflehogStatus.RUNNING, TrufflehogStatus.STARTING,
                        TrufflehogStatus.PAUSED):
            raise ValueError(
                f"A {src.label} scan is already running for project {project_id}"
            )
        state = TrufflehogState(
            project_id=project_id,
            user_id=user_id,
            source=source,
            run_id=source,
            target=target,
            status=TrufflehogStatus.STARTING,
            started_at=datetime.now(timezone.utc),
        )
        runs[source] = state
        # --- end of the atomic region ---------------------------------------

        try:
            # Memory admission on the source-qualified kind; the reconcile key in
            # _active_scan_keys is built the same way or the reaper frees this.
            await self._admit_scan(self._trufflehog_kind(source), project_id, source,
                                   user_id=user_id)
        except Exception:
            # Release the slot: a rejected admission must not leave a phantom
            # STARTING run that blocks every later start of this source.
            self._drop_trufflehog_run(project_id, source, state)
            raise

        container_name = self._get_trufflehog_container_name(project_id, source)
        try:
            self.client.containers.get(container_name).remove(force=True)
            logger.info(f"Removed old TruffleHog container {container_name}")
        except NotFound:
            pass

        # Resolved once, and kept for the error path: `state.error` is returned
        # by the status API and rendered in the UI, and these values are NOT in
        # the orchestrator's own environment, so redacting against os.environ
        # alone would not catch a token echoed back in an exception message.
        credential_env = self._trufflehog_credential_env(src, secrets)

        try:
            # NOTE: the graph is deliberately NOT cleared here. The scoped clear
            # lives at the head of update_graph_from_trufflehog, so the previous
            # run's findings survive until the new ones are ready to replace
            # them. Clearing up front meant a spawn that failed (missing image,
            # daemon error) destroyed the last good results and left nothing.
            run_dir = self._trufflehog_run_dir(project_id, source)
            run_dir.mkdir(parents=True, exist_ok=True)

            # Remove the PREVIOUS run's artifact before this one starts. The
            # container overwrites it within a second of starting, but a run that
            # never gets that far (image missing, OOM-kill at startup) would
            # otherwise leave the old file in place — and the terminal-state
            # ingest below would publish it as if this run had produced it,
            # attributing one target's findings to a scan of another.
            stale = run_dir / "out.json"
            try:
                stale.unlink()
            except FileNotFoundError:
                pass
            except OSError as e:
                logger.warning(f"[trufflehog] could not clear the previous {source} artifact: {e}")
            job = {
                "project_id": project_id,
                "user_id": user_id,
                "source": source,
                "run_id": source,
                "config": config,
                "common": common,
                "run_dir": "/work",
                # Into the run dir, NOT the shared output dir. The container
                # runs as a non-root uid with cap_drop=ALL, so it cannot write a
                # host-owned directory; and giving a container that parses
                # attacker-controlled bytes rw access to a dir the webapp serves
                # is a bad trade for saving one copy. _publish_trufflehog_output
                # moves the artifact once the run is over.
                "output_file": "/work/out.json",
            }
            (run_dir / "job.json").write_text(json.dumps(job))
            # World-readable: the container runs as a non-root uid that does not
            # exist on the host, so a 0600 job file would be unreadable to it.
            os.chmod(run_dir / "job.json", 0o644)
            try:
                os.chmod(run_dir, 0o777)
            except OSError:
                pass

            try:
                self.client.images.get(self.trufflehog_image)
            except NotFound:
                logger.info(f"Building TruffleHog image from {trufflehog_path}")
                self.client.images.build(
                    path=parent_host_path(parent_host_path(trufflehog_path)),
                    dockerfile=f"{Path(trufflehog_path).name}/Dockerfile",
                    tag=self.trufflehog_image,
                    rm=True,
                )

            self._ensure_trufflehog_network()

            scan_target_mounts = self._trufflehog_scan_root_mounts(source, config)
            git_config_mount = self._trufflehog_git_config_mount(run_dir, scan_target_mounts)

            container = self.client.containers.run(
                self.trufflehog_image,
                name=container_name,
                detach=True,
                network=self.trufflehog_network,
                cap_drop=["ALL"],
                read_only=True,
                tmpfs=self._trufflehog_tmpfs(),
                mem_limit=self._container_mem_limit(self._trufflehog_kind(source)),
                pids_limit=self._container_pids_limit(),
                nano_cpus=self._container_cpu_limit(),
                environment={
                    "PYTHONUNBUFFERED": "1",
                    "TRUFFLEHOG_JOB": "/work/job.json",
                    # ONLY this source's credentials. No NEO4J_*, no scanner API
                    # key, no webapp URL: a full RCE in here finds nothing but
                    # the key the operator already pointed at the target.
                    **credential_env,
                },
                volumes={
                    str(run_dir): {"bind": "/work", "mode": "rw"},
                    # Source read-only, so a compromised scan cannot rewrite the
                    # scanner and persist into every future run.
                    f"{trufflehog_path}": {"bind": "/app/trufflehog_scan", "mode": "ro"},
                    **scan_target_mounts,
                    **git_config_mount,
                },
                command="python trufflehog_scan/main.py",
            )

            state.container_id = container.id
            state.status = TrufflehogStatus.RUNNING
            # Auditability (12.9): who scanned WHAT with WHICH key. The credential
            # FIELD NAMES only — never a value — so an operator can reconstruct a
            # run from the logs without the log becoming a secret store.
            used_keys = sorted(c.settings_key for c in src.credentials
                               if str(secrets.get(c.settings_key) or "").strip())
            logger.info(
                f"Started TruffleHog {source} container {container.id} for project {project_id} "
                f"(user: {user_id}, target: {target}, "
                f"credentials: {', '.join(used_keys) if used_keys else 'none'})"
            )

        except Exception as e:
            state.status = TrufflehogStatus.ERROR
            state.error = th_sources.redact(str(e), {**os.environ, **credential_env})
            logger.error(f"Failed to start TruffleHog {source} for {project_id}: {e}")

        return state

    def _trufflehog_credential_env(self, src, secrets: dict) -> dict:
        """The env vars carrying this ONE source's credentials.

        Named exactly what TruffleHog documents for each flag ($GITHUB_TOKEN,
        $ELASTICSEARCH_API_KEY, ...), so the binary reads them itself and no
        token ever appears in the container's argv or process table.
        """
        env: dict[str, str] = {}
        for cred in src.credentials:
            value = str(secrets.get(cred.settings_key) or "").strip()
            if value:
                env[cred.env] = value
        return env

    def _trufflehog_scan_root_mounts(self, source: str, config: dict) -> dict:
        """Read-only mounts for the `filesystem` source's allowlisted roots.

        The scan root is a server-resolved allowlist entry, never an
        operator-typed host path: a free-text path plus a scan container is a
        file-disclosure primitive. A root with no configured host path is simply
        not mounted, and the scan then finds an empty directory rather than
        silently reading something else.
        """
        if source not in th_sources.SCAN_TARGET_DIRS:
            return {}
        host_path = self.trufflehog_scan_targets
        if not host_path:
            return {}
        # The whole tree, read-only, at one fixed point. Read-only matters: it is
        # the difference between a scan reading a fixture and a compromised scan
        # rewriting the fixture every later run will read.
        return {host_path: {"bind": th_sources.SCAN_TARGETS_MOUNT, "mode": "ro"}}

    GITHUB_HUNT_OUTPUT_DIR = Path("/app/github_secret_hunt/output")

    def _ingest_github_hunt(self, state: GithubHuntState) -> None:
        """Write a finished hunt's findings to the graph if the container did not.

        A BACKSTOP, not the primary path. The hunt writes its own graph update
        at the end of main.py, which covers a clean finish and (since the SIGTERM
        handler) a graceful stop. What it cannot cover is the container dying
        without running its exit path at all — SIGKILL after the stop grace
        period, an OOM kill, a hard crash. That happened for real: a stack
        restart killed a 58-minute scan and 799 findings produced zero nodes,
        because the only writer was inside the process being killed.

        TruffleHog already works this way round (`_ingest_trufflehog`); this puts
        the hunt behind the same safety net without taking away its own write.

        Skipped when the graph already holds THIS run, compared on the artifact's
        `scan_end_time`. Re-ingesting would be correct but not free: the write
        begins by clearing the previous subtree, so a needless repeat is a window
        where the data is briefly gone.

        Never raises: a failed ingest must not flip a finished scan into an error.
        """
        if state.ingested:
            return
        if state.ingest_attempts >= MAX_GITHUB_HUNT_INGEST_ATTEMPTS:
            return
        state.ingest_attempts += 1
        if not state.user_id:
            # An empty tenant key writes nodes no scoped read can see and no
            # scoped clear can remove. Refuse before doing any work.
            logger.error(
                f"[github-hunt] refusing to ingest {state.project_id}: "
                "the run carries no user_id")
            return

        out_path = self.GITHUB_HUNT_OUTPUT_DIR / f"github_hunt_{state.project_id}.json"
        if not out_path.exists():
            return
        try:
            data = json.loads(out_path.read_text())
        except (OSError, ValueError) as e:
            logger.warning(f"[github-hunt] unreadable findings for {state.project_id}: {e}")
            return
        if not data.get("findings"):
            state.ingested = True
            return

        try:
            from graph_db import Neo4jClient
        except ImportError:
            logger.warning("[github-hunt] graph_db unavailable; skipping ingest")
            return
        # Same caveat as the TruffleHog ingest: NEO4J_URI in this service's
        # environment is the value forwarded to HOST-network scan containers, so
        # it says localhost and reaches nothing from here.
        neo4j_uri = (os.environ.get("ORCHESTRATOR_NEO4J_URI", "").strip()
                     or "bolt://neo4j:7687")
        try:
            with Neo4jClient(uri=neo4j_uri) as client:
                if not client.verify_connection():
                    logger.warning("[github-hunt] Neo4j unreachable; skipping ingest")
                    return
                with client.driver.session() as session:
                    row = session.run(
                        """
                        MATCH (gh:GithubHunt {user_id: $uid, project_id: $pid})
                        RETURN gh.scan_end_time AS ended
                        """,
                        uid=state.user_id, pid=state.project_id).single()
                if row and row["ended"] and row["ended"] == data.get("scan_end_time"):
                    state.ingested = True
                    logger.info(
                        f"[github-hunt] {state.project_id} already in the graph "
                        f"(the container wrote it); nothing to do")
                    return

                stats = client.update_graph_from_github_hunt(
                    data, state.user_id, state.project_id,
                )
            state.ingested = True
            logger.info(
                f"[github-hunt] backstop ingest for {state.project_id} "
                f"({len(data.get('findings') or [])} findings): {stats}")
        except Exception as e:
            if state.ingest_attempts >= MAX_GITHUB_HUNT_INGEST_ATTEMPTS:
                logger.error(
                    f"[github-hunt] ingest failed for {state.project_id} after "
                    f"{state.ingest_attempts} attempts, giving up: {e}. "
                    f"Findings remain at {out_path}; re-run the hunt to retry.")
            else:
                logger.warning(
                    f"[github-hunt] ingest attempt {state.ingest_attempts} failed "
                    f"for {state.project_id}: {e}")

    def _ingest_trufflehog(self, state: TrufflehogState) -> None:
        """Read a finished run's findings JSON and write it to the graph.

        The clean half of the dirty/clean split: this runs in the orchestrator,
        which holds the Neo4j credentials the scan container deliberately did
        not. Every string in the file is target-controlled, so the graph write
        stays fully parameterised (never string-formatted into Cypher).

        Idempotent and never raises: a failed ingest must not flip a completed
        scan into an error state, and the status sweep calls this repeatedly.
        """
        if state.ingested or not state.source:
            return
        if state.ingest_attempts >= MAX_TRUFFLEHOG_INGEST_ATTEMPTS:
            return
        state.ingest_attempts += 1
        if not state.user_id:
            # Writing with an empty tenant key produces nodes no scoped read can
            # ever see and no scoped clear can ever remove. Refuse before doing
            # any work, so a tenant-less run cannot even publish an artifact.
            logger.error(
                f"[trufflehog] refusing to ingest {state.source} for {state.project_id}: "
                "the run carries no user_id")
            return
        out_path = self._publish_trufflehog_output(state.project_id, state.source)
        if out_path is None or not out_path.exists():
            return
        try:
            data = json.loads(out_path.read_text())
        except (OSError, ValueError) as e:
            logger.warning(f"[trufflehog] unreadable findings for {state.source}: {e}")
            return

        try:
            from graph_db import Neo4jClient
        except ImportError:
            logger.warning("[trufflehog] graph_db unavailable; skipping ingest")
            return
        # NEO4J_URI in this service's environment is NOT the orchestrator's own
        # connection: it is forwarded verbatim to spawned recon containers, which
        # run on the HOST network and so correctly say localhost. This process is
        # on the compose network, where the same string reaches nothing.
        neo4j_uri = (os.environ.get("ORCHESTRATOR_NEO4J_URI", "").strip()
                     or "bolt://neo4j:7687")
        try:
            with Neo4jClient(uri=neo4j_uri) as client:
                if not client.verify_connection():
                    logger.warning("[trufflehog] Neo4j unreachable; skipping ingest")
                    return
                stats = client.update_graph_from_trufflehog(
                    data, state.user_id, state.project_id,
                )
            state.ingested = True
            state.findings_count = len(data.get("findings") or [])
            logger.info(
                f"[trufflehog] ingested {state.findings_count} {state.source} findings "
                f"for {state.project_id}: {stats}"
            )
        except Exception as e:
            if state.ingest_attempts >= MAX_TRUFFLEHOG_INGEST_ATTEMPTS:
                # Say so once, loudly, naming the artifact — an operator can
                # re-run the source, and the findings are still on disk.
                logger.error(
                    f"[trufflehog] ingest failed for {state.project_id}/{state.source} "
                    f"after {state.ingest_attempts} attempts, giving up: {e}. "
                    f"Findings remain at {self._trufflehog_output_path(state.project_id, state.source)}; "
                    f"re-run the source to retry.")
            else:
                logger.warning(
                    f"[trufflehog] ingest attempt {state.ingest_attempts} failed for "
                    f"{state.source}: {e}")

    async def stop_trufflehog(self, project_id: str, source: str, timeout: int = 10) -> TrufflehogState:
        """Stop ONE source's run. Other sources in the same project keep going."""
        state = await self.get_trufflehog_status(project_id, source)

        if state.status in (TrufflehogStatus.RUNNING, TrufflehogStatus.STARTING,
                            TrufflehogStatus.PAUSED):
            state.status = TrufflehogStatus.STOPPING
            if state.container_id:
                def _kill(cid: str):
                    container = self.client.containers.get(cid)
                    if container.status == "paused":
                        container.unpause()
                    container.stop(timeout=timeout)
                    container.remove()
                try:
                    await asyncio.to_thread(_kill, state.container_id)
                    state.status = TrufflehogStatus.IDLE
                    state.completed_at = datetime.now(timezone.utc)
                    logger.info(f"Stopped TruffleHog {source} container for project {project_id}")
                except NotFound:
                    state.status = TrufflehogStatus.IDLE
                except Exception as e:
                    state.status = TrufflehogStatus.ERROR
                    state.error = f"Failed to stop: {e}"

        # Ingest whatever the run wrote before it was stopped: a partial result
        # is still a result, and the incremental save means the file is valid.
        await asyncio.to_thread(self._ingest_trufflehog, state)

        self._drop_trufflehog_run(project_id, source, state)

        return state

    async def stop_all_trufflehog(self, project_id: str, timeout: int = 10) -> list[TrufflehogState]:
        """Stop every source's run for a project.

        Project delete and project reset call this. A project-keyed single stop
        would leave every source but one running, which is exactly the orphan the
        run-keying introduces if nothing enumerates the nested dict.
        """
        runs = list(self.trufflehog_states.get(project_id, {}).keys())
        out: list[TrufflehogState] = []
        for source in runs:
            try:
                out.append(await self.stop_trufflehog(project_id, source, timeout=timeout))
            except Exception as e:
                logger.error(f"Error stopping TruffleHog {project_id}/{source}: {e}")
        return out
    def _parse_trufflehog_log_line(self, line: str, current_phase: Optional[str], current_phase_num: Optional[int], timestamp: Optional[datetime] = None) -> TrufflehogLogEvent:
        """Parse a TruffleHog log line and detect phase changes"""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        phase = current_phase
        phase_num = current_phase_num
        is_phase_start = False
        level = "info"

        # Strip ANSI escape codes
        line = ANSI_ESCAPE.sub('', line)

        # Detect log level
        if "[!]" in line or "[!!!]" in line:
            level = "error"
        elif "[+]" in line or "[✓]" in line:
            level = "success"
        elif "[*]" in line:
            level = "action"
        elif "[~]" in line:
            level = "warning"

        # Detect phase changes
        for pattern, phase_name, num in TRUFFLEHOG_PHASE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                if phase_name != current_phase:
                    phase = phase_name
                    phase_num = num
                    is_phase_start = True
                break

        return TrufflehogLogEvent(
            log=line.rstrip(),
            timestamp=timestamp,
            phase=phase,
            phase_number=phase_num,
            is_phase_start=is_phase_start,
            level=level,
        )

    async def stream_trufflehog_logs(self, project_id: str, source: str) -> AsyncGenerator[TrufflehogLogEvent, None]:
        """Stream logs from ONE source's TruffleHog container.

        Every line is redacted before it leaves the orchestrator: the binary can
        echo a composed clone URL carrying a token, and the log stream is a
        user-facing SSE surface.
        """
        state = await self.get_trufflehog_status(project_id, source)

        if not state.container_id:
            yield TrufflehogLogEvent(
                log=f"No TruffleHog {source} container found for this project",
                timestamp=datetime.now(timezone.utc),
                level="error",
            )
            return

        current_phase: Optional[str] = None
        current_phase_num: Optional[int] = None

        try:
            container = self.client.containers.get(state.container_id)

            log_queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue()
            loop = asyncio.get_running_loop()

            def read_logs():
                try:
                    # Throttle the per-line liveness reload() below: next allowed
                    # Docker status poll, in monotonic seconds (list = mutable box).
                    _log_status_gate = [time.monotonic() + 30.0]
                    for line in container.logs(stream=True, follow=True, timestamps=True):
                        asyncio.run_coroutine_threadsafe(
                            log_queue.put(line),
                            loop
                        ).result(timeout=5)
                        # Liveness check, THROTTLED to once per ~30s. Previously
                        # reload() ran on EVERY log line -- a Docker round-trip per
                        # line. A scan emitting 100k+ lines flooded the daemon,
                        # slowing every request and starving the event loop (the
                        # parallel-scan freeze). The stream generator ending already
                        # stops the loop when a container exits, so a 30s liveness
                        # poll loses nothing but the wasted daemon load.
                        if time.monotonic() >= _log_status_gate[0]:
                            _log_status_gate[0] = time.monotonic() + 30.0
                            try:
                                container.reload()
                                if container.status not in ("running", "paused"):
                                    break
                            except Exception:
                                break
                except Exception as e:
                    logger.error(f"Error in TruffleHog log reader thread: {e}")
                finally:
                    try:
                        asyncio.run_coroutine_threadsafe(
                            log_queue.put(None),
                            loop
                        ).result(timeout=5)
                    except Exception:
                        pass

            loop.run_in_executor(self._log_stream_executor, read_logs)

            while True:
                try:
                    line = await asyncio.wait_for(log_queue.get(), timeout=1.0)
                    if line is None:
                        break

                    decoded_line = line.decode("utf-8", errors="replace").rstrip()
                    if decoded_line:
                        # Parse Docker timestamp prefix
                        docker_ts = None
                        log_text = decoded_line
                        if len(decoded_line) > 30 and decoded_line[4] == '-' and decoded_line[10] == 'T':
                            space_idx = decoded_line.find(' ')
                            if space_idx > 0:
                                ts_str = decoded_line[:space_idx]
                                try:
                                    ts_clean = ts_str.replace('Z', '+00:00')
                                    dot_idx = ts_clean.find('.')
                                    plus_idx = ts_clean.find('+', dot_idx) if dot_idx > 0 else -1
                                    if dot_idx > 0 and plus_idx > 0:
                                        frac = ts_clean[dot_idx + 1:plus_idx][:6]
                                        ts_clean = ts_clean[:dot_idx + 1] + frac + ts_clean[plus_idx:]
                                    docker_ts = datetime.fromisoformat(ts_clean)
                                    log_text = decoded_line[space_idx + 1:]
                                except (ValueError, OverflowError):
                                    pass

                        if th_sources is not None:
                            log_text = th_sources.redact(log_text, dict(os.environ))
                        event = self._parse_trufflehog_log_line(log_text, current_phase, current_phase_num, timestamp=docker_ts)

                        if event.is_phase_start:
                            current_phase = event.phase
                            current_phase_num = event.phase_number

                            run = self.trufflehog_states.get(project_id, {}).get(source)
                            if run is not None:
                                run.current_phase = current_phase
                                run.phase_number = current_phase_num

                        yield event

                except asyncio.TimeoutError:
                    try:
                        container.reload()
                        if container.status not in ("running", "paused"):
                            break
                    except Exception:
                        break

        except (NotFound, APIError):
            yield TrufflehogLogEvent(
                log="TruffleHog container stopped",
                timestamp=datetime.now(timezone.utc),
                level="info",
            )
        except Exception as e:
            yield TrufflehogLogEvent(
                log=f"Error streaming TruffleHog logs: {e}",
                timestamp=datetime.now(timezone.utc),
                level="error",
            )

    def get_trufflehog_running_count(self) -> int:
        """Count of running TruffleHog runs across every source.

        Feeds /health and the admission accounting the dispatcher reads. Walking
        the outer dict only would count PROJECTS, so three parallel sources would
        report as one and the queue would over-admit.
        """
        return sum(
            1
            for runs in self.trufflehog_states.values()
            for st in runs.values()
            if st.status in (TrufflehogStatus.RUNNING, TrufflehogStatus.STARTING)
        )

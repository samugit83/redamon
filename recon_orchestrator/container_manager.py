"""
Docker container lifecycle management for recon processes
"""
import asyncio
import functools
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import AsyncGenerator, Optional

import docker
from docker.errors import NotFound, APIError
from docker.models.containers import Container

import resource_governor as rg
from admission_ledger import ReservationLedger, AdmissionError

from models import (
    ReconState, ReconStatus, ReconLogEvent,
    GvmState, GvmStatus, GvmLogEvent,
    GithubHuntState, GithubHuntStatus, GithubHuntLogEvent,
    TrufflehogState, TrufflehogStatus, TrufflehogLogEvent,
    PartialReconState, PartialReconStatus,
    AiAttackSurfaceState, AiAttackSurfaceStatus, AiAttackSurfaceLogEvent,
)

logger = logging.getLogger(__name__)

# ANSI escape code pattern for stripping terminal colors from logs
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*m|\033\[[0-9;]*m')


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

# TruffleHog Secret Scanner phase patterns to detect from logs
TRUFFLEHOG_PHASE_PATTERNS = [
    (r"TruffleHog Secret Scanner|Loading.*settings|Initializing TruffleHog", "Loading Settings", 1),
    (r"Scanning repositor|Scanning organization|Running:.*trufflehog", "Scanning Repositories", 2),
    (r"SCAN SUMMARY|Final results saved|Scan complete", "Complete", 3),
]

# AI Attack Surface phase patterns. Match ONLY the explicit [Phase N] markers
# that ai_attack_surface_scan/main.py prints (numbered in execution order).
# Bare keywords would false-match — e.g. "Attack" appears in the banner line
# "AI Attack Surface scan", which would bounce the phase back to 3.
AI_ATTACK_SURFACE_PHASE_PATTERNS = [
    (r"\[Phase 1\]", "Safety / bounds", 1),
    (r"\[Phase 2\]", "Target loading", 2),
    (r"\[Phase 3\]", "Attack", 3),
    (r"\[Phase 4\]", "Findings", 4),
]


class ContainerManager:
    """Manages Docker containers for recon, GVM scan, GitHub hunt, and TruffleHog processes"""

    def __init__(self, recon_image: str = "redamon-recon:latest", gvm_image: str = "redamon-vuln-scanner:latest", github_hunt_image: str = "redamon-github-hunter:latest", trufflehog_image: str = "redamon-trufflehog:latest", ai_attack_image: str = "redamon-ai-attack-surface:latest"):
        self.client = docker.from_env()
        self.recon_image = recon_image
        self.gvm_image = gvm_image
        self.github_hunt_image = github_hunt_image
        self.trufflehog_image = trufflehog_image
        self.ai_attack_image = ai_attack_image
        self.running_states: dict[str, ReconState] = {}
        # Nested dict: outer key = project_id, inner key = run_id
        self.partial_recon_states: dict[str, dict[str, PartialReconState]] = {}
        self.gvm_states: dict[str, GvmState] = {}
        self.github_hunt_states: dict[str, GithubHuntState] = {}
        self.trufflehog_states: dict[str, TrufflehogState] = {}
        # AI Attack Surface: nested project_id -> run_id (parallel per-tool jobs).
        self.ai_attack_states: dict[str, dict[str, AiAttackSurfaceState]] = {}
        # Set by api.py after construction: the on-demand Ollama judge manager
        # (Step 1). The AI attack lifecycle ref-counts a judge lease through it.
        self.local_llm_manager = None
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
        self.codefix_sandbox_mem = os.environ.get("CODEFIX_SANDBOX_MEM", "2g")
        self.codefix_sandbox_nanocpus = int(os.environ.get("CODEFIX_SANDBOX_NANOCPUS", str(2_000_000_000)))
        self.codefix_sandbox_pids = int(os.environ.get("CODEFIX_SANDBOX_PIDS", "512"))
        # Max lifetime before the reaper force-removes a sandbox (orphaned by a
        # crashed agent). Generous because real builds can be slow.
        self.codefix_sandbox_ttl = int(os.environ.get("CODEFIX_SANDBOX_TTL", "3600"))
        # Host path of the cypherfix-work volume (set by api.py after mount
        # auto-detection) — used to bind per-job worktrees into the sandbox.
        self.codefix_work_host_base: Optional[str] = None
        self.codefix_sandboxes: dict[str, dict] = {}

        # Memory governor (Part 1): reserves each scan job's expected RAM envelope
        # before spawning so concurrent scans can never sum past the host's scan
        # pool. Fail-open: with the governor disabled, try_admit always admits.
        self.ledger = ReservationLedger()

    def _scan_key(self, kind: str, project_id: str, run_id: Optional[str] = None) -> str:
        """Stable reservation key for a scan job."""
        base = f"{kind}:{project_id}"
        return f"{base}:{run_id}" if run_id else base

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
                    keys.add(self._scan_key("partial_recon", pid, rid))
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
        for pid, st in self.trufflehog_states.items():
            if st.status in (TrufflehogStatus.RUNNING, TrufflehogStatus.STARTING, TrufflehogStatus.PAUSED):
                keys.add(self._scan_key("trufflehog", pid))
        return keys

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
                await self.get_trufflehog_status(pid)
            except Exception:
                pass

    def _container_mem_limit(self, kind: str) -> Optional[int]:
        """Hard per-container memory ceiling (bytes) for a spawned scan, sized from
        the job envelope × headroom and clamped to PER_CONTAINER_MAX so one
        container can never take the whole host. Generous backstop: it sits ABOVE
        the admission envelope so a normal peak is never killed, only a runaway.
        Returns None (no limit) when the governor is disabled or RAM is unreadable."""
        if not rg.governor_enabled():
            return None
        envelope = self.ledger.envelope_for(kind)
        if envelope <= 0:
            return None
        headroom = rg._env_float("CONTAINER_CAP_HEADROOM", 1.5)
        if headroom < 1.0:
            headroom = 1.0
        cap = int(envelope * headroom)
        per_max = rg.env_bytes("PER_CONTAINER_MAX", None)
        if per_max is None:
            mem = rg.read_mem()
            per_max = int(mem[0] * 0.55) if mem else cap
        cap = min(cap, per_max)
        # Never size the hard cap BELOW the admission envelope (the expected peak),
        # or a normal run would be OOM-killed. On a host so small that per_max <
        # envelope, admission would already have rejected this scan; if it somehow
        # ran, the envelope floor still avoids a false kill.
        floor = 512 * 1024 ** 2
        return max(floor, envelope, cap)

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

    def _format_recon_job_id(self, prefix: str, started_at: datetime, unique_value: str) -> str:
        """Format graph job metadata ID for recon containers."""
        started_utc = started_at.astimezone(timezone.utc)
        stamp = started_utc.strftime("%Y%m%dT%H%M%SZ")
        suffix = "".join(ch for ch in unique_value if ch.isalnum())[:8]
        if not suffix:
            suffix = uuid.uuid4().hex[:8]
        return f"{prefix}-{stamp}-{suffix}"

    def _format_recon_job_started_at(self, started_at: datetime) -> str:
        """Format graph job start time as UTC ISO-8601 without microseconds."""
        started_utc = started_at.astimezone(timezone.utc).replace(microsecond=0)
        return started_utc.isoformat().replace("+00:00", "Z")

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
        delete_graph: bool = False,
    ) -> ReconState:
        """Start a recon container for a project"""

        # Check if already running or paused
        current_state = await self.get_status(project_id)
        if current_state.status in (ReconStatus.RUNNING, ReconStatus.PAUSED):
            raise ValueError(f"Recon already active for project {project_id}")

        # Mutual exclusion: block if any partial recon is running
        if self._count_active_partial_recons(project_id) > 0:
            raise ValueError(f"Partial recon(s) running for project {project_id}. Stop them first.")

        # Memory admission (Part 1): reserve this scan's RAM envelope or reject.
        await self._admit_scan("full_recon", project_id, user_id=user_id)

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
        job_unique = uuid.uuid4().hex
        recon_job_id = self._format_recon_job_id("full", state.started_at, job_unique)
        recon_job_started_at = self._format_recon_job_started_at(state.started_at)

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
                    "UPDATE_GRAPH_DB": "true",
                    "RECON_DELETE_GRAPH": "true" if delete_graph else "false",
                    "RECON_JOB_ID": recon_job_id,
                    "RECON_JOB_STARTED_AT": recon_job_started_at,
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
                    sibling_host_path(recon_path, "graph_db"): {"bind": "/app/graph_db", "mode": "ro"},
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

    async def start_capture_proxy(self, config: dict | None = None) -> dict:
        """Start (idempotently reconcile) the capture proxy + ingest pair.

        `config` (from the Global Settings toggle) may override runtime knobs:
        port, maxBodyKb, storeBodies, redactSecrets, scope, blockedIps. The image
        is NOT overridable from the UI (it comes from the trusted orchestrator env)
        so the operator toggle can never spawn an arbitrary container image.
        """
        config = config or {}
        image = self._capture_image()  # trusted env only, never from `config`
        port = int(config.get("port") or self._capture_port())
        max_body_kb = str(config.get("maxBodyKb") or os.environ.get("CAPTURE_PROXY_MAX_BODY_KB", "64"))
        store_bodies = self._bool_env(config.get("storeBodies"), os.environ.get("CAPTURE_PROXY_STORE_BODIES", "true"))
        redact = self._bool_env(config.get("redactSecrets"), os.environ.get("CAPTURE_PROXY_REDACT_SECRETS", "true"))
        blocked_ips = config.get("blockedIps") or os.environ.get("CAPTURE_BLOCKED_IPS", "")

        # Granular body-storage policy -> CAPTURE_* env the proxy addon reads
        # (capture_lib.decide_body / parse_body_rules). The addon fails safe on a
        # bad bodyRules value, but normalize here so garbage never reaches the env.
        store_req = self._bool_env(config.get("storeReqBodies"), os.environ.get("CAPTURE_STORE_REQ_BODIES", "true"))
        store_resp = self._bool_env(config.get("storeRespBodies"), os.environ.get("CAPTURE_STORE_RESP_BODIES", "true"))
        max_store_mb = str(config.get("maxStoreMb") if config.get("maxStoreMb") is not None
                           else os.environ.get("CAPTURE_MAX_STORE_MB", "5"))
        body_rules = config.get("bodyRules") or os.environ.get("CAPTURE_BODY_RULES", "")
        if body_rules:
            try:
                # accept a dict or JSON string; re-serialize compactly
                parsed = body_rules if isinstance(body_rules, dict) else json.loads(body_rules)
                body_rules = json.dumps(parsed, separators=(",", ":")) if isinstance(parsed, dict) else ""
            except (ValueError, TypeError):
                body_rules = ""

        # Egress-guard toggles (Global Settings > TrafficMind). Each config key maps
        # to a CAPTURE_EGRESS_* env the proxy addon reads (egress.policy_from_env).
        # Default is block (True); an omitted/None key keeps the always-on guard.
        _egress_map = {
            "egressBlockEmptyHost":     ("CAPTURE_EGRESS_BLOCK_EMPTY_HOST",     "CAPTURE_EGRESS_BLOCK_EMPTY_HOST"),
            "egressBlockHardGuardrail": ("CAPTURE_EGRESS_BLOCK_HARD_GUARDRAIL", "CAPTURE_EGRESS_BLOCK_HARD_GUARDRAIL"),
            "egressFailClosed":         ("CAPTURE_EGRESS_FAIL_CLOSED",          "CAPTURE_EGRESS_FAIL_CLOSED"),
            "egressBlockUnresolvable":  ("CAPTURE_EGRESS_BLOCK_UNRESOLVABLE",   "CAPTURE_EGRESS_BLOCK_UNRESOLVABLE"),
            "egressBlockPrivate":       ("CAPTURE_EGRESS_BLOCK_PRIVATE",        "CAPTURE_EGRESS_BLOCK_PRIVATE"),
            "egressBlockLoopback":      ("CAPTURE_EGRESS_BLOCK_LOOPBACK",       "CAPTURE_EGRESS_BLOCK_LOOPBACK"),
            "egressBlockLinkLocal":     ("CAPTURE_EGRESS_BLOCK_LINK_LOCAL",     "CAPTURE_EGRESS_BLOCK_LINK_LOCAL"),
            "egressBlockCgnat":         ("CAPTURE_EGRESS_BLOCK_CGNAT",          "CAPTURE_EGRESS_BLOCK_CGNAT"),
            "egressBlockReserved":      ("CAPTURE_EGRESS_BLOCK_RESERVED",       "CAPTURE_EGRESS_BLOCK_RESERVED"),
            "egressBlockMulticast":     ("CAPTURE_EGRESS_BLOCK_MULTICAST",      "CAPTURE_EGRESS_BLOCK_MULTICAST"),
            "egressBlockUnspecified":   ("CAPTURE_EGRESS_BLOCK_UNSPECIFIED",    "CAPTURE_EGRESS_BLOCK_UNSPECIFIED"),
        }
        egress_env = {}
        for cfg_key, (env_key, host_env) in _egress_map.items():
            egress_env[env_key] = self._bool_env(config.get(cfg_key), os.environ.get(host_env, "true"))

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
                "CAPTURE_PROXY_MAX_BODY_KB": max_body_kb,
                "CAPTURE_PROXY_STORE_BODIES": store_bodies,
                "CAPTURE_STORE_REQ_BODIES": store_req,
                "CAPTURE_STORE_RESP_BODIES": store_resp,
                "CAPTURE_MAX_STORE_MB": max_store_mb,
                "CAPTURE_BODY_RULES": body_rules,
                "CAPTURE_BLOCKED_IPS": blocked_ips,
                **egress_env,
            },
            volumes={**spool_vols, "redamon_capture_ca": {"bind": "/ca", "mode": "rw"}},
            cap_drop=["ALL"],
            read_only=True,
            tmpfs={"/tmp": "size=64m,exec"},
            mem_limit=os.environ.get("CAPTURE_PROXY_MEM", "384m"),
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
            },
            volumes=spool_vols,
            cap_drop=["ALL"],
            read_only=True,
            tmpfs={"/tmp": "size=64m,exec"},
            mem_limit=os.environ.get("TRAFFIC_INGEST_MEM", "256m"),
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
        for project_id in list(self.trufflehog_states.keys()):
            try:
                await self.stop_trufflehog(project_id, timeout=5)
            except Exception as e:
                logger.error(f"Error cleaning up TruffleHog {project_id}: {e}")
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
        await self._admit_scan("partial_recon", project_id, run_id, user_id=config.get("user_id"))

        state = PartialReconState(
            project_id=project_id,
            run_id=run_id,
            tool_id=tool_id,
            status=PartialReconStatus.STARTING,
            started_at=datetime.now(timezone.utc),
        )
        self.partial_recon_states.setdefault(project_id, {})[run_id] = state
        recon_job_id = self._format_recon_job_id("partial", state.started_at, run_id)
        recon_job_started_at = self._format_recon_job_started_at(state.started_at)

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
                    "RECON_JOB_ID": recon_job_id,
                    "RECON_JOB_STARTED_AT": recon_job_started_at,
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
                },
                volumes={
                    # V4: mount the BROKER's filtered socket via a named volume,
                    # NOT the raw host socket. The recon code still does `docker run`
                    # unchanged, but a compromised worker cannot mount / or run a
                    # privileged/arbitrary container; the broker rejects those.
                    BROKER_SOCKET_VOLUME: {"bind": "/var/run/broker", "mode": "rw"},
                    f"{recon_path}": {"bind": "/app/recon", "mode": "rw"},
                    sibling_host_path(recon_path, "graph_db"): {"bind": "/app/graph_db", "mode": "ro"},
                    "/tmp/redamon": {"bind": "/tmp/redamon", "mode": "rw"},
                    # JS Recon shared volumes with webapp (uploaded files + custom patterns)
                    "redamon_js_recon_uploads": {"bind": "/data/js-recon-uploads", "mode": "ro"},
                    "redamon_js_recon_custom": {"bind": "/data/js-recon-custom", "mode": "ro"},
                    # Official nuclei-templates volume (read-only) for the AI tag
                    # selector to read TEMPLATES-STATS.json.
                    "nuclei-templates": {"bind": "/opt/nuclei-templates-official", "mode": "ro"},
                },
                mem_limit=self._container_mem_limit("partial_recon"),  # Memory governor (Part 4c)
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
                    path=Path(ai_attack_path).parent.as_posix(),
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
                    path=Path(gvm_scan_path).parent.as_posix(),
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
                    sibling_host_path(recon_path, "graph_db"): {"bind": "/app/graph_db", "mode": "ro"},
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
        )
        self.github_hunt_states[project_id] = state

        try:
            # Ensure GitHub hunt image exists
            try:
                self.client.images.get(self.github_hunt_image)
            except NotFound:
                logger.info(f"Building GitHub hunt image from {github_hunt_path}")
                self.client.images.build(
                    path=Path(github_hunt_path).parent.as_posix(),
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
                    sibling_host_path(github_hunt_path, "graph_db"): {"bind": "/app/graph_db", "mode": "ro"},
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

    def _get_trufflehog_container_name(self, project_id: str) -> str:
        """Generate container name for a TruffleHog scan"""
        safe_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', project_id)
        return f"redamon-trufflehog-{safe_id}"

    async def get_trufflehog_status(self, project_id: str) -> TrufflehogState:
        """Get current status of a TruffleHog scan process. Docker inspection
        runs off the event loop (_run_blocking) so a slow daemon can't stall the
        worker -- same poll cadence and freeze risk as recon."""
        return await self._run_blocking(self._get_trufflehog_status_sync, project_id)

    def _get_trufflehog_status_sync(self, project_id: str) -> TrufflehogState:
        if project_id in self.trufflehog_states:
            state = self.trufflehog_states[project_id]

            if state.container_id:
                try:
                    container = self.client.containers.get(state.container_id)
                    if container.status == "paused":
                        state.status = TrufflehogStatus.PAUSED
                    elif container.status != "running":
                        exit_code = container.attrs.get("State", {}).get("ExitCode", -1)
                        if exit_code == 0:
                            state.status = TrufflehogStatus.COMPLETED
                            state.completed_at = datetime.now(timezone.utc)
                        else:
                            state.status = TrufflehogStatus.ERROR
                            state.error = f"Container exited with code {exit_code}"
                            state.completed_at = datetime.now(timezone.utc)

                        try:
                            container.remove()
                            logger.info(f"Auto-removed finished TruffleHog container for project {project_id}")
                        except Exception as e:
                            logger.warning(f"Failed to auto-remove TruffleHog container: {e}")
                except NotFound:
                    if state.status not in (TrufflehogStatus.COMPLETED, TrufflehogStatus.ERROR):
                        state.status = TrufflehogStatus.ERROR
                        state.error = "Container not found"
                except APIError as e:
                    logger.warning(f"Docker API error checking TruffleHog container for {project_id}: {e}")
                    if state.status not in (TrufflehogStatus.COMPLETED, TrufflehogStatus.ERROR):
                        state.status = TrufflehogStatus.ERROR
                        state.error = f"Docker API error: {e}"

            return state

        # Check if there's an orphan container
        container_name = self._get_trufflehog_container_name(project_id)
        try:
            container = self.client.containers.get(container_name)
            if container.status in ("running", "paused"):
                return TrufflehogState(
                    project_id=project_id,
                    status=TrufflehogStatus.PAUSED if container.status == "paused" else TrufflehogStatus.RUNNING,
                    container_id=container.id,
                )
        except NotFound:
            pass

        return TrufflehogState(
            project_id=project_id,
            status=TrufflehogStatus.IDLE,
        )

    async def start_trufflehog(
        self,
        project_id: str,
        user_id: str,
        webapp_api_url: str,
        trufflehog_path: str,
    ) -> TrufflehogState:
        """Start a TruffleHog scan container for a project"""

        # Check if already running
        current_state = await self.get_trufflehog_status(project_id)
        if current_state.status in (TrufflehogStatus.RUNNING, TrufflehogStatus.PAUSED):
            raise ValueError(f"TruffleHog scan already active for project {project_id}")

        # Memory admission (Part 1): reserve this scan's RAM envelope or reject.
        await self._admit_scan("trufflehog", project_id, user_id=user_id)

        # Clean up any existing container
        container_name = self._get_trufflehog_container_name(project_id)
        try:
            old_container = self.client.containers.get(container_name)
            old_container.remove(force=True)
            logger.info(f"Removed old TruffleHog container {container_name}")
        except NotFound:
            pass

        # Create new state
        state = TrufflehogState(
            project_id=project_id,
            status=TrufflehogStatus.STARTING,
            started_at=datetime.now(timezone.utc),
        )
        self.trufflehog_states[project_id] = state

        try:
            # Ensure TruffleHog image exists
            try:
                self.client.images.get(self.trufflehog_image)
            except NotFound:
                logger.info(f"Building TruffleHog image from {trufflehog_path}")
                self.client.images.build(
                    path=Path(trufflehog_path).parent.as_posix(),
                    dockerfile=f"{Path(trufflehog_path).name}/Dockerfile",
                    tag=self.trufflehog_image,
                    rm=True,
                )

            # Start container with environment variables
            container = self.client.containers.run(
                self.trufflehog_image,
                mem_limit=self._container_mem_limit("trufflehog"),  # Memory governor (Part 4c)
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
                    # TruffleHog output (read-write, for saving results)
                    f"{trufflehog_path}/output": {"bind": "/app/trufflehog_scan/output", "mode": "rw"},
                    # Mount trufflehog_scan source for development (no rebuild needed)
                    f"{trufflehog_path}": {"bind": "/app/trufflehog_scan", "mode": "rw"},
                    # Mount graph_db module for Neo4j integration
                    sibling_host_path(trufflehog_path, "graph_db"): {"bind": "/app/graph_db", "mode": "ro"},
                },
                command="python trufflehog_scan/main.py",
            )

            state.container_id = container.id
            state.status = TrufflehogStatus.RUNNING
            logger.info(f"Started TruffleHog container {container.id} for project {project_id}")

        except Exception as e:
            state.status = TrufflehogStatus.ERROR
            state.error = str(e)
            logger.error(f"Failed to start TruffleHog scan for {project_id}: {e}")

        return state

    async def pause_trufflehog(self, project_id: str) -> TrufflehogState:
        """Pause a running TruffleHog scan process"""
        state = await self.get_trufflehog_status(project_id)

        if state.status != TrufflehogStatus.RUNNING:
            return state

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.pause()
                state.status = TrufflehogStatus.PAUSED
                self.trufflehog_states[project_id] = state
                logger.info(f"Paused TruffleHog container for project {project_id}")
            except NotFound:
                state.status = TrufflehogStatus.ERROR
                state.error = "Container not found"
            except APIError as e:
                state.status = TrufflehogStatus.ERROR
                state.error = f"Failed to pause: {e}"

        return state

    async def resume_trufflehog(self, project_id: str) -> TrufflehogState:
        """Resume a paused TruffleHog scan process"""
        state = await self.get_trufflehog_status(project_id)

        if state.status != TrufflehogStatus.PAUSED:
            return state

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.unpause()
                state.status = TrufflehogStatus.RUNNING
                self.trufflehog_states[project_id] = state
                logger.info(f"Resumed TruffleHog container for project {project_id}")
            except NotFound:
                state.status = TrufflehogStatus.ERROR
                state.error = "Container not found"
            except APIError as e:
                state.status = TrufflehogStatus.ERROR
                state.error = f"Failed to resume: {e}"

        return state

    async def stop_trufflehog(self, project_id: str, timeout: int = 10) -> TrufflehogState:
        """Stop a running TruffleHog scan process"""
        state = await self.get_trufflehog_status(project_id)

        if state.status not in (TrufflehogStatus.RUNNING, TrufflehogStatus.PAUSED):
            return state

        state.status = TrufflehogStatus.STOPPING

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                if container.status == "paused":
                    container.unpause()
                container.stop(timeout=timeout)
                container.remove()
                state.status = TrufflehogStatus.IDLE
                state.completed_at = datetime.now(timezone.utc)
                logger.info(f"Stopped TruffleHog container for project {project_id}")
            except NotFound:
                state.status = TrufflehogStatus.IDLE
            except Exception as e:
                state.status = TrufflehogStatus.ERROR
                state.error = f"Failed to stop: {e}"

        if project_id in self.trufflehog_states:
            del self.trufflehog_states[project_id]

        return state

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

    async def stream_trufflehog_logs(self, project_id: str) -> AsyncGenerator[TrufflehogLogEvent, None]:
        """Stream logs from a TruffleHog scan container"""
        state = await self.get_trufflehog_status(project_id)

        if not state.container_id:
            yield TrufflehogLogEvent(
                log="No TruffleHog container found for this project",
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

                        event = self._parse_trufflehog_log_line(log_text, current_phase, current_phase_num, timestamp=docker_ts)

                        if event.is_phase_start:
                            current_phase = event.phase
                            current_phase_num = event.phase_number

                            if project_id in self.trufflehog_states:
                                self.trufflehog_states[project_id].current_phase = current_phase
                                self.trufflehog_states[project_id].phase_number = current_phase_num

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
        """Get count of running TruffleHog scan processes"""
        return sum(1 for s in self.trufflehog_states.values() if s.status == TrufflehogStatus.RUNNING)

"""
Recon Orchestrator API - FastAPI service for managing recon containers
"""
import asyncio
import json
import logging
import os
import socket
import time
import urllib.error
import urllib.request
from contextlib import asynccontextmanager
from typing import Optional

import docker
from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

from auth import is_orchestrator_request_authorized
from recon_settings.engagement import derive_roe_enabled
from container_manager import ContainerManager
from admission_ledger import AdmissionError


def _value_error_http(e: ValueError) -> "HTTPException":
    """Map a ValueError from a start endpoint to a 409. For an AdmissionError
    (memory governor), return the STRUCTURED limit payload (limitType/settingName/
    ...) the Part 5 UI modal needs, instead of a plain string."""
    from fastapi import HTTPException as _HTTPException
    if isinstance(e, AdmissionError):
        return _HTTPException(status_code=409, detail=e.result.payload())
    return _HTTPException(status_code=409, detail=str(e))
from local_llm_manager import LocalLlmManager
from scan_scheduler import scan_scheduler_loop
from job_dispatcher import job_dispatcher_loop, run_one_dispatch_tick
from webapp_client import internal_key as _webapp_internal_key, request_json as _webapp_request, webapp_base as _webapp_base
from models import (
    HealthResponse,
    CaptureProxyConfig,
    ReconStartRequest,
    ReconState,
    ReconStatus,
    GvmStartRequest,
    GvmState,
    GvmStatus,
    GithubHuntStartRequest,
    GithubHuntState,
    GithubHuntStatus,
    TrufflehogListResponse,
    TrufflehogStartRequest,
    TrufflehogState,
    SupplyChainStartRequest,
    SupplyChainState,
    SupplyChainStatus,
    GuarddogRequest,
    GuarddogResult,
    TrufflehogStatus,
    PartialReconStartRequest,
    PartialReconState,
    PartialReconStatus,
    PartialReconListResponse,
    AiAttackSurfaceStartRequest,
    AiAttackSurfaceState,
    AiAttackSurfaceStatus,
    AiAttackSurfaceListResponse,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def _detect_host_mounts() -> dict[str, str]:
    """
    Auto-detect host filesystem paths by inspecting this container's Docker mounts.

    Inside a Docker container the hostname equals the container ID.
    We use the Docker SDK (via the mounted socket) to inspect our own container
    and read the Source (host path) for each Destination (container path).

    Returns a dict mapping container_path -> host_path, e.g.:
        {"/app/recon": "/home/user/project/recon", ...}
    """
    try:
        client = docker.from_env()
        container = client.containers.get(socket.gethostname())
        mount_map = {}
        for mount in container.attrs["Mounts"]:
            mount_map[mount["Destination"]] = mount["Source"]
        logger.info(f"Auto-detected host mounts: { {k: v for k, v in mount_map.items() if k.startswith('/app/')} }")
        return mount_map
    except Exception as e:
        logger.warning(f"Could not auto-detect host mounts: {e}")
        return {}


def _get_host_path(mount_map: dict[str, str], container_path: str, env_var: str) -> str:
    """
    Resolve a host path: prefer auto-detected mount, fall back to env var.

    Raises RuntimeError if neither source provides a path.
    """
    # 1. Auto-detected from own container mounts (works on any machine)
    if container_path in mount_map:
        return mount_map[container_path]

    # 2. Explicit env var (no hardcoded default)
    path = os.getenv(env_var)
    if path:
        return path

    raise RuntimeError(
        f"Cannot determine host path for {container_path}. "
        f"Either run via docker-compose (auto-detected) or set {env_var} env var."
    )


# Auto-detect host mount paths from this container's own mounts
_host_mounts = _detect_host_mounts()

# Configuration — resolved dynamically, no hardcoded machine paths
RECON_PATH = _get_host_path(_host_mounts, "/app/recon", "RECON_PATH")
RECON_IMAGE = os.getenv("RECON_IMAGE", "redamon-recon:latest")
GVM_SCAN_PATH = _get_host_path(_host_mounts, "/app/gvm_scan", "GVM_SCAN_PATH")
GVM_IMAGE = os.getenv("GVM_IMAGE", "redamon-vuln-scanner:latest")
GITHUB_HUNT_PATH = _get_host_path(_host_mounts, "/app/github_secret_hunt", "GITHUB_HUNT_PATH")
GITHUB_HUNT_IMAGE = os.getenv("GITHUB_HUNT_IMAGE", "redamon-github-hunter:latest")
TRUFFLEHOG_PATH = _get_host_path(_host_mounts, "/app/trufflehog_scan", "TRUFFLEHOG_PATH")
TRUFFLEHOG_IMAGE = os.getenv("TRUFFLEHOG_IMAGE", "redamon-trufflehog:latest")
# Supply-Chain scan (L1). SUPPLY_CHAIN_UPLOADS_PATH is the host dir where the
# webapp stores an uploaded SBOM/lockfile; mounted read-only into the scan.
SUPPLY_CHAIN_PATH = _get_host_path(_host_mounts, "/app/supply_chain_scan", "SUPPLY_CHAIN_PATH")
SUPPLY_CHAIN_IMAGE = os.getenv("SUPPLY_CHAIN_IMAGE", "redamon-supply-chain:latest")
# graph_db host path, bound into EVERY spawned scan container. Resolved the same
# way as every other source path (auto-detected from our own mounts, env override
# second) instead of being DERIVED from a sibling's Source string: on any host
# where Docker reports a rewritten bind Source (Docker Desktop on Windows/WSL2)
# the sibling guess names a path that does not exist, Docker auto-creates it
# EMPTY, and the empty dir shadows the scan image's baked-in copy. Optional so an
# orchestrator container predating the compose mount still starts; container_manager
# then falls back to the legacy guess (and skips the mount where it would shadow a
# good baked-in copy).
try:
    GRAPH_DB_PATH = _get_host_path(_host_mounts, "/app/graph_db", "GRAPH_DB_PATH")
except RuntimeError:
    GRAPH_DB_PATH = ""
    logger.warning(
        "graph_db source is not mounted into the orchestrator, so its host path cannot "
        "be auto-detected. Add './graph_db:/app/graph_db:ro' to the recon-orchestrator "
        "volumes and recreate the container (or set GRAPH_DB_PATH) so spawned scans "
        "bind the real graph_db on every platform."
    )
# The recon settings registry, bound into every spawned scan container for the
# same reason graph_db is: it is baked into the scan images, and a mount of the
# host copy is what lets a registry edit reach a scan without a rebuild. Unlike
# graph_db, a missing registry is not a silent degradation - the loader refuses
# to start the scan - so the baked copy is the safety net and this mount is the
# freshness one.
try:
    RECON_SETTINGS_PATH = _get_host_path(_host_mounts, "/app/recon_settings", "RECON_SETTINGS_PATH")
except RuntimeError:
    RECON_SETTINGS_PATH = ""
    logger.warning(
        "recon_settings is not mounted into the orchestrator, so its host path cannot be "
        "auto-detected. Spawned scans will use the registry baked into their image, which "
        "means a registry edit needs a rebuild to take effect. Add "
        "'./recon_settings:/app/recon_settings:ro' to the recon-orchestrator volumes and "
        "recreate the container (or set RECON_SETTINGS_PATH)."
    )
try:
    AI_ATTACK_SURFACE_PATH = _get_host_path(_host_mounts, "/app/ai_attack_surface_scan", "AI_ATTACK_SURFACE_PATH")
except RuntimeError:
    AI_ATTACK_SURFACE_PATH = ""
    logger.info("AI Attack Surface source not mounted — feature disabled until mounted")
AI_ATTACK_SURFACE_IMAGE = os.getenv("AI_ATTACK_SURFACE_IMAGE", "redamon-ai-attack-surface:latest")
try:
    CUSTOM_TEMPLATES_PATH = _get_host_path(_host_mounts, "/app/nuclei-templates", "CUSTOM_TEMPLATES_PATH")
except RuntimeError:
    CUSTOM_TEMPLATES_PATH = ""
    logger.info("Custom nuclei templates not mounted — custom templates feature disabled")
# Host path of the cypherfix-work volume — needed to bind per-job worktrees into
# the CodeFix build sandbox (T6/E10). Optional: empty disables the feature.
try:
    CODEFIX_WORK_PATH = _get_host_path(_host_mounts, "/app/codefix-work", "CODEFIX_WORK_PATH")
except RuntimeError:
    CODEFIX_WORK_PATH = ""
    logger.info("CodeFix work volume not mounted — CodeFix sandbox feature disabled")
VERSION = "1.0.0"


def _trusted_webapp_base() -> str:
    """The orchestrator's OWN webapp base URL for its credentialed pre-flight calls.

    Never use the client-supplied ``request.webapp_api_url`` for these: it is
    ``http://localhost:3000`` (correct for the host-network *spawned* scan
    containers, but pointing at the orchestrator itself from here, so the call
    silently fails and the RoE / hard-guardrail check is skipped). It is also an
    SSRF / INTERNAL_API_KEY-leak vector (V2). After V1 the orchestrator shares a
    network with the webapp, so ``http://webapp:3000`` resolves by DNS.
    """
    return os.environ.get("WEBAPP_API_URL", "http://webapp:3000").rstrip("/")


def _fetch_project_for_preflight(project_id: str, refusal: str = "Refusing to start.") -> dict:
    """Fetch the project settings the guardrail / RoE pre-flight needs.

    Fails CLOSED. Any fetch failure or non-200 raises 503 naming the
    unreachable dependency, rather than logging "proceeding" and running the
    scan with neither the hard guardrail nor the RoE window applied. Scan
    starts became unattended and remote with the MCP surface, so "could not
    verify scope, started anyway" is no longer an acceptable degradation
    (mcp_plan.md P0-1). The guardrail is still applied at project creation and
    RoE excluded hosts inside the recon container, so this remains defence in
    depth rather than the only gate.
    """
    import urllib.request
    import json as json_mod

    url = f"{_trusted_webapp_base()}/api/projects/{project_id}"
    req = urllib.request.Request(url)
    req.add_header("X-Internal-Key", os.environ.get("INTERNAL_API_KEY", ""))
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status != 200:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        f"Cannot verify scan scope: the webapp project fetch "
                        f"returned HTTP {resp.status}. {refusal}"
                    ),
                )
            return json_mod.loads(resp.read().decode())
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Cannot verify scan scope: the webapp is unreachable "
                f"({type(e).__name__}). {refusal}"
            ),
        )


def _refuse_failed_spawn(state) -> None:
    """A start whose container could not be created is a refusal: 500 with code
    `spawn_failed`, never a 200 carrying `status: error`. The webapp would
    otherwise run retention, keep the prepared version and record a running
    ScanJob for a scan that never began. The queue treats the code as
    permanent: a missing image or a refused mount fails every retry.
    """
    if state.status in (ReconStatus.ERROR, PartialReconStatus.ERROR):
        raise HTTPException(
            status_code=500,
            detail={"detail": f"The scan container could not be started: {state.error}",
                    "code": "spawn_failed"},
        )


def _check_roe_time_window(project: dict, _now=None) -> None:
    """Enforce the RoE time-window. Raises 403 outside the window.

    A malformed timezone is a bad *setting*, not an unknown scope, so it raises
    400 naming the offending setting instead of silently passing (mcp_plan.md
    P0-1). Only that narrow carve-out is tolerated; every other failure
    propagates.

    A mirror of recon/helpers/roe_scope.py ``_check_roe_time_window``, which
    this image cannot import: a start admitted here that the scan container
    refuses exits 1 after the orchestrator reported it started. Both run
    recon/tests/fixtures/roe_time_window_vectors.json. Pass _now for testing.
    """
    # The THIRD enforcement point, after recon and the agent. It gates on the
    # DERIVED value like the other two: gating on the column would leave this
    # 403 keyed on something nothing writes, and the window would quietly stop
    # blocking.
    if not (derive_roe_enabled(project) and project.get('roeTimeWindowEnabled')):
        return

    from datetime import datetime
    try:
        import zoneinfo
    except ImportError:
        from backports import zoneinfo

    tz_name = project.get('roeTimeWindowTimezone', 'UTC')
    try:
        tz = zoneinfo.ZoneInfo(tz_name)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail=(
                f"RoE time window: invalid timezone '{tz_name}'. "
                f"Fix the project's RoE time-window timezone setting."
            ),
        )

    now_local = (_now or datetime.now(tz)).astimezone(tz)
    day_name = now_local.strftime('%A').lower()
    allowed_days = [str(d).lower() for d in project.get('roeTimeWindowDays') or []]
    start_time = project.get('roeTimeWindowStartTime', '09:00')
    end_time = project.get('roeTimeWindowEndTime', '18:00')
    current_time = now_local.strftime('%H:%M')

    if day_name not in allowed_days:
        raise HTTPException(
            status_code=403,
            detail=(
                f"RoE time window: testing not allowed on {day_name.capitalize()}. "
                f"Allowed days: {', '.join(d.capitalize() for d in allowed_days)}"
            ),
        )
    # Handle overnight windows (e.g. 22:00 - 06:00)
    if start_time <= end_time:
        outside = current_time < start_time or current_time > end_time
    else:
        outside = current_time < start_time and current_time > end_time
    if outside:
        raise HTTPException(
            status_code=403,
            detail=(
                f"RoE time window: current time {current_time} {tz_name} is "
                f"outside allowed window ({start_time}-{end_time})"
            ),
        )


def _recon_output_files(output_dir, project_id: str) -> list:
    """Every recon JSON this project owns: the canonical file plus each
    Domain-batch group file (`recon_<id>__<domain>.json`).

    Deleting only the canonical name leaks one file per domain per batch run.

    Group files are matched by LITERAL PREFIX, never by glob. A project id is
    client-suppliable at creation and is interpolated straight into this URL's
    path, so a glob built from it lets an id of `*` (or `[a-z]*`) select every
    OTHER project's group files - and this function's callers DELETE what it
    returns. startswith/endswith has no metacharacters to abuse. The parent-dir
    check stays as a second line of defence against a traversing id.
    """
    from pathlib import Path
    output_dir = Path(output_dir)
    prefix = f"recon_{project_id}__"

    candidates = [output_dir / f"recon_{project_id}.json"]
    try:
        candidates.extend(sorted(
            p for p in output_dir.iterdir()
            if p.name.startswith(prefix) and p.name.endswith(".json")
        ))
    except OSError:
        pass

    resolved_dir = output_dir.resolve()
    files = []
    for path in candidates:
        try:
            if path.is_file() and path.resolve().parent == resolved_dir:
                files.append(path)
        except OSError:
            continue
    return files


def _spawned_webapp_url() -> str:
    """The webapp URL forwarded to *spawned* scan containers (V2).

    Spawned recon/GVM/hunt/trufflehog/ai-attack containers run on the HOST
    network, so they reach the webapp via the host-published port
    (``http://localhost:3000``), NOT the ``webapp`` docker DNS name (which only
    resolves on a bridge network — that is why this differs from
    ``_trusted_webapp_base()``).

    This value is server-controlled and MUST NOT come from the request body:
    those containers send ``INTERNAL_API_KEY`` to this URL, so trusting a
    client-supplied ``webapp_api_url`` would be an SSRF / key-leak vector (V2).
    """
    return os.environ.get("SPAWNED_WEBAPP_API_URL", "http://localhost:3000").rstrip("/")

# Global container manager
container_manager: ContainerManager = None
# On-demand local LLM (Ollama) judge/attacker for the AI Attack Surface layer
local_llm_manager: LocalLlmManager = None

# How often the background reaper refreshes AI-attack states (releases orphaned
# Ollama leases from runs whose UI disconnected before completion).
AI_ATTACK_REAP_INTERVAL_S = int(os.environ.get("AI_ATTACK_REAP_INTERVAL", "30"))


# C-10: capture retention/quota housekeeping is not scheduled anywhere in the repo
# (README.TRAFFIC.md), so a busier queue grows captured_http_transactions unbounded.
# Fire it from the reaper on a TTL, alongside the existing sweeps.
TRAFFIC_MAINTENANCE_INTERVAL_S = int(os.environ.get("TRAFFIC_MAINTENANCE_INTERVAL", "3600"))
_last_traffic_maintenance = 0.0

# The webapp has no scheduler of its own (no instrumentation.ts, no setInterval),
# so its periodic jobs are driven from this loop. Daily is ample for pruning
# tokens that have been dead for 90 days.
MCP_TOKEN_PRUNE_INTERVAL_S = int(os.environ.get("MCP_TOKEN_PRUNE_INTERVAL", "86400"))
_last_mcp_token_prune = 0.0


def _interval_from_env(name: str, default: int) -> int:
    """A positive whole number of seconds from the environment, else `default`: an empty
    or bad value must not crash the orchestrator at import (int('') would)."""
    raw = (os.environ.get(name) or "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else default


# Plugin reconciliation (README.PLUGINS.md §9.7, TD-20): crash recovery, heals, revocations
# and clean-up run in the webapp, which has no scheduler, so this loop asks for them.
PLUGIN_RECONCILE_INTERVAL_S = _interval_from_env("PLUGIN_RECONCILE_INTERVAL", 300)
_last_plugin_reconcile = 0.0
_plugin_reconcile_task: Optional[asyncio.Task] = None
# Set by a 404: the webapp has no such route (an image older than the orchestrator, or
# the switch off in the webapp only). One log line, then quiet until a restart.
_plugin_reconcile_gone = False


def _reset_plugin_reconcile_state() -> None:
    global _last_plugin_reconcile, _plugin_reconcile_task, _plugin_reconcile_gone
    _last_plugin_reconcile = 0.0
    _plugin_reconcile_task = None
    _plugin_reconcile_gone = False


async def _post_job_queue_reconcile(cm) -> None:
    """Post the set of projects with a live scan so the webapp can close finished
    'running' JobQueue rows (Scan Queue C-6). Best-effort; never raises."""
    key = _webapp_internal_key()
    if not key or cm is None:
        return
    try:
        active = sorted(cm.active_scan_projects())
    except Exception as e:  # noqa: BLE001
        logger.warning("[jobDispatcher] could not enumerate active projects: %s", e)
        return
    await asyncio.to_thread(
        _webapp_request, f"{_webapp_base()}/api/internal/job-queue/reconcile", key,
        "POST", {"activeProjects": active}, 15.0, "jobDispatcher",
    )


async def _maybe_run_traffic_maintenance() -> None:
    """POST /api/traffic/maintenance at most once per TTL (C-10). Best-effort."""
    global _last_traffic_maintenance
    import time
    now = time.monotonic()
    if now - _last_traffic_maintenance < TRAFFIC_MAINTENANCE_INTERVAL_S:
        return
    _last_traffic_maintenance = now
    key = _webapp_internal_key()
    if not key:
        return
    await asyncio.to_thread(
        _webapp_request, f"{_webapp_base()}/api/traffic/maintenance", key,
        "POST", {}, 30.0, "trafficMaintenance",
    )


async def _maybe_prune_mcp_tokens() -> None:
    """POST /api/internal/mcp-tokens/prune at most once per TTL. Best-effort."""
    global _last_mcp_token_prune
    import time
    now = time.monotonic()
    if now - _last_mcp_token_prune < MCP_TOKEN_PRUNE_INTERVAL_S:
        return
    _last_mcp_token_prune = now
    key = _webapp_internal_key()
    if not key:
        return
    await asyncio.to_thread(
        _webapp_request, f"{_webapp_base()}/api/internal/mcp-tokens/prune", key,
        "POST", {}, 30.0, "mcpTokenPrune",
    )


def _post_status(url: str, key: str, timeout: float) -> Optional[int]:
    """Blocking POST with the internal key; the HTTP status, or None when unreachable.
    request_json cannot tell a 404 from an outage, which the reconcile tick must."""
    req = urllib.request.Request(url, data=b"{}", method="POST",
                                 headers={"x-internal-key": key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read()
            return getattr(r, "status", 200)
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:  # noqa: BLE001 - a worker must never die on I/O
        return None


async def _post_plugin_reconcile(key: str) -> None:
    global _plugin_reconcile_gone
    url = f"{_webapp_base()}/api/internal/plugins/reconcile"
    status = await asyncio.to_thread(_post_status, url, key, 60.0)
    if status == 404:
        if not _plugin_reconcile_gone:
            logger.warning("[plugins] reconcile: the webapp has no reconcile route (an older image); "
                           "not asking again until the orchestrator restarts")
        _plugin_reconcile_gone = True
    elif status is None or status >= 300 and status != 202:
        logger.debug("[plugins] reconcile: the webapp answered %s; retried at the next interval", status)


async def _maybe_reconcile_plugins() -> None:
    """Starts POST /api/internal/plugins/reconcile at most once per interval, as a background
    task never awaited here: the reaper awaits each step, and the same loop releases governor
    reservations and dispatches scans (RV-16)."""
    global _last_plugin_reconcile, _plugin_reconcile_task
    if _plugin_reconcile_gone:
        return
    if _plugin_reconcile_task is not None and not _plugin_reconcile_task.done():
        return
    now = time.monotonic()
    if _last_plugin_reconcile and now - _last_plugin_reconcile < PLUGIN_RECONCILE_INTERVAL_S:
        return
    _last_plugin_reconcile = now
    key = _webapp_internal_key()
    if not key:
        return
    _plugin_reconcile_task = asyncio.create_task(_post_plugin_reconcile(key))


async def _ai_attack_reaper():
    """Periodically release Ollama leases from finished-but-unpolled runs."""
    try:
        while True:
            await asyncio.sleep(AI_ATTACK_REAP_INTERVAL_S)
            if container_manager:
                try:
                    await container_manager.reap_ai_attack()
                except Exception as e:
                    logger.warning(f"AI attack reaper iteration failed: {e}")
                try:
                    await container_manager.reap_codefix_sandboxes()
                except Exception as e:
                    logger.warning(f"CodeFix sandbox reaper iteration failed: {e}")
                # Memory governor (Part 1): advance stale scan statuses from Docker,
                # then release reservations for finished/dead scans so the ledger
                # never leaks budget (even for scans whose UI never polled).
                try:
                    await container_manager.refresh_all_scan_states()
                    released = container_manager.reconcile_reservations()
                    if released:
                        logger.info(f"[governor] reconciled {released} stale scan reservation(s)")
                except Exception as e:
                    logger.warning(f"Reservation reconcile iteration failed: {e}")
                # Scan Queue: tell the webapp which projects still have a live scan
                # (C-6), then fire one dispatch tick — capacity just freed is exactly
                # when a queued job can move.
                try:
                    await _post_job_queue_reconcile(container_manager)
                except Exception as e:
                    logger.warning(f"[jobDispatcher] reconcile post failed: {e}")
                try:
                    await run_one_dispatch_tick(container_manager)
                except Exception as e:
                    logger.warning(f"[jobDispatcher] post-reconcile dispatch failed: {e}")
                try:
                    await _maybe_run_traffic_maintenance()
                except Exception as e:
                    logger.warning(f"traffic maintenance failed: {e}")
                try:
                    await _maybe_prune_mcp_tokens()
                except Exception as e:
                    logger.warning(f"mcp token prune failed: {e}")
                try:
                    await _maybe_reconcile_plugins()
                except Exception as e:
                    logger.warning(f"[plugins] reconcile tick failed: {e}")
    except asyncio.CancelledError:
        pass


def _fetch_capture_config(url: str, key: str):
    """Blocking GET of the global TrafficMind capture config from the webapp (the
    DB owner). Returns the parsed dict, or None on any non-200 / error so the caller
    keeps the last-good file rather than clobbering it with a relaxed policy."""
    import urllib.request
    req = urllib.request.Request(url, headers={"x-internal-key": key})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            if getattr(r, "status", 200) != 200:
                return None
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def _ensure_spool_shared(path: str) -> None:
    """Make the shared spool volume writable by the capture containers' non-root uid.

    This orchestrator is the FIRST and only always-on mounter of the `capture_spool`
    named volume (it publishes .capture-config.json there), and it runs as root
    while capture-proxy / traffic-ingest run as uid 10001 with a read-only rootfs.
    Docker applies an image's directory ownership to a named volume only while that
    volume is still EMPTY, so the moment this reconciler writes the config file the
    volume becomes non-empty and stays root:root 0755 forever. The capture
    containers then cannot mkdir /spool/.tmp or /spool/.rejected and crash-loop
    under restart=unless-stopped (issue #159).

    Widening the mount point to 0777 here is the same cross-uid sharing already
    applied to the bodies store by both capture entrypoints. It is an internal
    volume holding no secrets: the spool records carry an opaque ctx tag, and the
    proxy is credential-free by construction. Idempotent, so it also repairs
    volumes already broken in the field on the next orchestrator restart.
    """
    try:
        os.makedirs(path, exist_ok=True)
        if (os.stat(path).st_mode & 0o777) != 0o777:
            os.chmod(path, 0o777)
    except OSError as e:
        logger.warning("could not normalise spool dir %s (capture may fail): %s", path, e)


def _atomic_write(path: str, text: str) -> None:
    d = os.path.dirname(path) or "."
    _ensure_spool_shared(d)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)  # atomic rename; the proxy sees whole-file or nothing


async def _capture_config_reconcile():
    """DB -> file reconciler (single source of truth = the DB / TrafficMind).

    Polls the webapp for the global capture config and materialises it to the shared
    spool volume as `/spool/.capture-config.json`; the credential-free, target-facing
    proxy hot-reloads that file. Running continuously means ANY proxy start path
    (orchestrator spawn, a stray `docker compose up`, a manual restart) converges to
    the DB truth within one interval — drift becomes structurally impossible. The
    proxy never touches the DB; env in the proxy is only its fail-closed cold-start
    default before the first file appears."""
    base = os.environ.get("WEBAPP_API_URL", "http://webapp:3000").rstrip("/")
    url = f"{base}/api/internal/capture-config"
    key = os.environ.get("INTERNAL_API_KEY", "")
    path = os.environ.get("CAPTURE_CONFIG_FILE", "/spool/.capture-config.json")
    interval = float(os.environ.get("CAPTURE_CONFIG_RECONCILE_SEC", "5") or 5)
    # Repair the shared mount point up front, not just on the first write: if the
    # webapp is unreachable at boot we never write, yet the operator may still
    # toggle capture on and spawn the (non-root) proxy against a root-owned volume.
    _ensure_spool_shared(os.path.dirname(path) or "/spool")
    last = None
    while True:
        try:
            cfg = await asyncio.to_thread(_fetch_capture_config, url, key)
            if cfg is not None:
                # A2 rides this same fetch: the recon container needs the
                # operator's incident-match ignore list, and this loop is already
                # the one place that reads it from the DB. Stashed on the manager
                # and injected at spawn, exactly like the egress policy reaches
                # the proxy. Empty = "use the shipped provider list".
                if container_manager is not None:
                    container_manager.sca_intel_ignore_suffixes = str(
                        cfg.get("sca_intel_ignore_suffixes") or "")
                payload = json.dumps(cfg, separators=(",", ":"), sort_keys=True)
                # Rewrite when the DB payload changed OR the file went missing out of
                # band (deleted volume, fresh mount) — the latter keeps the proxy from
                # being stranded fail-closed just because the payload never changes.
                if payload != last or not os.path.exists(path):
                    await asyncio.to_thread(_atomic_write, path, payload)
                    last = payload
                    logger.info(
                        "capture-config reconciled -> %s (source=%s block_private=%s enabled=%s)",
                        path, cfg.get("source"),
                        cfg.get("egress", {}).get("block_private"), cfg.get("enabled"))
        except Exception as e:  # never let the reconciler die
            logger.warning("capture-config reconcile error (keeping last file): %s", e)
        await asyncio.sleep(interval)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and cleanup resources"""
    global container_manager, local_llm_manager
    logger.info("Starting Recon Orchestrator...")
    container_manager = ContainerManager(recon_image=RECON_IMAGE, gvm_image=GVM_IMAGE, github_hunt_image=GITHUB_HUNT_IMAGE, trufflehog_image=TRUFFLEHOG_IMAGE, ai_attack_image=AI_ATTACK_SURFACE_IMAGE, supply_chain_image=SUPPLY_CHAIN_IMAGE)
    # Share the orchestrator's docker client so the LLM lifecycle uses the same daemon.
    local_llm_manager = LocalLlmManager(client=container_manager.client)
    # The AI Attack Surface lifecycle ref-counts an Ollama judge lease through it.
    container_manager.local_llm_manager = local_llm_manager
    # CodeFix build sandbox (T6/E10): host path of the shared cypherfix-work volume.
    container_manager.codefix_work_host_base = CODEFIX_WORK_PATH
    # Auto-detected graph_db host path for every spawned scan container's
    # /app/graph_db bind. Empty => container_manager falls back to the legacy
    # sibling-derivation guess (and refuses to shadow a baked-in copy with it).
    container_manager.graph_db_host_path = GRAPH_DB_PATH
    # Auto-detected recon_settings host path. Empty => the spawned scan uses the
    # registry baked into its image rather than the host's, which is stale rather
    # than absent, so the scan still starts.
    container_manager.recon_settings_host_path = RECON_SETTINGS_PATH
    # Host path of the recon dir, used by the sca-intel refresh sidecar to derive
    # supply_chain_common's host path (it runs off the scan-spawn path and so has
    # no recon_path argument of its own).
    container_manager.recon_host_path = RECON_PATH
    # Host path of scanners/scan_targets, the only directory a TruffleHog scan
    # container may read from disk. Resolved from the orchestrator's OWN mount
    # (never a hardcoded or operator-typed path): compose binds the folder here,
    # so Docker reports its host source. Unresolvable => not mounted, and the
    # local-fixture sources find an empty directory rather than a guessed one.
    container_manager.trufflehog_scan_targets = _host_mounts.get("/app/scan_targets", "")
    # Copies of target JS a JS Recon run left behind (its container was killed
    # or crashed); a live, re-adopted run keeps its own.
    await container_manager._run_blocking(container_manager.sweep_trufflehog_stages)
    reaper = asyncio.create_task(_ai_attack_reaper())
    capture_reconciler = asyncio.create_task(_capture_config_reconcile())
    # Scan Timeline (Section 7.2): the scheduler worker lives here because the
    # orchestrator owns admission + the spawn. It only ticks; the webapp performs
    # the run through the same start path a manual scan uses.
    scan_scheduler = asyncio.create_task(scan_scheduler_loop(lambda: container_manager))
    # Scan Queue (Phase 2): the dispatcher worker lives here too — same reason as
    # the scheduler (the orchestrator owns admission + the spawn). It peeks the
    # queue, applies its own ceiling, and asks the webapp to run each job that fits.
    job_dispatcher = asyncio.create_task(job_dispatcher_loop(lambda: container_manager))
    yield
    logger.info("Shutting down Recon Orchestrator...")
    reaper.cancel()
    capture_reconciler.cancel()
    scan_scheduler.cancel()
    job_dispatcher.cancel()
    if local_llm_manager:
        local_llm_manager.shutdown()
    await container_manager.cleanup()


app = FastAPI(
    title="RedAmon Recon Orchestrator",
    description="Container orchestration service for recon processes",
    version=VERSION,
    lifespan=lifespan,
)

# CORS middleware for webapp access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------------------------------
# Inbound API authentication (V1-auth).
#
# The orchestrator holds the real Docker socket and is the privileged component.
# Network isolation already stops bridge peers (the worker) from reaching it, but
# a host-net peer (a compromised recon container) shares the host loopback and can
# still reach 127.0.0.1:8010. This middleware requires a shared secret on every
# request so only the webapp (which holds ORCHESTRATOR_API_KEY) can drive the API.
#
# The key is deliberately distinct from INTERNAL_API_KEY: the recon/scan containers
# are handed INTERNAL_API_KEY, so reusing it would let a compromised recon container
# authenticate. ORCHESTRATOR_API_KEY is shared only with the webapp.
#
# Fail-closed: if the key is unset, every non-exempt request is rejected.
# --------------------------------------------------------------------------
ORCHESTRATOR_API_KEY = os.environ.get("ORCHESTRATOR_API_KEY", "")


@app.middleware("http")
async def require_orchestrator_key(request: Request, call_next):
    # /health is polled unauthenticated by the Docker healthcheck; CORS preflight
    # (OPTIONS) carries no custom headers and is handled by the CORS middleware.
    # The decision lives in auth.is_orchestrator_request_authorized (unit-tested).
    if is_orchestrator_request_authorized(
        request.url.path,
        request.method,
        request.headers.get("X-Orchestrator-Key", ""),
        ORCHESTRATOR_API_KEY,
    ):
        return await call_next(request)
    return JSONResponse(
        status_code=401,
        content={"detail": "Unauthorized: missing or invalid X-Orchestrator-Key"},
    )


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        version=VERSION,
        running_recons=container_manager.get_running_count() if container_manager else 0,
        running_gvm_scans=container_manager.get_gvm_running_count() if container_manager else 0,
        running_github_hunts=container_manager.get_github_hunt_running_count() if container_manager else 0,
        running_trufflehog_scans=container_manager.get_trufflehog_running_count() if container_manager else 0,
        running_ai_attack_scans=container_manager.get_ai_attack_running_count() if container_manager else 0,
        gvm_available=container_manager.is_gvm_available() if container_manager else False,
        trufflehog_available=container_manager.is_trufflehog_available() if container_manager else False,
    )


@app.get("/system/scan-envelope")
async def system_scan_envelope(scan_type: str = "full_recon"):
    """Scan Timeline (Section 7.3): the RAM envelope a scan of `scan_type` reserves
    and the total pool available to scans, so the webapp can do the STATIC schedule
    feasibility check at creation time. Read-only, no reservation is taken — the
    authoritative gate stays `try_admit` at execution."""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    ledger = container_manager.ledger
    return {
        "scan_type": scan_type,
        "envelope_bytes": ledger.envelope_for(scan_type),
        "scan_pool_bytes": ledger.scan_pool(),
        "remaining_for_new_bytes": ledger.remaining_for_new(),
    }


@app.get("/system/stats")
async def system_stats():
    """Live host/VM memory + CPU for the governor UI (top-bar chip, bottom-bar
    htop meters). Read-only, no secrets. `remaining_for_new` is the RAM actually
    available to admit a new scan (Part 5)."""
    import resource_governor as rg
    # Read-only: no reconcile side-effect here (the reaper owns release timing);
    # committed may lag by up to one reaper interval, which is fine for a display.
    mem = container_manager.ledger.snapshot() if container_manager else {}
    disk = rg.disk_stats()
    return {
        "mem": mem,
        "cpu": {"percent": round(rg.cpu_percent(), 1), "cores": rg.cpu_cores()},
        "disk": ({"total": disk[0], "free": disk[1]} if disk else None),
        "governor_enabled": rg.governor_enabled(),
    }


"""Statuses that mean "this scan still occupies the host". Everything else is
terminal (completed / error) or means nothing is there (idle)."""
_ACTIVE_SCAN_STATUSES = {"starting", "running", "paused", "stopping"}


@app.get("/system/active-scans")
async def system_active_scans():
    """Every in-flight scan the orchestrator is holding, across ALL kinds.

    The per-kind `/{kind}/{project_id}/status` endpoints answer one project and one
    kind at a time, which is why a directly-started GVM or TruffleHog scan was
    invisible to any cross-project view: only full recon leaves a DB row
    (`scan_jobs`), and only queued work leaves a `job_queue` row. This is the
    single read that makes "what is running right now" answerable for every kind.

    Read-only, no secrets, no reservation side-effect.
    """
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    cm = container_manager
    out: list[dict] = []

    def add(kind: str, state, run_id: str = "", tool_id: str = ""):
        status = getattr(state, "status", None)
        status = getattr(status, "value", status)
        if status not in _ACTIVE_SCAN_STATUSES:
            return
        started = getattr(state, "started_at", None)
        out.append({
            "kind": kind,
            "project_id": getattr(state, "project_id", ""),
            "run_id": run_id,
            "tool_id": tool_id,
            "status": status,
            "current_phase": getattr(state, "current_phase", None),
            # Domain batch: phases restart per group, so the outer progress is
            # what tells "still on group 1" from "now on group 3".
            "current_group": getattr(state, "current_group", None),
            "group_number": getattr(state, "group_number", None),
            "total_groups": getattr(state, "total_groups", None),
            "started_at": started.isoformat() if started else None,
        })

    # One state per project.
    for state in cm.running_states.values():
        add("full_recon", state)
    for state in cm.gvm_states.values():
        add("gvm", state)
    for state in cm.github_hunt_states.values():
        add("github_hunt", state)
    for state in cm.supply_chain_states.values():
        add("supply_chain", state)

    # Run-keyed: {project_id: {run_id: state}}.
    for runs in cm.trufflehog_states.values():
        for source, state in runs.items():
            # run_id == source: the queue and the activity UI both key on it, and
            # a project-keyed entry here would make N parallel runs look like one,
            # over-admitting the queue while containers are still up.
            add("trufflehog", state, run_id=source, tool_id=source)
    for runs in cm.partial_recon_states.values():
        for run_id, state in runs.items():
            add("partial_recon", state, run_id=run_id, tool_id=getattr(state, "tool_id", ""))
    for runs in cm.ai_attack_states.values():
        for run_id, state in runs.items():
            add("ai_attack", state, run_id=run_id, tool_id=getattr(state, "tool", ""))

    return {"scans": out}


@app.get("/local-llm/status")
async def local_llm_status():
    """Current state of the on-demand local LLM (Ollama) judge service.

    Part of the AI Attack Surface layer (Step 1). Read-only: does not change
    the lease count or start/stop the container.
    """
    if not local_llm_manager:
        raise HTTPException(status_code=503, detail="Local LLM manager not initialized")
    status = await asyncio.to_thread(local_llm_manager.status)
    return status.to_dict()


@app.post("/local-llm/ensure")
async def local_llm_ensure(model: Optional[str] = None):
    """Acquire a lease and bring the local LLM up (spawn + pull model if needed).

    Ref-counted: each call increments the lease. Failure-soft -- always returns
    a status (available=false + warning on any failure), never errors out.
    First-ever call may take minutes to pull the model into the persistent volume.
    """
    if not local_llm_manager:
        raise HTTPException(status_code=503, detail="Local LLM manager not initialized")
    status = await asyncio.to_thread(local_llm_manager.ensure_up, model)
    return status.to_dict()


@app.post("/local-llm/release")
async def local_llm_release():
    """Release one lease. When the last lease is freed the container is stopped
    and removed; the model-weights volume (redamon_llm_models) persists."""
    if not local_llm_manager:
        raise HTTPException(status_code=503, detail="Local LLM manager not initialized")
    status = await asyncio.to_thread(local_llm_manager.release)
    return status.to_dict()


# --------------------------------------------------------------------------
# CodeFix build sandbox (T6/E10)
#
# The agent (via the webapp passthrough) drives an ephemeral, secret-free,
# network-isolated build sandbox for the UNTRUSTED clone+build step of CypherFix.
# All three routes are protected by the orchestrator-key middleware (only the
# webapp holds the key), so the agent reaches them only through the webapp.
# --------------------------------------------------------------------------


@app.post("/codefix-sandbox/{job_id}/start")
async def codefix_sandbox_start(job_id: str):
    if not container_manager:
        raise HTTPException(status_code=503, detail="Container manager not initialized")
    if not container_manager.codefix_work_host_base:
        raise HTTPException(status_code=503, detail="CodeFix sandbox feature not configured (work volume not mounted)")
    try:
        return await asyncio.to_thread(container_manager.start_codefix_sandbox, job_id)
    except Exception as e:
        logger.error(f"[codefix] start failed for {job_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start CodeFix sandbox: {e}")


@app.post("/codefix-sandbox/{job_id}/exec")
async def codefix_sandbox_exec(job_id: str, request: Request):
    if not container_manager:
        raise HTTPException(status_code=503, detail="Container manager not initialized")
    body = await request.json()
    command = body.get("command")
    if not command:
        raise HTTPException(status_code=400, detail="Missing 'command'")
    timeout = int(body.get("timeout", 600))
    return await container_manager.exec_codefix_sandbox(job_id, command, timeout)


@app.post("/codefix-sandbox/{job_id}/stop")
async def codefix_sandbox_stop(job_id: str):
    if not container_manager:
        raise HTTPException(status_code=503, detail="Container manager not initialized")
    await asyncio.to_thread(container_manager.stop_codefix_sandbox, job_id)
    return {"job_id": job_id, "stopped": True}


# ---------------------------------------------------------------------------
# HTTP traffic capture proxy lifecycle (Phase 1, plan §8.4). Toggled on/off by
# the webapp when the Global Settings capture flag flips. X-Orchestrator-Key
# protected like every other route; loopback-bound on orchestrator-net.
# ---------------------------------------------------------------------------
@app.post("/capture-proxy/start")
async def capture_proxy_start(config: Optional[CaptureProxyConfig] = None):
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    try:
        return await container_manager.start_capture_proxy(
            config.model_dump(exclude_none=True) if config else None
        )
    except Exception as e:
        logger.error(f"Error starting capture proxy: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/capture-proxy/stop")
async def capture_proxy_stop():
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    try:
        return await container_manager.stop_capture_proxy()
    except Exception as e:
        logger.error(f"Error stopping capture proxy: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/capture-proxy/status")
async def capture_proxy_status():
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    return await container_manager.capture_proxy_status()


@app.get("/defaults")
async def get_defaults():
    """
    Get default project settings from recon module.

    Returns DEFAULT_SETTINGS dict with camelCase keys for frontend compatibility.
    """
    import sys
    from pathlib import Path

    # Add recon path to sys.path to import project_settings
    recon_path = Path("/app/recon")
    if str(recon_path) not in sys.path:
        sys.path.insert(0, str(recon_path))

    try:
        # Import DEFAULT_SETTINGS from project_settings.py
        from project_settings import DEFAULT_SETTINGS

        # Runtime-only settings that must NOT reach the frontend or the database.
        #
        # DERIVED from the recon settings registry rather than hand-listed. The
        # list this replaced had drifted in both directions: it named FOFA_EMAIL,
        # which no longer exists, while a key added to DEFAULT_SETTINGS without
        # being added here would be sent to the browser as a project default and
        # then rejected by Prisma as an unknown column on save.
        #
        # Three classes, all of which the registry already records:
        #   source: user_account   an API credential fetched per scan
        #   source: internal       a value the pipeline computes, not a setting
        #   source: project_relation  the authenticated session, deliberately a
        #                          relation so it never reaches the browser
        #
        # Deriving it also fixes a documented workaround: the ProjectForm's
        # preset-apply path skips any /defaults key that is not already in the
        # form, because this payload carried settings that are NOT Project
        # columns (takeoverCnameValidationEnabled among them) and writing one
        # back made the save fail with a Prisma "Unknown argument" error. Those
        # keys are exactly `source: internal`, so they are gone from the payload
        # now rather than filtered out downstream.
        try:
            from settings_registry import runtime_only as _registry_runtime_only
        except ImportError:  # pragma: no cover - the repo layout
            from recon.settings_registry import runtime_only as _registry_runtime_only

        RUNTIME_ONLY_KEYS = set(_registry_runtime_only())
        # Plus the five the registry cannot infer. Each is a Project COLUMN, so
        # it is not runtime-only in the registry's sense; it is simply not a
        # global default. The rest of the targeting block legitimately has one:
        # an empty subdomain list, and the shipped `_redamon-verify` TXT prefix.
        RUNTIME_ONLY_KEYS.update({
            "USER_ID",          # the owner, set by the loader from the API response
            "TARGET_DOMAIN",    # per-project, provided by the operator
            "DOMAIN_BATCH_MODE",
            "DOMAIN_BATCH_GROUPS",
            # Generated per project at creation. The form POSTs back what this
            # payload seeds, so a value here became every new project's token.
            "OWNERSHIP_TOKEN",
        })


        # The column name for each runtime key, from the registry rather than
        # from a snake-to-camel conversion.
        #
        # The conversion cannot recover an intercap, and nine settings have one:
        # CRIMINALIP_ENABLED is the column `criminalIpEnabled`, not
        # `criminalipEnabled`. Those nine have therefore NEVER reached a new
        # project form, because the ProjectForm only applies a /defaults key it
        # already has - which is also why nobody noticed. The registry knows the
        # real mapping, so it answers.
        try:
            from settings_registry import by_runtime_key as _registry_by_runtime_key
        except ImportError:  # pragma: no cover - the repo layout
            from recon.settings_registry import by_runtime_key as _registry_by_runtime_key

        _column_for = {k: v["column"] for k, v in _registry_by_runtime_key().items()}

        def to_camel_case(snake_str: str) -> str:
            """Fallback for a key the registry has never heard of."""
            components = snake_str.lower().split('_')
            return components[0] + ''.join(x.title() for x in components[1:])

        camel_case_defaults = {
            _column_for.get(k) or to_camel_case(k): v
            for k, v in DEFAULT_SETTINGS.items()
            if k not in RUNTIME_ONLY_KEYS
        }

        # An engagement LIMIT has no global default: it is a property of one
        # engagement, not of the installation. Emitting one is worse than
        # useless, because the ProjectForm's preset-apply path resets every form
        # field that appears in this payload BEFORE applying the preset - so a
        # roeGlobalMaxRps: 0 here silently zeroes a configured rate ceiling and
        # empties the exclusion list on every preset apply.
        #
        # Filtered by COLUMN and derived from the registry group, so a newly
        # classified limit is excluded the day it is classified. One helper,
        # shared with the agent's own /defaults, so the two cannot disagree.
        from recon_settings.engagement import strip_engagement_limits

        strip_engagement_limits(camel_case_defaults)

        # Also import GVM scan defaults (use importlib to avoid module name collision
        # with recon's project_settings already cached above)
        try:
            import importlib.util
            gvm_settings_path = Path("/app/gvm_scan/project_settings.py")
            spec = importlib.util.spec_from_file_location("gvm_project_settings", gvm_settings_path)
            gvm_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(gvm_mod)

            # Convert SCAN_CONFIG → gvmScanConfig (prefix with 'gvm_')
            def to_gvm_camel(snake_str: str) -> str:
                prefixed = f"gvm_{snake_str}"
                components = prefixed.lower().split('_')
                return components[0] + ''.join(x.title() for x in components[1:])

            gvm_defaults = {to_gvm_camel(k): v for k, v in gvm_mod.DEFAULT_GVM_SETTINGS.items()}
            camel_case_defaults.update(gvm_defaults)
        except Exception:
            logger.warning("GVM project_settings not found, skipping GVM defaults")

        # Also import GitHub Secret Hunt defaults
        try:
            import importlib.util
            gh_settings_path = Path("/app/github_secret_hunt/project_settings.py")
            spec = importlib.util.spec_from_file_location("github_hunt_project_settings", gh_settings_path)
            gh_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(gh_mod)

            # Convert GITHUB_ACCESS_TOKEN → githubAccessToken (already github-prefixed)
            def to_gh_camel(snake_str: str) -> str:
                components = snake_str.lower().split('_')
                return components[0] + ''.join(x.title() for x in components[1:])

            gh_defaults = {to_gh_camel(k): v for k, v in gh_mod.DEFAULT_GITHUB_SETTINGS.items()}
            camel_case_defaults.update(gh_defaults)
        except Exception:
            logger.warning("GitHub Hunt project_settings not found, skipping GitHub defaults")

        return camel_case_defaults
    except ImportError as e:
        logger.error(f"Failed to import project_settings: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to load defaults: {e}")
    except Exception as e:
        logger.error(f"Error getting defaults: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/recon/{project_id}/start", response_model=ReconState)
async def start_recon(project_id: str, request: ReconStartRequest):
    """
    Start a new recon process for a project.

    - Checks RoE time window constraints
    - Checks if recon is already running
    - Starts new container with project settings from webapp API
    - Returns current state
    """
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    # Guardrail / RoE pre-flight: fetch project settings and verify. Fails
    # CLOSED — a fetch failure refuses the start (503) rather than proceeding
    # unverified (mcp_plan.md P0-1). Unconditional: the fetch goes to the trusted
    # webapp base, never to the client's webapp_api_url, so an empty value in the
    # request is no reason to skip the one check that cannot be switched off.
    project = _fetch_project_for_preflight(project_id)

    # Hard guardrail: deterministic, non-disableable — always blocks
    # government/public domains.
    if not project.get('ipMode', False):
        from hard_guardrail import first_hard_blocked
        from batch_scope import guardrail_targets
        # Domain batch has NO targetDomain: its targets are the listed hosts and
        # the derived group roots. Checking targetDomain alone would hand every
        # batch a free pass through the one control that cannot be switched off,
        # so check whatever this project actually scans.
        targets = guardrail_targets(project)
        from batch_scope import scope_groups
        if 'scopeGroups' in project and not scope_groups(project):
            # The webapp derived no valid group: the stored scope is refused by
            # the current rules (a public suffix, a malformed entry).
            raise HTTPException(
                status_code=400,
                detail="This project's saved scope is not valid under the current rules. "
                       "Edit the target and save it before scanning.",
            )
        if project.get('domainBatchMode', False) and not targets:
            # Fail CLOSED: batch mode with nothing to check means the
            # groups are missing or malformed, not that there is
            # nothing to guard.
            raise HTTPException(
                status_code=400,
                detail="Domain batch project has no valid domain groups. "
                       "Re-save the project's hostname list before scanning.",
            )

        hit = first_hard_blocked(targets)
        if hit:
            raise HTTPException(status_code=403, detail=f"Hard guardrail: {hit[1]}")

    _check_roe_time_window(project)

    try:
        state = await container_manager.start_recon(
            project_id=project_id,
            user_id=request.user_id,
            webapp_api_url=_spawned_webapp_url(),
            recon_path=RECON_PATH,
            custom_templates_path=CUSTOM_TEMPLATES_PATH,
            scan_mode=request.mode,
        )
    except ValueError as e:
        raise _value_error_http(e)
    except Exception as e:
        logger.error(f"Error starting recon: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    _refuse_failed_spawn(state)
    return state


@app.get("/recon/{project_id}/status", response_model=ReconState)
async def get_recon_status(project_id: str):
    """Get current status of a recon process"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    return await container_manager.get_status(project_id)


@app.post("/recon/{project_id}/stop", response_model=ReconState)
async def stop_recon(project_id: str, graceful: bool = True):
    """Stop a running recon process.

    Answers `stopping` at once: the run lands its queued graph writes and
    applies the mute rules within RECON_STOP_GRACE_S, then reads `idle`.
    `?graceful=false` kills it at once and answers when it is gone; the project
    delete passes it, so a draining run never writes into a deleted project.
    """
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.stop_recon(project_id, graceful=graceful)
    return state


@app.post("/recon/{project_id}/pause", response_model=ReconState)
async def pause_recon(project_id: str):
    """Pause a running recon process"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.pause_recon(project_id)
    return state


@app.post("/recon/{project_id}/resume", response_model=ReconState)
async def resume_recon(project_id: str):
    """Resume a paused recon process, inside the RoE time window only.

    A scan paused before the window closed would otherwise carry on outside
    it, where a new start is refused. The check fails closed like a start's
    (503 when the webapp cannot be reached), and a refused resume leaves the
    scan paused.
    """
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.get_status(project_id)
    if state.status != ReconStatus.PAUSED:
        return state
    project = _fetch_project_for_preflight(project_id, refusal="The scan stays paused.")
    _check_roe_time_window(project)

    state = await container_manager.resume_recon(project_id)
    return state


@app.get("/recon/{project_id}/logs")
async def stream_logs(project_id: str):
    """
    Stream logs from a recon container using Server-Sent Events.

    Events are sent as JSON with format:
    {
        "log": "...",
        "timestamp": "...",
        "phase": "...",
        "phase_number": 1,
        "is_phase_start": false,
        "level": "info"
    }
    """
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    # Check if there's a running container
    state = await container_manager.get_status(project_id)
    if state.status == ReconStatus.IDLE:
        raise HTTPException(status_code=404, detail="No recon process found for this project")

    async def event_generator():
        """Generate SSE events from container logs"""
        try:
            async for event in container_manager.stream_logs(project_id):
                yield {
                    "event": "log",
                    "data": json.dumps({
                        "log": event.log,
                        "timestamp": event.timestamp.isoformat(),
                        "phase": event.phase,
                        "phaseNumber": event.phase_number,
                        "isPhaseStart": event.is_phase_start,
                        "level": event.level,
                        # Domain batch outer progress; null for every other run.
                        "groupNumber": event.group_number,
                        "totalGroups": event.total_groups,
                        "currentGroup": event.current_group,
                        "isGroupStart": event.is_group_start,
                    }),
                }
        except Exception as e:
            logger.error(f"Error streaming logs: {e}")
            yield {
                "event": "error",
                "data": json.dumps({"error": str(e)}),
            }

        # Send completion event
        final_state = await container_manager.get_status(project_id)
        yield {
            "event": "complete",
            "data": json.dumps({
                "status": final_state.status.value,
                "completedAt": final_state.completed_at.isoformat() if final_state.completed_at else None,
                "error": final_state.error,
            }),
        }

    return EventSourceResponse(event_generator())


# =============================================================================
# Partial Recon Endpoints
# =============================================================================


@app.post("/recon/{project_id}/partial", response_model=PartialReconState)
async def start_partial_recon(project_id: str, request: PartialReconStartRequest):
    """
    Start a partial recon run for a specific tool.

    Spawns a lightweight recon container that runs only the requested tool
    (e.g., SubdomainDiscovery) and updates the graph with results.
    """
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    from batch_scope import (
        PartialScopeError,
        filter_partial_user_input,
        narrow_partial_roots,
        partial_project_roots,
        validate_partial_overrides,
    )

    # The pre-flight is unconditional: the roots come from the project, so a
    # start that cannot fetch it cannot know what it may scan.
    if not request.webapp_api_url:
        raise HTTPException(status_code=400, detail="webapp_api_url is required.")
    try:
        overrides = validate_partial_overrides(request.settings_overrides)
        project = _fetch_project_for_preflight(project_id)
        roots = narrow_partial_roots(
            partial_project_roots(project, project_id), request.graph_inputs)
    except PartialScopeError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)

    # Hard guardrail on every host and root of the project, as for a full recon:
    # a partial run reaches hosts beyond the roots it is narrowed to. IPs are not
    # hard-blocked (hard_guardrail.is_hard_blocked), and IP mode's root is a
    # synthetic name.
    if not project.get('ipMode', False):
        from hard_guardrail import first_hard_blocked
        from batch_scope import guardrail_targets
        names = guardrail_targets(project)
        hit = first_hard_blocked(names + [r for r in roots if r not in names])
        if hit:
            raise HTTPException(status_code=403, detail=f"Hard guardrail: {hit[1]}")

    _check_roe_time_window(project)

    # What the operator typed passes the same scope rule and guardrail the modal
    # applies, because a queued job or a direct API call never saw the modal.
    user_inputs, user_targets, refused = filter_partial_user_input(
        project, roots, request.user_inputs, request.user_targets)
    if refused:
        logger.warning(f"[{project_id}] partial {request.tool_id}: dropped out-of-scope input: {refused[:20]}")
    typed = bool(request.user_inputs) or any(
        (request.user_targets or {}).get(k) for k in ('subdomains', 'urls', 'ips'))
    kept = bool(user_inputs) or any((user_targets or {}).get(k) for k in ('subdomains', 'urls', 'ips'))
    if typed and not kept and not request.include_graph_targets:
        raise HTTPException(status_code=400, detail=f"No typed target is in this project's scope: {refused[:10]}")

    # Settings, and with them each root's group scope, are fetched by the recon
    # container itself via get_settings() (PROJECT_ID + WEBAPP_API_URL env vars,
    # same as main.py). It rebuilds the groups from that validated copy rather
    # than from anything written here, so the two can never disagree.
    config = {
        "tool_id": request.tool_id,
        "domains": roots,
        # Read by the tools not yet migrated to scope_roots().
        "domain": roots[0],
        "user_inputs": user_inputs,
        "user_targets": user_targets,
        "include_graph_targets": request.include_graph_targets,
        "settings_overrides": overrides,
        "user_id": request.user_id,
        "webapp_api_url": _spawned_webapp_url(),
    }

    try:
        state = await container_manager.start_partial_recon(
            project_id=project_id,
            tool_id=request.tool_id,
            config=config,
            recon_path=RECON_PATH,
            custom_templates_path=CUSTOM_TEMPLATES_PATH,
        )
        logger.info(
            f"Partial recon run {state.run_id}: project {project_id}, "
            f"tool {request.tool_id}, roots {', '.join(roots)}")
    except ValueError as e:
        raise _value_error_http(e)
    except Exception as e:
        logger.error(f"Error starting partial recon: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    _refuse_failed_spawn(state)
    return state


@app.get("/recon/{project_id}/partial/all", response_model=PartialReconListResponse)
async def list_partial_recons(project_id: str):
    """List all partial recon runs for a project"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    runs = await container_manager.get_all_partial_recon_statuses(project_id)
    return PartialReconListResponse(project_id=project_id, runs=runs)


@app.get("/recon/{project_id}/partial/{run_id}/status", response_model=PartialReconState)
async def get_partial_recon_status(project_id: str, run_id: str):
    """Get current status of a specific partial recon run"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    return await container_manager.get_partial_recon_status(project_id, run_id)


@app.post("/recon/{project_id}/partial/{run_id}/stop", response_model=PartialReconState)
async def stop_partial_recon(project_id: str, run_id: str, graceful: bool = True):
    """Stop a specific partial recon run; `stopping` at once, as for /recon/{id}/stop."""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    return await container_manager.stop_partial_recon(project_id, run_id, graceful=graceful)


@app.get("/recon/{project_id}/partial/{run_id}/logs")
async def stream_partial_logs(project_id: str, run_id: str):
    """Stream logs from a specific partial recon container via SSE"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.get_partial_recon_status(project_id, run_id)
    if state.status == PartialReconStatus.IDLE:
        raise HTTPException(status_code=404, detail="No partial recon process found")

    async def event_generator():
        try:
            async for event in container_manager.stream_partial_logs(project_id, run_id):
                yield {
                    "event": "log",
                    "data": json.dumps({
                        "log": event.log,
                        "timestamp": event.timestamp.isoformat(),
                        "phase": event.phase,
                        "phaseNumber": event.phase_number,
                        "isPhaseStart": event.is_phase_start,
                        "level": event.level,
                    }),
                }
        except Exception as e:
            logger.error(f"Error streaming partial recon logs: {e}")
            yield {
                "event": "error",
                "data": json.dumps({"error": str(e)}),
            }

        final_state = await container_manager.get_partial_recon_status(project_id, run_id)
        yield {
            "event": "complete",
            "data": json.dumps({
                "status": final_state.status.value if hasattr(final_state.status, 'value') else final_state.status,
                "completedAt": final_state.completed_at.isoformat() if final_state.completed_at else None,
                "error": final_state.error,
                "stats": final_state.stats,
            }),
        }

    return EventSourceResponse(event_generator())


@app.get("/recon/running")
async def list_running():
    """List all running recon processes"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    running = [
        state for state in container_manager.running_states.values()
        if state.status == ReconStatus.RUNNING
    ]
    return {"running": [s.dict() for s in running]}


@app.delete("/recon/{project_id}/data")
async def delete_recon_data(project_id: str):
    """
    Delete recon output data for a project.

    This endpoint is called when a project is deleted to clean up
    the associated JSON files.
    """
    import os
    from pathlib import Path

    # Build the path to the recon output file
    # Inside the orchestrator container, the output is at /app/recon/output
    output_dir = Path("/app/recon/output")

    deleted_files = []
    errors = []

    # Delete the canonical recon JSON file AND every Domain-batch per-group file
    # (recon_<id>__<domain>.json). Without the glob a batch project leaks one file
    # per domain on every run, forever.
    for path in _recon_output_files(output_dir, project_id):
        try:
            os.remove(path)
            deleted_files.append(str(path))
            logger.info(f"Deleted recon file: {path}")
        except Exception as e:
            errors.append(f"Failed to delete {path}: {e}")
            logger.error(f"Failed to delete recon file: {e}")

    # Also clean up any running state for this project
    if container_manager and project_id in container_manager.running_states:
        del container_manager.running_states[project_id]

    return {
        "success": len(errors) == 0,
        "deleted": deleted_files,
        "errors": errors,
    }


@app.delete("/project/{project_id}/files")
async def delete_project_files(project_id: str):
    """
    Delete all output files for a project (recon, GVM, GitHub hunt).

    Called when a project is deleted to clean up all associated JSON files.
    The orchestrator has write access to all output directories.
    """
    import os
    from pathlib import Path

    files_to_delete = [
        # Canonical recon file plus every Domain-batch per-group file.
        *_recon_output_files(Path("/app/recon/output"), project_id),
        Path("/app/gvm_scan/output") / f"gvm_{project_id}.json",
        Path("/app/github_secret_hunt/output") / f"github_hunt_{project_id}.json",
    ]

    deleted_files = []
    errors = []

    for file_path in files_to_delete:
        if file_path.exists():
            try:
                os.remove(file_path)
                deleted_files.append(str(file_path))
                logger.info(f"Deleted project file: {file_path}")
            except Exception as e:
                errors.append(f"Failed to delete {file_path}: {e}")
                logger.error(f"Failed to delete project file {file_path}: {e}")

    # Clean up any running state for this project
    if container_manager:
        if project_id in container_manager.running_states:
            del container_manager.running_states[project_id]
        if project_id in container_manager.gvm_states:
            del container_manager.gvm_states[project_id]
        if project_id in container_manager.github_hunt_states:
            del container_manager.github_hunt_states[project_id]

    return {
        "success": len(errors) == 0,
        "deleted": deleted_files,
        "errors": errors,
    }


@app.post("/project/{project_id}/artifacts/{artifact_type}")
async def upload_artifact(project_id: str, artifact_type: str, file: UploadFile):
    """
    Upload a scan output artifact (recon, gvm, github_hunt) for a project.

    Used by the import feature to restore scan output JSON files.
    """
    from pathlib import Path

    ALLOWED_TYPES = {
        "recon": Path("/app/recon/output") / f"recon_{project_id}.json",
        "gvm": Path("/app/gvm_scan/output") / f"gvm_{project_id}.json",
        "github_hunt": Path("/app/github_secret_hunt/output") / f"github_hunt_{project_id}.json",
    }

    if artifact_type not in ALLOWED_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid artifact type: {artifact_type}. Allowed: {list(ALLOWED_TYPES.keys())}",
        )

    target_path = ALLOWED_TYPES[artifact_type]

    try:
        content = await file.read()
        # Validate it's valid JSON
        json.loads(content)
        # Ensure parent directory exists
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(content)
        logger.info(f"Uploaded {artifact_type} artifact for project {project_id}: {target_path}")
        return {"success": True, "path": str(target_path), "size": len(content)}
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Uploaded file is not valid JSON")
    except Exception as e:
        logger.error(f"Failed to upload artifact: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# AI Attack Surface Endpoints
# =============================================================================


@app.post("/ai-attack-surface/{project_id}/start", response_model=AiAttackSurfaceState)
async def start_ai_attack_surface(project_id: str, request: AiAttackSurfaceStartRequest):
    """Start an AI Attack Surface job (one tool) against selected AI nodes.

    Brings up the on-demand Ollama judge (ref-counted) and spawns the
    ai_attack_surface_scan container. Launch reuses the partial-recon Run model:
    it runs a tool against the existing graph without re-crawling.
    """
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    if not AI_ATTACK_SURFACE_PATH:
        # A configuration error, not a passing outage: the queue must not
        # retry it as transient, so it carries a code.
        raise HTTPException(
            status_code=503,
            detail={"detail": "AI Attack Surface source not mounted into the orchestrator",
                     "code": "not_configured"},
        )

    run_config = {
        "tool": request.tool,
        "targets": request.targets,
        "bounds": request.bounds,
        "roe_confirmed": request.roe_confirmed,
        "dry_run": request.dry_run,
        "probes": request.probes,
        "strategies": request.strategies,
        "objective": request.objective,
        "target_model": request.target_model,
        "target_purpose": request.target_purpose,
        "api_key": request.api_key,
        "auth_header": request.auth_header,
        "auth_scheme": request.auth_scheme,
        "user_id": request.user_id,
        "webapp_api_url": _spawned_webapp_url(),
    }

    try:
        state = await container_manager.start_ai_attack_surface(
            project_id=project_id,
            user_id=request.user_id,
            webapp_api_url=_spawned_webapp_url(),
            run_config=run_config,
            ai_attack_path=AI_ATTACK_SURFACE_PATH,
        )
        return state
    except ValueError as e:
        raise _value_error_http(e)
    except Exception as e:
        logger.error(f"Error starting AI attack surface: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/ai-attack-surface/{project_id}/all", response_model=AiAttackSurfaceListResponse)
async def list_ai_attack_surface(project_id: str):
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    runs = await container_manager.get_all_ai_attack_surface_statuses(project_id)
    return AiAttackSurfaceListResponse(project_id=project_id, runs=runs)


@app.get("/ai-attack-surface/{project_id}/{run_id}/status", response_model=AiAttackSurfaceState)
async def get_ai_attack_surface_status(project_id: str, run_id: str):
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    return await container_manager.get_ai_attack_surface_status(project_id, run_id)


@app.post("/ai-attack-surface/{project_id}/{run_id}/stop", response_model=AiAttackSurfaceState)
async def stop_ai_attack_surface(project_id: str, run_id: str):
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    return await container_manager.stop_ai_attack_surface(project_id, run_id)


@app.get("/ai-attack-surface/{project_id}/{run_id}/logs")
async def stream_ai_attack_surface_logs(project_id: str, run_id: str):
    """Stream logs from an AI Attack Surface container via SSE."""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.get_ai_attack_surface_status(project_id, run_id)
    if state.status == AiAttackSurfaceStatus.IDLE:
        raise HTTPException(status_code=404, detail="No AI attack surface job found")

    async def event_generator():
        try:
            async for event in container_manager.stream_ai_attack_surface_logs(project_id, run_id):
                yield {
                    "event": "log",
                    "data": json.dumps({
                        "log": event.log,
                        "timestamp": event.timestamp.isoformat(),
                        "phase": event.phase,
                        "phaseNumber": event.phase_number,
                        "isPhaseStart": event.is_phase_start,
                        "level": event.level,
                    }),
                }
        except Exception as e:
            logger.error(f"Error streaming AI attack surface logs: {e}")
            yield {"event": "error", "data": json.dumps({"error": str(e)})}

    return EventSourceResponse(event_generator())


# =============================================================================
# GVM Vulnerability Scan Endpoints
# =============================================================================


@app.post("/gvm/{project_id}/start", response_model=GvmState)
async def start_gvm_scan(project_id: str, request: GvmStartRequest):
    """
    Start a GVM vulnerability scan for a project.

    Requires recon data to already exist for target extraction.
    """
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    # Check that recon data exists
    from pathlib import Path
    recon_file = Path("/app/recon/output") / f"recon_{project_id}.json"
    if not recon_file.exists():
        raise HTTPException(
            status_code=400,
            detail="Recon data required. Run reconnaissance first.",
        )

    try:
        state = await container_manager.start_gvm_scan(
            project_id=project_id,
            user_id=request.user_id,
            webapp_api_url=_spawned_webapp_url(),
            recon_path=RECON_PATH,
            gvm_scan_path=GVM_SCAN_PATH,
        )
        return state
    except ValueError as e:
        raise _value_error_http(e)
    except Exception as e:
        logger.error(f"Error starting GVM scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/gvm/{project_id}/status", response_model=GvmState)
async def get_gvm_status(project_id: str):
    """Get current status of a GVM scan process"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    return await container_manager.get_gvm_status(project_id)


@app.post("/gvm/{project_id}/stop", response_model=GvmState)
async def stop_gvm_scan(project_id: str, ingest: bool = True):
    """Stop a running GVM scan process.

    `?ingest=false` skips writing the stopped run's saved results to the graph;
    the project delete passes it because it clears the graph next.
    """
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.stop_gvm_scan(project_id, ingest=ingest)
    return state


@app.post("/gvm/{project_id}/pause", response_model=GvmState)
async def pause_gvm_scan(project_id: str):
    """Pause a running GVM scan process"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.pause_gvm_scan(project_id)
    return state


@app.post("/gvm/{project_id}/resume", response_model=GvmState)
async def resume_gvm_scan(project_id: str):
    """Resume a paused GVM scan process"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.resume_gvm_scan(project_id)
    return state


@app.get("/gvm/{project_id}/logs")
async def stream_gvm_logs(project_id: str):
    """
    Stream logs from a GVM scanner container using Server-Sent Events.
    """
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.get_gvm_status(project_id)
    if state.status == GvmStatus.IDLE:
        raise HTTPException(status_code=404, detail="No GVM scan found for this project")

    async def event_generator():
        try:
            async for event in container_manager.stream_gvm_logs(project_id):
                yield {
                    "event": "log",
                    "data": json.dumps({
                        "log": event.log,
                        "timestamp": event.timestamp.isoformat(),
                        "phase": event.phase,
                        "phaseNumber": event.phase_number,
                        "isPhaseStart": event.is_phase_start,
                        "level": event.level,
                    }),
                }
        except Exception as e:
            logger.error(f"Error streaming GVM logs: {e}")
            yield {
                "event": "error",
                "data": json.dumps({"error": str(e)}),
            }

        final_state = await container_manager.get_gvm_status(project_id)
        yield {
            "event": "complete",
            "data": json.dumps({
                "status": final_state.status.value,
                "completedAt": final_state.completed_at.isoformat() if final_state.completed_at else None,
                "error": final_state.error,
            }),
        }

    return EventSourceResponse(event_generator())


# =============================================================================
# GitHub Secret Hunt Endpoints
# =============================================================================


@app.post("/github-hunt/{project_id}/start", response_model=GithubHuntState)
async def start_github_hunt(project_id: str, request: GithubHuntStartRequest):
    """
    Start a GitHub Secret Hunt for a project.

    Requires recon data to already exist for target context.
    """
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    # Check that recon data exists
    from pathlib import Path
    recon_file = Path("/app/recon/output") / f"recon_{project_id}.json"
    if not recon_file.exists():
        raise HTTPException(
            status_code=400,
            detail="Recon data required. Run reconnaissance first.",
        )

    try:
        state = await container_manager.start_github_hunt(
            project_id=project_id,
            user_id=request.user_id,
            webapp_api_url=_spawned_webapp_url(),
            github_hunt_path=GITHUB_HUNT_PATH,
        )
        return state
    except ValueError as e:
        raise _value_error_http(e)
    except Exception as e:
        logger.error(f"Error starting GitHub hunt: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/github-hunt/{project_id}/status", response_model=GithubHuntState)
async def get_github_hunt_status(project_id: str):
    """Get current status of a GitHub Secret Hunt process"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    return await container_manager.get_github_hunt_status(project_id)


@app.post("/github-hunt/{project_id}/stop", response_model=GithubHuntState)
async def stop_github_hunt(project_id: str, ingest: bool = True):
    """Stop a running GitHub Secret Hunt process.

    `?ingest=false` skips the backstop graph write, as for the GVM stop.
    """
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.stop_github_hunt(project_id, ingest=ingest)
    return state


@app.post("/github-hunt/{project_id}/pause", response_model=GithubHuntState)
async def pause_github_hunt(project_id: str):
    """Pause a running GitHub Secret Hunt process"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.pause_github_hunt(project_id)
    return state


@app.post("/github-hunt/{project_id}/resume", response_model=GithubHuntState)
async def resume_github_hunt(project_id: str):
    """Resume a paused GitHub Secret Hunt process"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.resume_github_hunt(project_id)
    return state


@app.get("/github-hunt/{project_id}/logs")
async def stream_github_hunt_logs(project_id: str):
    """
    Stream logs from a GitHub Secret Hunt container using Server-Sent Events.
    """
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.get_github_hunt_status(project_id)
    if state.status == GithubHuntStatus.IDLE:
        raise HTTPException(status_code=404, detail="No GitHub hunt found for this project")

    async def event_generator():
        try:
            async for event in container_manager.stream_github_hunt_logs(project_id):
                yield {
                    "event": "log",
                    "data": json.dumps({
                        "log": event.log,
                        "timestamp": event.timestamp.isoformat(),
                        "phase": event.phase,
                        "phaseNumber": event.phase_number,
                        "isPhaseStart": event.is_phase_start,
                        "level": event.level,
                    }),
                }
        except Exception as e:
            logger.error(f"Error streaming GitHub hunt logs: {e}")
            yield {
                "event": "error",
                "data": json.dumps({"error": str(e)}),
            }

        final_state = await container_manager.get_github_hunt_status(project_id)
        yield {
            "event": "complete",
            "data": json.dumps({
                "status": final_state.status.value,
                "completedAt": final_state.completed_at.isoformat() if final_state.completed_at else None,
                "error": final_state.error,
            }),
        }

    return EventSourceResponse(event_generator())


# =============================================================================
# TruffleHog Secret Scanner Endpoints
# =============================================================================


@app.post("/trufflehog/{project_id}/start", response_model=TrufflehogState)
async def start_trufflehog(project_id: str, request: TrufflehogStartRequest):
    """Start ONE TruffleHog source for a project.

    The run key is the source, so two Docker Hub scans are refused while Docker
    and HuggingFace run side by side. Admission is the fleet-wide governor: no
    trufflehog-specific parallelism cap.

    Every gate the container manager applies (config validation, the mandatory
    credential check, the resolved-IP egress guard, the scope check) raises
    ValueError and surfaces here as a 400 — none of them are client-side only.
    """
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    try:
        state = await container_manager.start_trufflehog(
            project_id=project_id,
            user_id=request.user_id,
            trufflehog_path=TRUFFLEHOG_PATH,
            source=request.source,
            config=request.config,
            common=request.common,
            secrets=request.secrets,
        )
        return state
    except ValueError as e:
        raise _value_error_http(e)
    except Exception as e:
        logger.error(f"Error starting TruffleHog scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/trufflehog/{project_id}/all", response_model=TrufflehogListResponse)
async def list_trufflehog(project_id: str):
    """Every run for a project.

    The webapp's queue reconcile, the version-save guard and the graph
    activation guard read this. A project-level status endpoint can only ever
    describe one of N parallel runs, so the others look idle to every caller —
    which is how a version snapshot ends up taken mid-write.
    """
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    runs = await container_manager.get_all_trufflehog_statuses(project_id)
    return TrufflehogListResponse(project_id=project_id, runs=runs)


@app.post("/trufflehog/{project_id}/stop-all", response_model=TrufflehogListResponse)
async def stop_all_trufflehog(project_id: str):
    """Stop every source's run. Project delete and reset call this; a single
    project-keyed stop would orphan every source but one."""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    runs = await container_manager.stop_all_trufflehog(project_id)
    return TrufflehogListResponse(project_id=project_id, runs=runs)


@app.get("/trufflehog/{project_id}/{source}/status", response_model=TrufflehogState)
async def get_trufflehog_status(project_id: str, source: str):
    """Status of one source's run"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    return await container_manager.get_trufflehog_status(project_id, source)


@app.post("/trufflehog/{project_id}/{source}/stop", response_model=TrufflehogState)
async def stop_trufflehog(project_id: str, source: str):
    """Stop one source's run; the project's other sources keep going"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    return await container_manager.stop_trufflehog(project_id, source)


@app.get("/trufflehog/{project_id}/{source}/logs")
async def stream_trufflehog_logs(project_id: str, source: str):
    """Stream one source's container logs over SSE."""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.get_trufflehog_status(project_id, source)
    if state.status == TrufflehogStatus.IDLE:
        raise HTTPException(status_code=404, detail="No TruffleHog scan found for this source")

    async def event_generator():
        try:
            async for event in container_manager.stream_trufflehog_logs(project_id, source):
                yield {
                    "event": "log",
                    "data": json.dumps({
                        "log": event.log,
                        "timestamp": event.timestamp.isoformat(),
                        "phase": event.phase,
                        "phaseNumber": event.phase_number,
                        "isPhaseStart": event.is_phase_start,
                        "level": event.level,
                    }),
                }
        except Exception as e:
            logger.error(f"Error streaming TruffleHog logs: {e}")
            yield {
                "event": "error",
                "data": json.dumps({"error": str(e)}),
            }

        final_state = await container_manager.get_trufflehog_status(project_id, source)
        yield {
            "event": "complete",
            "data": json.dumps({
                "status": final_state.status.value,
                "source": final_state.source,
                "findingsCount": final_state.findings_count,
                "completedAt": final_state.completed_at.isoformat() if final_state.completed_at else None,
                "error": final_state.error,
            }),
        }

    return EventSourceResponse(event_generator())


# =============================================================================
# Supply-Chain scan (L1 "Other Scans") endpoints - mirror the trufflehog block.
# =============================================================================
@app.post("/supply-chain/{project_id}/start", response_model=SupplyChainState)
async def start_supply_chain(project_id: str, request: SupplyChainStartRequest):
    """Start a Supply-Chain scan (offline OSV audit of an uploaded SBOM/lockfile)."""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    try:
        return await container_manager.start_supply_chain(
            project_id=project_id,
            user_id=request.user_id,
            webapp_api_url=_spawned_webapp_url(),
            supply_chain_path=SUPPLY_CHAIN_PATH,
            repo_override_url=request.repo_override_url,
            repo_override_host=request.repo_override_host,
            repo_override_ref=request.repo_override_ref,
            repo_override_scope=request.repo_override_scope,
            repo_override_deep=request.repo_override_deep,
        )
    except ValueError as e:
        raise _value_error_http(e)
    except Exception as e:
        logger.error(f"Error starting Supply-Chain scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/supply-chain/guarddog", response_model=GuarddogResult)
async def supply_chain_guarddog(request: GuarddogRequest):
    """One-shot GuardDog behavioural analysis of a SINGLE package (L3).

    The agent's `execute_guarddog` reaches this via the webapp internal
    passthrough. GuardDog downloads the attacker-authored tarball, so it must
    run in the hardened, secret-free analyzer image - and only the orchestrator
    holds the Docker socket, so it dispatches here. The Kali worker (least-
    trusted, target-facing) never touches Docker. See the trust-boundary section
    of docs/readmes/README.TM.SYSTEM_OVERVIEW.md.
    """
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    # Memory-governed: this spawns a real ~1.5 GB analyzer container, so it books
    # its envelope like a scan does. A full host raises AdmissionError -> 409.
    try:
        result = await container_manager.run_guarddog_package_governed(
            request.ecosystem, request.name, request.version)
    except ValueError as e:   # AdmissionError subclasses ValueError
        raise _value_error_http(e)
    return GuarddogResult(**result)


@app.get("/supply-chain/{project_id}/status", response_model=SupplyChainState)
async def get_supply_chain_status(project_id: str):
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    return await container_manager.get_supply_chain_status(project_id)


@app.post("/supply-chain/{project_id}/stop", response_model=SupplyChainState)
async def stop_supply_chain(project_id: str):
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    return await container_manager.stop_supply_chain(project_id)


@app.post("/supply-chain/{project_id}/pause", response_model=SupplyChainState)
async def pause_supply_chain(project_id: str):
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    return await container_manager.pause_supply_chain(project_id)


@app.post("/supply-chain/{project_id}/resume", response_model=SupplyChainState)
async def resume_supply_chain(project_id: str):
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    return await container_manager.resume_supply_chain(project_id)


@app.get("/supply-chain/{project_id}/logs")
async def stream_supply_chain_logs(project_id: str):
    """Stream Supply-Chain scanner logs via Server-Sent Events."""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    state = await container_manager.get_supply_chain_status(project_id)
    if state.status == SupplyChainStatus.IDLE:
        raise HTTPException(status_code=404, detail="No Supply-Chain scan found for this project")

    async def event_generator():
        try:
            async for event in container_manager.stream_supply_chain_logs(project_id):
                yield {
                    "event": "log",
                    "data": json.dumps({
                        "log": event.log,
                        "timestamp": event.timestamp.isoformat(),
                        "level": event.level,
                    }),
                }
        except Exception as e:
            logger.error(f"Error streaming Supply-Chain logs: {e}")
            yield {"event": "error", "data": json.dumps({"error": str(e)})}

        final_state = await container_manager.get_supply_chain_status(project_id)
        yield {
            "event": "complete",
            "data": json.dumps({
                "status": final_state.status.value,
                "completedAt": final_state.completed_at.isoformat() if final_state.completed_at else None,
                "error": final_state.error,
            }),
        }

    return EventSourceResponse(event_generator())


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=8010,
        reload=True,
        log_level="info",
    )

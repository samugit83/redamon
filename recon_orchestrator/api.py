"""
Recon Orchestrator API - FastAPI service for managing recon containers
"""
import json
import logging
import os
import socket
from contextlib import asynccontextmanager

import docker
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sse_starlette.sse import EventSourceResponse

from container_manager import ContainerManager
from models import (
    HealthResponse,
    ReconStartRequest,
    ReconState,
    ReconStatus,
    GvmStartRequest,
    GvmState,
    GvmStatus,
    GithubHuntStartRequest,
    GithubHuntState,
    GithubHuntStatus,
    TrufflehogStartRequest,
    TrufflehogState,
    TrufflehogStatus,
    PartialReconStartRequest,
    PartialReconState,
    PartialReconStatus,
    PartialReconListResponse,
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
try:
    CUSTOM_TEMPLATES_PATH = _get_host_path(_host_mounts, "/app/nuclei-templates", "CUSTOM_TEMPLATES_PATH")
except RuntimeError:
    CUSTOM_TEMPLATES_PATH = ""
    logger.info("Custom nuclei templates not mounted — custom templates feature disabled")
VERSION = "1.0.0"

# Global container manager
container_manager: ContainerManager = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and cleanup resources"""
    global container_manager
    logger.info("Starting Recon Orchestrator...")
    container_manager = ContainerManager(recon_image=RECON_IMAGE, gvm_image=GVM_IMAGE, github_hunt_image=GITHUB_HUNT_IMAGE, trufflehog_image=TRUFFLEHOG_IMAGE)
    yield
    logger.info("Shutting down Recon Orchestrator...")
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
        gvm_available=container_manager.is_gvm_available() if container_manager else False,
    )


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

        # Runtime-only settings that should NOT be sent to frontend/database
        # These are used by recon module at runtime, not stored in PostgreSQL
        RUNTIME_ONLY_KEYS = {
            'PROJECT_ID',
            'USER_ID',
            'TARGET_DOMAIN',   # Provided by user, not a default
            # API keys fetched at runtime from user's global settings (not stored per-project)
            'SHODAN_API_KEY',
            'URLSCAN_API_KEY',
            'CENSYS_API_TOKEN',
            'CENSYS_ORG_ID',
            'OTX_API_KEY',
            'NETLAS_API_KEY',
            'VIRUSTOTAL_API_KEY',
            'ZOOMEYE_API_KEY',
            'CRIMINALIP_API_KEY',
            'FOFA_EMAIL',
            'FOFA_API_KEY',
            'UNCOVER_QUAKE_API_KEY',
            'UNCOVER_HUNTER_API_KEY',
            'UNCOVER_PUBLICWWW_API_KEY',
            'UNCOVER_HUNTERHOW_API_KEY',
            'UNCOVER_GOOGLE_API_KEY',
            'UNCOVER_GOOGLE_API_CX',
            'UNCOVER_ONYPHE_API_KEY',
            'UNCOVER_DRIFTNET_API_KEY',
        }

        # Convert snake_case keys to camelCase for frontend
        def to_camel_case(snake_str: str) -> str:
            components = snake_str.lower().split('_')
            return components[0] + ''.join(x.title() for x in components[1:])

        camel_case_defaults = {
            to_camel_case(k): v
            for k, v in DEFAULT_SETTINGS.items()
            if k not in RUNTIME_ONLY_KEYS
        }

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

    # RoE time window check: fetch project settings and verify
    if request.webapp_api_url:
        try:
            import urllib.request
            import json as json_mod
            from datetime import datetime
            try:
                import zoneinfo
            except ImportError:
                from backports import zoneinfo

            url = f"{request.webapp_api_url.rstrip('/')}/api/projects/{project_id}"
            req = urllib.request.Request(url)
            req.add_header("X-Internal-Key", os.environ.get("INTERNAL_API_KEY", ""))
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    project = json_mod.loads(resp.read().decode())

                    # Hard guardrail: deterministic, non-disableable — always blocks government/public domains
                    if not project.get('ipMode', False) and project.get('targetDomain'):
                        from hard_guardrail import is_hard_blocked
                        blocked, reason = is_hard_blocked(project['targetDomain'])
                        if blocked:
                            raise HTTPException(
                                status_code=403,
                                detail=f"Hard guardrail: {reason}"
                            )

                    if project.get('roeEnabled') and project.get('roeTimeWindowEnabled'):
                        tz_name = project.get('roeTimeWindowTimezone', 'UTC')
                        try:
                            tz = zoneinfo.ZoneInfo(tz_name)
                            now_local = datetime.now(tz)
                            day_name = now_local.strftime('%A').lower()
                            allowed_days = project.get('roeTimeWindowDays', [])
                            start_time = project.get('roeTimeWindowStartTime', '09:00')
                            end_time = project.get('roeTimeWindowEndTime', '18:00')
                            current_time = now_local.strftime('%H:%M')

                            if day_name not in allowed_days:
                                raise HTTPException(
                                    status_code=403,
                                    detail=f"RoE time window: testing not allowed on {day_name.capitalize()}. Allowed days: {', '.join(d.capitalize() for d in allowed_days)}"
                                )
                            # Handle overnight windows (e.g. 22:00 - 06:00)
                            if start_time <= end_time:
                                outside = current_time < start_time or current_time > end_time
                            else:
                                # Overnight: allowed if AFTER start OR BEFORE end
                                outside = current_time < start_time and current_time > end_time
                            if outside:
                                raise HTTPException(
                                    status_code=403,
                                    detail=f"RoE time window: current time {current_time} {tz_name} is outside allowed window ({start_time}-{end_time})"
                                )
                        except HTTPException:
                            raise
                        except Exception as e:
                            logger.warning(f"RoE time window check failed (proceeding): {e}")
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"Could not check RoE time window (proceeding): {e}")

    try:
        state = await container_manager.start_recon(
            project_id=project_id,
            user_id=request.user_id,
            webapp_api_url=request.webapp_api_url,
            recon_path=RECON_PATH,
            custom_templates_path=CUSTOM_TEMPLATES_PATH,
        )
        return state
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        logger.error(f"Error starting recon: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/recon/{project_id}/status", response_model=ReconState)
async def get_recon_status(project_id: str):
    """Get current status of a recon process"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    return await container_manager.get_status(project_id)


@app.post("/recon/{project_id}/stop", response_model=ReconState)
async def stop_recon(project_id: str):
    """Stop a running recon process"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.stop_recon(project_id)
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
    """Resume a paused recon process"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

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

    # RoE time window + hard guardrail checks (same as full recon)
    if request.webapp_api_url:
        try:
            import urllib.request
            import json as json_mod
            from datetime import datetime
            try:
                import zoneinfo
            except ImportError:
                from backports import zoneinfo

            url = f"{request.webapp_api_url.rstrip('/')}/api/projects/{project_id}"
            req = urllib.request.Request(url)
            req.add_header("X-Internal-Key", os.environ.get("INTERNAL_API_KEY", ""))
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    project = json_mod.loads(resp.read().decode())

                    # Hard guardrail check
                    domain = request.graph_inputs.get("domain", "")
                    if domain:
                        from hard_guardrail import is_hard_blocked
                        blocked, reason = is_hard_blocked(domain)
                        if blocked:
                            raise HTTPException(status_code=403, detail=f"Hard guardrail: {reason}")

                    # RoE time window check
                    if project.get('roeEnabled') and project.get('roeTimeWindowEnabled'):
                        tz_name = project.get('roeTimeWindowTimezone', 'UTC')
                        try:
                            tz = zoneinfo.ZoneInfo(tz_name)
                            now_local = datetime.now(tz)
                            day_name = now_local.strftime('%A').lower()
                            allowed_days = project.get('roeTimeWindowDays', [])
                            start_time = project.get('roeTimeWindowStartTime', '09:00')
                            end_time = project.get('roeTimeWindowEndTime', '18:00')
                            current_time = now_local.strftime('%H:%M')

                            if day_name not in allowed_days:
                                raise HTTPException(
                                    status_code=403,
                                    detail=f"RoE time window: testing not allowed on {day_name.capitalize()}"
                                )
                            if start_time <= end_time:
                                outside = current_time < start_time or current_time > end_time
                            else:
                                outside = current_time < start_time and current_time > end_time
                            if outside:
                                raise HTTPException(
                                    status_code=403,
                                    detail=f"RoE time window: current time {current_time} {tz_name} outside allowed ({start_time}-{end_time})"
                                )
                        except HTTPException:
                            raise
                        except Exception as e:
                            logger.warning(f"RoE check failed (proceeding): {e}")
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"Could not check RoE (proceeding): {e}")

    # Note: settings are fetched by the recon container itself via get_settings()
    # (uses PROJECT_ID + WEBAPP_API_URL env vars, same as main.py)

    # Build the config dict for the partial recon container
    config = {
        "tool_id": request.tool_id,
        "domain": request.graph_inputs.get("domain", ""),
        "user_inputs": request.user_inputs,
        "user_targets": request.user_targets,
        "include_graph_targets": request.include_graph_targets,
        "settings_overrides": request.settings_overrides,
        "user_id": request.user_id,
        "webapp_api_url": request.webapp_api_url,
    }

    try:
        state = await container_manager.start_partial_recon(
            project_id=project_id,
            tool_id=request.tool_id,
            config=config,
            recon_path=RECON_PATH,
        )
        return state
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        logger.error(f"Error starting partial recon: {e}")
        raise HTTPException(status_code=500, detail=str(e))


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
async def stop_partial_recon(project_id: str, run_id: str):
    """Stop a specific partial recon run"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    return await container_manager.stop_partial_recon(project_id, run_id)


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


@app.get("/recon/{project_id}/graph-inputs/{tool_id}")
async def get_graph_inputs(project_id: str, tool_id: str, user_id: str = ""):
    """
    Get existing graph inputs for a partial recon tool.

    Queries Neo4j for relevant data (e.g., Domain node for SubdomainDiscovery).
    Note: The neo4j Python driver is not installed in the orchestrator image.
    This endpoint uses a raw Bolt connection via the neo4j library in graph_db
    (which is volume-mounted read-only). If that fails, it falls back to
    project settings from the webapp API.
    """
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    result = {"domain": None, "existing_subdomains_count": 0, "source": "settings"}

    # Try querying Neo4j directly using the graph_db module (volume-mounted)
    # This may fail if the neo4j Python package is not installed in the orchestrator
    try:
        import sys
        from pathlib import Path
        graph_parent = Path("/app")
        if str(graph_parent) not in sys.path:
            sys.path.insert(0, str(graph_parent))

        from graph_db import Neo4jClient
        with Neo4jClient() as client:
            if client.verify_connection():
                graph_result = client.get_graph_inputs_for_tool(tool_id, user_id, project_id)
                if graph_result.get("domain"):
                    return graph_result
    except ImportError:
        logger.info("neo4j package not available in orchestrator, falling back to webapp API")
    except Exception as e:
        logger.warning(f"Neo4j query failed for graph-inputs: {e}")

    # Fallback: get domain from project settings via webapp API
    webapp_url = os.environ.get("WEBAPP_API_URL", "")
    if not webapp_url:
        webapp_url = "http://localhost:3000"

    try:
        import urllib.request
        import json as json_mod
        url = f"{webapp_url}/api/projects/{project_id}"
        req = urllib.request.Request(url)
        req.add_header("X-Internal-Key", os.environ.get("INTERNAL_API_KEY", ""))
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                project = json_mod.loads(resp.read().decode())
                result["domain"] = project.get("targetDomain", "")
                result["source"] = "settings"
    except Exception as e:
        logger.warning(f"Could not fetch project settings for graph-inputs: {e}")

    return result


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
    recon_file = output_dir / f"recon_{project_id}.json"

    deleted_files = []
    errors = []

    # Delete recon JSON file
    if recon_file.exists():
        try:
            os.remove(recon_file)
            deleted_files.append(str(recon_file))
            logger.info(f"Deleted recon file: {recon_file}")
        except Exception as e:
            errors.append(f"Failed to delete {recon_file}: {e}")
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
        Path("/app/recon/output") / f"recon_{project_id}.json",
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
            webapp_api_url=request.webapp_api_url,
            recon_path=RECON_PATH,
            gvm_scan_path=GVM_SCAN_PATH,
        )
        return state
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
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
async def stop_gvm_scan(project_id: str):
    """Stop a running GVM scan process"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.stop_gvm_scan(project_id)
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
            webapp_api_url=request.webapp_api_url,
            github_hunt_path=GITHUB_HUNT_PATH,
        )
        return state
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
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
async def stop_github_hunt(project_id: str):
    """Stop a running GitHub Secret Hunt process"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.stop_github_hunt(project_id)
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
    """
    Start a TruffleHog Secret Scanner for a project.

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
        state = await container_manager.start_trufflehog(
            project_id=project_id,
            user_id=request.user_id,
            webapp_api_url=request.webapp_api_url,
            trufflehog_path=TRUFFLEHOG_PATH,
        )
        return state
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        logger.error(f"Error starting TruffleHog scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/trufflehog/{project_id}/status", response_model=TrufflehogState)
async def get_trufflehog_status(project_id: str):
    """Get current status of a TruffleHog scan process"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    return await container_manager.get_trufflehog_status(project_id)


@app.post("/trufflehog/{project_id}/stop", response_model=TrufflehogState)
async def stop_trufflehog(project_id: str):
    """Stop a running TruffleHog scan process"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.stop_trufflehog(project_id)
    return state


@app.post("/trufflehog/{project_id}/pause", response_model=TrufflehogState)
async def pause_trufflehog(project_id: str):
    """Pause a running TruffleHog scan process"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.pause_trufflehog(project_id)
    return state


@app.post("/trufflehog/{project_id}/resume", response_model=TrufflehogState)
async def resume_trufflehog(project_id: str):
    """Resume a paused TruffleHog scan process"""
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.resume_trufflehog(project_id)
    return state


@app.get("/trufflehog/{project_id}/logs")
async def stream_trufflehog_logs(project_id: str):
    """
    Stream logs from a TruffleHog scanner container using Server-Sent Events.
    """
    if not container_manager:
        raise HTTPException(status_code=503, detail="Service not initialized")

    state = await container_manager.get_trufflehog_status(project_id)
    if state.status == TrufflehogStatus.IDLE:
        raise HTTPException(status_code=404, detail="No TruffleHog scan found for this project")

    async def event_generator():
        try:
            async for event in container_manager.stream_trufflehog_logs(project_id):
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

        final_state = await container_manager.get_trufflehog_status(project_id)
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

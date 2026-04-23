"""
Docker container lifecycle management for recon processes
"""
import asyncio
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator, Optional

import docker
from docker.errors import NotFound, APIError
from docker.models.containers import Container

from models import (
    ReconState, ReconStatus, ReconLogEvent,
    GvmState, GvmStatus, GvmLogEvent,
    GithubHuntState, GithubHuntStatus, GithubHuntLogEvent,
    TrufflehogState, TrufflehogStatus, TrufflehogLogEvent,
    PartialReconState, PartialReconStatus,
)

logger = logging.getLogger(__name__)

# ANSI escape code pattern for stripping terminal colors from logs
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*m|\033\[[0-9;]*m')

# Maximum number of concurrent partial recon runs per project
MAX_PARALLEL_PARTIAL_RECONS = 12

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


class ContainerManager:
    """Manages Docker containers for recon, GVM scan, GitHub hunt, and TruffleHog processes"""

    def __init__(self, recon_image: str = "redamon-recon:latest", gvm_image: str = "redamon-vuln-scanner:latest", github_hunt_image: str = "redamon-github-hunter:latest", trufflehog_image: str = "redamon-trufflehog:latest"):
        self.client = docker.from_env()
        self.recon_image = recon_image
        self.gvm_image = gvm_image
        self.github_hunt_image = github_hunt_image
        self.trufflehog_image = trufflehog_image
        self.running_states: dict[str, ReconState] = {}
        # Nested dict: outer key = project_id, inner key = run_id
        self.partial_recon_states: dict[str, dict[str, PartialReconState]] = {}
        self.gvm_states: dict[str, GvmState] = {}
        self.github_hunt_states: dict[str, GithubHuntState] = {}
        self.trufflehog_states: dict[str, TrufflehogState] = {}
        self._log_tasks: dict[str, asyncio.Task] = {}

    def _get_container_name(self, project_id: str) -> str:
        """Generate container name for a project"""
        # Sanitize project_id for container name
        safe_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', project_id)
        return f"redamon-recon-{safe_id}"

    async def get_status(self, project_id: str) -> ReconState:
        """Get current status of a recon process"""
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
    ) -> ReconState:
        """Start a recon container for a project"""

        # Check if already running or paused
        current_state = await self.get_status(project_id)
        if current_state.status in (ReconStatus.RUNNING, ReconStatus.PAUSED):
            raise ValueError(f"Recon already active for project {project_id}")

        # Mutual exclusion: block if any partial recon is running
        if self._count_active_partial_recons(project_id) > 0:
            raise ValueError(f"Partial recon(s) running for project {project_id}. Stop them first.")

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
                privileged=True,
                environment={
                    "PROJECT_ID": project_id,
                    "USER_ID": user_id,
                    "WEBAPP_API_URL": webapp_api_url,
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
                    "INTERNAL_API_KEY": os.environ.get("INTERNAL_API_KEY", ""),
                },
                volumes={
                    "/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "rw"},
                    # Mount source code for development (no rebuild needed)
                    # Note: rw needed because output/data are subdirectories
                    f"{recon_path}": {"bind": "/app/recon", "mode": "rw"},
                    # Mount graph_db module
                    f"{Path(recon_path).parent}/graph_db": {"bind": "/app/graph_db", "mode": "ro"},
                    # Mount /tmp for Docker-in-Docker temp files (avoids spaces in paths)
                    "/tmp/redamon": {"bind": "/tmp/redamon", "mode": "rw"},
                    # JS Recon shared volumes with webapp
                    "redamon_js_recon_uploads": {"bind": "/data/js-recon-uploads", "mode": "ro"},
                    "redamon_js_recon_custom": {"bind": "/data/js-recon-custom", "mode": "ro"},
                },
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
                    for line in container.logs(stream=True, follow=True, timestamps=True):
                        asyncio.run_coroutine_threadsafe(
                            log_queue.put(line),
                            loop
                        ).result(timeout=5)
                        # Check if container is still running
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
            loop.run_in_executor(None, read_logs)

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
            self._refresh_partial_recon_state(state)
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

        for run_id, state in runs.items():
            self._refresh_partial_recon_state(state)
            # Auto-clean old completed/errored entries
            if state.status in (PartialReconStatus.COMPLETED, PartialReconStatus.ERROR):
                if state.completed_at and (datetime.now(timezone.utc) - state.completed_at).total_seconds() > 60:
                    to_remove.append(run_id)

        for run_id in to_remove:
            del runs[run_id]
        if not runs and project_id in self.partial_recon_states:
            del self.partial_recon_states[project_id]

        return list(runs.values())

    async def start_partial_recon(
        self,
        project_id: str,
        tool_id: str,
        config: dict,
        recon_path: str,
    ) -> PartialReconState:
        """Start a partial recon container for a specific tool.

        Args:
            project_id: Project identifier
            tool_id: Tool to run (e.g., "SubdomainDiscovery")
            config: Full config dict to write as JSON for the container
            recon_path: Host path to the recon directory
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

        state = PartialReconState(
            project_id=project_id,
            run_id=run_id,
            tool_id=tool_id,
            status=PartialReconStatus.STARTING,
            started_at=datetime.now(timezone.utc),
        )
        self.partial_recon_states.setdefault(project_id, {})[run_id] = state

        try:
            # Ensure recon image exists
            try:
                self.client.images.get(self.recon_image)
            except NotFound:
                logger.info(f"Building recon image from {recon_path}")
                self.client.images.build(path=recon_path, tag=self.recon_image, rm=True)

            # Write config JSON to /tmp/redamon/ (shared volume)
            import json
            config_dir = Path("/tmp/redamon")
            config_dir.mkdir(parents=True, exist_ok=True)
            config_path = config_dir / f"partial_{project_id}_{run_id}.json"
            with open(config_path, "w") as f:
                json.dump(config, f)

            # Start container with the partial_recon.py entry point
            container = self.client.containers.run(
                self.recon_image,
                name=container_name,
                detach=True,
                network_mode="host",
                privileged=True,
                environment={
                    "PROJECT_ID": project_id,
                    "USER_ID": config.get("user_id", ""),
                    "WEBAPP_API_URL": config.get("webapp_api_url", ""),
                    "PARTIAL_RECON_CONFIG": f"/tmp/redamon/partial_{project_id}_{run_id}.json",
                    "PARTIAL_RECON_RUN_ID": run_id,
                    "UPDATE_GRAPH_DB": "true",
                    "HOST_RECON_OUTPUT_PATH": f"{recon_path}/output",
                    "NEO4J_URI": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                    "NEO4J_USER": os.environ.get("NEO4J_USER", "neo4j"),
                    "NEO4J_PASSWORD": os.environ.get("NEO4J_PASSWORD", ""),
                    "INTERNAL_API_KEY": os.environ.get("INTERNAL_API_KEY", ""),
                },
                volumes={
                    "/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "rw"},
                    f"{recon_path}": {"bind": "/app/recon", "mode": "rw"},
                    f"{Path(recon_path).parent}/graph_db": {"bind": "/app/graph_db", "mode": "ro"},
                    "/tmp/redamon": {"bind": "/tmp/redamon", "mode": "rw"},
                    # JS Recon shared volumes with webapp (uploaded files + custom patterns)
                    "redamon_js_recon_uploads": {"bind": "/data/js-recon-uploads", "mode": "ro"},
                    "redamon_js_recon_custom": {"bind": "/data/js-recon-custom", "mode": "ro"},
                },
                command="python /app/recon/partial_recon.py",
            )

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

            def read_logs():
                try:
                    for line in container.logs(stream=True, follow=True, timestamps=True):
                        asyncio.run_coroutine_threadsafe(
                            log_queue.put(line), loop
                        ).result(timeout=5)
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

            loop.run_in_executor(None, read_logs)

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
    # GVM Vulnerability Scan Container Lifecycle
    # =========================================================================

    def _get_gvm_container_name(self, project_id: str) -> str:
        """Generate container name for a GVM scan"""
        safe_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', project_id)
        return f"redamon-gvm-{safe_id}"

    async def get_gvm_status(self, project_id: str) -> GvmState:
        """Get current status of a GVM scan process"""
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
                name=container_name,
                detach=True,
                network_mode="host",
                environment={
                    "PROJECT_ID": project_id,
                    "USER_ID": user_id,
                    "WEBAPP_API_URL": webapp_api_url,
                    "PYTHONUNBUFFERED": "1",
                    # Forward Neo4j credentials from orchestrator environment
                    "NEO4J_URI": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                    "NEO4J_USER": os.environ.get("NEO4J_USER", "neo4j"),
                    "NEO4J_PASSWORD": os.environ.get("NEO4J_PASSWORD", ""),
                    "INTERNAL_API_KEY": os.environ.get("INTERNAL_API_KEY", ""),
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
                    f"{Path(recon_path).parent}/graph_db": {"bind": "/app/graph_db", "mode": "ro"},
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
                    for line in container.logs(stream=True, follow=True, timestamps=True):
                        asyncio.run_coroutine_threadsafe(
                            log_queue.put(line),
                            loop
                        ).result(timeout=5)
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

            loop.run_in_executor(None, read_logs)

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
        """Get current status of a GitHub hunt process"""
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
                name=container_name,
                detach=True,
                network_mode="host",
                environment={
                    "PROJECT_ID": project_id,
                    "USER_ID": user_id,
                    "WEBAPP_API_URL": webapp_api_url,
                    "PYTHONUNBUFFERED": "1",
                    # Forward Neo4j credentials from orchestrator environment
                    "NEO4J_URI": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                    "NEO4J_USER": os.environ.get("NEO4J_USER", "neo4j"),
                    "NEO4J_PASSWORD": os.environ.get("NEO4J_PASSWORD", ""),
                    "INTERNAL_API_KEY": os.environ.get("INTERNAL_API_KEY", ""),
                },
                volumes={
                    # GitHub hunt output (read-write, for saving results)
                    f"{github_hunt_path}/output": {"bind": "/app/github_secret_hunt/output", "mode": "rw"},
                    # Mount github_secret_hunt source for development (no rebuild needed)
                    f"{github_hunt_path}": {"bind": "/app/github_secret_hunt", "mode": "rw"},
                    # Mount graph_db module for Neo4j integration
                    f"{Path(github_hunt_path).parent}/graph_db": {"bind": "/app/graph_db", "mode": "ro"},
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
                    for line in container.logs(stream=True, follow=True, timestamps=True):
                        asyncio.run_coroutine_threadsafe(
                            log_queue.put(line),
                            loop
                        ).result(timeout=5)
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

            loop.run_in_executor(None, read_logs)

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
        """Get current status of a TruffleHog scan process"""
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
                name=container_name,
                detach=True,
                network_mode="host",
                environment={
                    "PROJECT_ID": project_id,
                    "USER_ID": user_id,
                    "WEBAPP_API_URL": webapp_api_url,
                    "PYTHONUNBUFFERED": "1",
                    # Forward Neo4j credentials from orchestrator environment
                    "NEO4J_URI": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                    "NEO4J_USER": os.environ.get("NEO4J_USER", "neo4j"),
                    "NEO4J_PASSWORD": os.environ.get("NEO4J_PASSWORD", ""),
                    "INTERNAL_API_KEY": os.environ.get("INTERNAL_API_KEY", ""),
                },
                volumes={
                    # TruffleHog output (read-write, for saving results)
                    f"{trufflehog_path}/output": {"bind": "/app/trufflehog_scan/output", "mode": "rw"},
                    # Mount trufflehog_scan source for development (no rebuild needed)
                    f"{trufflehog_path}": {"bind": "/app/trufflehog_scan", "mode": "rw"},
                    # Mount graph_db module for Neo4j integration
                    f"{Path(trufflehog_path).parent}/graph_db": {"bind": "/app/graph_db", "mode": "ro"},
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
                    for line in container.logs(stream=True, follow=True, timestamps=True):
                        asyncio.run_coroutine_threadsafe(
                            log_queue.put(line),
                            loop
                        ).result(timeout=5)
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

            loop.run_in_executor(None, read_logs)

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

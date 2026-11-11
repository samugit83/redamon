"""
RedAmon - Docker Helper Functions
=================================
Utilities for Docker container operations, image management, and file permissions.
"""

import os
import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

# Volume name for persistent nuclei templates
NUCLEI_TEMPLATES_VOLUME = "nuclei-templates"


# =============================================================================
# Generic Docker Utilities
# =============================================================================

def is_docker_installed() -> bool:
    """Check if Docker is installed and accessible."""
    return shutil.which("docker") is not None


def is_docker_running() -> bool:
    """Check if Docker daemon is running."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def _image_on_host(docker_image: str) -> bool:
    """True when the image is already in the local Docker store. Never raises."""
    try:
        result = subprocess.run(["docker", "images", "-q", docker_image],
                                capture_output=True, text=True, timeout=30)
        return result.returncode == 0 and bool(result.stdout.strip())
    except Exception:
        return False


def pull_image_or_use_local(docker_image: str, label: str, *,
                            platform: Optional[str] = None, timeout: int = 300) -> bool:
    """Pull `docker_image` so a moving tag stays current, and fall back to the copy
    already on this host when the pull fails. Never raises.

    A pull fails for reasons that say nothing about the image: no DNS, a registry
    rate limit, an offline host. Treating that as "tool unavailable" silently drops
    the tool from the run, even though it would have worked from the local copy.
    False only when the pull failed AND there is no local copy.
    """
    cmd = ["docker", "pull"] + (["--platform", platform] if platform else []) + [docker_image]
    reason = ""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            return True
        lines = (result.stderr or "").strip().splitlines()
        reason = lines[-1][:140] if lines else f"exit {result.returncode}"
    except Exception as e:  # noqa: BLE001 - a failed pull must never raise into a scan
        reason = type(e).__name__
    if _image_on_host(docker_image):
        print(f"[!][{label}] Pull failed ({reason}) - using the image already on this host")
        return True
    return False


def kill_container(name: str) -> None:
    """`docker kill` a named container. Never raises.

    Needed after `subprocess.run(["docker", "run", ...], timeout=...)` times out:
    the timeout kills only the docker CLI, and the container keeps running. A
    container started with `--rm` is removed by the daemon once killed.
    """
    try:
        subprocess.run(["docker", "kill", name],
                       capture_output=True, text=True, timeout=15, check=False)
    except Exception as e:  # noqa: BLE001
        print(f"[!][Docker] failed to kill {name}: {type(e).__name__}")


@dataclass(frozen=True)
class ToolContainerRun:
    """What a `run_tool_container` call produced.

    ``returncode`` is None when the timeout cut the run; ``stdout`` and
    ``stderr`` then hold what the tool printed before it was killed.
    """
    name: str
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool


def _name_part(value: str, limit: int) -> str:
    return re.sub(r"[^a-z0-9_-]+", "-", value.lower()).strip("-_")[:limit]


def tool_container_name(tool: str) -> str:
    """`<tool>-<run id>-<8 hex>`: unique, and readable as this run's in `docker ps`.

    The run id is the one recon/entrypoint.sh names to the broker (a partial
    run's first), so the name and the broker's `redamon.run_id` label agree.
    Outside a run a random id stands in.
    """
    run = os.environ.get("PARTIAL_RECON_RUN_ID") or os.environ.get("RECON_RUN_ID") or ""
    return (f"{_name_part(tool, 24) or 'tool'}-{_name_part(run, 64) or uuid.uuid4().hex[:8]}"
            f"-{uuid.uuid4().hex[:8]}")


def _with_name(cmd: list, name: str) -> list:
    if any(cmd[i:i + 2] == ["--name", name] for i in range(2, len(cmd) - 1)) \
            or f"--name={name}" in cmd:
        return cmd
    # After the argv's opening self-contained flags (`--rm`, `--net=host`), so
    # the familiar head of each tool's command stays put and the name can never
    # land between an option and its value.
    i = 2
    while i < len(cmd) and (cmd[i] == "--rm" or (cmd[i].startswith("--") and "=" in cmd[i])):
        i += 1
    return [*cmd[:i], "--name", name, *cmd[i:]]


def _text(data) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    return data.replace("\r\n", "\n")


def run_tool_container(cmd: Sequence[str], *, tool: str, timeout: float,
                       input: Optional[str] = None,
                       name: Optional[str] = None) -> ToolContainerRun:
    """Run a `docker run` argv to completion or `timeout`, never leaving its container behind.

    A timeout on `subprocess.run` kills only the docker CLI: the daemon-owned
    container goes on scanning the target after the run has moved on. So the
    container gets a name (``name``, else ``tool_container_name(tool)``; an
    argv that already carries ``--name <name>`` is left as it is) and, on
    timeout, is killed by it once the CLI has exited. The run labels come from
    the broker, which stamps every container this process creates
    (recon/entrypoint.sh).

    Returns the exit code and output; on timeout, ``timed_out`` and the output
    read so far, for the caller to parse and to record what went unchecked.
    A failure to start (no docker binary) raises as `subprocess.run` does.
    """
    cmd = list(cmd)
    if len(cmd) < 2 or cmd[0] != "docker" or cmd[1] != "run":
        raise ValueError("run_tool_container takes a `docker run` argv")
    name = name or tool_container_name(tool)
    argv = _with_name(cmd, name)
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              input=input, check=False)
    except subprocess.TimeoutExpired as expired:
        kill_container(name)
        return ToolContainerRun(name, None, _text(expired.stdout), _text(expired.stderr), True)
    return ToolContainerRun(name, done.returncode, done.stdout or "", done.stderr or "", False)


def get_real_user_ids() -> tuple:
    """
    Get the real user's UID and GID, even when running under sudo.
    This ensures Docker creates files owned by the actual user, not root.
    """
    # Check if running under sudo - use original user's IDs
    sudo_uid = os.environ.get('SUDO_UID')
    sudo_gid = os.environ.get('SUDO_GID')
    
    if sudo_uid and sudo_gid:
        return int(sudo_uid), int(sudo_gid)
    
    # Not running under sudo, use current user
    return os.getuid(), os.getgid()


def fix_file_ownership(file_path: Path) -> None:
    """
    Fix ownership of Docker-created files to match the real user.
    Docker often creates files as root, which breaks normal user access.
    """
    try:
        uid, gid = get_real_user_ids()
        
        # Only change ownership if we're root (can actually do it)
        if os.getuid() == 0:
            os.chown(file_path, uid, gid)
            
        # Also fix parent directory if needed
        parent = file_path.parent
        if parent.exists() and os.getuid() == 0:
            os.chown(parent, uid, gid)
            
    except Exception as e:
        # Non-fatal - file might still be usable
        print(f"[!][Docker] Warning: Could not fix file ownership: {e}")


# =============================================================================
# Nuclei Docker Management
# =============================================================================

def pull_nuclei_docker_image(docker_image: str) -> bool:
    """
    Pull the nuclei Docker image if not present.
    
    Args:
        docker_image: The Docker image name (e.g., 'projectdiscovery/nuclei:latest')
        
    Returns:
        True if successful, False otherwise
    """
    print(f"[*][Docker] Pulling Docker image: {docker_image}...")
    return pull_image_or_use_local(docker_image, "Docker")


def ensure_templates_volume(docker_image: str, auto_update: bool = False) -> bool:
    """
    Ensure the nuclei-templates Docker volume exists and has templates.
    Creates the volume and downloads templates if needed.
    
    Args:
        docker_image: Nuclei Docker image to use for template updates
        auto_update: Whether to check for template updates
    
    Returns:
        True if templates are ready, False otherwise
    """
    try:
        # Check if volume exists
        result = subprocess.run(
            ["docker", "volume", "inspect", NUCLEI_TEMPLATES_VOLUME],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        volume_exists = result.returncode == 0
        needs_download = False
        
        if not volume_exists:
            print(f"[*][Docker] Creating templates volume: {NUCLEI_TEMPLATES_VOLUME}...")
            subprocess.run(
                ["docker", "volume", "create", NUCLEI_TEMPLATES_VOLUME],
                capture_output=True,
                text=True,
                timeout=30
            )
            needs_download = True  # New volume, definitely needs templates
        else:
            # Volume exists - check if it has templates by counting .yaml files
            check_result = run_tool_container(
                ["docker", "run", "--rm",
                 "-v", f"{NUCLEI_TEMPLATES_VOLUME}:/root/nuclei-templates",
                 "alpine",
                 "sh", "-c", "find /root/nuclei-templates -name '*.yaml' 2>/dev/null | head -5 | wc -l"],
                tool="nuclei-templates-count", timeout=30)
            if check_result.timed_out:
                print("[!][Docker] Timeout while counting the nuclei templates")
                return False

            template_count = int(check_result.stdout.strip()) if check_result.stdout.strip().isdigit() else 0
            needs_download = template_count == 0
        
        # Download templates if needed OR auto-update is enabled
        if needs_download:
            print(f"[*][Docker] Downloading nuclei templates (first run, this may take a minute)...")
        elif auto_update:
            print(f"[*][Docker] Checking for template updates...")
        
        if needs_download or auto_update:
            # Stopped on a timeout: the container would go on rewriting the
            # volume the scan is about to read.
            update_result = run_tool_container(
                ["docker", "run", "--rm",
                 "-v", f"{NUCLEI_TEMPLATES_VOLUME}:/root/nuclei-templates",
                 docker_image,
                 "-ut"],  # Update templates
                tool="nuclei-update", timeout=600,  # 10 minutes for initial download
                name=f"redamon-nuclei-update-{uuid.uuid4().hex[:12]}")
            if update_result.timed_out:
                # Stopped mid-write, the volume can hold half-updated templates
                # that fail to load, so Nuclei is skipped (its findings kept)
                # rather than run on them.
                print("[!][Docker] Template update timed out - stopped it; the templates "
                      "may be half-written, so Nuclei is skipped this run")
                return False
            
            if update_result.returncode != 0:
                print(f"[!][Docker] Warning: Template update may have issues")
                if update_result.stderr:
                    # Filter out info messages
                    errors = [l for l in update_result.stderr.split('\n') if 'FTL' in l or 'ERR' in l]
                    if errors:
                        print(f"[!][Docker] {errors[0][:200]}")
            else:
                # Parse update info from output
                if update_result.stdout:
                    for line in update_result.stdout.split('\n'):
                        if 'Successfully updated' in line or 'already up to date' in line.lower():
                            print(f"[✓][Docker] {line.strip()[:80]}")
                            break
                    else:
                        print(f"[✓][Docker] Templates updated successfully")
                else:
                    print(f"[✓][Docker] Templates ready")
        else:
            print(f"[✓][Docker] Templates volume ready (auto-update disabled)")
        
        return True
        
    except subprocess.TimeoutExpired:
        print(f"[!][Docker] Timeout while setting up templates")
        return False
    except Exception as e:
        print(f"[!][Docker] Error setting up templates: {e}")
        return False


# =============================================================================
# Katana Docker Management
# =============================================================================

def pull_katana_docker_image(docker_image: str) -> bool:
    """
    Pull the Katana Docker image if not present.
    
    Args:
        docker_image: The Docker image name (e.g., 'projectdiscovery/katana:latest')
        
    Returns:
        True if successful, False otherwise
    """
    print(f"[*][Docker] Pulling Katana image: {docker_image}...")
    return pull_image_or_use_local(docker_image, "Docker")


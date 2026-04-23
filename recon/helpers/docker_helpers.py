"""
RedAmon - Docker Helper Functions
=================================
Utilities for Docker container operations, image management, and file permissions.
"""

import os
import shutil
import subprocess
from pathlib import Path

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
    try:
        print(f"[*][Docker] Pulling Docker image: {docker_image}...")
        result = subprocess.run(
            ["docker", "pull", docker_image],
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.returncode == 0
    except Exception:
        return False


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
            check_result = subprocess.run(
                ["docker", "run", "--rm", 
                 "-v", f"{NUCLEI_TEMPLATES_VOLUME}:/root/nuclei-templates",
                 "alpine", 
                 "sh", "-c", "find /root/nuclei-templates -name '*.yaml' 2>/dev/null | head -5 | wc -l"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            template_count = int(check_result.stdout.strip()) if check_result.stdout.strip().isdigit() else 0
            needs_download = template_count == 0
        
        # Download templates if needed OR auto-update is enabled
        if needs_download:
            print(f"[*][Docker] Downloading nuclei templates (first run, this may take a minute)...")
        elif auto_update:
            print(f"[*][Docker] Checking for template updates...")
        
        if needs_download or auto_update:
            update_result = subprocess.run(
                ["docker", "run", "--rm",
                 "-v", f"{NUCLEI_TEMPLATES_VOLUME}:/root/nuclei-templates",
                 docker_image,
                 "-ut"],  # Update templates
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes for initial download
            )
            
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
    try:
        print(f"[*][Docker] Pulling Katana image: {docker_image}...")
        result = subprocess.run(
            ["docker", "pull", docker_image],
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.returncode == 0
    except Exception:
        return False


# =============================================================================
# Network Utilities
# =============================================================================

def is_tor_running() -> bool:
    """Check if Tor is running by testing SOCKS proxy."""
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('127.0.0.1', 9050))
        sock.close()
        return result == 0
    except Exception:
        return False


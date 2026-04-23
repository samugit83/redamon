"""
GitHub Secret Hunt Project Settings - Fetch GitHub scan configuration from webapp API

When PROJECT_ID and WEBAPP_API_URL are set as environment variables,
settings are fetched from the PostgreSQL database via webapp API.
Otherwise, falls back to DEFAULT_GITHUB_SETTINGS for standalone usage.

Mirrors the pattern from gvm_scan/project_settings.py.
"""
import os
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

# =============================================================================
# DEFAULT SETTINGS - Used as fallback for standalone usage and missing API fields
# =============================================================================

DEFAULT_GITHUB_SETTINGS: dict[str, Any] = {
    'GITHUB_ACCESS_TOKEN': os.getenv('GITHUB_ACCESS_TOKEN', ''),
    'GITHUB_TARGET_ORG': '',
    'GITHUB_TARGET_REPOS': '',
    'GITHUB_SCAN_MEMBERS': False,
    'GITHUB_SCAN_GISTS': True,
    'GITHUB_SCAN_COMMITS': True,
    'GITHUB_MAX_COMMITS': 100,
    'GITHUB_OUTPUT_JSON': True,
}


def fetch_github_settings(project_id: str, webapp_url: str) -> dict[str, Any]:
    """
    Fetch GitHub scan settings from webapp API.

    Args:
        project_id: The project ID to fetch settings for
        webapp_url: Base URL of the webapp API (e.g., http://localhost:3000)

    Returns:
        Dictionary of settings in SCREAMING_SNAKE_CASE format
    """
    import requests

    url = f"{webapp_url.rstrip('/')}/api/projects/{project_id}"
    logger.info(f"Fetching GitHub settings from {url}")

    _internal_headers = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}
    response = requests.get(url, timeout=30, headers=_internal_headers)
    response.raise_for_status()
    project = response.json()

    # Start with defaults, then override with API values
    settings = DEFAULT_GITHUB_SETTINGS.copy()

    # Fetch GitHub access token from user global settings (not project)
    user_id = os.environ.get('USER_ID', '')
    if user_id:
        try:
            user_settings_url = f"{webapp_url.rstrip('/')}/api/users/{user_id}/settings?internal=true"
            _internal_headers = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}
            user_resp = requests.get(user_settings_url, timeout=30, headers=_internal_headers)
            user_resp.raise_for_status()
            user_settings = user_resp.json()
            settings['GITHUB_ACCESS_TOKEN'] = user_settings.get('githubAccessToken', DEFAULT_GITHUB_SETTINGS['GITHUB_ACCESS_TOKEN'])
        except Exception as e:
            logger.warning(f"Failed to fetch user settings for GitHub token: {e}")

    # Map camelCase API fields to SCREAMING_SNAKE_CASE
    settings['GITHUB_TARGET_ORG'] = project.get('githubTargetOrg', DEFAULT_GITHUB_SETTINGS['GITHUB_TARGET_ORG'])
    settings['GITHUB_TARGET_REPOS'] = project.get('githubTargetRepos', DEFAULT_GITHUB_SETTINGS['GITHUB_TARGET_REPOS'])
    settings['GITHUB_SCAN_MEMBERS'] = project.get('githubScanMembers', DEFAULT_GITHUB_SETTINGS['GITHUB_SCAN_MEMBERS'])
    settings['GITHUB_SCAN_GISTS'] = project.get('githubScanGists', DEFAULT_GITHUB_SETTINGS['GITHUB_SCAN_GISTS'])
    settings['GITHUB_SCAN_COMMITS'] = project.get('githubScanCommits', DEFAULT_GITHUB_SETTINGS['GITHUB_SCAN_COMMITS'])
    settings['GITHUB_MAX_COMMITS'] = project.get('githubMaxCommits', DEFAULT_GITHUB_SETTINGS['GITHUB_MAX_COMMITS'])
    settings['GITHUB_OUTPUT_JSON'] = project.get('githubOutputJson', DEFAULT_GITHUB_SETTINGS['GITHUB_OUTPUT_JSON'])

    logger.info(f"Loaded {len(settings)} GitHub settings for project {project_id}")
    return settings


def get_settings() -> dict[str, Any]:
    """
    Get current GitHub settings.

    Returns cached settings if loaded for a project, otherwise defaults.
    Use load_project_settings() to fetch settings for a specific project.

    Returns:
        Dictionary of settings in SCREAMING_SNAKE_CASE format
    """
    global _settings
    if _settings is not None:
        return _settings
    logger.info("Using DEFAULT_GITHUB_SETTINGS (no project loaded yet)")
    return DEFAULT_GITHUB_SETTINGS.copy()


# Singleton settings instance
_settings: Optional[dict[str, Any]] = None
_current_project_id: Optional[str] = None


def load_project_settings(project_id: str) -> dict[str, Any]:
    """
    Fetch and cache settings for a specific project from webapp API.

    Args:
        project_id: The project ID received from the frontend

    Returns:
        Dictionary of settings in SCREAMING_SNAKE_CASE format
    """
    global _settings, _current_project_id

    # Skip if already loaded for this project
    if _current_project_id == project_id and _settings is not None:
        return _settings

    webapp_url = os.environ.get('WEBAPP_API_URL')

    if not webapp_url:
        logger.warning("WEBAPP_API_URL not set, using DEFAULT_GITHUB_SETTINGS")
        _settings = DEFAULT_GITHUB_SETTINGS.copy()
        _current_project_id = project_id
        return _settings

    try:
        _settings = fetch_github_settings(project_id, webapp_url)
        _current_project_id = project_id
        logger.info(f"Loaded {len(_settings)} GitHub settings from API for project {project_id}")
        return _settings

    except Exception as e:
        logger.error(f"Failed to fetch GitHub settings for project {project_id}: {e}")
        logger.warning("Falling back to DEFAULT_GITHUB_SETTINGS")
        _settings = DEFAULT_GITHUB_SETTINGS.copy()
        _current_project_id = project_id
        return _settings


def get_setting(key: str, default: Any = None) -> Any:
    """
    Get a single GitHub setting value.

    Args:
        key: Setting name in SCREAMING_SNAKE_CASE
        default: Default value if setting not found

    Returns:
        Setting value or default
    """
    return get_settings().get(key, default)


def reload_settings(project_id: Optional[str] = None) -> dict[str, Any]:
    """Force reload of settings for a project."""
    global _settings, _current_project_id
    if project_id:
        _current_project_id = None  # Force refetch
        return load_project_settings(project_id)
    _settings = None
    _current_project_id = None
    return get_settings()

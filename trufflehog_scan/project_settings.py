"""
TruffleHog Scan Project Settings - Fetch TruffleHog scan configuration from webapp API

When PROJECT_ID and WEBAPP_API_URL are set as environment variables,
settings are fetched from the PostgreSQL database via webapp API.
Otherwise, falls back to DEFAULT_TRUFFLEHOG_SETTINGS for standalone usage.

Mirrors the pattern from github_secret_hunt/project_settings.py.
"""
import os
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

# =============================================================================
# DEFAULT SETTINGS - Used as fallback for standalone usage and missing API fields
# =============================================================================

DEFAULT_TRUFFLEHOG_SETTINGS: dict[str, Any] = {
    'GITHUB_ACCESS_TOKEN': os.getenv('GITHUB_ACCESS_TOKEN', ''),
    'TRUFFLEHOG_ENABLED': False,
    'TRUFFLEHOG_GITHUB_ORG': '',
    'TRUFFLEHOG_GITHUB_REPOS': '',
    'TRUFFLEHOG_ONLY_VERIFIED': False,
    'TRUFFLEHOG_NO_VERIFICATION': False,
    'TRUFFLEHOG_CONCURRENCY': 8,
    'TRUFFLEHOG_INCLUDE_DETECTORS': '',
    'TRUFFLEHOG_EXCLUDE_DETECTORS': '',
}


def fetch_trufflehog_settings(project_id: str, webapp_url: str) -> dict[str, Any]:
    """
    Fetch TruffleHog scan settings from webapp API.

    Args:
        project_id: The project ID to fetch settings for
        webapp_url: Base URL of the webapp API (e.g., http://localhost:3000)

    Returns:
        Dictionary of settings in SCREAMING_SNAKE_CASE format
    """
    import requests

    url = f"{webapp_url.rstrip('/')}/api/projects/{project_id}"
    logger.info(f"Fetching TruffleHog settings from {url}")

    _internal_headers = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}
    response = requests.get(url, timeout=30, headers=_internal_headers)
    response.raise_for_status()
    project = response.json()

    # Start with defaults, then override with API values
    settings = DEFAULT_TRUFFLEHOG_SETTINGS.copy()

    # Fetch GitHub access token from user global settings (not project)
    user_id = os.environ.get('USER_ID', '')
    if user_id:
        try:
            user_settings_url = f"{webapp_url.rstrip('/')}/api/users/{user_id}/settings?internal=true"
            _internal_headers = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}
            user_resp = requests.get(user_settings_url, timeout=30, headers=_internal_headers)
            user_resp.raise_for_status()
            user_settings = user_resp.json()
            settings['GITHUB_ACCESS_TOKEN'] = user_settings.get('githubAccessToken', DEFAULT_TRUFFLEHOG_SETTINGS['GITHUB_ACCESS_TOKEN'])
        except Exception as e:
            logger.warning(f"Failed to fetch user settings for GitHub token: {e}")

    # Map camelCase API fields to SCREAMING_SNAKE_CASE
    settings['TRUFFLEHOG_ENABLED'] = project.get('trufflehogEnabled', DEFAULT_TRUFFLEHOG_SETTINGS['TRUFFLEHOG_ENABLED'])
    settings['TRUFFLEHOG_GITHUB_ORG'] = project.get('trufflehogGithubOrg', DEFAULT_TRUFFLEHOG_SETTINGS['TRUFFLEHOG_GITHUB_ORG'])
    settings['TRUFFLEHOG_GITHUB_REPOS'] = project.get('trufflehogGithubRepos', DEFAULT_TRUFFLEHOG_SETTINGS['TRUFFLEHOG_GITHUB_REPOS'])
    settings['TRUFFLEHOG_ONLY_VERIFIED'] = project.get('trufflehogOnlyVerified', DEFAULT_TRUFFLEHOG_SETTINGS['TRUFFLEHOG_ONLY_VERIFIED'])
    settings['TRUFFLEHOG_NO_VERIFICATION'] = project.get('trufflehogNoVerification', DEFAULT_TRUFFLEHOG_SETTINGS['TRUFFLEHOG_NO_VERIFICATION'])
    settings['TRUFFLEHOG_CONCURRENCY'] = project.get('trufflehogConcurrency', DEFAULT_TRUFFLEHOG_SETTINGS['TRUFFLEHOG_CONCURRENCY'])
    settings['TRUFFLEHOG_INCLUDE_DETECTORS'] = project.get('trufflehogIncludeDetectors', DEFAULT_TRUFFLEHOG_SETTINGS['TRUFFLEHOG_INCLUDE_DETECTORS'])
    settings['TRUFFLEHOG_EXCLUDE_DETECTORS'] = project.get('trufflehogExcludeDetectors', DEFAULT_TRUFFLEHOG_SETTINGS['TRUFFLEHOG_EXCLUDE_DETECTORS'])

    logger.info(f"Loaded {len(settings)} TruffleHog settings for project {project_id}")
    return settings


def get_settings() -> dict[str, Any]:
    """
    Get current TruffleHog settings.

    Returns cached settings if loaded for a project, otherwise defaults.
    Use load_project_settings() to fetch settings for a specific project.

    Returns:
        Dictionary of settings in SCREAMING_SNAKE_CASE format
    """
    global _settings
    if _settings is not None:
        return _settings
    logger.info("Using DEFAULT_TRUFFLEHOG_SETTINGS (no project loaded yet)")
    return DEFAULT_TRUFFLEHOG_SETTINGS.copy()


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
        logger.warning("WEBAPP_API_URL not set, using DEFAULT_TRUFFLEHOG_SETTINGS")
        _settings = DEFAULT_TRUFFLEHOG_SETTINGS.copy()
        _current_project_id = project_id
        return _settings

    try:
        _settings = fetch_trufflehog_settings(project_id, webapp_url)
        _current_project_id = project_id
        logger.info(f"Loaded {len(_settings)} TruffleHog settings from API for project {project_id}")
        return _settings

    except Exception as e:
        logger.error(f"Failed to fetch TruffleHog settings for project {project_id}: {e}")
        logger.warning("Falling back to DEFAULT_TRUFFLEHOG_SETTINGS")
        _settings = DEFAULT_TRUFFLEHOG_SETTINGS.copy()
        _current_project_id = project_id
        return _settings


def get_setting(key: str, default: Any = None) -> Any:
    """
    Get a single TruffleHog setting value.

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

"""Supply-Chain Scan project settings (mirrors github_secret_hunt/project_settings.py).

Fetches per-project supply-chain settings from the webapp API when PROJECT_ID +
WEBAPP_API_URL are set; otherwise falls back to defaults for standalone use.
"""

import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_SUPPLY_CHAIN_SETTINGS: dict[str, Any] = {
    # Which input the scan reads: 'upload' (the SBOM/lockfile in the uploads
    # volume) or 'github' (a repository cloned by the scan itself).
    'SUPPLY_CHAIN_INPUT_MODE': 'upload',
    # 'upload' input: the basename inside the uploads volume. Uploads REPLACE
    # each other, so this always names the only file present for the project.
    'SUPPLY_CHAIN_SBOM_FILE': '',
    # 'github' input.
    'SUPPLY_CHAIN_REPO_URL': '',
    'SUPPLY_CHAIN_REPO_REF': '',
    # Optional subpath/scope inside the repo (Scan Queue Phase 6 org batch).
    'SUPPLY_CHAIN_REPO_SCOPE': '',
    # Comma-separated OSV ecosystem names to report (osv auto-detects from the
    # file; this is an allow-filter for the graph write).
    'SUPPLY_CHAIN_ECOSYSTEMS': 'npm,PyPI,Go,Maven,crates.io,Packagist,RubyGems,NuGet',
    # GuardDog deep analysis (downloads untrusted tarballs). OFF by default (S5.5).
    'SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED': False,
    # Read from the USER's global settings, and only in the github input mode.
    # Empty means clone anonymously (public repositories only).
    'GITHUB_ACCESS_TOKEN': '',
    # The host the repo is cloned from: github.com or the operator's GitHub
    # Enterprise server. Derived from the repo URL / batch override.
    'SUPPLY_CHAIN_GITHUB_HOST': 'github.com',
    # The GHE host the OPERATOR configured, from their global settings. This is
    # the allowlist the clone is checked against, so it is deliberately NOT
    # derived from the repo URL: empty means github.com only.
    'SUPPLY_CHAIN_GHE_HOST': '',
}


def _host_from_repo_url(value: str) -> str:
    """The hostname of a full https repo URL, or '' for `owner/repo` shorthand."""
    if not isinstance(value, str) or not value.strip().lower().startswith("https://"):
        return ''
    from urllib.parse import urlparse
    try:
        return (urlparse(value.strip()).hostname or '').lower()
    except ValueError:
        return ''


def _scan_auth_headers() -> dict:
    """The scoped scanner key (S3/E6) and the scan's job credential (step 1.16): the
    webapp reads a project or its owner's settings only with both. INTERNAL_API_KEY no
    longer reaches a scan container; it is left for a CLI run by an operator."""
    headers = {"X-Internal-Key": (os.environ.get("SCANNER_API_KEY")
                                  or os.environ.get("INTERNAL_API_KEY", ""))}
    job = os.environ.get("REDAMON_JOB_CREDENTIAL", "")
    if job:
        headers["X-Redamon-Job"] = job
    return headers


def fetch_supply_chain_settings(project_id: str, webapp_url: str) -> dict[str, Any]:
    import requests

    url = f"{webapp_url.rstrip('/')}/api/projects/{project_id}"
    logger.info(f"Fetching Supply-Chain settings from {url}")
    headers = _scan_auth_headers()
    response = requests.get(url, timeout=30, headers=headers)
    response.raise_for_status()
    project = response.json()

    settings = DEFAULT_SUPPLY_CHAIN_SETTINGS.copy()
    settings['SUPPLY_CHAIN_INPUT_MODE'] = project.get(
        'supplyChainInputMode', DEFAULT_SUPPLY_CHAIN_SETTINGS['SUPPLY_CHAIN_INPUT_MODE'])
    settings['SUPPLY_CHAIN_SBOM_FILE'] = project.get(
        'supplyChainSbomFile', DEFAULT_SUPPLY_CHAIN_SETTINGS['SUPPLY_CHAIN_SBOM_FILE'])
    settings['SUPPLY_CHAIN_REPO_URL'] = project.get(
        'supplyChainRepoUrl', DEFAULT_SUPPLY_CHAIN_SETTINGS['SUPPLY_CHAIN_REPO_URL'])
    settings['SUPPLY_CHAIN_REPO_REF'] = project.get(
        'supplyChainRepoRef', DEFAULT_SUPPLY_CHAIN_SETTINGS['SUPPLY_CHAIN_REPO_REF'])
    settings['SUPPLY_CHAIN_ECOSYSTEMS'] = project.get(
        'supplyChainEcosystems', DEFAULT_SUPPLY_CHAIN_SETTINGS['SUPPLY_CHAIN_ECOSYSTEMS'])
    settings['SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED'] = project.get(
        'supplyChainDeepAnalysisEnabled',
        DEFAULT_SUPPLY_CHAIN_SETTINGS['SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED'])

    # The GitHub token lives in the USER's global settings, not the project -
    # the same one the secret hunter and trufflehog use, so a private repo needs
    # no second credential. Only fetched for the github input mode: an
    # SBOM-upload scan has no business holding a token.
    # A supply_chain_repo batch item forces github mode via env override (below),
    # so fetch the token when EITHER the project is github-mode OR an override is
    # active - otherwise a private batch repo would fail to clone anonymously.
    if settings['SUPPLY_CHAIN_INPUT_MODE'] == 'github' or os.environ.get('SUPPLY_CHAIN_REPO_OVERRIDE_URL', '').strip():
        # Which host this scan will clone from: the batch override wins, else the
        # project's own repo URL, else github.com.
        host = (os.environ.get('SUPPLY_CHAIN_REPO_OVERRIDE_HOST', '').strip().lower()
                or _host_from_repo_url(os.environ.get('SUPPLY_CHAIN_REPO_OVERRIDE_URL', ''))
                or _host_from_repo_url(settings['SUPPLY_CHAIN_REPO_URL'])
                or 'github.com')
        settings['SUPPLY_CHAIN_GITHUB_HOST'] = host

        user_id = os.environ.get('USER_ID', '')
        if user_id:
            try:
                user_url = f"{webapp_url.rstrip('/')}/api/users/{user_id}/settings?internal=true"
                user_resp = requests.get(user_url, timeout=30, headers=headers)
                user_resp.raise_for_status()
                user_settings = user_resp.json()
                ghe_host = (user_settings.get('githubEnterpriseHost') or '').strip().lower()
                settings['SUPPLY_CHAIN_GHE_HOST'] = ghe_host
                # Credential BY HOST. A GitHub Enterprise PAT must never be sent
                # to github.com, nor a github.com PAT to an internal server, so
                # an unrecognised host gets NO token rather than the wrong one
                # (the clone then fails the host allowlist anyway).
                if host == 'github.com':
                    settings['GITHUB_ACCESS_TOKEN'] = user_settings.get('supplyChainGithubToken') or ''
                elif ghe_host and host == ghe_host:
                    settings['GITHUB_ACCESS_TOKEN'] = user_settings.get('githubEnterpriseToken') or ''
                else:
                    logger.warning(
                        "Repo host %s is not the configured GitHub Enterprise host (%s); "
                        "no credential will be used", host, ghe_host or '(none)')
            except Exception as exc:
                # Not fatal: public repositories clone anonymously. Say so, or a
                # private-repo failure later looks like a missing repository.
                logger.warning(f"No GitHub token available ({exc}); "
                               "private repositories will fail to clone")

    logger.info(f"Loaded {len(settings)} Supply-Chain settings for project {project_id}")
    return settings


_settings: Optional[dict[str, Any]] = None
_current_project_id: Optional[str] = None


def _apply_repo_override(settings: dict[str, Any]) -> dict[str, Any]:
    """Scan Queue Phase 6: a supply_chain_repo (org-batch) job targets ONE specific
    repo, passed by the orchestrator as env (SUPPLY_CHAIN_REPO_OVERRIDE_*). When an
    override URL is present, force github input mode and override the repo, ref,
    scope and deep-analysis flag, REGARDLESS of the project's own supply-chain
    config. Applied on EVERY return of load_project_settings (both DEFAULT fallbacks
    AND the successful project fetch), so a batch item never scans the project's
    default target by accident. A no-op when no override env is set."""
    repo_url = os.environ.get('SUPPLY_CHAIN_REPO_OVERRIDE_URL', '').strip()
    if not repo_url:
        return settings
    settings['SUPPLY_CHAIN_INPUT_MODE'] = 'github'
    settings['SUPPLY_CHAIN_REPO_URL'] = repo_url
    override_host = os.environ.get('SUPPLY_CHAIN_REPO_OVERRIDE_HOST', '').strip().lower()
    if override_host:
        settings['SUPPLY_CHAIN_GITHUB_HOST'] = override_host
    settings['SUPPLY_CHAIN_REPO_REF'] = os.environ.get('SUPPLY_CHAIN_REPO_OVERRIDE_REF', '').strip()
    settings['SUPPLY_CHAIN_REPO_SCOPE'] = os.environ.get('SUPPLY_CHAIN_REPO_OVERRIDE_SCOPE', '').strip()
    deep = os.environ.get('SUPPLY_CHAIN_REPO_OVERRIDE_DEEP', '').strip().lower()
    if deep in ('1', 'true', 'yes', 'on'):
        settings['SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED'] = True
    elif deep in ('0', 'false', 'no', 'off'):
        settings['SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED'] = False
    logger.info("[batch] repo override active -> %s (ref=%s, deep=%s)",
                repo_url, settings['SUPPLY_CHAIN_REPO_REF'] or 'default',
                settings['SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED'])
    return settings


def load_project_settings(project_id: str) -> dict[str, Any]:
    global _settings, _current_project_id
    if _current_project_id == project_id and _settings is not None:
        return _settings

    webapp_url = os.environ.get('WEBAPP_API_URL')
    if not webapp_url:
        logger.warning("WEBAPP_API_URL not set, using DEFAULT_SUPPLY_CHAIN_SETTINGS")
        settings = DEFAULT_SUPPLY_CHAIN_SETTINGS.copy()
    else:
        try:
            settings = fetch_supply_chain_settings(project_id, webapp_url)
        except Exception as e:
            logger.error(f"Failed to fetch Supply-Chain settings for {project_id}: {e}")
            settings = DEFAULT_SUPPLY_CHAIN_SETTINGS.copy()

    _settings = _apply_repo_override(settings)
    _current_project_id = project_id
    return _settings


def get_settings() -> dict[str, Any]:
    global _settings
    return _settings if _settings is not None else DEFAULT_SUPPLY_CHAIN_SETTINGS.copy()


def get_setting(key: str, default: Any = None) -> Any:
    return get_settings().get(key, default)
